/**
 * JarvisHub — Durable Object, one per device (id = device:<device_id>).
 *
 * Hibernation API ONLY — state.acceptWebSocket() + webSocketMessage /
 * webSocketClose / webSocketError. Plain accept() + manual listeners
 * KABHI NAHI (poora connected time duration charge hota hai).
 *
 * Auth model (frozen, Pehle-Jaanch §3.5 + M-4):
 * - Device signs its OUTBOUND messages (HELLO, STEP_RESULT) with its
 *   Ed25519 private key (Android Keystore). Hub verifies with the
 *   registered public key (D1 devices table).
 * - EXECUTE_STEP flows HUB -> DEVICE SIGNED (M-4): the DO signs every
 *   step at send time with the hub Ed25519 key (Workers secret
 *   HUB_SIGN_SECRET) — envelope {type, step, device_id, nonce, ts,
 *   step_ts, key_id:"hub-1", sig, payload_raw}; device verifies (app
 *   1.7.0) and rejects on any failure. Sign-fail -> step is NOT sent
 *   (fail-closed, never an unsigned fallback).
 * - Routing guard: Worker passes x-expected-device on the upgrade
 *   request; HELLO.device_id must match it (else 4401 close) — a device
 *   cannot claim another device's DO + pending steps.
 * - Nonces: one-time, 5-min expiry, DO SQLite (replay = 403/close).
 * - Unauthenticated sockets: 30s alarm closes them (no HELLO = close).
 * - Hub public key reaches the device at pairing (register response)
 *   and via HELLO_ACK bootstrap for already-paired devices (M-4 §4.4).
 *   A new key_id is NEVER accepted from HELLO_ACK — rotation is
 *   re-pair-only.
 * - Captcha assist (3c, D3 human-assist-first): the device reports
 *   CAPTCHA_DETECTED / CAPTCHA_RESOLVED as SIGNED messages (same
 *   verify path as HELLO/STEP_RESULT); the hub sends CAPTCHA_ASSIST
 *   events to the paired device (live, or queued as a marked row in
 *   pending_steps, max 50/device, C-T9). The event is display-only —
 *   no command executes from it — so it is NOT signed; the session
 *   itself is paired + HELLO-verified. A solution/token value is
 *   NEVER read, traced, or stored.
 * - Live screen (R3.1, U22): the device streams OCR text/events as
 *   signed LIVE_SCREEN WS messages; the DO forwards them to the OTHER
 *   sockets of this DO (admin viewer, R4) — never echoed to the
 *   sender, never traced, never stored. Worker -> DO dispatch is POST
 *   /live-screen (secret-gated), queued as a "__live_screen__" marked
 *   row when offline and flushed RAW on the next HELLO (MEMORY_PUSH
 *   pattern). Pixels never reach the hub; sensitive screen kinds
 *   (otp/banking/password/payment) are dropped at the DO.
 *
 * SQLite tables (DO built-in): sessions, nonces, pending_steps.
 * Presence = WS connection itself (C1) — no heartbeat polling.
 */
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../hub";
import {
  HUB_KEY_ID,
  deriveHubPublicKeyB64,
  importPrivateKey,
  isTimestampFresh,
  randomNonceHex,
  signHubMessage,
  verifySignature,
} from "../crypto";
import { getDevice, insertTrace, touchDeviceSeen } from "../db";
import {
  captchaAssistTrace,
  ensureBrowserTask,
  requestCaptchaAssist,
  resolveCaptchaAssist,
  type AssistOutcome,
} from "../browser";

const NONCE_TTL_MS = 300_000; // 5 min
const HELLO_TIMEOUT_MS = 30_000; // 30s
const MAX_PENDING_PER_DEVICE = 50;
// R3.1: live-screen kinds the DO never forwards (defense in depth —
// the phone excludes them first; the hub drops them here too).
const LIVE_SCREEN_SENSITIVE_KINDS = new Set(["otp", "banking", "password", "payment"]);

interface DeviceMessage {
  type: string;
  device_id: string;
  nonce: string;
  ts: number;
  sig: string;
  payload_raw: string;
}

// NOTE: a DO class MUST extend DurableObject (from "cloudflare:workers")
// — a plain class deploys but the Worker cannot serve ANY request
// (live 1042 on every route, found 2026-11-21). Regression test:
// tests/do.test.ts "class extends DurableObject".
export class JarvisHub extends DurableObject<Env> {
  // `state` is our own field (the base keeps it as `ctx`); sql() uses
  // state.storage. `env` comes from the base class (protected).
  state: DurableObjectState;
  private expectedDeviceId: string | null = null;
  private authenticatedDeviceId: string | null = null;
  private publicKey: string | null = null;
  private sockets = new Set<WebSocket>();
  // M-4 hub signing key, instance-level cache (never re-import per step).
  // null after a failed load attempt (missing/invalid secret) — signing
  // then fails closed (step not sent) until the DO is recreated.
  private hubKey: { priv: CryptoKey; pubB64: string } | null = null;
  private hubKeyTried = false;

  /**
   * Load (once) the hub Ed25519 signing key from HUB_SIGN_SECRET.
   * Returns null when the secret is missing or malformed — the caller
   * must then NOT send the step (M-4 §6.4). The secret value is never
   * logged, traced, or returned.
   */
  private async ensureHubKey(): Promise<{ priv: CryptoKey; pubB64: string } | null> {
    if (this.hubKeyTried) return this.hubKey;
    this.hubKeyTried = true;
    const secret = (this.env as unknown as Record<string, string | undefined>).HUB_SIGN_SECRET;
    if (!secret) return null;
    try {
      const priv = await importPrivateKey(secret);
      const pubB64 = await deriveHubPublicKeyB64(priv);
      this.hubKey = { priv, pubB64 };
      return this.hubKey;
    } catch {
      return null;
    }
  }

  /**
   * Build the signed EXECUTE_STEP envelope (§3.1) for one delivery.
   * payload_raw is stringified ONCE from the step and never re-serialized.
   * stepTs = first-dispatch time (live send: null -> ts itself;
   * flush: row created_at). One Date.now() call feeds both ts and
   * step_ts on live send, so they are exactly equal.
   * Returns null on sign failure — caller must not send anything.
   */
  private async signStepEnvelope(
    deviceId: string,
    step: Record<string, unknown>,
    stepTs: number | null,
  ): Promise<Record<string, unknown> | null> {
    const key = await this.ensureHubKey();
    if (!key) return null;
    const payloadRaw = JSON.stringify(step);
    const nonce = randomNonceHex();
    const ts = Date.now();
    try {
      const sig = await signHubMessage(key.priv, deviceId, nonce, ts, payloadRaw);
      return {
        type: "EXECUTE_STEP",
        step,
        device_id: deviceId,
        nonce,
        ts,
        step_ts: stepTs ?? ts,
        key_id: HUB_KEY_ID,
        sig,
        payload_raw: payloadRaw,
      };
    } catch {
      return null;
    }
  }

  /** Best-effort trace for a sign failure (§6.4). Never carries the secret. */
  private async traceSignFailed(deviceId: string, step: Record<string, unknown>): Promise<void> {
    try {
      const device = await getDevice(this.env.DB, deviceId);
      if (!device) return;
      await insertTrace(this.env.DB, device.tenant_id, deviceId, "step_sign_failed", {
        job_id: typeof step.job_id === "string" ? step.job_id : null,
      });
    } catch {
      // tracing must never break dispatch
    }
  }

  /** 3c: CAPTCHA_DETECTED from the device (PhoneWebView executor). */
  private async handleCaptchaDetected(deviceId: string, payload: Record<string, unknown>): Promise<void> {
    const taskId = typeof payload.task_id === "string" ? payload.task_id : "";
    if (!taskId) return;
    const site = typeof payload.site === "string" ? payload.site : "";
    const taskName = typeof payload.task_name === "string" ? payload.task_name : "Browser task";
    try {
      const device = await getDevice(this.env.DB, deviceId);
      if (!device) return;
      await ensureBrowserTask(this.env.DB, {
        id: taskId,
        tenant_id: device.tenant_id,
        device_id: deviceId,
        task_name: taskName,
        site: site || null,
        provider: "phone_webview",
      });
      const res = await requestCaptchaAssist(this.env.DB, taskId);
      if (res.ok) {
        await insertTrace(
          this.env.DB,
          device.tenant_id,
          deviceId,
          "captcha_assist",
          captchaAssistTrace(taskId, site || null, { outcome: "requested", assist_count: res.assist_count }),
        );
      } else if (res.error === "assist_cap_reached") {
        // 4th assist: task auto-paused, no event sent. Trace the cap
        // so the "continue karun?" prompt has an audit trail.
        await insertTrace(
          this.env.DB,
          device.tenant_id,
          deviceId,
          "captcha_assist",
          captchaAssistTrace(taskId, site || null, { outcome: "cap_reached", assist_count: res.assist_count }),
        );
      }
      // task_closed (aborted/done): nothing to do — the device already stopped.
    } catch {
      // tracing/state must never break the WS session
    }
  }

  /** 3c: CAPTCHA_RESOLVED from the device (solved / timeout / aborted). */
  private async handleCaptchaResolved(deviceId: string, payload: Record<string, unknown>): Promise<void> {
    const taskId = typeof payload.task_id === "string" ? payload.task_id : "";
    if (!taskId) return;
    const site = typeof payload.site === "string" ? payload.site : "";
    const solved = payload.solved === true;
    const aborted = payload.aborted === true;
    const durationS = typeof payload.duration_s === "number" ? payload.duration_s : undefined;
    const outcome: AssistOutcome = aborted ? "aborted" : solved ? "solved" : "timeout";
    try {
      const device = await getDevice(this.env.DB, deviceId);
      if (!device) return;
      const res = await resolveCaptchaAssist(this.env.DB, taskId, outcome);
      if (!res.ok) return;
      await insertTrace(
        this.env.DB,
        device.tenant_id,
        deviceId,
        "captcha_assist",
        captchaAssistTrace(taskId, site || null, { solved, duration_s: durationS, outcome }),
      );
    } catch {
      // tracing/state must never break the WS session
    }
  }

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.state = state;
  }

  private sql() {
    return this.state.storage.sql;
  }

  private ensureTables(): void {
    this.sql().exec(
      "CREATE TABLE IF NOT EXISTS sessions (device_id TEXT PRIMARY KEY, connected_at INTEGER, last_seen INTEGER)",
    );
    this.sql().exec(
      "CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expires_at INTEGER)",
    );
    this.sql().exec(
      "CREATE TABLE IF NOT EXISTS pending_steps (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT, created_at INTEGER)",
    );
  }

  private async useNonce(nonce: string, nowMs: number): Promise<boolean> {
    // One-time: insert fails (UNIQUE) if already used; expired rows pruned.
    this.sql().exec("DELETE FROM nonces WHERE expires_at < ?", nowMs);
    try {
      this.sql().exec("INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)", nonce, nowMs + NONCE_TTL_MS);
      return true;
    } catch {
      return false; // replay
    }
  }

  private async verifyDeviceMessage(msg: DeviceMessage): Promise<boolean> {
    if (!isTimestampFresh(msg.ts, Date.now())) return false;
    if (this.expectedDeviceId && msg.device_id !== this.expectedDeviceId) return false;
    if (!(await this.useNonce(msg.nonce, Date.now()))) return false;
    if (!this.publicKey) {
      const device = await getDevice(this.env.DB, msg.device_id);
      if (!device || device.enabled === 0) return false;
      this.publicKey = device.public_key;
    }
    return await verifySignature(
      this.publicKey,
      msg.sig,
      msg.device_id,
      msg.nonce,
      msg.ts,
      msg.payload_raw,
    );
  }

  private async flushPending(ws: WebSocket): Promise<void> {
    const deviceId = this.authenticatedDeviceId ?? this.expectedDeviceId;
    if (!deviceId) return;
    const rows = [
      ...this.sql().exec("SELECT id, payload, created_at FROM pending_steps ORDER BY id ASC").toArray(),
    ] as {
      id: number;
      payload: string;
      created_at: number;
    }[];
    for (const row of rows) {
      let step: Record<string, unknown>;
      try {
        step = JSON.parse(row.payload) as Record<string, unknown>;
      } catch {
        return; // corrupt row — stop flushing; rows stay for next connect
      }
      // 3c: queued CAPTCHA_ASSIST events are marked rows — they go out
      // as RAW events (never signed as EXECUTE_STEP), then deleted.
      // R2.4: same for queued MEMORY_PUSH events (marker
      // "__memory_push__" — the phone pulls the rows after the notice).
      // R3.1: same for queued LIVE_SCREEN events (marker
      // "__live_screen__" — text/events only, never pixels).
      if (
        step &&
        typeof step === "object" &&
        ("__captcha_assist__" in step || "__memory_push__" in step || "__live_screen__" in step)
      ) {
        const event = (step["__captcha_assist__"] ?? step["__memory_push__"] ?? step["__live_screen__"]) as Record<
          string,
          unknown
        >;
        try {
          ws.send(JSON.stringify(event));
        } catch {
          return; // socket dead — stop flushing; rows stay for next connect
        }
        this.sql().exec("DELETE FROM pending_steps WHERE id = ?", row.id);
        continue;
      }
      // M-4: sign at send time; step_ts = first dispatch (row created_at).
      // Sign-fail -> STOP, leave the row (retry next HELLO). Never send unsigned.
      const envelope = await this.signStepEnvelope(deviceId, step, row.created_at);
      if (!envelope) {
        await this.traceSignFailed(deviceId, step);
        return;
      }
      try {
        ws.send(JSON.stringify(envelope));
      } catch {
        return; // socket dead — stop flushing; rows stay for next connect
      }
      this.sql().exec("DELETE FROM pending_steps WHERE id = ?", row.id);
    }
  }

  private async queueOrSend(step: Record<string, unknown>, deviceId: string): Promise<boolean> {
    // M-4: live send is signed at send time. Sign-fail -> queue the step
    // (it stays queued for a later HELLO flush) + trace; never send unsigned.
    if (this.sockets.size > 0) {
      const envelope = await this.signStepEnvelope(deviceId, step, null);
      if (!envelope) {
        await this.traceSignFailed(deviceId, step);
      } else {
        for (const ws of this.sockets) {
          try {
            ws.send(JSON.stringify(envelope));
            return true;
          } catch {
            // try next socket, else fall through to queue
          }
        }
      }
    }
    // No live socket (or send/sign failed): queue (max 50, oldest dropped + trace).
    const count = [...this.sql().exec("SELECT COUNT(*) AS n FROM pending_steps").toArray()][0] as { n: number };
    if (count.n >= MAX_PENDING_PER_DEVICE) {
      this.sql().exec("DELETE FROM pending_steps WHERE id = (SELECT MIN(id) FROM pending_steps)");
    }
    this.sql().exec("INSERT INTO pending_steps (payload, created_at) VALUES (?, ?)", JSON.stringify(step), Date.now());
    return false;
  }

  /**
   * 3c: send a CAPTCHA_ASSIST event to the paired device. Live send
   * only on an authenticated socket (HELLO done) — an unauthenticated
   * socket never sees site/task names. Offline -> queued as a marked
   * row in pending_steps (max 50/device, shared with steps, C-T9);
   * flushPending sends marked rows back out as raw events.
   * R2.4: MEMORY_PUSH uses the same shape with marker
   * "__memory_push__" — the event carries ids/counts only, never
   * memory content; the phone pulls the rows from /api/memory/list.
   * R3.1: LIVE_SCREEN uses the same shape with marker
   * "__live_screen__" — the event carries OCR text/events only,
   * never pixels; a connected admin viewer (R4) reads the screen
   * through it, the phone never re-reads its own frames.
   */
  private async queueOrSendEvent(
    deviceId: string,
    event: Record<string, unknown>,
    marker: "__captcha_assist__" | "__memory_push__" | "__live_screen__" = "__captcha_assist__",
  ): Promise<boolean> {
    if (this.authenticatedDeviceId === deviceId && this.sockets.size > 0) {
      for (const ws of this.sockets) {
        try {
          ws.send(JSON.stringify(event));
          return true;
        } catch {
          // try next socket, else fall through to queue
        }
      }
    }
    const count = [...this.sql().exec("SELECT COUNT(*) AS n FROM pending_steps").toArray()][0] as { n: number };
    if (count.n >= MAX_PENDING_PER_DEVICE) {
      this.sql().exec("DELETE FROM pending_steps WHERE id = (SELECT MIN(id) FROM pending_steps)");
    }
    this.sql().exec(
      "INSERT INTO pending_steps (payload, created_at) VALUES (?, ?)",
      JSON.stringify({ [marker]: event }),
      Date.now(),
    );
    return false;
  }

  async fetch(request: Request): Promise<Response> {
    this.ensureTables();
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    // Internal dispatch (Worker -> DO): POST /dispatch, secret-gated.
    if (path === "/dispatch" && request.method === "POST") {
      const secret = (this.env as unknown as Record<string, string | undefined>).INTERNAL_SECRET;
      if (!secret || request.headers.get("x-internal-secret") !== secret) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const body = (await request.json()) as { device_id?: string; step?: Record<string, unknown> };
      if (!body.device_id || !body.step) {
        return Response.json({ error: "bad_request" }, { status: 400 });
      }
      if (this.expectedDeviceId && body.device_id !== this.expectedDeviceId) {
        return Response.json({ error: "device_mismatch" }, { status: 400 });
      }
      const sent = await this.queueOrSend(body.step, body.device_id);
      return Response.json({ ok: true, sent });
    }
    // 3c: CAPTCHA_ASSIST dispatch (Worker -> DO): POST /captcha-assist,
    // secret-gated. Body: {device_id, event:{type:"CAPTCHA_ASSIST", ...}}.
    if (path === "/captcha-assist" && request.method === "POST") {
      const secret = (this.env as unknown as Record<string, string | undefined>).INTERNAL_SECRET;
      if (!secret || request.headers.get("x-internal-secret") !== secret) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const body = (await request.json()) as { device_id?: string; event?: Record<string, unknown> };
      if (!body.device_id || !body.event || body.event.type !== "CAPTCHA_ASSIST") {
        return Response.json({ error: "bad_request" }, { status: 400 });
      }
      if (this.expectedDeviceId && body.device_id !== this.expectedDeviceId) {
        return Response.json({ error: "device_mismatch" }, { status: 400 });
      }
      const sent = await this.queueOrSendEvent(body.device_id, body.event);
      return Response.json({ ok: true, sent });
    }
    // R2.4: MEMORY_PUSH dispatch (Worker -> DO): POST /memory-push,
    // secret-gated. Body: {device_id, event:{type:"MEMORY_PUSH", ...}}.
    // Same shape as /captcha-assist — live send on an authenticated
    // socket, else queued as a "__memory_push__" marked row and flushed
    // RAW on the next HELLO. The event carries ids/counts only.
    if (path === "/memory-push" && request.method === "POST") {
      const secret = (this.env as unknown as Record<string, string | undefined>).INTERNAL_SECRET;
      if (!secret || request.headers.get("x-internal-secret") !== secret) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const body = (await request.json()) as { device_id?: string; event?: Record<string, unknown> };
      if (!body.device_id || !body.event || body.event.type !== "MEMORY_PUSH") {
        return Response.json({ error: "bad_request" }, { status: 400 });
      }
      if (this.expectedDeviceId && body.device_id !== this.expectedDeviceId) {
        return Response.json({ error: "device_mismatch" }, { status: 400 });
      }
      const sent = await this.queueOrSendEvent(body.device_id, body.event, "__memory_push__");
      return Response.json({ ok: true, sent });
    }
    // R3.1: LIVE_SCREEN dispatch (Worker -> DO): POST /live-screen,
    // secret-gated. Body: {device_id, event:{type:"LIVE_SCREEN", ...}}.
    // Same shape as /memory-push — live send on an authenticated
    // socket, else queued as a "__live_screen__" marked row and flushed
    // RAW on the next HELLO. The event carries OCR text/events only —
    // never pixels, never screen content from sensitive kinds.
    if (path === "/live-screen" && request.method === "POST") {
      const secret = (this.env as unknown as Record<string, string | undefined>).INTERNAL_SECRET;
      if (!secret || request.headers.get("x-internal-secret") !== secret) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const body = (await request.json()) as { device_id?: string; event?: Record<string, unknown> };
      if (!body.device_id || !body.event || body.event.type !== "LIVE_SCREEN") {
        return Response.json({ error: "bad_request" }, { status: 400 });
      }
      if (this.expectedDeviceId && body.device_id !== this.expectedDeviceId) {
        return Response.json({ error: "device_mismatch" }, { status: 400 });
      }
      const sent = await this.queueOrSendEvent(body.device_id, body.event, "__live_screen__");
      return Response.json({ ok: true, sent });
    }
    // WS upgrade (Worker routes /ws/:deviceId here with x-expected-device).
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }
    const expected = request.headers.get("x-expected-device");
    if (!expected) {
      return Response.json({ error: "missing_device" }, { status: 400 });
    }
    this.expectedDeviceId = expected;
    const pair = new WebSocketPair();
    this.state.acceptWebSocket(pair[1]);
    this.sockets.add(pair[1]);
    // Unauthenticated sockets die after 30s (no valid HELLO = close).
    await this.state.storage.setAlarm(Date.now() + HELLO_TIMEOUT_MS);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    let msg: DeviceMessage;
    try {
      msg = JSON.parse(typeof message === "string" ? message : new TextDecoder().decode(message)) as DeviceMessage;
    } catch {
      ws.close(4400, "bad_json");
      return;
    }
    if (msg.type === "PING") {
      ws.send(JSON.stringify({ type: "PONG" }));
      return;
    }
    if (
      msg.type !== "HELLO" &&
      msg.type !== "STEP_RESULT" &&
      msg.type !== "CAPTCHA_DETECTED" &&
      msg.type !== "CAPTCHA_RESOLVED" &&
      msg.type !== "LIVE_SCREEN"
    ) {
      ws.close(4400, "unknown_type");
      return;
    }
    if (!(await this.verifyDeviceMessage(msg))) {
      ws.close(4401, "unauthorized");
      return;
    }
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(msg.payload_raw) as Record<string, unknown>;
    } catch {
      ws.close(4400, "bad_payload");
      return;
    }
    if (msg.type === "HELLO") {
      this.authenticatedDeviceId = msg.device_id;
      const now = Date.now();
      this.sql().exec(
        "INSERT INTO sessions (device_id, connected_at, last_seen) VALUES (?, ?, ?) " +
          "ON CONFLICT(device_id) DO UPDATE SET last_seen = excluded.last_seen",
        msg.device_id,
        now,
        now,
      );
      await touchDeviceSeen(this.env.DB, msg.device_id);
      // M-4 §4.4 HELLO_ACK bootstrap: already-paired devices get the hub
      // public key here (first-seen store on the device; a stored key is
      // only confirmed when key_id matches — rotation is re-pair-only).
      // No key available (secret missing) -> fields omitted, not faked.
      const hubKey = await this.ensureHubKey();
      ws.send(
        JSON.stringify({
          type: "HELLO_ACK",
          device_id: msg.device_id,
          ...(hubKey ? { hub_public_key: hubKey.pubB64, key_id: HUB_KEY_ID } : {}),
        }),
      );
      await this.flushPending(ws);
      return;
    }
    // 3c: device-reported captcha assist (PhoneWebView executor).
    // Signed + verified above, same as HELLO/STEP_RESULT. The device
    // is the executor here, so its task_id is authoritative — the row
    // is created if new. A `solution`/`token` field in the payload is
    // NEVER read, traced, or stored (D3 §3.2).
    if (msg.type === "CAPTCHA_DETECTED") {
      await this.handleCaptchaDetected(msg.device_id, payload);
      ws.send(JSON.stringify({ type: "ACK", id: typeof payload.task_id === "string" ? payload.task_id : null }));
      return;
    }
    if (msg.type === "CAPTCHA_RESOLVED") {
      await this.handleCaptchaResolved(msg.device_id, payload);
      ws.send(JSON.stringify({ type: "ACK", id: typeof payload.task_id === "string" ? payload.task_id : null }));
      return;
    }
    // R3.1: device-reported live-screen frame (OCR text/events from the
    // phone's LiveScreenWatcher). Signed + verified above, same as
    // HELLO/STEP_RESULT. Forwarded to the OTHER sockets of this DO
    // (admin viewer, R4) — never echoed back to the sender, never
    // traced, never stored (events pass through the DO only). Sensitive
    // screen kinds are dropped here too (defense in depth — the phone
    // excludes them first; the hub never forwards them). A frame with
    // no text is dropped silently; a malformed frame never closes the
    // session.
    if (msg.type === "LIVE_SCREEN") {
      const kind = typeof payload.screen_kind === "string" ? payload.screen_kind : "unknown";
      if (LIVE_SCREEN_SENSITIVE_KINDS.has(kind)) return;
      const text = typeof payload.text === "string" ? payload.text : "";
      if (!text) return;
      const boxes = Array.isArray(payload.boxes) ? payload.boxes : [];
      const event = {
        type: "LIVE_SCREEN",
        device_id: msg.device_id,
        text: text.slice(0, 4000),
        boxes,
        screen_kind: kind,
        at: Date.now(),
      };
      for (const other of this.sockets) {
        if (other === ws) continue;
        try {
          other.send(JSON.stringify(event));
        } catch {
          // socket dead — skip it, never break the session
        }
      }
      return;
    }
    // STEP_RESULT: trace it (D1) + ack.
    const device = await getDevice(this.env.DB, msg.device_id);
    if (device) {
      const summary = typeof payload.summary === "string" ? payload.summary.slice(0, 200) : null;
      await insertTrace(this.env.DB, device.tenant_id, msg.device_id, "step_result", {
        ok: payload.ok ?? null,
        summary,
      });
      // M-4 §6: device rejected a step on signature-verify failure ->
      // extra trace so F-1 (cron job-pause) can find it by job_id.
      // step_id IS the job_id for cron steps (2b-2 S5). Both device
      // reject summaries count (bad sig + no hub key yet). The rejected
      // step is never re-queued (it was already delivered once).
      if (
        summary !== null &&
        (summary.startsWith("Hub signature verify fail") || summary.startsWith("Hub key nahi mili"))
      ) {
        await insertTrace(this.env.DB, device.tenant_id, msg.device_id, "step_rejected_bad_sig", {
          job_id: typeof payload.step_id === "string" ? payload.step_id : null,
          ok: false,
          summary,
        });
      }
    }
    ws.send(JSON.stringify({ type: "ACK", id: (payload as Record<string, unknown>).step_id ?? null }));
  }

  async webSocketClose(ws: WebSocket, _code: number, _reason: string, _wasClean: boolean): Promise<void> {
    this.sockets.delete(ws);
    if (this.authenticatedDeviceId) {
      try {
        await touchDeviceSeen(this.env.DB, this.authenticatedDeviceId);
      } catch {
        // best-effort; DO storage already has last_seen via sessions table
      }
      this.sql().exec("DELETE FROM sessions WHERE device_id = ?", this.authenticatedDeviceId);
      this.authenticatedDeviceId = null;
    }
  }

  async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    this.sockets.delete(ws);
    try {
      ws.close(1011, "error");
    } catch {
      // already closed
    }
  }

  async alarm(): Promise<void> {
    // Close unauthenticated sockets (no valid HELLO within 30s).
    if (!this.authenticatedDeviceId) {
      for (const ws of this.sockets) {
        try {
          ws.close(4401, "hello_timeout");
        } catch {
          // already closed
        }
      }
      this.sockets.clear();
    }
  }
}
