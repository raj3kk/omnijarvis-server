/**
 * JarvisHub — Durable Object, one per device (id = device:<device_id>).
 *
 * Hibernation API ONLY — state.acceptWebSocket() + webSocketMessage /
 * webSocketClose / webSocketError. Plain accept() + manual listeners
 * KABHI NAHI (poora connected time duration charge hota hai).
 *
 * Auth model (frozen, Pehle-Jaanch §3.5 + design correction):
 * - Device signs its OUTBOUND messages (HELLO, STEP_RESULT) with its
 *   Ed25519 private key (Android Keystore). Hub verifies with the
 *   registered public key (D1 devices table).
 * - EXECUTE_STEP flows HUB -> DEVICE over the WS session established
 *   with a signed HELLO (channel authenticated at establishment).
 * - Routing guard: Worker passes x-expected-device on the upgrade
 *   request; HELLO.device_id must match it (else 4401 close) — a device
 *   cannot claim another device's DO + pending steps.
 * - Nonces: one-time, 5-min expiry, DO SQLite (replay = 403/close).
 * - Unauthenticated sockets: 30s alarm closes them (no HELLO = close).
 *
 * SQLite tables (DO built-in): sessions, nonces, pending_steps.
 * Presence = WS connection itself (C1) — no heartbeat polling.
 */
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../hub";
import { isTimestampFresh, verifySignature } from "../crypto";
import { getDevice, insertTrace, touchDeviceSeen } from "../db";

const NONCE_TTL_MS = 300_000; // 5 min
const HELLO_TIMEOUT_MS = 30_000; // 30s
const MAX_PENDING_PER_DEVICE = 50;

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
    const rows = [...this.sql().exec("SELECT id, payload FROM pending_steps ORDER BY id ASC").toArray()] as {
      id: number;
      payload: string;
    }[];
    for (const row of rows) {
      try {
        ws.send(JSON.stringify({ type: "EXECUTE_STEP", step: JSON.parse(row.payload) }));
      } catch {
        return; // socket dead — stop flushing; rows stay for next connect
      }
      this.sql().exec("DELETE FROM pending_steps WHERE id = ?", row.id);
    }
  }

  private async queueOrSend(step: Record<string, unknown>): Promise<boolean> {
    const payload = JSON.stringify(step);
    for (const ws of this.sockets) {
      try {
        ws.send(JSON.stringify({ type: "EXECUTE_STEP", step }));
        return true;
      } catch {
        // fall through to queue
      }
    }
    // No live socket: queue (max 50, oldest dropped + trace).
    const count = [...this.sql().exec("SELECT COUNT(*) AS n FROM pending_steps").toArray()][0] as { n: number };
    if (count.n >= MAX_PENDING_PER_DEVICE) {
      this.sql().exec("DELETE FROM pending_steps WHERE id = (SELECT MIN(id) FROM pending_steps)");
    }
    this.sql().exec("INSERT INTO pending_steps (payload, created_at) VALUES (?, ?)", payload, Date.now());
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
      const sent = await this.queueOrSend(body.step);
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
    if (msg.type !== "HELLO" && msg.type !== "STEP_RESULT") {
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
      ws.send(JSON.stringify({ type: "HELLO_ACK", device_id: msg.device_id }));
      await this.flushPending(ws);
      return;
    }
    // STEP_RESULT: trace it (D1) + ack.
    const device = await getDevice(this.env.DB, msg.device_id);
    if (device) {
      await insertTrace(this.env.DB, device.tenant_id, msg.device_id, "step_result", {
        ok: payload.ok ?? null,
        summary: typeof payload.summary === "string" ? payload.summary.slice(0, 200) : null,
      });
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
