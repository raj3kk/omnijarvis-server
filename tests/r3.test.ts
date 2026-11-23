/**
 * R3 tests (hub v19) — Live screen + tap-to-operate (server legs).
 *
 * R3.1 DO __live_screen__ marker + POST /live-screen dispatch (MEMORY_PUSH
 * mirror) + signed WS LIVE_SCREEN forward to the OTHER sockets of the DO
 * (admin viewer) — never echoed, never traced, never stored; sensitive
 * screen kinds dropped at the DO.
 * R3.7 captcha "slider" + "geetest" are KNOWN types (detection +
 * human-assist) but NEVER auto-solvable (D3 lock) — route accepts them
 * and answers 200 ok:false not_allowed, exactly like turnstile.
 *
 * Gemini/Groq are NOT called on these paths (no vision leg runs for
 * not_allowed types). Live happy-path proof needs the parent-side live
 * verify (BUILD_NOTES).
 */
import { beforeEach, describe, expect, it } from "vitest";
import { FakeD1 } from "./fake-d1";
import { FakeDOState, type FakeWebSocket } from "./fake-do";
import { JarvisHub } from "../src/do/JarvisHub";
import { genDeviceKey, type DeviceKey } from "./helpers";
import { handleRequest, type Env } from "../src/hub";
import { canonicalString, bytesToBase64 } from "../src/crypto";
import { sortedJson } from "../src/docs";
import { encryptTenantKey, importMasterKey } from "../src/keyvault";
import { resetRateLimitFallback } from "../src/ratelimit";
import { registerDevice } from "../src/pairing";
import {
  AUTO_SOLVABLE_TYPES,
  KNOWN_CHALLENGE_TYPES,
  isAutoSolvableType,
  validateSolveRequest,
} from "../src/captcha";

const FIXED_NOW = Date.UTC(2026, 11, 23, 16, 0, 0);
const IMG_B64 = Buffer.from("fake-captcha-png-bytes").toString("base64");

beforeEach(() => {
  resetRateLimitFallback();
});

// --- Shared DO harness (R2 pattern) ---

function makeHub(db: FakeD1) {
  const state = new FakeDOState(db);
  const env = {
    DB: db,
    INTERNAL_SECRET: "test-internal",
  } as unknown as Env;
  const hub = new JarvisHub(state as unknown as DurableObjectState, env);
  return { hub, state, env };
}

async function connectAndHello(
  hub: JarvisHub,
  state: FakeDOState,
  key: DeviceKey,
  deviceId = "dev-1",
) {
  await hub.fetch(
    new Request(`https://hub/ws/${deviceId}`, {
      headers: { Upgrade: "websocket", "x-expected-device": deviceId },
    }),
  );
  const ws = state.accepted[state.accepted.length - 1] as unknown as WebSocket;
  const fakeWs = state.accepted[state.accepted.length - 1];
  const nonce = "nonce-" + Math.random().toString(36).slice(2);
  const ts = Date.now();
  const payloadRaw = JSON.stringify({ hello: true, app_version: "1.18.0" });
  const sig = await key.sign(canonicalString(deviceId, nonce, ts, payloadRaw));
  await hub.webSocketMessage(
    ws,
    JSON.stringify({ type: "HELLO", device_id: deviceId, nonce, ts, sig, payload_raw: payloadRaw }),
  );
  return { ws, fakeWs };
}

async function sendLiveScreen(
  hub: JarvisHub,
  ws: WebSocket,
  key: DeviceKey,
  deviceId: string,
  payload: Record<string, unknown>,
) {
  const nonce = "nonce-" + Math.random().toString(36).slice(2);
  const ts = Date.now();
  const payloadRaw = JSON.stringify(payload);
  const sig = await key.sign(canonicalString(deviceId, nonce, ts, payloadRaw));
  await hub.webSocketMessage(
    ws,
    JSON.stringify({ type: "LIVE_SCREEN", device_id: deviceId, nonce, ts, sig, payload_raw: payloadRaw }),
  );
}

function liveScreenEvents(fakeWs: FakeWebSocket): Record<string, unknown>[] {
  return fakeWs.sent
    .map((s) => JSON.parse(s) as Record<string, unknown>)
    .filter((m) => m.type === "LIVE_SCREEN");
}

function executeSteps(fakeWs: FakeWebSocket): Record<string, unknown>[] {
  return fakeWs.sent
    .map((s) => JSON.parse(s) as Record<string, unknown>)
    .filter((m) => m.type === "EXECUTE_STEP");
}

async function dispatchLiveScreen(
  hub: JarvisHub,
  deviceId: string,
  event: Record<string, unknown>,
  secret = "test-internal",
) {
  return await hub.fetch(
    new Request("https://hub/live-screen", {
      method: "POST",
      headers: { "x-internal-secret": secret, "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: deviceId, event }),
    }),
  );
}

const liveEvent = {
  type: "LIVE_SCREEN",
  tenant_id: "t-1",
  text: "Settings screen, Wi-Fi toggle ON",
  boxes: [{ x: 10, y: 20, w: 100, h: 40, label: "Wi-Fi" }],
  screen_kind: "normal",
  at: FIXED_NOW,
};

// --- R3.1: DO /live-screen dispatch ---

describe("JarvisHub DO — R3.1 live_screen dispatch", () => {
  it("LIVE_SCREEN live socket -> raw event sent, NOT an EXECUTE_STEP, no pixels inside", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const { fakeWs } = await connectAndHello(hub, state, key);
    const res = await dispatchLiveScreen(hub, "dev-1", liveEvent);
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(true);
    const events = liveScreenEvents(fakeWs);
    expect(events.length).toBe(1);
    expect(events[0]).toMatchObject({ text: "Settings screen, Wi-Fi toggle ON", screen_kind: "normal" });
    expect(JSON.stringify(events[0])).not.toContain("image_b64");
    expect(JSON.stringify(events[0])).not.toContain("pixels");
    expect(executeSteps(fakeWs).length).toBe(0);
  });

  it("LIVE_SCREEN wrong secret -> 401; bad event type -> 400; device_mismatch -> 400", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const wrong = await dispatchLiveScreen(hub, "dev-1", liveEvent, "wrong");
    expect(wrong.status).toBe(401);
    const bad = await dispatchLiveScreen(hub, "dev-1", { type: "EXECUTE_STEP" });
    expect(bad.status).toBe(400);
    await connectAndHello(hub, state, key);
    const mismatch = await dispatchLiveScreen(hub, "dev-2", liveEvent);
    expect(mismatch.status).toBe(400);
  });

  it("LIVE_SCREEN offline -> queued as __live_screen__ row, flushed RAW on HELLO", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const res = await dispatchLiveScreen(hub, "dev-1", liveEvent);
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(false);
    const queued = state.sql.exec("SELECT * FROM pending_steps").toArray();
    expect(queued.length).toBe(1);
    expect(String(queued[0].payload)).toContain("__live_screen__");
    const { fakeWs } = await connectAndHello(hub, state, key);
    const events = liveScreenEvents(fakeWs);
    expect(events.length).toBe(1);
    expect(events[0].text).toBe("Settings screen, Wi-Fi toggle ON");
    expect(executeSteps(fakeWs).length).toBe(0);
    expect(state.sql.exec("SELECT * FROM pending_steps").toArray().length).toBe(0);
  });
});

// --- R3.1: DO WS LIVE_SCREEN forward (phone -> admin viewer) ---

describe("JarvisHub DO — R3.1 LIVE_SCREEN WS forward", () => {
  it("signed LIVE_SCREEN from the phone reaches the OTHER socket, never echoes to the sender", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const phone = await connectAndHello(hub, state, key);
    const viewer = await connectAndHello(hub, state, key);
    await sendLiveScreen(hub, phone.ws, key, "dev-1", {
      text: "Home screen, Jarvis icon visible",
      boxes: [{ x: 1, y: 2, w: 3, h: 4, label: "Jarvis" }],
      screen_kind: "normal",
    });
    const viewerEvents = liveScreenEvents(viewer.fakeWs);
    expect(viewerEvents.length).toBe(1);
    expect(viewerEvents[0]).toMatchObject({
      device_id: "dev-1",
      text: "Home screen, Jarvis icon visible",
      screen_kind: "normal",
    });
    // The phone's own socket got HELLO_ACK only — no echo of its frame.
    expect(liveScreenEvents(phone.fakeWs).length).toBe(0);
  });

  it("sensitive screen kind (banking) is dropped at the DO — viewer gets nothing", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const phone = await connectAndHello(hub, state, key);
    const viewer = await connectAndHello(hub, state, key);
    for (const kind of ["banking", "otp", "password", "payment"]) {
      await sendLiveScreen(hub, phone.ws, key, "dev-1", { text: "secret screen", screen_kind: kind });
    }
    expect(liveScreenEvents(viewer.fakeWs).length).toBe(0);
    expect(viewer.fakeWs.closed).toBeNull();
  });

  it("LIVE_SCREEN with no text is dropped silently; session stays open", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const phone = await connectAndHello(hub, state, key);
    const viewer = await connectAndHello(hub, state, key);
    await sendLiveScreen(hub, phone.ws, key, "dev-1", { screen_kind: "normal", boxes: [] });
    expect(liveScreenEvents(viewer.fakeWs).length).toBe(0);
    expect(phone.fakeWs.closed).toBeNull();
    expect(viewer.fakeWs.closed).toBeNull();
  });

  it("unknown WS type still closes the socket (regression guard for the LIVE_SCREEN allow-list)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const { ws, fakeWs } = await connectAndHello(hub, state, key);
    const nonce = "nonce-" + Math.random().toString(36).slice(2);
    const ts = Date.now();
    const payloadRaw = JSON.stringify({ hello: true });
    const sig = await key.sign(canonicalString("dev-1", nonce, ts, payloadRaw));
    await hub.webSocketMessage(
      ws,
      JSON.stringify({ type: "NOPE", device_id: "dev-1", nonce, ts, sig, payload_raw: payloadRaw }),
    );
    expect(fakeWs.closed).toMatchObject({ code: 4400, reason: "unknown_type" });
  });
});

// --- R3.7: captcha slider/geetest — known, never auto-solved ---

describe("captcha — R3.7 slider/geetest known but never auto-solved (D3 lock)", () => {
  it("slider + geetest are KNOWN types; AUTO_SOLVABLE_TYPES is still exactly the 3 frozen types", () => {
    expect((KNOWN_CHALLENGE_TYPES as readonly string[]).includes("slider")).toBe(true);
    expect((KNOWN_CHALLENGE_TYPES as readonly string[]).includes("geetest")).toBe(true);
    expect([...AUTO_SOLVABLE_TYPES]).toEqual(["recaptcha_grid", "hcaptcha_grid", "text"]);
    expect(isAutoSolvableType("slider")).toBe(false);
    expect(isAutoSolvableType("geetest")).toBe(false);
  });

  it("validateSolveRequest accepts slider + geetest (route-level 200, not 400)", () => {
    const base = {
      task_id: "bt-0000000000000001",
      site: "example.com",
      image_b64: IMG_B64,
      auto_solve_allowed: true,
    };
    expect(validateSolveRequest({ ...base, challenge_type: "slider" }).ok).toBe(true);
    expect(validateSolveRequest({ ...base, challenge_type: "geetest" }).ok).toBe(true);
    expect(validateSolveRequest({ ...base, challenge_type: "recaptcha_v3" }).ok).toBe(false);
  });

  it("route: slider + geetest -> 200 ok:false not_allowed + human_assist, 0 vision attempts", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    for (const challengeType of ["slider", "geetest"]) {
      const res = await signedSolve(db, key, solveBody({ challenge_type: challengeType }), { masterB64: master });
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect(body.ok).toBe(false);
      expect(body.error).toBe("not_allowed");
      expect(body.fallback).toBe("human_assist");
      expect(body.attempts).toBe(0);
    }
    // The audit rows exist (not_allowed recorded) — but no vision call
    // ran: the outcomes are all not_allowed, none submitted/answered.
    const rows = (await db.prepare("SELECT outcome FROM captcha_solves").all()).results as Record<
      string,
      unknown
    >[];
    expect(rows.length).toBe(2);
    expect(rows.every((r) => r.outcome === "not_allowed")).toBe(true);
  });
});

async function makeMasterKeyB64(): Promise<string> {
  const k = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
  return bytesToBase64(raw);
}

async function seedTenantWithKeys(db: FakeD1, id: string, masterB64: string): Promise<void> {
  const master = await importMasterKey(masterB64);
  const keyEnc = await encryptTenantKey(master, "TEST-GEMINI-KEY-1");
  const groqKeyEnc = await encryptTenantKey(master, "gsk_test_groq_key_1");
  await db
    .prepare(
      "INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, groq_key_enc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id, `${id}@example.com`, "pro", "byok", keyEnc, groqKeyEnc, FIXED_NOW)
    .run();
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string, publicKeyB64: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, publicKeyB64, FIXED_NOW, FIXED_NOW, 1)
    .run();
}

function solveBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    task_id: "bt-0000000000000001",
    site: "example.com",
    challenge_type: "recaptcha_grid",
    image_b64: IMG_B64,
    auto_solve_allowed: true,
    ...overrides,
  };
}

function fakeEnv(db: FakeD1, overrides: Partial<Env> = {}): Env {
  return {
    JARVIS_HUB: {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        fetch: async () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
      }),
    } as unknown as DurableObjectNamespace,
    DB: db as unknown as D1Database,
    INTERNAL_SECRET: "test-internal",
    CRON_SECRET: "test-cron",
    ...overrides,
  };
}

async function signedSolve(
  db: FakeD1,
  key: Awaited<ReturnType<typeof genDeviceKey>>,
  body: Record<string, unknown>,
  opts: { deviceId?: string; masterB64?: string } = {},
): Promise<Response> {
  const deviceId = opts.deviceId ?? "dev-1";
  const nonce = "aabbccddeeff00112233445566778899";
  const ts = Date.now();
  const payload = sortedJson(body);
  const sig = await key.sign(canonicalString(deviceId, nonce, ts, payload));
  return handleRequest(
    new Request("https://hub/api/captcha/solve", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-device-id": deviceId,
        "x-nonce": nonce,
        "x-ts": String(ts),
        "x-signature": sig,
      },
      body: JSON.stringify(body),
    }),
    fakeEnv(db, opts.masterB64 ? { KEY_ENC_SECRET: opts.masterB64 } : {}),
  );
}
