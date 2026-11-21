import { describe, expect, it } from "vitest";
import { JarvisHub } from "../src/do/JarvisHub";
import type { Env } from "../src/hub";
import { FakeD1 } from "./fake-d1";
import { FakeDOState, FakeWebSocket } from "./fake-do";

// Node has no WebSocketPair (Workers-only global) — stub it with fakes.
// The DO uses pair[1] (server side); pair[0] goes to the client Response.
class FakeWebSocketPair {
  0: FakeWebSocket;
  1: FakeWebSocket;
  constructor() {
    this[0] = new FakeWebSocket();
    this[1] = new FakeWebSocket();
  }
}
(globalThis as unknown as { WebSocketPair: typeof FakeWebSocketPair }).WebSocketPair =
  FakeWebSocketPair;

// Node's Response rejects status 101 — the DO's WS upgrade returns one.
// Shim it: build a 200 Response, then shadow `status` with 101 and keep
// the webSocket on the instance (test-only, Workers behaviour unchanged).
const NativeResponse = Response;
class TestResponse extends NativeResponse {
  declare webSocket: WebSocket | null;
  constructor(
    body: BodyInit | null,
    init?: ResponseInit & { webSocket?: unknown },
  ) {
    if (init?.status === 101) {
      super(body, { status: 200, headers: init.headers });
      this.webSocket = init.webSocket as WebSocket | null;
      Object.defineProperty(this, "status", { value: 101 });
    } else {
      super(body, init);
    }
  }
}
(globalThis as unknown as { Response: typeof TestResponse }).Response = TestResponse;
import { registerDevice } from "../src/pairing";
import { canonicalString } from "../src/crypto";
import { genDeviceKey } from "./helpers";

function makeHub(db: FakeD1) {
  const state = new FakeDOState(db);
  const env = { DB: db, INTERNAL_SECRET: "test-internal" } as unknown as Env;
  const hub = new JarvisHub(state as unknown as DurableObjectState, env);
  return { hub, state, env };
}

async function signedMsg(
  key: Awaited<ReturnType<typeof genDeviceKey>>,
  deviceId: string,
  type: string,
  payloadRaw: string,
  nonce = "nonce-" + Math.random().toString(36).slice(2),
) {
  const ts = Date.now();
  const sig = await key.sign(canonicalString(deviceId, nonce, ts, payloadRaw));
  return JSON.stringify({ type, device_id: deviceId, nonce, ts, sig, payload_raw: payloadRaw });
}

describe("JarvisHub DO", () => {
  it("WS upgrade without x-expected-device -> 400", async () => {
    const db = new FakeD1();
    const { hub } = makeHub(db);
    const res = await hub.fetch(
      new Request("https://hub/ws/dev-1", { headers: { Upgrade: "websocket" } }),
    );
    expect(res.status).toBe(400);
  });

  it("WS upgrade -> 101 + alarm set", async () => {
    const db = new FakeD1();
    const { hub, state } = makeHub(db);
    const res = await hub.fetch(
      new Request("https://hub/ws/dev-1", {
        headers: { Upgrade: "websocket", "x-expected-device": "dev-1" },
      }),
    );
    expect(res.status).toBe(101);
    expect(state.accepted.length).toBe(1);
    expect(state.alarms.length).toBe(1);
  });

  it("HELLO valid -> HELLO_ACK + session row", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    await hub.fetch(
      new Request("https://hub/ws/dev-1", {
        headers: { Upgrade: "websocket", "x-expected-device": "dev-1" },
      }),
    );
    const ws = state.accepted[0] as unknown as WebSocket;
    const fakeWs = state.accepted[0];
    await hub.webSocketMessage(
      ws,
      await signedMsg(key, "dev-1", "HELLO", JSON.stringify({ hello: true, app_version: "1.6.0" })),
    );
    const parsed = fakeWs.sent.map((s) => JSON.parse(s) as Record<string, unknown>);
    expect(parsed.some((m) => m.type === "HELLO_ACK")).toBe(true);
    const sessions = state.sql.exec("SELECT * FROM sessions").toArray();
    expect(sessions.length).toBe(1);
    expect(sessions[0].device_id).toBe("dev-1");
  });

  it("HELLO wrong device_id (routing guard) -> close 4401", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    await hub.fetch(
      new Request("https://hub/ws/dev-1", {
        headers: { Upgrade: "websocket", "x-expected-device": "dev-1" },
      }),
    );
    const ws = state.accepted[0] as unknown as WebSocket;
    const fakeWs = state.accepted[0];
    await hub.webSocketMessage(
      ws,
      await signedMsg(key, "dev-2", "HELLO", JSON.stringify({ hello: true })),
    );
    expect(fakeWs.closed?.code).toBe(4401);
  });

  it("HELLO replay (same nonce twice) -> second close 4401", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    await hub.fetch(
      new Request("https://hub/ws/dev-1", {
        headers: { Upgrade: "websocket", "x-expected-device": "dev-1" },
      }),
    );
    const ws = state.accepted[0] as unknown as WebSocket;
    const fakeWs = state.accepted[0];
    const msg = await signedMsg(key, "dev-1", "HELLO", JSON.stringify({ hello: true }), "fixed-nonce-1");
    await hub.webSocketMessage(ws, msg);
    expect(fakeWs.closed).toBeNull();
    await hub.webSocketMessage(ws, msg); // replay
    expect(fakeWs.closed?.code).toBe(4401);
  });

  it("STEP_RESULT valid -> ACK + trace row in D1", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    await hub.fetch(
      new Request("https://hub/ws/dev-1", {
        headers: { Upgrade: "websocket", "x-expected-device": "dev-1" },
      }),
    );
    const ws = state.accepted[0] as unknown as WebSocket;
    const fakeWs = state.accepted[0];
    await hub.webSocketMessage(
      ws,
      await signedMsg(key, "dev-1", "HELLO", JSON.stringify({ hello: true })),
    );
    await hub.webSocketMessage(
      ws,
      await signedMsg(
        key,
        "dev-1",
        "STEP_RESULT",
        JSON.stringify({ step_id: "s-1", ok: true, summary: "done" }),
      ),
    );
    const parsed = fakeWs.sent.map((s) => JSON.parse(s) as Record<string, unknown>);
    expect(parsed.some((m) => m.type === "ACK")).toBe(true);
    const traces = await db.prepare("SELECT * FROM traces").bind().all();
    expect(traces.results.length).toBe(1);
    expect((traces.results[0] as Record<string, unknown>).kind).toBe("step_result");
  });

  it("dispatch with live socket -> EXECUTE_STEP sent", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    await hub.fetch(
      new Request("https://hub/ws/dev-1", {
        headers: { Upgrade: "websocket", "x-expected-device": "dev-1" },
      }),
    );
    const res = await hub.fetch(
      new Request("https://hub/dispatch", {
        method: "POST",
        headers: { "x-internal-secret": "test-internal", "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", step: { kind: "OPEN_APP", target: "youtube" } }),
      }),
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(true);
    const fakeWs = state.accepted[0];
    const parsed = fakeWs.sent.map((s) => JSON.parse(s) as Record<string, unknown>);
    expect(parsed.some((m) => m.type === "EXECUTE_STEP")).toBe(true);
  });

  it("dispatch with no socket -> queued, flushed on HELLO", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const res = await hub.fetch(
      new Request("https://hub/dispatch", {
        method: "POST",
        headers: { "x-internal-secret": "test-internal", "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", step: { kind: "OPEN_APP", target: "youtube" } }),
      }),
    );
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(false);
    expect(state.sql.exec("SELECT * FROM pending_steps").toArray().length).toBe(1);
    // Now connect + HELLO -> flush.
    await hub.fetch(
      new Request("https://hub/ws/dev-1", {
        headers: { Upgrade: "websocket", "x-expected-device": "dev-1" },
      }),
    );
    const ws = state.accepted[0] as unknown as WebSocket;
    const fakeWs = state.accepted[0];
    await hub.webSocketMessage(
      ws,
      await signedMsg(key, "dev-1", "HELLO", JSON.stringify({ hello: true })),
    );
    const parsed = fakeWs.sent.map((s) => JSON.parse(s) as Record<string, unknown>);
    expect(parsed.some((m) => m.type === "EXECUTE_STEP")).toBe(true);
    expect(state.sql.exec("SELECT * FROM pending_steps").toArray().length).toBe(0);
  });

  it("dispatch wrong secret -> 401", async () => {
    const db = new FakeD1();
    const { hub } = makeHub(db);
    const res = await hub.fetch(
      new Request("https://hub/dispatch", {
        method: "POST",
        headers: { "x-internal-secret": "wrong", "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", step: {} }),
      }),
    );
    expect(res.status).toBe(401);
  });

  it("alarm without auth -> closes socket", async () => {
    const db = new FakeD1();
    const { hub, state } = makeHub(db);
    await hub.fetch(
      new Request("https://hub/ws/dev-1", {
        headers: { Upgrade: "websocket", "x-expected-device": "dev-1" },
      }),
    );
    const fakeWs = state.accepted[0];
    await hub.alarm();
    expect(fakeWs.closed?.code).toBe(4401);
  });

  it("PING -> PONG", async () => {
    const db = new FakeD1();
    const { hub, state } = makeHub(db);
    await hub.fetch(
      new Request("https://hub/ws/dev-1", {
        headers: { Upgrade: "websocket", "x-expected-device": "dev-1" },
      }),
    );
    const ws = state.accepted[0] as unknown as WebSocket;
    const fakeWs = state.accepted[0];
    await hub.webSocketMessage(ws, JSON.stringify({ type: "PING" }));
    const parsed = fakeWs.sent.map((s) => JSON.parse(s) as Record<string, unknown>);
    expect(parsed.some((m) => m.type === "PONG")).toBe(true);
  });
});
