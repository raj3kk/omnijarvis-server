import { DurableObject } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { JarvisHub } from "../src/do/JarvisHub";
import type { Env } from "../src/hub";
import { FakeD1 } from "./fake-d1";
import { FakeDOState, FakeWebSocket } from "./fake-do";

// Workers-only globals (WebSocketPair / Response-101 / DurableObject)
// are stubbed in tests/setup.ts (must run BEFORE this module's imports).
import { registerDevice } from "../src/pairing";
import { canonicalString, verifySignature } from "../src/crypto";
import { genDeviceKey, genHubKey } from "./helpers";

function makeHub(db: FakeD1, hubSecret?: string) {
  const state = new FakeDOState(db);
  const env = {
    DB: db,
    INTERNAL_SECRET: "test-internal",
    ...(hubSecret ? { HUB_SIGN_SECRET: hubSecret } : {}),
  } as unknown as Env;
  const hub = new JarvisHub(state as unknown as DurableObjectState, env);
  return { hub, state, env };
}

/** Signed EXECUTE_STEP envelope from a live socket's sent frames. */
function executeSteps(fakeWs: FakeWebSocket): Record<string, unknown>[] {
  return fakeWs.sent
    .map((s) => JSON.parse(s) as Record<string, unknown>)
    .filter((m) => m.type === "EXECUTE_STEP");
}

async function connectAndHello(
  hub: JarvisHub,
  state: FakeDOState,
  key: Awaited<ReturnType<typeof genDeviceKey>>,
  deviceId = "dev-1",
) {
  await hub.fetch(
    new Request(`https://hub/ws/${deviceId}`, {
      headers: { Upgrade: "websocket", "x-expected-device": deviceId },
    }),
  );
  const ws = state.accepted[state.accepted.length - 1] as unknown as WebSocket;
  const fakeWs = state.accepted[state.accepted.length - 1];
  await hub.webSocketMessage(
    ws,
    await signedMsg(key, deviceId, "HELLO", JSON.stringify({ hello: true, app_version: "1.6.0" })),
  );
  return { ws, fakeWs };
}

async function dispatchStep(hub: JarvisHub, step: Record<string, unknown>, deviceId = "dev-1") {
  return await hub.fetch(
    new Request("https://hub/dispatch", {
      method: "POST",
      headers: { "x-internal-secret": "test-internal", "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: deviceId, step }),
    }),
  );
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
  it("class extends DurableObject (plain class = live 1042)", () => {
    expect(Object.getPrototypeOf(JarvisHub)).toBe(DurableObject);
  });

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

  it("dispatch with live socket -> signed EXECUTE_STEP sent (M-4 envelope)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    const hubKey = await genHubKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db, hubKey.privateKeyB64);
    const { fakeWs } = await connectAndHello(hub, state, key);
    const step = { kind: "OPEN_APP", target: "youtube" };
    const res = await dispatchStep(hub, step);
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(true);
    const steps = executeSteps(fakeWs);
    expect(steps.length).toBe(1);
    const env = steps[0];
    // Envelope fields (§3.1).
    expect(env.device_id).toBe("dev-1");
    expect(env.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(typeof env.ts).toBe("number");
    expect(env.step_ts).toBe(env.ts); // live send: step_ts == ts
    expect(env.key_id).toBe("hub-1");
    expect(typeof env.sig).toBe("string");
    expect(typeof env.payload_raw).toBe("string");
    // payload_raw parses back to the exact step (backward-compat `step` too).
    expect(JSON.parse(String(env.payload_raw))).toEqual(step);
    expect(env.step).toEqual(step);
    // Signature verifies against the hub public key.
    expect(
      await verifySignature(
        hubKey.publicKeyB64,
        String(env.sig),
        String(env.device_id),
        String(env.nonce),
        Number(env.ts),
        String(env.payload_raw),
      ),
    ).toBe(true);
  });

  it("dispatch twice -> nonces differ (fresh per send)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    const hubKey = await genHubKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db, hubKey.privateKeyB64);
    const { fakeWs } = await connectAndHello(hub, state, key);
    await dispatchStep(hub, { kind: "OPEN_APP", target: "youtube" });
    await dispatchStep(hub, { kind: "OPEN_APP", target: "maps" });
    const steps = executeSteps(fakeWs);
    expect(steps.length).toBe(2);
    expect(steps[0].nonce).not.toBe(steps[1].nonce);
    for (const env of steps) {
      expect(
        await verifySignature(
          hubKey.publicKeyB64,
          String(env.sig),
          String(env.device_id),
          String(env.nonce),
          Number(env.ts),
          String(env.payload_raw),
        ),
      ).toBe(true);
    }
  });

  it("dispatch with no socket -> queued, flushed on HELLO with step_ts = created_at", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    const hubKey = await genHubKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db, hubKey.privateKeyB64);
    const res = await dispatchStep(hub, { kind: "OPEN_APP", target: "youtube" });
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(false);
    const queued = state.sql.exec("SELECT * FROM pending_steps").toArray();
    expect(queued.length).toBe(1);
    const createdAt = Number(queued[0].created_at);
    // Now connect + HELLO -> flush.
    const { fakeWs } = await connectAndHello(hub, state, key);
    const steps = executeSteps(fakeWs);
    expect(steps.length).toBe(1);
    expect(steps[0].step_ts).toBe(createdAt); // flush: step_ts = row created_at
    expect(
      await verifySignature(
        hubKey.publicKeyB64,
        String(steps[0].sig),
        String(steps[0].device_id),
        String(steps[0].nonce),
        Number(steps[0].ts),
        String(steps[0].payload_raw),
      ),
    ).toBe(true);
    expect(state.sql.exec("SELECT * FROM pending_steps").toArray().length).toBe(0);
  });

  it("HELLO_ACK carries hub_public_key + key_id (M-4 §4.4 bootstrap)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    const hubKey = await genHubKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db, hubKey.privateKeyB64);
    const { fakeWs } = await connectAndHello(hub, state, key);
    const parsed = fakeWs.sent.map((s) => JSON.parse(s) as Record<string, unknown>);
    const ack = parsed.find((m) => m.type === "HELLO_ACK");
    expect(ack).toBeDefined();
    expect(ack?.hub_public_key).toBe(hubKey.publicKeyB64);
    expect(ack?.key_id).toBe("hub-1");
  });

  it("HELLO_ACK without HUB_SIGN_SECRET -> key fields omitted (not faked)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db); // no hub secret
    const { fakeWs } = await connectAndHello(hub, state, key);
    const parsed = fakeWs.sent.map((s) => JSON.parse(s) as Record<string, unknown>);
    const ack = parsed.find((m) => m.type === "HELLO_ACK");
    expect(ack).toBeDefined();
    expect(ack?.hub_public_key).toBeUndefined();
    expect(ack?.key_id).toBeUndefined();
  });

  it("HUB_SIGN_SECRET missing -> live dispatch sends NOTHING + step_sign_failed trace", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db); // no hub secret
    const { fakeWs } = await connectAndHello(hub, state, key);
    const res = await dispatchStep(hub, { kind: "CRON_COMMAND", command: "open youtube", job_id: "job-1" });
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(false);
    // No unsigned fallback: zero EXECUTE_STEP frames on the socket.
    expect(executeSteps(fakeWs).length).toBe(0);
    // Step stays queued for a later (signed) flush.
    expect(state.sql.exec("SELECT * FROM pending_steps").toArray().length).toBe(1);
    const traces = await db.prepare("SELECT * FROM traces").bind().all();
    expect(traces.results.some((t) => (t as Record<string, unknown>).kind === "step_sign_failed")).toBe(true);
  });

  it("HUB_SIGN_SECRET missing -> flush sends NOTHING, queued row stays", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db); // no hub secret
    await dispatchStep(hub, { kind: "OPEN_APP", target: "youtube" });
    expect(state.sql.exec("SELECT * FROM pending_steps").toArray().length).toBe(1);
    const { fakeWs } = await connectAndHello(hub, state, key);
    expect(executeSteps(fakeWs).length).toBe(0);
    expect(state.sql.exec("SELECT * FROM pending_steps").toArray().length).toBe(1);
  });

  it("STEP_RESULT 'Hub signature verify fail' -> step_rejected_bad_sig trace (job_id = step_id)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db, (await genHubKey()).privateKeyB64);
    const { ws } = await connectAndHello(hub, state, key);
    await hub.webSocketMessage(
      ws,
      await signedMsg(
        key,
        "dev-1",
        "STEP_RESULT",
        JSON.stringify({ step_id: "job-1", ok: false, summary: "Hub signature verify fail — step rejected" }),
      ),
    );
    const traces = (await db.prepare("SELECT * FROM traces").bind().all()).results as Record<string, unknown>[];
    const bad = traces.filter((t) => t.kind === "step_rejected_bad_sig");
    expect(bad.length).toBe(1);
    expect(JSON.parse(String(bad[0].detail))).toMatchObject({ job_id: "job-1" });
  });

  it("STEP_RESULT normal ok -> no step_rejected_bad_sig trace", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db, (await genHubKey()).privateKeyB64);
    const { ws } = await connectAndHello(hub, state, key);
    await hub.webSocketMessage(
      ws,
      await signedMsg(
        key,
        "dev-1",
        "STEP_RESULT",
        JSON.stringify({ step_id: "job-1", ok: true, summary: "Task finished" }),
      ),
    );
    const traces = (await db.prepare("SELECT * FROM traces").bind().all()).results as Record<string, unknown>[];
    expect(traces.some((t) => t.kind === "step_rejected_bad_sig")).toBe(false);
    expect(traces.some((t) => t.kind === "step_result")).toBe(true);
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
