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

describe("JarvisHub DO — 3c captcha assist (D3 human-assist-first)", () => {
  /** Raw CAPTCHA_ASSIST frames on a socket (never wrapped in EXECUTE_STEP). */
  function captchaEvents(fakeWs: FakeWebSocket): Record<string, unknown>[] {
    return fakeWs.sent
      .map((s) => JSON.parse(s) as Record<string, unknown>)
      .filter((m) => m.type === "CAPTCHA_ASSIST");
  }

  async function dispatchCaptchaAssist(
    hub: JarvisHub,
    deviceId: string,
    event: Record<string, unknown>,
    secret = "test-internal",
  ) {
    return await hub.fetch(
      new Request("https://hub/captcha-assist", {
        method: "POST",
        headers: { "x-internal-secret": secret, "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: deviceId, event }),
      }),
    );
  }

  const assistEvent = {
    type: "CAPTCHA_ASSIST",
    task_id: "bt-1",
    site: "example.com",
    task_name: "Fill form",
    screenshot_b64: "aGVsbG8=",
  };

  it("CAPTCHA_ASSIST live socket -> raw event sent, NOT an EXECUTE_STEP", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const { fakeWs } = await connectAndHello(hub, state, key);
    const res = await dispatchCaptchaAssist(hub, "dev-1", assistEvent);
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(true);
    const events = captchaEvents(fakeWs);
    expect(events.length).toBe(1);
    expect(events[0]).toMatchObject({ task_id: "bt-1", site: "example.com", task_name: "Fill form" });
    expect(executeSteps(fakeWs).length).toBe(0);
  });

  it("CAPTCHA_ASSIST wrong secret -> 401; bad event type -> 400", async () => {
    const db = new FakeD1();
    const { hub } = makeHub(db);
    const wrong = await dispatchCaptchaAssist(hub, "dev-1", assistEvent, "wrong");
    expect(wrong.status).toBe(401);
    const bad = await dispatchCaptchaAssist(hub, "dev-1", { type: "EXECUTE_STEP" });
    expect(bad.status).toBe(400);
  });

  it("CAPTCHA_ASSIST offline -> queued as marked row, flushed RAW on HELLO (C-T9)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const res = await dispatchCaptchaAssist(hub, "dev-1", assistEvent);
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(false);
    const queued = state.sql.exec("SELECT * FROM pending_steps").toArray();
    expect(queued.length).toBe(1);
    expect(String(queued[0].payload)).toContain("__captcha_assist__");
    const { fakeWs } = await connectAndHello(hub, state, key);
    const events = captchaEvents(fakeWs);
    expect(events.length).toBe(1);
    expect(events[0].task_id).toBe("bt-1");
    // Flushed as a raw event — never signed/executed as a step.
    expect(executeSteps(fakeWs).length).toBe(0);
    expect(state.sql.exec("SELECT * FROM pending_steps").toArray().length).toBe(0);
  });

  it("CAPTCHA_ASSIST unauthenticated socket -> queued, never sent live", async () => {
    const db = new FakeD1();
    const { hub, state } = makeHub(db);
    await hub.fetch(
      new Request("https://hub/ws/dev-1", {
        headers: { Upgrade: "websocket", "x-expected-device": "dev-1" },
      }),
    );
    const fakeWs = state.accepted[0];
    const res = await dispatchCaptchaAssist(hub, "dev-1", assistEvent);
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(false);
    expect(fakeWs.sent.length).toBe(0);
    expect(state.sql.exec("SELECT * FROM pending_steps").toArray().length).toBe(1);
  });

  it("CAPTCHA_DETECTED signed -> task row awaiting_user + captcha_assist trace", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const { ws, fakeWs } = await connectAndHello(hub, state, key);
    await hub.webSocketMessage(
      ws,
      await signedMsg(
        key,
        "dev-1",
        "CAPTCHA_DETECTED",
        JSON.stringify({ task_id: "bt-9", site: "example.com", task_name: "Fill form" }),
      ),
    );
    const parsed = fakeWs.sent.map((s) => JSON.parse(s) as Record<string, unknown>);
    expect(parsed.some((m) => m.type === "ACK" && m.id === "bt-9")).toBe(true);
    const rows = await db.prepare("SELECT * FROM browser_tasks WHERE id = ?").bind("bt-9").all();
    expect(rows.results.length).toBe(1);
    const row = rows.results[0] as Record<string, unknown>;
    expect(row.status).toBe("awaiting_user");
    expect(row.assist_count).toBe(1);
    expect(row.provider).toBe("phone_webview");
    const traces = (await db.prepare("SELECT * FROM traces").bind().all()).results as Record<string, unknown>[];
    const assist = traces.filter((t) => t.kind === "captcha_assist");
    expect(assist.length).toBe(1);
    expect(JSON.parse(String(assist[0].detail))).toMatchObject({
      task_id: "bt-9",
      outcome: "requested",
      assist_count: 1,
    });
  });

  it("CAPTCHA_DETECTED 4th time -> cap, task paused (C-T5, device path)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const { ws } = await connectAndHello(hub, state, key);
    for (let i = 0; i < 4; i++) {
      await hub.webSocketMessage(
        ws,
        await signedMsg(
          key,
          "dev-1",
          "CAPTCHA_DETECTED",
          JSON.stringify({ task_id: "bt-cap", site: "example.com", task_name: "T" }),
        ),
      );
    }
    const rows = await db.prepare("SELECT * FROM browser_tasks WHERE id = ?").bind("bt-cap").all();
    const row = rows.results[0] as Record<string, unknown>;
    expect(row.assist_count).toBe(3);
    expect(row.status).toBe("paused");
    const traces = (await db.prepare("SELECT * FROM traces").bind().all()).results as Record<string, unknown>[];
    expect(
      traces.some(
        (t) =>
          t.kind === "captcha_assist" &&
          JSON.parse(String(t.detail)).outcome === "cap_reached",
      ),
    ).toBe(true);
  });

  it("CAPTCHA_RESOLVED solved -> task running + trace solved:true (C-T3)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const { ws } = await connectAndHello(hub, state, key);
    await hub.webSocketMessage(
      ws,
      await signedMsg(
        key,
        "dev-1",
        "CAPTCHA_DETECTED",
        JSON.stringify({ task_id: "bt-10", site: "example.com", task_name: "T" }),
      ),
    );
    await hub.webSocketMessage(
      ws,
      await signedMsg(
        key,
        "dev-1",
        "CAPTCHA_RESOLVED",
        JSON.stringify({ task_id: "bt-10", site: "example.com", solved: true, duration_s: 12 }),
      ),
    );
    const rows = await db.prepare("SELECT * FROM browser_tasks WHERE id = ?").bind("bt-10").all();
    expect((rows.results[0] as Record<string, unknown>).status).toBe("running");
    const traces = (await db.prepare("SELECT * FROM traces").bind().all()).results as Record<string, unknown>[];
    const resolved = traces.filter(
      (t) => t.kind === "captcha_assist" && JSON.parse(String(t.detail)).outcome === "solved",
    );
    expect(resolved.length).toBe(1);
    expect(JSON.parse(String(resolved[0].detail))).toMatchObject({ solved: true, duration_s: 12 });
  });

  it("CAPTCHA_RESOLVED with a solution field -> solution NEVER traced/stored (C-T8)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const { ws } = await connectAndHello(hub, state, key);
    await hub.webSocketMessage(
      ws,
      await signedMsg(
        key,
        "dev-1",
        "CAPTCHA_DETECTED",
        JSON.stringify({ task_id: "bt-11", site: "example.com", task_name: "T" }),
      ),
    );
    await hub.webSocketMessage(
      ws,
      await signedMsg(
        key,
        "dev-1",
        "CAPTCHA_RESOLVED",
        JSON.stringify({
          task_id: "bt-11",
          site: "example.com",
          solved: true,
          duration_s: 9,
          solution: "SECRET-SOLUTION-abc123",
          token: "SECRET-TOKEN-xyz",
          screenshot_b64: "aGVsbG8=",
        }),
      ),
    );
    const traces = (await db.prepare("SELECT * FROM traces").bind().all()).results as Record<string, unknown>[];
    const allDetail = traces.map((t) => String(t.detail)).join("\n");
    expect(allDetail).not.toContain("SECRET-SOLUTION-abc123");
    expect(allDetail).not.toContain("SECRET-TOKEN-xyz");
    expect(allDetail).not.toContain("screenshot");
    const rows = await db.prepare("SELECT * FROM browser_tasks WHERE id = ?").bind("bt-11").all();
    expect((rows.results[0] as Record<string, unknown>).status).toBe("running");
  });

  it("CAPTCHA_RESOLVED timeout -> task paused, never failed (C-T2)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const { ws } = await connectAndHello(hub, state, key);
    await hub.webSocketMessage(
      ws,
      await signedMsg(
        key,
        "dev-1",
        "CAPTCHA_DETECTED",
        JSON.stringify({ task_id: "bt-12", site: "example.com", task_name: "T" }),
      ),
    );
    await hub.webSocketMessage(
      ws,
      await signedMsg(
        key,
        "dev-1",
        "CAPTCHA_RESOLVED",
        JSON.stringify({ task_id: "bt-12", site: "example.com", solved: false, duration_s: 60 }),
      ),
    );
    const rows = await db.prepare("SELECT * FROM browser_tasks WHERE id = ?").bind("bt-12").all();
    expect((rows.results[0] as Record<string, unknown>).status).toBe("paused");
  });

  it("CAPTCHA_DETECTED bad signature -> close 4401 (signed path enforced)", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    const otherKey = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const { ws, fakeWs } = await connectAndHello(hub, state, key);
    await hub.webSocketMessage(
      ws,
      await signedMsg(
        otherKey,
        "dev-1",
        "CAPTCHA_DETECTED",
        JSON.stringify({ task_id: "bt-13", site: "example.com", task_name: "T" }),
      ),
    );
    expect(fakeWs.closed?.code).toBe(4401);
  });

  it("unknown WS type still -> close 4400", async () => {
    const db = new FakeD1();
    const { hub, state } = makeHub(db);
    await hub.fetch(
      new Request("https://hub/ws/dev-1", {
        headers: { Upgrade: "websocket", "x-expected-device": "dev-1" },
      }),
    );
    const ws = state.accepted[0] as unknown as WebSocket;
    const fakeWs = state.accepted[0];
    await hub.webSocketMessage(ws, JSON.stringify({ type: "NOPE" }));
    expect(fakeWs.closed?.code).toBe(4400);
  });
});
