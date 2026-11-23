/**
 * R2 tests (hub v18) — Trained Jarvis + shared memory + admin training.
 *
 * R2.3 /api/admin/train (admin-only) + Main run-start recall.
 * R2.4 GET /api/memory/list (pull) + WS memory_push (DO) + FCM fallback.
 * R2.2 sync tables "memories" + "events".
 * R2.5 cap 2000 (full FIFO proof lives in memory.test.ts S-T11).
 * R2.6 Jarvis Store is app-side (JarvisStoreTest, R1-pattern) — not here.
 *
 * Gemini embeddings are MOCKED (keyword -> fixed vector; no real key).
 * Live happy-path proof needs the parent-side live verify (BUILD_NOTES).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { FakeDOState, type FakeWebSocket } from "./fake-do";
import { JarvisHub } from "../src/do/JarvisHub";
import { genDeviceKey, type DeviceKey } from "./helpers";
import { handleRequest, type Env } from "../src/hub";
import { canonicalString } from "../src/crypto";
import { sortedJson } from "../src/docs";
import { encryptTenantKey, importMasterKey } from "../src/keyvault";
import { bytesToBase64 } from "../src/crypto";
import { resetRateLimitFallback } from "../src/ratelimit";
import { handleSync, type SyncRequest } from "../src/sync";
import { registerDevice } from "../src/pairing";
import { loadRouterConfig } from "../src/router";
import { MEMORY_CAP_PER_TENANT } from "../src/memory";
import { formatMainRecall, loadMainRecall } from "../src/main";

const FIXED_NOW = Date.UTC(2026, 11, 23, 14, 0, 0);
const ADMIN = { "x-admin-token": "test-admin" };
const INTERNAL = { "x-internal-secret": "test-internal" };

beforeEach(() => {
  resetRateLimitFallback();
});

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
    LLM_ADMIN_TOKEN: "test-admin",
    ...overrides,
  };
}

async function makeMasterKeyB64(): Promise<string> {
  const k = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
  return bytesToBase64(raw);
}

async function seedTenant(db: FakeD1, id: string, keyEnc: string | null = null): Promise<void> {
  await db
    .prepare(
      "INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id, `${id}@example.com`, "pro", "byok", keyEnc, 0, FIXED_NOW)
    .run();
}

async function seedTenantWithKey(db: FakeD1, id: string, masterB64: string): Promise<void> {
  const master = await importMasterKey(masterB64);
  const enc = await encryptTenantKey(master, "TEST-GEMINI-KEY-1");
  await seedTenant(db, id, enc);
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string, publicKeyB64: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, publicKeyB64, FIXED_NOW, FIXED_NOW, 1)
    .run();
}

/** Combined fetch stub: Gemini embedContent + train URL docs. */
function stubFetch(): void {
  vi.stubGlobal(
    "fetch",
    async (url: unknown, init?: { body?: unknown }) => {
      const u = String(url);
      if (u.includes("generativelanguage.googleapis.com") && u.includes(":embedContent")) {
        const parsed = JSON.parse(String(init?.body ?? "{}")) as {
          content?: { parts?: Array<{ text?: string }> };
        };
        const text = parsed.content?.parts?.[0]?.text ?? "";
        let values: number[];
        if (/\bcat/i.test(text)) values = [1, 0];
        else if (/\bdog/i.test(text)) values = [0, 1];
        else values = [0.7071, 0.7071];
        return new Response(
          JSON.stringify({ embedding: { values }, usageMetadata: { promptTokenCount: 5 } }),
          { status: 200 },
        );
      }
      if (u === "https://example.com/article") {
        return new Response(
          "<html><head><title>T</title><style>.x{}</style></head><body><h1>Chai recipe</h1><p>Boil water with ginger and cardamom.</p><script>evil()</script></body></html>",
          { status: 200, headers: { "Content-Type": "text/html" } },
        );
      }
      if (u === "https://example.com/plain.txt") {
        return new Response("Plain training text about monsoon.", {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        });
      }
      return new Response(JSON.stringify({ error: "unexpected fetch " + u }), { status: 500 });
    },
  );
}

async function postJson(
  env: Env,
  path: string,
  body: Record<string, unknown>,
  headers: Record<string, string> = INTERNAL,
): Promise<Response> {
  return handleRequest(
    new Request(`https://hub${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
    }),
    env,
  );
}

async function signedListHeaders(key: DeviceKey, deviceId: string, payloadRaw: string) {
  const nonce = "aabbccddeeff00112233445566778899";
  const ts = Date.now();
  const sig = await key.sign(canonicalString(deviceId, nonce, ts, payloadRaw));
  return { "x-device-id": deviceId, "x-nonce": nonce, "x-ts": String(ts), "x-signature": sig };
}

// --- R2.3: /api/admin/train ---

describe("R2.3 POST /api/admin/train", () => {
  it("no admin token -> 401; unknown tenant -> 404; empty body -> 400", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    stubFetch();
    const env = fakeEnv(db, { KEY_ENC_SECRET: master });
    const noAuth = await postJson(env, "/api/admin/train", { tenant_id: "t-1", instructions: [{ text: "x" }] }, {});
    expect(noAuth.status).toBe(401);
    const noTenant = await postJson(env, "/api/admin/train", { tenant_id: "ghost", instructions: [{ text: "x" }] }, ADMIN);
    expect(noTenant.status).toBe(404);
    const empty = await postJson(env, "/api/admin/train", { tenant_id: "t-1" }, ADMIN);
    expect(empty.status).toBe(400);
  });

  it("text doc + instruction -> patterns_added 1, memories_added 1, D1 rows correct", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    stubFetch();
    const env = fakeEnv(db, { KEY_ENC_SECRET: master });
    const res = await postJson(
      env,
      "/api/admin/train",
      {
        tenant_id: "t-1",
        documents: [{ title: "Chai", text: "Chai needs ginger and cardamom." }],
        instructions: [{ text: "User likes ginger chai." }],
      },
      ADMIN,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(body.patterns_added).toBe(1);
    expect(body.memories_added).toBe(1);
    expect((body.push as Record<string, unknown>).devices).toBe(1);
    const pattern = await db
      .prepare("SELECT * FROM learned_patterns WHERE template = ?")
      .bind("User likes ginger chai.")
      .first<Record<string, unknown>>();
    expect(pattern).not.toBeNull();
    expect(pattern?.source).toBe("admin");
    expect(pattern?.approved).toBe(1);
    const memory = await db
      .prepare("SELECT * FROM memories WHERE tenant_id = ?")
      .bind("t-1")
      .first<Record<string, unknown>>();
    expect(memory?.kind).toBe("admin_training");
    expect(String(memory?.content)).toContain("ginger");
  });

  it("same instruction twice -> use_count bumps to 2 (upsert, no duplicate row)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    stubFetch();
    const env = fakeEnv(db, { KEY_ENC_SECRET: master });
    const payload = { tenant_id: "t-1", instructions: [{ text: "User likes ginger chai." }] };
    expect((await postJson(env, "/api/admin/train", payload, ADMIN)).status).toBe(200);
    expect((await postJson(env, "/api/admin/train", payload, ADMIN)).status).toBe(200);
    const rows = await db.prepare("SELECT * FROM learned_patterns").bind().all();
    expect(rows.results.length).toBe(1);
    expect((rows.results[0] as Record<string, unknown>).use_count).toBe(2);
  });

  it("URL doc (HTML) -> tags stripped, text stored; blocked hosts -> 400", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    stubFetch();
    const env = fakeEnv(db, { KEY_ENC_SECRET: master });
    const res = await postJson(
      env,
      "/api/admin/train",
      { tenant_id: "t-1", documents: [{ title: "Recipe", url: "https://example.com/article" }] },
      ADMIN,
    );
    expect(res.status).toBe(200);
    const memory = await db
      .prepare("SELECT * FROM memories WHERE tenant_id = ?")
      .bind("t-1")
      .first<Record<string, unknown>>();
    expect(String(memory?.content)).toContain("Boil water with ginger and cardamom");
    expect(String(memory?.content)).not.toContain("<h1>");
    expect(String(memory?.content)).not.toContain("evil()");
    const http = await postJson(
      env,
      "/api/admin/train",
      { tenant_id: "t-1", documents: [{ url: "http://example.com/article" }] },
      ADMIN,
    );
    expect(http.status).toBe(400);
    expect(((await http.json()) as Record<string, unknown>).error).toBe("https_only");
    const local = await postJson(
      env,
      "/api/admin/train",
      { tenant_id: "t-1", documents: [{ url: "https://localhost:8080/x" }] },
      ADMIN,
    );
    expect(local.status).toBe(400);
    expect(((await local.json()) as Record<string, unknown>).error).toBe("blocked_host");
  });

  it("too many documents -> 400; empty instruction -> 400", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    stubFetch();
    const env = fakeEnv(db, { KEY_ENC_SECRET: master });
    const docs = Array.from({ length: 11 }, (_, i) => ({ title: `d${i}`, text: "x" }));
    const many = await postJson(env, "/api/admin/train", { tenant_id: "t-1", documents: docs }, ADMIN);
    expect(many.status).toBe(400);
    const emptyInst = await postJson(env, "/api/admin/train", { tenant_id: "t-1", instructions: [{ text: "  " }] }, ADMIN);
    expect(emptyInst.status).toBe(400);
  });
});

// --- R2.4: GET /api/memory/list ---

describe("R2.4 GET /api/memory/list", () => {
  async function seedMemoryList(db: FakeD1): Promise<void> {
    await db
      .prepare("INSERT INTO memories (tenant_id, content, embedding, kind, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind("t-1", "old fact", JSON.stringify([1, 0]), "fact", FIXED_NOW)
      .run();
    await db
      .prepare("INSERT INTO memories (tenant_id, content, embedding, kind, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind("t-1", "admin fact", JSON.stringify([0, 1]), "admin_training", FIXED_NOW + 1000)
      .run();
    await db
      .prepare("INSERT INTO learned_patterns (id, template_hash, template, use_count, first_seen, last_seen, approved, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .bind("pat-1", "h1", "Admin says chai at 4pm.", 3, FIXED_NOW, FIXED_NOW, 1, "admin")
      .run();
    await db
      .prepare("INSERT INTO learned_patterns (id, template_hash, template, use_count, first_seen, last_seen, approved, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .bind("pat-2", "h2", "User prefers text replies.", 9, FIXED_NOW, FIXED_NOW, 1, "user")
      .run();
  }

  it("x-internal-secret -> memories newest-first + patterns admin-first; since filters", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    await seedMemoryList(db);
    const env = fakeEnv(db);
    const res = await handleRequest(
      new Request("https://hub/api/memory/list?tenant_id=t-1&since=0&limit=50", {
        method: "GET",
        headers: INTERNAL,
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    const memories = body.memories as Array<Record<string, unknown>>;
    expect(memories.length).toBe(2);
    expect(memories[0].content).toBe("admin fact");
    const patterns = body.patterns as Array<Record<string, unknown>>;
    expect(patterns.length).toBe(2);
    expect(patterns[0].source).toBe("admin");
    const sinceRes = await handleRequest(
      new Request(`https://hub/api/memory/list?tenant_id=t-1&since=${FIXED_NOW + 500}&limit=50`, {
        method: "GET",
        headers: INTERNAL,
      }),
      env,
    );
    const sinceBody = (await sinceRes.json()) as Record<string, unknown>;
    expect((sinceBody.memories as unknown[]).length).toBe(1);
  });

  it("device-signed -> 200; no auth -> 401; tenant mismatch -> 403", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    await seedTenant(db, "t-2");
    await seedMemoryList(db);
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const env = fakeEnv(db);
    const payload = "memory-list:t-1:0:50";
    const headers = await signedListHeaders(key, "dev-1", payload);
    const ok = await handleRequest(
      new Request("https://hub/api/memory/list?tenant_id=t-1&since=0&limit=50", { method: "GET", headers }),
      env,
    );
    expect(ok.status).toBe(200);
    const noAuth = await handleRequest(
      new Request("https://hub/api/memory/list?tenant_id=t-1&since=0&limit=50", { method: "GET" }),
      env,
    );
    expect(noAuth.status).toBe(401);
    const mismatchPayload = "memory-list:t-2:0:50";
    const mismatchHeaders = await signedListHeaders(key, "dev-1", mismatchPayload);
    const mismatch = await handleRequest(
      new Request("https://hub/api/memory/list?tenant_id=t-2&since=0&limit=50", { method: "GET", headers: mismatchHeaders }),
      env,
    );
    expect(mismatch.status).toBe(403);
  });
});

// --- R2.2: sync tables "memories" + "events" ---

describe("R2.2 sync memories + events", () => {
  async function signedSyncReq(
    key: DeviceKey,
    deviceId: string,
    table: "memories" | "events",
    rows: Record<string, unknown>[],
  ): Promise<SyncRequest> {
    const raw = JSON.stringify(rows);
    const ts = Date.now();
    const nonce = "nonce-" + Math.random().toString(36).slice(2);
    const sig = await key.sign(canonicalString(deviceId, nonce, ts, raw));
    return { device_id: deviceId, table, rows, last_seq: 1, nonce, ts, sig };
  }

  it("memories sync -> embedded + stored in D1; embed failure -> nothing stored", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    stubFetch();
    const embedDeps = { db, masterKeyB64: master, config: loadRouterConfig({}) };
    const rows = [
      { content: "cats are great", kind: "fact" },
      { content: "dogs are loyal", kind: "fact" },
    ];
    const req = await signedSyncReq(key, "dev-1", "memories", rows);
    const res = await handleSync(db, req, JSON.stringify(rows), embedDeps);
    expect(res.ok).toBe(true);
    expect(res.accepted).toBe(2);
    const stored = await db.prepare("SELECT * FROM memories WHERE tenant_id = ?").bind("t-1").all();
    expect(stored.results.length).toBe(2);
    // Embed failure (fetch 500s on the embed endpoint): zero writes.
    vi.stubGlobal("fetch", async () => new Response("oops", { status: 500 }));
    const badRows = [{ content: "never stored", kind: "fact" }];
    const badReq = await signedSyncReq(key, "dev-1", "memories", badRows);
    const badRes = await handleSync(db, badReq, JSON.stringify(badRows), embedDeps);
    expect(badRes.ok).toBe(false);
    expect(badRes.accepted).toBe(0);
    const after = await db.prepare("SELECT * FROM memories WHERE content = ?").bind("never stored").all();
    expect(after.results.length).toBe(0);
  });

  it("events sync -> rows land in jarvis_events", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const rows = [
      { turn: "turn-1", action: "open_app", result: "ok", screen_meaning: "home screen" },
      { turn: "turn-1", action: "search_docs", result: "2 hits", screen_meaning: "trained tab" },
    ];
    const req = await signedSyncReq(key, "dev-1", "events", rows);
    const res = await handleSync(db, req, JSON.stringify(rows));
    expect(res.ok).toBe(true);
    expect(res.accepted).toBe(2);
    const stored = await db.prepare("SELECT * FROM jarvis_events WHERE tenant_id = ?").bind("t-1").all();
    expect(stored.results.length).toBe(2);
    expect((stored.results[0] as Record<string, unknown>).action).toBe("open_app");
  });
});

// --- R2.3: Main run-start recall ---

describe("R2.3 Main run-start recall", () => {
  it("admin patterns first, then user by use_count; admin memories capped at 10", async () => {
    const db = new FakeD1();
    const now = FIXED_NOW;
    const seedPattern = async (id: string, hash: string, template: string, useCount: number, source: string, approved: number) => {
      await db
        .prepare("INSERT INTO learned_patterns (id, template_hash, template, use_count, first_seen, last_seen, approved, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(id, hash, template, useCount, now, now, approved, source)
        .run();
    };
    await seedPattern("p-admin-1", "h-a1", "Admin: deploy only on Fridays.", 1, "admin", 1);
    await seedPattern("p-user-1", "h-u1", "User: short replies.", 50, "user", 1);
    await seedPattern("p-user-2", "h-u2", "User: Hinglish replies.", 5, "user", 1);
    await seedPattern("p-unapproved", "h-u9", "Draft: never use.", 99, "user", 0);
    for (let i = 0; i < 12; i++) {
      await db
        .prepare("INSERT INTO memories (tenant_id, content, embedding, kind, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind("t-1", `admin memory ${i}`, JSON.stringify([1, 0]), "admin_training", now + i)
        .run();
    }
    const recall = await loadMainRecall(db, "t-1");
    expect(recall.patterns.map((p) => p.template)).toEqual([
      "Admin: deploy only on Fridays.",
      "User: short replies.",
      "User: Hinglish replies.",
    ]);
    expect(recall.memories.length).toBe(10);
    expect(recall.memories[0].content).toBe("admin memory 11");
    const formatted = formatMainRecall(recall);
    expect(formatted).toContain("[admin] Admin: deploy only on Fridays.");
    expect(formatted).toContain("Admin training memories:");
  });

  it("empty recall -> empty block", async () => {
    const db = new FakeD1();
    const recall = await loadMainRecall(db, "t-1");
    expect(recall.patterns).toEqual([]);
    expect(recall.memories).toEqual([]);
    expect(formatMainRecall(recall)).toBe("");
  });

  it("cap 2000 constant", () => {
    expect(MEMORY_CAP_PER_TENANT).toBe(2000);
  });
});

// --- R2.4: DO memory-push ---

describe("JarvisHub DO — R2.4 memory_push", () => {
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
    const payloadRaw = JSON.stringify({ hello: true, app_version: "1.17.0" });
    const sig = await key.sign(canonicalString(deviceId, nonce, ts, payloadRaw));
    await hub.webSocketMessage(
      ws,
      JSON.stringify({ type: "HELLO", device_id: deviceId, nonce, ts, sig, payload_raw: payloadRaw }),
    );
    return { ws, fakeWs };
  }

  function memoryEvents(fakeWs: FakeWebSocket): Record<string, unknown>[] {
    return fakeWs.sent
      .map((s) => JSON.parse(s) as Record<string, unknown>)
      .filter((m) => m.type === "MEMORY_PUSH");
  }

  function executeSteps(fakeWs: FakeWebSocket): Record<string, unknown>[] {
    return fakeWs.sent
      .map((s) => JSON.parse(s) as Record<string, unknown>)
      .filter((m) => m.type === "EXECUTE_STEP");
  }

  async function dispatchMemoryPush(hub: JarvisHub, deviceId: string, event: Record<string, unknown>, secret = "test-internal") {
    return await hub.fetch(
      new Request("https://hub/memory-push", {
        method: "POST",
        headers: { "x-internal-secret": secret, "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: deviceId, event }),
      }),
    );
  }

  const pushEvent = {
    type: "MEMORY_PUSH",
    tenant_id: "t-1",
    memory_ids: [11, 12],
    patterns_added: 1,
    at: FIXED_NOW,
  };

  it("MEMORY_PUSH live socket -> raw event sent, NOT an EXECUTE_STEP, no content inside", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const { fakeWs } = await connectAndHello(hub, state, key);
    const res = await dispatchMemoryPush(hub, "dev-1", pushEvent);
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(true);
    const events = memoryEvents(fakeWs);
    expect(events.length).toBe(1);
    expect(events[0]).toMatchObject({ tenant_id: "t-1", memory_ids: [11, 12], patterns_added: 1 });
    expect(JSON.stringify(events[0])).not.toContain("ginger");
    expect(executeSteps(fakeWs).length).toBe(0);
  });

  it("MEMORY_PUSH wrong secret -> 401; bad event type -> 400", async () => {
    const db = new FakeD1();
    const { hub } = makeHub(db);
    const wrong = await dispatchMemoryPush(hub, "dev-1", pushEvent, "wrong");
    expect(wrong.status).toBe(401);
    const bad = await dispatchMemoryPush(hub, "dev-1", { type: "EXECUTE_STEP" });
    expect(bad.status).toBe(400);
  });

  it("MEMORY_PUSH offline -> queued as __memory_push__ row, flushed RAW on HELLO", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const { hub, state } = makeHub(db);
    const res = await dispatchMemoryPush(hub, "dev-1", pushEvent);
    expect(((await res.json()) as Record<string, unknown>).sent).toBe(false);
    const queued = state.sql.exec("SELECT * FROM pending_steps").toArray();
    expect(queued.length).toBe(1);
    expect(String(queued[0].payload)).toContain("__memory_push__");
    const { fakeWs } = await connectAndHello(hub, state, key);
    const events = memoryEvents(fakeWs);
    expect(events.length).toBe(1);
    expect(events[0].memory_ids).toEqual([11, 12]);
    expect(executeSteps(fakeWs).length).toBe(0);
    expect(state.sql.exec("SELECT * FROM pending_steps").toArray().length).toBe(0);
  });
});
