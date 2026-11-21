/**
 * Router tests (Phase 3, stage 3a) — D11 brief §9 R-T1–R-T10 + additions
 * R-T11 turn-complete/reply counting · R-T12 keyvault round-trip ·
 * R-T13 env-config chains · R-T14 admin key-set route · R-T15 embeddings ·
 * R-T16 hub /api/llm/route mapping · R-T17 live kind refused by design.
 * Gemini upstream is MOCKED (no real key in CI). Live happy-path proof
 * needs a test BYOK key (parent-side, U-1) — see AUDIT_3a.md.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { handleRequest, type Env } from "../src/hub";
import {
  MODEL_25,
  MODEL_31,
  MODEL_35,
  completeTurn,
  loadRouterConfig,
  resetCircuitBreakers,
  routeLlm,
  type ChatMessage,
  type RouterDeps,
} from "../src/router";
import { currentPeriod } from "../src/metering";
import { bytesToBase64 } from "../src/crypto";
import { decryptTenantKey, encryptTenantKey, importMasterKey } from "../src/keyvault";

const FIXED_NOW = Date.UTC(2026, 10, 21, 12, 0, 0);
const PERIOD = "2026-11";

async function makeMasterKeyB64(): Promise<string> {
  const k = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
  return bytesToBase64(raw);
}

async function seedTenant(
  db: FakeD1,
  opts: { id: string; plan?: string; billingMode?: string; keyEnc?: string | null },
): Promise<void> {
  await db
    .prepare("INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(opts.id, `${opts.id}@example.com`, opts.plan ?? "pro", opts.billingMode ?? "byok", opts.keyEnc ?? null, FIXED_NOW)
    .run();
}

async function seedTenantWithKey(db: FakeD1, id: string, masterB64: string, key = "TEST-GEMINI-KEY-1", plan = "pro"): Promise<void> {
  const master = await importMasterKey(masterB64);
  const enc = await encryptTenantKey(master, key);
  await seedTenant(db, { id, plan, keyEnc: enc });
}

function seedUsage(db: FakeD1, tenantId: string, replies: number): Promise<void> {
  return db
    .prepare("INSERT INTO usage_counters (tenant_id, period, replies, e2b_runs, llm_calls, input_tokens, output_tokens, cost_usd_micro) VALUES (?, ?, ?, 0, 0, 0, 0, 0)")
    .bind(tenantId, PERIOD, replies)
    .run() as unknown as Promise<void>;
}

type MockBehaviour = (model: string, callNo: number) => Response;

function okText(text: string, inTok = 100, outTok = 20): Response {
  return new Response(
    JSON.stringify({
      candidates: [{ content: { parts: [{ text }] }, finishReason: "STOP" }],
      usageMetadata: { promptTokenCount: inTok, candidatesTokenCount: outTok },
    }),
    { status: 200 },
  );
}

function errResp(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: { code: status, message } }), { status });
}

function makeMockFetch(behaviour: MockBehaviour): { fetchFn: typeof fetch; calls: { model: string; url: string; body: string }[] } {
  const calls: { model: string; url: string; body: string }[] = [];
  let n = 0;
  const fetchFn = (async (url: unknown, init?: { body?: unknown }) => {
    const u = String(url);
    const m = u.match(/models\/([^:]+):/)?.[1] ?? "unknown";
    calls.push({ model: m, url: u, body: String(init?.body ?? "") });
    return behaviour(m, ++n);
  }) as unknown as typeof fetch;
  return { fetchFn, calls };
}

function baseDeps(db: FakeD1, masterB64: string, fetchFn: typeof fetch, extra: Partial<RouterDeps> = {}): RouterDeps {
  return {
    db,
    fetchFn,
    sleepFn: async () => {},
    nowMs: () => FIXED_NOW,
    masterKeyB64: masterB64,
    ...extra,
  };
}

function req(tenantId: string, turnId: string, kind: "agent_plan" | "quick_command" | "casual_chat" | "search_grounding" | "live" | "doc_extraction" | "embeddings" = "quick_command", messages: ChatMessage[] = [{ role: "user", text: "hello" }]) {
  return { tenant_id: tenantId, turn_id: turnId, kind, messages };
}

async function usageRows(db: FakeD1): Promise<Record<string, unknown>[]> {
  return (await db.prepare("SELECT * FROM llm_usage").all()).results as Record<string, unknown>[];
}

async function traceRows(db: FakeD1): Promise<Record<string, unknown>[]> {
  return (await db.prepare("SELECT * FROM traces").all()).results as Record<string, unknown>[];
}

beforeEach(() => {
  resetCircuitBreakers();
  vi.unstubAllGlobals();
});

describe("router fallback + metering (R-T1–R-T10)", () => {
  it("R-T1 BYOK fallback order: 3.5 fails 429 -> 3.1 serves", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const { fetchFn, calls } = makeMockFetch((model) =>
      model === MODEL_35 ? errResp(429, "Resource exhausted") : okText("from 3.1", 100, 20),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-1", "turn-1"));
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_31);
    expect(res.attempted_models).toEqual([MODEL_35, MODEL_31]);
    expect(res.status).toBe("fallback_used");
    expect(calls.map((c) => c.model)).toEqual([MODEL_35, MODEL_31]);
    const rows = await usageRows(db);
    expect(rows).toHaveLength(1);
    expect(JSON.parse(String(rows[0].attempted_models))).toEqual([MODEL_35, MODEL_31]);
    // 100 in * 0.25 + 20 out * 1.50 = 25 + 30 = 55 micro
    expect(rows[0].cost_usd_micro).toBe(55);
  });

  it("R-T2 founder-pays fallback order: 2.5 fails -> 3.1 serves, 3.5 never tried", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenant(db, { id: "t-2", billingMode: "founder_pays" });
    const { fetchFn, calls } = makeMockFetch((model) =>
      model === MODEL_25 ? errResp(500, "boom") : okText("from 3.1", 100, 20),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn, { founderKey: "FOUNDER-TEST-KEY" }), req("t-2", "turn-2"));
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_31);
    expect(res.attempted_models).toEqual([MODEL_25, MODEL_31]);
    expect(calls.map((c) => c.model)).not.toContain(MODEL_35);
  });

  it("R-T3 cap breach -> hard refuse, no upstream call, refused_cap row", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-3", master, "TEST-KEY", "free"); // free = 100 replies
    await seedUsage(db, "t-3", 100);
    const { fetchFn, calls } = makeMockFetch(() => okText("x"));
    const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-3", "turn-3"));
    expect(res.ok).toBe(false);
    expect(res.error_code).toBe("replies_cap");
    expect(calls).toHaveLength(0);
    const rows = await usageRows(db);
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("refused_cap");
    const counters = await db.prepare("SELECT llm_calls FROM usage_counters WHERE tenant_id = ? AND period = ?").bind("t-3", PERIOD).first<{ llm_calls: number }>();
    expect(counters?.llm_calls).toBe(0); // refused calls do not count
  });

  it("R-T4 5k token cap: 20k-token history truncates, truncated metered", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-4", master);
    const longText = "x".repeat(80_000); // ~20k tokens
    const messages: ChatMessage[] = [
      { role: "user", text: "old turn 1" },
      { role: "model", text: "old answer 1" },
      { role: "user", text: longText },
      { role: "model", text: "recent answer" },
      { role: "user", text: "latest question" },
    ];
    const { fetchFn, calls } = makeMockFetch(() => okText("ok", 4000, 10));
    const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-4", "turn-4", "quick_command", messages));
    expect(res.ok).toBe(true);
    expect(res.truncated).toBe(true);
    const sent = JSON.parse(calls[0].body) as { contents: { parts: { text: string }[] }[] };
    const sentChars = sent.contents.reduce((n, c) => n + c.parts.reduce((m, p) => m + p.text.length, 0), 0);
    expect(sentChars).toBeLessThanOrEqual(21_000); // ~5000 tokens * 4 chars + margin
    // Latest question survives intact (last 2 turns kept).
    expect(sent.contents[sent.contents.length - 1].parts[0].text).toBe("latest question");
  });

  it("R-T5 5 calls/turn cap: 6th call never happens", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-5", master);
    for (let i = 0; i < 5; i++) {
      await db
        .prepare("INSERT INTO llm_usage (tenant_id, turn_id, model, attempted_models, input_tokens, output_tokens, cost_usd_micro, billing_mode, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind("t-5", "turn-5", MODEL_25, "[]", 10, 5, 3, "byok", "ok", FIXED_NOW)
        .run();
    }
    const { fetchFn, calls } = makeMockFetch(() => okText("x"));
    const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-5", "turn-5"));
    expect(res.ok).toBe(false);
    expect(res.error_code).toBe("turn_calls_cap");
    expect(calls).toHaveLength(0);
  });

  it("R-T6 3.8 FL never default + config with 3.8 throws", async () => {
    expect(() => loadRouterConfig({ ROUTER_CONFIG: JSON.stringify({ chains: { byok: { quick_command: ["gemini-3.8-flash"] } } }) })).toThrow(/3\.8/);
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenant(db, { id: "t-6", billingMode: "founder_pays" });
    const { fetchFn, calls } = makeMockFetch(() => okText("x", 10, 5));
    for (const kind of ["agent_plan", "quick_command", "casual_chat", "search_grounding", "doc_extraction"] as const) {
      const res = await routeLlm(baseDeps(db, master, fetchFn, { founderKey: "FOUNDER-TEST-KEY" }), req("t-6", `turn-6-${kind}`, kind));
      expect(res.ok).toBe(true);
    }
    expect(calls.map((c) => c.model).join(" ")).not.toContain("3.8");
  });

  it("R-T7 metering accuracy: 10 calls, D1 sum == usageMetadata sum, rollup matches", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-7", master);
    const { fetchFn } = makeMockFetch(() => okText("x", 100, 20));
    let expectedIn = 0;
    let expectedOut = 0;
    let expectedCost = 0;
    for (let i = 0; i < 10; i++) {
      const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-7", `turn-7-${i}`));
      expect(res.ok).toBe(true);
      expectedIn += 100;
      expectedOut += 20;
      expectedCost += 100 * 0.3 + 20 * 2.5; // 3.5 FL prices: 30 + 50 = 80 micro/call
    }
    const rows = await usageRows(db);
    expect(rows).toHaveLength(10);
    const sum = (col: string) => rows.reduce((n, r) => n + Number(r[col]), 0);
    expect(sum("input_tokens")).toBe(expectedIn);
    expect(sum("output_tokens")).toBe(expectedOut);
    expect(sum("cost_usd_micro")).toBe(expectedCost);
    const counters = await db.prepare("SELECT * FROM usage_counters WHERE tenant_id = ? AND period = ?").bind("t-7", PERIOD).first<Record<string, number>>();
    expect(counters?.llm_calls).toBe(10);
    expect(counters?.input_tokens).toBe(expectedIn);
    expect(counters?.output_tokens).toBe(expectedOut);
    expect(counters?.cost_usd_micro).toBe(expectedCost);
  });

  it("R-T8 BYOK no-key refuse: byok_required, founder quota untouched", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenant(db, { id: "t-8" }); // no key
    const { fetchFn, calls } = makeMockFetch(() => okText("x"));
    const res = await routeLlm(baseDeps(db, master, fetchFn, { founderKey: "FOUNDER-TEST-KEY" }), req("t-8", "turn-8"));
    expect(res.ok).toBe(false);
    expect(res.error_code).toBe("byok_required");
    expect(calls).toHaveLength(0); // founder key was NOT used
  });

  it("R-T9 circuit breaker: 5 failures -> 6th call skips straight to next model", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-9", master);
    const { fetchFn, calls } = makeMockFetch((model) =>
      model === MODEL_35 ? errResp(429, "Resource exhausted") : okText("from 3.1", 10, 5),
    );
    for (let i = 0; i < 5; i++) {
      const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-9", `turn-9-${i}`));
      expect(res.model).toBe(MODEL_31);
    }
    const before = calls.length;
    const res6 = await routeLlm(baseDeps(db, master, fetchFn), req("t-9", "turn-9-5"));
    expect(res6.ok).toBe(true);
    expect(res6.attempted_models[0]).toBe(MODEL_31); // 3.5 skipped by breaker
    expect(calls.slice(before).map((c) => c.model)).toEqual([MODEL_31]);
    const traces = await traceRows(db);
    expect(traces.some((t) => t.kind === "router_circuit_break")).toBe(true);
  });

  it("R-T10 PII leak check: prompts never land in llm_usage or traces", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-10", master);
    const marker = "PII-MARKER-98765-XYZ";
    const { fetchFn } = makeMockFetch(() => okText("ok", 50, 10));
    for (let i = 0; i < 5; i++) {
      await routeLlm(baseDeps(db, master, fetchFn), req("t-10", `turn-10-${i}`, "quick_command", [
        { role: "user", text: `mera number ${marker} hai, madad karo` },
      ]));
    }
    const dump = JSON.stringify([...(await usageRows(db)), ...(await traceRows(db))]);
    expect(dump).not.toContain(marker);
    expect(dump).not.toContain("TEST-GEMINI-KEY-1"); // key never metered either
  });
});

describe("router additions (R-T11–R-T17)", () => {
  it("R-T11 turn-complete: success turn = 1 reply, failed turn = 0, calls metered", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-11", master);
    const { fetchFn } = makeMockFetch(() => okText("x", 10, 5));
    const ok = await routeLlm(baseDeps(db, master, fetchFn), req("t-11", "turn-11-ok"));
    expect(ok.ok).toBe(true);
    await completeTurn(db, "t-11", "turn-11-ok", true);
    const { fetchFn: failFetch } = makeMockFetch(() => errResp(500, "boom"));
    const bad = await routeLlm(baseDeps(db, master, failFetch), req("t-11", "turn-11-bad"));
    expect(bad.ok).toBe(false);
    await completeTurn(db, "t-11", "turn-11-bad", false);
    const counters = await db.prepare("SELECT * FROM usage_counters WHERE tenant_id = ? AND period = ?").bind("t-11", currentPeriod(FIXED_NOW)).first<Record<string, number>>();
    expect(counters?.replies).toBe(1);
    expect(counters?.llm_calls).toBe(2); // both turns' calls metered
  });

  it("R-T12 keyvault round-trip + wrong master key fails closed", async () => {
    const masterB64 = await makeMasterKeyB64();
    const master = await importMasterKey(masterB64);
    const enc = await encryptTenantKey(master, "MY-SECRET-KEY");
    expect(await decryptTenantKey(master, enc)).toBe("MY-SECRET-KEY");
    const otherB64 = await makeMasterKeyB64();
    const other = await importMasterKey(otherB64);
    await expect(decryptTenantKey(other, enc)).rejects.toThrow();
    await expect(importMasterKey(bytesToBase64(new Uint8Array(16)))).rejects.toThrow(/32 bytes/);
  });

  it("R-T13 chains + prices come from env config (override wins)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-13", master);
    const config = loadRouterConfig({
      ROUTER_CONFIG: JSON.stringify({ chains: { byok: { quick_command: [MODEL_25, MODEL_31] } } }),
    });
    const { fetchFn, calls } = makeMockFetch(() => okText("from 2.5", 100, 20));
    const res = await routeLlm(baseDeps(db, master, fetchFn, { config }), req("t-13", "turn-13"));
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_25);
    expect(calls[0].model).toBe(MODEL_25);
  });

  it("R-T15 embeddings kind: gemini-embedding-001, cost at embed price", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-15", master);
    const { fetchFn } = makeMockFetch((model) => {
      if (model === "gemini-embedding-001") {
        return new Response(JSON.stringify({ embedding: { values: [0.1, 0.2, 0.3] }, usageMetadata: { promptTokenCount: 10 } }), { status: 200 });
      }
      return errResp(404, "not found");
    });
    const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-15", "turn-15", "embeddings", [{ role: "user", text: "skill search text" }]));
    expect(res.ok).toBe(true);
    expect(res.embedding).toEqual([0.1, 0.2, 0.3]);
    expect(res.input_tokens).toBe(10);
    expect(res.output_tokens).toBe(0);
    // 10 in * 0.15 = 1.5 -> round 2 micro
    expect(res.cost_usd_micro).toBe(2);
  });

  it("R-T17 live kind is refused by design (native-audio needs the Live API)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-17", master);
    const { fetchFn, calls } = makeMockFetch(() => okText("x"));
    const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-17", "turn-17", "live"));
    expect(res.ok).toBe(false);
    expect(res.error_code).toBe("live_not_routed");
    expect(calls).toHaveLength(0);
    expect(await usageRows(db)).toHaveLength(0);
  });
});

describe("hub LLM routes (R-T14, R-T16)", () => {
  function fakeEnv(db: FakeD1, overrides: Partial<Env> = {}): Env {
    return {
      JARVIS_HUB: { idFromName: (n: string) => ({ name: n }), get: () => ({ fetch: async () => new Response("{}") }) } as unknown as DurableObjectNamespace,
      DB: db as unknown as D1Database,
      INTERNAL_SECRET: "test-internal",
      CRON_SECRET: "test-cron",
      KEY_ENC_SECRET: "",
      LLM_ADMIN_TOKEN: "test-admin",
      ...overrides,
    };
  }

  it("R-T14 admin key-set: no token -> 401; invalid key -> 400; valid -> 200, key never echoed", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenant(db, { id: "t-14" });
    const noAuth = await handleRequest(
      new Request("https://hub/api/tenants/t-14/key", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ gemini_key: "K" }) }),
      fakeEnv(db, { KEY_ENC_SECRET: master }),
    );
    expect(noAuth.status).toBe(401);

    // Invalid key (mock Gemini 400).
    vi.stubGlobal("fetch", async () => errResp(400, "API key not valid. Please pass a valid API key."));
    const bad = await handleRequest(
      new Request("https://hub/api/tenants/t-14/key", { method: "POST", headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" }, body: JSON.stringify({ gemini_key: "BAD-KEY" }) }),
      fakeEnv(db, { KEY_ENC_SECRET: master }),
    );
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as Record<string, unknown>).error).toBe("invalid_key");

    // Valid key (mock Gemini 200).
    vi.stubGlobal("fetch", async () => okText("hi", 1, 1));
    const good = await handleRequest(
      new Request("https://hub/api/tenants/t-14/key", { method: "POST", headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" }, body: JSON.stringify({ gemini_key: "REAL-TEST-KEY-999" }) }),
      fakeEnv(db, { KEY_ENC_SECRET: master }),
    );
    expect(good.status).toBe(200);
    expect(JSON.stringify(await good.clone().json())).not.toContain("REAL-TEST-KEY-999");
    const status = await handleRequest(new Request("https://hub/api/tenants/t-14/key-status", { headers: { "x-admin-token": "test-admin" } }), fakeEnv(db, { KEY_ENC_SECRET: master }));
    const statusBody = (await status.json()) as Record<string, unknown>;
    expect(statusBody.has_key).toBe(true);
    // Stored value is an encrypted envelope, not the key.
    const tenant = await db.prepare("SELECT gemini_key_enc FROM tenants WHERE id = ?").bind("t-14").first<{ gemini_key_enc: string }>();
    expect(tenant?.gemini_key_enc).not.toContain("REAL-TEST-KEY-999");
    expect(await decryptTenantKey(await importMasterKey(master), tenant!.gemini_key_enc)).toBe("REAL-TEST-KEY-999");
    // DELETE removes it.
    const del = await handleRequest(new Request("https://hub/api/tenants/t-14/key", { method: "DELETE", headers: { "x-admin-token": "test-admin" } }), fakeEnv(db, { KEY_ENC_SECRET: master }));
    expect(del.status).toBe(200);
    const after = await db.prepare("SELECT gemini_key_enc FROM tenants WHERE id = ?").bind("t-14").first<{ gemini_key_enc: string | null }>();
    expect(after?.gemini_key_enc).toBeNull();
  });

  it("R-T16 /api/llm/route: no internal secret -> 401; byok tenant without key -> 402", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-16" });
    const noSecret = await handleRequest(
      new Request("https://hub/api/llm/route", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tenant_id: "t-16", turn_id: "turn-16", kind: "quick_command", messages: [{ role: "user", text: "hi" }] }) }),
      fakeEnv(db),
    );
    expect(noSecret.status).toBe(401);
    const byok = await handleRequest(
      new Request("https://hub/api/llm/route", { method: "POST", headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" }, body: JSON.stringify({ tenant_id: "t-16", turn_id: "turn-16", kind: "quick_command", messages: [{ role: "user", text: "hi" }] }) }),
      fakeEnv(db),
    );
    expect(byok.status).toBe(402);
    expect(((await byok.json()) as Record<string, unknown>).error).toBe("byok_required");
  });
});
