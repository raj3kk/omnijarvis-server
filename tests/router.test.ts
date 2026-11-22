/**
 * Router tests (Phase 3, stage 3a) — D11 brief §9 R-T1–R-T10 + additions
 * R-T11 turn-complete/reply counting · R-T12 keyvault round-trip ·
 * R-T13 env-config chains · R-T14 admin key-set route · R-T15 embeddings ·
 * R-T16 hub /api/llm/route mapping · R-T17 live kind refused by design.
 * R-T18 validation fallback (first live model 404 -> second ok -> true) ·
 * R-T19 retired model never in any chain (config guard).
 * R-T20–R-T26 Groq free fallback leg (R3, 2026-11-22): gpt-oss-120b serves
 * after both Gemini legs fail; skipped with no key; 401/usage/config-guard;
 * hub groq-key routes. OpenRouter is NOT a leg (D8 still OPEN).
 * R-T27–R-T32 captcha_solve kind (D3 LOCKED, 2026-11-22): vision chain
 * 3.5 -> 3.1 -> qwen3.8-27b; gpt-oss-120b (text-only) never called;
 * image parts (Gemini inlineData / Groq image_url); usage_metadata_missing
 * still fails; no recordReply on solve; founder-pays chain order.
 * M-I-3 (2026-11-22): Groq-only tenant routes (T33–T37) — Gemini key
 * not required when a Groq key exists; byok_required only when NEITHER
 * key exists, or the kind has no Groq leg (embeddings/doc_extraction).
 * gemini-2.5-flash-lite is RETIRED (P0 fix 2026-11-21) — it appears nowhere
 * in this file except this note and the R-T19 guard test.
 * Gemini upstream is MOCKED (no real key in CI). Live happy-path proof
 * needs a test BYOK key (parent-side, U-1) — see AUDIT_3a.md.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { handleRequest, type Env } from "../src/hub";
import {
  MODEL_31,
  MODEL_35,
  MODEL_GROQ,
  MODEL_GROQ_VISION,
  RETIRED_MODELS,
  completeTurn,
  loadRouterConfig,
  resetCircuitBreakers,
  routeLlm,
  validateGeminiKey,
  validateGroqKey,
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

/** Seed a tenant with both BYOK keys. Pass null for a key to seed WITHOUT it
 * (defaults: Gemini test key + Groq test key). */
async function seedTenantWithKeys(
  db: FakeD1,
  id: string,
  masterB64: string,
  opts: { geminiKey?: string | null; groqKey?: string | null; plan?: string } = {},
): Promise<void> {
  const master = await importMasterKey(masterB64);
  const geminiKey = opts.geminiKey === undefined ? "TEST-GEMINI-KEY-1" : opts.geminiKey;
  const groqKey = opts.groqKey === undefined ? "gsk_test_groq_key_1" : opts.groqKey;
  const keyEnc = geminiKey === null ? null : await encryptTenantKey(master, geminiKey);
  const groqKeyEnc = groqKey === null ? null : await encryptTenantKey(master, groqKey);
  await db
    .prepare("INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, groq_key_enc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(id, `${id}@example.com`, opts.plan ?? "pro", "byok", keyEnc, groqKeyEnc, FIXED_NOW)
    .run();
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

/** Groq-shaped 200: OpenAI chat completion + usage tokens. */
function okGroq(text: string, inTok = 100, outTok = 20): Response {
  return new Response(
    JSON.stringify({
      id: "chatcmpl-test",
      object: "chat.completion",
      choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "stop" }],
      usage: { prompt_tokens: inTok, completion_tokens: outTok, total_tokens: inTok + outTok },
    }),
    { status: 200 },
  );
}

/** Dual mock: api.groq.com URLs go to the Groq behaviour (model from the
 * request body), everything else to the Gemini behaviour (model from URL). */
function makeDualMockFetch(
  geminiBehaviour: MockBehaviour,
  groqBehaviour: MockBehaviour,
): { fetchFn: typeof fetch; calls: { model: string; url: string; body: string; headers: string }[] } {
  const calls: { model: string; url: string; body: string; headers: string }[] = [];
  let n = 0;
  const fetchFn = (async (url: unknown, init?: { body?: unknown; headers?: unknown }) => {
    const u = String(url);
    const body = String(init?.body ?? "");
    const headers = JSON.stringify(init?.headers ?? {});
    if (u.includes("api.groq.com")) {
      let model = "groq-models-list";
      if (body) {
        try {
          model = (JSON.parse(body) as { model?: string }).model ?? "unknown-groq";
        } catch {
          model = "unknown-groq";
        }
      }
      calls.push({ model, url: u, body, headers });
      return groqBehaviour(model, ++n);
    }
    const m = u.match(/models\/([^:]+):/)?.[1] ?? "unknown";
    calls.push({ model: m, url: u, body, headers });
    return geminiBehaviour(m, ++n);
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

function req(tenantId: string, turnId: string, kind: "agent_plan" | "quick_command" | "casual_chat" | "search_grounding" | "live" | "doc_extraction" | "embeddings" | "captcha_solve" = "quick_command", messages: ChatMessage[] = [{ role: "user", text: "hello" }]) {
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

  it("R-T2 founder-pays fallback order: 3.1 fails -> 3.5 serves", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenant(db, { id: "t-2", billingMode: "founder_pays" });
    const { fetchFn, calls } = makeMockFetch((model) =>
      model === MODEL_31 ? errResp(500, "boom") : okText("from 3.5", 100, 20),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn, { founderKey: "FOUNDER-TEST-KEY" }), req("t-2", "turn-2"));
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_35);
    expect(res.attempted_models).toEqual([MODEL_31, MODEL_35]);
    expect(calls.map((c) => c.model)).toEqual([MODEL_31, MODEL_35]);
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
        .bind("t-5", "turn-5", MODEL_31, "[]", 10, 5, 3, "byok", "ok", FIXED_NOW)
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
      ROUTER_CONFIG: JSON.stringify({ chains: { byok: { quick_command: [MODEL_31, MODEL_35] } } }),
    });
    const { fetchFn, calls } = makeMockFetch(() => okText("from 3.1", 100, 20));
    const res = await routeLlm(baseDeps(db, master, fetchFn, { config }), req("t-13", "turn-13"));
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_31);
    expect(calls[0].model).toBe(MODEL_31);
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

describe("router P0 fix (R-T18–R-T19)", () => {
  it("R-T18 validation fallback: first live model 404 -> second ok -> true", async () => {
    const { fetchFn, calls } = makeMockFetch((model) =>
      model === MODEL_35 ? errResp(404, "models/gemini-3.5-flash-lite is not found") : okText("hi", 2, 1),
    );
    expect(await validateGeminiKey("SOME-KEY", fetchFn)).toBe(true);
    expect(calls.map((c) => c.model)).toEqual([MODEL_35, MODEL_31]);
  });

  it("R-T18 validation: 401 invalid key -> false at once, no fallback attempt", async () => {
    const { fetchFn, calls } = makeMockFetch(() => errResp(401, "API key not valid"));
    expect(await validateGeminiKey("BAD-KEY", fetchFn)).toBe(false);
    expect(calls).toHaveLength(1);
  });

  it("R-T18 validation: 429 -> false (unvalidated keys never stored); both 404 -> false", async () => {
    const { fetchFn: rateFetch, calls: rateCalls } = makeMockFetch(() => errResp(429, "Resource exhausted"));
    expect(await validateGeminiKey("SOME-KEY", rateFetch)).toBe(false);
    expect(rateCalls).toHaveLength(1);
    const { fetchFn: goneFetch, calls: goneCalls } = makeMockFetch(() => errResp(404, "model not found"));
    expect(await validateGeminiKey("SOME-KEY", goneFetch)).toBe(false);
    expect(goneCalls.map((c) => c.model)).toEqual([MODEL_35, MODEL_31]);
  });

  it("R-T19 retired model never in any chain: config with 2.5 FL throws; defaults are live-only", () => {
    for (const retired of RETIRED_MODELS) {
      expect(() =>
        loadRouterConfig({ ROUTER_CONFIG: JSON.stringify({ chains: { byok: { quick_command: [MODEL_35, retired] } } }) }),
      ).toThrow(/retired/);
    }
    const defaults = loadRouterConfig({});
    const allowed = new Set([MODEL_31, MODEL_35, MODEL_GROQ, MODEL_GROQ_VISION, "gemini-embedding-001", "gemini-2.5-flash-native-audio-dialog"]);
    for (const [mode, kinds] of Object.entries(defaults.chains)) {
      for (const [kind, chain] of Object.entries(kinds)) {
        for (const model of chain as string[]) {
          expect(allowed.has(model)).toBe(true);
          expect(RETIRED_MODELS).not.toContain(model);
        }
        // Founder-pays default (C1) is the cheapest LIVE lite model, every kind.
        if (mode === "founder_pays" && kind !== "live" && kind !== "embeddings") {
          expect((chain as string[])[0]).toBe(MODEL_31);
        }
      }
    }
    for (const retired of RETIRED_MODELS) {
      expect(defaults.prices).not.toHaveProperty(retired);
    }
  });
});

describe("router Groq free leg (R-T20–R-T25)", () => {
  it("R-T20 Groq serves after both Gemini legs 429: fallback_used, cost 0, Bearer key never in URL", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-20", master);
    const { fetchFn, calls } = makeDualMockFetch(
      () => errResp(429, "Resource exhausted"),
      () => okGroq("from groq", 100, 20),
    );
    const res = await routeLlm(
      baseDeps(db, master, fetchFn),
      { ...req("t-20", "turn-20"), system: "you are jarvis" },
    );
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_GROQ);
    expect(res.attempted_models).toEqual([MODEL_35, MODEL_31, MODEL_GROQ]);
    expect(res.status).toBe("fallback_used");
    expect(res.cost_usd_micro).toBe(0);
    expect(calls.map((c) => c.model)).toEqual([MODEL_35, MODEL_31, MODEL_GROQ]);
    const groqCall = calls.find((c) => c.url.includes("api.groq.com"))!;
    expect(groqCall.url).toBe("https://api.groq.com/openai/v1/chat/completions");
    expect(groqCall.url).not.toContain("gsk_test");
    expect(groqCall.headers).toContain("gsk_test_groq_key_1");
    const sent = JSON.parse(groqCall.body) as { model: string; messages: { role: string; content: string }[] };
    expect(sent.model).toBe(MODEL_GROQ);
    expect(sent.messages).toEqual([
      { role: "system", content: "you are jarvis" },
      { role: "user", content: "hello" },
    ]);
    const rows = await usageRows(db);
    expect(rows).toHaveLength(1);
    expect(rows[0].model).toBe(MODEL_GROQ);
    expect(rows[0].cost_usd_micro).toBe(0);
    expect(rows[0].input_tokens).toBe(100);
    expect(rows[0].output_tokens).toBe(20);
  });

  it("R-T21 Groq skipped with no key: chain exhausts, Groq never fetched, skip traced", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-21", master, { groqKey: null }); // Gemini key only
    const { fetchFn, calls } = makeDualMockFetch(
      () => errResp(429, "Resource exhausted"),
      () => okGroq("should never serve"),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-21", "turn-21"));
    expect(res.ok).toBe(false);
    expect(res.error_code).toBe("rate_limited");
    expect(res.attempted_models).toEqual([MODEL_35, MODEL_31]); // Groq never attempted
    expect(calls.every((c) => !c.url.includes("api.groq.com"))).toBe(true);
    const traces = await traceRows(db);
    expect(traces.some((t) => t.kind === "router_groq_skipped")).toBe(true);
  });

  it("R-T22 Groq 401 -> invalid_key at once; Groq 429 -> chain exhausts failed", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-22a", master, { groqKey: "gsk_bad_key" });
    const bad = makeDualMockFetch(
      () => errResp(429, "Resource exhausted"),
      () => errResp(401, "Invalid API key provided"),
    );
    const resBad = await routeLlm(baseDeps(db, master, bad.fetchFn), req("t-22a", "turn-22a"));
    expect(resBad.ok).toBe(false);
    expect(resBad.error_code).toBe("invalid_key");
    expect(resBad.attempted_models).toEqual([MODEL_35, MODEL_31, MODEL_GROQ]);
    await seedTenantWithKeys(db, "t-22b", master, { groqKey: "gsk_ok_but_limited" });
    const limited = makeDualMockFetch(
      () => errResp(429, "Resource exhausted"),
      () => errResp(429, "Rate limit exceeded"),
    );
    const resLimited = await routeLlm(baseDeps(db, master, limited.fetchFn), req("t-22b", "turn-22b"));
    expect(resLimited.ok).toBe(false);
    expect(resLimited.error_code).toBe("rate_limited");
  });

  it("R-T23 Groq missing usage -> usage_metadata_missing, no billing on estimate", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-23", master);
    const { fetchFn } = makeDualMockFetch(
      () => errResp(429, "Resource exhausted"),
      () =>
        new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "no usage here" } }] }), {
          status: 200,
        }),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-23", "turn-23"));
    expect(res.ok).toBe(false);
    expect(res.error_code).toBe("usage_metadata_missing");
    const rows = await usageRows(db);
    expect(rows).toHaveLength(1);
    expect(rows[0].cost_usd_micro).toBe(0);
  });

  it("R-T24 validateGroqKey: 200 -> true (models URL + Bearer); 401/429/throw -> false", async () => {
    const seen: { url: string; auth: string }[] = [];
    const cap = (async (url: unknown, init?: { headers?: Record<string, string> }) => {
      seen.push({ url: String(url), auth: String(init?.headers?.Authorization ?? "") });
      return new Response(JSON.stringify({ data: [{ id: "openai/gpt-oss-120b" }] }), { status: 200 });
    }) as unknown as typeof fetch;
    expect(await validateGroqKey("gsk_secret_123", cap)).toBe(true);
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe("https://api.groq.com/openai/v1/models");
    expect(seen[0].auth).toBe("Bearer gsk_secret_123");
    const bad = (async () =>
      new Response(JSON.stringify({ error: { message: "Invalid API key provided" } }), { status: 401 })) as unknown as typeof fetch;
    expect(await validateGroqKey("gsk_bad", bad)).toBe(false);
    const limited = (async () => errResp(429, "Rate limit exceeded")) as unknown as typeof fetch;
    expect(await validateGroqKey("gsk_x", limited)).toBe(false);
    const throwing = (async () => {
      throw new Error("boom");
    }) as unknown as typeof fetch;
    expect(await validateGroqKey("gsk_x", throwing)).toBe(false);
  });

  it("R-T25 config guard: qwen3.8 in a chain does NOT throw (R3 fix); gemini-3.8 still throws", async () => {
    const ok = loadRouterConfig({
      ROUTER_CONFIG: JSON.stringify({ chains: { byok: { quick_command: [MODEL_35, "qwen/qwen3.8-27b"] } } }),
    });
    expect(ok.chains.byok.quick_command).toEqual([MODEL_35, "qwen/qwen3.8-27b"]);
    expect(() =>
      loadRouterConfig({ ROUTER_CONFIG: JSON.stringify({ chains: { byok: { quick_command: ["gemini-3.8-flash"] } } }) }),
    ).toThrow(/3\.8/);
    expect(() =>
      loadRouterConfig({ ROUTER_CONFIG: JSON.stringify({ prices: { "gemini-3.8-flash": { in: 1, out: 1 } } }) }),
    ).toThrow(/3\.8/);
  });

  it("R-T25b qwen3.8-27b chain leg serves through the Groq caller at $0", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-25b", master);
    const config = loadRouterConfig({
      ROUTER_CONFIG: JSON.stringify({ chains: { byok: { quick_command: ["qwen/qwen3.8-27b"] } } }),
    });
    const { fetchFn, calls } = makeDualMockFetch(
      () => errResp(500, "never reached"),
      () => okGroq("from qwen", 50, 10),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn, { config }), req("t-25b", "turn-25b"));
    expect(res.ok).toBe(true);
    expect(res.model).toBe("qwen/qwen3.8-27b");
    expect(res.cost_usd_micro).toBe(0);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toContain("api.groq.com");
  });
});

describe("router captcha_solve kind (R-T27–R-T32, D3 LOCKED)", () => {
  const IMG_B64 = Buffer.from("fake-captcha-png-bytes").toString("base64");
  const TILES_JSON = JSON.stringify({ kind: "tiles", grid_rows: 3, grid_cols: 3, tiles: [0, 4, 7], confidence: 0.87 });

  function captchaReq(tenantId: string, turnId: string) {
    return {
      ...req(tenantId, turnId, "captcha_solve", [{ role: "user", text: "solve this grid" } as ChatMessage]),
      image_b64: IMG_B64,
    };
  }

  it("R-T27 BYOK chain order: 3.5 -> 3.1 -> qwen3.8-27b; gpt-oss-120b never called", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-27", master);
    const { fetchFn, calls } = makeDualMockFetch(
      (model) => (model === MODEL_35 ? errResp(429, "Resource exhausted") : errResp(500, "boom")),
      () => okGroq(TILES_JSON, 100, 20),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn), captchaReq("t-27", "turn-27"));
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_GROQ_VISION);
    expect(res.attempted_models).toEqual([MODEL_35, MODEL_31, MODEL_GROQ_VISION]);
    expect(calls.map((c) => c.model)).toEqual([MODEL_35, MODEL_31, MODEL_GROQ_VISION]);
    expect(calls.map((c) => c.model)).not.toContain(MODEL_GROQ);
    expect(res.text).toBe(TILES_JSON);
  });

  it("R-T28 gpt-oss-120b in a captcha_solve chain is skipped (text-only), never fetched", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-28", master);
    const config = loadRouterConfig({
      ROUTER_CONFIG: JSON.stringify({ chains: { byok: { captcha_solve: [MODEL_GROQ, MODEL_35] } } }),
    });
    const { fetchFn, calls } = makeDualMockFetch(
      () => okText(TILES_JSON, 100, 20),
      () => okGroq("should never serve", 100, 20),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn, { config }), captchaReq("t-28", "turn-28"));
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_35);
    expect(res.attempted_models).toEqual([MODEL_35]);
    expect(calls.map((c) => c.model)).toEqual([MODEL_35]);
    const traces = await traceRows(db);
    expect(
      traces.some((t) => t.kind === "router_groq_skipped" && String(t.detail).includes("text_only_model")),
    ).toBe(true);
  });

  it("R-T29 image parts: Gemini inlineData + Groq image_url data part carry the challenge image", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-29", master);
    const { fetchFn, calls } = makeDualMockFetch(
      (model) => (model === MODEL_35 ? errResp(429, "Resource exhausted") : errResp(500, "boom")),
      () => okGroq(TILES_JSON, 100, 20),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn), captchaReq("t-29", "turn-29"));
    expect(res.ok).toBe(true);
    const geminiBody = JSON.parse(calls[0].body) as { contents: { parts: Record<string, unknown>[] }[] };
    const parts = geminiBody.contents[geminiBody.contents.length - 1].parts;
    expect(parts.some((p) => (p.inlineData as { mimeType?: string } | undefined)?.mimeType === "image/png")).toBe(true);
    expect(parts.some((p) => (p.inlineData as { data?: string } | undefined)?.data === IMG_B64)).toBe(true);
    const groqBody = JSON.parse(calls[2].body) as { messages: { content: unknown }[] };
    expect(JSON.stringify(groqBody.messages[groqBody.messages.length - 1].content)).toContain(
      `data:image/png;base64,${IMG_B64}`,
    );
  });

  it("R-T30 usage_metadata_missing still fails captcha_solve (never billed on estimate)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-30", master);
    const noUsage = () =>
      new Response(
        JSON.stringify({ candidates: [{ content: { parts: [{ text: TILES_JSON }] }, finishReason: "STOP" }] }),
        { status: 200 },
      );
    const { fetchFn } = makeDualMockFetch(() => noUsage(), () => noUsage());
    const res = await routeLlm(baseDeps(db, master, fetchFn), captchaReq("t-30", "turn-30"));
    expect(res.ok).toBe(false);
    expect(res.error_code).toBe("usage_metadata_missing");
    const rows = await usageRows(db);
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("failed");
    expect(rows[0].cost_usd_micro).toBe(0);
  });

  it("R-T31 a solve meters llm_usage but does NOT count a reply (D3 Q2 locked)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-31", master);
    const { fetchFn } = makeDualMockFetch(() => okText(TILES_JSON, 100, 20), () => okGroq(TILES_JSON, 100, 20));
    const res = await routeLlm(baseDeps(db, master, fetchFn), captchaReq("t-31", "turn-31"));
    expect(res.ok).toBe(true);
    const rows = await usageRows(db);
    expect(rows).toHaveLength(1);
    expect(rows[0].model).toBe(MODEL_35);
    const counters = await db
      .prepare("SELECT replies FROM usage_counters WHERE tenant_id = ? AND period = ?")
      .bind("t-31", PERIOD)
      .first<{ replies: number }>();
    expect(counters?.replies ?? 0).toBe(0);
  });

  it("R-T32 founder-pays chain order: 3.1 -> 3.5 -> qwen3.8-27b", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenant(db, { id: "t-32", billingMode: "founder_pays" });
    const { fetchFn, calls } = makeDualMockFetch(
      (model) => (model === MODEL_31 ? errResp(429, "Resource exhausted") : okText(TILES_JSON, 100, 20)),
      () => okGroq(TILES_JSON, 100, 20),
    );
    const res = await routeLlm(
      baseDeps(db, master, fetchFn, { founderKey: "FOUNDER-TEST-KEY" }),
      captchaReq("t-32", "turn-32"),
    );
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_35);
    expect(res.attempted_models).toEqual([MODEL_31, MODEL_35]);
    expect(calls.map((c) => c.model)).toEqual([MODEL_31, MODEL_35]);
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

  it("micro-fix (2026-11-22): malformed message shape -> 400 bad_request, no upstream call, no usage row", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-mf", master);
    const { fetchFn, calls } = makeDualMockFetch(
      () => errResp(500, "Gemini must never be called"),
      () => okGroq("groq must never be called"),
    );
    // {"role","content"} instead of {"role","text"} — the shape that used
    // to 500 inside truncateMessages/estimateTokens (m.text undefined).
    const bad1 = await routeLlm(baseDeps(db, master, fetchFn), {
      tenant_id: "t-mf",
      turn_id: "turn-mf-1",
      kind: "quick_command",
      messages: [{ role: "user", content: "hi" } as unknown as ChatMessage],
    });
    expect(bad1.ok).toBe(false);
    expect(bad1.error_code).toBe("bad_request");
    // Non-string text, and a null entry, fail the same way.
    const badShapes: ChatMessage[][] = [
      [{ role: "user", text: 42 }] as unknown as ChatMessage[],
      [null as unknown as ChatMessage],
    ];
    for (const messages of badShapes) {
      const res = await routeLlm(baseDeps(db, master, fetchFn), {
        tenant_id: "t-mf",
        turn_id: "turn-mf-2",
        kind: "quick_command",
        messages,
      });
      expect(res.ok).toBe(false);
      expect(res.error_code).toBe("bad_request");
    }
    expect(calls).toHaveLength(0);
    expect(await usageRows(db)).toHaveLength(0);
  });

  it("micro-fix (2026-11-22): hub /api/llm/route maps the malformed shape to HTTP 400", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-mf2" });
    const res = await handleRequest(
      new Request("https://hub/api/llm/route", { method: "POST", headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" }, body: JSON.stringify({ tenant_id: "t-mf2", turn_id: "turn-mf2", kind: "quick_command", messages: [{ role: "user", content: "hi" }] }) }),
      fakeEnv(db),
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("bad_request");
  });

  it("R-T26 hub groq-key: 401 without token; invalid -> 400; valid -> 200, key never echoed, envelope decrypts; DELETE clears", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenant(db, { id: "t-26" });
    const noAuth = await handleRequest(
      new Request("https://hub/api/tenants/t-26/groq-key", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ groq_key: "gsk_x" }) }),
      fakeEnv(db, { KEY_ENC_SECRET: master }),
    );
    expect(noAuth.status).toBe(401);

    // Invalid key (mock Groq 401).
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ error: { message: "Invalid API key provided" } }), { status: 401 }));
    const bad = await handleRequest(
      new Request("https://hub/api/tenants/t-26/groq-key", { method: "POST", headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" }, body: JSON.stringify({ groq_key: "gsk_BAD" }) }),
      fakeEnv(db, { KEY_ENC_SECRET: master }),
    );
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as Record<string, unknown>).error).toBe("invalid_key");

    // Valid key (mock Groq 200 models list).
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ data: [{ id: "openai/gpt-oss-120b" }] }), { status: 200 }));
    const good = await handleRequest(
      new Request("https://hub/api/tenants/t-26/groq-key", { method: "POST", headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" }, body: JSON.stringify({ groq_key: "gsk_REAL_TEST_999" }) }),
      fakeEnv(db, { KEY_ENC_SECRET: master }),
    );
    expect(good.status).toBe(200);
    expect(JSON.stringify(await good.clone().json())).not.toContain("gsk_REAL_TEST_999");
    const status = await handleRequest(new Request("https://hub/api/tenants/t-26/groq-key-status", { headers: { "x-admin-token": "test-admin" } }), fakeEnv(db, { KEY_ENC_SECRET: master }));
    const statusBody = (await status.json()) as Record<string, unknown>;
    expect(statusBody.has_groq_key).toBe(true);
    // Stored value is an encrypted envelope, not the key.
    const tenant = await db.prepare("SELECT groq_key_enc FROM tenants WHERE id = ?").bind("t-26").first<{ groq_key_enc: string }>();
    expect(tenant?.groq_key_enc).not.toContain("gsk_REAL_TEST_999");
    expect(await decryptTenantKey(await importMasterKey(master), tenant!.groq_key_enc)).toBe("gsk_REAL_TEST_999");
    // DELETE removes it.
    const del = await handleRequest(new Request("https://hub/api/tenants/t-26/groq-key", { method: "DELETE", headers: { "x-admin-token": "test-admin" } }), fakeEnv(db, { KEY_ENC_SECRET: master }));
    expect(del.status).toBe(200);
    const after = await db.prepare("SELECT groq_key_enc FROM tenants WHERE id = ?").bind("t-26").first<{ groq_key_enc: string | null }>();
    expect(after?.groq_key_enc).toBeNull();
  });
});

describe("router Groq-only tenant path (M-I-3, 2026-11-22)", () => {
  it("M-I-3/T33 Groq-only tenant routes: Gemini legs skipped (traced), Groq serves at $0", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-33", master, { geminiKey: null, groqKey: "gsk_only_groq" });
    const { fetchFn, calls } = makeDualMockFetch(
      () => errResp(500, "Gemini must never be called"),
      () => okGroq("from groq only", 100, 20),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-33", "turn-33"));
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_GROQ);
    expect(res.attempted_models).toEqual([MODEL_GROQ]); // Gemini legs never attempted
    expect(res.cost_usd_micro).toBe(0);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toContain("api.groq.com");
    const traces = await traceRows(db);
    expect(traces.filter((t) => t.kind === "router_gemini_skipped")).toHaveLength(2);
    expect(traces.some((t) => t.kind === "router_gemini_skipped" && String(t.detail).includes("no_gemini_key"))).toBe(true);
    const rows = await usageRows(db);
    expect(rows).toHaveLength(1);
    expect(rows[0].model).toBe(MODEL_GROQ);
  });

  it("M-I-3/T34 no-key tenant (neither Gemini nor Groq) still byok_required, zero upstream calls", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-34", master, { geminiKey: null, groqKey: null });
    const { fetchFn, calls } = makeDualMockFetch(
      () => okText("x"),
      () => okGroq("x"),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-34", "turn-34"));
    expect(res.ok).toBe(false);
    expect(res.error_code).toBe("byok_required");
    expect(calls).toHaveLength(0);
  });

  it("M-I-3/T35 no-key tenant + FOUNDER_GROQ_KEY routes via founder Groq ($0, no quota burns)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-35", master, { geminiKey: null, groqKey: null });
    const { fetchFn, calls } = makeDualMockFetch(
      () => errResp(500, "Gemini must never be called"),
      () => okGroq("from founder groq", 50, 10),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn, { founderGroqKey: "gsk_founder_groq" }), req("t-35", "turn-35"));
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_GROQ);
    expect(res.attempted_models).toEqual([MODEL_GROQ]);
    expect(calls).toHaveLength(1);
    expect(calls[0].headers).toContain("gsk_founder_groq");
  });

  it("M-I-3/T36 Groq-only tenant + Gemini-only kind (embeddings / doc_extraction) -> byok_required", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-36", master, { geminiKey: null, groqKey: "gsk_only_groq" });
    const { fetchFn, calls } = makeDualMockFetch(
      () => okText("x"),
      () => okGroq("x"),
    );
    const emb = await routeLlm(baseDeps(db, master, fetchFn), req("t-36", "turn-36-emb", "embeddings", [{ role: "user", text: "x" }]));
    expect(emb.ok).toBe(false);
    expect(emb.error_code).toBe("byok_required");
    const doc = await routeLlm(baseDeps(db, master, fetchFn), req("t-36", "turn-36-doc", "doc_extraction", [{ role: "user", text: "x" }]));
    expect(doc.ok).toBe(false);
    expect(doc.error_code).toBe("byok_required");
    expect(calls).toHaveLength(0);
  });

  it("M-I-3/T37 Gemini+Groq order unchanged: Gemini serves first, Groq never called", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-37", master);
    const { fetchFn, calls } = makeDualMockFetch(
      () => okText("from 3.5", 100, 20),
      () => okGroq("should never serve"),
    );
    const res = await routeLlm(baseDeps(db, master, fetchFn), req("t-37", "turn-37"));
    expect(res.ok).toBe(true);
    expect(res.model).toBe(MODEL_35);
    expect(res.attempted_models).toEqual([MODEL_35]);
    expect(res.status).toBe("ok");
    expect(calls).toHaveLength(1);
    expect(calls[0].url).not.toContain("api.groq.com");
  });
});
