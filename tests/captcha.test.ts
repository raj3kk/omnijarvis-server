/**
 * Captcha auto-solver tests (D3 LOCKED 2026-11-22, DESIGN §8.1).
 * Hub only (no app changes in this track). Upstream Gemini/Groq are
 * MOCKED (no real key, no network). Live happy-path proof needs a test
 * BYOK key (parent-side, U-1) — see DESIGN §8.4.
 *
 * Coverage: frozen constants · scope matrix · answer-schema validation
 * incl. the 0.79/0.80 boundary · image-size gate · cap boundaries
 * (2/task, 10/day, UTC rollover) · chain order + qwen3.8-27b vision leg
 * (gpt-oss-120b NEVER called) · parse-failure advance · safety-blocked
 * stops the chain · byok_required path · SECRET-* marker test (no
 * answer/token/image in logs/traces) · rate-limit budget · route auth
 * matrix (401/403/400/402/cap) · no recordReply on solve.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { genDeviceKey } from "./helpers";
import { handleRequest, type Env } from "../src/hub";
import { canonicalString, bytesToBase64 } from "../src/crypto";
import { sortedJson } from "../src/docs";
import { RATE_LIMITS, checkRateLimit, resetRateLimitFallback } from "../src/ratelimit";
import { MODEL_31, MODEL_35, MODEL_GROQ, MODEL_GROQ_VISION, loadRouterConfig, resetCircuitBreakers, routeLlm } from "../src/router";
import { encryptTenantKey, importMasterKey } from "../src/keyvault";
import {
  CAPTCHA_AUTO_SOLVE_BUDGET_MS,
  CAPTCHA_SOLVE_TIMEOUT_MS,
  MAX_AUTO_SOLVED_PER_TASK,
  MAX_AUTO_SOLVES_PER_DAY,
  MAX_AUTO_SOLVE_ATTEMPTS,
  MAX_CAPTCHA_IMAGE_BYTES,
  MIN_SOLVE_CONFIDENCE,
  countAutoSubmissionsForTask,
  countAutoSubmissionsToday,
  isAutoSolvableType,
  newSolveId,
  parseSolveAnswer,
  solveCaptcha,
  validateSolveAnswer,
  validateSolveRequest,
  type CaptchaDeps,
} from "../src/captcha";

const FIXED_NOW = Date.UTC(2026, 10, 22, 12, 0, 0);
/** Small valid base64 "PNG" (test fixture — not a real image). */
const IMG_B64 = Buffer.from("fake-captcha-png-bytes").toString("base64");
const TILES_JSON = JSON.stringify({ kind: "tiles", grid_rows: 3, grid_cols: 3, tiles: [0, 4, 7], confidence: 0.87 });
const TILES_JSON_LOW = JSON.stringify({ kind: "tiles", grid_rows: 3, grid_cols: 3, tiles: [0, 4, 7], confidence: 0.79 });
const TILES_JSON_EDGE = JSON.stringify({ kind: "tiles", grid_rows: 3, grid_cols: 3, tiles: [1, 2], confidence: 0.8 });

async function makeMasterKeyB64(): Promise<string> {
  const k = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
  return bytesToBase64(raw);
}

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

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string, publicKeyB64: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, publicKeyB64, FIXED_NOW, FIXED_NOW, 1)
    .run();
}

async function seedSubmittedRow(
  db: FakeD1,
  opts: { id: string; tenantId: string; taskId: string; createdAt?: number },
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO captcha_solves (id, tenant_id, device_id, task_id, site, challenge_type, model, confidence, outcome, attempts, latency_ms, flag_asserted, image_sha256, created_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(opts.id, opts.tenantId, "dev-1", opts.taskId, "example.com", "recaptcha_grid", MODEL_35, 0.9, "submitted", 1, 100, 1, "deadbeef", opts.createdAt ?? FIXED_NOW)
    .run();
}

async function solveRows(db: FakeD1): Promise<Record<string, unknown>[]> {
  return (await db.prepare("SELECT * FROM captcha_solves").all()).results as Record<string, unknown>[];
}

async function traceRows(db: FakeD1): Promise<Record<string, unknown>[]> {
  return (await db.prepare("SELECT * FROM traces").all()).results as Record<string, unknown>[];
}

type GeminiBehaviour = (model: string, callNo: number) => Response;
type GroqBehaviour = (model: string, callNo: number) => Response;

function okGeminiText(text: string, inTok = 100, outTok = 20): Response {
  return new Response(
    JSON.stringify({
      candidates: [{ content: { parts: [{ text }] }, finishReason: "STOP" }],
      usageMetadata: { promptTokenCount: inTok, candidatesTokenCount: outTok },
    }),
    { status: 200 },
  );
}

function okGroqText(text: string, inTok = 100, outTok = 20): Response {
  return new Response(
    JSON.stringify({
      id: "chatcmpl-test",
      choices: [{ message: { content: text }, finish_reason: "stop" }],
      usage: { prompt_tokens: inTok, completion_tokens: outTok },
    }),
    { status: 200 },
  );
}

function errResp(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: { code: status, message } }), { status });
}

/** Dual mock fetch (Gemini + Groq), same shape as router.test.ts. */
function makeDualMockFetch(
  geminiBehaviour: GeminiBehaviour,
  groqBehaviour: GroqBehaviour,
): { fetchFn: typeof fetch; calls: { model: string; url: string; body: string }[] } {
  const calls: { model: string; url: string; body: string }[] = [];
  let n = 0;
  const fetchFn = (async (url: unknown, init?: { body?: unknown }) => {
    const u = String(url);
    const body = String(init?.body ?? "");
    if (u.includes("api.groq.com")) {
      let model = "groq-models-list";
      if (body) {
        try {
          model = (JSON.parse(body) as { model?: string }).model ?? "unknown-groq";
        } catch {
          model = "unknown-groq";
        }
      }
      calls.push({ model, url: u, body });
      return groqBehaviour(model, ++n);
    }
    const m = u.match(/models\/([^:]+):/)?.[1] ?? "unknown";
    calls.push({ model: m, url: u, body });
    return geminiBehaviour(m, ++n);
  }) as unknown as typeof fetch;
  return { fetchFn, calls };
}

function captchaDeps(db: FakeD1, masterB64: string, fetchFn: typeof fetch): CaptchaDeps {
  return { db, fetchFn, sleepFn: async () => {}, nowMs: () => FIXED_NOW, masterKeyB64: masterB64 };
}

function solveInput(overrides: Partial<{ task_id: string; challenge_type: string }> = {}) {
  return {
    tenant_id: "t-1",
    device_id: "dev-1",
    task_id: overrides.task_id ?? "bt-0000000000000001",
    site: "example.com",
    challenge_type: overrides.challenge_type ?? "recaptcha_grid",
    image_b64: IMG_B64,
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

/** Signed POST /api/captcha/solve, docs-style (sortedJson payload). */
async function signedSolve(
  db: FakeD1,
  key: Awaited<ReturnType<typeof genDeviceKey>>,
  body: Record<string, unknown>,
  opts: { deviceId?: string; masterB64?: string; signPayload?: string } = {},
): Promise<Response> {
  const deviceId = opts.deviceId ?? "dev-1";
  const nonce = "aabbccddeeff00112233445566778899";
  const ts = Date.now();
  const payload = opts.signPayload ?? sortedJson(body);
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

beforeEach(() => {
  resetCircuitBreakers();
  resetRateLimitFallback();
  vi.unstubAllGlobals();
});

describe("captcha constants (DESIGN §3.1 frozen numbers)", () => {
  it("frozen numbers are exactly the DESIGN values", () => {
    expect(MAX_AUTO_SOLVE_ATTEMPTS).toBe(3);
    expect(MIN_SOLVE_CONFIDENCE).toBe(0.8);
    expect(CAPTCHA_SOLVE_TIMEOUT_MS).toBe(15_000);
    expect(CAPTCHA_AUTO_SOLVE_BUDGET_MS).toBe(60_000);
    expect(MAX_AUTO_SOLVED_PER_TASK).toBe(2);
    expect(MAX_AUTO_SOLVES_PER_DAY).toBe(10);
    expect(MAX_CAPTCHA_IMAGE_BYTES).toBe(200 * 1024);
  });

  it("solve_id is cs- + 16 hex", () => {
    expect(newSolveId()).toMatch(/^cs-[0-9a-f]{16}$/);
    expect(newSolveId()).not.toBe(newSolveId());
  });
});

describe("scope matrix (DESIGN §5/§6)", () => {
  it("grids + simple text are solvable; audio/Turnstile/v3/unknown are not", () => {
    for (const t of ["recaptcha_grid", "hcaptcha_grid", "text"]) expect(isAutoSolvableType(t)).toBe(true);
    for (const t of ["audio", "turnstile", "recaptcha_v3", "slider", "unknown", ""]) {
      expect(isAutoSolvableType(t)).toBe(false);
    }
  });
});

describe("answer-schema validation (DESIGN §2.2)", () => {
  it("valid tiles + valid text pass", () => {
    expect(validateSolveAnswer(JSON.parse(TILES_JSON), "recaptcha_grid").ok).toBe(true);
    expect(
      validateSolveAnswer({ kind: "text", text: "ab12cd", confidence: 0.91 }, "text").ok,
    ).toBe(true);
  });

  it("bad JSON, missing fields, out-of-range tile, missing confidence fail", () => {
    expect(parseSolveAnswer("Sure, here are the tiles: 0, 4, 7")).toBeNull();
    expect(parseSolveAnswer("")).toBeNull();
    expect(validateSolveAnswer({ kind: "tiles", grid_rows: 3, grid_cols: 3, tiles: [0, 4] }, "recaptcha_grid").ok).toBe(false); // no confidence
    expect(
      validateSolveAnswer({ kind: "tiles", grid_rows: 3, grid_cols: 3, tiles: [0, 9], confidence: 0.9 }, "recaptcha_grid").ok,
    ).toBe(false); // 9 out of range for 3x3
    expect(
      validateSolveAnswer({ kind: "tiles", grid_rows: 3, grid_cols: 3, tiles: [], confidence: 0.9 }, "recaptcha_grid").ok,
    ).toBe(false); // empty tiles
    expect(
      validateSolveAnswer({ kind: "tiles", grid_rows: 3, tiles: [0], confidence: 0.9 }, "recaptcha_grid").ok,
    ).toBe(false); // missing grid_cols
    expect(validateSolveAnswer({ kind: "text", text: "", confidence: 0.9 }, "text").ok).toBe(false);
    expect(validateSolveAnswer({ kind: "tiles", grid_rows: 3, grid_cols: 3, tiles: [0], confidence: 0.9 }, "text").ok).toBe(false); // kind/type mismatch
    expect(validateSolveAnswer({ kind: "text", text: "ab", confidence: 1.2 }, "text").ok).toBe(false); // confidence > 1
  });

  it("0.79 fails the threshold, 0.80 passes it (boundary, DESIGN §3.1)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    // Leg 1 returns 0.79 -> low_confidence, advance; leg 2 returns 0.80 -> success.
    const { fetchFn, calls } = makeDualMockFetch(
      (model) => (model === MODEL_35 ? okGeminiText(TILES_JSON_LOW) : okGeminiText(TILES_JSON_EDGE)),
      () => okGroqText(TILES_JSON),
    );
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput());
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.confidence).toBe(0.8);
    expect(res.model).toBe(MODEL_31);
    expect(res.attempts).toBe(2);
    expect(calls.map((c) => c.model)).toEqual([MODEL_35, MODEL_31]);
    const rows = await solveRows(db);
    expect(rows.map((r) => r.outcome)).toEqual(["low_confidence", "submitted"]);
    expect(rows[0].confidence).toBe(0.79);
  });
});

describe("request validation + image-size gate (DESIGN §2.4)", () => {
  it("valid request passes; missing/oversized image, bad type, flag false fail", () => {
    expect(validateSolveRequest(solveBody()).ok).toBe(true);
    expect(validateSolveRequest(solveBody({ image_b64: undefined })).ok).toBe(false);
    expect(validateSolveRequest(solveBody({ auto_solve_allowed: false })).ok).toBe(false);
    expect(validateSolveRequest(solveBody({ auto_solve_allowed: undefined })).ok).toBe(false);
    expect(validateSolveRequest(solveBody({ challenge_type: "slider" })).ok).toBe(false);
    expect(validateSolveRequest(solveBody({ task_id: "" })).ok).toBe(false);
    expect(validateSolveRequest(solveBody({ image_b64: "!!!not-base64!!!" })).ok).toBe(false);
    // Oversized: 200 KB + 1 byte decoded.
    const big = Buffer.alloc(MAX_CAPTCHA_IMAGE_BYTES + 1, 0x41).toString("base64");
    expect(validateSolveRequest(solveBody({ image_b64: big })).ok).toBe(false);
    // Exactly 200 KB decoded passes.
    const exact = Buffer.alloc(MAX_CAPTCHA_IMAGE_BYTES, 0x41).toString("base64");
    expect(validateSolveRequest(solveBody({ image_b64: exact })).ok).toBe(true);
  });
});

describe("vision chain (DESIGN §2.2)", () => {
  it("chain order 3.5 -> 3.1 -> qwen3.8-27b; Groq leg is vision, gpt-oss-120b never called", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const { fetchFn, calls } = makeDualMockFetch(
      (model) => (model === MODEL_35 ? errResp(429, "Resource exhausted") : errResp(500, "boom")),
      (model) => {
        expect(model).toBe(MODEL_GROQ_VISION);
        return okGroqText(TILES_JSON);
      },
    );
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput());
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.model).toBe(MODEL_GROQ_VISION);
    expect(res.attempts).toBe(3);
    expect(res.answer).toEqual({ kind: "tiles", grid_rows: 3, grid_cols: 3, tiles: [0, 4, 7] });
    expect(res.confidence).toBe(0.87);
    expect(res.solve_id).toMatch(/^cs-[0-9a-f]{16}$/);
    expect(calls.map((c) => c.model)).toEqual([MODEL_35, MODEL_31, MODEL_GROQ_VISION]);
    expect(calls.map((c) => c.model)).not.toContain(MODEL_GROQ);
    // Groq leg carries the image as an image_url data part.
    const groqBody = JSON.parse(calls[2].body) as { messages: { content: unknown }[] };
    const lastMsg = groqBody.messages[groqBody.messages.length - 1];
    expect(JSON.stringify(lastMsg.content)).toContain(`data:image/png;base64,${IMG_B64}`);
    // Gemini legs carry the image as inlineData parts.
    const geminiBody = JSON.parse(calls[0].body) as { contents: { parts: Record<string, unknown>[] }[] };
    const parts = geminiBody.contents[geminiBody.contents.length - 1].parts;
    expect(parts.some((p) => (p.inlineData as { mimeType?: string; data?: string } | undefined)?.mimeType === "image/png")).toBe(true);
    expect(parts.some((p) => (p.inlineData as { data?: string } | undefined)?.data === IMG_B64)).toBe(true);
  });

  it("solveCaptcha pins the frozen chain: a config naming gpt-oss-120b first is ignored, never called", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const { fetchFn, calls } = makeDualMockFetch(
      () => okGeminiText(TILES_JSON),
      () => okGroqText(TILES_JSON),
    );
    // Custom config names the text-only model first for captcha_solve —
    // solveCaptcha drives legs from the frozen chain constants, so the
    // config value is discarded and gpt-oss-120b is never fetched.
    // (The routeLlm-level guard for direct callers is R-T28.)
    const config = loadRouterConfig({});
    config.chains.byok.captcha_solve = [MODEL_GROQ, MODEL_35, MODEL_31];
    const res = await solveCaptcha({ ...captchaDeps(db, master, fetchFn), config }, solveInput());
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.model).toBe(MODEL_35);
    expect(res.attempts).toBe(1);
    expect(calls.map((c) => c.model)).toEqual([MODEL_35]);
    expect(calls.map((c) => c.model)).not.toContain(MODEL_GROQ);
  });

  it("parse failure advances to the next leg", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const { fetchFn, calls } = makeDualMockFetch(
      (model) => (model === MODEL_35 ? okGeminiText("Here are the tiles you asked for...") : okGeminiText(TILES_JSON)),
      () => okGroqText(TILES_JSON),
    );
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput());
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.attempts).toBe(2);
    expect(calls).toHaveLength(2);
    const rows = await solveRows(db);
    expect(rows.map((r) => r.outcome)).toEqual(["parse_failed", "submitted"]);
  });

  it("safety-blocked stops the chain immediately (no leg 2/3 call)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const safety = new Response(
      JSON.stringify({
        candidates: [{ finishReason: "SAFETY" }],
        promptFeedback: { blockReason: "SAFETY" },
        usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 0 },
      }),
      { status: 200 },
    );
    const { fetchFn, calls } = makeDualMockFetch(() => safety, () => okGroqText(TILES_JSON));
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput());
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toBe("safety_blocked");
    expect(res.fallback).toBe("human_assist");
    expect(res.attempts).toBe(1);
    expect(calls).toHaveLength(1);
    const rows = await solveRows(db);
    expect(rows).toHaveLength(1);
    expect(rows[0].outcome).toBe("safety_blocked");
  });

  it("usage_metadata_missing fails the leg (never billed on estimate) and advances", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const noUsageGemini = () =>
      new Response(
        JSON.stringify({ candidates: [{ content: { parts: [{ text: TILES_JSON }] }, finishReason: "STOP" }] }),
        { status: 200 },
      );
    const noUsageGroq = () =>
      new Response(
        JSON.stringify({ choices: [{ message: { content: TILES_JSON }, finish_reason: "stop" }] }),
        { status: 200 },
      );
    const { fetchFn } = makeDualMockFetch(() => noUsageGemini(), () => noUsageGroq());
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput());
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toBe("model_error");
    expect(res.attempts).toBe(3);
    const rows = await solveRows(db);
    expect(rows.map((r) => r.outcome)).toEqual(["model_error", "model_error", "model_error"]);
  });

  it("all 3 attempts exhausted -> ok:false + human_assist, no submission", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const { fetchFn } = makeDualMockFetch(() => errResp(500, "boom"), () => errResp(500, "boom"));
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput());
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toBe("model_error");
    expect(res.fallback).toBe("human_assist");
    expect(res.attempts).toBe(3);
    expect(await countAutoSubmissionsForTask(db, "bt-0000000000000001")).toBe(0);
  });
});

describe("byok_required path (DESIGN §3.2)", () => {
  it("tenant with no Gemini/Groq key -> byok_required, zero upstream calls", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master, { geminiKey: null, groqKey: null });
    const { fetchFn, calls } = makeDualMockFetch(() => okGeminiText(TILES_JSON), () => okGroqText(TILES_JSON));
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput());
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toBe("byok_required");
    expect(res.fallback).toBe("human_assist");
    expect(calls).toHaveLength(0);
    const rows = await solveRows(db);
    expect(rows).toHaveLength(1);
    expect(rows[0].outcome).toBe("byok_required");
    expect(rows[0].model).toBeNull();
  });
});

describe("caps (DESIGN §3.3 — submissions, from captcha_solves)", () => {
  it("per-task cap: 2 submitted in the task -> 3rd is cap_reached, no upstream call", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    await seedSubmittedRow(db, { id: "cs-seed-1", tenantId: "t-1", taskId: "bt-0000000000000001" });
    await seedSubmittedRow(db, { id: "cs-seed-2", tenantId: "t-1", taskId: "bt-0000000000000001" });
    const { fetchFn, calls } = makeDualMockFetch(() => okGeminiText(TILES_JSON), () => okGroqText(TILES_JSON));
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput());
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toBe("cap_reached");
    expect(res.fallback).toBe("human_assist");
    expect(calls).toHaveLength(0);
    expect(await countAutoSubmissionsForTask(db, "bt-0000000000000001")).toBe(2);
  });

  it("per-day cap: 10 submitted today -> 11th is cap_reached; 9 today proceeds", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    for (let i = 0; i < 10; i++) {
      await seedSubmittedRow(db, { id: `cs-day-${i}`, tenantId: "t-1", taskId: `bt-day-${i}` });
    }
    expect(await countAutoSubmissionsToday(db, "t-1", FIXED_NOW)).toBe(10);
    const { fetchFn, calls } = makeDualMockFetch(() => okGeminiText(TILES_JSON), () => okGroqText(TILES_JSON));
    const capped = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput({ task_id: "bt-new-task" }));
    expect(capped.ok).toBe(false);
    if (!capped.ok) expect(capped.error).toBe("cap_reached");
    expect(calls).toHaveLength(0);

    const db2 = new FakeD1();
    await seedTenantWithKeys(db2, "t-1", master);
    for (let i = 0; i < 9; i++) {
      await seedSubmittedRow(db2, { id: `cs-day-${i}`, tenantId: "t-1", taskId: `bt-day-${i}` });
    }
    const { fetchFn: fetchFn2, calls: calls2 } = makeDualMockFetch(() => okGeminiText(TILES_JSON), () => okGroqText(TILES_JSON));
    const ok = await solveCaptcha(captchaDeps(db2, master, fetchFn2), solveInput({ task_id: "bt-new-task" }));
    expect(ok.ok).toBe(true);
    expect(calls2.length).toBeGreaterThan(0);
  });

  it("UTC-day rollover: 10 submitted yesterday do not count today", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const yesterday = FIXED_NOW - 24 * 60 * 60_000;
    for (let i = 0; i < 10; i++) {
      await seedSubmittedRow(db, { id: `cs-old-${i}`, tenantId: "t-1", taskId: `bt-old-${i}`, createdAt: yesterday });
    }
    expect(await countAutoSubmissionsToday(db, "t-1", FIXED_NOW)).toBe(0);
    const { fetchFn } = makeDualMockFetch(() => okGeminiText(TILES_JSON), () => okGroqText(TILES_JSON));
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput({ task_id: "bt-new-task" }));
    expect(res.ok).toBe(true);
  });

  it("a successful solve increments the task/day counts by exactly 1", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const { fetchFn } = makeDualMockFetch(() => okGeminiText(TILES_JSON), () => okGroqText(TILES_JSON));
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput());
    expect(res.ok).toBe(true);
    expect(await countAutoSubmissionsForTask(db, "bt-0000000000000001")).toBe(1);
    expect(await countAutoSubmissionsToday(db, "t-1", FIXED_NOW)).toBe(1);
    // ... and the second solve in the same task still proceeds (cap is 2).
    const res2 = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput());
    expect(res2.ok).toBe(true);
    expect(await countAutoSubmissionsForTask(db, "bt-0000000000000001")).toBe(2);
  });
});

describe("audit: SECRET-* markers never in traces or rows (DESIGN §4.3/§4.4)", () => {
  it("answer + token values never appear in captcha_solves rows or traces", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    // The model "solves" a text captcha with a marker value as the answer.
    const markerText = JSON.stringify({ kind: "text", text: "SECRET-TOKEN-XYZ", confidence: 0.95 });
    const { fetchFn } = makeDualMockFetch(() => okGeminiText(markerText), () => okGroqText(markerText));
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput({ challenge_type: "text" }));
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    // The answer reached the caller (in-memory only) ...
    expect(res.answer).toEqual({ kind: "text", text: "SECRET-TOKEN-XYZ" });
    // ... but NOTHING persisted carries it.
    const rows = await solveRows(db);
    const traces = await traceRows(db);
    const persisted = JSON.stringify({ rows, traces });
    expect(persisted).not.toContain("SECRET-TOKEN-XYZ");
    expect(persisted).not.toContain("SECRET-SOLUTION");
    expect(persisted).not.toContain(IMG_B64);
    // Schema check: no answer/solution/token/image column exists.
    expect(Object.keys(rows[0]).sort()).not.toContain("answer");
    expect(Object.keys(rows[0]).sort()).not.toContain("solution");
    expect(Object.keys(rows[0]).sort()).not.toContain("token");
    expect(Object.keys(rows[0]).sort()).not.toContain("image_b64");
    expect(rows[0].image_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(rows[0].outcome).toBe("submitted");
  });
});

describe("metering: solves do not consume the replies/mo cap (D3 Q2 locked)", () => {
  it("a successful solve meters llm_usage but leaves replies at 0", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const { fetchFn } = makeDualMockFetch(() => okGeminiText(TILES_JSON), () => okGroqText(TILES_JSON));
    const res = await solveCaptcha(captchaDeps(db, master, fetchFn), solveInput());
    expect(res.ok).toBe(true);
    const usage = await db.prepare("SELECT * FROM llm_usage").all();
    expect(usage.results.length).toBeGreaterThan(0);
    const counters = await db
      .prepare("SELECT replies FROM usage_counters WHERE tenant_id = ? AND period = ?")
      .bind("t-1", "2026-11")
      .first<{ replies: number }>();
    expect(counters?.replies ?? 0).toBe(0);
  });
});

describe("rate-limit budget (DESIGN §2.2)", () => {
  it("captcha_solve budget is 10/min per tenant", () => {
    expect(RATE_LIMITS.captcha_solve).toEqual({ limit: 10, windowMs: 60_000 });
  });

  it("11th call in a minute is refused (in-memory fallback, no Upstash)", async () => {
    const env = fakeEnv(new FakeD1());
    for (let i = 0; i < 10; i++) {
      expect((await checkRateLimit(env, "captcha_solve", "t-rl")).allowed).toBe(true);
    }
    const refused = await checkRateLimit(env, "captcha_solve", "t-rl");
    expect(refused.allowed).toBe(false);
    // M-I-4 follow-up: the refusal carries the window so the caller
    // can send Retry-After (60 s for every route today).
    expect(refused.retryAfterSec).toBe(60);
    // A different tenant is unaffected.
    expect((await checkRateLimit(env, "captcha_solve", "t-other")).allowed).toBe(true);
  });
});

describe("POST /api/captcha/solve route matrix (DESIGN §8.1/§8.4)", () => {
  it("no signature -> 401; bad signature -> 401; unpaired device -> 403", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);

    const noSig = await handleRequest(
      new Request("https://hub/api/captcha/solve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(solveBody()),
      }),
      fakeEnv(db, { KEY_ENC_SECRET: master }),
    );
    expect(noSig.status).toBe(401);

    const bad = await signedSolve(db, key, solveBody(), { signPayload: "deadbeef", masterB64: master });
    expect(bad.status).toBe(401);

    const ghost = await signedSolve(db, key, solveBody(), { deviceId: "dev-ghost", masterB64: master });
    expect(ghost.status).toBe(403);
    expect(((await ghost.json()) as Record<string, unknown>).error).toBe("device_not_paired");
  });

  it("missing image / oversized image / flag false / bad type -> 400", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);

    const missing = await signedSolve(db, key, solveBody({ image_b64: undefined }), { masterB64: master });
    expect(missing.status).toBe(400);
    const flagOff = await signedSolve(db, key, solveBody({ auto_solve_allowed: false }), { masterB64: master });
    expect(flagOff.status).toBe(400);
    const badType = await signedSolve(db, key, solveBody({ challenge_type: "slider" }), { masterB64: master });
    expect(badType.status).toBe(400);
    const big = Buffer.alloc(MAX_CAPTCHA_IMAGE_BYTES + 1, 0x41).toString("base64");
    const oversized = await signedSolve(db, key, solveBody({ image_b64: big }), { masterB64: master });
    expect(oversized.status).toBe(400);
  });

  it("known unsolvable type (turnstile) -> 200 ok:false not_allowed + human_assist", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const res = await signedSolve(db, key, solveBody({ challenge_type: "turnstile" }), { masterB64: master });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(false);
    expect(body.error).toBe("not_allowed");
    expect(body.fallback).toBe("human_assist");
  });

  it("tenant with no key -> 402 byok_required with ok:false + human_assist", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master, { geminiKey: null, groqKey: null });
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const res = await signedSolve(db, key, solveBody(), { masterB64: master });
    expect(res.status).toBe(402);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(false);
    expect(body.error).toBe("byok_required");
    expect(body.fallback).toBe("human_assist");
    expect(String(body.solve_id)).toMatch(/^cs-[0-9a-f]{16}$/);
  });

  it("happy path (mocked upstream) -> 200 ok:true with solve_id + model + confidence; audit row present", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    vi.stubGlobal(
      "fetch",
      async (url: unknown) => {
        const u = String(url);
        if (u.includes("generativelanguage.googleapis.com")) return okGeminiText(TILES_JSON);
        if (u.includes("api.groq.com")) return okGroqText(TILES_JSON);
        return new Response(JSON.stringify({ error: "unexpected fetch " + u }), { status: 500 });
      },
    );
    const res = await signedSolve(db, key, solveBody(), { masterB64: master });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(String(body.solve_id)).toMatch(/^cs-[0-9a-f]{16}$/);
    expect(body.model).toBe(MODEL_35);
    expect(body.confidence).toBe(0.87);
    expect(body.answer).toEqual({ kind: "tiles", grid_rows: 3, grid_cols: 3, tiles: [0, 4, 7] });
    expect(body.attempts).toBe(1);
    const rows = await solveRows(db);
    expect(rows).toHaveLength(1);
    expect(rows[0].outcome).toBe("submitted");
    expect(rows[0].model).toBe(MODEL_35);
    expect(JSON.stringify(rows[0])).not.toContain("0,4,7");
  });

  it("cap hit via the route -> 200 ok:false cap_reached + human_assist (not an HTTP error)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    await seedSubmittedRow(db, { id: "cs-seed-1", tenantId: "t-1", taskId: "bt-0000000000000001" });
    await seedSubmittedRow(db, { id: "cs-seed-2", tenantId: "t-1", taskId: "bt-0000000000000001" });
    const res = await signedSolve(db, key, solveBody(), { masterB64: master });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(false);
    expect(body.error).toBe("cap_reached");
    expect(body.fallback).toBe("human_assist");
  });

  it("11th solve in a minute -> 429 rate_limited WITH Retry-After: 60 (M-I-4 follow-up)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    // Key-less tenant: the first 10 pass the limiter and 402 at
    // byok_required (exactly the M-I-4 live shape), the 11th 429s.
    await seedTenantWithKeys(db, "t-429", master, { geminiKey: null, groqKey: null });
    const key = await genDeviceKey();
    await seedDevice(db, "dev-429", "t-429", key.publicKeyB64);
    for (let i = 0; i < 10; i++) {
      const res = await signedSolve(db, key, solveBody({ task_id: `bt-429-${i}` }), {
        deviceId: "dev-429",
        masterB64: master,
      });
      expect(res.status).toBe(402);
    }
    const limited = await signedSolve(db, key, solveBody({ task_id: "bt-429-10" }), {
      deviceId: "dev-429",
      masterB64: master,
    });
    expect(limited.status).toBe(429);
    expect(((await limited.json()) as Record<string, unknown>).error).toBe("rate_limited");
    expect(limited.headers.get("Retry-After")).toBe("60");
    // No Upstash in the test env, so the in-memory fallback enforced it.
    expect(limited.headers.get("x-ratelimit-fallback")).toBe("1");
  });
});

describe("routeLlm captcha_solve plumbing (DESIGN §7.1)", () => {
  it("captcha_solve without an image is bad_request", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKeys(db, "t-1", master);
    const { fetchFn } = makeDualMockFetch(() => okGeminiText(TILES_JSON), () => okGroqText(TILES_JSON));
    const res = await routeLlm(
      { db, fetchFn, sleepFn: async () => {}, nowMs: () => FIXED_NOW, masterKeyB64: master },
      { tenant_id: "t-1", turn_id: "turn-1", kind: "captcha_solve", messages: [{ role: "user", text: "solve" }] },
    );
    expect(res.ok).toBe(false);
    expect(res.error_code).toBe("bad_request");
  });
});
