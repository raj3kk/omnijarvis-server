/**
 * captcha.ts — Captcha auto-solver (D3 LOCKED 2026-11-22, DESIGN §2–§4).
 *
 * Hub-side only: the device captures the challenge image from its live
 * WebView session, asserts the one-time user flag, and calls
 * POST /api/captcha/solve; this module runs the vision chain and hands
 * the answer back. The hub NEVER applies the answer and NEVER receives
 * a solution token.
 *
 * Frozen numbers (DESIGN §3.1 — do not re-derive):
 *   3 attempts (one per chain leg), confidence >= 0.80, 15 s per call,
 *   60 s total budget, 1 submission/challenge, 2 auto-solved/task,
 *   10/day/tenant (UTC day).
 *
 * Vision chain (DESIGN §2.2): gemini-3.5-flash-lite ->
 * gemini-3.1-flash-lite -> qwen/qwen3.8-27b (Groq vision). gpt-oss-120b
 * is TEXT-ONLY and is refused for this kind inside routeLlm(); this
 * module never names it.
 *
 * Caps count SUBMISSIONS (captcha_solves rows with outcome='submitted'),
 * not vision attempts — attempts are read-only and never touch the site.
 * A cap hit is a normal outcome (200 ok:false error cap_reached +
 * fallback human_assist), never an HTTP error.
 *
 * Audit (DESIGN §4.1): one captcha_solves row per attempt. The table's
 * id is the solve_id — but a request can make up to 3 attempts, so
 * attempts 2–3 carry id `<solve_id>-a<n>` (the DESIGN text says both
 * "id = solve_id, one per request" and "one row per attempt"; the
 * suffix is the only reading that keeps the PK unique). Attempt 1
 * always carries the bare solve_id. No row, trace, or log ever carries
 * the answer, a solution token, or the image bytes — only the image
 * SHA-256 (audit/dedup).
 *
 * Solves do NOT consume the replies/mo cap (D3 Q2 locked): tokens are
 * metered in llm_usage per vision call via routeLlm(); recordReply /
 * completeTurn is never called here.
 */
import type { D1Like } from "./db";
import { getTenant, insertTrace } from "./db";
import { base64ToBytes } from "./crypto";
import { sha256HexBytes } from "./docs";
import {
  MODEL_31,
  MODEL_35,
  MODEL_GROQ_VISION,
  loadRouterConfig,
  routeLlm,
  type RouterConfig,
  type RouterDeps,
} from "./router";

/** Frozen numbers — DESIGN §3.1. */
export const MAX_AUTO_SOLVE_ATTEMPTS = 3;
export const MIN_SOLVE_CONFIDENCE = 0.8;
export const CAPTCHA_SOLVE_TIMEOUT_MS = 15_000;
export const CAPTCHA_AUTO_SOLVE_BUDGET_MS = 60_000;
export const MAX_SUBMISSIONS_PER_CHALLENGE = 1;
export const MAX_AUTO_SOLVED_PER_TASK = 2;
export const MAX_AUTO_SOLVES_PER_DAY = 10;
/** Challenge image cap (DESIGN §2.1): PNG <= 200 KB decoded. */
export const MAX_CAPTCHA_IMAGE_BYTES = 200 * 1024;

/** Vision chain, BYOK quality-first (DESIGN §2.2). */
export const CAPTCHA_SOLVE_CHAIN_BYOK = [MODEL_35, MODEL_31, MODEL_GROQ_VISION] as const;
/** Founder-pays cost-first order (gated — no founder key live, so BYOK in practice). */
export const CAPTCHA_SOLVE_CHAIN_FOUNDER = [MODEL_31, MODEL_35, MODEL_GROQ_VISION] as const;

/** Challenge types the route accepts (DESIGN §2.4 + §4.1 audit values). */
export const KNOWN_CHALLENGE_TYPES = [
  "recaptcha_grid",
  "hcaptcha_grid",
  "text",
  "turnstile",
  "audio",
  "unknown",
] as const;
export type ChallengeType = (typeof KNOWN_CHALLENGE_TYPES)[number];

/** Types the vision chain may attempt (DESIGN §5 scope). */
export const AUTO_SOLVABLE_TYPES = ["recaptcha_grid", "hcaptcha_grid", "text"] as const;
export type AutoSolvableType = (typeof AUTO_SOLVABLE_TYPES)[number];

export function isAutoSolvableType(challengeType: string): challengeType is AutoSolvableType {
  return (AUTO_SOLVABLE_TYPES as readonly string[]).includes(challengeType);
}

/** Fixed vision prompts, one per type (DESIGN §2.6 — no per-site tuning,
 * no page content is ever sent; the model reads the instruction text
 * rendered in the challenge image itself). */
export const CAPTCHA_PROMPTS: Record<AutoSolvableType, string> = {
  recaptcha_grid:
    "You are solving a visual captcha grid. Look at the image and read the instruction text shown in it " +
    "(for example, select all tiles containing a named object). Reply with JSON only, no other text: " +
    '{"kind":"tiles","grid_rows":<rows>,"grid_cols":<cols>,"tiles":[<row-major indices, 0 = top-left>],"confidence":<0-1>}. ' +
    "grid_rows and grid_cols must match the visible grid. confidence is your own confidence that the tiles are correct.",
  hcaptcha_grid:
    "You are solving a visual captcha grid. Look at the image and read the instruction text shown in it " +
    "(for example, select all tiles containing a named object). Reply with JSON only, no other text: " +
    '{"kind":"tiles","grid_rows":<rows>,"grid_cols":<cols>,"tiles":[<row-major indices, 0 = top-left>],"confidence":<0-1>}. ' +
    "grid_rows and grid_cols must match the visible grid. confidence is your own confidence that the tiles are correct.",
  text:
    "Read the characters shown in this distorted-text captcha image. Reply with JSON only, no other text: " +
    '{"kind":"text","text":"<characters>","confidence":<0-1>}. ' +
    "confidence is your own confidence that the characters are correct.",
};

/** Solve answers (DESIGN §2.2 schemas). The answer lives only in memory
 * on the device for the apply step — it is NEVER written to D1, traces,
 * or logs (DESIGN §4.3). */
export type SolveAnswer =
  | { kind: "tiles"; grid_rows: number; grid_cols: number; tiles: number[] }
  | { kind: "text"; text: string };

export type SolveError =
  | "low_confidence"
  | "no_answer"
  | "model_error"
  | "safety_blocked"
  | "cap_reached"
  | "not_allowed"
  | "byok_required";

/** Audit outcomes (DESIGN §4.1), plus 'submitted' — the hub-side
 * submission event (the answer handed to the device, which submits it
 * exactly once). submitted_ok / submitted_wrong are device-side
 * distinctions reported via /api/browser/resolve with the solve_id —
 * linkSolveOutcome() below links them back to the submitted row, so
 * the success rate is auditable per solve_id (U12, hub v17). */
export type SolveOutcome =
  | "answered"
  | "low_confidence"
  | "no_answer"
  | "parse_failed"
  | "model_error"
  | "timeout"
  | "safety_blocked"
  | "cap_reached"
  | "not_allowed"
  | "byok_required"
  | "submitted"
  | "submitted_ok"
  | "submitted_wrong";

/** cs- + 16 hex (DESIGN §2.4). */
export function newSolveId(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return "cs-" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Decoded byte length of a base64 string, without decoding it. */
export function decodedImageByteLength(b64: string): number {
  const clean = b64.replace(/\s/g, "");
  if (clean.length === 0) return 0;
  const pad = clean.endsWith("==") ? 2 : clean.endsWith("=") ? 1 : 0;
  return Math.floor((clean.length * 3) / 4) - pad;
}

export function isValidBase64(b64: string): boolean {
  const clean = b64.replace(/\s/g, "");
  if (clean.length === 0 || clean.length % 4 !== 0) return false;
  return /^[A-Za-z0-9+/]+={0,2}$/.test(clean);
}

// --- Request validation (hub route: 400 bad_request) ---

export interface ValidatedSolveRequest {
  task_id: string;
  site: string;
  challenge_type: ChallengeType;
  image_b64: string;
  auto_solve_allowed: true;
}

export function validateSolveRequest(
  body: Record<string, unknown>,
): { ok: true; value: ValidatedSolveRequest } | { ok: false; error: "bad_request" } {
  const bad = { ok: false, error: "bad_request" } as const;
  const taskId = body.task_id;
  const site = body.site;
  const challengeType = body.challenge_type;
  const imageB64 = body.image_b64;
  if (typeof taskId !== "string" || !taskId) return bad;
  if (typeof site !== "string" || !site) return bad;
  if (typeof challengeType !== "string" || !(KNOWN_CHALLENGE_TYPES as readonly string[]).includes(challengeType)) {
    return bad;
  }
  if (typeof imageB64 !== "string" || !imageB64) return bad;
  if (!isValidBase64(imageB64)) return bad;
  if (decodedImageByteLength(imageB64) > MAX_CAPTCHA_IMAGE_BYTES) return bad;
  if (body.auto_solve_allowed !== true) return bad;
  return {
    ok: true,
    value: {
      task_id: taskId,
      site,
      challenge_type: challengeType as ChallengeType,
      image_b64: imageB64,
      auto_solve_allowed: true,
    },
  };
}

// --- Answer parsing + schema validation (DESIGN §2.2) ---

/** Strict JSON only. One surrounding ```json fence is tolerated (models
 * emit it despite the prompt); anything else — prose, missing fields,
 * out-of-range indices, confidence absent/outside 0–1 — is a parse
 * failure and the chain advances. */
export function parseSolveAnswer(text: string): unknown | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  let json = trimmed;
  if (json.startsWith("```")) {
    json = json.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  }
  try {
    return JSON.parse(json) as unknown;
  } catch {
    return null;
  }
}

export function validateSolveAnswer(
  value: unknown,
  challengeType: string,
): { ok: true; answer: SolveAnswer; confidence: number } | { ok: false } {
  if (!value || typeof value !== "object" || Array.isArray(value)) return { ok: false };
  const v = value as Record<string, unknown>;
  const confidence = v.confidence;
  if (typeof confidence !== "number" || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    return { ok: false };
  }
  if (challengeType === "text") {
    if (v.kind !== "text" || typeof v.text !== "string" || !v.text || v.text.length > 128) {
      return { ok: false };
    }
    return { ok: true, answer: { kind: "text", text: v.text }, confidence };
  }
  // Grid types: kind must be tiles, dims must match the visible grid,
  // every index must be in range.
  if (v.kind !== "tiles") return { ok: false };
  const rows = v.grid_rows;
  const cols = v.grid_cols;
  const tiles = v.tiles;
  if (typeof rows !== "number" || !Number.isInteger(rows) || rows < 1 || rows > 10) return { ok: false };
  if (typeof cols !== "number" || !Number.isInteger(cols) || cols < 1 || cols > 10) return { ok: false };
  if (!Array.isArray(tiles) || tiles.length === 0) return { ok: false };
  const total = rows * cols;
  for (const t of tiles) {
    if (typeof t !== "number" || !Number.isInteger(t) || t < 0 || t >= total) return { ok: false };
  }
  return { ok: true, answer: { kind: "tiles", grid_rows: rows, grid_cols: cols, tiles: tiles as number[] }, confidence };
}

// --- Cap counting (DESIGN §3.3: submissions, from captcha_solves) ---

export async function countAutoSubmissionsForTask(db: D1Like, taskId: string): Promise<number> {
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM captcha_solves WHERE task_id = ? AND outcome = ?")
    .bind(taskId, "submitted")
    .first<{ n: number }>();
  return row?.n ?? 0;
}

export async function countAutoSubmissionsToday(db: D1Like, tenantId: string, nowMs: number): Promise<number> {
  const start = new Date(nowMs);
  start.setUTCHours(0, 0, 0, 0);
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM captcha_solves WHERE tenant_id = ? AND outcome = ? AND created_at >= ?")
    .bind(tenantId, "submitted", start.getTime())
    .first<{ n: number }>();
  return row?.n ?? 0;
}

// --- Audit rows + traces (answer-free, DESIGN §4.1/§4.3) ---

interface SolveRow {
  solve_id: string;
  tenant_id: string;
  device_id: string;
  task_id: string;
  site: string;
  challenge_type: string;
  model: string | null;
  confidence: number | null;
  outcome: SolveOutcome;
  attempts: number;
  latency_ms: number;
  image_sha256: string | null;
  created_at: number;
}

async function insertSolveRow(db: D1Like, row: SolveRow): Promise<void> {
  // Attempt 1 carries the bare solve_id; attempts 2–3 carry a suffix
  // (see the module header — the PK must stay unique per attempt).
  const id = row.attempts <= 1 ? row.solve_id : `${row.solve_id}-a${row.attempts}`;
  await db
    .prepare(
      "INSERT INTO captcha_solves (id, tenant_id, device_id, task_id, site, challenge_type, model, confidence, outcome, attempts, latency_ms, flag_asserted, image_sha256, created_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(
      id,
      row.tenant_id,
      row.device_id,
      row.task_id,
      row.site,
      row.challenge_type,
      row.model,
      row.confidence,
      row.outcome,
      row.attempts,
      row.latency_ms,
      1,
      row.image_sha256,
      row.created_at,
    )
    .run();
}

/**
 * U12 — link a solve outcome back to its solve_id (hub v17).
 * The device reports, via /api/browser/resolve { solve_id, solved },
 * whether the submitted answer actually cleared the challenge. The
 * submitted row is the successful attempt's row: id = solve_id
 * (attempt 1) or `<solve_id>-a2` / `-a3` (attempts 2–3). Only a row
 * still in outcome 'submitted' is relinked — a failed/capped attempt
 * keeps its own outcome, and a second link finds no 'submitted' row
 * (idempotent: linked:false, no overwrite). tenantId scopes the
 * update for device callers; internal-secret callers pass undefined
 * (admin-equivalent, unscoped).
 */
export async function linkSolveOutcome(
  db: D1Like,
  solveId: string,
  solved: boolean,
  tenantId?: string,
): Promise<{ ok: boolean; linked: boolean }> {
  const outcome: SolveOutcome = solved ? "submitted_ok" : "submitted_wrong";
  const ids = [solveId, `${solveId}-a2`, `${solveId}-a3`];
  const placeholders = ids.map(() => "?").join(",");
  const where = tenantId
    ? `tenant_id = ? AND outcome = 'submitted' AND id IN (${placeholders})`
    : `outcome = 'submitted' AND id IN (${placeholders})`;
  const args = tenantId ? [tenantId, ...ids] : ids;
  const res = await db
    .prepare(`UPDATE captcha_solves SET outcome = ? WHERE ${where}`)
    .bind(outcome, ...args)
    .run();
  const changes = (res.meta as { changes?: number } | undefined)?.changes ?? 0;
  return { ok: true, linked: changes > 0 };
}

async function traceSolve(
  db: D1Like,
  tenantId: string,
  deviceId: string,
  row: Pick<SolveRow, "solve_id" | "task_id" | "site" | "challenge_type" | "model" | "confidence" | "outcome" | "attempts" | "latency_ms">,
): Promise<void> {
  // Detail = the table row minus the hash. NEVER the answer/token/image.
  await insertTrace(db, tenantId, deviceId, "captcha_auto_solve", {
    solve_id: row.solve_id,
    task_id: row.task_id,
    site: row.site,
    challenge_type: row.challenge_type,
    model: row.model,
    confidence: row.confidence,
    outcome: row.outcome,
    attempts: row.attempts,
    latency_ms: row.latency_ms,
  });
}

// --- Orchestration ---

export interface CaptchaDeps {
  db: D1Like;
  fetchFn?: typeof fetch;
  sleepFn?: (ms: number) => Promise<void>;
  nowMs?: () => number;
  masterKeyB64?: string;
  founderKey?: string;
  founderGroqKey?: string;
  config?: RouterConfig;
}

export interface SolveCaptchaInput {
  tenant_id: string;
  device_id: string;
  task_id: string;
  site: string;
  challenge_type: string;
  image_b64: string;
}

export type SolveCaptchaResult =
  | {
      ok: true;
      solve_id: string;
      task_id: string;
      site: string;
      challenge_type: string;
      answer: SolveAnswer;
      confidence: number;
      model: string;
      attempts: number;
      latency_ms: number;
    }
  | {
      ok: false;
      solve_id: string;
      error: SolveError;
      attempts: number;
      latency_ms: number;
      fallback: "human_assist";
    };

/** Error codes from routeLlm that end the chain at once — retrying
 * another leg cannot change them (cap/tenant/setup states). */
const STOP_ERROR_CODES = new Set([
  "safety_blocked",
  "byok_required",
  "replies_cap",
  "turn_calls_cap",
  "tenant_not_found",
  "founder_key_missing",
  "no_route",
]);

function failure(
  solveId: string,
  error: SolveError,
  attempts: number,
  latencyMs: number,
): Extract<SolveCaptchaResult, { ok: false }> {
  return { ok: false, solve_id: solveId, error, attempts, latency_ms: latencyMs, fallback: "human_assist" };
}

/**
 * Run the auto-solve phase for one challenge. Input is assumed
 * validated by validateSolveRequest (the hub route enforces it).
 * One vision call per chain leg, driven one leg at a time so a
 * parse failure / low confidence can advance to the next leg —
 * routeLlm() alone cannot do that (it stops at the first leg that
 * returns text). Each leg call goes through the full routeLlm()
 * machinery (caps, metering via llm_usage, circuit breaker, traces).
 */
export async function solveCaptcha(deps: CaptchaDeps, input: SolveCaptchaInput): Promise<SolveCaptchaResult> {
  const now = deps.nowMs ? deps.nowMs() : Date.now();
  const started = now;
  const elapsed = () => (deps.nowMs ? deps.nowMs() : Date.now()) - started;
  const solveId = newSolveId();
  const { tenant_id, device_id, task_id, site, challenge_type } = input;

  let imageSha: string | null = null;
  try {
    const bytes = base64ToBytes(input.image_b64);
    imageSha = await sha256HexBytes(bytes.buffer as ArrayBuffer);
  } catch {
    imageSha = null; // hash is audit-only; a decode failure must not fail the solve
  }

  const record = async (partial: Omit<SolveRow, "solve_id" | "tenant_id" | "device_id" | "task_id" | "site" | "challenge_type" | "image_sha256" | "created_at">): Promise<void> => {
    const row: SolveRow = {
      solve_id: solveId,
      tenant_id,
      device_id,
      task_id,
      site,
      challenge_type,
      image_sha256: imageSha,
      created_at: deps.nowMs ? deps.nowMs() : Date.now(),
      ...partial,
    };
    await insertSolveRow(deps.db, row);
    await traceSolve(deps.db, tenant_id, device_id, row);
  };

  // Scope: only grids + simple text are solvable (DESIGN §5). Anything
  // else (audio, Turnstile, v3, unknown) is human-only by design.
  if (!isAutoSolvableType(challenge_type)) {
    await record({ model: null, confidence: null, outcome: "not_allowed", attempts: 0, latency_ms: elapsed() });
    return failure(solveId, "not_allowed", 0, elapsed());
  }

  // Caps (DESIGN §3.3): 2/task, 10/day — counted from submissions.
  // Checked BEFORE any vision call: a capped challenge costs no tokens.
  const taskCount = await countAutoSubmissionsForTask(deps.db, task_id);
  const dayCount = await countAutoSubmissionsToday(deps.db, tenant_id, started);
  if (taskCount >= MAX_AUTO_SOLVED_PER_TASK || dayCount >= MAX_AUTO_SOLVES_PER_DAY) {
    await record({ model: null, confidence: null, outcome: "cap_reached", attempts: 0, latency_ms: elapsed() });
    return failure(solveId, "cap_reached", 0, elapsed());
  }

  const tenant = await getTenant(deps.db, tenant_id);
  if (!tenant) {
    await record({ model: null, confidence: null, outcome: "model_error", attempts: 0, latency_ms: elapsed() });
    return failure(solveId, "model_error", 0, elapsed());
  }
  const chain =
    tenant.billing_mode === "founder_pays" ? CAPTCHA_SOLVE_CHAIN_FOUNDER : CAPTCHA_SOLVE_CHAIN_BYOK;
  const baseConfig = deps.config ?? loadRouterConfig({});
  const prompt = CAPTCHA_PROMPTS[challenge_type as AutoSolvableType];

  let lastFailure: SolveError = "no_answer";
  for (let i = 0; i < MAX_AUTO_SOLVE_ATTEMPTS; i++) {
    // Total budget (60 s): expiry aborts the phase at once, no partial
    // answer is ever submitted.
    if (elapsed() >= CAPTCHA_AUTO_SOLVE_BUDGET_MS) {
      await record({ model: null, confidence: null, outcome: "timeout", attempts: i, latency_ms: elapsed() });
      return failure(solveId, "model_error", i, elapsed());
    }
    const model = chain[i];
    // One leg per routeLlm call: the chain is pinned to this leg only,
    // so this module — not routeLlm — decides whether to advance.
    const legChains = JSON.parse(JSON.stringify(baseConfig.chains)) as RouterConfig["chains"];
    for (const mode of Object.keys(legChains)) legChains[mode]["captcha_solve"] = [model];
    const legConfig: RouterConfig = { prices: baseConfig.prices, chains: legChains };
    const legStart = deps.nowMs ? deps.nowMs() : Date.now();
    const legLatency = () => (deps.nowMs ? deps.nowMs() : Date.now()) - legStart;
    const res = await routeLlm(
      {
        db: deps.db,
        fetchFn: deps.fetchFn,
        sleepFn: deps.sleepFn,
        nowMs: deps.nowMs,
        masterKeyB64: deps.masterKeyB64,
        founderKey: deps.founderKey,
        founderGroqKey: deps.founderGroqKey,
        config: legConfig,
        timeoutMs: CAPTCHA_SOLVE_TIMEOUT_MS,
      },
      {
        tenant_id,
        device_id,
        turn_id: solveId,
        kind: "captcha_solve",
        messages: [{ role: "user", text: prompt }],
        image_b64: input.image_b64,
      },
    );
    const attemptNo = i + 1;

    if (!res.ok) {
      const code = res.error_code ?? "upstream_error";
      if (code === "safety_blocked") {
        // Safety-blocked stops the chain immediately — a refusal will
        // not change on the next model (DESIGN §3.2).
        await record({ model, confidence: null, outcome: "safety_blocked", attempts: attemptNo, latency_ms: legLatency() });
        return failure(solveId, "safety_blocked", attemptNo, elapsed());
      }
      if (code === "byok_required") {
        // No usable key for any leg: silent human-assist (a setup
        // state, not a solve failure). The hub maps this to HTTP 402.
        await record({ model: null, confidence: null, outcome: "byok_required", attempts: i, latency_ms: legLatency() });
        return failure(solveId, "byok_required", i, elapsed());
      }
      if (STOP_ERROR_CODES.has(code)) {
        await record({ model, confidence: null, outcome: "model_error", attempts: attemptNo, latency_ms: legLatency() });
        return failure(solveId, "model_error", attemptNo, elapsed());
      }
      const outcome: SolveOutcome = code === "timeout" ? "timeout" : "model_error";
      lastFailure = "model_error";
      await record({ model, confidence: null, outcome, attempts: attemptNo, latency_ms: legLatency() });
      continue;
    }

    const text = res.text ?? "";
    if (!text) {
      lastFailure = "no_answer";
      await record({ model, confidence: null, outcome: "no_answer", attempts: attemptNo, latency_ms: legLatency() });
      continue;
    }
    const parsed = parseSolveAnswer(text);
    if (parsed === null) {
      lastFailure = "no_answer";
      await record({ model, confidence: null, outcome: "parse_failed", attempts: attemptNo, latency_ms: legLatency() });
      continue;
    }
    const validated = validateSolveAnswer(parsed, challenge_type);
    if (!validated.ok) {
      lastFailure = "no_answer";
      await record({ model, confidence: null, outcome: "parse_failed", attempts: attemptNo, latency_ms: legLatency() });
      continue;
    }
    if (validated.confidence < MIN_SOLVE_CONFIDENCE) {
      // Below threshold: the answer is NOT submitted. Advance a leg.
      lastFailure = "low_confidence";
      await record({ model, confidence: validated.confidence, outcome: "low_confidence", attempts: attemptNo, latency_ms: legLatency() });
      continue;
    }
    // Success: the answer is handed to the device, which submits it
    // exactly once (MAX_SUBMISSIONS_PER_CHALLENGE = 1, device-side).
    await record({ model, confidence: validated.confidence, outcome: "submitted", attempts: attemptNo, latency_ms: legLatency() });
    return {
      ok: true,
      solve_id: solveId,
      task_id,
      site,
      challenge_type,
      answer: validated.answer,
      confidence: validated.confidence,
      model,
      attempts: attemptNo,
      latency_ms: elapsed(),
    };
  }

  // All 3 attempts exhausted without a >= 0.80 answer: human-assist.
  return failure(solveId, lastFailure, MAX_AUTO_SOLVE_ATTEMPTS, elapsed());
}
