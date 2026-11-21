/**
 * router.ts — Workers-native LLM router (D11, Phase 3 stage 3a).
 *
 * LiteLLM proxy is REJECTED (541 MB idle > Render free 512 MB) — this is
 * a few-hundred-KB module inside omnijarvis-hub. It enforces, in order:
 *   1. tenant exists + plan limits (D2 pricing)
 *   2. BYOK key present + decryptable (founder key is NEVER a silent
 *      fallback — founder quota never burns for a customer)
 *   3. replies/mo cap + 5 calls/turn cap (hard refuse, no charge)
 *   4. 5,000 input-token cap (truncate oldest-first, system + last 2 turns kept)
 *   5. fallback chain (retryable failures only) + circuit breaker
 *   6. metering per call (usageMetadata is the source of truth)
 *
 * Two modes (D11 §3.1 — the tension, resolved by billing_mode):
 *   byok (live default):        3.5 FL -> 3.1 FL (quality-first)
 *   founder_pays (gated):       3.1 FL -> 3.5 FL (cost-first)
 * gemini-2.5-flash-lite is RETIRED (Google 404 for new users since
 * ~Nov 2026 — "no longer available to new users, use gemini-3.5-flash-lite").
 * It appears NOWHERE in chains/prices/validation (P0 fix, 2026-11-21):
 * loadRouterConfig throws on any retired model in a chain (R-T19 guard),
 * and validateGeminiKey falls back across live models (R-T18).
 * 3.8 Flash is BLOCK-LISTED in paid routes (2027 price doubles) — it is
 * refused even if it appears in config. Founder-pays tenants cannot be
 * created until a founder key exists (admin route refuses the mode).
 *
 * Live mode (native-audio) is NOT routable here: generateContent cannot
 * serve gemini-2.5-flash-native-audio-dialog (Live API, not REST) — kind
 * "live" returns error live_not_routed by design; the phone's existing
 * Live path stays the only Live route. (2026-11-21: that model name is
 * not even in ListModels anymore, and generateContent on it is 404.)
 *
 * Gemini upstream: v1beta generateContent / embedContent, x-goog-api-key.
 * Prices are $/1M tokens == micro-dollars per token (5000 in + 500 out
 * on 3.1 FL = 5000*0.25 + 500*1.50 = 2000 micro = $0.00200).
 * Margin warning (P0 audit §7.2 re-check): at 3.1 FL prices the
 * founder-pays worst case goes NEGATIVE (Pro −₹1,442 / Business −₹4,361)
 * at current ₹999/₹2,999 pricing — see AUDIT_P0_ROUTER_FIX.md. BYOK is
 * unaffected (founder cost ₹0); founder-pays is gated (no founder key)
 * and must NOT be enabled without a pricing revisit (parent decision).
 */
import type { D1Like } from "./db";
import { getTenant, insertTrace } from "./db";
import { countTurnCalls, currentPeriod, getMonthUsage, recordReply, recordUsage } from "./metering";
import { decryptTenantKey, importMasterKey } from "./keyvault";

export const MODEL_31 = "gemini-3.1-flash-lite";
export const MODEL_35 = "gemini-3.5-flash-lite";
export const MODEL_EMBED = "gemini-embedding-001";
export const MODEL_LIVE = "gemini-2.5-flash-native-audio-dialog";

/** Live text models, quality-first (BYOK primary order). Validation tries these in order. */
export const LIVE_TEXT_MODELS = [MODEL_35, MODEL_31] as const;
/** Retired models — must never appear in any chain, price, or validation attempt. */
export const RETIRED_MODELS = ["gemini-2.5-flash-lite", "text-embedding-004"] as const;

export const DEFAULT_PRICES: Record<string, { in: number; out: number }> = {
  [MODEL_31]: { in: 0.25, out: 1.5 },
  [MODEL_35]: { in: 0.3, out: 2.5 },
  [MODEL_EMBED]: { in: 0.15, out: 0 },
};

export type RequestKind =
  | "agent_plan"
  | "quick_command"
  | "casual_chat"
  | "search_grounding"
  | "live"
  | "doc_extraction"
  | "embeddings";

const DEFAULT_CHAINS: Record<string, Record<RequestKind, string[]>> = {
  byok: {
    agent_plan: [MODEL_35, MODEL_31],
    quick_command: [MODEL_35, MODEL_31],
    casual_chat: [MODEL_35, MODEL_31],
    search_grounding: [MODEL_31, MODEL_35],
    live: [MODEL_LIVE],
    doc_extraction: [MODEL_35, MODEL_31],
    embeddings: [MODEL_EMBED],
  },
  founder_pays: {
    agent_plan: [MODEL_31, MODEL_35],
    quick_command: [MODEL_31, MODEL_35],
    casual_chat: [MODEL_31, MODEL_35],
    search_grounding: [MODEL_31, MODEL_35],
    live: [MODEL_LIVE],
    doc_extraction: [MODEL_31, MODEL_35],
    embeddings: [MODEL_EMBED],
  },
};

export const PLAN_LIMITS: Record<string, { replies: number; docs: boolean }> = {
  free: { replies: 100, docs: false },
  pro: { replies: 2500, docs: true },
  business: { replies: 7500, docs: true },
};

export const MAX_INPUT_TOKENS = 5000;
export const MAX_CALLS_PER_TURN = 5;
export const CALL_TIMEOUT_MS = 30_000;
const CIRCUIT_BREAKER_FAILURES = 5;
const CIRCUIT_BREAKER_MS = 5 * 60_000;

export interface RouterConfig {
  prices: Record<string, { in: number; out: number }>;
  chains: Record<string, Record<string, string[]>>;
}

/** Parse ROUTER_CONFIG env JSON over defaults. 3.8 anywhere = throw (block-listed). */
export function loadRouterConfig(env: { ROUTER_CONFIG?: string }): RouterConfig {
  const config: RouterConfig = {
    prices: { ...DEFAULT_PRICES },
    chains: JSON.parse(JSON.stringify(DEFAULT_CHAINS)) as RouterConfig["chains"],
  };
  const raw = env.ROUTER_CONFIG;
  if (raw) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error("ROUTER_CONFIG is not valid JSON");
    }
    const p = parsed as { prices?: Record<string, { in: number; out: number }>; chains?: unknown };
    if (p.prices) for (const [k, v] of Object.entries(p.prices)) config.prices[k] = v;
    if (p.chains && typeof p.chains === "object") {
      for (const [mode, kinds] of Object.entries(p.chains as Record<string, unknown>)) {
        if (!config.chains[mode]) config.chains[mode] = {};
        for (const [kind, chain] of Object.entries(kinds as Record<string, unknown>)) {
          if (Array.isArray(chain)) config.chains[mode][kind] = chain as string[];
        }
      }
    }
  }
  const flat = JSON.stringify(config);
  if (flat.includes("3.8")) throw new Error("router config: gemini-3.8 is block-listed in paid routes");
  // R-T19 guard: a retired model in any chain can never serve a new key —
  // refuse the config loudly instead of routing into a guaranteed 404.
  for (const mode of Object.values(config.chains)) {
    for (const chain of Object.values(mode)) {
      for (const model of chain as string[]) {
        if ((RETIRED_MODELS as readonly string[]).includes(model)) {
          throw new Error(`router config: ${model} is retired and must never appear in a chain`);
        }
      }
    }
  }
  return config;
}

export function costMicro(prices: Record<string, { in: number; out: number }>, model: string, inTok: number, outTok: number): number {
  const p = prices[model];
  if (!p) return 0;
  return Math.round(inTok * p.in + outTok * p.out);
}

export interface ChatMessage {
  role: "user" | "model";
  text: string;
}

export interface RouteRequest {
  tenant_id: string;
  device_id?: string;
  turn_id: string;
  kind: RequestKind;
  messages: ChatMessage[];
  system?: string;
  response_schema?: Record<string, unknown>;
}

export interface RouteResult {
  ok: boolean;
  model?: string;
  text?: string;
  embedding?: number[];
  input_tokens: number;
  output_tokens: number;
  cost_usd_micro: number;
  attempted_models: string[];
  truncated: boolean;
  status: string;
  error?: string;
  error_code?: string;
  ms: number;
}

export interface RouterDeps {
  db: D1Like;
  fetchFn?: typeof fetch;
  sleepFn?: (ms: number) => Promise<void>;
  nowMs?: () => number;
  masterKeyB64?: string;
  founderKey?: string;
  config?: RouterConfig;
  timeoutMs?: number;
}

const sleepDefault = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// Circuit breaker (per model, in-memory per isolate — documented limitation,
// same as the in-memory rate-limit fallback). D1 trace on every trip.
const breaker = new Map<string, { failures: number; skipUntil: number }>();
export function resetCircuitBreakers(): void {
  breaker.clear();
}

function breakerSkip(model: string, now: number): boolean {
  const b = breaker.get(model);
  return !!b && b.skipUntil > now;
}

function breakerRecord(model: string, failed: boolean, now: number): void {
  const b = breaker.get(model) ?? { failures: 0, skipUntil: 0 };
  if (failed) {
    b.failures += 1;
    if (b.failures >= CIRCUIT_BREAKER_FAILURES) b.skipUntil = now + CIRCUIT_BREAKER_MS;
  } else {
    b.failures = 0;
    b.skipUntil = 0;
  }
  breaker.set(model, b);
}

/** Token estimate for pre-call truncation: ~4 chars/token (documented estimate). */
export function estimateTokens(messages: ChatMessage[], system?: string): number {
  let chars = system ? system.length : 0;
  for (const m of messages) chars += m.text.length;
  return Math.ceil(chars / 4);
}

/** Truncate oldest-first; system + last 2 turns (4 messages) always kept.
 *  Old messages (beyond the last 4) are dropped first; after that the
 *  longest kept message's text is cut from the front until under budget.
 *  Cutting never drops a kept message unless its text is fully consumed. */
export function truncateMessages(messages: ChatMessage[], system?: string): { messages: ChatMessage[]; truncated: boolean } {
  let kept = [...messages];
  let truncated = false;
  for (let iter = 0; iter < 100 && estimateTokens(kept, system) > MAX_INPUT_TOKENS; iter++) {
    if (kept.length > 4) {
      kept = kept.slice(1);
      truncated = true;
      continue;
    }
    let longest = 0;
    for (let i = 1; i < kept.length; i++) {
      if (kept[i].text.length > kept[longest].text.length) longest = i;
    }
    const overChars = (estimateTokens(kept, system) - MAX_INPUT_TOKENS) * 4 + 100;
    const msg = kept[longest];
    if (msg.text.length <= overChars) {
      if (kept.length === 1) {
        kept[longest] = { ...msg, text: "" };
        truncated = true;
        break; // nothing left to cut (system alone may still exceed — accepted)
      }
      kept = kept.filter((_, i) => i !== longest);
    } else {
      kept[longest] = { ...msg, text: msg.text.slice(overChars) };
    }
    truncated = true;
  }
  return { messages: kept, truncated };
}

function toGeminiContents(messages: ChatMessage[]): { role: string; parts: { text: string }[] }[] {
  return messages.map((m) => ({ role: m.role, parts: [{ text: m.text }] }));
}

interface GeminiCallOutcome {
  retryable: boolean;
  status: number;
  text?: string;
  embedding?: number[];
  inputTokens: number;
  outputTokens: number;
  error?: string;
  errorCode?: string;
}

async function callGemini(
  deps: RouterDeps,
  model: string,
  apiKey: string,
  req: RouteRequest,
  messages: ChatMessage[],
): Promise<GeminiCallOutcome> {
  const timeoutMs = deps.timeoutMs ?? CALL_TIMEOUT_MS;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    if (model === MODEL_EMBED) {
      const text = messages.map((m) => m.text).join("\n");
      const res = await (deps.fetchFn ?? fetch)(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:embedContent`,
        {
          method: "POST",
          headers: { "x-goog-api-key": apiKey, "Content-Type": "application/json" },
          body: JSON.stringify({ content: { parts: [{ text }] } }),
          signal: ctrl.signal,
        },
      );
      if (!res.ok) return classifyError(res.status, await safeText(res));
      const data = (await res.json()) as {
        embedding?: { values?: number[] };
        usageMetadata?: { promptTokenCount?: number };
      };
      const values = data.embedding?.values;
      if (!values) return { retryable: true, status: res.status, inputTokens: 0, outputTokens: 0, error: "empty_embedding", errorCode: "empty_response" };
      return {
        retryable: false,
        status: res.status,
        embedding: values,
        inputTokens: data.usageMetadata?.promptTokenCount ?? 0,
        outputTokens: 0,
      };
    }
    const body: Record<string, unknown> = { contents: toGeminiContents(messages) };
    if (req.system) body.systemInstruction = { parts: [{ text: req.system }] };
    if (req.response_schema) {
      body.generationConfig = { responseMimeType: "application/json", responseSchema: req.response_schema };
    }
    const res = await (deps.fetchFn ?? fetch)(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
      {
        method: "POST",
        headers: { "x-goog-api-key": apiKey, "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      },
    );
    if (!res.ok) return classifyError(res.status, await safeText(res));
    const data = (await res.json()) as {
      candidates?: { content?: { parts?: { text?: string }[] }; finishReason?: string }[];
      promptFeedback?: { blockReason?: string };
      usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number };
    };
    if (data.promptFeedback?.blockReason || data.candidates?.[0]?.finishReason === "SAFETY") {
      return { retryable: false, status: res.status, inputTokens: 0, outputTokens: 0, error: "safety_blocked", errorCode: "safety_blocked" };
    }
    const parts = data.candidates?.[0]?.content?.parts ?? [];
    const text = parts.map((p) => p.text ?? "").join("");
    if (!text) {
      return { retryable: true, status: res.status, inputTokens: 0, outputTokens: 0, error: "empty_response", errorCode: "empty_response" };
    }
    const meta = data.usageMetadata;
    if (!meta || typeof meta.promptTokenCount !== "number" || typeof meta.candidatesTokenCount !== "number") {
      // usageMetadata is the source of truth — without it, no billing.
      return { retryable: false, status: res.status, inputTokens: 0, outputTokens: 0, error: "usage_metadata_missing", errorCode: "usage_metadata_missing" };
    }
    return {
      retryable: false,
      status: res.status,
      text,
      inputTokens: meta.promptTokenCount,
      outputTokens: meta.candidatesTokenCount,
    };
  } catch (e) {
    if ((e as Error)?.name === "AbortError") {
      return { retryable: true, status: 0, inputTokens: 0, outputTokens: 0, error: "timeout", errorCode: "timeout" };
    }
    return { retryable: true, status: 0, inputTokens: 0, outputTokens: 0, error: String((e as Error)?.message ?? e).slice(0, 200), errorCode: "network_error" };
  } finally {
    clearTimeout(timer);
  }
}

async function safeText(res: { text(): Promise<string> }): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}

function classifyError(status: number, bodyText: string): GeminiCallOutcome {
  const lower = bodyText.toLowerCase();
  if (status === 429) return { retryable: true, status, inputTokens: 0, outputTokens: 0, error: "rate_limited", errorCode: "rate_limited" };
  if (status >= 500) return { retryable: true, status, inputTokens: 0, outputTokens: 0, error: `upstream_${status}`, errorCode: "upstream_error" };
  if (status === 404 && (lower.includes("not found") || lower.includes("not_found"))) {
    return { retryable: true, status, inputTokens: 0, outputTokens: 0, error: "model_not_found", errorCode: "model_not_found" };
  }
  if (status === 400 && (lower.includes("api_key_invalid") || lower.includes("api key not valid"))) {
    return { retryable: false, status, inputTokens: 0, outputTokens: 0, error: "invalid_key", errorCode: "invalid_key" };
  }
  return { retryable: false, status, inputTokens: 0, outputTokens: 0, error: `upstream_${status}`, errorCode: "upstream_error" };
}

function failResult(
  attempted: string[],
  errorCode: string,
  error: string,
  ms: number,
): RouteResult {
  return {
    ok: false,
    input_tokens: 0,
    output_tokens: 0,
    cost_usd_micro: 0,
    attempted_models: attempted,
    truncated: false,
    status: "failed",
    error,
    error_code: errorCode,
    ms,
  };
}

export async function routeLlm(deps: RouterDeps, req: RouteRequest): Promise<RouteResult> {
  const now = deps.nowMs ? deps.nowMs() : Date.now();
  const started = now;
  const ms = () => (deps.nowMs ? deps.nowMs() : Date.now()) - started;
  const config = deps.config ?? loadRouterConfig({});
  const tenantId = req.tenant_id;
  const deviceId = req.device_id ?? "";

  // Live is not routable via generateContent (native-audio needs the Live API).
  if (req.kind === "live") {
    return failResult([], "live_not_routed", "Live mode server router se nahi chalta — phone ka Live path use karo", ms());
  }
  if (!tenantId || !req.turn_id || !req.messages || req.messages.length === 0) {
    return failResult([], "bad_request", "tenant_id, turn_id aur messages chahiye", ms());
  }

  const tenant = await getTenant(deps.db, tenantId);
  if (!tenant) return failResult([], "tenant_not_found", "tenant nahi mila", ms());
  const plan = PLAN_LIMITS[tenant.plan_tier] ?? PLAN_LIMITS.free;
  const billingMode = tenant.billing_mode === "founder_pays" ? "founder_pays" : "byok";
  if (req.kind === "doc_extraction" && !plan.docs) {
    await recordUsage(deps.db, {
      tenant_id: tenantId,
      turn_id: req.turn_id,
      model: "",
      attempted_models: [],
      input_tokens: 0,
      output_tokens: 0,
      cost_usd_micro: 0,
      billing_mode: billingMode,
      status: "refused_cap",
    }, now, false);
    return { ...failResult([], "plan_docs_not_allowed", "Doc extraction Pro plan me hai", ms()), status: "refused_cap" };
  }

  // BYOK key (or founder key in founder-pays mode). Never a silent fallback.
  let apiKey: string | null = null;
  if (billingMode === "byok") {
    if (!tenant.gemini_key_enc) {
      await recordUsage(deps.db, {
        tenant_id: tenantId, turn_id: req.turn_id, model: "", attempted_models: [],
        input_tokens: 0, output_tokens: 0, cost_usd_micro: 0,
        billing_mode: billingMode, status: "refused_cap",
      }, now, false);
      return { ...failResult([], "byok_required", "Server AI ke liye apni Gemini key jodo — AI Brain → Keys", ms()), status: "refused_cap" };
    }
    if (!deps.masterKeyB64) {
      return failResult([], "key_vault_not_configured", "Server key vault setup nahi hai", ms());
    }
    try {
      const master = await importMasterKey(deps.masterKeyB64);
      apiKey = await decryptTenantKey(master, tenant.gemini_key_enc);
    } catch {
      return failResult([], "key_decrypt_failed", "Saved key khul nahi rahi — key dobara dalo", ms());
    }
  } else {
    if (!deps.founderKey) {
      return failResult([], "founder_key_missing", "Founder-pays mode abhi band hai — card approval ke baad khulega", ms());
    }
    apiKey = deps.founderKey;
  }

  // Caps: replies/mo, then calls/turn.
  const usage = await getMonthUsage(deps.db, tenantId, currentPeriod(now));
  if (usage.replies >= plan.replies) {
    await recordUsage(deps.db, {
      tenant_id: tenantId, turn_id: req.turn_id, model: "", attempted_models: [],
      input_tokens: 0, output_tokens: 0, cost_usd_micro: 0,
      billing_mode: billingMode, status: "refused_cap",
    }, now, false);
    return { ...failResult([], "replies_cap", "Is mahine ke replies khatam — upgrade karo ya agle mahine ka intezaar karo", ms()), status: "refused_cap" };
  }
  const turnCalls = await countTurnCalls(deps.db, req.turn_id);
  if (turnCalls >= MAX_CALLS_PER_TURN) {
    return { ...failResult([], "turn_calls_cap", "Is turn me 5 calls ho chuke — aage badhaun ya rukun?", ms()), status: "refused_cap" };
  }

  const chain = (config.chains[billingMode]?.[req.kind] ?? config.chains.byok[req.kind] ?? []) as string[];
  if (chain.length === 0) return failResult([], "no_route", "Is request kind ke liye koi route nahi", ms());
  const { messages, truncated } = truncateMessages(req.messages, req.system);
  const attempted: string[] = [];
  const sleep = deps.sleepFn ?? sleepDefault;
  let lastError: GeminiCallOutcome | null = null;

  for (let i = 0; i < chain.length; i++) {
    const model = chain[i];
    if (breakerSkip(model, now)) {
      await insertTrace(deps.db, tenantId, deviceId, "router_circuit_break", {
        turn_id: req.turn_id,
        model,
        skipped: true,
      });
      continue;
    }
    attempted.push(model);
    const outcome = await callGemini(deps, model, apiKey as string, req, messages);
    if (outcome.retryable) {
      breakerRecord(model, true, now);
      lastError = outcome;
      // Backoff between attempts (1s -> 2s -> 4s); 429 Retry-After wins.
      if (i < chain.length - 1) await sleep(1000 * 2 ** i);
      continue;
    }
    if (outcome.error) {
      // Non-retryable (invalid key / safety / metadata missing): no fallback.
      breakerRecord(model, true, now);
      await recordUsage(deps.db, {
        tenant_id: tenantId, turn_id: req.turn_id, model, attempted_models: attempted,
        input_tokens: 0, output_tokens: 0, cost_usd_micro: 0,
        billing_mode: billingMode, status: "failed",
      });
      await insertTrace(deps.db, tenantId, deviceId, "router_call", {
        turn_id: req.turn_id, kind: req.kind, model, attempted_models: attempted,
        status: "failed", error: outcome.errorCode, ms: ms(), truncated,
      });
      return { ...failResult(attempted, outcome.errorCode ?? "upstream_error", outcome.error, ms()), status: "failed" };
    }
    // Success.
    breakerRecord(model, false, now);
    const cost = costMicro(config.prices, model, outcome.inputTokens, outcome.outputTokens);
    const status = i === 0 ? "ok" : "fallback_used";
    await recordUsage(deps.db, {
      tenant_id: tenantId, turn_id: req.turn_id, model, attempted_models: attempted,
      input_tokens: outcome.inputTokens, output_tokens: outcome.outputTokens,
      cost_usd_micro: cost, billing_mode: billingMode, status,
    });
    await insertTrace(deps.db, tenantId, deviceId, "router_call", {
      turn_id: req.turn_id, kind: req.kind, model, attempted_models: attempted,
      input_tokens: outcome.inputTokens, output_tokens: outcome.outputTokens,
      cost_usd_micro: cost, status, ms: ms(), truncated,
    });
    return {
      ok: true,
      model,
      text: outcome.text,
      embedding: outcome.embedding,
      input_tokens: outcome.inputTokens,
      output_tokens: outcome.outputTokens,
      cost_usd_micro: cost,
      attempted_models: attempted,
      truncated,
      status,
      ms: ms(),
    };
  }

  // Chain exhausted (all retryable failures, or all breaker-skipped).
  const errCode = lastError?.errorCode ?? "all_models_skipped";
  const errText = lastError?.error ?? "AI abhi jawab nahi de pa raha, thodi der me try karo";
  await recordUsage(deps.db, {
    tenant_id: tenantId, turn_id: req.turn_id, model: attempted[attempted.length - 1] ?? "",
    attempted_models: attempted, input_tokens: 0, output_tokens: 0, cost_usd_micro: 0,
    billing_mode: billingMode, status: "failed",
  });
  await insertTrace(deps.db, tenantId, deviceId, "router_call", {
    turn_id: req.turn_id, kind: req.kind, attempted_models: attempted,
    status: "failed", error: errCode, ms: ms(), truncated,
  });
  return { ...failResult(attempted, errCode, errText, ms()), status: "failed" };
}

/** Turn end: success => 1 reply counted; failure => 0. Caller is server-side (trusted). */
export async function completeTurn(
  db: D1Like,
  tenantId: string,
  turnId: string,
  success: boolean,
  nowMs = Date.now(),
): Promise<void> {
  if (success) await recordReply(db, tenantId, nowMs);
  await insertTrace(db, tenantId, "", "turn_complete", { turn_id: turnId, success });
}

/**
 * Validate a tenant-supplied Gemini key with a tiny generateContent call
 * (1-word prompt, ~2 tokens). Tries the live text models in BYOK-primary
 * order (3.5 FL, then 3.1 FL) — a single retired model must never again
 * decide validity (P0, 2026-11-21: 2.5 FL 404 broke ALL key-setting).
 * 404 / model-not-found => try the next live model. 401/403 (invalid key)
 * => false at once (an invalid key is invalid on every model). 429/5xx
 * => false (unvalidated keys are never stored). Any model ok => true.
 * Timeout 15s per attempt, max 3 attempts (only 2 live text models exist).
 * The key travels only in the x-goog-api-key header to Google — never in
 * a URL, log, or response.
 */
export async function validateGeminiKey(apiKey: string, fetchFn: typeof fetch = fetch): Promise<boolean> {
  for (const model of LIVE_TEXT_MODELS) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 15_000);
      try {
        const res = await fetchFn(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
          {
            method: "POST",
            headers: { "x-goog-api-key": apiKey, "Content-Type": "application/json" },
            body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hi" }] }] }),
            signal: ctrl.signal,
          },
        );
        if (res.ok) return true;
        if (res.status === 404) continue; // retired / not found on this model — try next
        return false; // 401/403 invalid key, 429/5xx, 400 — no point trying another model
      } finally {
        clearTimeout(timer);
      }
    } catch {
      return false;
    }
  }
  return false;
}
