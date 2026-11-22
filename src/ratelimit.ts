/**
 * ratelimit.ts — Upstash Redis rate limits (distributed quota).
 *
 * Key scheme: rl:<route>:<identifier> (identifier = IP for licence
 * routes, tenant_id for authed routes, device_id for sync).
 * Budgets = Worker v1 wale hi (verify 30/min, generate 20/min,
 * release 30/min, status 60/min, patterns 60/120/20 per min).
 * Naye routes: pairing init 10/min/IP, sync 120/min/device.
 *
 * Upstash: REST API (POST <url>/pipeline with INCR + EXPIRE). Env:
 * UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN (Worker secrets).
 * Fallback: env unset/down ho to in-memory per-isolate sliding window
 * (v1 jaisa) + caller `x-ratelimit-fallback: 1` header lagata hai
 * (visible, chhupa nahi). Fallback permanent nahi hai.
 */
import type { Env } from "./hub";

export const RATE_LIMITS: Record<string, { limit: number; windowMs: number }> = {
  licenceVerify: { limit: 30, windowMs: 60_000 },
  licenceGenerate: { limit: 20, windowMs: 60_000 },
  licenceRelease: { limit: 30, windowMs: 60_000 },
  licenceStatus: { limit: 60, windowMs: 60_000 },
  patternsPost: { limit: 60, windowMs: 60_000 },
  patternsGet: { limit: 120, windowMs: 60_000 },
  patternsDelete: { limit: 20, windowMs: 60_000 },
  pairingInit: { limit: 10, windowMs: 60_000 },
  pairingRegister: { limit: 10, windowMs: 60_000 },
  sync: { limit: 120, windowMs: 60_000 },
  llmRoute: { limit: 60, windowMs: 60_000 },
  docs: { limit: 30, windowMs: 60_000 },
  browser: { limit: 30, windowMs: 60_000 },
  skills: { limit: 30, windowMs: 60_000 },
  memory: { limit: 60, windowMs: 60_000 },
  billing: { limit: 30, windowMs: 60_000 },
  billingAdmin: { limit: 30, windowMs: 60_000 },
  e2b: { limit: 30, windowMs: 60_000 },
  // D3 locked (captcha-solver DESIGN §2.2): 10/min/tenant — far above
  // the 10/day solve cap, so it only bites on a runaway loop.
  captcha_solve: { limit: 10, windowMs: 60_000 },
  googleOauthStart: { limit: 10, windowMs: 60_000 },
  googleApi: { limit: 30, windowMs: 60_000 },
};

export interface RateLimitResult {
  allowed: boolean;
  fallback: boolean;
}

export interface UpstashOpts {
  fetchFn?: typeof fetch;
}

/** Configured ONLY when BOTH UPSTASH_REDIS_REST_URL and TOKEN are set. */
export function upstashStatus(env: Env): { configured: boolean } {
  const rec = env as unknown as Record<string, string | undefined>;
  return { configured: Boolean(rec.UPSTASH_REDIS_REST_URL && rec.UPSTASH_REDIS_REST_TOKEN) };
}

function upstashCreds(env: Env): { url: string; token: string } | null {
  const rec = env as unknown as Record<string, string | undefined>;
  const url = (rec.UPSTASH_REDIS_REST_URL ?? "").replace(/\/+$/, "");
  const token = rec.UPSTASH_REDIS_REST_TOKEN ?? "";
  return url && token ? { url, token } : null;
}

/**
 * Live check (completeness #45): GET {url}/ping -> {"result":"PONG"}.
 * The real Upstash REST API answers a JSON OBJECT, not a bare string —
 * the first version compared res.text() to "PONG" and could never be
 * live (caught by the live probe 2026-11-22: configured:true,
 * live:false while curl showed {"result":"PONG"} HTTP 200). Accept
 * both the object shape and a bare "PONG" string.
 * `live: false` with `configured: true` means the Worker cannot reach
 * Upstash (or the token is wrong) — checkRateLimit then falls back
 * visibly (x-ratelimit-fallback: 1), never silently.
 */
export async function checkUpstashLive(
  env: Env,
  opts: UpstashOpts = {},
): Promise<{ configured: boolean; live: boolean }> {
  const creds = upstashCreds(env);
  if (!creds) return { configured: false, live: false };
  try {
    const res = await (opts.fetchFn ?? fetch)(`${creds.url}/ping`, {
      headers: { Authorization: `Bearer ${creds.token}` },
    });
    if (!res.ok) return { configured: true, live: false };
    const raw = (await res.text()).trim();
    let live = false;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed === "string") live = parsed === "PONG";
      else if (parsed && typeof parsed === "object")
        live = (parsed as { result?: unknown }).result === "PONG";
    } catch {
      live = raw.replace(/^"|"$/g, "") === "PONG";
    }
    return { configured: true, live };
  } catch {
    return { configured: true, live: false };
  }
}

/**
 * Distributed-counter proof (completeness #45, admin diagnostic only):
 * INCR the same probe key twice through the Upstash pipeline, then DEL
 * it. Two sequential counts (n, n+1) prove the counter lives in
 * Upstash, not in the isolate — a per-isolate fallback could never
 * return a persisted second increment from a fresh pipeline call.
 * The probe key is random per call and deleted afterwards, so it leaks
 * no real quota state. Never throws.
 */
export async function probeUpstashCounter(
  env: Env,
  opts: UpstashOpts = {},
): Promise<{ ok: boolean; key?: string; counts?: number[]; error?: string }> {
  const creds = upstashCreds(env);
  if (!creds) return { ok: false, error: "upstash_not_configured" };
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  const key = `rl:probe:${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
  try {
    const res = await (opts.fetchFn ?? fetch)(`${creds.url}/pipeline`, {
      method: "POST",
      headers: { Authorization: `Bearer ${creds.token}`, "Content-Type": "application/json" },
      body: JSON.stringify([["INCR", key], ["INCR", key], ["DEL", key]]),
    });
    if (!res.ok) return { ok: false, error: "upstash_error" };
    const data = (await res.json()) as { result?: unknown }[];
    const counts = [Number(data?.[0]?.result ?? NaN), Number(data?.[1]?.result ?? NaN)];
    if (!counts.every((c) => Number.isFinite(c))) return { ok: false, error: "upstash_error" };
    if (counts[1] !== counts[0] + 1) return { ok: false, key, counts, error: "counter_not_sequential" };
    return { ok: true, key, counts };
  } catch {
    return { ok: false, error: "upstash_error" };
  }
}

// In-memory fallback store (per-isolate; v1 documented limitation).
const fallbackStore = new Map<string, number[]>();

/** Test-only reset (mirrors resetCircuitBreakers in router.ts): the
 * fallback store is module-level, so a test file that makes many
 * calls for one tenant/route would otherwise trip its own 30/min
 * budget across tests. Production behaviour is unchanged. */
export function resetRateLimitFallback(): void {
  fallbackStore.clear();
}

function fallbackCheck(key: string, limit: number, windowMs: number, nowMs: number): boolean {
  const hits = (fallbackStore.get(key) ?? []).filter((t) => nowMs - t < windowMs);
  if (hits.length >= limit) {
    fallbackStore.set(key, hits);
    return false;
  }
  hits.push(nowMs);
  fallbackStore.set(key, hits);
  return true;
}

export async function checkRateLimit(
  env: Env,
  route: keyof typeof RATE_LIMITS,
  identifier: string,
): Promise<RateLimitResult> {
  const budget = RATE_LIMITS[route];
  const key = `rl:${route}:${identifier}`;
  const url = (env as unknown as Record<string, string | undefined>).UPSTASH_REDIS_REST_URL;
  const token = (env as unknown as Record<string, string | undefined>).UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) {
    return { allowed: fallbackCheck(key, budget.limit, budget.windowMs, Date.now()), fallback: true };
  }
  try {
    const res = await fetch(`${url}/pipeline`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify([
        ["INCR", key],
        ["PEXPIRE", key, String(budget.windowMs), "NX"],
      ]),
    });
    if (!res.ok) throw new Error(`upstash:${res.status}`);
    const data = (await res.json()) as { result?: unknown[] }[];
    const count = Number(data?.[0]?.result ?? 0);
    return { allowed: count <= budget.limit, fallback: false };
  } catch {
    return { allowed: fallbackCheck(key, budget.limit, budget.windowMs, Date.now()), fallback: true };
  }
}
