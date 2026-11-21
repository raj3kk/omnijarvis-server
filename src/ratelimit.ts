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
};

export interface RateLimitResult {
  allowed: boolean;
  fallback: boolean;
}

// In-memory fallback store (per-isolate; v1 documented limitation).
const fallbackStore = new Map<string, number[]>();

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
