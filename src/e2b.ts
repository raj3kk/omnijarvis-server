/**
 * e2b.ts — E2B sandbox runs + Pro-floor threshold gating (Phase 4).
 *
 * Frozen (UPI spec §6–§8, D4):
 * - No E2B account exists yet (U-4, parent-side). There is NO E2B API
 *   call, key, URL, or SDK in this module — only an env presence check
 *   (E2B_API_KEY), exactly like the Render RENDER_WORKER_URL pattern.
 *   Until the account exists every run request honestly refuses with
 *   `e2b_not_configured` (503) + a device-as-sandbox fallback hint.
 *   Never a fake run, never a silent fallback.
 * - C4: run max 15 min, auto-kill (the sweep in billing.ts kills held
 *   runs older than E2B_MAX_RUN_MS; kill here marks a run killed).
 * - Hold/settle/release (§8): run start reserves 1 from the monthly
 *   quota (counter +1, one D1 batch with the run row); success settles
 *   (count stays); failure releases (counter −1, one batch — the
 *   customer is never charged for a failed run); auto-kill settles
 *   (the run did run — count stays).
 * - Pro floor $150/mo = ₹13,950/mo opens ONLY when aggregate paid
 *   customer margin >= threshold AND a card is on file (user decision
 *   — without the card the floor stays closed even past threshold).
 * - Hobby runway: $100 one-time ≈ 3,600 ten-minute runs (2vCPU/4GiB,
 *   $0.0276/10-min run) ≈ 120 Pro-customer-months / 36 Business.
 */
import { d1Batch, getTenant, type D1Like } from "./db";
import { getMonthUsage, currentPeriod } from "./metering";
import { planLimits } from "./router";
import { randomNonceHex } from "./crypto";

/** C4: max E2B run duration — 15 min, auto-kill. Hard, never configurable. */
export const E2B_MAX_RUN_MS = 15 * 60 * 1000;
/** $/10-min run (2vCPU/4GiB) — audit §7.2 source of truth. */
export const E2B_RUN_COST_USD_PER_10MIN = 0.0276;
/** $100 Hobby credit / $0.0276 ≈ 3,600 ten-minute runs. */
export const E2B_HOBBY_RUNWAY_RUNS = 3600;
/** Pro floor $150/mo at ₹93/$ = ₹13,950/mo. */
export const E2B_THRESHOLD_PAISE = 1_395_000;
/** USD→paise at ₹93/$: paise = microUSD × 93 / 10000. */
export const USD_INR = 93;

export function microUsdToPaise(costUsdMicro: number): number {
  return Math.round((costUsdMicro * USD_INR) / 10000);
}

export type E2BRunStatus = "held" | "settled" | "released" | "killed";

export interface E2BRunRow {
  id: string;
  tenant_id: string;
  status: E2BRunStatus;
  started_at: string;
  ended_at: string | null;
  detail: string | null;
}

export function newE2BRunId(): string {
  return `e2b-${randomNonceHex(8)}`;
}

/**
 * Aggregate paid-customer monthly margin (paise) for the threshold:
 * active-subscription revenue MINUS founder-pays LLM cost (same period
 * proxy — llm_usage has no period column, so cost is lifetime-to-date;
 * the threshold is a runway signal, not a billing invoice — the
 * sandbox-monitor labels it as such). BYOK rows are EXCLUDED: their
 * cost_usd_micro is recorded but the founder pays ₹0 for them — counting
 * them would fake a founder loss.
 */
export async function aggregateMarginPaise(db: D1Like): Promise<number> {
  const rev = await db
    .prepare("SELECT SUM(amount_paise) AS total FROM subscriptions WHERE status = ?")
    .bind("active")
    .first<{ total: number }>();
  const revenue = rev?.total ?? 0;
  const costRows = await db
    .prepare("SELECT cost_usd_micro FROM llm_usage WHERE billing_mode = ?")
    .bind("founder_pays")
    .all<{ cost_usd_micro: number }>();
  let founderCostPaise = 0;
  for (const r of costRows.results ?? []) founderCostPaise += microUsdToPaise(r.cost_usd_micro ?? 0);
  return revenue - founderCostPaise;
}

/** Total E2B runs used across all tenants (all periods — Hobby runway is lifetime). */
export async function totalE2BRunsUsed(db: D1Like): Promise<number> {
  const row = await db
    .prepare("SELECT SUM(e2b_runs) AS total FROM usage_counters")
    .bind()
    .first<{ total: number }>();
  return row?.total ?? 0;
}

export interface ThresholdInput {
  aggregateMarginPaise: number;
  hobbyRunsUsed: number;
  cardOnFile: boolean;
  hobbyExhausted: boolean;
}

export interface ThresholdStatus {
  proFloorOpen: boolean;
  reason: "pro_floor_open" | "threshold_not_met" | "card_required" | "hobby_exhausted";
  thresholdPaise: number;
  hobbyRunsRemaining: number;
}

/** Pure threshold decision — no DB, no env. Testable in isolation. */
export function e2bThresholdStatus(input: ThresholdInput): ThresholdStatus {
  const hobbyRunsRemaining = Math.max(0, E2B_HOBBY_RUNWAY_RUNS - input.hobbyRunsUsed);
  if (input.hobbyExhausted || hobbyRunsRemaining <= 0) {
    return { proFloorOpen: false, reason: "hobby_exhausted", thresholdPaise: E2B_THRESHOLD_PAISE, hobbyRunsRemaining };
  }
  if (input.aggregateMarginPaise < E2B_THRESHOLD_PAISE) {
    return { proFloorOpen: false, reason: "threshold_not_met", thresholdPaise: E2B_THRESHOLD_PAISE, hobbyRunsRemaining };
  }
  if (!input.cardOnFile) {
    return { proFloorOpen: false, reason: "card_required", thresholdPaise: E2B_THRESHOLD_PAISE, hobbyRunsRemaining };
  }
  return { proFloorOpen: true, reason: "pro_floor_open", thresholdPaise: E2B_THRESHOLD_PAISE, hobbyRunsRemaining };
}

export type E2BRunRequestResult =
  | { ok: true; run_id: string; status: "held"; max_run_ms: number }
  | { ok: false; error: "tenant_not_found" | "e2b_runs_cap" | "e2b_not_configured" | "e2b_paused" | "threshold_not_met"; detail?: string; device_fallback: boolean };

/**
 * Request an E2B run. Frozen check order: tenant → monthly runs cap →
 * Hobby exhausted (pause) → E2B account configured? → hold (1 batch).
 * The cap check comes BEFORE the not-configured check: a capped tenant
 * gets `e2b_runs_cap` (429 semantics at the route), not a 503.
 * The threshold gate does NOT block Hobby runs — Hobby credit + device
 * fallback run below the threshold by design; the threshold only gates
 * the $150/mo Pro floor (which needs a card + an account anyway).
 */
export async function requestE2BRun(
  db: D1Like,
  opts: {
    tenant_id: string;
    plan_tier: string;
    e2bConfigured: boolean;
    hobbyExhausted: boolean;
    task?: string;
    nowMs?: number;
  },
): Promise<E2BRunRequestResult> {
  const nowMs = opts.nowMs ?? Date.now();
  const period = currentPeriod(nowMs);
  const tenant = await getTenant(db, opts.tenant_id);
  if (!tenant) {
    return { ok: false, error: "tenant_not_found", device_fallback: false };
  }
  const usage = await getMonthUsage(db, opts.tenant_id, period);
  const limits = planLimits(opts.plan_tier);
  if (usage.e2b_runs >= limits.e2b_runs) {
    return {
      ok: false,
      error: "e2b_runs_cap",
      detail: "E2B runs khatam — device-as-sandbox par chalao ya upgrade karo",
      device_fallback: true,
    };
  }
  if (opts.hobbyExhausted) {
    return {
      ok: false,
      error: "e2b_paused",
      detail: "E2B Hobby credit khatam — device fallback chala raha hai; customers ko bataya gaya",
      device_fallback: true,
    };
  }
  if (!opts.e2bConfigured) {
    // U-4: no E2B account yet. Honest refuse — no hold is recorded,
    // no quota is consumed, no run is faked.
    return {
      ok: false,
      error: "e2b_not_configured",
      detail: "e2b_not_configured: no E2B account yet (U-4) — server sandbox execution is gated",
      device_fallback: true,
    };
  }
  // Hold: run row + counter +1 in ONE batch (GAP-10 — never sequential).
  const runId = newE2BRunId();
  const startedAt = new Date(nowMs).toISOString();
  await d1Batch(db, [
    db
      .prepare("INSERT INTO e2b_runs (id, tenant_id, status, started_at, ended_at, detail) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(runId, opts.tenant_id, "held", startedAt, null, opts.task ? JSON.stringify({ task: opts.task }) : null),
    db
      .prepare(
        "INSERT INTO usage_counters (tenant_id, period, replies, e2b_runs, llm_calls, input_tokens, output_tokens, cost_usd_micro) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT(tenant_id, period) DO UPDATE SET " +
          "e2b_runs = usage_counters.e2b_runs + excluded.e2b_runs",
      )
      .bind(opts.tenant_id, period, 0, 1, 0, 0, 0, 0),
  ]);
  return { ok: true, run_id: runId, status: "held", max_run_ms: E2B_MAX_RUN_MS };
}

export async function getE2BRun(db: D1Like, runId: string): Promise<E2BRunRow | null> {
  const row = await db
    .prepare("SELECT id, tenant_id, status, started_at, ended_at, detail FROM e2b_runs WHERE id = ?")
    .bind(runId)
    .first<E2BRunRow>();
  return row;
}

/**
 * Complete a held run. success → settle (count stays). failure →
 * release (counter −1, one batch — the customer is never charged for a
 * failed run). Only a `held` run can complete; anything else is a 409
 * at the route (checked by the caller via the returned row state).
 */
export async function completeE2BRun(
  db: D1Like,
  run: E2BRunRow,
  success: boolean,
  nowMs = Date.now(),
): Promise<{ status: E2BRunStatus }> {
  const endedAt = new Date(nowMs).toISOString();
  if (success) {
    await db
      .prepare("UPDATE e2b_runs SET status = ?, ended_at = ? WHERE id = ?")
      .bind("settled", endedAt, run.id)
      .run();
    return { status: "settled" };
  }
  // Release: the counter decrement MUST hit the hold's own period
  // (from run.started_at), not the current month — a run held late in
  // one month and released in the next must not corrupt either counter.
  const holdPeriod = currentPeriod(Date.parse(run.started_at));
  await d1Batch(db, [
    db.prepare("UPDATE e2b_runs SET status = ?, ended_at = ? WHERE id = ?").bind("released", endedAt, run.id),
    db
      .prepare(
        "INSERT INTO usage_counters (tenant_id, period, replies, e2b_runs, llm_calls, input_tokens, output_tokens, cost_usd_micro) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT(tenant_id, period) DO UPDATE SET " +
          "e2b_runs = usage_counters.e2b_runs + excluded.e2b_runs",
      )
      .bind(run.tenant_id, holdPeriod, 0, -1, 0, 0, 0, 0),
  ]);
  return { status: "released" };
}

/**
 * Kill a held run (15-min auto-kill or manual kill). The run DID run,
 * so the count stays (settle semantics — spec §8). Returns the kill
 * message the user must see.
 */
export async function killE2BRun(
  db: D1Like,
  run: E2BRunRow,
  nowMs = Date.now(),
): Promise<{ status: "killed"; message: string }> {
  await db
    .prepare("UPDATE e2b_runs SET status = ?, ended_at = ? WHERE id = ?")
    .bind("killed", new Date(nowMs).toISOString(), run.id)
    .run();
  return {
    status: "killed",
    message: "15-min cap par ruka — task chhota karke dobara try karo",
  };
}

/** Held runs older than the 15-min cap (for the billing sweep). */
export async function listStaleHeldRuns(db: D1Like, nowMs: number): Promise<E2BRunRow[]> {
  const rows = await db
    .prepare("SELECT id, tenant_id, status, started_at, ended_at, detail FROM e2b_runs WHERE status = ?")
    .bind("held")
    .all<E2BRunRow>();
  const cutoff = nowMs - E2B_MAX_RUN_MS;
  return (rows.results ?? []).filter((r) => Date.parse(r.started_at) < cutoff);
}
