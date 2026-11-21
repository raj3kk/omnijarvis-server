/**
 * metering.ts — D1 metering ledger for the LLM router (D11 brief §6).
 *
 * Rules (frozen):
 * - usageMetadata is the source of truth — never an estimate. A call
 *   without usageMetadata is recorded status=failed, cost 0 + diagnostic.
 * - llm_usage holds counts + model + status ONLY — never prompt/response
 *   text (PII). Traces hold no PII either.
 * - Rollup (usage_counters) is updated incrementally per call. The
 *   insert + upsert are sequential prepares (D1Like has no batch) — NOT
 *   atomic; the monthly reconciliation (R-T7: rows sum == rollup) is the
 *   safety net. A failed upsert after a successful insert is logged as
 *   a trace (kind=metering_rollup_failed) — never swallowed silently.
 * - "AI reply" = 1 successful user-facing turn. recordReply() is called
 *   by completeTurn() only — failed turns count 0 replies; calls are
 *   metered separately so abuse stays visible.
 */
import type { D1Like } from "./db";
import { insertTrace } from "./db";

export interface UsageRecord {
  tenant_id: string;
  turn_id: string;
  model: string;
  attempted_models: string[];
  input_tokens: number;
  output_tokens: number;
  cost_usd_micro: number;
  billing_mode: string;
  status: string; // ok | fallback_used | failed | refused_cap
}

export function currentPeriod(nowMs: number): string {
  const d = new Date(nowMs);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

export interface MonthUsage {
  replies: number;
  e2b_runs: number;
  llm_calls: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd_micro: number;
}

const EMPTY_USAGE: MonthUsage = {
  replies: 0,
  e2b_runs: 0,
  llm_calls: 0,
  input_tokens: 0,
  output_tokens: 0,
  cost_usd_micro: 0,
};

export async function getMonthUsage(db: D1Like, tenantId: string, period: string): Promise<MonthUsage> {
  const row = await db
    .prepare(
      "SELECT replies, e2b_runs, llm_calls, input_tokens, output_tokens, cost_usd_micro " +
        "FROM usage_counters WHERE tenant_id = ? AND period = ?",
    )
    .bind(tenantId, period)
    .first<MonthUsage>();
  return row ?? { ...EMPTY_USAGE };
}

export async function countTurnCalls(db: D1Like, turnId: string): Promise<number> {
  // Only real attempts count (ok / fallback_used / failed) — refused_cap
  // rows are an audit trail, not calls. Filtered in JS: FakeD1 has no IN.
  const res = await db
    .prepare("SELECT status FROM llm_usage WHERE turn_id = ?")
    .bind(turnId)
    .all<{ status: string }>();
  return (res.results ?? []).filter((r) => r.status === "ok" || r.status === "fallback_used" || r.status === "failed").length;
}

async function upsertCounters(
  db: D1Like,
  tenantId: string,
  period: string,
  delta: MonthUsage,
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO usage_counters (tenant_id, period, replies, e2b_runs, llm_calls, input_tokens, output_tokens, cost_usd_micro) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(tenant_id, period) DO UPDATE SET " +
        "replies = usage_counters.replies + excluded.replies, " +
        "e2b_runs = usage_counters.e2b_runs + excluded.e2b_runs, " +
        "llm_calls = usage_counters.llm_calls + excluded.llm_calls, " +
        "input_tokens = usage_counters.input_tokens + excluded.input_tokens, " +
        "output_tokens = usage_counters.output_tokens + excluded.output_tokens, " +
        "cost_usd_micro = usage_counters.cost_usd_micro + excluded.cost_usd_micro",
    )
    .bind(
      tenantId,
      period,
      delta.replies,
      delta.e2b_runs,
      delta.llm_calls,
      delta.input_tokens,
      delta.output_tokens,
      delta.cost_usd_micro,
    )
    .run();
}

export async function recordUsage(
  db: D1Like,
  rec: UsageRecord,
  nowMs = Date.now(),
  countCall = true,
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO llm_usage (tenant_id, turn_id, model, attempted_models, input_tokens, output_tokens, cost_usd_micro, billing_mode, status, created_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(
      rec.tenant_id,
      rec.turn_id,
      rec.model,
      JSON.stringify(rec.attempted_models),
      rec.input_tokens,
      rec.output_tokens,
      rec.cost_usd_micro,
      rec.billing_mode,
      rec.status,
      nowMs,
    )
    .run();
  try {
    await upsertCounters(db, rec.tenant_id, currentPeriod(nowMs), {
      replies: 0,
      e2b_runs: 0,
      llm_calls: countCall ? 1 : 0,
      input_tokens: countCall ? rec.input_tokens : 0,
      output_tokens: countCall ? rec.output_tokens : 0,
      cost_usd_micro: countCall ? rec.cost_usd_micro : 0,
    });
  } catch (e) {
    // Rollup failed but the row is recorded — reconciliation will flag
    // the drift; never swallow silently.
    await insertTrace(db, rec.tenant_id, "", "metering_rollup_failed", {
      turn_id: rec.turn_id,
      error: String((e as Error)?.message ?? e).slice(0, 200),
    });
    throw e;
  }
}

/** One successful user-facing turn = 1 reply. Failed turn = 0 (do not call). */
export async function recordReply(db: D1Like, tenantId: string, nowMs = Date.now()): Promise<void> {
  await upsertCounters(db, tenantId, currentPeriod(nowMs), {
    replies: 1,
    e2b_runs: 0,
    llm_calls: 0,
    input_tokens: 0,
    output_tokens: 0,
    cost_usd_micro: 0,
  });
}
