/**
 * cron.ts — tick handler (GitHub Actions 5-min dispatcher calls this).
 *
 * Auth: header x-cron-secret == CRON_SECRET (Worker secret). Constant-time
 * compare (timing leak se bachne ke liye).
 * Due jobs: Supabase scheduled_jobs (enabled=true AND next_run_at <= now).
 * Table na ho -> 503 schema_pending (2a-3 me schema aayega; tick tab tak
 * fail-closed rehta hai, silently PASS nahi karta).
 * Idempotency: har fire ke liye D1 traces me kind=cron_fire,
 * detail={job_id, minute} check — pehle se fired ho to skip (dispatcher
 * retry / double-tick se ek job do baar fire nahi hoti).
 * Dispatch: DO ko EXECUTE_STEP bhejta hai (device connected ho to turant,
 * nahi to pending_steps) — dispatch function caller inject karta hai
 * (Worker env se DO stub) taaki vitest me fake kar sakein.
 * Jitter documented: tick 5-min par hai, par GitHub best-effort delays
 * (5–30 min load par) — "exact time" ka vaada kabhi nahi.
 */
import { supabaseSelect, supabaseUpdate, SupabaseMissing, SupabaseSchemaPending } from "./supabase";
import type { D1Like } from "./db";
import { insertTrace } from "./db";

export interface CronEnv {
  CRON_SECRET?: string;
  SUPABASE_URL?: string;
  SUPABASE_SERVICE_ROLE_KEY?: string;
}

export type DispatchStep = (deviceId: string, step: Record<string, unknown>) => Promise<boolean>;

export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function cronMinuteKey(jobId: string, nowMs: number): string {
  const minute = Math.floor(nowMs / 60_000);
  return `${jobId}:${minute}`;
}

export interface TickResult {
  ok: boolean;
  fired: number;
  skipped: number;
  error?: string;
}

export async function handleTick(
  db: D1Like,
  env: CronEnv,
  secret: string | null,
  dispatch: DispatchStep,
  nowMs = Date.now(),
): Promise<TickResult> {
  if (!env.CRON_SECRET || !secret || !constantTimeEqual(secret, env.CRON_SECRET)) {
    return { ok: false, fired: 0, skipped: 0, error: "unauthorized" };
  }
  let jobs: Record<string, unknown>[];
  try {
    jobs = await supabaseSelect(
      env,
      "scheduled_jobs",
      `select=id,tenant_id,device_id,cron_expr,command&enabled=eq.true&next_run_at=lte.${new Date(nowMs).toISOString()}`,
    );
  } catch (e) {
    if (e instanceof SupabaseMissing) return { ok: false, fired: 0, skipped: 0, error: "config_missing" };
    if (e instanceof SupabaseSchemaPending) return { ok: false, fired: 0, skipped: 0, error: "schema_pending" };
    throw e;
  }
  let fired = 0;
  let skipped = 0;
  for (const job of jobs) {
    const jobId = String(job.id);
    const minuteKey = cronMinuteKey(jobId, nowMs);
    const existing = await db
      .prepare("SELECT id FROM traces WHERE kind = ? AND detail LIKE ? LIMIT 1")
      .bind("cron_fire", `%"minute":"${minuteKey}"%`)
      .first<{ id: number }>();
    if (existing) {
      skipped++;
      continue;
    }
    const dispatched = await dispatch(String(job.device_id), {
      kind: "CRON_COMMAND",
      command: String(job.command),
      job_id: jobId,
    });
    await insertTrace(db, String(job.tenant_id), String(job.device_id), "cron_fire", {
      job_id: jobId,
      minute: minuteKey,
      dispatched,
    });
    // next_run_at: proper cron next-run (minimal 5-field parser, neeche).
    // Naive +5min GALAT hota (daily job har 5 min fire hoti) — isliye
    // parser mandatory hai, simplification nahi.
    const next = nextCronRun(String(job.cron_expr), nowMs);
    await supabaseUpdate(env, "scheduled_jobs", `id=eq.${jobId}`, {
      last_run_at: new Date(nowMs).toISOString(),
      next_run_at: next ? new Date(next).toISOString() : null,
    });
    fired++;
  }
  return { ok: true, fired, skipped };
}

/**
 * Minimal 5-field cron parser (minute hour dom month dow).
 * Supports: * , lists (1,2), ranges (1-5), steps (*\/15, 0-30/10).
 * Months 1-12, dow 0-6 (0 = Sunday; 7 bhi Sunday mana jata hai).
 * Returns next matching minute AFTER fromMs (exclusive), ya null agar
 * 366 din me koi match na mile (invalid expr jaisa treat karo).
 * UTC me compute hota hai (server time UTC hai; user timezone ka
 * conversion client-side hota hai — Phase 2 me UTC hi canonical hai).
 */
export function nextCronRun(cronExpr: string, fromMs: number): number | null {
  const fields = cronExpr.trim().split(/\s+/);
  if (fields.length !== 5) return null;
  const parse = (field: string, min: number, max: number): Set<number> | null => {
    const out = new Set<number>();
    for (const part of field.split(",")) {
      const stepSplit = part.split("/");
      const range = stepSplit[0];
      const step = stepSplit.length > 1 ? Number(stepSplit[1]) : 1;
      if (!Number.isInteger(step) || step < 1) return null;
      let lo = min;
      let hi = max;
      if (range !== "*") {
        const dash = range.split("-");
        if (dash.length === 1) {
          lo = hi = Number(dash[0]);
        } else if (dash.length === 2) {
          lo = Number(dash[0]);
          hi = Number(dash[1]);
        } else {
          return null;
        }
        if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < min || hi > max || lo > hi) {
          return null;
        }
      }
      for (let v = lo; v <= hi; v += step) out.add(v);
    }
    return out;
  };
  const minutes = parse(fields[0], 0, 59);
  const hours = parse(fields[1], 0, 23);
  const doms = parse(fields[2], 1, 31);
  const months = parse(fields[3], 1, 12);
  const dowsRaw = parse(fields[4], 0, 7);
  if (!minutes || !hours || !doms || !months || !dowsRaw) return null;
  // dow: 7 -> 0 (Sunday).
  const dows = new Set<number>();
  for (const d of dowsRaw) dows.add(d === 7 ? 0 : d);
  const domStar = fields[2] === "*";
  const dowStar = fields[4] === "*";
  // Start at next minute boundary after fromMs.
  let t = Math.floor(fromMs / 60_000) * 60_000 + 60_000;
  const limit = fromMs + 366 * 24 * 60 * 60_000;
  while (t <= limit) {
    const d = new Date(t);
    const domMatch = doms.has(d.getUTCDate());
    const dowMatch = dows.has(d.getUTCDay());
    // Standard cron: dom/dow me agar ek * hai to doosra decide karta hai;
    // dono specified hon to OR hota hai.
    const dayMatch = domStar && dowStar ? true : domStar ? dowMatch : dowStar ? domMatch : domMatch || dowMatch;
    if (
      minutes.has(d.getUTCMinutes()) &&
      hours.has(d.getUTCHours()) &&
      months.has(d.getUTCMonth() + 1) &&
      dayMatch
    ) {
      return t;
    }
    t += 60_000;
  }
  return null;
}
