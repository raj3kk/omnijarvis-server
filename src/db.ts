/**
 * db.ts — D1 helpers (thin wrappers; SQL yahin rehta hai, routes me nahi).
 * Env.DB is a D1Database binding (wrangler.toml). Tests pass a fake
 * implementing the same { prepare } surface.
 *
 * D1 is THE store (D12 reframed, 2026-11-21 — Supabase removed):
 * licences, tenants, scheduled_jobs, global_skills live here too
 * (migration 0002), not in any external DB.
 */

export interface D1Like {
  prepare(query: string): D1PreparedLike;
  /**
   * Phase 4 (GAP-10 fix): D1 batch — one batch = one transaction
   * (BEGIN/COMMIT). Ledger writes MUST go through d1Batch() below;
   * sequential prepares without a batch are NOT atomic. Optional so
   * old fakes still typecheck — d1Batch falls back to sequential
   * runs only when batch is absent (never on live D1).
   */
  batch?(statements: D1PreparedLike[]): Promise<unknown[]>;
}

/**
 * Run prepared statements as ONE D1 batch (atomic). Live D1Database
 * has batch(); the cast is inside this helper only — callers pass
 * plain D1PreparedLike statements and never cast. Throws on any
 * statement failure (the batch rolls back); callers must not catch
 * and continue as if the writes landed.
 */
export async function d1Batch(db: D1Like, statements: D1PreparedLike[]): Promise<void> {
  const maybeBatch = (db as unknown as { batch?: (s: unknown[]) => Promise<unknown> }).batch;
  if (typeof maybeBatch === "function") {
    await maybeBatch.call(db, statements as unknown[]);
    return;
  }
  for (const s of statements) await s.run();
}

export interface D1PreparedLike {
  bind(...args: unknown[]): D1PreparedLike;
  run(): Promise<{ success: boolean; meta?: unknown }>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
}

export async function getDevice(
  db: D1Like,
  deviceId: string,
): Promise<{ device_id: string; tenant_id: string; public_key: string; enabled: number } | null> {
  const row = await db
    .prepare("SELECT device_id, tenant_id, public_key, enabled FROM devices WHERE device_id = ?")
    .bind(deviceId)
    .first<{ device_id: string; tenant_id: string; public_key: string; enabled: number }>();
  return row;
}

export async function insertTrace(
  db: D1Like,
  tenantId: string,
  deviceId: string,
  kind: string,
  detail: Record<string, unknown>,
): Promise<void> {
  await db
    .prepare("INSERT INTO traces (tenant_id, device_id, kind, detail, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(tenantId, deviceId, kind, JSON.stringify(detail), Date.now())
    .run();
}

export async function touchDeviceSeen(db: D1Like, deviceId: string): Promise<void> {
  await db
    .prepare("UPDATE devices SET last_seen = ? WHERE device_id = ?")
    .bind(Date.now(), deviceId)
    .run();
}

/**
 * Licence-key check (pairing init): D1 `licences` table (key, user_id,
 * device_id, status) — status 'active' hona chahiye. Revoked/missing
 * key -> false. (Was Supabase REST before the 2026-11-21 migration.)
 */
export async function verifyLicenceKey(db: D1Like, key: string): Promise<boolean> {
  const row = await db
    .prepare("SELECT status FROM licences WHERE key = ?")
    .bind(key)
    .first<{ status: string }>();
  return row?.status === "active";
}

export interface TenantRow {
  id: string;
  owner_email: string;
  plan_tier: string;
  billing_mode: string;
  gemini_key_enc: string | null;
  groq_key_enc?: string | null; // 0008 (R3): BYOK Groq key, same AES-GCM envelope
  pii_consent?: number | null; // 0004: DPDP consent for storing PII in doc_jobs (default 0)
  email_verified?: number | null; // 0007: 1 = email verified (Resend token / admin god-mode)
  pending_downgrade_tier?: string | null; // 0007: downgrade effective next cycle
}

/** Tenant lookup for the LLM router (Phase 3, stage 3a). Phase 4: also
 * returns email_verified + pending_downgrade_tier (0007 columns). */
export async function getTenant(db: D1Like, tenantId: string): Promise<TenantRow | null> {
  const row = await db
    .prepare(
      "SELECT id, owner_email, plan_tier, billing_mode, gemini_key_enc, groq_key_enc, pii_consent, email_verified, pending_downgrade_tier FROM tenants WHERE id = ?",
    )
    .bind(tenantId)
    .first<TenantRow>();
  return row;
}

export interface DueJob {
  id: string;
  tenant_id: string;
  device_id: string;
  cron_expr: string;
  command: string;
  enabled: number;
  last_run_at: number | null;
  next_run_at: number | null;
}

/** Due jobs: enabled AND next_run_at <= now, earliest first. */
export async function getDueJobs(db: D1Like, nowMs: number): Promise<DueJob[]> {
  const res = await db
    .prepare(
      "SELECT id, tenant_id, device_id, cron_expr, command, enabled, last_run_at, next_run_at " +
        "FROM scheduled_jobs WHERE enabled = ? AND next_run_at <= ? ORDER BY next_run_at ASC",
    )
    .bind(1, nowMs)
    .all<DueJob>();
  return res.results ?? [];
}

/** After a fire: record last run + next run (null = no future run). */
export async function markJobRun(
  db: D1Like,
  jobId: string,
  lastRunAt: number,
  nextRunAt: number | null,
): Promise<void> {
  await db
    .prepare("UPDATE scheduled_jobs SET last_run_at = ?, next_run_at = ? WHERE id = ?")
    .bind(lastRunAt, nextRunAt, jobId)
    .run();
}

/**
 * M-4 F-1: pause a job (owner re-enables manually — no auto-resume).
 * getDueJobs only returns enabled=1, so a paused job stops firing.
 */
export async function pauseJob(db: D1Like, jobId: string): Promise<void> {
  await db.prepare("UPDATE scheduled_jobs SET enabled = ? WHERE id = ?").bind(0, jobId).run();
}

/**
 * M-4 F-1: true when this job has a step_rejected_bad_sig trace in the
 * last 24h (device rejected a hub-signed step). The LIKE pattern anchors
 * on `,"job_id":"<id>",` — job_id is the FIRST detail field of the DO's
 * step_rejected_bad_sig trace, so "job-1" never matches "job-10".
 */
export async function hasRecentSigReject(db: D1Like, jobId: string, nowMs: number): Promise<boolean> {
  const row = await db
    .prepare(
      "SELECT id FROM traces WHERE kind = ? AND detail LIKE ? AND created_at >= ? LIMIT 1",
    )
    .bind("step_rejected_bad_sig", `%"job_id":"${jobId}",%`, nowMs - 24 * 60 * 60_000)
    .first<{ id: number }>();
  return row !== null;
}
