-- OmniJarvis D1 migration 0014 — Main Executor jobs (R1, hybrid core).
-- One row per Main Executor job (escalation or admin-triggered ask).
-- The loop is a Workers step-runner: one step per invocation, state
-- lives here (never in Worker memory). Transcript is JSON: every step
-- appended (mini-swe save() shape) so a reviewer sees what the model
-- saw and did. Status: received, planned, editing, validating,
-- pr_open, pr_open_needs_work, parked, partial, done, failed,
-- blocked_token. Mode: github (admin token set) or dry-run (local
-- snapshot supplied at job creation — patch is authored + scanned but
-- the GitHub write waits for the token).
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + indexes only.
CREATE TABLE IF NOT EXISTS main_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  device_id TEXT,
  ask TEXT NOT NULL,
  repo TEXT NOT NULL,
  base_branch TEXT NOT NULL DEFAULT 'main',
  branch TEXT,
  status TEXT NOT NULL DEFAULT 'received',
  mode TEXT NOT NULL DEFAULT 'github',
  plan TEXT,
  transcript TEXT NOT NULL DEFAULT '[]',
  pr_url TEXT,
  pr_number INTEGER,
  ci_status TEXT,
  scan_verdict TEXT,
  llm_calls INTEGER NOT NULL DEFAULT 0,
  steps_used INTEGER NOT NULL DEFAULT 0,
  retries_used INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  error_code TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_main_jobs_status ON main_jobs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_main_jobs_tenant ON main_jobs(tenant_id, created_at);
