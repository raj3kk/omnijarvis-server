-- OmniJarvis D1 migration 0009 — Captcha auto-solve audit log (D3 LOCKED 2026-11-22).
-- captcha_solves: one row per auto-solve attempt (vision call), plus the
-- submission outcome (DESIGN §4.1). Append-only in v1 (D3 Q3 locked:
-- no retention job; revisit with a 90-day rule if any tenant exceeds 10k rows).
-- Columns carry NO answer, NO solution token, NO image bytes (DESIGN §4.3):
-- only the image SHA-256 (audit/dedup). The answer lives only in memory
-- on the device for the apply step.
-- id: solve_id (cs- + 16 hex) for attempt 1; attempts 2-3 carry
-- `<solve_id>-a<n>` so the PK stays unique per attempt (see src/captcha.ts).
-- outcome 'submitted' = the hub-side submission event (the answer handed
-- to the device, which submits it exactly once). Caps (2/task, 10/day)
-- count outcome='submitted' rows (DESIGN §3.3).
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + indexes only.
CREATE TABLE IF NOT EXISTS captcha_solves (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  site TEXT,
  challenge_type TEXT NOT NULL,
  model TEXT,
  confidence REAL,
  outcome TEXT NOT NULL CHECK (outcome IN ('answered', 'low_confidence', 'no_answer', 'parse_failed', 'model_error', 'timeout', 'safety_blocked', 'cap_reached', 'not_allowed', 'byok_required', 'submitted', 'submitted_ok', 'submitted_wrong')),
  attempts INTEGER NOT NULL,
  latency_ms INTEGER,
  flag_asserted INTEGER NOT NULL DEFAULT 1,
  image_sha256 TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_captcha_solves_tenant ON captcha_solves(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_captcha_solves_task ON captcha_solves(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_captcha_solves_outcome ON captcha_solves(outcome, created_at);
