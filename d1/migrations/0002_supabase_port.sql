-- OmniJarvis D1 migration 0002 — Supabase port + licence store.
-- Ports supabase/migrations/0001_tenants_jobs_skills.sql (Postgres -> SQLite)
-- and jarvis-server/supabase/schema.sql (licences + learned_patterns).
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + indexes only.
-- Dialect notes:
-- * No auth.users in D1: licences.user_id is opaque TEXT (owner identifier).
-- * Timestamps are INTEGER unix-ms (not TIMESTAMPTZ).
-- * Booleans are INTEGER 0/1 (approved, enabled).
-- * template / manifest stored as JSON TEXT (JSON.parse on read).
-- * RLS is gone by design: access control lives in Worker code
--   (D1 binding is private; no service key exists to leak).
-- Canonical copy: omnijarvis-server/d1/migrations/0002_supabase_port.sql.
-- goes to omnijarvis-server/d1/migrations/ at step 3 (after 2b-1 push).

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  owner_email TEXT NOT NULL UNIQUE,
  plan_tier TEXT NOT NULL DEFAULT 'free',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scheduled_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  device_id TEXT NOT NULL,
  cron_expr TEXT NOT NULL,
  command TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_run_at INTEGER,
  next_run_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_due ON scheduled_jobs(enabled, next_run_at);

CREATE TABLE IF NOT EXISTS global_skills (
  id TEXT PRIMARY KEY,
  manifest TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'quarantined' CHECK (status IN ('quarantined', 'approved', 'rejected')),
  submitted_by TEXT REFERENCES tenants(id),
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_global_skills_status ON global_skills(status);

CREATE TABLE IF NOT EXISTS licences (
  key TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_id TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS licences_one_active_per_user ON licences(user_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS learned_patterns (
  id TEXT PRIMARY KEY,
  template_hash TEXT UNIQUE NOT NULL,
  template TEXT NOT NULL,
  use_count INTEGER NOT NULL DEFAULT 1,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  approved INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_learned_patterns_approved ON learned_patterns(approved, use_count);
