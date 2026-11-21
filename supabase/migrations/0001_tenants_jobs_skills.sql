-- OmniJarvis Supabase migration 0001 — tenants, scheduled_jobs, global_skills + RLS.
-- Project: jarvis-licence (hvcsdlmgsnemprzfdynk). Coexists with live
-- `licences` + `learned_patterns` tables — those are NEVER touched here.
--
-- APPLY (gated on B-A/B-C): via Supabase Management API (jarvis-mgmt PAT)
-- once the PAT is fixed, OR via the dashboard SQL Editor (parent browser
-- task, rajraj3kk account). Until applied, the hub answers 503
-- `schema_pending` on the Supabase-backed routes (fail-closed) — the
-- Worker still deploys and serves the D1-backed routes.
-- NON-DESTRUCTIVE, re-runnable: only CREATE TABLE IF NOT EXISTS +
-- CREATE INDEX IF NOT EXISTS + DROP POLICY IF EXISTS / CREATE POLICY.
-- No DROP TABLE / TRUNCATE / DELETE anywhere in this file.
--
-- RLS model (frozen, Pehle-Jaanch §3.4): a user sees only their own
-- tenant's rows. Tenants are keyed by owner_email (frozen schema — no
-- owner_auth_id column), so policies use the JWT email claim
-- (auth.jwt() ->> 'email'). The service-role key bypasses RLS, so the
-- Worker's Supabase calls (licence verify, due jobs) work regardless.
-- Requires the Supabase `auth` schema (auth.jwt()) — Supabase only,
-- NOT bare Postgres.

-- tenants (RLS: user apna tenant hi padh sakta hai; service-role bypass karta hai)
CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_email TEXT NOT NULL UNIQUE,
  plan_tier TEXT NOT NULL DEFAULT 'free',   -- free | pro | business
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenants_select_own ON tenants;
CREATE POLICY tenants_select_own ON tenants FOR SELECT
  USING (owner_email = (auth.jwt() ->> 'email'));
DROP POLICY IF EXISTS tenants_insert_own ON tenants;
CREATE POLICY tenants_insert_own ON tenants FOR INSERT
  WITH CHECK (owner_email = (auth.jwt() ->> 'email'));
DROP POLICY IF EXISTS tenants_update_own ON tenants;
CREATE POLICY tenants_update_own ON tenants FOR UPDATE
  USING (owner_email = (auth.jwt() ->> 'email'))
  WITH CHECK (owner_email = (auth.jwt() ->> 'email'));

-- scheduled_jobs (NL cron — dispatcher isey padhta hai)
CREATE TABLE IF NOT EXISTS scheduled_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  device_id TEXT NOT NULL,
  cron_expr TEXT NOT NULL,           -- validated 5-field cron
  command TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  last_run_at TIMESTAMPTZ,
  next_run_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE scheduled_jobs ENABLE ROW LEVEL SECURITY;

-- Due-jobs query (cron tick): enabled=true AND next_run_at <= now.
CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_due ON scheduled_jobs(enabled, next_run_at);

DROP POLICY IF EXISTS jobs_select_own ON scheduled_jobs;
CREATE POLICY jobs_select_own ON scheduled_jobs FOR SELECT
  USING (tenant_id IN (SELECT id FROM tenants WHERE owner_email = (auth.jwt() ->> 'email')));
DROP POLICY IF EXISTS jobs_insert_own ON scheduled_jobs;
CREATE POLICY jobs_insert_own ON scheduled_jobs FOR INSERT
  WITH CHECK (tenant_id IN (SELECT id FROM tenants WHERE owner_email = (auth.jwt() ->> 'email')));
DROP POLICY IF EXISTS jobs_update_own ON scheduled_jobs;
CREATE POLICY jobs_update_own ON scheduled_jobs FOR UPDATE
  USING (tenant_id IN (SELECT id FROM tenants WHERE owner_email = (auth.jwt() ->> 'email')))
  WITH CHECK (tenant_id IN (SELECT id FROM tenants WHERE owner_email = (auth.jwt() ->> 'email')));
DROP POLICY IF EXISTS jobs_delete_own ON scheduled_jobs;
CREATE POLICY jobs_delete_own ON scheduled_jobs FOR DELETE
  USING (tenant_id IN (SELECT id FROM tenants WHERE owner_email = (auth.jwt() ->> 'email')));

-- global_skills (QUARANTINED-only — publish flow Phase 3 me; status kabhi
-- 'approved' yahan se nahi). RLS has NO UPDATE/DELETE policy on purpose:
-- only the service role (Phase 3 approval flow) can change status.
CREATE TABLE IF NOT EXISTS global_skills (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  manifest JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'quarantined'
    CHECK (status IN ('quarantined', 'approved', 'rejected')),
  submitted_by UUID REFERENCES tenants(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE global_skills ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_global_skills_status ON global_skills(status);

DROP POLICY IF EXISTS skills_select_own ON global_skills;
CREATE POLICY skills_select_own ON global_skills FOR SELECT
  USING (submitted_by IN (SELECT id FROM tenants WHERE owner_email = (auth.jwt() ->> 'email')));
DROP POLICY IF EXISTS skills_insert_own ON global_skills;
CREATE POLICY skills_insert_own ON global_skills FOR INSERT
  WITH CHECK (submitted_by IN (SELECT id FROM tenants WHERE owner_email = (auth.jwt() ->> 'email')));
