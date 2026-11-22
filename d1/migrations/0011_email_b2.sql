-- OmniJarvis D1 migration 0009 — Resend email log + B2 backup records
-- (open-source completeness #52 Resend, #49 B2 backup, 2026-11-22).
-- email_sends: one row per send attempt (success AND failure — the
-- cap/429 audit trail; a failed send is never silent). to_email is
-- the tenant's own owner_email (already stored in D1); no email body
-- is ever stored here.
-- backups: one row per B2 tenant-export backup (metadata only — the
-- encrypted object lives in B2; sha256 is over the PLAINTEXT export
-- JSON so restore-test can verify content integrity after decrypt).
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + indexes only.
CREATE TABLE IF NOT EXISTS email_sends (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  to_email TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('sent', 'failed', 'capped', 'not_configured')),
  resend_id TEXT,
  error TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_sends_tenant_time ON email_sends(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS backups (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  b2_key TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok', 'failed')),
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_backups_tenant_time ON backups(tenant_id, created_at);
