-- OmniJarvis D1 migration 0017 — R4 (Models + admin website + FCM triggers).
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- New: idempotency_keys (Track E Gmail-send dedupe, R4.6 / D-R18) +
-- cap_warnings (R4.9 80% cap-warning email, one row per tenant+period).
-- Alter: licence_web_users gains `is_admin` (R4.5 admin website — the
-- owner email flipify.com@gmail.com is the only admin; the flag is also
-- set at runtime by ensureOwnerAdmin so a row created after this
-- migration still becomes admin).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + one ADD COLUMN + one
-- UPDATE + INSERT OR IGNORE only.
CREATE TABLE IF NOT EXISTS idempotency_keys (
  tenant_id TEXT NOT NULL,
  key TEXT NOT NULL,
  gmail_message_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, key)
);
CREATE INDEX IF NOT EXISTS idx_idempotency_keys_created ON idempotency_keys(tenant_id, created_at);
CREATE TABLE IF NOT EXISTS cap_warnings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  period TEXT NOT NULL,
  replies_at_send INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
ALTER TABLE licence_web_users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
UPDATE licence_web_users SET is_admin = 1 WHERE email = 'flipify.com@gmail.com';
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0017_r4_idempotency_admin.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
