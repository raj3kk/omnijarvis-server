-- OmniJarvis D1 migration 0016 — R2 shared memory (Trained Jarvis + admin training).
-- N-3 FIX (third audit): there was NO d1_migrations tracking table — the
-- schema existed only as loose files, so "which migrations are applied"
-- was unauditable. This migration creates the table AND records every
-- migration 0001-0016 (retroactive rows for 0001-0015, which were applied
-- before tracking existed). R1's Main Executor planned this exact table
-- (job main-mwszr7l9-nc9euz, "Add d1_migrations table") but the job is
-- stuck in `planned` on the unauthenticated GitHub rate limit — the table
-- lands here instead, not as a duplicate.
-- New: jarvis_events (shared event log — Talker + Executor both read/write).
-- Alter: learned_patterns gains `source` ('user' | 'admin'; admin wins on
-- conflict — R2.3). Admin training rows are approved=1 at insert.
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + one ADD COLUMN + indexes
-- + INSERT OR IGNORE only.
CREATE TABLE IF NOT EXISTS d1_migrations (
  name TEXT PRIMARY KEY,
  applied_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS jarvis_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  turn TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  result TEXT NOT NULL DEFAULT '',
  screen_meaning TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jarvis_events_tenant ON jarvis_events(tenant_id, created_at);
ALTER TABLE learned_patterns ADD COLUMN source TEXT NOT NULL DEFAULT 'user';
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0001_init.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0002_supabase_port.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0003_router.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0004_docs.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0005_browser.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0006_skills.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0007_billing.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0008_groq_key.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0009_captcha_solves.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0010_google_oauth.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0011_email_b2.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0012_fcm.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0013_licence_web.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0014_main_jobs.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0015_key_audit.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0016_r2_shared_memory.sql', CAST(strftime('%s','now') AS INTEGER)*1000);
