-- OmniJarvis D1 migration 0013 — self-serve licence web UI (M-I-28).
-- Passwordless email-code auth for the hub-served licence pages:
--   licence_web_users: one row per email (verified flag only — no
--     passwords anywhere in this system, by design).
--   licence_email_codes: one active 6-digit code per (email, purpose);
--     code is SHA-256 hashed at rest, 10-min expiry, max 5 attempts.
--   licence_web_sessions: SHA-256 hash of the session token (the raw
--     token lives only in the HttpOnly cookie), 30-day expiry.
-- No change to `licences` (the licence Worker owns it) or `tenants`
-- (a licence user becomes a tenant only when they pair a device).
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + indexes only.
CREATE TABLE IF NOT EXISTS licence_web_users (
  email TEXT PRIMARY KEY,
  email_verified INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS licence_email_codes (
  email TEXT NOT NULL,
  purpose TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (email, purpose)
);

CREATE TABLE IF NOT EXISTS licence_web_sessions (
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_licence_web_sessions_email
  ON licence_web_sessions(email, expires_at);
