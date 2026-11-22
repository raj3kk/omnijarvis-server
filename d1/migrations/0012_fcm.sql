-- OmniJarvis D1 migration 0012 — FCM push (1.12.0, 2026-11-22).
-- fcm_tokens: one row per paired device (device_id PK) — the FCM
-- registration token the app fetched from Firebase. Tokens are push
-- addresses, not user content: no PII beyond the device_id that
-- already exists in `devices`. Token values are NEVER logged,
-- never returned in any API response, never stored in traces.
-- fcm_sends: one row per send attempt (success AND failure — the
-- audit trail; a failed send is never silent). fcm_message_id is
-- FCM's `projects/<id>/messages/<mid>` name on success, NULL on
-- failure. No message title/body is ever stored here.
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + indexes only.
CREATE TABLE IF NOT EXISTS fcm_tokens (
  device_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  token TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fcm_tokens_tenant ON fcm_tokens(tenant_id);

CREATE TABLE IF NOT EXISTS fcm_sends (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('sent', 'failed', 'not_configured', 'no_token')),
  fcm_message_id TEXT,
  error TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fcm_sends_tenant_time ON fcm_sends(tenant_id, created_at);
