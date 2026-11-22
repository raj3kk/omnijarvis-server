-- OmniJarvis D1 migration 0010 — Direct Google OAuth token vault (Track E, item #27).
-- google_tokens: ONE Google account per tenant (single-owner product;
-- a second connect upserts). Access + refresh tokens live AES-GCM
-- encrypted (KEY_ENC_SECRET, keyvault.ts envelope) — never plaintext.
-- google_oauth_states: one-time 10-min state rows for the consent
-- callback (pairing_tokens shape, 0001). Expired rows are harmless
-- (no tokens, no partial state); no cleanup job is required, but a
-- periodic DELETE of expired rows is safe at any time.
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + indexes only.
CREATE TABLE IF NOT EXISTS google_tokens (
  tenant_id TEXT PRIMARY KEY,
  google_email TEXT NOT NULL,
  access_token_enc TEXT NOT NULL,
  refresh_token_enc TEXT NOT NULL,
  scopes TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS google_oauth_states (
  state TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_google_oauth_states_expiry ON google_oauth_states(expires_at);
