-- OmniJarvis D1 migration 0001 — devices, pairing tokens, sync state, traces, usage counters.
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d). Applied via CF API.
-- Destructive kabhi nahi: sirf CREATE TABLE IF NOT EXISTS + indexes.

-- devices: paired devices (public key hub par, private key sirf phone ke Keystore me)
CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  paired_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant_id);

-- pairing_tokens: 5-min one-time tokens (Worker routes se use hote hain;
-- DO SQLite me nahi — Worker ko shared store chahiye, isliye D1).
CREATE TABLE IF NOT EXISTS pairing_tokens (
  token TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pairing_tokens_expiry ON pairing_tokens(expires_at);

-- sync_state: per-device, per-table sync cursors
CREATE TABLE IF NOT EXISTS sync_state (
  device_id TEXT NOT NULL,
  table_name TEXT NOT NULL,
  last_seq INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (device_id, table_name)
);

-- traces: high-volume execution traces (PRD 8.2 — Supabase me nahi).
-- detail JSON hai; PII kabhi nahi.
CREATE TABLE IF NOT EXISTS traces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_traces_tenant_time ON traces(tenant_id, created_at);

-- usage_counters: per-tenant, per-month metering (Phase 4 metering ki neev)
CREATE TABLE IF NOT EXISTS usage_counters (
  tenant_id TEXT NOT NULL,
  period TEXT NOT NULL,
  replies INTEGER NOT NULL DEFAULT 0,
  e2b_runs INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, period)
);
