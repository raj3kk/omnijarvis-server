-- OmniJarvis D1 migration 0007 — billing ledger + UPI subscriptions + E2B runs (Phase 4).
-- Pehle-Jaanch phase-4 §2a. NUMBER NOTE: 0006 was taken by 3d (0006_skills.sql,
-- live applied) — this migration is 0007 (live D1 schema check 2026-11-22: 19 tables,
-- no billing tables, tenants has gemini_key_enc/billing_mode/pii_consent).
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + indexes + ALTER TABLE ADD COLUMN only.
-- Dialect (UPI_FLOW_SPEC §4, frozen): TEXT ids, INTEGER paise (float kabhi nahi),
-- TEXT ISO-8601 timestamps, UNIQUE UTR. Timestamps TEXT hain (purani tables INTEGER
-- ms rehti hain — code ISO strings banata hai, kabhi mix nahi karta).
-- Atomicity: ledger writes D1 batch API se hote hain (ek batch = BEGIN/COMMIT) —
-- hold/settle/refund/approve ke multi-row updates ek hi batch me likho (GAP-10 fix).
-- UPI-only (D7): Razorpay nahi, koi payment gateway nahi. VPA code/repo me nahi —
-- admin_settings.upi_vpa me admin khud dalega.

-- subscriptions: ek tenant ki current + past subscriptions.
CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  plan_tier TEXT NOT NULL,
  billing_period TEXT NOT NULL,
  amount_paise INTEGER NOT NULL,
  status TEXT NOT NULL,
  starts_at TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_tenant ON subscriptions(tenant_id);

-- payments: har UPI payment (UTR ke saath). utr UNIQUE = duplicate UTR auto-block.
CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  subscription_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  utr TEXT NOT NULL UNIQUE,
  amount_paise INTEGER NOT NULL,
  method TEXT NOT NULL DEFAULT 'upi',
  status TEXT NOT NULL,
  admin_note TEXT,
  decided_by TEXT,
  decided_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_payments_tenant ON payments(tenant_id);

-- refunds: manual UPI sends ka record (auto-refund nahi hai).
CREATE TABLE IF NOT EXISTS refunds (
  id TEXT PRIMARY KEY,
  payment_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  amount_paise INTEGER NOT NULL,
  refund_utr TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_refunds_tenant ON refunds(tenant_id);

-- ledger_events: audit trail (har state change). detail = JSON string
-- (amounts, UTR, reason — PII nahi: bank account number / full UPI ID kabhi nahi).
CREATE TABLE IF NOT EXISTS ledger_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  detail TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_ledger_events_tenant ON ledger_events(tenant_id);

-- e2b_runs: hold/settle/release/kill ka record (UPI spec §8).
-- held = quota reserve hui; settled = run chala (count rehta hai);
-- released = failed run, hold wapas (count nahi hota); killed = 15-min cap.
CREATE TABLE IF NOT EXISTS e2b_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('held', 'settled', 'released', 'killed')),
  started_at TEXT NOT NULL,
  ended_at TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_e2b_runs_tenant ON e2b_runs(tenant_id);

-- admin_settings: UPI VPA + Grievance placeholder + E2B test hook.
-- Koi secret kabhi nahi (VPA business detail hai, secret nahi).
CREATE TABLE IF NOT EXISTS admin_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- tenants: email verification (Resend token hashed + 24h expiry) + pending downgrade.
ALTER TABLE tenants ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN email_verify_token_hash TEXT;
ALTER TABLE tenants ADD COLUMN email_verify_expires_at INTEGER;
ALTER TABLE tenants ADD COLUMN pending_downgrade_tier TEXT;
