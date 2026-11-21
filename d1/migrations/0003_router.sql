-- OmniJarvis D1 migration 0003 — LLM router metering (Phase 3, stage 3a).
-- D11_ROUTER_DECISION_BRIEF.md §6 schema (adapted — see Pehle-Jaanch §1):
-- * "migration 0002" in the brief is STALE (0002 = Supabase port, applied).
-- * Key storage is D1 `tenants.gemini_key_enc` (AES-GCM, KEY_ENC_SECRET),
--   NOT Supabase (removed 2026-11-21). No service key exists.
-- * Reconciliation target is `llm_usage` vs `usage_counters` rollup
--   (financial ledger is D1 in Phase 4 — no Supabase ledger anymore).
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD COLUMN + indexes.
-- Idempotency note: ALTER TABLE ADD COLUMN fails on re-apply
-- ("duplicate column name") — the apply script treats that as OK/skip.

-- llm_usage: one row per server LLM call (failed calls too, cost 0).
-- PII NEVER here: no prompt/response text — counts + model + status only.
CREATE TABLE IF NOT EXISTS llm_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  turn_id TEXT NOT NULL,
  model TEXT NOT NULL,
  attempted_models TEXT NOT NULL,
  input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,
  cost_usd_micro INTEGER NOT NULL,
  billing_mode TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_llm_usage_tenant_time ON llm_usage(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_llm_usage_turn ON llm_usage(turn_id);

-- tenants: BYOK key (AES-GCM envelope, base64(iv || ciphertext)) + billing mode.
ALTER TABLE tenants ADD COLUMN gemini_key_enc TEXT;
ALTER TABLE tenants ADD COLUMN billing_mode TEXT NOT NULL DEFAULT 'byok';

-- usage_counters: LLM rollup columns (replies/e2b_runs already in 0001).
ALTER TABLE usage_counters ADD COLUMN llm_calls INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_counters ADD COLUMN input_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_counters ADD COLUMN output_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_counters ADD COLUMN cost_usd_micro INTEGER NOT NULL DEFAULT 0;
