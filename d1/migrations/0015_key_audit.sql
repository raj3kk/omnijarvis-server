-- OmniJarvis D1 migration 0015 — key set/delete audit trace (R1, N-7 fix).
-- The pre-R-15 Gemini key loss was unauditable because POST/DELETE
-- /api/tenants/:id/key and /groq-key wrote no trace row. Every set and
-- delete now writes one row here (key VALUE never recorded — only the
-- fact, the kind, the tenant, and the actor). Actor is "admin" for the
-- x-admin-token routes. Read-only audit table: nothing deletes from it.
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + index only.
CREATE TABLE IF NOT EXISTS key_audit (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  key_kind TEXT NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT 'admin',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_key_audit_tenant ON key_audit(tenant_id, created_at);
