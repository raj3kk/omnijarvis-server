-- OmniJarvis D1 migration 0004 — doc pipeline (Phase 3, stage 3b).
-- Pehle-Jaanch phase-3/3b §2b: doc_jobs + certificates + tenants.pii_consent.
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD COLUMN + indexes.
-- Idempotency note: ALTER TABLE ADD COLUMN fails on re-apply
-- ("duplicate column name") — the apply script treats that as OK/skip.
-- PII RULE: doc_jobs.result_json holds PII ONLY when the tenant's
-- tenants.pii_consent = 1; otherwise PII fields are stored as [REDACTED].
-- PII never goes into logs/traces. No real Aadhaar/PAN is ever stored
-- by tests — fixtures use invented values.

-- doc_jobs: one row per ingested/extracted/confirmed document.
-- status: ingested -> extracted -> confirmed (one-shot confirm, 3c card).
CREATE TABLE IF NOT EXISTS doc_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  source_name TEXT,
  result_json TEXT,
  confidence REAL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_doc_jobs_tenant_time ON doc_jobs(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_doc_jobs_status ON doc_jobs(status);

-- certificates: one row per issued certificate.
-- payload_hash UNIQUE: same canonical payload = same certificate
-- (hub returns the existing row instead of failing on re-issue).
-- pdf_url: Render origin that generated the PDF (no blob store on the
-- free tier — PDF bytes are returned inline in the certificate response
-- for one-shot download; pdf_url records the Render endpoint + hash
-- for regeneration).
CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  doc_job_id INTEGER NOT NULL,
  payload_hash TEXT UNIQUE NOT NULL,
  pdf_url TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_certificates_hash ON certificates(payload_hash);

-- tenants: DPDP consent flag for storing PII in doc_jobs.result_json.
ALTER TABLE tenants ADD COLUMN pii_consent INTEGER NOT NULL DEFAULT 0;
