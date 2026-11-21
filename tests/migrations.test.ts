import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const SQL = readFileSync(
  new URL("../d1/migrations/0002_supabase_port.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0002 (Supabase port: tenants/jobs/skills + licences/patterns)", () => {
  it("creates the five tables (IF NOT EXISTS)", () => {
    for (const table of ["tenants", "scheduled_jobs", "global_skills", "licences", "learned_patterns"]) {
      expect(SQL).toContain(`CREATE TABLE IF NOT EXISTS ${table} (`);
    }
  });

  it("has NO Supabase / RLS / auth references", () => {
    // Executable SQL only: `--` header comments are provenance (which
    // Postgres file this ports), not functional references — same
    // comment-strip as the non-destructive test below.
    const code = SQL.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code.toLowerCase()).not.toContain("supabase");
    expect(code).not.toContain("ROW LEVEL SECURITY");
    expect(code).not.toContain("auth.jwt");
    expect(code).not.toContain("gen_random_uuid");
  });

  it("timestamps are INTEGER unix-ms, booleans INTEGER 0/1", () => {
    expect(SQL).toContain("created_at INTEGER NOT NULL");
    expect(SQL).toContain("approved INTEGER NOT NULL DEFAULT 0");
    expect(SQL).toContain("enabled INTEGER NOT NULL DEFAULT 1");
  });

  it("global_skills status is CHECK-constrained to the 3 states", () => {
    expect(SQL).toContain("CHECK (status IN ('quarantined', 'approved', 'rejected'))");
    expect(SQL).toContain("DEFAULT 'quarantined'");
  });

  it("licences: one active per user via partial unique index", () => {
    expect(SQL).toContain("CREATE UNIQUE INDEX IF NOT EXISTS licences_one_active_per_user ON licences(user_id) WHERE status = 'active'");
    expect(SQL).toContain("CHECK (status IN ('active', 'revoked'))");
  });

  it("learned_patterns: template is JSON TEXT, approved defaults 0", () => {
    expect(SQL).toContain("template TEXT NOT NULL");
    expect(SQL).toContain("template_hash TEXT UNIQUE NOT NULL");
  });

  it("has the due-jobs index (enabled, next_run_at)", () => {
    expect(SQL).toContain("idx_scheduled_jobs_due ON scheduled_jobs(enabled, next_run_at)");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM", () => {
    const code = SQL.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
  });
});

const SQL3 = readFileSync(
  new URL("../d1/migrations/0003_router.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0003 (LLM router metering: llm_usage + tenant key/mode + counters)", () => {
  it("creates llm_usage with the D11 §6 columns", () => {
    expect(SQL3).toContain("CREATE TABLE IF NOT EXISTS llm_usage (");
    for (const col of ["tenant_id TEXT NOT NULL", "turn_id TEXT NOT NULL", "model TEXT NOT NULL", "attempted_models TEXT NOT NULL", "input_tokens INTEGER NOT NULL", "output_tokens INTEGER NOT NULL", "cost_usd_micro INTEGER NOT NULL", "billing_mode TEXT NOT NULL", "status TEXT NOT NULL", "created_at INTEGER NOT NULL"]) {
      expect(SQL3).toContain(col);
    }
    expect(SQL3).toContain("idx_llm_usage_tenant_time ON llm_usage(tenant_id, created_at)");
    expect(SQL3).toContain("idx_llm_usage_turn ON llm_usage(turn_id)");
  });

  it("adds tenant key + billing_mode columns (BYOK, AES-GCM envelope)", () => {
    expect(SQL3).toContain("ALTER TABLE tenants ADD COLUMN gemini_key_enc TEXT");
    expect(SQL3).toContain("ALTER TABLE tenants ADD COLUMN billing_mode TEXT NOT NULL DEFAULT 'byok'");
  });

  it("adds the four LLM rollup columns to usage_counters", () => {
    for (const col of ["llm_calls INTEGER NOT NULL DEFAULT 0", "input_tokens INTEGER NOT NULL DEFAULT 0", "output_tokens INTEGER NOT NULL DEFAULT 0", "cost_usd_micro INTEGER NOT NULL DEFAULT 0"]) {
      expect(SQL3).toContain(`ALTER TABLE usage_counters ADD COLUMN ${col}`);
    }
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM, no Supabase refs", () => {
    const code = SQL3.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
    expect(code.toLowerCase()).not.toContain("supabase");
  });
});

const SQL4 = readFileSync(
  new URL("../d1/migrations/0004_docs.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0004 (doc pipeline: doc_jobs + certificates + pii_consent)", () => {
  it("creates doc_jobs with the 3b §2b columns", () => {
    expect(SQL4).toContain("CREATE TABLE IF NOT EXISTS doc_jobs (");
    for (const col of ["tenant_id TEXT NOT NULL", "device_id TEXT NOT NULL", "kind TEXT NOT NULL", "status TEXT NOT NULL", "source_name TEXT", "result_json TEXT", "confidence REAL", "created_at INTEGER NOT NULL"]) {
      expect(SQL4).toContain(col);
    }
    expect(SQL4).toContain("idx_doc_jobs_tenant_time ON doc_jobs(tenant_id, created_at)");
    expect(SQL4).toContain("idx_doc_jobs_status ON doc_jobs(status)");
  });

  it("creates certificates with UNIQUE payload_hash", () => {
    expect(SQL4).toContain("CREATE TABLE IF NOT EXISTS certificates (");
    for (const col of ["tenant_id TEXT NOT NULL", "doc_job_id INTEGER NOT NULL", "payload_hash TEXT UNIQUE NOT NULL", "pdf_url TEXT NOT NULL", "created_at INTEGER NOT NULL"]) {
      expect(SQL4).toContain(col);
    }
    expect(SQL4).toContain("idx_certificates_hash ON certificates(payload_hash)");
  });

  it("adds tenants.pii_consent (default 0, consent-gated PII storage)", () => {
    expect(SQL4).toContain("ALTER TABLE tenants ADD COLUMN pii_consent INTEGER NOT NULL DEFAULT 0");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM, no Supabase refs", () => {
    const code = SQL4.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
    expect(code.toLowerCase()).not.toContain("supabase");
  });
});
