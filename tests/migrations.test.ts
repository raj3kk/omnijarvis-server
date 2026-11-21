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

const SQL5 = readFileSync(
  new URL("../d1/migrations/0005_browser.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0005 (browser agent: browser_tasks + AWAITING_USER)", () => {
  it("creates browser_tasks with the 3c §2b columns", () => {
    expect(SQL5).toContain("CREATE TABLE IF NOT EXISTS browser_tasks (");
    for (const col of ["id TEXT PRIMARY KEY", "tenant_id TEXT NOT NULL", "device_id TEXT NOT NULL", "task_name TEXT NOT NULL", "site TEXT", "url TEXT", "provider TEXT NOT NULL DEFAULT 'phone_webview'", "status TEXT NOT NULL DEFAULT 'running'", "assist_count INTEGER NOT NULL DEFAULT 0", "created_at INTEGER NOT NULL", "updated_at INTEGER NOT NULL"]) {
      expect(SQL5).toContain(col);
    }
    expect(SQL5).toContain("idx_browser_tasks_device ON browser_tasks(device_id, created_at)");
    expect(SQL5).toContain("idx_browser_tasks_status ON browser_tasks(status)");
  });

  it("status is CHECK-constrained to the 5 lifecycle states incl. awaiting_user", () => {
    expect(SQL5).toContain("CHECK (status IN ('running', 'awaiting_user', 'paused', 'aborted', 'done'))");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM, no Supabase refs", () => {
    const code = SQL5.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
    expect(code.toLowerCase()).not.toContain("supabase");
  });
});

const SQL6 = readFileSync(
  new URL("../d1/migrations/0006_skills.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0006 (skill registry: skill_reviews + skill_signatures + memories)", () => {
  it("creates skill_reviews with the 3d §2a columns + decision CHECK", () => {
    expect(SQL6).toContain("CREATE TABLE IF NOT EXISTS skill_reviews (");
    for (const col of ["id INTEGER PRIMARY KEY AUTOINCREMENT", "skill_id TEXT NOT NULL", "reviewer TEXT NOT NULL", "decision TEXT NOT NULL", "reason TEXT", "created_at INTEGER NOT NULL"]) {
      expect(SQL6).toContain(col);
    }
    expect(SQL6).toContain("CHECK (decision IN ('approved', 'rejected'))");
    expect(SQL6).toContain("idx_skill_reviews_skill ON skill_reviews(skill_id, created_at)");
  });

  it("creates skill_signatures keyed by skill_id", () => {
    expect(SQL6).toContain("CREATE TABLE IF NOT EXISTS skill_signatures (");
    for (const col of ["skill_id TEXT PRIMARY KEY", "signature TEXT NOT NULL", "public_key TEXT NOT NULL", "signed_at INTEGER NOT NULL"]) {
      expect(SQL6).toContain(col);
    }
  });

  it("creates memories with the 3d §2a columns + tenant index", () => {
    expect(SQL6).toContain("CREATE TABLE IF NOT EXISTS memories (");
    for (const col of ["id INTEGER PRIMARY KEY AUTOINCREMENT", "tenant_id TEXT NOT NULL", "content TEXT NOT NULL", "embedding TEXT", "kind TEXT NOT NULL DEFAULT 'fact'", "created_at INTEGER NOT NULL"]) {
      expect(SQL6).toContain(col);
    }
    expect(SQL6).toContain("idx_memories_tenant ON memories(tenant_id, created_at)");
  });

  it("documents the 0005 collision (this file is 0006, not 0005)", () => {
    expect(SQL6).toContain("0006");
    expect(SQL6).toContain("0005 was taken by 3c");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM, no Supabase refs", () => {
    const code = SQL6.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
    expect(code.toLowerCase()).not.toContain("supabase");
  });
});

const SQL7 = readFileSync(
  new URL("../d1/migrations/0007_billing.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0007 (billing ledger: subscriptions + payments + refunds + ledger_events + e2b_runs + admin_settings)", () => {
  it("creates subscriptions with the UPI spec §4 columns + tenant index", () => {
    expect(SQL7).toContain("CREATE TABLE IF NOT EXISTS subscriptions (");
    for (const col of ["id TEXT PRIMARY KEY", "tenant_id TEXT NOT NULL", "plan_tier TEXT NOT NULL", "billing_period TEXT NOT NULL", "amount_paise INTEGER NOT NULL", "status TEXT NOT NULL", "starts_at TEXT", "expires_at TEXT", "created_at TEXT NOT NULL"]) {
      expect(SQL7).toContain(col);
    }
    expect(SQL7).toContain("idx_subscriptions_tenant ON subscriptions(tenant_id)");
  });

  it("creates payments with UNIQUE UTR + tenant index", () => {
    expect(SQL7).toContain("CREATE TABLE IF NOT EXISTS payments (");
    expect(SQL7).toContain("utr TEXT NOT NULL UNIQUE");
    expect(SQL7).toContain("amount_paise INTEGER NOT NULL");
    expect(SQL7).toContain("method TEXT NOT NULL DEFAULT 'upi'");
    expect(SQL7).toContain("idx_payments_tenant ON payments(tenant_id)");
  });

  it("creates refunds + ledger_events + e2b_runs (held/settled/released/killed CHECK) + admin_settings", () => {
    expect(SQL7).toContain("CREATE TABLE IF NOT EXISTS refunds (");
    expect(SQL7).toContain("refund_utr TEXT NOT NULL");
    expect(SQL7).toContain("CREATE TABLE IF NOT EXISTS ledger_events (");
    expect(SQL7).toContain("detail TEXT NOT NULL");
    expect(SQL7).toContain("CREATE TABLE IF NOT EXISTS e2b_runs (");
    expect(SQL7).toContain("CHECK (status IN ('held', 'settled', 'released', 'killed'))");
    expect(SQL7).toContain("CREATE TABLE IF NOT EXISTS admin_settings (");
    expect(SQL7).toContain("key TEXT PRIMARY KEY");
  });

  it("extends tenants with email verification + pending downgrade (ALTER, duplicate-column-safe)", () => {
    expect(SQL7).toContain("ALTER TABLE tenants ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0");
    expect(SQL7).toContain("ALTER TABLE tenants ADD COLUMN email_verify_token_hash TEXT");
    expect(SQL7).toContain("ALTER TABLE tenants ADD COLUMN email_verify_expires_at INTEGER");
    expect(SQL7).toContain("ALTER TABLE tenants ADD COLUMN pending_downgrade_tier TEXT");
  });

  it("documents that 0007 follows 0006 (no collision with 3d)", () => {
    expect(SQL7).toContain("0007");
    expect(SQL7).toContain("0006 was taken by 3d");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM, no Supabase refs, no Razorpay", () => {
    const code = SQL7.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
    expect(code.toLowerCase()).not.toContain("supabase");
    expect(code.toLowerCase()).not.toContain("razorpay");
  });
});
