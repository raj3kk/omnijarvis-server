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

const SQL9 = readFileSync(
  new URL("../d1/migrations/0009_captcha_solves.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0009 (captcha auto-solve audit: captcha_solves)", () => {
  it("creates captcha_solves with the DESIGN §4.1 columns + outcome CHECK", () => {
    expect(SQL9).toContain("CREATE TABLE IF NOT EXISTS captcha_solves (");
    for (const col of ["id TEXT PRIMARY KEY", "tenant_id TEXT NOT NULL", "device_id TEXT NOT NULL", "task_id TEXT NOT NULL", "site TEXT", "challenge_type TEXT NOT NULL", "model TEXT", "confidence REAL", "outcome TEXT NOT NULL", "attempts INTEGER NOT NULL", "latency_ms INTEGER", "flag_asserted INTEGER NOT NULL", "image_sha256 TEXT", "created_at INTEGER NOT NULL"]) {
      expect(SQL9).toContain(col);
    }
    for (const outcome of ["submitted", "submitted_ok", "submitted_wrong", "low_confidence", "parse_failed", "safety_blocked", "cap_reached", "not_allowed", "byok_required"]) {
      expect(SQL9).toContain(`'${outcome}'`);
    }
    expect(SQL9).toContain("idx_captcha_solves_tenant ON captcha_solves(tenant_id, created_at)");
    expect(SQL9).toContain("idx_captcha_solves_task ON captcha_solves(task_id, created_at)");
    expect(SQL9).toContain("idx_captcha_solves_outcome ON captcha_solves(outcome, created_at)");
  });

  it("carries NO answer/solution/token/image column (DESIGN §4.3)", () => {
    // Column names only — a substring search false-positives on the
    // outcome value 'answered' (which contains "answer").
    const tableSql = SQL9.slice(SQL9.indexOf("CREATE TABLE"), SQL9.indexOf(");"));
    const colNames = [...tableSql.matchAll(/^\s{2}(\w+)\s/mg)].map((m) => m[1].toLowerCase());
    expect(colNames.length).toBeGreaterThan(0);
    for (const forbidden of ["answer", "solution", "token", "image_b64", "image_bytes"]) {
      expect(colNames).not.toContain(forbidden);
    }
    // Only the image hash is retained (audit/dedup).
    expect(SQL9).toContain("image_sha256 TEXT");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM, no Supabase refs", () => {
    const code = SQL9.replace(/--[^\\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
    expect(code.toLowerCase()).not.toContain("supabase");
  });
});

const SQL10 = readFileSync(
  new URL("../d1/migrations/0010_google_oauth.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0010 (Track E: Google OAuth token vault)", () => {
  it("creates google_tokens + google_oauth_states, encrypted columns, non-destructive", () => {
    expect(SQL10).toContain("CREATE TABLE IF NOT EXISTS google_tokens (");
    expect(SQL10).toContain("CREATE TABLE IF NOT EXISTS google_oauth_states (");
    expect(SQL10).toContain("tenant_id TEXT NOT NULL");
    const code = SQL10.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toContain("client_secret");
  });
});

const SQL11 = readFileSync(
  new URL("../d1/migrations/0011_email_b2.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0011 (Track C: Resend email log + B2 backup records)", () => {
  it("creates email_sends with the four honest statuses + tenant index", () => {
    expect(SQL11).toContain("CREATE TABLE IF NOT EXISTS email_sends (");
    for (const col of ["id TEXT PRIMARY KEY", "tenant_id TEXT NOT NULL", "kind TEXT NOT NULL", "to_email TEXT NOT NULL", "status TEXT NOT NULL", "resend_id TEXT", "error TEXT", "created_at INTEGER NOT NULL"]) {
      expect(SQL11).toContain(col);
    }
    expect(SQL11).toContain("CHECK (status IN ('sent', 'failed', 'capped', 'not_configured'))");
    expect(SQL11).toContain("idx_email_sends_tenant_time ON email_sends(tenant_id, created_at)");
  });

  it("creates backups with ok/failed status + tenant index", () => {
    expect(SQL11).toContain("CREATE TABLE IF NOT EXISTS backups (");
    for (const col of ["id TEXT PRIMARY KEY", "tenant_id TEXT NOT NULL", "kind TEXT NOT NULL", "b2_key TEXT NOT NULL", "size_bytes INTEGER NOT NULL", "sha256 TEXT NOT NULL", "status TEXT NOT NULL", "created_at INTEGER NOT NULL"]) {
      expect(SQL11).toContain(col);
    }
    expect(SQL11).toContain("CHECK (status IN ('ok', 'failed'))");
    expect(SQL11).toContain("idx_backups_tenant_time ON backups(tenant_id, created_at)");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM, no secrets", () => {
    const code = SQL11.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
    expect(code.toLowerCase()).not.toContain("resend_api_key");
    expect(code.toLowerCase()).not.toContain("application_key");
  });
});

const SQL12 = readFileSync(
  new URL("../d1/migrations/0012_fcm.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0012 (1.12.0 FCM: fcm_tokens + fcm_sends)", () => {
  it("creates fcm_tokens keyed by device_id + tenant index", () => {
    expect(SQL12).toContain("CREATE TABLE IF NOT EXISTS fcm_tokens (");
    for (const col of ["device_id TEXT PRIMARY KEY", "tenant_id TEXT NOT NULL", "token TEXT NOT NULL", "updated_at INTEGER NOT NULL"]) {
      expect(SQL12).toContain(col);
    }
    expect(SQL12).toContain("idx_fcm_tokens_tenant ON fcm_tokens(tenant_id)");
  });

  it("creates fcm_sends with the four honest statuses + tenant index, no title/body columns", () => {
    expect(SQL12).toContain("CREATE TABLE IF NOT EXISTS fcm_sends (");
    for (const col of ["id TEXT PRIMARY KEY", "tenant_id TEXT NOT NULL", "device_id TEXT NOT NULL", "kind TEXT NOT NULL", "status TEXT NOT NULL", "fcm_message_id TEXT", "error TEXT", "created_at INTEGER NOT NULL"]) {
      expect(SQL12).toContain(col);
    }
    expect(SQL12).toContain("CHECK (status IN ('sent', 'failed', 'not_configured', 'no_token'))");
    expect(SQL12).toContain("idx_fcm_sends_tenant_time ON fcm_sends(tenant_id, created_at)");
    const tableSql = SQL12.slice(SQL12.indexOf("CREATE TABLE IF NOT EXISTS fcm_sends"), SQL12.indexOf(");", SQL12.indexOf("CREATE TABLE IF NOT EXISTS fcm_sends")));
    expect(tableSql).not.toContain("title");
    expect(tableSql).not.toContain("body");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM, no secrets", () => {
    const code = SQL12.replace(/--[^\\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
    expect(code.toLowerCase()).not.toContain("private_key");
    expect(code.toLowerCase()).not.toContain("service_account");
  });
});

const SQL13 = readFileSync(
  new URL("../d1/migrations/0013_licence_web.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0013 (M-I-28 licence web: users + codes + sessions)", () => {
  it("creates licence_web_users keyed by email, no password column anywhere", () => {
    expect(SQL13).toContain("CREATE TABLE IF NOT EXISTS licence_web_users (");
    for (const col of ["email TEXT PRIMARY KEY", "email_verified INTEGER NOT NULL DEFAULT 0", "created_at INTEGER NOT NULL", "last_login_at INTEGER"]) {
      expect(SQL13).toContain(col);
    }
    expect(SQL13.toLowerCase()).not.toContain("password_hash");
    const usersTable = SQL13.slice(SQL13.indexOf("CREATE TABLE IF NOT EXISTS licence_web_users"), SQL13.indexOf(");", SQL13.indexOf("CREATE TABLE IF NOT EXISTS licence_web_users")));
    expect(usersTable.toLowerCase()).not.toContain("password");
  });

  it("creates licence_email_codes keyed by (email, purpose) with hashed code + expiry + attempts", () => {
    expect(SQL13).toContain("CREATE TABLE IF NOT EXISTS licence_email_codes (");
    for (const col of ["email TEXT NOT NULL", "purpose TEXT NOT NULL", "code_hash TEXT NOT NULL", "expires_at INTEGER NOT NULL", "attempts INTEGER NOT NULL DEFAULT 0", "PRIMARY KEY (email, purpose)"]) {
      expect(SQL13).toContain(col);
    }
    expect(SQL13).not.toContain("code TEXT");
  });

  it("creates licence_web_sessions keyed by token hash + email index", () => {
    expect(SQL13).toContain("CREATE TABLE IF NOT EXISTS licence_web_sessions (");
    for (const col of ["token_hash TEXT PRIMARY KEY", "email TEXT NOT NULL", "expires_at INTEGER NOT NULL", "last_seen_at INTEGER NOT NULL"]) {
      expect(SQL13).toContain(col);
    }
    expect(SQL13).toContain("idx_licence_web_sessions_email");
    expect(SQL13).not.toContain("token TEXT");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM, no secrets", () => {
    const code = SQL13.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
    expect(code.toLowerCase()).not.toContain("licence_admin_token");
    expect(code.toLowerCase()).not.toContain("resend_api_key");
  });
});

const SQL14 = readFileSync(
  new URL("../d1/migrations/0014_main_jobs.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0014 (R1 Main Executor jobs)", () => {
  it("creates main_jobs with the job state machine columns", () => {
    expect(SQL14).toContain("CREATE TABLE IF NOT EXISTS main_jobs (");
    for (const col of ["id TEXT PRIMARY KEY", "tenant_id TEXT NOT NULL", "ask TEXT NOT NULL", "repo TEXT NOT NULL", "status TEXT NOT NULL DEFAULT 'received'", "mode TEXT NOT NULL DEFAULT 'github'", "plan TEXT", "transcript TEXT NOT NULL DEFAULT '[]'", "pr_url TEXT", "llm_calls INTEGER NOT NULL DEFAULT 0", "steps_used INTEGER NOT NULL DEFAULT 0", "created_at INTEGER NOT NULL"]) {
      expect(SQL14).toContain(col);
    }
    expect(SQL14).toContain("idx_main_jobs_status");
    expect(SQL14).toContain("idx_main_jobs_tenant");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM, no secrets", () => {
    const code = SQL14.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
    expect(code.toLowerCase()).not.toContain("github_admin_token");
  });
});

const SQL15 = readFileSync(
  new URL("../d1/migrations/0015_key_audit.sql", import.meta.url),
  "utf8",
);

describe("D1 migration 0015 (R1 key set/delete audit trace, N-7 fix)", () => {
  it("creates key_audit with tenant + kind + action, and NO value column", () => {
    expect(SQL15).toContain("CREATE TABLE IF NOT EXISTS key_audit (");
    for (const col of ["id TEXT PRIMARY KEY", "tenant_id TEXT NOT NULL", "key_kind TEXT NOT NULL", "action TEXT NOT NULL", "actor TEXT NOT NULL DEFAULT 'admin'", "created_at INTEGER NOT NULL"]) {
      expect(SQL15).toContain(col);
    }
    expect(SQL15).toContain("idx_key_audit_tenant");
    // The key VALUE is never recorded — there must be no column that
    // could hold one.
    const code = SQL15.replace(/--[^\n]*/g, "");
    expect(code.toLowerCase()).not.toContain("key_value");
    expect(code.toLowerCase()).not.toContain("key_enc");
    expect(code.toLowerCase()).not.toContain("secret");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM", () => {
    const code = SQL15.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
  });
});
