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
