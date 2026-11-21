import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const SQL = readFileSync(
  new URL("../supabase/migrations/0001_tenants_jobs_skills.sql", import.meta.url),
  "utf8",
);

describe("supabase migration 0001 (tenants/jobs/skills)", () => {
  it("creates the three tables (IF NOT EXISTS)", () => {
    for (const table of ["tenants", "scheduled_jobs", "global_skills"]) {
      expect(SQL).toContain(`CREATE TABLE IF NOT EXISTS ${table} (`);
    }
  });

  it("enables RLS on all three tables", () => {
    for (const table of ["tenants", "scheduled_jobs", "global_skills"]) {
      expect(SQL).toContain(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;`);
    }
  });

  it("has RLS policies keyed on the JWT email claim", () => {
    expect(SQL).toContain("auth.jwt() ->> 'email'");
    for (const policy of [
      "tenants_select_own",
      "tenants_insert_own",
      "tenants_update_own",
      "jobs_select_own",
      "jobs_insert_own",
      "jobs_update_own",
      "jobs_delete_own",
      "skills_select_own",
      "skills_insert_own",
    ]) {
      expect(SQL).toContain(`CREATE POLICY ${policy} ON`);
    }
  });

  it("global_skills has NO update/delete policy (quarantine enforced)", () => {
    expect(SQL).not.toMatch(/CREATE POLICY \w+ ON global_skills FOR (UPDATE|DELETE)/);
  });

  it("global_skills status is CHECK-constrained to the 3 states", () => {
    expect(SQL).toContain("CHECK (status IN ('quarantined', 'approved', 'rejected'))");
    expect(SQL).toContain("DEFAULT 'quarantined'");
  });

  it("has the due-jobs index (enabled, next_run_at)", () => {
    expect(SQL).toContain("idx_scheduled_jobs_due ON scheduled_jobs(enabled, next_run_at)");
  });

  it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM", () => {
    // Strip -- comments first (the header comment NAMES the forbidden
    // statements; the check is about executable SQL).
    const code = SQL.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
  });

  it("is re-runnable: policies use DROP POLICY IF EXISTS first", () => {
    const creates = [...SQL.matchAll(/CREATE POLICY (\w+) ON/g)].map((m) => m[1]);
    expect(creates.length).toBeGreaterThan(0);
    for (const name of creates) {
      expect(SQL).toContain(`DROP POLICY IF EXISTS ${name} ON`);
    }
  });

  it("references the live tables as untouched (licences/learned_patterns)", () => {
    expect(SQL).toContain("licences");
    expect(SQL).toContain("learned_patterns");
  });
});
