import { describe, expect, it } from "vitest";
import { FakeD1 } from "./fake-d1";
import { constantTimeEqual, cronMinuteKey, handleTick, nextCronRun } from "../src/cron";

const ENV = { CRON_SECRET: "test-cron" };

async function seedJob(
  db: FakeD1,
  id: string,
  cronExpr: string,
  command: string,
  nextRunAt: number,
  now: number,
) {
  await db
    .prepare(
      "INSERT INTO scheduled_jobs (id, tenant_id, device_id, cron_expr, command, enabled, last_run_at, next_run_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id, "t-1", "dev-1", cronExpr, command, 1, null, nextRunAt, now)
    .run();
}

describe("cron tick (D1 scheduled_jobs)", () => {
  it("wrong secret -> unauthorized", async () => {
    const db = new FakeD1();
    const res = await handleTick(db, ENV, "wrong", async () => true);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("unauthorized");
  });

  it("no CRON_SECRET configured -> unauthorized", async () => {
    const db = new FakeD1();
    const res = await handleTick(db, {}, "whatever", async () => true);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("unauthorized");
  });

  it("empty D1 -> ok, fires 0", async () => {
    const db = new FakeD1();
    const res = await handleTick(db, ENV, "test-cron", async () => true, Date.parse("2026-11-21T09:00:00Z"));
    expect(res.ok).toBe(true);
    expect(res.fired).toBe(0);
    expect(res.skipped).toBe(0);
  });

  it("fires due jobs once per minute (idempotency); future jobs do not fire", async () => {
    const db = new FakeD1();
    const now = Date.parse("2026-11-21T09:00:00Z");
    await seedJob(db, "job-1", "0 9 * * *", "open youtube", now - 60_000, now);
    await seedJob(db, "job-2", "*/15 * * * *", "check mail", now - 60_000, now);
    await seedJob(db, "job-3", "0 10 * * *", "future job", now + 3_600_000, now);
    const dispatched: string[] = [];
    const dispatch = async (deviceId: string, step: Record<string, unknown>) => {
      dispatched.push(String(step.job_id));
      return true;
    };
    const r1 = await handleTick(db, ENV, "test-cron", dispatch, now);
    expect(r1.ok).toBe(true);
    expect(r1.fired).toBe(2);
    expect(dispatched).toEqual(["job-1", "job-2"]);
    // markJobRun wrote next_run_at: daily 09:00 -> next day 09:00.
    // (Read BEFORE the reset below — tick 2 skips, so it never rewrites.)
    const row = await db
      .prepare("SELECT next_run_at FROM scheduled_jobs WHERE id = ?")
      .bind("job-1")
      .first<{ next_run_at: number }>();
    expect(row?.next_run_at).toBe(Date.parse("2026-11-22T09:00:00Z"));
    // Same minute again -> both skipped (idempotency via traces).
    // NOTE: tick 1's markJobRun already advanced next_run_at, so a plain
    // re-tick would find no due jobs at all. Re-open the jobs (simulates
    // the concurrent double-tick race: tick B read the due list before
    // tick A's markJobRun landed) — the traces guard must still skip.
    await db.prepare("UPDATE scheduled_jobs SET next_run_at = ? WHERE id = ?").bind(now - 60_000, "job-1").run();
    await db.prepare("UPDATE scheduled_jobs SET next_run_at = ? WHERE id = ?").bind(now - 60_000, "job-2").run();
    const r2 = await handleTick(db, ENV, "test-cron", dispatch, now + 30_000);
    expect(r2.fired).toBe(0);
    expect(r2.skipped).toBe(2);
    expect(dispatched.length).toBe(2);
  });

  it("constantTimeEqual", () => {
    expect(constantTimeEqual("abc", "abc")).toBe(true);
    expect(constantTimeEqual("abc", "abd")).toBe(false);
    expect(constantTimeEqual("abc", "abcd")).toBe(false);
  });

  it("cronMinuteKey: same minute same key", () => {
    expect(cronMinuteKey("j", 1700000000000)).toBe(cronMinuteKey("j", 1700000000000 + 30_000));
    expect(cronMinuteKey("j", 1700000000000)).not.toBe(cronMinuteKey("j", 1700000000000 + 61_000));
  });
});

describe("cron F-1 (M-4): pause job after step_rejected_bad_sig", () => {
  async function seedRejectTrace(db: FakeD1, jobId: string, createdAt: number) {
    await db
      .prepare("INSERT INTO traces (tenant_id, device_id, kind, detail, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind("t-1", "dev-1", "step_rejected_bad_sig", JSON.stringify({ job_id: jobId, ok: false }), createdAt)
      .run();
  }

  it("recent reject (24h) -> dispatch skipped + job paused + job_paused_sig_fail trace", async () => {
    const db = new FakeD1();
    const now = Date.now();
    await seedJob(db, "job-1", "0 9 * * *", "open youtube", now - 60_000, now);
    await seedRejectTrace(db, "job-1", now - 60_000);
    const dispatched: string[] = [];
    const res = await handleTick(db, ENV, "test-cron", async (_d, step) => {
      dispatched.push(String(step.job_id));
      return true;
    }, now);
    expect(res.ok).toBe(true);
    expect(res.fired).toBe(0);
    expect(res.skipped).toBe(1);
    expect(dispatched).toEqual([]);
    const row = await db
      .prepare("SELECT enabled FROM scheduled_jobs WHERE id = ?")
      .bind("job-1")
      .first<{ enabled: number }>();
    expect(row?.enabled).toBe(0);
    const traces = (await db.prepare("SELECT * FROM traces").bind().all()).results as Record<string, unknown>[];
    expect(traces.some((t) => t.kind === "job_paused_sig_fail")).toBe(true);
    // Paused job never fires again (getDueJobs only returns enabled=1).
    const res2 = await handleTick(db, ENV, "test-cron", async () => true, now + 60_000);
    expect(res2.fired).toBe(0);
  });

  it("old reject (>24h) -> job still dispatches", async () => {
    const db = new FakeD1();
    const now = Date.now();
    await seedJob(db, "job-1", "0 9 * * *", "open youtube", now - 60_000, now);
    await seedRejectTrace(db, "job-1", now - 25 * 60 * 60_000);
    const dispatched: string[] = [];
    const res = await handleTick(db, ENV, "test-cron", async (_d, step) => {
      dispatched.push(String(step.job_id));
      return true;
    }, now);
    expect(res.fired).toBe(1);
    expect(dispatched).toEqual(["job-1"]);
  });

  it("reject for another job (job-10) does NOT pause job-1 (exact job_id match)", async () => {
    const db = new FakeD1();
    const now = Date.now();
    await seedJob(db, "job-1", "0 9 * * *", "open youtube", now - 60_000, now);
    await seedRejectTrace(db, "job-10", now - 60_000);
    const dispatched: string[] = [];
    const res = await handleTick(db, ENV, "test-cron", async (_d, step) => {
      dispatched.push(String(step.job_id));
      return true;
    }, now);
    expect(res.fired).toBe(1);
    expect(dispatched).toEqual(["job-1"]);
    const row = await db
      .prepare("SELECT enabled FROM scheduled_jobs WHERE id = ?")
      .bind("job-1")
      .first<{ enabled: number }>();
    expect(row?.enabled).toBe(1);
  });

  it("no reject trace -> job dispatches normally", async () => {
    const db = new FakeD1();
    const now = Date.now();
    await seedJob(db, "job-1", "0 9 * * *", "open youtube", now - 60_000, now);
    const res = await handleTick(db, ENV, "test-cron", async () => true, now);
    expect(res.fired).toBe(1);
    expect(res.skipped).toBe(0);
  });
});

describe("nextCronRun (minimal 5-field parser)", () => {
  it("daily 09:00", () => {
    const from = Date.parse("2026-11-21T00:00:00Z");
    expect(nextCronRun("0 9 * * *", from)).toBe(Date.parse("2026-11-21T09:00:00Z"));
  });

  it("every 15 min", () => {
    const from = Date.parse("2026-11-21T10:07:00Z");
    expect(nextCronRun("*/15 * * * *", from)).toBe(Date.parse("2026-11-21T10:15:00Z"));
  });

  it("monthly 1st 00:00", () => {
    const from = Date.parse("2026-11-21T10:00:00Z");
    expect(nextCronRun("0 0 1 * *", from)).toBe(Date.parse("2026-12-01T00:00:00Z"));
  });

  it("Monday 09:00 (2026-11-21 is Saturday; next Monday is 23rd)", () => {
    const from = Date.parse("2026-11-21T10:00:00Z");
    expect(nextCronRun("0 9 * * 1", from)).toBe(Date.parse("2026-11-23T09:00:00Z"));
  });

  it("range + step: 0-30/10 minutes", () => {
    const from = Date.parse("2026-11-21T10:07:00Z");
    expect(nextCronRun("0-30/10 * * * *", from)).toBe(Date.parse("2026-11-21T10:10:00Z"));
  });

  it("invalid expr -> null", () => {
    expect(nextCronRun("not a cron", Date.now())).toBeNull();
    expect(nextCronRun("61 25 * * *", Date.now())).toBeNull();
    expect(nextCronRun("0 9 * *", Date.now())).toBeNull();
  });
});
