import { afterEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { constantTimeEqual, cronMinuteKey, handleTick, nextCronRun } from "../src/cron";

const ENV = { CRON_SECRET: "test-cron", SUPABASE_URL: "https://x.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "k" };

function stubSupabase(jobs: Record<string, unknown>[]) {
  vi.stubGlobal(
    "fetch",
    async (url: string) => {
      if (url.includes("/rest/v1/scheduled_jobs")) {
        if (url.includes("select=")) return new Response(JSON.stringify(jobs), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    },
  );
}

function stubSupabase404() {
  vi.stubGlobal("fetch", async () => new Response("{}", { status: 404 }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("cron tick", () => {
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

  it("scheduled_jobs table missing (404) -> schema_pending", async () => {
    const db = new FakeD1();
    stubSupabase404();
    const res = await handleTick(db, ENV, "test-cron", async () => true);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("schema_pending");
  });

  it("fires due jobs once per minute (idempotency)", async () => {
    const db = new FakeD1();
    const jobs = [
      { id: "job-1", tenant_id: "t-1", device_id: "dev-1", cron_expr: "0 9 * * *", command: "open youtube" },
      { id: "job-2", tenant_id: "t-1", device_id: "dev-1", cron_expr: "*/15 * * * *", command: "check mail" },
    ];
    stubSupabase(jobs);
    const dispatched: string[] = [];
    const dispatch = async (deviceId: string, step: Record<string, unknown>) => {
      dispatched.push(String(step.job_id));
      return true;
    };
    const now = Date.parse("2026-11-21T09:00:00Z");
    const r1 = await handleTick(db, ENV, "test-cron", dispatch, now);
    expect(r1.ok).toBe(true);
    expect(r1.fired).toBe(2);
    expect(dispatched).toEqual(["job-1", "job-2"]);
    // Same minute again -> both skipped (idempotency via traces).
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
