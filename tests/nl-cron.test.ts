/**
 * M-I-30 tests — in-app cron, server part: NL -> cron parsing
 * (deterministic Hinglish/English + LLM-fallback extraction) and the
 * cron manager API gaps (enable + delete; create/list/disable already
 * existed and are covered in billing.test.ts). No D1 migration: the
 * scheduled_jobs schema already has every column.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { handleRequest, type Env } from "../src/hub";
import { resetRateLimitFallback } from "../src/ratelimit";
import { cronLlmSystemPrompt, llmParseCronText, parseNaturalCron } from "../src/nl-cron";
import { encryptTenantKey, importMasterKey } from "../src/keyvault";
import { bytesToBase64 } from "../src/crypto";

// Saturday 2026-11-21 12:00 UTC (matches cron.test.ts's Monday anchor).
const NOW = Date.UTC(2026, 10, 21, 12, 0, 0);

beforeEach(() => {
  resetRateLimitFallback();
  vi.unstubAllGlobals();
});

function fakeEnv(db: FakeD1, overrides: Partial<Env> = {}): Env {
  return {
    JARVIS_HUB: {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        fetch: async () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
      }),
    } as unknown as DurableObjectNamespace,
    DB: db as unknown as D1Database,
    INTERNAL_SECRET: "test-internal",
    CRON_SECRET: "test-cron",
    LLM_ADMIN_TOKEN: "test-admin",
    ...overrides,
  };
}

async function seedTenant(db: FakeD1, id: string, plan = "pro"): Promise<void> {
  await db
    .prepare("INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, email_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id, `${id}@example.com`, plan, "byok", null, 0, 1, NOW)
    .run();
}

async function seedTenantWithKey(db: FakeD1, id: string, masterB64: string): Promise<void> {
  const master = await importMasterKey(masterB64);
  const enc = await encryptTenantKey(master, "TEST-GEMINI-KEY-1");
  await db
    .prepare("INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, email_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id, `${id}@example.com`, "pro", "byok", enc, 0, 1, NOW)
    .run();
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, "pubkey", NOW, NOW, 1)
    .run();
}

async function makeMasterKeyB64(): Promise<string> {
  const k = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
  return bytesToBase64(raw);
}

type Json = Record<string, unknown>;

async function call(
  db: FakeD1,
  method: string,
  path: string,
  body?: unknown,
  envOverrides: Partial<Env> = {},
): Promise<{ status: number; body: Json }> {
  const res = await handleRequest(
    new Request(`https://hub${path}`, {
      method,
      headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    fakeEnv(db, envOverrides),
  );
  return { status: res.status, body: (await res.json()) as Json };
}

describe("parseNaturalCron — deterministic Hinglish/English", () => {
  it("har subah 8 baje -> daily 08:00 UTC", () => {
    const r = parseNaturalCron("har subah 8 baje", { nowMs: NOW });
    expect(r?.cron_expr).toBe("0 8 * * *");
    expect(r?.source).toBe("deterministic");
    expect(r?.next_run_at).toBe(Date.UTC(2026, 10, 22, 8, 0, 0));
  });

  it("every Monday 9am -> 0 9 * * 1 (next Monday is 23rd)", () => {
    const r = parseNaturalCron("every Monday 9am", { nowMs: NOW });
    expect(r?.cron_expr).toBe("0 9 * * 1");
    expect(r?.next_run_at).toBe(Date.UTC(2026, 10, 23, 9, 0, 0));
  });

  it("IST: har Somvar subah 8 baje -> Monday 02:30 UTC (08:00 IST)", () => {
    const r = parseNaturalCron("har Somvar subah 8 baje", { utcOffsetMinutes: 330, nowMs: NOW });
    expect(r?.cron_expr).toBe("30 2 * * 1");
    expect(r?.next_run_at).toBe(Date.UTC(2026, 10, 23, 2, 30, 0));
  });

  it("IST midnight crossing: har Ravivar raat 12:30 baje -> Saturday 19:00 UTC", () => {
    const r = parseNaturalCron("har Ravivar raat 12:30 baje", { utcOffsetMinutes: 330, nowMs: NOW });
    expect(r?.cron_expr).toBe("0 19 * * 6");
  });

  it("intervals: har 15 minute / every 2 hours / har ghante", () => {
    expect(parseNaturalCron("har 15 minute", { nowMs: NOW })?.cron_expr).toBe("*/15 * * * *");
    expect(parseNaturalCron("every 2 hours", { nowMs: NOW })?.cron_expr).toBe("0 */2 * * *");
    expect(parseNaturalCron("har ghante", { nowMs: NOW })?.cron_expr).toBe("0 * * * *");
  });

  it("har mahine ki 1 tarikh subah 9 baje -> 0 9 1 * * (the 1 is a date, not the hour)", () => {
    const r = parseNaturalCron("har mahine ki 1 tarikh subah 9 baje", { nowMs: NOW });
    expect(r?.cron_expr).toBe("0 9 1 * *");
  });

  it("har mahine ki 1 tarikh (no time) -> 09:00 default", () => {
    expect(parseNaturalCron("har mahine ki 1 tarikh", { nowMs: NOW })?.cron_expr).toBe("0 9 1 * *");
  });

  it("weekdays 9am / raat 9 baje / 8:30 baje", () => {
    expect(parseNaturalCron("weekdays 9am", { nowMs: NOW })?.cron_expr).toBe("0 9 * * 1-5");
    expect(parseNaturalCron("raat 9 baje", { nowMs: NOW })?.cron_expr).toBe("0 21 * * *");
    expect(parseNaturalCron("8:30 baje", { nowMs: NOW })?.cron_expr).toBe("30 8 * * *");
  });

  it("unparseable: no time, bad interval, empty", () => {
    expect(parseNaturalCron("kal subah milte hain", { nowMs: NOW })).toBeNull();
    expect(parseNaturalCron("har 90 minute", { nowMs: NOW })).toBeNull();
    expect(parseNaturalCron("har 25 ghante", { nowMs: NOW })).toBeNull();
    expect(parseNaturalCron("", { nowMs: NOW })).toBeNull();
    expect(parseNaturalCron("hello world", { nowMs: NOW })).toBeNull();
  });
});

describe("llmParseCronText — strict extraction + validation", () => {
  it("bare expr passes; NO_TIME / prose-only / 4-field / invalid all fail", () => {
    expect(llmParseCronText("0 8 * * *", NOW)?.cron_expr).toBe("0 8 * * *");
    expect(llmParseCronText("NO_TIME", NOW)).toBeNull();
    expect(llmParseCronText("I cannot do that", NOW)).toBeNull();
    expect(llmParseCronText("0 8 * *", NOW)).toBeNull();
    expect(llmParseCronText("61 25 * * *", NOW)).toBeNull();
  });

  it("expr embedded in a sentence still extracts (first cron-shaped token wins)", () => {
    expect(llmParseCronText("Sure! Here is your schedule: 0 8 * * * enjoy!", NOW)?.cron_expr).toBe("0 8 * * *");
  });

  it("system prompt names the UTC offset and the NO_TIME contract", () => {
    const p = cronLlmSystemPrompt(330);
    expect(p).toContain("UTC+5:30");
    expect(p).toContain("NO_TIME");
    expect(p).toContain("ONLY the cron expression");
  });
});

describe("POST /api/cron/parse route", () => {
  it("deterministic: har subah 8 baje -> 200 with expr + next_run_at, no LLM call", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-parse-1");
    const res = await call(db, "POST", "/api/cron/parse", { tenant_id: "t-parse-1", text: "har subah 8 baje" });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.cron_expr).toBe("0 8 * * *");
    expect(res.body.source).toBe("deterministic");
    expect(typeof res.body.next_run_at).toBe("number");
  });

  it("IST offset flows through: har Somvar subah 8 baje + 330 -> 30 2 * * 1", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-parse-2");
    const res = await call(db, "POST", "/api/cron/parse", {
      tenant_id: "t-parse-2",
      text: "har Somvar subah 8 baje",
      utc_offset_minutes: 330,
    });
    expect(res.status).toBe(200);
    expect(res.body.cron_expr).toBe("30 2 * * 1");
  });

  it("unparseable + key-less tenant -> 422 unparseable (LLM fallback refuses, never a 500)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-parse-3");
    const res = await call(db, "POST", "/api/cron/parse", { tenant_id: "t-parse-3", text: "kal milte hain" });
    expect(res.status).toBe(422);
    expect(res.body.error).toBe("unparseable");
  });

  it("LLM fallback: keyed tenant + mocked Gemini replying a bare expr -> 200 source llm", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-parse-4", master);
    vi.stubGlobal(
      "fetch",
      async () =>
        new Response(
          JSON.stringify({
            candidates: [{ content: { parts: [{ text: "0 8 * * *" }] }, finishReason: "STOP" }],
            usageMetadata: { promptTokenCount: 50, candidatesTokenCount: 5 },
          }),
          { status: 200 },
        ),
    );
    const res = await call(db, "POST", "/api/cron/parse", { tenant_id: "t-parse-4", text: "roz subah office jaane se pehle" }, { KEY_ENC_SECRET: master });
    expect(res.status).toBe(200);
    expect(res.body.cron_expr).toBe("0 8 * * *");
    expect(res.body.source).toBe("llm");
  });

  it("no auth -> 401; empty text -> 400; unknown tenant -> 404", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-parse-5");
    const noAuth = await handleRequest(
      new Request("https://hub/api/cron/parse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenant_id: "t-parse-5", text: "har subah 8 baje" }),
      }),
      fakeEnv(db),
    );
    expect(noAuth.status).toBe(401);
    expect((await call(db, "POST", "/api/cron/parse", { tenant_id: "t-parse-5", text: "   " })).status).toBe(400);
    expect((await call(db, "POST", "/api/cron/parse", { tenant_id: "t-ghost", text: "har subah 8 baje" })).status).toBe(404);
  });
});

describe("cron manager: enable + delete lifecycle", () => {
  async function setupJob(db: FakeD1, tenantId = "t-job-1"): Promise<string> {
    await seedTenant(db, tenantId, "pro");
    await seedDevice(db, `dev-${tenantId}`, tenantId);
    const created = await call(db, "POST", "/api/billing/cron-jobs", {
      tenant_id: tenantId,
      device_id: `dev-${tenantId}`,
      cron_expr: "0 9 * * *",
      command: "job 1",
    });
    expect(created.status).toBe(200);
    return String(created.body.job_id);
  }

  it("create -> list(1) -> disable -> enable (next_run recomputed) -> delete -> list(0)", async () => {
    const db = new FakeD1();
    const jobId = await setupJob(db);
    const list1 = await call(db, "GET", "/api/billing/cron-jobs?tenant_id=t-job-1");
    expect(list1.body.count).toBe(1);
    expect((await call(db, "POST", `/api/billing/cron-jobs/${jobId}/disable`, { tenant_id: "t-job-1" })).status).toBe(200);
    const afterDisable = await call(db, "GET", "/api/billing/cron-jobs?tenant_id=t-job-1");
    expect((afterDisable.body.jobs as Json[])[0].enabled).toBe(0);
    const enabled = await call(db, "POST", `/api/billing/cron-jobs/${jobId}/enable`, { tenant_id: "t-job-1" });
    expect(enabled.status).toBe(200);
    expect(enabled.body.enabled).toBe(true);
    expect(typeof enabled.body.next_run_at).toBe("number");
    const deleted = await call(db, "DELETE", `/api/billing/cron-jobs/${jobId}`);
    expect(deleted.status).toBe(200);
    expect(deleted.body.deleted).toBe(true);
    const list0 = await call(db, "GET", "/api/billing/cron-jobs?tenant_id=t-job-1");
    expect(list0.body.count).toBe(0);
  });

  it("enable an already-enabled job is a no-op 200; delete/ enable of a ghost job -> 404", async () => {
    const db = new FakeD1();
    const jobId = await setupJob(db, "t-job-2");
    const again = await call(db, "POST", `/api/billing/cron-jobs/${jobId}/enable`, { tenant_id: "t-job-2" });
    expect(again.status).toBe(200);
    expect(again.body.enabled).toBe(true);
    expect((await call(db, "DELETE", "/api/billing/cron-jobs/job-ghost")).status).toBe(404);
    expect((await call(db, "POST", "/api/billing/cron-jobs/job-ghost/enable", { tenant_id: "t-job-2" })).status).toBe(404);
    expect((await call(db, "POST", "/api/billing/cron-jobs/job-ghost/disable", { tenant_id: "t-job-2" })).status).toBe(404);
  });

  it("enable at cap -> 403 cron_cap (Phase 4 caps pattern reused)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-job-3", "pro"); // pro cap = 5
    await seedDevice(db, "dev-t-job-3", "t-job-3");
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      const c = await call(db, "POST", "/api/billing/cron-jobs", {
        tenant_id: "t-job-3",
        device_id: "dev-t-job-3",
        cron_expr: "0 9 * * *",
        command: `job ${i}`,
      });
      expect(c.status).toBe(200);
      ids.push(String(c.body.job_id));
    }
    expect((await call(db, "POST", `/api/billing/cron-jobs/${ids[0]}/disable`, { tenant_id: "t-job-3" })).status).toBe(200);
    const sixth = await call(db, "POST", "/api/billing/cron-jobs", {
      tenant_id: "t-job-3",
      device_id: "dev-t-job-3",
      cron_expr: "0 10 * * *",
      command: "job 5",
    });
    expect(sixth.status).toBe(200); // 4 enabled + 1 new = 5, at cap
    const over = await call(db, "POST", `/api/billing/cron-jobs/${ids[0]}/enable`, { tenant_id: "t-job-3" });
    expect(over.status).toBe(403);
    expect(over.body.error).toBe("cron_cap");
  });
});
