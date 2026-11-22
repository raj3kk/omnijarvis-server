/**
 * Resend email tests (Track C, #52 U-6) — mocked fetch only, no live
 * Resend account. Covers: raw send success / 429 / 4xx / fetch-throw /
 * not-configured (fetch never called), verification send (link contains
 * the token, D1 row recorded), local daily cap, renewal reminder, and
 * the hub verify-email routes (email status honestly reported, token
 * never in the response).
 */
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { FakeD1 } from "./fake-d1";
import { handleRequest, type Env } from "../src/hub";
import { resetRateLimitFallback } from "../src/ratelimit";
import {
  DEFAULT_DAILY_CAP,
  countSentToday,
  listEmailSends,
  recordEmailSend,
  sendEmail,
  sendRenewalReminderEmail,
  sendVerificationEmail,
  type EmailEnv,
} from "../src/email";
import { requestEmailVerification } from "../src/billing";
import type { TenantRow } from "../src/db";

const NOW = Date.UTC(2026, 11, 22, 12, 0, 0);

beforeEach(() => {
  resetRateLimitFallback();
  vi.unstubAllGlobals();
});

afterEach(() => {
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

async function seedTenant(db: FakeD1, id: string, plan = "free", verified = 0): Promise<void> {
  await db
    .prepare("INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, email_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id, `${id}@example.com`, plan, "byok", null, 0, verified, NOW)
    .run();
}

type Json = Record<string, unknown>;

async function call(
  db: FakeD1,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = { "x-internal-secret": "test-internal" },
  envOverrides: Partial<Env> = {},
): Promise<{ status: number; body: Json }> {
  const res = await handleRequest(
    new Request(`https://hub${path}`, {
      method,
      headers: { "Content-Type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    fakeEnv(db, envOverrides),
  );
  return { status: res.status, body: (await res.json()) as Json };
}

const KEYED: EmailEnv = { RESEND_API_KEY: "re_test_key", RESEND_FROM: "OmniJarvis <noreply@example.com>" };

function tenantRow(id: string): TenantRow {
  return {
    id,
    owner_email: `${id}@example.com`,
    plan_tier: "pro",
    billing_mode: "byok",
    gemini_key_enc: null,
    email_verified: 0,
  };
}

describe("sendEmail (Resend API, mocked fetch)", () => {
  it("200 {id} -> ok:true + id; Authorization Bearer + from/to/subject sent", async () => {
    const seen: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal(
      "fetch",
      async (url: string, init?: RequestInit) => {
        seen.push({ url, init: init ?? {} });
        return new Response(JSON.stringify({ id: "re_123" }), { status: 200 });
      },
    );
    const res = await sendEmail(KEYED, { to: "a@example.com", subject: "Hi", html: "<p>Hi</p>", text: "Hi" });
    expect(res).toEqual({ ok: true, id: "re_123" });
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe("https://api.resend.com/emails");
    expect(seen[0].init.method).toBe("POST");
    const headers = seen[0].init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer re_test_key");
    const body = JSON.parse(String(seen[0].init.body));
    expect(body.from).toBe("OmniJarvis <noreply@example.com>");
    expect(body.to).toBe("a@example.com");
    expect(body.subject).toBe("Hi");
  });

  it("429 -> rate_limited (cap signal), no throw", async () => {
    vi.stubGlobal("fetch", async () => new Response("slow down", { status: 429 }));
    const res = await sendEmail(KEYED, { to: "a@example.com", subject: "Hi", html: "x", text: "x" });
    expect(res).toEqual({ ok: false, error: "rate_limited", status: 429 });
  });

  it("400 -> resend_error with status + truncated detail", async () => {
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ message: "bad from" }), { status: 400 }));
    const res = await sendEmail(KEYED, { to: "a@example.com", subject: "Hi", html: "x", text: "x" });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe("resend_error");
      expect(res.status).toBe(400);
      expect(res.detail).toContain("bad from");
    }
  });

  it("fetch throws -> fetch_failed, no throw", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("network down");
    });
    const res = await sendEmail(KEYED, { to: "a@example.com", subject: "Hi", html: "x", text: "x" });
    expect(res).toEqual({ ok: false, error: "fetch_failed" });
  });

  it("no RESEND_API_KEY -> not_configured and fetch is NEVER called", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await sendEmail({}, { to: "a@example.com", subject: "Hi", html: "x", text: "x" });
    expect(res).toEqual({ ok: false, error: "not_configured" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("sendVerificationEmail + D1 record", () => {
  it("sends the verify link with the token; email_sends row status sent + resend_id", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    let capturedBody = "";
    vi.stubGlobal(
      "fetch",
      async (_url: string, init?: RequestInit) => {
        capturedBody = String(init?.body ?? "");
        return new Response(JSON.stringify({ id: "re_verify1" }), { status: 200 });
      },
    );
    const res = await sendVerificationEmail(KEYED, db, {
      tenant: tenantRow("t-1"),
      email: "t-1@example.com",
      token: "tok-abc-123",
    });
    expect(res.ok).toBe(true);
    const body = JSON.parse(capturedBody);
    expect(body.to).toBe("t-1@example.com");
    expect(body.subject).toContain("Verify");
    expect(body.html).toContain("/api/billing/verify-email/confirm?tenant_id=t-1&token=tok-abc-123");
    expect(body.text).toContain("tok-abc-123");
    const rows = await listEmailSends(db, "t-1");
    expect(rows).toHaveLength(1);
    expect(rows[0].kind).toBe("email_verification");
    expect(rows[0].status).toBe("sent");
    expect(rows[0].resend_id).toBe("re_verify1");
  });

  it("no key -> not_configured, row recorded, fetch never called", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await sendVerificationEmail({}, db, { tenant: tenantRow("t-1"), email: "t-1@example.com", token: "tok-x" });
    expect(res).toEqual({ ok: false, error: "not_configured", email_send_id: expect.any(String) });
    expect(fetchMock).not.toHaveBeenCalled();
    const rows = await listEmailSends(db, "t-1");
    expect(rows[0].status).toBe("not_configured");
  });

  it("429 -> rate_limited + failed row with error text (never crashes)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    vi.stubGlobal("fetch", async () => new Response("{}", { status: 429 }));
    const res = await sendVerificationEmail(KEYED, db, { tenant: tenantRow("t-1"), email: "t-1@example.com", token: "tok-x" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("rate_limited");
    const rows = await listEmailSends(db, "t-1");
    expect(rows[0].status).toBe("failed");
    expect(String(rows[0].error)).toContain("rate_limited");
  });

  it("local daily cap: 100 sent today -> no fetch, capped row, rate_limited", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    // Seed relative to REAL now (the code under test counts from
    // Date.now(), not from the fixed NOW constant).
    const realNow = Date.now();
    const dayStart = realNow - (realNow % 86_400_000);
    for (let i = 0; i < DEFAULT_DAILY_CAP; i++) {
      await recordEmailSend(db, { tenantId: "t-1", kind: "email_verification", to: "t-1@example.com", status: "sent", nowMs: dayStart + 1000 + i });
    }
    expect(await countSentToday(db, "t-1", realNow)).toBe(DEFAULT_DAILY_CAP);
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ id: "re_nope" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await sendVerificationEmail(KEYED, db, { tenant: tenantRow("t-1"), email: "t-1@example.com", token: "tok-x" });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe("rate_limited");
      expect(res.detail).toBe("local_daily_cap");
    }
    expect(fetchMock).not.toHaveBeenCalled();
    // 101 rows now — list with a limit above the default 50.
    const rows = await listEmailSends(db, "t-1", 200);
    expect(rows.some((r) => r.status === "capped")).toBe(true);
  });
});

describe("sendRenewalReminderEmail", () => {
  it("7d window: subject + expiry + amount; kind renewal_reminder_7d", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro", 1);
    let captured = "";
    vi.stubGlobal(
      "fetch",
      async (_url: string, init?: RequestInit) => {
        captured = String(init?.body ?? "");
        return new Response(JSON.stringify({ id: "re_rem1" }), { status: 200 });
      },
    );
    const res = await sendRenewalReminderEmail(KEYED, db, {
      tenant: tenantRow("t-1"),
      subscription: {
        id: "sub-1",
        tenant_id: "t-1",
        plan_tier: "pro",
        billing_period: "monthly",
        amount_paise: 99900,
        status: "active",
        starts_at: "2026-11-22T00:00:00.000Z",
        expires_at: "2026-12-22T00:00:00.000Z",
        created_at: "2026-11-22T00:00:00.000Z",
      },
      window: "7d",
    });
    expect(res.ok).toBe(true);
    const body = JSON.parse(captured);
    expect(body.subject).toContain("renews in 7 days");
    expect(body.text).toContain("2026-12-22");
    expect(body.text).toContain("₹999.00");
    const rows = await listEmailSends(db, "t-1");
    expect(rows[0].kind).toBe("renewal_reminder_7d");
    expect(rows[0].status).toBe("sent");
  });

  it("1d window subject differs", async () => {
    const db = new FakeD1();
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ id: "re_rem2" }), { status: 200 }));
    const res = await sendRenewalReminderEmail(KEYED, db, {
      tenant: tenantRow("t-1"),
      subscription: {
        id: "sub-1",
        tenant_id: "t-1",
        plan_tier: "business",
        billing_period: "annual",
        amount_paise: 3298900,
        status: "active",
        starts_at: "2026-11-22T00:00:00.000Z",
        expires_at: "2026-11-23T00:00:00.000Z",
        created_at: "2026-11-22T00:00:00.000Z",
      },
      window: "1d",
    });
    expect(res.ok).toBe(true);
    const rows = await listEmailSends(db, "t-1");
    expect(rows[0].kind).toBe("renewal_reminder_1d");
  });
});

describe("hub verify-email routes (Resend wired)", () => {
  it("request with RESEND_API_KEY -> email:sent, token never in response", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 0);
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ id: "re_route1" }), { status: 200 }));
    const res = await call(db, "POST", "/api/billing/verify-email/request", { tenant_id: "t-1", email: "real@example.com" }, { "x-internal-secret": "test-internal" }, { RESEND_API_KEY: "re_test_key" });
    expect(res.status).toBe(200);
    expect(res.body.verification_pending).toBe(true);
    expect(res.body.email).toBe("sent");
    expect(JSON.stringify(res.body)).not.toContain("token");
    const rows = await listEmailSends(db, "t-1");
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("sent");
  });

  it("request without RESEND_API_KEY -> email:not_configured, still 200 + pending", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 0);
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await call(db, "POST", "/api/billing/verify-email/request", { tenant_id: "t-1", email: "real@example.com" });
    expect(res.status).toBe(200);
    expect(res.body.email).toBe("not_configured");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("request with Resend 429 -> email:failed, still 200 + pending (never crashes)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 0);
    vi.stubGlobal("fetch", async () => new Response("{}", { status: 429 }));
    const res = await call(db, "POST", "/api/billing/verify-email/request", { tenant_id: "t-1", email: "real@example.com" }, { "x-internal-secret": "test-internal" }, { RESEND_API_KEY: "re_test_key" });
    expect(res.status).toBe(200);
    expect(res.body.email).toBe("failed");
    expect(res.body.email_error).toBe("rate_limited");
  });

  it("GET confirm with the real token -> verified (email link path)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 0);
    const tenant = (await db
      .prepare("SELECT id, owner_email, plan_tier, billing_mode, gemini_key_enc, email_verified FROM tenants WHERE id = ?")
      .bind("t-1")
      .first()) as unknown as TenantRow;
    const token = "aabbccddeeff00112233445566778899";
    expect((await requestEmailVerification(db, { tenant, email: "real@example.com", tokenForTest: token })).ok).toBe(true);
    const res = await call(db, "GET", `/api/billing/verify-email/confirm?tenant_id=t-1&token=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.email_verified).toBe(true);
    const row = await db.prepare("SELECT email_verified FROM tenants WHERE id = ?").bind("t-1").first<{ email_verified: number }>();
    expect(row?.email_verified).toBe(1);
  });

  it("GET confirm with wrong token -> 400", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 0);
    const res = await call(db, "GET", "/api/billing/verify-email/confirm?tenant_id=t-1&token=nope");
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("verification_failed");
  });

  it("admin email-sends list: 401 without admin token, rows with it", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 0);
    await recordEmailSend(db, { tenantId: "t-1", kind: "email_verification", to: "t-1@example.com", status: "failed", error: "rate_limited:429" });
    const denied = await call(db, "GET", "/api/billing/admin/email-sends", undefined, { "x-internal-secret": "test-internal" });
    expect(denied.status).toBe(401);
    const res = await call(db, "GET", "/api/billing/admin/email-sends?tenant_id=t-1", undefined, { "x-admin-token": "test-admin" });
    expect(res.status).toBe(200);
    expect(res.body.count).toBe(1);
    expect((res.body.email_sends as Array<Record<string, unknown>>)[0].status).toBe("failed");
  });
});
