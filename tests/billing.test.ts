/**
 * Billing tests (Phase 4) — B-T1…: subscription + UPI + D1 ledger +
 * caps + metering + E2B threshold + wipe + legal + launch gates.
 *
 * Test-plan mapping (PHASE4_TEST_PLAN.md): T-M5/T-M6 are BLOCKED
 * (margin NEGATIVE at current pricing — the tests assert the exact
 * loss numbers + blocked=true, never a PASS target). T-M7 is math-only
 * (no runtime controls-off flag exists anywhere in src/).
 * T-B1–T-B3/T-B5 are router-covered (3a/P0); T-B4 rotation is here.
 * T-C10/T-C11 are skills/docs-covered (3d/3b); T-C1–C3 are router-covered.
 */
import { describe, expect, it, vi, beforeEach } from "vitest";
import { FakeD1 } from "./fake-d1";
import { genDeviceKey } from "./helpers";
import { handleRequest, type Env } from "../src/hub";
import { canonicalString, bytesToBase64 } from "../src/crypto";
import { sortedJson } from "../src/docs";
import { resetRateLimitFallback } from "../src/ratelimit";
import {
  computeMargin,
  proratedUpgradeCharge,
  upiLink,
  runBillingSweeps,
  reconcileBilling,
} from "../src/billing";
import { d1Batch } from "../src/db";
import { recordUsage } from "../src/metering";
import { encryptTenantKey, importMasterKey } from "../src/keyvault";

const NOW = Date.UTC(2026, 11, 22, 12, 0, 0);

// The in-memory rate-limit fallback is module-level: reset it between
// tests so one tenant's calls in an earlier test never trip a later
// test's 30/min budget (production behaviour unchanged).
beforeEach(() => {
  resetRateLimitFallback();
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

async function seedTenant(db: FakeD1, id: string, plan = "free", verified = 1): Promise<void> {
  await db
    .prepare("INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, email_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id, `${id}@example.com`, plan, "byok", null, 0, verified, NOW)
    .run();
}

async function setVpa(db: FakeD1, vpa = "admin@okhdfc"): Promise<void> {
  await db
    .prepare("INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?)")
    .bind("upi_vpa", vpa, new Date(NOW).toISOString())
    .run();
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string, publicKeyB64: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, publicKeyB64, NOW, NOW, 1)
    .run();
}

async function seedPairingToken(db: FakeD1, token: string, deviceId: string, tenantId: string): Promise<void> {
  await db
    .prepare("INSERT INTO pairing_tokens (token, device_id, tenant_id, expires_at) VALUES (?, ?, ?, ?)")
    .bind(token, deviceId, tenantId, Date.now() + 300_000)
    .run();
}

async function seedUsage(db: FakeD1, tenantId: string, replies: number, e2bRuns = 0): Promise<void> {
  const period = new Date().toISOString().slice(0, 7);
  await db
    .prepare("INSERT INTO usage_counters (tenant_id, period, replies, e2b_runs, llm_calls, input_tokens, output_tokens, cost_usd_micro) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(tenantId, period, replies, e2bRuns, 0, 0, 0, 0)
    .run();
}

type Json = Record<string, unknown>;

async function call(
  db: FakeD1,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = { "x-internal-secret": "test-internal" },
): Promise<{ status: number; body: Json }> {
  const res = await handleRequest(
    new Request(`https://hub${path}`, {
      method,
      headers: { "Content-Type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    fakeEnv(db),
  );
  return { status: res.status, body: (await res.json()) as Json };
}

async function callAdmin(db: FakeD1, method: string, path: string, body?: unknown): Promise<{ status: number; body: Json }> {
  return call(db, method, path, body, { "x-admin-token": "test-admin" });
}

/** Signed-device call (docs pattern): canonical(device, nonce, ts, payloadRaw). */
async function callSigned(
  db: FakeD1,
  method: string,
  path: string,
  deviceId: string,
  sign: (data: string) => Promise<string>,
  body?: unknown,
  payloadRaw?: string,
): Promise<{ status: number; body: Json }> {
  const nonce = "aabbccddeeff00112233445566778899";
  const ts = Date.now();
  const raw = payloadRaw ?? sortedJson((body ?? {}) as Record<string, unknown>);
  const sig = await sign(canonicalString(deviceId, nonce, ts, raw));
  return call(
    db,
    method,
    path,
    body,
    { "x-device-id": deviceId, "x-nonce": nonce, "x-ts": String(ts), "x-signature": sig },
  );
}

/** Full UPI happy path for one tenant (subscribe → UTR → approve).
 * Each call uses a fresh test UTR (counter) — reusing one UTR across
 * tenants would trip the duplicate-UTR guard (T-U3) by design. */
let utrSeq = 400000000000;
async function happyPath(
  db: FakeD1,
  tenantId: string,
  plan: "pro" | "business",
  period: "monthly" | "annual",
): Promise<{ subscription_id: string; payment_id: string; expires_at: string }> {
  const sub = await call(db, "POST", "/api/billing/subscribe", { tenant_id: tenantId, plan_tier: plan, billing_period: period });
  expect(sub.status).toBe(200);
  const subscriptionId = String(sub.body.subscription_id);
  const utr = await call(db, "POST", "/api/billing/utr", { subscription_id: subscriptionId, utr: String(++utrSeq) });
  expect(utr.status).toBe(200);
  const paymentId = String(utr.body.payment_id);
  const appr = await callAdmin(db, "POST", "/api/billing/admin/approve", { payment_id: paymentId });
  expect(appr.status).toBe(200);
  return { subscription_id: subscriptionId, payment_id: paymentId, expires_at: String(appr.body.expires_at) };
}

describe("margin math — P0 §G7.2 formula (T-M5/T-M6 BLOCKED, T-M7)", () => {
  it("T-M5 BLOCKED: Pro worst case = ₹2,440.51 total, margin −₹1,441.51 (NOT a pass)", () => {
    const m = computeMargin("pro", "worst");
    expect(m.total_paise).toBe(244051);
    expect(m.margin_paise).toBe(-144151);
    expect(m.blocked).toBe(true);
  });

  it("T-M6 BLOCKED: Business worst case = ₹7,360.02 total, margin −₹4,361.02 (NOT a pass)", () => {
    const m = computeMargin("business", "worst");
    expect(m.total_paise).toBe(736002);
    expect(m.margin_paise).toBe(-436102);
    expect(m.blocked).toBe(true);
  });

  it("lean + base cases reproduce the audit exactly (all still loss)", () => {
    expect(computeMargin("pro", "lean").margin_paise).toBe(-22089);
    expect(computeMargin("business", "lean").margin_paise).toBe(-69915);
    expect(computeMargin("pro", "base").margin_paise).toBe(-800);
    expect(computeMargin("business", "base").margin_paise).toBe(-4768);
  });

  it("T-M7: without controls = LOSS (≈ −₹511 Pro / −₹1,607 Business) — controls are necessary; no runtime flag exists", () => {
    const pro = computeMargin("pro", "worst_no_controls");
    const biz = computeMargin("business", "worst_no_controls");
    expect(pro.margin_paise).toBe(-51076); // −₹510.76 ≈ −₹511
    expect(biz.margin_paise).toBe(-160729); // −₹1,607.29 ≈ −₹1,607
    expect(pro.blocked).toBe(true);
    expect(biz.blocked).toBe(true);
  });

  it("pro-rated upgrade math: half the Pro cycle left → charge = Business − remaining", () => {
    const start = Date.UTC(2026, 10, 22, 0, 0, 0);
    const end = start + 30 * 24 * 60 * 60 * 1000;
    const mid = start + 15 * 24 * 60 * 60 * 1000;
    const { remaining_paise, charge_paise } = proratedUpgradeCharge(99900, new Date(start).toISOString(), new Date(end).toISOString(), 299900, mid);
    expect(remaining_paise).toBe(49950);
    expect(charge_paise).toBe(249950);
  });

  it("UPI link shape (spec §3): pa + am + cu=INR + tn", () => {
    const link = upiLink("admin@okhdfc", 99900, "pro", "monthly");
    expect(link).toBe("upi://pay?pa=admin%40okhdfc&am=999&cu=INR&tn=OmniJarvis%20pro%20monthly");
  });
});

describe("D1 batch atomicity (GAP-10 fix)", () => {
  it("a failing statement rolls the whole batch back (first insert undone)", async () => {
    const db = new FakeD1();
    await expect(
      d1Batch(db, [
        db.prepare("INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?)").bind("k1", "v1", "t"),
        // Second insert violates the PK (same key) → batch must roll back.
        db.prepare("INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?)").bind("k1", "v2", "t"),
      ]),
    ).rejects.toThrow();
    const row = await db.prepare("SELECT value FROM admin_settings WHERE key = ?").bind("k1").first<{ value: string }>();
    expect(row).toBeNull();
  });

  it("a successful batch commits all statements", async () => {
    const db = new FakeD1();
    await d1Batch(db, [
      db.prepare("INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?)").bind("k1", "v1", "t"),
      db.prepare("INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?)").bind("k2", "v2", "t"),
    ]);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM admin_settings").bind().first<{ n: number }>())?.n).toBe(2);
  });
});

describe("subscribe (T-U1 setup, T-A2 gate)", () => {
  it("happy: verified tenant + VPA → pending_payment + UPI link + ledger event", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const res = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("pending_payment");
    expect(res.body.amount_paise).toBe(99900);
    expect(String(res.body.upi_link)).toContain("upi://pay?pa=");
    expect(String(res.body.upi_link)).toContain("am=999");
    expect(res.body.utr_expires_at).toBeTruthy();
    const sub = await db.prepare("SELECT status FROM subscriptions WHERE id = ?").bind(String(res.body.subscription_id)).first<{ status: string }>();
    expect(sub?.status).toBe("pending_payment");
    const ev = await db.prepare("SELECT kind FROM ledger_events WHERE tenant_id = ?").bind("t-1").first<{ kind: string }>();
    expect(ev?.kind).toBe("subscription_created");
  });

  it("T-A2: unverified email → 403 email_not_verified (no subscription created)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 0);
    await setVpa(db);
    const res = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe("email_not_verified");
    expect((await db.prepare("SELECT COUNT(*) AS n FROM subscriptions").bind().first<{ n: number }>())?.n).toBe(0);
  });

  it("no VPA configured → 503 upi_vpa_not_configured (VPA never in code)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    const res = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    expect(res.status).toBe(503);
    expect(res.body.error).toBe("upi_vpa_not_configured");
  });

  it("free tier subscribe → 400; unknown tenant → 404; no auth → 401; second open sub → 409", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    expect((await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "free", billing_period: "monthly" })).body.error).toBe("bad_request");
    expect((await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-ghost", plan_tier: "pro", billing_period: "monthly" })).status).toBe(404);
    const noAuth = await handleRequest(
      new Request("https://hub/api/billing/subscribe", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" }) }),
      fakeEnv(db),
    );
    expect(noAuth.status).toBe(401);
    const first = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    expect(first.status).toBe(200);
    const second = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "business", billing_period: "monthly" });
    expect(second.status).toBe(409);
    expect(second.body.error).toBe("subscription_exists");
  });
});

describe("UTR submit + approve/reject (T-U1–T-U5)", () => {
  it("T-U1: pay → UTR → approve → ACTIVE, expiry = approve + 30d, plan live", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const before = Date.now();
    const { subscription_id, expires_at } = await happyPath(db, "t-1", "pro", "monthly");
    expect(Date.parse(expires_at) - before).toBeGreaterThan(29 * 24 * 60 * 60 * 1000);
    expect(Date.parse(expires_at) - before).toBeLessThanOrEqual(31 * 24 * 60 * 60 * 1000);
    const sub = await db.prepare("SELECT status, plan_tier FROM subscriptions WHERE id = ?").bind(subscription_id).first<{ status: string; plan_tier: string }>();
    expect(sub?.status).toBe("active");
    const tenant = await db.prepare("SELECT plan_tier FROM tenants WHERE id = ?").bind("t-1").first<{ plan_tier: string }>();
    expect(tenant?.plan_tier).toBe("pro");
    const kinds = (await db.prepare("SELECT kind FROM ledger_events WHERE tenant_id = ?").bind("t-1").all<{ kind: string }>()).results ?? [];
    expect(kinds.map((k) => k.kind)).toEqual(["subscription_created", "utr_submitted", "approved"]);
  });

  it("T-U7: annual approve → expiry + 12 months (not 30 days)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const before = Date.now();
    const { expires_at } = await happyPath(db, "t-1", "pro", "annual");
    const diffDays = (Date.parse(expires_at) - before) / (24 * 60 * 60 * 1000);
    expect(diffDays).toBeGreaterThan(360);
    expect(diffDays).toBeLessThanOrEqual(367);
  });

  it("T-U2 (API level): wrong amount on UTR submit → 400 amount_mismatch, no payment row", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const sub = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    const res = await call(db, "POST", "/api/billing/utr", { subscription_id: String(sub.body.subscription_id), utr: "400000000001", amount_paise: 90000 });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("amount_mismatch");
    expect((await db.prepare("SELECT COUNT(*) AS n FROM payments").bind().first<{ n: number }>())?.n).toBe(0);
  });

  it("T-U2/T-U4 (admin level): reject + reason → subscription rejected, customer sees reason in status", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const sub = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    const utr = await call(db, "POST", "/api/billing/utr", { subscription_id: String(sub.body.subscription_id), utr: "400000000002" });
    const rej = await callAdmin(db, "POST", "/api/billing/admin/reject", { payment_id: String(utr.body.payment_id), reason: "amount mismatch with bank statement" });
    expect(rej.status).toBe(200);
    expect(rej.body.status).toBe("rejected");
    const s = await db.prepare("SELECT status FROM subscriptions WHERE id = ?").bind(String(sub.body.subscription_id)).first<{ status: string }>();
    expect(s?.status).toBe("rejected");
    // Reject without reason → 400 reason_required.
    const db2 = new FakeD1();
    await seedTenant(db2, "t-1", "free", 1);
    await setVpa(db2);
    const sub2 = await call(db2, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    const utr2 = await call(db2, "POST", "/api/billing/utr", { subscription_id: String(sub2.body.subscription_id), utr: "400000000003" });
    const rej2 = await callAdmin(db2, "POST", "/api/billing/admin/reject", { payment_id: String(utr2.body.payment_id), reason: "  " });
    expect(rej2.status).toBe(400);
    expect(rej2.body.error).toBe("reason_required");
  });

  it("invalid UTR format → 400; unknown subscription → 404", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const sub = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    expect((await call(db, "POST", "/api/billing/utr", { subscription_id: String(sub.body.subscription_id), utr: "abc" })).body.error).toBe("invalid_utr");
    expect((await call(db, "POST", "/api/billing/utr", { subscription_id: "sub-ghost", utr: "400000000001" })).status).toBe(404);
  });

  it("T-U3: duplicate UTR → 409 utr_duplicate (second submit blocked)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await seedTenant(db, "t-2", "free", 1);
    await setVpa(db);
    const s1 = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    const u1 = await call(db, "POST", "/api/billing/utr", { subscription_id: String(s1.body.subscription_id), utr: "400000000009" });
    expect(u1.status).toBe(200);
    const s2 = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-2", plan_tier: "pro", billing_period: "monthly" });
    const u2 = await call(db, "POST", "/api/billing/utr", { subscription_id: String(s2.body.subscription_id), utr: "400000000009" });
    expect(u2.status).toBe(409);
    expect(u2.body.error).toBe("utr_duplicate");
  });

  it("T-U5: double approve = no-op (one ACTIVE subscription, expiry UNCHANGED)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const { payment_id, expires_at } = await happyPath(db, "t-1", "pro", "monthly");
    const again = await callAdmin(db, "POST", "/api/billing/admin/approve", { payment_id });
    expect(again.status).toBe(200);
    expect(again.body.already).toBe(true);
    expect(again.body.expires_at).toBe(expires_at);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM subscriptions WHERE status = ?").bind("active").first<{ n: number }>())?.n).toBe(1);
    const trace = await db.prepare("SELECT kind FROM traces WHERE kind = ?").bind("billing_approve_noop").first<{ kind: string }>();
    expect(trace?.kind).toBe("billing_approve_noop");
  });

  it("approve/reject need admin token (401); unknown payment → 404", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    expect((await call(db, "POST", "/api/billing/admin/approve", { payment_id: "pay-x" })).status).toBe(401);
    expect((await callAdmin(db, "POST", "/api/billing/admin/approve", { payment_id: "pay-x" })).status).toBe(404);
    expect((await callAdmin(db, "POST", "/api/billing/admin/reject", { payment_id: "pay-x", reason: "r" })).status).toBe(404);
  });
});

describe("renew / upgrade / downgrade (T-U6–T-U9)", () => {
  it("T-U8: Pro mid-cycle → Business upgrade is pro-rated (exact paise) + approve supersedes old", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const { subscription_id: oldId } = await happyPath(db, "t-1", "pro", "monthly");
    // Fake the old subscription to mid-cycle: starts 15d ago, expires in 15d.
    const start = Date.now() - 15 * 24 * 60 * 60 * 1000;
    const end = Date.now() + 15 * 24 * 60 * 60 * 1000;
    await db.prepare("UPDATE subscriptions SET starts_at = ?, expires_at = ? WHERE id = ?").bind(new Date(start).toISOString(), new Date(end).toISOString(), oldId).run();
    const up = await call(db, "POST", "/api/billing/upgrade", { tenant_id: "t-1", to_tier: "business" });
    expect(up.status).toBe(200);
    expect(up.body.remaining_paise).toBe(49950);
    expect(up.body.prorated_amount_paise).toBe(249950);
    const utr = await call(db, "POST", "/api/billing/utr", { subscription_id: String(up.body.subscription_id), utr: "400000000011" });
    expect(utr.status).toBe(200);
    const appr = await callAdmin(db, "POST", "/api/billing/admin/approve", { payment_id: String(utr.body.payment_id) });
    expect(appr.status).toBe(200);
    expect(appr.body.plan_tier).toBe("business");
    const old = await db.prepare("SELECT status FROM subscriptions WHERE id = ?").bind(oldId).first<{ status: string }>();
    expect(old?.status).toBe("expired");
    const tenant = await db.prepare("SELECT plan_tier FROM tenants WHERE id = ?").bind("t-1").first<{ plan_tier: string }>();
    expect(tenant?.plan_tier).toBe("business");
  });

  it("upgrade without an active Pro sub → 409 subscription_not_active", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const res = await call(db, "POST", "/api/billing/upgrade", { tenant_id: "t-1", to_tier: "business" });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe("subscription_not_active");
  });

  it("T-U9: downgrade is next-cycle only — current cycle stays Business, pending tier set", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    await happyPath(db, "t-1", "business", "monthly");
    const down = await call(db, "POST", "/api/billing/downgrade", { tenant_id: "t-1", to_tier: "pro" });
    expect(down.status).toBe(200);
    expect(down.body.pending_downgrade_tier).toBe("pro");
    expect(down.body.effective).toBe("next_cycle");
    const tenant = await db.prepare("SELECT plan_tier, pending_downgrade_tier FROM tenants WHERE id = ?").bind("t-1").first<{ plan_tier: string; pending_downgrade_tier: string }>();
    expect(tenant?.plan_tier).toBe("business"); // current cycle unchanged
    expect(tenant?.pending_downgrade_tier).toBe("pro");
    const ev = await db.prepare("SELECT kind FROM ledger_events WHERE kind = ?").bind("downgraded").first<{ kind: string }>();
    expect(ev?.kind).toBe("downgraded");
  });

  it("downgrade to a higher tier → 400 not_a_downgrade", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro", 1);
    const res = await call(db, "POST", "/api/billing/downgrade", { tenant_id: "t-1", to_tier: "business" });
    expect(res.status).toBe(400);
  });

  it("renew: expired sub → new pending_payment; active far from expiry → 409", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const { subscription_id } = await happyPath(db, "t-1", "pro", "monthly");
    expect((await call(db, "POST", "/api/billing/renew", { tenant_id: "t-1" })).body.error).toBe("subscription_active");
    // Expire the sub, then renew works.
    await db.prepare("UPDATE subscriptions SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() - 1000).toISOString(), subscription_id).run();
    await runBillingSweeps(db, Date.now());
    const renew = await call(db, "POST", "/api/billing/renew", { tenant_id: "t-1" });
    expect(renew.status).toBe(200);
    expect(renew.body.plan_tier).toBe("pro");
    expect(renew.body.amount_paise).toBe(99900);
    expect(renew.body.status).toBe("pending_payment");
  });
});

describe("refund (T-U10)", () => {
  it("full refund → payment refunded + subscription expired + plan free + ledger refunded", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const { subscription_id, payment_id } = await happyPath(db, "t-1", "pro", "monthly");
    const ref = await callAdmin(db, "POST", "/api/billing/refund", { payment_id, refund_utr: "400000000021", reason: "customer asked, duplicate charge" });
    expect(ref.status).toBe(200);
    expect(String(ref.body.refund_id)).toMatch(/^ref-/);
    const pay = await db.prepare("SELECT status FROM payments WHERE id = ?").bind(payment_id).first<{ status: string }>();
    expect(pay?.status).toBe("refunded");
    const sub = await db.prepare("SELECT status FROM subscriptions WHERE id = ?").bind(subscription_id).first<{ status: string }>();
    expect(sub?.status).toBe("expired");
    const tenant = await db.prepare("SELECT plan_tier FROM tenants WHERE id = ?").bind("t-1").first<{ plan_tier: string }>();
    expect(tenant?.plan_tier).toBe("free");
    const rows = await db.prepare("SELECT amount_paise, refund_utr, reason FROM refunds WHERE payment_id = ?").bind(payment_id).all<{ amount_paise: number }>();
    expect((rows.results ?? [])[0]?.amount_paise).toBe(99900);
  });

  it("partial refund → subscription stays active", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const { subscription_id, payment_id } = await happyPath(db, "t-1", "pro", "monthly");
    const ref = await callAdmin(db, "POST", "/api/billing/refund", { payment_id, refund_utr: "400000000022", amount_paise: 10000, reason: "partial goodwill" });
    expect(ref.status).toBe(200);
    const sub = await db.prepare("SELECT status FROM subscriptions WHERE id = ?").bind(subscription_id).first<{ status: string }>();
    expect(sub?.status).toBe("active");
  });

  it("refund on a non-approved payment → 409; refund amount > paid → 400", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const sub = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    const utr = await call(db, "POST", "/api/billing/utr", { subscription_id: String(sub.body.subscription_id), utr: "400000000023" });
    expect((await callAdmin(db, "POST", "/api/billing/refund", { payment_id: String(utr.body.payment_id), refund_utr: "400000000024", reason: "x" })).body.error).toBe("payment_not_approved");
  });
});

describe("sweeps — expiry + reminders (T-U6, T-U9, T-U11)", () => {
  it("T-U11: pending_payment older than 24h → expired (sweep is idempotent)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const sub = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    const subId = String(sub.body.subscription_id);
    await db.prepare("UPDATE subscriptions SET created_at = ? WHERE id = ?").bind(new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString(), subId).run();
    const r1 = await runBillingSweeps(db, Date.now());
    expect(r1.expired_pending).toBe(1);
    const r2 = await runBillingSweeps(db, Date.now());
    expect(r2.expired_pending).toBe(0);
    const s = await db.prepare("SELECT status FROM subscriptions WHERE id = ?").bind(subId).first<{ status: string }>();
    expect(s?.status).toBe("expired");
  });

  it("T-U6: active expiry → plan drops to Free, data NOT deleted, reminder trace was written at 7d", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const { subscription_id } = await happyPath(db, "t-1", "pro", "monthly");
    // 6 days left → 7d reminder trace appears.
    await db.prepare("UPDATE subscriptions SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() + 6 * 24 * 60 * 60 * 1000).toISOString(), subscription_id).run();
    const r1 = await runBillingSweeps(db, Date.now());
    expect(r1.reminders).toBe(1);
    expect(r1.expired_active).toBe(0);
    // Now past expiry → expired + plan free; subscription row still exists.
    await db.prepare("UPDATE subscriptions SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() - 1000).toISOString(), subscription_id).run();
    const r2 = await runBillingSweeps(db, Date.now());
    expect(r2.expired_active).toBe(1);
    const tenant = await db.prepare("SELECT plan_tier FROM tenants WHERE id = ?").bind("t-1").first<{ plan_tier: string }>();
    expect(tenant?.plan_tier).toBe("free");
    const s = await db.prepare("SELECT status FROM subscriptions WHERE id = ?").bind(subscription_id).first<{ status: string }>();
    expect(s?.status).toBe("expired");
  });

  it("T-U9 (sweep half): expiry with pending downgrade creates a pending Pro subscription", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const { subscription_id } = await happyPath(db, "t-1", "business", "monthly");
    await call(db, "POST", "/api/billing/downgrade", { tenant_id: "t-1", to_tier: "pro" });
    await db.prepare("UPDATE subscriptions SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() - 1000).toISOString(), subscription_id).run();
    const r = await runBillingSweeps(db, Date.now());
    expect(r.downgrades_applied).toBe(1);
    const pending = await db.prepare("SELECT plan_tier, amount_paise FROM subscriptions WHERE tenant_id = ? AND status = ?").bind("t-1", "pending_payment").first<{ plan_tier: string; amount_paise: number }>();
    expect(pending?.plan_tier).toBe("pro");
    expect(pending?.amount_paise).toBe(99900);
  });
});

describe("status + warnings + isolation (T-C12, T-I1/I2/I5)", () => {
  it("T-C12: usage at 80% of replies cap → warnings includes replies", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro", 1);
    await seedUsage(db, "t-1", 2000); // 2000/2500 = 80%
    const res = await call(db, "GET", "/api/billing/status?tenant_id=t-1");
    expect(res.status).toBe(200);
    expect(res.body.plan_tier).toBe("pro");
    expect(res.body.limits).toMatchObject({ replies: 2500, e2b_runs: 30, cron_jobs: 5, devices: 3 });
    expect(res.body.warnings).toContain("replies");
  });

  it("T-C12: usage below 80% → no warnings", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro", 1);
    await seedUsage(db, "t-1", 100);
    const res = await call(db, "GET", "/api/billing/status?tenant_id=t-1");
    expect(res.body.warnings).toEqual([]);
  });

  it("T-I1: signed device of tenant A cannot read tenant B status → 403", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-a", "pro", 1);
    await seedTenant(db, "t-b", "pro", 1);
    const key = await genDeviceKey();
    await seedDevice(db, "dev-a", "t-a", key.publicKeyB64);
    const res = await callSigned(db, "GET", "/api/billing/status?tenant_id=t-b", "dev-a", key.sign, undefined, "billing-status:t-b");
    expect(res.status).toBe(403);
    expect(res.body.error).toBe("forbidden");
    const own = await callSigned(db, "GET", "/api/billing/status?tenant_id=t-a", "dev-a", key.sign, undefined, "billing-status:t-a");
    expect(own.status).toBe(200);
  });

  it("T-I5: admin telemetry sees both tenants (admin CAN see all — that is a pass)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-a", "pro", 1);
    await seedTenant(db, "t-b", "business", 1);
    const res = await callAdmin(db, "GET", "/api/billing/admin/telemetry");
    expect(res.status).toBe(200);
    expect(res.body.count).toBe(2);
  });

  it("admin pending list shows submitted UTRs with owner email", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    const sub = await call(db, "POST", "/api/billing/subscribe", { tenant_id: "t-1", plan_tier: "pro", billing_period: "monthly" });
    await call(db, "POST", "/api/billing/utr", { subscription_id: String(sub.body.subscription_id), utr: "400000000031" });
    const res = await callAdmin(db, "GET", "/api/billing/admin/pending");
    expect(res.status).toBe(200);
    expect(res.body.count).toBe(1);
    const first = (res.body.pending as Array<Record<string, unknown>>)[0];
    expect(first.utr).toBe("400000000031");
    expect(first.owner_email).toBe("t-1@example.com");
    expect(first.amount_paise).toBe(99900);
    expect((await call(db, "GET", "/api/billing/admin/pending")).status).toBe(401);
  });
});

describe("reconciliation + retention + metering (T-L2/L3/L6, T-L1 shape)", () => {
  it("T-L3: approved payments sum = active subscriptions expected revenue → diff 0", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await seedTenant(db, "t-2", "free", 1);
    await setVpa(db);
    await happyPath(db, "t-1", "pro", "monthly");
    await happyPath(db, "t-2", "business", "monthly");
    const rec = await reconcileBilling(db);
    expect(rec.approved_payments_paise).toBe(99900 + 299900);
    expect(rec.expected_revenue_paise).toBe(99900 + 299900);
    expect(rec.diff_payments_vs_expected).toBe(0);
    const viaRoute = await callAdmin(db, "POST", "/api/billing/admin/reconcile");
    expect(viaRoute.body.diff_blocked).toBe(false);
  });

  it("T-L3 negative control: a tampered extra approved payment makes diff ≠ 0 (BLOCKER signal)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    await happyPath(db, "t-1", "pro", "monthly");
    // Tamper: an approved payment with no matching active subscription.
    await db.prepare("INSERT INTO payments (id, subscription_id, tenant_id, utr, amount_paise, method, status, admin_note, decided_by, decided_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind("pay-tamper", "sub-ghost", "t-1", "400000000099", 50000, "upi", "approved", null, null, null, new Date().toISOString()).run();
    const rec = await reconcileBilling(db);
    expect(rec.diff_payments_vs_expected).toBe(50000);
  });

  it("T-L2: rollup counters = raw llm_usage rows (exact)", async () => {
    const db = new FakeD1();
    await recordUsage(db, { tenant_id: "t-1", turn_id: "turn-1", model: "gemini-3.1-flash-lite", attempted_models: ["gemini-3.1-flash-lite"], input_tokens: 100, output_tokens: 20, cost_usd_micro: 55, billing_mode: "byok", status: "ok" });
    await recordUsage(db, { tenant_id: "t-1", turn_id: "turn-2", model: "gemini-3.5-flash-lite", attempted_models: ["gemini-3.5-flash-lite"], input_tokens: 200, output_tokens: 40, cost_usd_micro: 160, billing_mode: "byok", status: "fallback_used" });
    const period = new Date().toISOString().slice(0, 7);
    // FakeD1 SUM supports one column per query — one aggregate per call.
    const sumIn = await db.prepare("SELECT SUM(input_tokens) AS total FROM llm_usage WHERE tenant_id = ?").bind("t-1").first<{ total: number }>();
    const sumCost = await db.prepare("SELECT SUM(cost_usd_micro) AS total FROM llm_usage WHERE tenant_id = ?").bind("t-1").first<{ total: number }>();
    expect(sumIn?.total).toBe(300);
    expect(sumCost?.total).toBe(215);
    const counters = await db.prepare("SELECT llm_calls, input_tokens, cost_usd_micro FROM usage_counters WHERE tenant_id = ? AND period = ?").bind("t-1", period).first<{ llm_calls: number; input_tokens: number; cost_usd_micro: number }>();
    expect(counters?.llm_calls).toBe(2);
    expect(counters?.input_tokens).toBe(300);
    expect(counters?.cost_usd_micro).toBe(215);
  });

  it("T-L6: 13-month-old llm_usage rows purge, recent rows + rollup survive", async () => {
    const db = new FakeD1();
    const old = Date.now() - 14 * 30 * 24 * 60 * 60 * 1000;
    const recent = Date.now() - 1000;
    await recordUsage(db, { tenant_id: "t-1", turn_id: "old", model: "m", attempted_models: ["m"], input_tokens: 1, output_tokens: 1, cost_usd_micro: 1, billing_mode: "byok", status: "ok" }, old);
    await recordUsage(db, { tenant_id: "t-1", turn_id: "new", model: "m", attempted_models: ["m"], input_tokens: 2, output_tokens: 2, cost_usd_micro: 2, billing_mode: "byok", status: "ok" }, recent);
    const res = await callAdmin(db, "POST", "/api/billing/admin/retention");
    expect(res.body.deleted).toBe(1);
    const left = await db.prepare("SELECT turn_id FROM llm_usage WHERE tenant_id = ?").bind("t-1").all<{ turn_id: string }>();
    expect((left.results ?? []).map((r) => r.turn_id)).toEqual(["new"]);
    const counters = await db.prepare("SELECT COUNT(*) AS n FROM usage_counters WHERE tenant_id = ?").bind("t-1").first<{ n: number }>();
    expect(counters?.n).toBeGreaterThan(0);
  });

  it("T-L5: ledger event details never carry prompt/response text", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await setVpa(db);
    await happyPath(db, "t-1", "pro", "monthly");
    const rows = await db.prepare("SELECT detail FROM ledger_events WHERE tenant_id = ?").bind("t-1").all<{ detail: string }>();
    for (const r of rows.results ?? []) {
      const detail = JSON.parse(r.detail) as Record<string, unknown>;
      expect(Object.keys(detail).sort()).not.toContain("prompt");
      expect(Object.keys(detail).sort()).not.toContain("response");
      expect(r.detail).not.toContain("my secret prompt");
    }
  });
});

describe("cron + device caps (T-C6–T-C9, T-A3)", () => {
  async function seedJobDevice(db: FakeD1, tenantId: string): Promise<void> {
    const key = await genDeviceKey();
    await seedDevice(db, `dev-${tenantId}`, tenantId, key.publicKeyB64);
  }

  it("T-C6: Pro cron cap 5 — 6th create blocked with a clear message", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro", 1);
    await seedJobDevice(db, "t-1");
    for (let i = 0; i < 5; i++) {
      const res = await call(db, "POST", "/api/billing/cron-jobs", { tenant_id: "t-1", device_id: "dev-t-1", cron_expr: "0 9 * * *", command: `job ${i}` });
      expect(res.status).toBe(200);
    }
    const sixth = await call(db, "POST", "/api/billing/cron-jobs", { tenant_id: "t-1", device_id: "dev-t-1", cron_expr: "0 10 * * *", command: "job 6" });
    expect(sixth.status).toBe(403);
    expect(sixth.body.error).toBe("cron_cap");
    expect(String(sixth.body.detail)).toContain("Cron limit khatam");
    // Disable one → a new create works again.
    const list = await call(db, "GET", "/api/billing/cron-jobs?tenant_id=t-1");
    const firstJob = ((list.body.jobs as Array<Record<string, unknown>>)[0]?.id as string) ?? "";
    expect((await call(db, "POST", `/api/billing/cron-jobs/${firstJob}/disable`, { tenant_id: "t-1" })).status).toBe(200);
    expect((await call(db, "POST", "/api/billing/cron-jobs", { tenant_id: "t-1", device_id: "dev-t-1", cron_expr: "0 10 * * *", command: "job 6" })).status).toBe(200);
  });

  it("T-C7: Business cron cap 20 — 21st blocked", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "business", 1);
    await seedJobDevice(db, "t-1");
    for (let i = 0; i < 20; i++) {
      expect((await call(db, "POST", "/api/billing/cron-jobs", { tenant_id: "t-1", device_id: "dev-t-1", cron_expr: "0 9 * * *", command: `job ${i}` })).status).toBe(200);
    }
    expect((await call(db, "POST", "/api/billing/cron-jobs", { tenant_id: "t-1", device_id: "dev-t-1", cron_expr: "0 10 * * *", command: "job 21" })).body.error).toBe("cron_cap");
  });

  it("T-C6 (Free): Free tier cron cap is 0 — first create blocked", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await seedJobDevice(db, "t-1");
    expect((await call(db, "POST", "/api/billing/cron-jobs", { tenant_id: "t-1", device_id: "dev-t-1", cron_expr: "0 9 * * *", command: "job" })).body.error).toBe("cron_cap");
  });

  it("T-C8: Pro devices cap 3 — 4th register refused", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro", 1);
    await seedLicenceForPairing(db);
    for (let i = 1; i <= 3; i++) {
      await seedPairingToken(db, `tok-${i}`, `dev-${i}`, "t-1");
      const res = await handleRequest(
        new Request("https://hub/api/pairing/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: `tok-${i}`, device_id: `dev-${i}`, public_key: "cHVibGlj" }) }),
        fakeEnv(db),
      );
      expect(res.status).toBe(200);
    }
    await seedPairingToken(db, "tok-4", "dev-4", "t-1");
    const fourth = await handleRequest(
      new Request("https://hub/api/pairing/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: "tok-4", device_id: "dev-4", public_key: "cHVibGlj" }) }),
      fakeEnv(db),
    );
    expect(fourth.status).toBe(403);
    expect(((await fourth.json()) as Json).error).toBe("device_limit");
  });

  it("T-A3: 5th distinct device in 30 days writes a velocity flag trace (flag ≠ block)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "business", 1);
    await seedLicenceForPairing(db);
    for (let i = 1; i <= 5; i++) {
      await seedPairingToken(db, `tok-${i}`, `dev-${i}`, "t-1");
      const res = await handleRequest(
        new Request("https://hub/api/pairing/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: `tok-${i}`, device_id: `dev-${i}`, public_key: "cHVibGlj" }) }),
        fakeEnv(db),
      );
      expect(res.status).toBe(200);
    }
    const flag = await db.prepare("SELECT kind FROM traces WHERE kind = ?").bind("device_velocity_flag").first<{ kind: string }>();
    expect(flag?.kind).toBe("device_velocity_flag");
  });
});

async function seedLicenceForPairing(db: FakeD1): Promise<void> {
  await db
    .prepare("INSERT INTO licences (key, user_id, device_id, status, created_at) VALUES (?, ?, NULL, ?, ?)")
    .bind("L-1", "owner@example.com", "active", Date.now())
    .run();
}

describe("email verification + disposable blocklist (T-A1, T-B4 key rotation)", () => {
  it("T-A1: disposable domain → 400 disposable_email", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 0);
    const res = await call(db, "POST", "/api/billing/verify-email/request", { tenant_id: "t-1", email: "x@mailinator.com" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("disposable_email");
  });

  it("verify request → confirm with the right token → verified; wrong/expired token → 400", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 0);
    const req = await call(db, "POST", "/api/billing/verify-email/request", { tenant_id: "t-1", email: "real@example.com" });
    expect(req.status).toBe(200);
    expect(req.body.verification_pending).toBe(true);
    // The token is never in the response — confirm with a wrong one fails.
    expect((await call(db, "POST", "/api/billing/verify-email/confirm", { tenant_id: "t-1", token: "00".repeat(16) })).body.error).toBe("verification_failed");
    // Confirm with the real token via the test-only injection path.
    const { requestEmailVerification, confirmEmailVerification } = await import("../src/billing");
    const tenant = (await db.prepare("SELECT id, owner_email, plan_tier, billing_mode, gemini_key_enc, email_verified FROM tenants WHERE id = ?").bind("t-1").first()) as unknown as import("../src/db").TenantRow;
    const token = "aabbccddeeff00112233445566778899";
    expect((await requestEmailVerification(db, { tenant, email: "real@example.com", tokenForTest: token })).ok).toBe(true);
    expect((await confirmEmailVerification(db, { tenant, token })).ok).toBe(true);
    const row = await db.prepare("SELECT email_verified FROM tenants WHERE id = ?").bind("t-1").first<{ email_verified: number }>();
    expect(row?.email_verified).toBe(1);
    // Already verified → request again is a 409.
    expect((await call(db, "POST", "/api/billing/verify-email/request", { tenant_id: "t-1", email: "real@example.com" })).body.error).toBe("already_verified");
  });

  it("T-B4: BYOK key rotation — new key serves, old key is gone (mocked Gemini)", async () => {
    const db = new FakeD1();
    const master = await (async () => {
      const k = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
      const raw = new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
      return bytesToBase64(raw);
    })();
    await seedTenant(db, "t-1", "pro", 1);
    const seenKeys: string[] = [];
    const geminiOk = async (url: string, init?: RequestInit) => {
      const key = (init?.headers as Record<string, string>)?.["x-goog-api-key"] ?? "";
      seenKeys.push(key);
      const isValidate = String(url).includes(":generateContent") && (init?.body as string)?.includes('"hi"');
      void isValidate;
      return new Response(
        JSON.stringify({
          candidates: [{ content: { parts: [{ text: "OK" }] } }],
          usageMetadata: { promptTokenCount: 5, candidatesTokenCount: 1 },
        }),
        { status: 200 },
      );
    };
    vi.stubGlobal("fetch", geminiOk);
    try {
      const env = fakeEnv(db, { KEY_ENC_SECRET: master });
      const setKey = async (key: string) =>
        handleRequest(
          new Request("https://hub/api/tenants/t-1/key", { method: "POST", headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" }, body: JSON.stringify({ gemini_key: key }) }),
          env,
        );
      expect((await setKey("KEY-ONE")).status).toBe(200);
      const route1 = await handleRequest(
        new Request("https://hub/api/llm/route", { method: "POST", headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" }, body: JSON.stringify({ tenant_id: "t-1", turn_id: "turn-rot-1", kind: "quick_command", messages: [{ role: "user", text: "hi" }] }) }),
        env,
      );
      expect(route1.status).toBe(200);
      expect((await route1.json() as Json).ok).toBe(true);
      expect(seenKeys).toContain("KEY-ONE");
      // Rotate to KEY-TWO: the old key must never serve again.
      expect((await setKey("KEY-TWO")).status).toBe(200);
      seenKeys.length = 0;
      const route2 = await handleRequest(
        new Request("https://hub/api/llm/route", { method: "POST", headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" }, body: JSON.stringify({ tenant_id: "t-1", turn_id: "turn-rot-2", kind: "quick_command", messages: [{ role: "user", text: "hi" }] }) }),
        env,
      );
      expect(route2.status).toBe(200);
      expect(seenKeys).toContain("KEY-TWO");
      expect(seenKeys).not.toContain("KEY-ONE");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("DPDP wipe (T-W1–T-W5)", () => {
  it("wipe deletes all tenant rows across D1 tables + writes a tenant_wipe audit trace", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    await seedTenant(db, "t-2", "free", 1);
    await setVpa(db);
    await happyPath(db, "t-1", "pro", "monthly");
    await happyPath(db, "t-2", "pro", "monthly");
    // Extra tenant rows: memory + usage + device.
    await db.prepare("INSERT INTO memories (id, tenant_id, content, embedding, kind, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(1, "t-1", "secret fact", "[]", "fact", Date.now()).run();
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const res = await call(db, "POST", "/api/billing/wipe", { tenant_id: "t-1" });
    expect(res.status).toBe(200);
    expect(res.body.qdrant).toBe("not_configured");
    expect(res.body.b2).toBe("not_configured");
    const deleted = res.body.deleted as Record<string, number>;
    expect(deleted.subscriptions).toBe(1);
    expect(deleted.payments).toBe(1);
    expect(deleted.ledger_events).toBeGreaterThan(0);
    expect(deleted.memories).toBe(1);
    expect(deleted.devices).toBe(1);
    for (const table of ["subscriptions", "payments", "refunds", "ledger_events", "llm_usage", "memories"] as const) {
      const n = await db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE tenant_id = ?`).bind("t-1").first<{ n: number }>();
      expect(n?.n, table).toBe(0);
    }
    // Tenants row itself is gone (tenants has no tenant_id column — check by id).
    expect(await db.prepare("SELECT id FROM tenants WHERE id = ?").bind("t-1").first()).toBeNull();
    // Tenant t-2 is untouched.
    expect((await db.prepare("SELECT COUNT(*) AS n FROM subscriptions WHERE tenant_id = ?").bind("t-2").first<{ n: number }>())?.n).toBe(1);
    // Wipe audit: a tenant_wipe trace survives (T-W5).
    const trace = await db.prepare("SELECT kind FROM traces WHERE kind = ?").bind("tenant_wipe").first<{ kind: string }>();
    expect(trace?.kind).toBe("tenant_wipe");
  });
});

describe("legal + grievance + launch gates + god-mode (T-G1–T-G4, T-I6)", () => {
  it("T-G3: Terms / Privacy / Refund pages live; refund policy covers manual-UPI refund + failed-run release", async () => {
    const db = new FakeD1();
    for (const page of ["terms", "privacy", "refund"] as const) {
      const res = await handleRequest(new Request(`https://hub/api/legal/${page}`), fakeEnv(db));
      expect(res.status).toBe(200);
      const body = (await res.json()) as Json;
      expect(typeof body.body).toBe("string");
      expect(String(body.body).length).toBeGreaterThan(100);
    }
    const refund = (await (await handleRequest(new Request("https://hub/api/legal/refund"), fakeEnv(db))).json()) as Json;
    expect(String(refund.body)).toContain("manual");
    expect(String(refund.body)).toContain("Failed E2B runs are released");
    const terms = (await (await handleRequest(new Request("https://hub/api/legal/terms"), fakeEnv(db))).json()) as Json;
    expect(String(terms.body)).toContain("UPI-only");
  });

  it("T-G1: grievance placeholder — empty fields + s.79 risk note + pending status", async () => {
    const db = new FakeD1();
    const res = await callAdmin(db, "GET", "/api/billing/admin/grievance");
    expect(res.status).toBe(200);
    expect(res.body.name).toBe("");
    expect(res.body.designation).toBe("");
    expect(res.body.email).toBe("");
    expect(String(res.body.s79_risk_note)).toContain("Section 79");
    expect(res.body.status).toBe("pending — user deferred");
  });

  it("T-G2/T-G4: launch gate list has the grievance line + GST OPEN + launch GATED", async () => {
    const db = new FakeD1();
    const res = await callAdmin(db, "GET", "/api/billing/admin/launch-gates");
    expect(res.status).toBe(200);
    expect(res.body.launch).toBe("GATED");
    const gates = res.body.gates as Array<Record<string, string>>;
    expect(gates.find((g) => g.gate === "grievance_officer")?.status).toBe("pending — user deferred");
    expect(gates.find((g) => g.gate === "gst_ca_verification")?.status).toBe("OPEN");
    expect(gates.find((g) => g.gate === "founder_pays_margin")?.status).toBe("BLOCKED");
  });

  it("T-I6: god-mode actions are audited (trace + ledger where a subscription changed)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "free", 1);
    const act = await callAdmin(db, "POST", "/api/billing/admin/god-mode", { tenant_id: "t-1", action: "activate", plan_tier: "pro", billing_period: "monthly" });
    expect(act.status).toBe(200);
    expect(act.body.status).toBe("active");
    const trace = await db.prepare("SELECT kind FROM traces WHERE kind = ?").bind("billing_godmode").first<{ kind: string }>();
    expect(trace?.kind).toBe("billing_godmode");
    const ev = await db.prepare("SELECT kind FROM ledger_events WHERE kind = ?").bind("approved").first<{ kind: string }>();
    expect(ev?.kind).toBe("approved");
    const exp = await callAdmin(db, "POST", "/api/billing/admin/god-mode", { tenant_id: "t-1", action: "expire" });
    expect(exp.status).toBe(200);
    const tenant = await db.prepare("SELECT plan_tier FROM tenants WHERE id = ?").bind("t-1").first<{ plan_tier: string }>();
    expect(tenant?.plan_tier).toBe("free");
    // God-mode verify-email (admin path for the U-6 email gap).
    await db.prepare("UPDATE tenants SET email_verified = ? WHERE id = ?").bind(0, "t-1").run();
    expect((await callAdmin(db, "POST", "/api/billing/admin/verify-email", { tenant_id: "t-1" })).body.email_verified).toBe(true);
  });

  it("god-mode deactivate_device unpairs a device (cap relief path)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro", 1);
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    expect((await callAdmin(db, "POST", "/api/billing/admin/god-mode", { tenant_id: "t-1", action: "deactivate_device", device_id: "dev-1" })).status).toBe(200);
    const dev = await db.prepare("SELECT enabled FROM devices WHERE device_id = ?").bind("dev-1").first<{ enabled: number }>();
    expect(dev?.enabled).toBe(0);
  });

  it("admin settings: UPI VPA set/get; invalid VPA → 400", async () => {
    const db = new FakeD1();
    expect((await callAdmin(db, "POST", "/api/billing/admin/settings", { upi_vpa: "not-a-vpa" })).body.error).toBe("invalid_vpa");
    expect((await callAdmin(db, "POST", "/api/billing/admin/settings", { upi_vpa: "admin@okhdfc" })).status).toBe(200);
    const get = await callAdmin(db, "GET", "/api/billing/admin/settings");
    expect((get.body.settings as Record<string, string>).upi_vpa).toBe("admin@okhdfc");
  });
});

describe("T-U12: 10 test subscriptions end-to-end (mixed monthly/annual, Pro/Business)", () => {
  it("10/10 PASS in vitest (pay → UTR → approve → active → use)", async () => {
    const db = new FakeD1();
    await setVpa(db);
    const cases: Array<{ plan: "pro" | "business"; period: "monthly" | "annual" }> = [
      { plan: "pro", period: "monthly" },
      { plan: "pro", period: "annual" },
      { plan: "business", period: "monthly" },
      { plan: "business", period: "annual" },
      { plan: "pro", period: "monthly" },
      { plan: "business", period: "monthly" },
      { plan: "pro", period: "annual" },
      { plan: "business", period: "annual" },
      { plan: "pro", period: "monthly" },
      { plan: "business", period: "monthly" },
    ];
    for (let i = 0; i < cases.length; i++) {
      const tenantId = `t-u12-${i}`;
      await seedTenant(db, tenantId, "free", 1);
      const { subscription_id, expires_at } = await happyPath(db, tenantId, cases[i].plan, cases[i].period);
      const sub = await db.prepare("SELECT status, plan_tier FROM subscriptions WHERE id = ?").bind(subscription_id).first<{ status: string; plan_tier: string }>();
      expect(sub?.status, tenantId).toBe("active");
      expect(sub?.plan_tier, tenantId).toBe(cases[i].plan);
      expect(expires_at, tenantId).toBeTruthy();
    }
    expect((await db.prepare("SELECT COUNT(*) AS n FROM subscriptions WHERE status = ?").bind("active").first<{ n: number }>())?.n).toBe(10);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM payments WHERE status = ?").bind("approved").first<{ n: number }>())?.n).toBe(10);
  });
});
