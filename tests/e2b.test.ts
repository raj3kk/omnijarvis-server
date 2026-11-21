/**
 * E2B tests (Phase 4) — E-T1…: threshold gating, hold/settle/release/
 * kill, caps, not-configured honesty, Hobby pause, 15-min auto-kill.
 *
 * Test-plan mapping: T-E1 (15-min kill), T-E2 (stuck kill), T-E3
 * (failed run refund), T-E4 (Hobby runway tracking), T-E5 (threshold
 * gate), T-E6 (Hobby exhausted → pause), T-M4 (15-min auto-kill),
 * T-C4/T-C5 (E2B runs cap). No E2B account exists (U-4) — the live
 * path is the honest 503, never a faked run.
 */
import { describe, expect, it, beforeEach } from "vitest";
import { FakeD1 } from "./fake-d1";
import { handleRequest, type Env } from "../src/hub";
import { resetRateLimitFallback } from "../src/ratelimit";
import {
  aggregateMarginPaise,
  completeE2BRun,
  e2bThresholdStatus,
  getE2BRun,
  killE2BRun,
  listStaleHeldRuns,
  requestE2BRun,
  totalE2BRunsUsed,
  E2B_HOBBY_RUNWAY_RUNS,
  E2B_MAX_RUN_MS,
  E2B_THRESHOLD_PAISE,
} from "../src/e2b";
import { runBillingSweeps } from "../src/billing";
import { getMonthUsage, currentPeriod } from "../src/metering";

const NOW = Date.UTC(2026, 11, 22, 12, 0, 0);

// Rate-limit fallback reset (see billing.test.ts — same reason).
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

async function seedTenant(db: FakeD1, id: string, plan = "pro"): Promise<void> {
  await db
    .prepare("INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, email_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id, `${id}@example.com`, plan, "byok", null, 0, 1, NOW)
    .run();
}

async function seedE2BUsage(db: FakeD1, tenantId: string, runs: number): Promise<void> {
  await db
    .prepare("INSERT INTO usage_counters (tenant_id, period, replies, e2b_runs, llm_calls, input_tokens, output_tokens, cost_usd_micro) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(tenantId, currentPeriod(NOW), 0, runs, 0, 0, 0, 0)
    .run();
}

describe("E2B threshold (T-E5, D4)", () => {
  it("below ₹13,950 aggregate margin → Pro floor closed (threshold_not_met)", () => {
    const s = e2bThresholdStatus({ aggregateMarginPaise: 100000, hobbyRunsUsed: 0, cardOnFile: true, hobbyExhausted: false });
    expect(s.proFloorOpen).toBe(false);
    expect(s.reason).toBe("threshold_not_met");
    expect(s.thresholdPaise).toBe(E2B_THRESHOLD_PAISE);
    expect(E2B_THRESHOLD_PAISE).toBe(1395000);
  });

  it("past threshold but no card → closed (card_required); card on file → open", () => {
    const noCard = e2bThresholdStatus({ aggregateMarginPaise: 1400000, hobbyRunsUsed: 0, cardOnFile: false, hobbyExhausted: false });
    expect(noCard.proFloorOpen).toBe(false);
    expect(noCard.reason).toBe("card_required");
    const withCard = e2bThresholdStatus({ aggregateMarginPaise: 1400000, hobbyRunsUsed: 0, cardOnFile: true, hobbyExhausted: false });
    expect(withCard.proFloorOpen).toBe(true);
    expect(withCard.reason).toBe("pro_floor_open");
  });

  it("T-E4: Hobby runway = 3,600 runs; remaining = 3600 − used", () => {
    expect(E2B_HOBBY_RUNWAY_RUNS).toBe(3600);
    const s = e2bThresholdStatus({ aggregateMarginPaise: 0, hobbyRunsUsed: 100, cardOnFile: false, hobbyExhausted: false });
    expect(s.hobbyRunsRemaining).toBe(3500);
  });

  it("aggregate margin = active revenue − founder-pays LLM cost (BYOK excluded)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro");
    // Active Pro subscription: ₹999 = 99,900 paise revenue.
    await db.prepare("INSERT INTO subscriptions (id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind("sub-1", "t-1", "pro", "monthly", 99900, "active", new Date(NOW).toISOString(), new Date(NOW + 30 * 86400000).toISOString(), new Date(NOW).toISOString()).run();
    // Founder-pays LLM cost $1.00 = 1,000,000 micro → 9,300 paise.
    await db.prepare("INSERT INTO llm_usage (tenant_id, turn_id, model, attempted_models, input_tokens, output_tokens, cost_usd_micro, billing_mode, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind("t-1", "turn-1", "gemini-3.1-flash-lite", "[]", 5000, 500, 1000000, "founder_pays", "ok", NOW).run();
    // BYOK cost $10.00 must NOT count (founder pays ₹0 for BYOK).
    await db.prepare("INSERT INTO llm_usage (tenant_id, turn_id, model, attempted_models, input_tokens, output_tokens, cost_usd_micro, billing_mode, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind("t-1", "turn-2", "gemini-3.5-flash-lite", "[]", 5000, 500, 10000000, "byok", "ok", NOW).run();
    expect(await aggregateMarginPaise(db)).toBe(99900 - 9300);
    expect(await totalE2BRunsUsed(db)).toBe(0);
  });
});

describe("E2B run lifecycle (T-E1–T-E3, T-M4, T-C4/C5)", () => {
  it("T-C4: Pro at 29/30 runs → one hold OK (30), next refused with device fallback", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro");
    await seedE2BUsage(db, "t-1", 29);
    const first = await requestE2BRun(db, { tenant_id: "t-1", plan_tier: "pro", e2bConfigured: true, hobbyExhausted: false, nowMs: NOW });
    expect(first.ok).toBe(true);
    const usage = await getMonthUsage(db, "t-1", currentPeriod(NOW));
    expect(usage.e2b_runs).toBe(30);
    const second = await requestE2BRun(db, { tenant_id: "t-1", plan_tier: "pro", e2bConfigured: true, hobbyExhausted: false, nowMs: NOW });
    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(second.error).toBe("e2b_runs_cap");
      expect(second.device_fallback).toBe(true);
    }
  });

  it("unknown tenant → tenant_not_found (no hold, no quota consumed)", async () => {
    const db = new FakeD1();
    const res = await requestE2BRun(db, { tenant_id: "t-ghost", plan_tier: "pro", e2bConfigured: true, hobbyExhausted: false });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("tenant_not_found");
  });

  it("U-4: no E2B account → 503 e2b_not_configured, NO hold row, NO quota consumed", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro");
    const res = await requestE2BRun(db, { tenant_id: "t-1", plan_tier: "pro", e2bConfigured: false, hobbyExhausted: false });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe("e2b_not_configured");
      expect(res.device_fallback).toBe(true);
    }
    expect((await db.prepare("SELECT COUNT(*) AS n FROM e2b_runs").bind().first<{ n: number }>())?.n).toBe(0);
    expect((await getMonthUsage(db, "t-1", currentPeriod(NOW))).e2b_runs).toBe(0);
    // Same honest path through the HTTP route.
    const http = await handleRequest(
      new Request("https://hub/api/e2b/run", { method: "POST", headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" }, body: JSON.stringify({ tenant_id: "t-1" }) }),
      fakeEnv(db),
    );
    expect(http.status).toBe(503);
    expect(((await http.json()) as Record<string, unknown>).error).toBe("e2b_not_configured");
  });

  it("T-E6: hobby exhausted → e2b_paused + device fallback (pause only makes E2B MORE restrictive)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro");
    const res = await requestE2BRun(db, { tenant_id: "t-1", plan_tier: "pro", e2bConfigured: true, hobbyExhausted: true, nowMs: NOW });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe("e2b_paused");
      expect(res.device_fallback).toBe(true);
    }
  });

  it("T-E3: failed run releases the hold (counter back down — customer never charged)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro");
    const held = await requestE2BRun(db, { tenant_id: "t-1", plan_tier: "pro", e2bConfigured: true, hobbyExhausted: false, nowMs: NOW });
    expect(held.ok).toBe(true);
    if (!held.ok) throw new Error("hold failed");
    expect((await getMonthUsage(db, "t-1", currentPeriod(NOW))).e2b_runs).toBe(1);
    const run = await getE2BRun(db, held.run_id);
    expect(run?.status).toBe("held");
    const done = await completeE2BRun(db, run!, false);
    expect(done.status).toBe("released");
    expect((await getMonthUsage(db, "t-1", currentPeriod(NOW))).e2b_runs).toBe(0);
    // Success settles instead (count stays).
    const held2 = await requestE2BRun(db, { tenant_id: "t-1", plan_tier: "pro", e2bConfigured: true, hobbyExhausted: false, nowMs: NOW });
    if (!held2.ok) throw new Error("hold 2 failed");
    const run2 = await getE2BRun(db, held2.run_id);
    expect((await completeE2BRun(db, run2!, true)).status).toBe("settled");
    expect((await getMonthUsage(db, "t-1", currentPeriod(NOW))).e2b_runs).toBe(1);
  });

  it("T-E1/T-M4: 15-min auto-kill — stale held run killed by the sweep, count stays, message set", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro");
    const held = await requestE2BRun(db, { tenant_id: "t-1", plan_tier: "pro", e2bConfigured: true, hobbyExhausted: false, nowMs: NOW - 16 * 60 * 1000 });
    expect(held.ok).toBe(true);
    if (!held.ok) throw new Error("hold failed");
    const stale = await listStaleHeldRuns(db, NOW);
    expect(stale.map((r) => r.id)).toContain(held.run_id);
    const sweeps = await runBillingSweeps(db, NOW);
    expect(sweeps.killed_runs).toBe(1);
    const run = await getE2BRun(db, held.run_id);
    expect(run?.status).toBe("killed");
    // Kill settles: the run did run, so the count stays at 1.
    expect((await getMonthUsage(db, "t-1", currentPeriod(NOW))).e2b_runs).toBe(1);
    const trace = await db.prepare("SELECT kind FROM traces WHERE kind = ?").bind("e2b_auto_kill").first<{ kind: string }>();
    expect(trace?.kind).toBe("e2b_auto_kill");
  });

  it("T-E2: manual kill endpoint marks a stuck run killed with the cap message", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro");
    const held = await requestE2BRun(db, { tenant_id: "t-1", plan_tier: "pro", e2bConfigured: true, hobbyExhausted: false, nowMs: NOW });
    if (!held.ok) throw new Error("hold failed");
    const kill = await handleRequest(
      new Request(`https://hub/api/e2b/run/${held.run_id}/kill`, { method: "POST", headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" }, body: "{}" }),
      fakeEnv(db),
    );
    expect(kill.status).toBe(200);
    const body = (await kill.json()) as Record<string, unknown>;
    expect(body.status).toBe("killed");
    expect(String(body.message)).toContain("15-min cap");
    // Killing a non-held run → 409.
    const again = await handleRequest(
      new Request(`https://hub/api/e2b/run/${held.run_id}/kill`, { method: "POST", headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" }, body: "{}" }),
      fakeEnv(db),
    );
    expect(again.status).toBe(409);
  });

  it("E2B_MAX_RUN_MS is exactly 15 minutes (C4, hard)", () => {
    expect(E2B_MAX_RUN_MS).toBe(15 * 60 * 1000);
  });

  it("sandbox-monitor: threshold progress + hobby remaining (T-E4)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1", "pro");
    await seedE2BUsage(db, "t-1", 10);
    const res = await handleRequest(
      new Request("https://hub/api/billing/admin/sandbox-monitor", { headers: { "x-admin-token": "test-admin" } }),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.hobby_runs_used).toBe(10);
    expect(body.hobby_runs_remaining).toBe(3590);
    expect(body.threshold_paise).toBe(1395000);
    expect(body.pro_floor_open).toBe(false);
    expect(body.pro_floor_reason).toBe("threshold_not_met");
  });
});
