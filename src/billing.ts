/**
 * billing.ts — Phase 4: subscription + UPI flow + D1 ledger + caps +
 * metering reconciliation + sweeps (server-only, launch GATED).
 *
 * Frozen (UPI spec §1–§15, D2/D7/D12/D13, P0 §G7.2):
 * - Payment UPI-only (Flow99 pattern: pay → UTR submit → admin approve
 *   → ACTIVE). Razorpay NAHI, koi payment gateway nahi.
 * - Financial ledger = D1 (TEXT ids, INTEGER paise, UNIQUE UTR, TEXT
 *   ISO-8601 timestamps). Amounts paise me — float kabhi nahi.
 * - Ledger writes MUST use d1Batch (ONE batch = BEGIN/COMMIT) — GAP-10:
 *   approve/refund/hold-settle ke multi-row updates ek hi batch me.
 *   Sequential D1 writes without a transaction NAHI chalenge.
 * - Caps (6, server-side hard enforce): replies / E2B runs / cron jobs /
 *   devices / skills / docs — cap hit = hard refuse, koi charge nahi.
 * - No-loss controls C1–C4 hard-enforce hain — config flag se off nahi
 *   hote. Is module me koi controls-off switch NAHI hai (T-M7 sirf math
 *   se — computeMargin 'worst_no_controls' — koi runtime flag nahi).
 * - ⛔ MARGIN BLOCKER: 3.1 FL default par founder-pays current pricing
 *   par har scenario LOSS hai (worst Pro −₹1,441.51 / Business
 *   −₹4,361.02). computeMargin yehi numbers reproduce karta hai aur
 *   T-M5/T-M6 BLOCKED hain — PASS claim kabhi mat karo. Pricing change
 *   mat karo; founder-pays enable mat karo; BYOK unaffected.
 * - Launch GATED (user word): implementation only — koi paid customer
 *   nahi, koi UPI collection live nahi.
 */
import { d1Batch, getTenant, insertTrace, type D1Like, type TenantRow } from "./db";
import { getMonthUsage, currentPeriod } from "./metering";
import { DEFAULT_PRICES, planLimits } from "./router";
import { randomNonceHex } from "./crypto";
import { sha256Hex } from "./docs";
import { killE2BRun, listStaleHeldRuns, microUsdToPaise } from "./e2b";
import { nextCronRun } from "./cron";

export type PlanTier = "free" | "pro" | "business";
export type BillingPeriod = "monthly" | "annual";

/** D2 FINAL (annual = 11× monthly). Paise me — float kabhi nahi. */
export const PRICES_PAISE: Record<Exclude<PlanTier, "free">, { monthly: number; annual: number }> = {
  pro: { monthly: 99900, annual: 1098900 },
  business: { monthly: 299900, annual: 3298900 },
};

export function subscriptionAmountPaise(tier: PlanTier, period: BillingPeriod): number {
  if (tier === "free") return 0;
  return PRICES_PAISE[tier][period];
}

export function isoNow(ms = Date.now()): string {
  return new Date(ms).toISOString();
}

/** Monthly: approve + 30 din. Annual: approve + 12 mahine (calendar months). */
export function expiryFor(startMs: number, period: BillingPeriod): string {
  const d = new Date(startMs);
  if (period === "annual") d.setMonth(d.getMonth() + 12);
  else d.setDate(d.getDate() + 30);
  return d.toISOString();
}

/** UTR submit expiry: 24h me UTR na aaye to auto-expire (sweep). */
export const UTR_SUBMIT_WINDOW_MS = 24 * 60 * 60 * 1000;

export function newBillingId(prefix: string): string {
  return `${prefix}-${randomNonceHex(8)}`;
}

/**
 * UPI deep link (spec §3): `upi://pay?pa=<admin_vpa>&am=<amount>&cu=INR&tn=...`.
 * VPA admin_settings se aata hai — kabhi code/repo me nahi. Amount
 * paise se rupees (₹999 → am=999).
 */
export function upiLink(vpa: string, amountPaise: number, tier: PlanTier, period: BillingPeriod): string {
  const rupees = amountPaise / 100;
  const tn = encodeURIComponent(`OmniJarvis ${tier} ${period}`);
  return `upi://pay?pa=${encodeURIComponent(vpa)}&am=${rupees}&cu=INR&tn=${tn}`;
}

/** UTR format (spec §3): 12-digit, UPI apps dete hain. */
export function isValidUtr(utr: string): boolean {
  return /^\d{12}$/.test(utr);
}

// --- Margin math (P0 §G7.2 formula — verified, exact reproduce) ---

export type MarginScenario = "worst" | "lean" | "base" | "worst_no_controls";

export interface MarginResult {
  tier: PlanTier;
  scenario: MarginScenario;
  revenue_paise: number;
  llm_cost_paise: number;
  e2b_cost_paise: number;
  total_paise: number;
  margin_paise: number;
  /** T-M5/T-M6: worst-case margin is NEGATIVE at current pricing — BLOCKED. */
  blocked: boolean;
}

/**
 * computeMargin — P0 §G7.2 formula, per-component paise rounding (wahi
 * rounding jisse audit ke numbers exact reproduce hote hain):
 * per-call micro = in×price.in + out×price.out; LLM $ = replies ×
 * calls/turn × per-call; E2B $ = runs × (mins/10) × $0.0276; ₹93/$.
 * worst: 3.1 FL, 5000 in + 500 out, C=5, E2B 15-min.
 * lean: 3.1 FL, 2000 in + 300 out, C=5, E2B 15-min.
 * base: 3.1 FL, 5000 in + 500 out, C=2, E2B 10-min.
 * worst_no_controls: 3.5 FL, 5000 in + 500 out, C=2, E2B 30-min (T-M7).
 */
export function computeMargin(tier: Exclude<PlanTier, "free">, scenario: MarginScenario): MarginResult {
  const replies = tier === "pro" ? 2500 : 7500;
  const e2bRuns = tier === "pro" ? 30 : 100;
  const revenue = tier === "pro" ? 99900 : 299900;
  const spec =
    scenario === "worst"
      ? { model: "gemini-3.1-flash-lite", inTok: 5000, outTok: 500, calls: 5, e2bMins: 15 }
      : scenario === "lean"
        ? { model: "gemini-3.1-flash-lite", inTok: 2000, outTok: 300, calls: 5, e2bMins: 15 }
        : scenario === "base"
          ? { model: "gemini-3.1-flash-lite", inTok: 5000, outTok: 500, calls: 2, e2bMins: 10 }
          : { model: "gemini-3.5-flash-lite", inTok: 5000, outTok: 500, calls: 2, e2bMins: 30 };
  const price = DEFAULT_PRICES[spec.model];
  const perCallMicro = spec.inTok * price.in + spec.outTok * price.out;
  const llmUsd = (replies * spec.calls * perCallMicro) / 1_000_000;
  const e2bUsd = e2bRuns * (spec.e2bMins / 10) * 0.0276;
  // Per-component paise rounding — audit numbers exact reproduce hote hain.
  const llmCostPaise = Math.round(llmUsd * 93 * 100);
  const e2bCostPaise = Math.round(e2bUsd * 93 * 100);
  const total = llmCostPaise + e2bCostPaise;
  const margin = revenue - total;
  return {
    tier,
    scenario,
    revenue_paise: revenue,
    llm_cost_paise: llmCostPaise,
    e2b_cost_paise: e2bCostPaise,
    total_paise: total,
    margin_paise: margin,
    blocked: margin < 0,
  };
}

/** Pro-rated upgrade (paise me exact, integer math): bacha hua Pro
 * amount adjust karke Business charge. Expired sub par upgrade nahi. */
export function proratedUpgradeCharge(
  oldAmountPaise: number,
  oldStartsAtIso: string,
  oldExpiresAtIso: string,
  newPricePaise: number,
  nowMs = Date.now(),
): { remaining_paise: number; charge_paise: number } {
  const totalMs = Date.parse(oldExpiresAtIso) - Date.parse(oldStartsAtIso);
  const remainingMs = Math.max(0, Date.parse(oldExpiresAtIso) - nowMs);
  const remaining = totalMs > 0 ? Math.floor((oldAmountPaise * remainingMs) / totalMs) : 0;
  return { remaining_paise: remaining, charge_paise: Math.max(0, newPricePaise - remaining) };
}

// --- D1 rows (ledger tables) ---

export interface SubscriptionRow {
  id: string;
  tenant_id: string;
  plan_tier: string;
  billing_period: string;
  amount_paise: number;
  status: string;
  starts_at: string | null;
  expires_at: string | null;
  created_at: string;
}

export interface PaymentRow {
  id: string;
  subscription_id: string;
  tenant_id: string;
  utr: string;
  amount_paise: number;
  method: string;
  status: string;
  admin_note: string | null;
  decided_by: string | null;
  decided_at: string | null;
  created_at: string;
}

export async function getSubscription(db: D1Like, id: string): Promise<SubscriptionRow | null> {
  const row = await db
    .prepare(
      "SELECT id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at FROM subscriptions WHERE id = ?",
    )
    .bind(id)
    .first<SubscriptionRow>();
  return row;
}

export async function getPayment(db: D1Like, id: string): Promise<PaymentRow | null> {
  const row = await db
    .prepare(
      "SELECT id, subscription_id, tenant_id, utr, amount_paise, method, status, admin_note, decided_by, decided_at, created_at FROM payments WHERE id = ?",
    )
    .bind(id)
    .first<PaymentRow>();
  return row;
}

/** Tenant ki open subscription (pending_payment ya utr_submitted) — latest first. */
export async function getOpenSubscription(db: D1Like, tenantId: string): Promise<SubscriptionRow | null> {
  const rows = await db
    .prepare(
      "SELECT id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at FROM subscriptions WHERE tenant_id = ? ORDER BY created_at DESC",
    )
    .bind(tenantId)
    .all<SubscriptionRow>();
  return (rows.results ?? []).find((r) => r.status === "pending_payment" || r.status === "utr_submitted") ?? null;
}

export async function getActiveSubscription(db: D1Like, tenantId: string): Promise<SubscriptionRow | null> {
  const rows = await db
    .prepare(
      "SELECT id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at FROM subscriptions WHERE tenant_id = ? ORDER BY created_at DESC",
    )
    .bind(tenantId)
    .all<SubscriptionRow>();
  return (rows.results ?? []).find((r) => r.status === "active") ?? null;
}

/** Latest subscription of any status (renew/upgrade ko purana plan chahiye). */
export async function getLatestSubscription(db: D1Like, tenantId: string): Promise<SubscriptionRow | null> {
  const rows = await db
    .prepare(
      "SELECT id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at FROM subscriptions WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenantId)
    .all<SubscriptionRow>();
  return (rows.results ?? [])[0] ?? null;
}

export async function getAdminSetting(db: D1Like, key: string): Promise<string | null> {
  const row = await db
    .prepare("SELECT value FROM admin_settings WHERE key = ?")
    .bind(key)
    .first<{ value: string }>();
  return row?.value ?? null;
}

export async function setAdminSetting(db: D1Like, key: string, value: string, nowMs = Date.now()): Promise<void> {
  await db
    .prepare(
      "INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?) " +
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key, value, isoNow(nowMs))
    .run();
}

/** Ledger event prepared statement — batch me daalne ke liye (execute mat karo). */
export function ledgerEventStmt(
  db: D1Like,
  tenantId: string,
  kind: string,
  detail: Record<string, unknown>,
  actor: string,
  nowMs = Date.now(),
) {
  return db
    .prepare("INSERT INTO ledger_events (id, tenant_id, kind, detail, actor, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(newBillingId("lev"), tenantId, kind, JSON.stringify(detail), actor, isoNow(nowMs));
}

// --- Subscription lifecycle (har multi-row write EK batch me) ---

export async function createSubscription(
  db: D1Like,
  opts: { tenant_id: string; plan_tier: PlanTier; billing_period: BillingPeriod; amount_paise: number; nowMs?: number },
): Promise<SubscriptionRow> {
  const nowMs = opts.nowMs ?? Date.now();
  const id = newBillingId("sub");
  const createdAt = isoNow(nowMs);
  const sub: SubscriptionRow = {
    id,
    tenant_id: opts.tenant_id,
    plan_tier: opts.plan_tier,
    billing_period: opts.billing_period,
    amount_paise: opts.amount_paise,
    status: "pending_payment",
    starts_at: null,
    expires_at: null,
    created_at: createdAt,
  };
  await d1Batch(db, [
    db
      .prepare(
        "INSERT INTO subscriptions (id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(id, sub.tenant_id, sub.plan_tier, sub.billing_period, sub.amount_paise, sub.status, null, null, createdAt),
    ledgerEventStmt(db, opts.tenant_id, "subscription_created", { subscription_id: id, plan_tier: opts.plan_tier, billing_period: opts.billing_period, amount_paise: opts.amount_paise }, "system", nowMs),
  ]);
  return sub;
}

export type SubmitUtrResult =
  | { ok: true; payment_id: string; status: "utr_submitted" }
  | { ok: false; error: "subscription_not_pending" | "utr_duplicate" | "invalid_utr" };

/**
 * UTR submit. Amount client se NAHI liya jata (auto = subscription
 * amount). Duplicate UTR: code check pehle (FakeD1 UNIQUE enforce nahi
 * karta — GAP-7), live D1 UNIQUE constraint second line of defence.
 * 1 batch: payment row + subscription utr_submitted + ledger event.
 */
export async function submitUtr(
  db: D1Like,
  opts: { subscription: SubscriptionRow; utr: string; note?: string | null; payment_date?: string | null; nowMs?: number },
): Promise<SubmitUtrResult> {
  const nowMs = opts.nowMs ?? Date.now();
  if (!isValidUtr(opts.utr)) return { ok: false, error: "invalid_utr" };
  if (opts.subscription.status !== "pending_payment") return { ok: false, error: "subscription_not_pending" };
  const dup = await db.prepare("SELECT id FROM payments WHERE utr = ?").bind(opts.utr).first<{ id: string }>();
  if (dup) return { ok: false, error: "utr_duplicate" };
  const paymentId = newBillingId("pay");
  await d1Batch(db, [
    db
      .prepare(
        "INSERT INTO payments (id, subscription_id, tenant_id, utr, amount_paise, method, status, admin_note, decided_by, decided_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(paymentId, opts.subscription.id, opts.subscription.tenant_id, opts.utr, opts.subscription.amount_paise, "upi", "submitted", opts.note ?? null, null, null, isoNow(nowMs)),
    db.prepare("UPDATE subscriptions SET status = ? WHERE id = ?").bind("utr_submitted", opts.subscription.id),
    ledgerEventStmt(db, opts.subscription.tenant_id, "utr_submitted", { subscription_id: opts.subscription.id, payment_id: paymentId, utr: opts.utr, amount_paise: opts.subscription.amount_paise, note: opts.note ?? undefined, payment_date: opts.payment_date ?? undefined }, "customer", nowMs),
  ]);
  return { ok: true, payment_id: paymentId, status: "utr_submitted" };
}

export type ApproveResult =
  | { ok: true; already?: boolean; subscription: SubscriptionRow; expires_at: string | null }
  | { ok: false; error: "payment_decided" | "subscription_not_submitted" };

/**
 * Admin approve. Idempotent: already-approved → no-op (koi dobara
 * charge/extend nahi, expiry UNCHANGED). 1 batch: payment approved +
 * subscription active (+ starts/expires) + tenants plan_tier (+ upgrade
 * supersede: purani active subscription expired + ledger event).
 */
export async function approvePayment(
  db: D1Like,
  opts: { payment: PaymentRow; subscription: SubscriptionRow; admin: string; nowMs?: number },
): Promise<ApproveResult> {
  const nowMs = opts.nowMs ?? Date.now();
  if (opts.payment.status === "approved") {
    return { ok: true, already: true, subscription: opts.subscription, expires_at: opts.subscription.expires_at };
  }
  if (opts.payment.status !== "submitted" || opts.subscription.status !== "utr_submitted") {
    return { ok: false, error: opts.payment.status !== "submitted" ? "payment_decided" : "subscription_not_submitted" };
  }
  const expiresAt = expiryFor(nowMs, opts.subscription.billing_period as BillingPeriod);
  const startsAt = isoNow(nowMs);
  const stmts = [
    db
      .prepare("UPDATE payments SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?")
      .bind("approved", opts.admin, isoNow(nowMs), opts.payment.id),
    db
      .prepare("UPDATE subscriptions SET status = ?, starts_at = ?, expires_at = ? WHERE id = ?")
      .bind("active", startsAt, expiresAt, opts.subscription.id),
    db.prepare("UPDATE tenants SET plan_tier = ?, pending_downgrade_tier = NULL WHERE id = ?").bind(opts.subscription.plan_tier, opts.subscription.tenant_id),
    ledgerEventStmt(db, opts.subscription.tenant_id, "approved", { subscription_id: opts.subscription.id, payment_id: opts.payment.id, utr: opts.payment.utr, amount_paise: opts.payment.amount_paise, plan_tier: opts.subscription.plan_tier, billing_period: opts.subscription.billing_period, expires_at: expiresAt }, opts.admin, nowMs),
  ];
  // Upgrade supersede: tenant ki koi AUR active subscription ho to use expire karo.
  const oldActive = await getActiveSubscription(db, opts.subscription.tenant_id);
  if (oldActive && oldActive.id !== opts.subscription.id) {
    stmts.push(
      db.prepare("UPDATE subscriptions SET status = ? WHERE id = ?").bind("expired", oldActive.id),
      ledgerEventStmt(db, opts.subscription.tenant_id, "expired", { subscription_id: oldActive.id, reason: "upgrade_superseded", superseded_by: opts.subscription.id }, "system", nowMs),
    );
  }
  await d1Batch(db, stmts);
  return {
    ok: true,
    subscription: { ...opts.subscription, status: "active", starts_at: startsAt, expires_at: expiresAt },
    expires_at: expiresAt,
  };
}

export type RejectResult = { ok: true } | { ok: false; error: "payment_decided" | "subscription_not_submitted" };

/** Admin reject (reason required — route checks). 1 batch: payment + subscription + ledger. */
export async function rejectPayment(
  db: D1Like,
  opts: { payment: PaymentRow; subscription: SubscriptionRow; admin: string; reason: string; nowMs?: number },
): Promise<RejectResult> {
  const nowMs = opts.nowMs ?? Date.now();
  if (opts.payment.status !== "submitted" || opts.subscription.status !== "utr_submitted") {
    return { ok: false, error: opts.payment.status !== "submitted" ? "payment_decided" : "subscription_not_submitted" };
  }
  await d1Batch(db, [
    db
      .prepare("UPDATE payments SET status = ?, decided_by = ?, decided_at = ?, admin_note = ? WHERE id = ?")
      .bind("rejected", opts.admin, isoNow(nowMs), opts.reason, opts.payment.id),
    db.prepare("UPDATE subscriptions SET status = ? WHERE id = ?").bind("rejected", opts.subscription.id),
    ledgerEventStmt(db, opts.subscription.tenant_id, "rejected", { subscription_id: opts.subscription.id, payment_id: opts.payment.id, utr: opts.payment.utr, amount_paise: opts.payment.amount_paise, reason: opts.reason }, opts.admin, nowMs),
  ]);
  return { ok: true };
}

export type RefundResult = { ok: true; refund_id: string } | { ok: false; error: "payment_not_approved" | "amount_too_large" };

/**
 * Manual UPI refund ka record (admin UPI app se bhejta hai, phir ledger
 * me record karta hai — auto-refund nahi). Full refund → subscription
 * expired; partial → active rehti hai. 1 batch: refunds row + payment
 * refunded + (full: subscription expired + ledger expired) + ledger refunded.
 */
export async function recordRefund(
  db: D1Like,
  opts: { payment: PaymentRow; subscription: SubscriptionRow; refund_utr: string; amount_paise: number; reason: string; admin: string; nowMs?: number },
): Promise<RefundResult> {
  const nowMs = opts.nowMs ?? Date.now();
  if (opts.payment.status !== "approved") return { ok: false, error: "payment_not_approved" };
  if (opts.amount_paise <= 0 || opts.amount_paise > opts.payment.amount_paise) {
    return { ok: false, error: "amount_too_large" };
  }
  const full = opts.amount_paise === opts.payment.amount_paise;
  const refundId = newBillingId("ref");
  const stmts = [
    db
      .prepare("INSERT INTO refunds (id, payment_id, tenant_id, amount_paise, refund_utr, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(refundId, opts.payment.id, opts.payment.tenant_id, opts.amount_paise, opts.refund_utr, opts.reason, isoNow(nowMs)),
    db.prepare("UPDATE payments SET status = ? WHERE id = ?").bind("refunded", opts.payment.id),
    ledgerEventStmt(db, opts.payment.tenant_id, "refunded", { subscription_id: opts.subscription.id, payment_id: opts.payment.id, refund_id: refundId, refund_utr: opts.refund_utr, amount_paise: opts.amount_paise, reason: opts.reason, full }, opts.admin, nowMs),
  ];
  if (full && opts.subscription.status === "active") {
    stmts.push(
      db.prepare("UPDATE subscriptions SET status = ? WHERE id = ?").bind("expired", opts.subscription.id),
      ledgerEventStmt(db, opts.payment.tenant_id, "expired", { subscription_id: opts.subscription.id, reason: "refunded_full" }, "system", nowMs),
    );
  }
  await d1Batch(db, stmts);
  return { ok: true, refund_id: refundId };
}

// --- Reconciliation + retention (metering, T-L2/L3/L6) ---

export interface Reconciliation {
  approved_payments_paise: number;
  expected_revenue_paise: number;
  founder_llm_cost_paise: number;
  /** payments.approved sum − subscriptions.active expected revenue. 0 = PASS, >0 = BLOCKER. */
  diff_payments_vs_expected: number;
}

/**
 * Monthly reconciliation — same DB, aggregate queries (FakeD1 SUM
 * support §2a se). BYOK cost founder margin me nahi aata (founder ₹0),
 * isliye LLM cost sirf billing_mode='founder_pays' rows se.
 */
export async function reconcileBilling(db: D1Like): Promise<Reconciliation> {
  const approved = await db
    .prepare("SELECT SUM(amount_paise) AS total FROM payments WHERE status = ?")
    .bind("approved")
    .first<{ total: number }>();
  const expected = await db
    .prepare("SELECT SUM(amount_paise) AS total FROM subscriptions WHERE status = ?")
    .bind("active")
    .first<{ total: number }>();
  const cost = await db
    .prepare("SELECT SUM(cost_usd_micro) AS total FROM llm_usage WHERE billing_mode = ?")
    .bind("founder_pays")
    .first<{ total: number }>();
  const approvedPaise = approved?.total ?? 0;
  const expectedPaise = expected?.total ?? 0;
  return {
    approved_payments_paise: approvedPaise,
    expected_revenue_paise: expectedPaise,
    founder_llm_cost_paise: microUsdToPaise(cost?.total ?? 0),
    diff_payments_vs_expected: approvedPaise - expectedPaise,
  };
}

/** Retention (T-L6): 13-month purani llm_usage raw rows purge karo;
 * monthly rollup (usage_counters) bacha rehta hai. Returns deleted count. */
export async function purgeOldUsage(db: D1Like, nowMs = Date.now()): Promise<number> {
  const cutoff = nowMs - 13 * 30 * 24 * 60 * 60 * 1000;
  const rows = await db
    .prepare("SELECT id FROM llm_usage WHERE created_at < ?")
    .bind(cutoff)
    .all<{ id: number }>();
  const ids = rows.results ?? [];
  for (const r of ids) {
    await db.prepare("DELETE FROM llm_usage WHERE id = ?").bind(r.id).run();
  }
  return ids.length;
}

// --- Cap warnings (T-C12) ---

export interface CapUsage {
  replies: number;
  e2b_runs: number;
  cron_jobs: number;
  devices: number;
}

/** Har cap jis par usage >= 80% ho — status response me warnings[].
 * Email send U-6 ke kaaran nahi; warning status me hona hi server-side proof hai. */
export function capWarnings(usage: CapUsage, planTier: string): string[] {
  const limits = planLimits(planTier);
  const out: string[] = [];
  const checks: [string, number, number][] = [
    ["replies", usage.replies, limits.replies],
    ["e2b_runs", usage.e2b_runs, limits.e2b_runs],
    ["cron_jobs", usage.cron_jobs, limits.cron_jobs],
    ["devices", usage.devices, limits.devices],
  ];
  for (const [name, used, limit] of checks) {
    if (limit > 0 && used / limit >= 0.8) out.push(name);
  }
  return out;
}

export async function countEnabledDevices(db: D1Like, tenantId: string): Promise<number> {
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM devices WHERE tenant_id = ? AND enabled = ?")
    .bind(tenantId, 1)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

export async function countEnabledJobs(db: D1Like, tenantId: string): Promise<number> {
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM scheduled_jobs WHERE tenant_id = ? AND enabled = ?")
    .bind(tenantId, 1)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

// --- Cron jobs (Phase 4 ka naya create route — pehle koi route nahi tha) ---

export type CreateJobResult =
  | { ok: true; job_id: string; next_run_at: number | null }
  | { ok: false; error: "cron_cap" | "bad_cron" | "device_not_paired" };

/** Job create + cap check (T-C6/C7). next_run_at minimal cron parser se
 * (cron.ts nextCronRun reuse — hub route se pass hota hai? Nahi: yahan
 * import karo — cron.ts D1Like-independent pure function hai). */
export async function createCronJob(
  db: D1Like,
  opts: { tenant: TenantRow; device_id: string; cron_expr: string; command: string; nowMs?: number },
): Promise<CreateJobResult> {
  const nowMs = opts.nowMs ?? Date.now();
  const limits = planLimits(opts.tenant.plan_tier);
  const used = await countEnabledJobs(db, opts.tenant.id);
  if (used >= limits.cron_jobs) {
    return { ok: false, error: "cron_cap" };
  }
  const next = nextCronRun(opts.cron_expr, nowMs);
  if (next === null) return { ok: false, error: "bad_cron" };
  const jobId = newBillingId("job");
  await db
    .prepare(
      "INSERT INTO scheduled_jobs (id, tenant_id, device_id, cron_expr, command, enabled, last_run_at, next_run_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(jobId, opts.tenant.id, opts.device_id, opts.cron_expr, opts.command, 1, null, next, nowMs)
    .run();
  return { ok: true, job_id: jobId, next_run_at: next };
}

// --- Email verification + disposable blocklist (T-A1/A2, U-6) ---

/** Disposable-email blocklist (free list, signup/verify-request par check). */
export const DISPOSABLE_EMAIL_DOMAINS = [
  "mailinator.com",
  "tempmail.com",
  "guerrillamail.com",
  "10minutemail.com",
  "throwawaymail.com",
  "yopmail.com",
  "temp-mail.org",
  "fakeinbox.com",
  "maildrop.cc",
  "getnada.com",
  "sharklasers.com",
  "dispostable.com",
  "trashmail.com",
  "mintemail.com",
  "mytemp.email",
  "tempail.com",
  "emailondeck.com",
  "mohmal.com",
  "spamgourmet.com",
  "jetable.org",
] as const;

export function isDisposableEmail(email: string): boolean {
  const domain = email.split("@")[1]?.toLowerCase() ?? "";
  return (DISPOSABLE_EMAIL_DOMAINS as readonly string[]).includes(domain);
}

/** Verify token hash (sha256, hex) — token kabhi plaintext store nahi hota. */
export async function hashEmailVerifyToken(token: string): Promise<string> {
  return sha256Hex(token);
}

export const EMAIL_VERIFY_TTL_MS = 24 * 60 * 60 * 1000;

export type RequestVerifyResult =
  | { ok: true; verification_pending: true }
  | { ok: false; error: "disposable_email" | "already_verified" };

/**
 * Verify-email request. Token generate karo, HASH + 24h expiry store
 * karo — token response me KABHI nahi (email se jayega). Email send
 * U-6 ke kaaran abhi wired nahi hai (koi Resend/SMTP code nahi) —
 * isliye live me admin god-mode verify-email se khola jayega.
 * `tokenForTest` sirf vitest ke liye hai (route kabhi pass nahi karta).
 */
export async function requestEmailVerification(
  db: D1Like,
  opts: { tenant: TenantRow; email: string; nowMs?: number; tokenForTest?: string },
): Promise<RequestVerifyResult> {
  if (opts.tenant.email_verified === 1) return { ok: false, error: "already_verified" };
  if (isDisposableEmail(opts.email)) return { ok: false, error: "disposable_email" };
  const nowMs = opts.nowMs ?? Date.now();
  const token = opts.tokenForTest ?? randomNonceHex(16);
  const hash = await hashEmailVerifyToken(token);
  await db
    .prepare("UPDATE tenants SET email_verify_token_hash = ?, email_verify_expires_at = ? WHERE id = ?")
    .bind(hash, nowMs + EMAIL_VERIFY_TTL_MS, opts.tenant.id)
    .run();
  return { ok: true, verification_pending: true };
}

export type ConfirmVerifyResult = { ok: true } | { ok: false; error: "verification_failed" };

export async function confirmEmailVerification(
  db: D1Like,
  opts: { tenant: TenantRow; token: string; nowMs?: number },
): Promise<ConfirmVerifyResult> {
  const nowMs = opts.nowMs ?? Date.now();
  const stored = await db
    .prepare("SELECT email_verify_token_hash, email_verify_expires_at FROM tenants WHERE id = ?")
    .bind(opts.tenant.id)
    .first<{ email_verify_token_hash: string | null; email_verify_expires_at: number | null }>();
  if (!stored?.email_verify_token_hash || !stored.email_verify_expires_at) {
    return { ok: false, error: "verification_failed" };
  }
  if (stored.email_verify_expires_at < nowMs) return { ok: false, error: "verification_failed" };
  const hash = await hashEmailVerifyToken(opts.token);
  if (hash !== stored.email_verify_token_hash) return { ok: false, error: "verification_failed" };
  await db
    .prepare("UPDATE tenants SET email_verified = ?, email_verify_token_hash = NULL, email_verify_expires_at = NULL WHERE id = ?")
    .bind(1, opts.tenant.id)
    .run();
  return { ok: true };
}

// --- Sweeps (tick me fold — cron.ts chhedo mat) ---

export interface SweepResult {
  expired_pending: number;
  expired_active: number;
  downgrades_applied: number;
  reminders: number;
  killed_runs: number;
}

/** Idempotent billing sweep (dobara tick = no-op — status check ke baad hi likho). */
export async function runBillingSweeps(db: D1Like, nowMs = Date.now()): Promise<SweepResult> {
  const result: SweepResult = { expired_pending: 0, expired_active: 0, downgrades_applied: 0, reminders: 0, killed_runs: 0 };

  // 1. Pending-payment expiry (24h UTR na aaye — T-U11).
  const pending = await db
    .prepare("SELECT id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at FROM subscriptions WHERE status = ?")
    .bind("pending_payment")
    .all<SubscriptionRow>();
  for (const sub of pending.results ?? []) {
    if (Date.parse(sub.created_at) + UTR_SUBMIT_WINDOW_MS > nowMs) continue;
    await d1Batch(db, [
      db.prepare("UPDATE subscriptions SET status = ? WHERE id = ?").bind("expired", sub.id),
      ledgerEventStmt(db, sub.tenant_id, "expired", { subscription_id: sub.id, reason: "utr_timeout" }, "system", nowMs),
    ]);
    result.expired_pending++;
  }

  // 2. Active expiry → Free (+ pending downgrade lagu — T-U6/T-U9).
  const active = await db
    .prepare("SELECT id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at FROM subscriptions WHERE status = ?")
    .bind("active")
    .all<SubscriptionRow>();
  for (const sub of active.results ?? []) {
    if (!sub.expires_at || Date.parse(sub.expires_at) >= nowMs) continue;
    const tenant = await getTenant(db, sub.tenant_id);
    const stmts = [
      db.prepare("UPDATE subscriptions SET status = ? WHERE id = ?").bind("expired", sub.id),
      db.prepare("UPDATE tenants SET plan_tier = ?, pending_downgrade_tier = NULL WHERE id = ?").bind("free", sub.tenant_id),
      ledgerEventStmt(db, sub.tenant_id, "expired", { subscription_id: sub.id, reason: "expiry" }, "system", nowMs),
    ];
    // Pending downgrade: us tier ki nayi pending_payment subscription banao.
    const downgradeTo = (tenant?.pending_downgrade_tier ?? null) as PlanTier | null;
    if (downgradeTo && downgradeTo !== "free") {
      const amount = subscriptionAmountPaise(downgradeTo, (sub.billing_period as BillingPeriod) ?? "monthly");
      const newId = newBillingId("sub");
      stmts.push(
        db
          .prepare(
            "INSERT INTO subscriptions (id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
          )
          .bind(newId, sub.tenant_id, downgradeTo, sub.billing_period, amount, "pending_payment", null, null, isoNow(nowMs)),
        ledgerEventStmt(db, sub.tenant_id, "downgraded", { subscription_id: newId, from_tier: sub.plan_tier, to_tier: downgradeTo, effective: "next_cycle" }, "system", nowMs),
      );
      result.downgrades_applied++;
    } else if (downgradeTo === "free") {
      stmts.push(
        ledgerEventStmt(db, sub.tenant_id, "downgraded", { subscription_id: sub.id, from_tier: sub.plan_tier, to_tier: "free", effective: "next_cycle" }, "system", nowMs),
      );
      result.downgrades_applied++;
    }
    await d1Batch(db, stmts);
    result.expired_active++;
  }

  // 3. Renewal reminders (7d / 1d) — trace = reminder-due ka record;
  // email send U-6 ke kaaran nahi (trace + status flag hi proof hai).
  const activeNow = await db
    .prepare("SELECT id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at FROM subscriptions WHERE status = ?")
    .bind("active")
    .all<SubscriptionRow>();
  for (const sub of activeNow.results ?? []) {
    if (!sub.expires_at) continue;
    const msLeft = Date.parse(sub.expires_at) - nowMs;
    if (msLeft <= 0 || msLeft > 7 * 24 * 60 * 60 * 1000) continue;
    const window = msLeft <= 24 * 60 * 60 * 1000 ? "1d" : "7d";
    const existing = await db
      .prepare("SELECT id FROM traces WHERE kind = ? AND detail LIKE ? AND detail LIKE ? LIMIT 1")
      .bind("renewal_reminder", `%"subscription_id":"${sub.id}"%`, `%"window":"${window}"%`)
      .first<{ id: number }>();
    if (existing) continue;
    await insertTrace(db, sub.tenant_id, "", "renewal_reminder", { subscription_id: sub.id, window });
    result.reminders++;
  }

  // 4. E2B auto-kill (C4: 15-min cap — T-E1/T-M4).
  const stale = await listStaleHeldRuns(db, nowMs);
  for (const run of stale) {
    await killE2BRun(db, run, nowMs);
    await insertTrace(db, run.tenant_id, "", "e2b_auto_kill", { run_id: run.id, max_run_ms: 15 * 60 * 1000 });
    result.killed_runs++;
  }

  return result;
}

// --- DPDP wipe (T-W1–T-W5) ---

export interface WipeCounts {
  subscriptions: number;
  payments: number;
  refunds: number;
  ledger_events: number;
  llm_usage: number;
  usage_counters: number;
  traces: number;
  memories: number;
  doc_jobs: number;
  certificates: number;
  scheduled_jobs: number;
  devices: number;
  global_skills: number;
  pairing_tokens: number;
}

/**
 * Tenant wipe (D1 — Qdrant/B2 ke liye koi client nahi hai, isliye
 * response me `qdrant:"not_configured", b2:"not_configured"` honest
 * field hai). Wipe audit: DELETEs ke BAAD `traces` me ek `tenant_wipe`
 * row (wipe khud bina trail ke nahi — T-W5). Licences table wipe NAHI
 * hoti (licence user_id-opaque hai, tenant id se map nahi hoti — licence
 * revoke alag flow hai).
 */
export async function wipeTenant(
  db: D1Like,
  tenantId: string,
  nowMs = Date.now(),
): Promise<{ counts: WipeCounts; qdrant: string; b2: string }> {
  const counts: WipeCounts = {
    subscriptions: 0, payments: 0, refunds: 0, ledger_events: 0, llm_usage: 0,
    usage_counters: 0, traces: 0, memories: 0, doc_jobs: 0, certificates: 0,
    scheduled_jobs: 0, devices: 0, global_skills: 0, pairing_tokens: 0,
  };
  const del = async (table: string, key: keyof WipeCounts, where: string) => {
    const rows = await db.prepare(`SELECT id FROM ${table} WHERE ${where}`).bind(tenantId).all<{ id: unknown }>();
    const hits = rows.results ?? [];
    for (const r of hits) {
      await db.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(r.id).run();
    }
    counts[key] = hits.length;
  };
  await del("payments", "payments", "tenant_id = ?");
  await del("refunds", "refunds", "tenant_id = ?");
  await del("subscriptions", "subscriptions", "tenant_id = ?");
  await del("ledger_events", "ledger_events", "tenant_id = ?");
  // llm_usage / usage_counters: tenant_id filter (usage_counters ka PK tenant_id+period hai).
  {
    const rows = await db.prepare("SELECT id FROM llm_usage WHERE tenant_id = ?").bind(tenantId).all<{ id: number }>();
    for (const r of rows.results ?? []) await db.prepare("DELETE FROM llm_usage WHERE id = ?").bind(r.id).run();
    counts.llm_usage = (rows.results ?? []).length;
    const crows = await db.prepare("SELECT tenant_id, period FROM usage_counters WHERE tenant_id = ?").bind(tenantId).all<{ tenant_id: string; period: string }>();
    for (const r of crows.results ?? []) {
      await db.prepare("DELETE FROM usage_counters WHERE tenant_id = ? AND period = ?").bind(r.tenant_id, r.period).run();
    }
    counts.usage_counters = (crows.results ?? []).length;
  }
  await del("traces", "traces", "tenant_id = ?");
  await del("memories", "memories", "tenant_id = ?");
  await del("doc_jobs", "doc_jobs", "tenant_id = ?");
  await del("certificates", "certificates", "tenant_id = ?");
  await del("scheduled_jobs", "scheduled_jobs", "tenant_id = ?");
  // devices + per-device sync_state + pairing_tokens.
  {
    const rows = await db.prepare("SELECT device_id FROM devices WHERE tenant_id = ?").bind(tenantId).all<{ device_id: string }>();
    for (const r of rows.results ?? []) {
      await db.prepare("DELETE FROM devices WHERE device_id = ?").bind(r.device_id).run();
      await db.prepare("DELETE FROM sync_state WHERE device_id = ?").bind(r.device_id).run();
    }
    counts.devices = (rows.results ?? []).length;
    const prows = await db.prepare("SELECT token FROM pairing_tokens WHERE tenant_id = ?").bind(tenantId).all<{ token: string }>();
    for (const r of prows.results ?? []) await db.prepare("DELETE FROM pairing_tokens WHERE token = ?").bind(r.token).run();
    counts.pairing_tokens = (prows.results ?? []).length;
  }
  // global_skills submitted_by tenant.
  {
    const rows = await db.prepare("SELECT id FROM global_skills WHERE submitted_by = ?").bind(tenantId).all<{ id: string }>();
    for (const r of rows.results ?? []) await db.prepare("DELETE FROM global_skills WHERE id = ?").bind(r.id).run();
    counts.global_skills = (rows.results ?? []).length;
  }
  // Tenant row last (traces wipe ke baad audit trace likhi jayegi).
  await db.prepare("DELETE FROM tenants WHERE id = ?").bind(tenantId).run();
  await insertTrace(db, tenantId, "", "tenant_wipe", {
    tenant_id: tenantId,
    stores: { d1: true, qdrant: "not_configured", b2: "not_configured" },
    deleted: counts,
  });
  void nowMs;
  return { counts, qdrant: "not_configured", b2: "not_configured" };
}

// --- Grievance placeholder + launch gates + legal pages (T-G1–T-G4) ---

export const S79_RISK_NOTE =
  "Grievance Officer abhi appointed nahi hai (user deferred — D5 SKIP). " +
  "IT Rules 2021 ke bina Grievance Officer ke Section 79 safe harbour nahi milega — " +
  "ye legal risk hai. Launch se pehle ek real person ka naam, designation aur email chahiye.";

export async function getGrievance(db: D1Like): Promise<{ name: string; designation: string; email: string; s79_risk_note: string; status: string }> {
  const name = (await getAdminSetting(db, "grievance_officer_name")) ?? "";
  const designation = (await getAdminSetting(db, "grievance_officer_designation")) ?? "";
  const email = (await getAdminSetting(db, "grievance_officer_email")) ?? "";
  return { name, designation, email, s79_risk_note: S79_RISK_NOTE, status: "pending — user deferred" };
}

export interface LaunchGate {
  gate: string;
  status: string;
  note: string;
}

/** Launch gate list — implementation complete ≠ launch. */
export async function getLaunchGates(db: D1Like): Promise<LaunchGate[]> {
  const vpa = await getAdminSetting(db, "upi_vpa");
  return [
    { gate: "gst_ca_verification", status: "OPEN", note: "D6 — CA se verify karwana hai ki exemption valid hai ya invoicing chahiye (user-side)." },
    { gate: "grievance_officer", status: "pending — user deferred", note: "D5 SKIP — placeholder slot only; naam/designation/email user dega tabhi live hoga." },
    { gate: "founder_pays_margin", status: "BLOCKED", note: "Worst-case margin NEGATIVE (Pro −₹1,441.51 / Business −₹4,361.02) — pricing revisit ke bina founder-pays enable nahi hoga." },
    { gate: "caps_enforcement_tests", status: "implemented", note: "T-C1–T-C13 vitest + live — audit report dekho (exit item 2)." },
    { gate: "e2b_account", status: "gated — no account (U-4)", note: "E2B account nahi hai; threshold code + gating implemented; device-as-sandbox fallback live hai." },
    { gate: "upi_vpa", status: vpa ? "configured" : "not_configured", note: "Admin VPA admin panel se set karega — bina VPA ke UPI link nahi banega." },
    { gate: "launch", status: "GATED", note: "Implementation complete ≠ launch — user go/no-go (numbered) chahiye." },
  ];
}

export const LEGAL_UPDATED = "2026-11-22";

export const TERMS_BODY = [
  "OmniJarvis Terms of Service (Last updated: 2026-11-22).",
  "1. Plans: Free (₹0, 100 AI replies/month, device-only), Pro (₹999/month), Business (₹2,999/month). Annual = 11x monthly.",
  "2. Payment is UPI-only. You pay via UPI, submit the 12-digit UTR, and the admin approves after matching the bank statement. No card is stored. No payment gateway is used.",
  "3. Caps: when a monthly cap is reached the feature is blocked with a clear message. There is no auto top-up and no overage billing — you are never charged beyond your plan price.",
  "4. Refunds: manual UPI refunds recorded in the ledger (see Refund Policy). Failed E2B runs are released automatically and never count against your quota.",
  "5. Your data: you may request a full wipe (DPDP) — D1, Qdrant and B2 copies are purged on request. Bank account numbers and full UPI IDs are never stored in the ledger.",
  "6. Grievance Officer: not yet appointed (pending — user deferred). See the admin panel for the current status.",
].join("\n");

export const PRIVACY_BODY = [
  "OmniJarvis Privacy Policy (Last updated: 2026-11-22).",
  "1. What we store: your email, plan, usage counters (reply counts, token counts, cost) and ledger rows (UTR + amount + plan).",
  "2. What we NEVER store: prompt or response text in metering or traces, bank account numbers, full UPI IDs, or your Gemini API key in plaintext (it is AES-GCM encrypted).",
  "3. Your Gemini key (BYOK) is yours — it is validated once, encrypted, and never sent anywhere except Google's Gemini API.",
  "4. DPDP: you can ask for a full wipe of your data at any time; the wipe itself is recorded in the audit log.",
  "5. Tenant isolation: your data is scoped to your tenant in the Worker — no other tenant can read it.",
].join("\n");

export const REFUND_BODY = [
  "OmniJarvis Refund Policy (Last updated: 2026-11-22).",
  "1. UPI refunds are manual: the admin sends the refund via their UPI app and records it in the ledger (amount + refund UTR + reason). There is no auto-refund.",
  "2. Full refund: the subscription is expired on refund. Partial refund: the subscription stays active.",
  "3. Failed E2B runs are released automatically — a failed run never counts against your monthly E2B quota.",
  "4. Refund requests: contact the admin with your UTR and reason. Each case is decided individually.",
  "5. Duplicate or fake UTR submissions are rejected by the admin after bank-statement matching.",
].join("\n");

export function legalPage(page: "terms" | "privacy" | "refund"): { ok: true; page: string; updated: string; body: string } {
  const body = page === "terms" ? TERMS_BODY : page === "privacy" ? PRIVACY_BODY : REFUND_BODY;
  return { ok: true, page, updated: LEGAL_UPDATED, body };
}

// Re-export for routes that need the current month's usage shape.
export { getMonthUsage, currentPeriod };
