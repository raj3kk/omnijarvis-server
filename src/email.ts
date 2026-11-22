/**
 * email.ts — Resend send wiring (open-source completeness #52, U-6).
 *
 * Before this file: NO email send code existed anywhere in the Worker
 * (hub.ts verify-email route stored the token hash + 24h expiry and
 * stopped there; live Phase 4 testing used admin god-mode verify).
 * This module is the send path: env-gated fetch POST to the Resend
 * API — no SDK, no new dependency.
 *
 * Env (Workers secrets / vars — NAMES only, never values):
 * - RESEND_API_KEY (secret): unset = not_configured, sends honestly
 *   refuse; the verify route still stores the token and reports
 *   email:"not_configured" (never fakes a send).
 * - RESEND_FROM (var): sender, e.g. "OmniJarvis <noreply@flow99.in>".
 *   Default is a PLACEHOLDER the parent sets before going live.
 * - RESEND_VERIFY_URL_BASE (var): base URL for the verification link
 *   (default: the live hub host). The link is a GET to
 *   /api/billing/verify-email/confirm?tenant_id=...&token=... — email
 *   links are GET by nature; the POST confirm route is unchanged.
 * - RESEND_DAILY_CAP (var): local daily sent cap, default 100 (Resend
 *   free tier: 3,000/mo, 100/day). Counted from the email_sends table
 *   (status='sent', today). Hitting it returns rate_limited and
 *   records a 'capped' row — it never silently drops a send.
 *
 * Cap / failure handling (hard rule): on 429 or any Resend error the
 * failure is RECORDED in D1 (email_sends row, status failed/capped)
 * and returned honestly; the caller never crashes the request and
 * never claims a send happened. sendEmailWithRecord / the two
 * send*Email helpers never throw for HTTP/fetch failures.
 */
import type { D1Like } from "./db";
import { newBillingId, type SubscriptionRow } from "./billing";
import type { TenantRow } from "./db";

export interface EmailEnv {
  RESEND_API_KEY?: string;
  RESEND_FROM?: string;
  RESEND_VERIFY_URL_BASE?: string;
  RESEND_DAILY_CAP?: string;
}

export const RESEND_API_URL = "https://api.resend.com/emails";

/** Placeholder sender — the parent sets RESEND_FROM before live use. */
export const DEFAULT_FROM = "OmniJarvis <noreply@example.com>";

/** Live hub host — default base for verification links. */
export const DEFAULT_VERIFY_URL_BASE = "https://omnijarvis-hub.rajraj3kk.workers.dev";

/** Resend free tier daily cap (3,000/mo, 100/day). */
export const DEFAULT_DAILY_CAP = 100;

export function isEmailConfigured(env: EmailEnv): boolean {
  return Boolean(env.RESEND_API_KEY);
}

export function dailyCap(env: EmailEnv): number {
  const n = Number(env.RESEND_DAILY_CAP ?? "");
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_DAILY_CAP;
}

export type EmailSendResult =
  | { ok: true; id: string }
  | {
      ok: false;
      error: "not_configured" | "rate_limited" | "resend_error" | "fetch_failed";
      status?: number;
      detail?: string;
    };

export interface SendEmailOpts {
  to: string;
  subject: string;
  html: string;
  text: string;
}

/**
 * Raw Resend send (fetch-only). Returns a discriminated result — never
 * throws on HTTP errors or fetch failures. `detail` is truncated and
 * never contains request headers (the API key is never echoed back).
 */
export async function sendEmail(env: EmailEnv, opts: SendEmailOpts): Promise<EmailSendResult> {
  if (!env.RESEND_API_KEY) return { ok: false, error: "not_configured" };
  let res: Response;
  try {
    res = await fetch(RESEND_API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: env.RESEND_FROM ?? DEFAULT_FROM,
        to: opts.to,
        subject: opts.subject,
        html: opts.html,
        text: opts.text,
      }),
    });
  } catch {
    return { ok: false, error: "fetch_failed" };
  }
  if (res.status === 429) return { ok: false, error: "rate_limited", status: 429 };
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.text()).slice(0, 200);
    } catch {
      detail = "";
    }
    return { ok: false, error: "resend_error", status: res.status, detail };
  }
  let id = "";
  try {
    id = ((await res.json()) as { id?: string }).id ?? "";
  } catch {
    id = "";
  }
  return { ok: true, id };
}

// --- D1 record (email_sends, migration 0009) ---

export type EmailSendStatus = "sent" | "failed" | "capped" | "not_configured";

export async function recordEmailSend(
  db: D1Like,
  opts: {
    tenantId: string;
    kind: string;
    to: string;
    status: EmailSendStatus;
    resendId?: string | null;
    error?: string | null;
    nowMs?: number;
  },
): Promise<string> {
  const id = newBillingId("eml");
  await db
    .prepare(
      "INSERT INTO email_sends (id, tenant_id, kind, to_email, status, resend_id, error, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id, opts.tenantId, opts.kind, opts.to, opts.status, opts.resendId ?? null, opts.error ?? null, opts.nowMs ?? Date.now())
    .run();
  return id;
}

/** Today's sent count for this tenant (local daily-cap guard). */
export async function countSentToday(db: D1Like, tenantId: string, nowMs = Date.now()): Promise<number> {
  const dayStart = nowMs - (nowMs % 86_400_000);
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM email_sends WHERE tenant_id = ? AND status = ? AND created_at >= ?")
    .bind(tenantId, "sent", dayStart)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

export type SendWithRecordResult = EmailSendResult & { email_send_id: string | null };

/**
 * Send + record in D1. Local daily cap is checked BEFORE the fetch
 * (free-tier 100/day): at cap, no fetch happens, a 'capped' row is
 * recorded and rate_limited is returned. A failed record write never
 * masks the send result (email_send_id null, result stands).
 */
export async function sendEmailWithRecord(
  env: EmailEnv,
  db: D1Like,
  opts: SendEmailOpts & { tenantId: string; kind: string },
): Promise<SendWithRecordResult> {
  if (!isEmailConfigured(env)) {
    let id: string | null = null;
    try {
      id = await recordEmailSend(db, { tenantId: opts.tenantId, kind: opts.kind, to: opts.to, status: "not_configured", error: "resend_not_configured" });
    } catch {
      id = null;
    }
    return { ok: false, error: "not_configured", email_send_id: id };
  }
  let sentToday = 0;
  try {
    sentToday = await countSentToday(db, opts.tenantId);
  } catch {
    sentToday = 0;
  }
  if (sentToday >= dailyCap(env)) {
    let id: string | null = null;
    try {
      id = await recordEmailSend(db, { tenantId: opts.tenantId, kind: opts.kind, to: opts.to, status: "capped", error: "local_daily_cap" });
    } catch {
      id = null;
    }
    return { ok: false, error: "rate_limited", detail: "local_daily_cap", email_send_id: id };
  }
  const res = await sendEmail(env, opts);
  let id: string | null = null;
  try {
    id = await recordEmailSend(db, {
      tenantId: opts.tenantId,
      kind: opts.kind,
      to: opts.to,
      status: res.ok ? "sent" : "failed",
      resendId: res.ok ? res.id : null,
      error: res.ok ? null : `${res.error}${res.status ? `:${res.status}` : ""}${res.detail ? ` ${res.detail}` : ""}`.slice(0, 200),
    });
  } catch {
    id = null;
  }
  return { ...res, email_send_id: id };
}

// --- Call site (a): email-verification token send at signup ---

export function verificationEmailContent(verifyUrl: string): { subject: string; html: string; text: string } {
  return {
    subject: "Verify your OmniJarvis email",
    html:
      `<p>Welcome to OmniJarvis. Please verify your email to activate your account:</p>` +
      `<p><a href="${verifyUrl}">Verify my email</a></p>` +
      `<p>This link expires in 24 hours. If you did not sign up, ignore this email.</p>`,
    text:
      `Welcome to OmniJarvis. Verify your email to activate your account:\n${verifyUrl}\n` +
      `This link expires in 24 hours. If you did not sign up, ignore this email.`,
  };
}

/**
 * Verification send. `token` comes from requestEmailVerification's
 * return (caller-only — it is NEVER in an HTTP response). The link is
 * a GET to /api/billing/verify-email/confirm.
 */
export async function sendVerificationEmail(
  env: EmailEnv,
  db: D1Like,
  opts: { tenant: TenantRow; email: string; token: string },
): Promise<SendWithRecordResult> {
  const base = (env.RESEND_VERIFY_URL_BASE ?? DEFAULT_VERIFY_URL_BASE).replace(/\/+$/, "");
  const verifyUrl =
    `${base}/api/billing/verify-email/confirm` +
    `?tenant_id=${encodeURIComponent(opts.tenant.id)}&token=${encodeURIComponent(opts.token)}`;
  const content = verificationEmailContent(verifyUrl);
  return sendEmailWithRecord(env, db, {
    tenantId: opts.tenant.id,
    kind: "email_verification",
    to: opts.email,
    ...content,
  });
}

// --- Call site (b): subscription expiry / renewal reminder ---

export function renewalReminderContent(
  sub: SubscriptionRow,
  window: "7d" | "1d",
): { subject: string; html: string; text: string } {
  const amountInr = (sub.amount_paise / 100).toFixed(2);
  const subject =
    window === "1d"
      ? `Your OmniJarvis ${sub.plan_tier} plan renews tomorrow`
      : `Your OmniJarvis ${sub.plan_tier} plan renews in 7 days`;
  const bodyText =
    `Your OmniJarvis ${sub.plan_tier} plan (${sub.billing_period}) expires on ${sub.expires_at ?? "unknown"}. ` +
    `Amount: ₹${amountInr}. To renew, pay via UPI and submit your 12-digit UTR in the app. ` +
    `If it lapses, your plan drops to Free.`;
  return {
    subject,
    html: `<p>${bodyText}</p>`,
    text: bodyText,
  };
}

/** Renewal reminder send (sweep callback — never throws). */
export async function sendRenewalReminderEmail(
  env: EmailEnv,
  db: D1Like,
  opts: { tenant: TenantRow; subscription: SubscriptionRow; window: "7d" | "1d" },
): Promise<SendWithRecordResult> {
  try {
    const content = renewalReminderContent(opts.subscription, opts.window);
    return await sendEmailWithRecord(env, db, {
      tenantId: opts.tenant.id,
      kind: `renewal_reminder_${opts.window}`,
      to: opts.tenant.owner_email,
      ...content,
    });
  } catch {
    return { ok: false, error: "fetch_failed", email_send_id: null };
  }
}

/** Admin list helper: recent email_sends rows (newest first). The
 * LIMIT is interpolated from a clamped code-side number (FakeD1 and
 * D1 both accept a literal there; it is never user input). */
export async function listEmailSends(
  db: D1Like,
  tenantId?: string,
  limit = 50,
): Promise<Array<Record<string, unknown>>> {
  const n = Math.min(Math.max(Math.floor(limit) || 50, 1), 200);
  const rows = tenantId
    ? await db
        .prepare(`SELECT id, tenant_id, kind, to_email, status, resend_id, error, created_at FROM email_sends WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ${n}`)
        .bind(tenantId)
        .all<Record<string, unknown>>()
    : await db
        .prepare(`SELECT id, tenant_id, kind, to_email, status, resend_id, error, created_at FROM email_sends ORDER BY created_at DESC LIMIT ${n}`)
        .bind()
        .all<Record<string, unknown>>();
  return rows.results ?? [];
}
