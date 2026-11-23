/**
 * cap-warning.ts — 80% cap-warning email (R4.9, U28).
 *
 * Design change (recorded in BUILD_NOTES §6): billing.ts capWarnings()
 * (T-C12) was STATUS-ONLY BY DESIGN — "Cap-warning emails are NOT sent".
 * R4.9 changes that for the replies/mo cap only: when a tenant's
 * replies cross 80% of the plan cap, the owner gets ONE warning email
 * per billing period (Resend, the U-6 live-proven path). One row per
 * tenant+period in cap_warnings (migration 0017) dedupes it; a failed
 * send writes no row, so the next turn retries.
 *
 * Hook: /api/llm/turn-complete in hub.ts calls maybeSendCapWarning()
 * best-effort after completeTurn() — a warning failure never fails the
 * turn. Only replies are watched (e2b/cron/devices stay status-only).
 */
import { getTenant } from "./db";
import type { D1Like } from "./db";
import { sendEmailWithRecord, type EmailEnv } from "./email";
import { currentPeriod, getMonthUsage } from "./metering";
import { PLAN_LIMITS } from "./router";

/** Warn when replies reach this fraction of the plan cap. */
export const CAP_WARNING_THRESHOLD = 0.8;

export function capWarningEmailContent(
  tenantId: string,
  period: string,
  replies: number,
  cap: number,
): { subject: string; html: string; text: string } {
  const pct = Math.round((replies / cap) * 100);
  const subject = `OmniJarvis: ${pct}% of your monthly AI replies used`;
  const text =
    `Hi — your OmniJarvis account (${tenantId}) has used ${replies} of ${cap} AI replies ` +
    `in ${period} (${pct}%). When the cap is reached, AI replies pause until the next month ` +
    `or an upgrade. Check usage in the Jarvis app (AI Brain) or the admin console.`;
  const html = `<p>Hi — your OmniJarvis account (<code>${tenantId}</code>) has used <strong>${replies} of ${cap}</strong> AI replies in ${period} (${pct}%).</p><p>When the cap is reached, AI replies pause until the next month or an upgrade. Check usage in the Jarvis app (AI Brain) or the admin console.</p>`;
  return { subject, html, text };
}

export type CapWarningResult =
  | { sent: true; replies: number; cap: number; period: string; email_send_id: string | null }
  | { sent: false; reason: "below_threshold" | "already_sent" | "no_owner_email" | "tenant_not_found" | "send_failed"; replies: number; cap: number; period: string };

/**
 * Send the 80% warning once per tenant+period. Never throws — every
 * failure mode is a {sent:false} result so the turn-complete hook
 * stays best-effort.
 */
export async function maybeSendCapWarning(
  env: EmailEnv,
  db: D1Like,
  tenantId: string,
  nowMs = Date.now(),
): Promise<CapWarningResult> {
  const period = currentPeriod(nowMs);
  let tenant;
  try {
    tenant = await getTenant(db, tenantId);
  } catch {
    return { sent: false, reason: "tenant_not_found", replies: 0, cap: 0, period };
  }
  if (!tenant) return { sent: false, reason: "tenant_not_found", replies: 0, cap: 0, period };
  const cap = (PLAN_LIMITS[tenant.plan_tier] ?? PLAN_LIMITS.free).replies;
  const usage = await getMonthUsage(db, tenantId, period);
  const replies = usage.replies;
  if (cap <= 0 || replies / cap < CAP_WARNING_THRESHOLD) {
    return { sent: false, reason: "below_threshold", replies, cap, period };
  }
  const ownerEmail = (tenant.owner_email ?? "").trim();
  if (!ownerEmail) return { sent: false, reason: "no_owner_email", replies, cap, period };
  const rowId = `${tenantId}:${period}`;
  const existing = await db
    .prepare("SELECT id FROM cap_warnings WHERE id = ?")
    .bind(rowId)
    .first<{ id: string }>();
  if (existing) return { sent: false, reason: "already_sent", replies, cap, period };
  const content = capWarningEmailContent(tenantId, period, replies, cap);
  let sent;
  try {
    sent = await sendEmailWithRecord(env, db, {
      tenantId,
      kind: "cap_warning",
      to: ownerEmail,
      ...content,
    });
  } catch {
    return { sent: false, reason: "send_failed", replies, cap, period };
  }
  if (!sent.ok) return { sent: false, reason: "send_failed", replies, cap, period };
  await db
    .prepare("INSERT INTO cap_warnings (id, tenant_id, period, replies_at_send, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(rowId, tenantId, period, replies, nowMs)
    .run();
  return { sent: true, replies, cap, period, email_send_id: sent.email_send_id };
}
