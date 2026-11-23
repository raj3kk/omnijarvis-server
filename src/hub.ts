/**
 * omnijarvis-hub — Cloudflare Worker entry (control plane).
 *
 * Stage 2a-2: pairing / sync / cron / WS routes + DO dispatch.
 * Licence routes live in the SEPARATE `jarvis-licence` Worker (Phase 0)
 * — unhe yahan port mat karo.
 *
 * Store: D1 ONLY (D12 reframed 2026-11-21 — Supabase fully removed).
 * Licence keys are verified against the D1 `licences` table; scheduled
 * jobs come from D1 `scheduled_jobs`. No external DB, no service key.
 *
 * Auth summary:
 * - /api/pairing/init: licence-key verified (D1 licences table).
 * - /api/pairing/register: one-time 5-min token (D1 pairing_tokens).
 * - /api/sync: paired device + Ed25519 signature (crypto.ts).
 * - /api/cron/tick: x-cron-secret (constant-time compare).
 * - /ws/:deviceId: paired-device check, then DO (x-expected-device).
 * - /dispatch is DO-internal (x-internal-secret) — not exposed here.
 * - /api/llm/route + /api/llm/turn-complete: x-internal-secret (server-to-server).
 * - /api/tenants/:id/key(+status): x-admin-token (LLM_ADMIN_TOKEN).
 * - /api/tenants/:id/groq-key(+status): same gate, Groq BYOK key (R3).
 * - /api/docs/*: x-internal-secret (agent) OR paired device + Ed25519
 *   signature (3b); Free tier: doc extraction blocked.
 * - /api/browser/*: x-internal-secret (3c); device reports captcha
 *   via signed WS messages (DO), not these routes. Executor default
 *   PhoneWebView; E2B gated, Render refuses (hosting proof FAIL).
 * - /api/captcha/solve: paired device + Ed25519 signature (docs-style
 *   authorizeDocsRequest); D3 LOCKED auto-solver (Gemini/Groq vision
 *   only, caps 2/task + 10/day, audit table captcha_solves). byok_required
 *   is HTTP 402 with ok:false + fallback human_assist; cap_reached is
 *   200 ok:false (a normal outcome, not an HTTP error).
 * - /api/fcm/* (1.12.0): register — paired device + Ed25519 signature
 *   (docs-style authorizeDocsRequest), token upsert into fcm_tokens;
 *   send — x-internal-secret ONLY (admin/cron trigger), service-account
 *   JWT -> FCM v1, audit table fcm_sends; status — x-internal-secret
 *   ONLY, reports whether a device has a token. No device-triggered
 *   send in v1 (no legit use case yet). unset service-account key =
 *   honest not_configured, never a faked send.
 * - /api/skills/submit: paired device + Ed25519 signature (docs-style)
 *   or x-internal-secret; ALWAYS quarantined, never auto-approved (3d).
 * - /api/skills/review: x-admin-token (LLM_ADMIN_TOKEN); approve needs
 *   a clean Render AST scan re-run + Ed25519 sign (SKILL_SIGN_SECRET).
 * - /api/skills/library: approved-only; Free = 1 skill, Pro/Business =
 *   full library. Quarantined skills are never listed (3d).
 * - /api/memory/*: paired device + Ed25519 or x-internal-secret;
 *   D1-backed vector store (JS cosine, cap 2000/tenant, R2.5 D-R16).
 *   Qdrant is env-gated and NOT live (account pending) — D1 fallback (3d).
 *   R2: GET /api/memory/list (pull: memories + approved patterns) and
 *   POST /api/admin/train (admin-only training); new memories push to
 *   the phone over WS (memory_push) with an FCM notice fallback.
 * - /api/billing/*: subscription + UPI flow (Phase 4, UPI-only — no
 *   gateway). subscribe/utr/renew/upgrade/downgrade: paired device or
 *   x-internal-secret; /admin/*: x-admin-token (LLM_ADMIN_TOKEN).
 *   Ledger = D1 batch transactions (GAP-10 fix). Caps hard-enforced.
 *   Email: Resend (#52) — verification send at signup + renewal
 *   reminders from the tick sweep; missing RESEND_API_KEY = honest
 *   not_configured, never a faked send. Backups: B2 (#49) — admin
 *   D1 export + encrypted upload + restore-test (dry-run).
 * - /api/e2b/*: E2B runs (Phase 4) — x-internal-secret; no E2B account
 *   yet (U-4) so runs honestly refuse e2b_not_configured; hold/settle/
 *   release/kill + 15-min auto-kill via the billing sweep.
 * - /api/legal/*: public Terms/Privacy/Refund pages (JSON).
 * - /api/billing/cron-jobs: job create (cap-checked) + list + disable.
 * - /oauth/google/* + /api/google/* (Track E #27): direct Google OAuth
 *   (Gmail read/send + Drive read) — the Nango-free Layer 8 path.
 *   start: signed device, returns {auth_url} (app opens in browser);
 *   callback: one-time D1 state row, exchanges code, stores encrypted
 *   tokens in D1 google_tokens. API routes: paired device + Ed25519
 *   (GET signs path+query, POST signs sortedJson(body)) OR
 *   x-internal-secret + explicit tenant_id. Env-gated on
 *   GOOGLE_OAUTH_CLIENT_ID/SECRET — unset = google_oauth_not_configured.
 */
import { JarvisHub } from "./do/JarvisHub";

export { JarvisHub };

export interface Env {
  JARVIS_HUB: DurableObjectNamespace;
  DB: D1Database;
  INTERNAL_SECRET?: string;
  CRON_SECRET?: string;
  KEY_ENC_SECRET?: string;
  HUB_SIGN_SECRET?: string; // M-4: Ed25519 PKCS8 base64 — hub signs EXECUTE_STEP
  LLM_ADMIN_TOKEN?: string;
  SKILL_SIGN_SECRET?: string; // 3d: Ed25519 PKCS8 base64 — signs approved skills
  SKILL_SIGN_PUBLIC_KEY?: string; // 3d: derived public key (clients verify)
  QDRANT_URL?: string; // 3d: unset = qdrant_not_configured (account pending)
  QDRANT_API_KEY?: string;
  FOUNDER_GEMINI_KEY?: string;
  FOUNDER_GROQ_KEY?: string; // R3: optional founder Groq key ($0 free tier) — founder_pays Groq leg only
  ROUTER_CONFIG?: string;
  WORKER_URL?: string; // v9: doc worker URL (any host); RENDER_WORKER_URL is the legacy fallback
  RENDER_WORKER_URL?: string;
  E2B_API_KEY?: string; // Phase 4: unset = e2b_not_configured (U-4, no account yet)
  GOOGLE_OAUTH_CLIENT_ID?: string; // Track E #27: GCP OAuth client (Web app) — parent-created; unset = google_oauth_not_configured
  GOOGLE_OAUTH_CLIENT_SECRET?: string; // Track E #27: same — never logged/returned
  UPSTASH_REDIS_REST_URL?: string;
  UPSTASH_REDIS_REST_TOKEN?: string;
  LANGFUSE_PUBLIC_KEY?: string;
  LANGFUSE_SECRET_KEY?: string;
  LANGFUSE_HOST?: string;
  LANGFUSE_BASE_URL?: string; // signups.env name; observability.ts prefers HOST, falls back here
  SENTRY_DSN?: string;
  RESEND_API_KEY?: string; // #52: unset = email not_configured (never faked)
  RESEND_FROM?: string; // sender, e.g. "OmniJarvis <noreply@flow99.in>"
  RESEND_VERIFY_URL_BASE?: string; // base for verification links (default: live hub host)
  RESEND_DAILY_CAP?: string; // local daily sent cap, default 100 (free tier)
  FIREBASE_SERVICE_ACCOUNT_JSON?: string; // 1.12.0 FCM: whole service-account JSON as one secret — unset = push not_configured (never faked)
  B2_ENDPOINT?: string; // #49: S3 endpoint, e.g. https://s3.us-west-002.backblazeb2.com
  B2_REGION?: string; // e.g. us-west-002 (derived from endpoint when possible)
  B2_BUCKET?: string;
  B2_KEY_ID?: string;
  B2_APPLICATION_KEY?: string;
  LICENCE_ADMIN_TOKEN?: string; // M-I-28: hub calls the licence Worker generate/release with this (same value as the Worker's own secret — no new secret)
  LICENCE_WORKER_URL?: string; // M-I-28: override, default https://jarvis-licence.rajraj3kk.workers.dev
  LICENCE_WORKER?: Fetcher; // M-I-28: service binding to jarvis-licence (see licenceWorkerCall — workers.dev subrequests 1042)
  GITHUB_ADMIN_TOKEN?: string; // R1 Main Executor: admin GitHub PAT (repo read/write on raj3kk/jarvis-agent-app + raj3kk/omnijarvis-server) — set once by the admin as a Worker secret; unset = Main runs propose-only (dry-run)
}

const SERVICE = "omnijarvis-hub";
const VERSION = "21"; // 21: G-17 observability first-use — Sentry call site + Langfuse OTel rewrite + /api/observability/probe; 20 was R4 models + admin website + FCM triggers

import { consumePairingToken, deriveSixDigit, deriveTenantId, issuePairingToken, registerDevice } from "./pairing";
import { getHubPublicKey, importPrivateKey } from "./crypto";
import { handleSync, type SyncRequest } from "./sync";
import { constantTimeEqual, handleTick, nextCronRun, type DispatchStep } from "./cron";
import { cronLlmSystemPrompt, llmParseCronText, parseNaturalCron } from "./nl-cron";
import {
  LICENCE_CODE_MAX_ATTEMPTS,
  LICENCE_CODE_TTL_MS,
  LICENCE_SESSION_COOKIE,
  LICENCE_SESSION_TTL_MS,
  LICENCE_WORKER_URL_DEFAULT,
  clearSessionCookie,
  hashEmailCode,
  hashSessionToken,
  isValidEmail,
  licenceAdminPage,
  licenceCodeEmailContent,
  licenceDashboardPage,
  licenceLandingPage,
  licenceLoginPage,
  maskLicenceKey,
  newEmailCode,
  newSessionToken,
  normalizeEmail,
  sessionCookie,
  verifyEmailCode,
} from "./licence-web";
// R4: admin website (v1) + Gmail-send idempotency + cap-warning emails.
import {
  OWNER_ADMIN_EMAIL,
  adminDashboardPage,
  adminLoginPage,
  adminOverview,
  ensureOwnerAdmin,
  isAdminUser,
} from "./admin";
import { getIdempotencyRecord, storeIdempotencyRecord } from "./idempotency";
import { maybeSendCapWarning } from "./cap-warning";
import { checkRateLimit, checkUpstashLive, probeUpstashCounter, upstashStatus, type RateLimitResult } from "./ratelimit";
import { d1Batch, getDevice, getTenant, insertKeyAudit, insertTrace, verifyLicenceKey, type D1Like, type TenantRow } from "./db";
import {
  buildCaptchaAssistEvent,
  executeBrowserTask,
  getBrowserTask,
  requestCaptchaAssist,
  resolveCaptchaAssist,
  captchaAssistTrace,
  type AssistOutcome,
  type CaptchaAssistEvent,
} from "./browser";
import { completeTurn, loadRouterConfig, routeLlm, validateGeminiKey, validateGroqKey, type RequestKind } from "./router";
import { encryptTenantKey, importMasterKey } from "./keyvault";
import {
  MAX_SKILL_CODE_BYTES,
  countActiveSkillsByTenant,
  getSkill,
  getSkillPublicKey,
  getSkillSignature,
  insertSkill,
  insertSkillReview,
  insertSkillSignature,
  listApprovedSkills,
  listApprovedSkillsSince,
  manifestHash,
  newSkillId,
  recordUserApproval,
  scanSkillCode,
  selfExtendedTemplateHasUserContent,
  setSkillStatus,
  signSkill,
  classifySkillClass,
  validateResearchCandidate,
  validateSkillManifest,
  type SkillManifest,
} from "./skills";
import {
  MAX_MEMORY_CONTENT_CHARS,
  embedText,
  listMemoriesByKind,
  loadApprovedPatterns,
  qdrantStatus,
  searchMemories,
  storeMemory,
  wipeMemories,
} from "./memory";
import {
  approvePayment,
  capWarnings,
  confirmEmailVerification,
  countEnabledDevices,
  countEnabledJobs,
  createCronJob,
  createSubscription,
  expiryFor,
  getActiveSubscription,
  getAdminSetting,
  getGrievance,
  getLatestSubscription,
  getLaunchGates,
  getOpenSubscription,
  getPayment,
  getSubscription,
  isValidUtr,
  ledgerEventStmt,
  legalPage,
  newBillingId,
  proratedUpgradeCharge,
  purgeOldUsage,
  reconcileBilling,
  recordRefund,
  rejectPayment,
  requestEmailVerification,
  runBillingSweeps,
  setAdminSetting,
  submitUtr,
  subscriptionAmountPaise,
  upiLink,
  wipeTenant,
  type BillingPeriod,
  type PaymentRow,
  type PlanTier,
} from "./billing";
import {
  completeE2BRun,
  e2bThresholdStatus,
  aggregateMarginPaise,
  getE2BRun,
  killE2BRun,
  requestE2BRun,
  totalE2BRunsUsed,
  E2B_HOBBY_RUNWAY_RUNS,
  E2B_MAX_RUN_MS,
  E2B_THRESHOLD_PAISE,
} from "./e2b";
import { getMonthUsage, currentPeriod } from "./metering";
import { planLimits } from "./router";
import { listEmailSends, sendEmail, sendEmailWithRecord, sendRenewalReminderEmail, sendVerificationEmail } from "./email";
import { createTenantBackup, listBackups, restoreTestBackup } from "./backup";
import {
  GoogleError,
  buildAuthUrl,
  calendarCreateEvent,
  calendarListEvents,
  consumeOAuthState,
  driveReadFile,
  driveUploadFile,
  exchangeCodeForTokens,
  fetchGoogleEmail,
  gmailListMessages,
  gmailSend,
  googleRedirectUri,
  googleStatus,
  isGoogleOAuthConfigured,
  issueOAuthState,
  revokeGoogleTokens,
  storeGoogleTokens,
} from "./google";
import { linkSolveOutcome, solveCaptcha, validateSolveRequest } from "./captcha";
import { getFcmRegistration, registerFcmToken, sendFcm } from "./fcm";
import { captureError, isLangfuseConfigured, isSentryConfigured, langfuseHost, trace } from "./observability";
import {
  createPullRequest,
  getFileContent,
  isGitHubConfigured,
  isWriteRepo,
  parseRepoSlug,
} from "./github";
import {
  MAIN_INLINE_STEPS_PER_RUN,
  appendTranscript,
  createMainJob,
  getMainJob,
  parseTranscript,
  runMainStep,
  stepMainJobs,
} from "./main";
import {
  MAX_INGEST_BYTES,
  authorizeDocsRequest,
  canonicalPayload,
  createDocJob,
  docsAllowedForTenant,
  extractStructured,
  forwardToRender,
  getCertificateByHash,
  getDocJob,
  insertCertificate,
  redactFields,
  redactPiiText,
  resolveWorkerBase,
  sha256Hex,
  sha256HexBytes,
  sortedJson,
  updateDocJob,
} from "./docs";

/**
 * Pure route dispatch for health/status/404 (no env access) — vitest
 * se testable hai bina Workers runtime ke. (2a-1 compatibility.)
 */
export function route(path: string): Response {
  const p = path.replace(/\/+$/, "") || "/";
  if (p === "/health") {
    return Response.json({ ok: true, service: SERVICE, version: VERSION });
  }
  if (p === "/") {
    return Response.json({ ok: true, service: SERVICE, version: VERSION });
  }
  return Response.json({ error: "not_found" }, { status: 404 });
}

function json(body: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

/**
 * Fire-and-forget observability that survives the response: register the
 * promise with ctx.waitUntil when the runtime gives us a context (the
 * live Worker fetch path); without one (tests / direct calls) the promise
 * still runs best-effort. G-17: a bare `void trace(...)` in the request
 * path is DROPPED by the runtime once the Response returns — the
 * llm_route trace from a live turn never landed until waitUntil was
 * threaded through. Senders never reject, so an unregistered promise
 * can never become an unhandled rejection.
 */
export function observe(
  ctx: { waitUntil(promise: Promise<unknown>): void } | undefined,
  p: Promise<unknown>,
): void {
  if (ctx) ctx.waitUntil(p);
}

/**
 * Shared 429 for every `checkRateLimit` refusal (M-I-4 follow-up,
 * 2026-11-22): the captcha 429s carried NO Retry-After header, so
 * clients had to guess the 60 s window. Every rate-limited response
 * now carries `Retry-After: <window seconds>` (60 today) plus the
 * existing `x-ratelimit-fallback: 1` marker when the per-isolate
 * fallback enforced it. One helper, all 27+ call sites.
 */
function rateLimited(rl: RateLimitResult): Response {
  return json({ error: "rate_limited" }, 429, {
    "Retry-After": String(rl.retryAfterSec ?? 60),
    ...(rl.fallback ? { "x-ratelimit-fallback": "1" } : {}),
  });
}

function clientIp(request: Request): string {
  return request.headers.get("cf-connecting-ip") ?? "unknown";
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  try {
    return (await request.json()) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/** 3c: deliver a CAPTCHA_ASSIST event to a device's DO (live or queued). */
async function dispatchCaptchaAssist(
  env: Env,
  deviceId: string,
  event: CaptchaAssistEvent,
): Promise<{ sent: boolean }> {
  const id = env.JARVIS_HUB.idFromName(`device:${deviceId}`);
  const stub = env.JARVIS_HUB.get(id);
  const res = await stub.fetch(
    new Request("https://hub/captcha-assist", {
      method: "POST",
      headers: {
        "x-internal-secret": env.INTERNAL_SECRET ?? "",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ device_id: deviceId, event }),
    }),
  );
  if (!res.ok) return { sent: false };
  const body = (await res.json()) as { sent?: boolean };
  return { sent: body.sent === true };
}

/** R2.4: deliver a MEMORY_PUSH event to a device's DO (live or queued),
 * with an FCM notice fallback when the device is not on WS. The event
 * carries NO memory content — only ids/counts; the phone pulls the real
 * rows from GET /api/memory/list. The FCM notice is best-effort (a
 * notice only — execution never comes from FCM) and never throws. */
export interface MemoryPushEvent {
  type: "MEMORY_PUSH";
  tenant_id: string;
  memory_ids: number[];
  patterns_added: number;
  at: number;
}

async function dispatchMemoryPush(
  env: Env,
  tenantId: string,
  deviceId: string,
  event: MemoryPushEvent,
): Promise<{ sent: boolean; fcm: boolean }> {
  try {
    const id = env.JARVIS_HUB.idFromName(`device:${deviceId}`);
    const stub = env.JARVIS_HUB.get(id);
    const res = await stub.fetch(
      new Request("https://hub/memory-push", {
        method: "POST",
        headers: {
          "x-internal-secret": env.INTERNAL_SECRET ?? "",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ device_id: deviceId, event }),
      }),
    );
    if (res.ok) {
      const body = (await res.json()) as { sent?: boolean };
      if (body.sent === true) return { sent: true, fcm: false };
    }
  } catch {
    // DO unreachable — fall through to the FCM notice below.
  }
  try {
    const fcm = await sendFcm(env, env.DB, {
      tenantId,
      deviceId,
      title: "Jarvis ko kuch naya sikhaya gaya",
      body: "Nayi yaadein aayi hain — kholo to dekhoge.",
      kind: "memory_push",
      data: { type: "MEMORY_PUSH" },
    });
    return { sent: false, fcm: fcm.ok };
  } catch {
    return { sent: false, fcm: false };
  }
}

/** R2.4: fan a MEMORY_PUSH out to every enabled device of a tenant.
 * Best-effort per device — one device failing never blocks the others
 * or the train call that triggered it. */
async function fanOutMemoryPush(
  env: Env,
  tenantId: string,
  event: MemoryPushEvent,
): Promise<{ devices: number; ws: number; fcm: number }> {
  let devices = 0;
  let ws = 0;
  let fcm = 0;
  try {
    const rows = await env.DB.prepare(
      "SELECT device_id FROM devices WHERE tenant_id = ? AND enabled = 1",
    )
      .bind(tenantId)
      .all<{ device_id: string }>();
    for (const row of rows.results ?? []) {
      devices++;
      const r = await dispatchMemoryPush(env, tenantId, row.device_id, event);
      if (r.sent) ws++;
      else if (r.fcm) fcm++;
    }
  } catch {
    // Fan-out is best-effort — the train already succeeded.
  }
  return { devices, ws, fcm };
}

/**
 * R2.3: fetch one admin-training URL as plain text. SSRF guard:
 * https only; localhost / private / loopback / link-local hostnames and
 * IP literals are refused (metadata endpoints included). DNS rebinding
 * cannot be checked from inside a Worker (no DNS API) — the primary
 * control is the x-admin-token gate: only the admin can call this
 * route at all. HTML is tag-stripped; PDFs/binaries are refused
 * (use the Trained tab + doc worker for those). 4 MB cap, 15 s timeout.
 */
const TRAIN_FETCH_TIMEOUT_MS = 15_000;

function isTrainUrlBlocked(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h === "metadata.google.internal" || h.endsWith(".local")) return true;
  if (h === "::1" || h === "0.0.0.0") return true;
  const v4 = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }
  if (h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd")) return true;
  return false;
}

function stripHtmlToText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

async function fetchTrainUrl(
  rawUrl: string,
  fetchFn: typeof fetch = fetch,
): Promise<{ ok: true; text: string } | { ok: false; error: string }> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, error: "invalid_url" };
  }
  if (url.protocol !== "https:") return { ok: false, error: "https_only" };
  if (isTrainUrlBlocked(url.hostname)) return { ok: false, error: "blocked_host" };
  let res: Response;
  try {
    res = await fetchFn(url.toString(), { signal: AbortSignal.timeout(TRAIN_FETCH_TIMEOUT_MS) });
  } catch {
    return { ok: false, error: "fetch_failed" };
  }
  if (!res.ok) return { ok: false, error: "fetch_failed" };
  const contentType = res.headers.get("content-type") ?? "";
  if (!/^(text\/|application\/json)/i.test(contentType)) {
    return { ok: false, error: "unsupported_content_type" };
  }
  let buf: ArrayBuffer;
  try {
    buf = await res.arrayBuffer();
  } catch {
    return { ok: false, error: "fetch_failed" };
  }
  if (buf.byteLength > MAX_INGEST_BYTES) return { ok: false, error: "content_too_long" };
  const raw = new TextDecoder().decode(buf);
  const text = /text\/html/i.test(contentType) ? stripHtmlToText(raw) : raw.trim();
  if (!text) return { ok: false, error: "empty_document" };
  return { ok: true, text };
}

/** R2.3: split training text into ≤4000-char chunks on paragraph lines. */
function chunkTrainText(text: string, maxChars = MAX_MEMORY_CONTENT_CHARS): string[] {
  const chunks: string[] = [];
  let current = "";
  for (const para of text.split(/\n+/)) {
    const piece = para.trim();
    if (!piece) continue;
    if (current && current.length + 1 + piece.length > maxChars) {
      chunks.push(current);
      current = piece;
    } else {
      current = current ? `${current}\n${piece}` : piece;
    }
    while (current.length > maxChars) {
      chunks.push(current.slice(0, maxChars));
      current = current.slice(maxChars);
    }
  }
  if (current) chunks.push(current);
  return chunks;
}

function newPatternId(): string {
  const rand = new Uint8Array(4);
  crypto.getRandomValues(rand);
  return `pat-${Date.now().toString(36)}-${[...rand].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

/**
 * Shared cron-tick runner (B-3: GitHub scheduler bypass).
 * Used by BOTH entry points so the behaviour is identical:
 *  - POST /api/cron/tick (GitHub Actions dispatcher, header-secret gated)
 *  - Cloudflare Cron Trigger (scheduled(), Worker's own CRON_SECRET)
 * The tick itself is idempotent (cron.ts: cron_fire trace per job+minute),
 * so a GitHub tick and a Cloudflare tick in the same minute never
 * double-fire a job. Billing sweeps run after the tick in both paths.
 */
/** Owner tenant lookup by email (admin website keys section). */
async function getTenantByOwnerEmail(db: D1Like): Promise<TenantRow | null> {
  const row = await db
    .prepare("SELECT id, owner_email, plan_tier, billing_mode, gemini_key_enc, groq_key_enc, pii_consent, email_verified, pending_downgrade_tier FROM tenants WHERE owner_email = ? LIMIT 1")
    .bind(OWNER_ADMIN_EMAIL)
    .first<TenantRow>();
  return row;
}

export async function runCronTick(
  env: Env,
  source: "http" | "cf-cron",
  cronExpr?: string,
  scheduledTimeMs?: number,
): Promise<Record<string, unknown>> {
  if (source === "cf-cron") {
    await insertTrace(env.DB, "system", "hub", "cron_trigger", {
      source: "cf-cron",
      cron: cronExpr ?? "*/5 * * * *",
      scheduledTime: scheduledTimeMs ?? Date.now(),
    });
  }
  const dispatch: DispatchStep = async (deviceId, step) => {
    const id = env.JARVIS_HUB.idFromName(`device:${deviceId}`);
    const stub = env.JARVIS_HUB.get(id);
    const res = await stub.fetch(
      new Request("https://hub/dispatch", {
        method: "POST",
        headers: {
          "x-internal-secret": env.INTERNAL_SECRET ?? "",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ device_id: deviceId, step }),
      }),
    );
    return res.ok;
  };
  const result = await handleTick(
    env.DB,
    env,
    env.CRON_SECRET ?? null,
    dispatch,
    Date.now(),
    // R4.2 — due-job FCM push (kind "due-job"): when a scheduled job
    // fires, wake/notify the device so the due job is visible even if
    // the WS is down. Best-effort only: a missing device / unconfigured
    // FCM must never fail the tick (sendFcm records the outcome in
    // fcm_sends either way). The DO dispatch above already ran — the
    // push is a notice, not the execution.
    async (job) => {
      try {
        await sendFcm(env, env.DB, {
          tenantId: job.tenant_id,
          deviceId: job.device_id,
          title: "Jarvis — scheduled job due",
          body: job.command.slice(0, 200) || "A scheduled job is due.",
          kind: "due-job",
          data: { job_id: job.id },
        });
      } catch {
        // sendFcm itself never throws for HTTP failures; this guards
        // the record-write path. The tick result stands either way.
      }
    },
  );
  // R1: step pending Main Executor jobs (max 2 per tick, one step each).
  // Best-effort — a Main failure never breaks the tick (traced, the
  // next tick retries after the backoff).
  try {
    await stepMainJobs(env);
  } catch (e) {
    await insertTrace(env.DB, "system", "hub", "main_step_tick_failed", {
      error: String((e as Error)?.message ?? e).slice(0, 200),
    });
  }
  // Billing sweeps run after the tick in both paths. The renewal
  // reminder callback sends the Resend email (best-effort, recorded
  // in email_sends; a failed send never breaks the tick).
  const sweeps = await runBillingSweeps(env.DB, Date.now(), {
    onReminder: async ({ tenant, subscription, window }) => {
      await sendRenewalReminderEmail(env, env.DB, { tenant, subscription, window });
    },
  });
  return { ...result, billing_sweeps: sweeps };
}

export async function handleRequest(
  request: Request,
  env: Env,
  ctx?: { waitUntil(promise: Promise<unknown>): void },
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;
  try {
    // Public: status + health (pure route()).
    if (path === "/" || path === "/health") return route(path);
    // Keep-alive probe (2a-4): REAL checks, not a static ok.
    // - D1 devices: device count (the Worker's core store) — `ok`
    //   reflects D1 only; a D1 failure fails the keepalive-check workflow.
    // - D1 licences: licences-table probe (count) — the licence store
    //   is D1 now (was Supabase tenants before the 2026-11-21 migration).
    if (path === "/api/keepalive" && method === "GET") {
      let d1Ok = false;
      let devices = 0;
      try {
        const count = await env.DB
          .prepare("SELECT COUNT(*) AS n FROM devices")
          .bind()
          .first<{ n: number }>();
        d1Ok = typeof count?.n === "number";
        devices = typeof count?.n === "number" ? count.n : 0;
      } catch {
        d1Ok = false;
      }
      let licencesState = "error";
      let licences = 0;
      try {
        const count = await env.DB
          .prepare("SELECT COUNT(*) AS n FROM licences")
          .bind()
          .first<{ n: number }>();
        licencesState = typeof count?.n === "number" ? "ok" : "error";
        licences = typeof count?.n === "number" ? count.n : 0;
      } catch {
        licencesState = "error";
      }
      return json({
        ok: d1Ok,
        service: SERVICE,
        version: VERSION,
        time: Date.now(),
        checks: {
          d1: { ok: d1Ok, devices },
          licences: { state: licencesState, count: licences },
        },
      });
    }

    // Admin diagnostic (completeness #45): proves the Upstash
    // distributed counter is live — ping + two sequential INCRs on a
    // random, deleted probe key. ADMIN-ONLY (x-admin-token); the
    // response carries no real route quota state, only the probe's
    // own counts. Never a public route.
    if (path === "/api/admin/ratelimit-probe" && method === "POST") {
      if (!env.LLM_ADMIN_TOKEN || request.headers.get("x-admin-token") !== env.LLM_ADMIN_TOKEN) {
        return json({ error: "unauthorized" }, 401);
      }
      const live = await checkUpstashLive(env);
      const probe = live.live
        ? await probeUpstashCounter(env)
        : { ok: false as const, error: "upstash_not_live" };
      return json({
        ok: probe.ok,
        upstash: live,
        probe: probe.ok
          ? { counts: (probe as { counts: number[] }).counts, sequential: true }
          : { error: probe.error },
      });
    }

    // R2.3 U19: admin training — the admin trains Jarvis from the
    // server (Trained tab se ALAG: this is the server-side console
    // path; the website UI lands in R4). ADMIN-ONLY (x-admin-token).
    // Body: {tenant_id, documents: [{title, text?, url?, kind?}],
    // instructions: [{text}]}. Documents are chunked (<=4000 chars)
    // and stored as kind 'admin_training' memories (embedded via the
    // same path as /api/memory/store); instructions become approved
    // learned_patterns rows (source='admin', approved=1 — the admin IS
    // the approver, no queue). Admin wins on conflict and the Talker
    // says so. New memories push to the tenant's devices (WS
    // memory_push, FCM notice fallback). At least one of documents /
    // instructions is required. Caps: 10 docs, 50 instructions,
    // 50 memories per call.
    if (path === "/api/admin/train" && method === "POST") {
      // R4.5: the admin website has no x-admin-token to send — it logs
      // in with the licence-web email-code session. Accept a valid
      // admin session (owner email + is_admin flag) as an alternative
      // to the token gate. The token gate stays for API callers.
      let adminAuthed = !!env.LLM_ADMIN_TOKEN && request.headers.get("x-admin-token") === env.LLM_ADMIN_TOKEN;
      if (!adminAuthed) {
        const cookie = request.headers.get("cookie") ?? "";
        const m = cookie.match(new RegExp(`(?:^|;\\s*)${LICENCE_SESSION_COOKIE}=([^;]+)`));
        if (m) {
          const tokenHash = await hashSessionToken(m[1]);
          const sessRow = await env.DB.prepare("SELECT email, expires_at FROM licence_web_sessions WHERE token_hash = ?")
            .bind(tokenHash)
            .first<{ email: string; expires_at: number }>();
          if (sessRow && sessRow.expires_at >= Date.now() && (await isAdminUser(env.DB, sessRow.email))) {
            adminAuthed = true;
          }
        }
      }
      if (!adminAuthed) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await readJson(request);
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const documents = Array.isArray(body.documents) ? (body.documents as Record<string, unknown>[]) : [];
      const instructions = Array.isArray(body.instructions) ? (body.instructions as Record<string, unknown>[]) : [];
      if (documents.length === 0 && instructions.length === 0) {
        return json({ error: "bad_request", detail: "documents ya instructions chahiye" }, 400);
      }
      if (documents.length > 10) return json({ error: "too_many_documents" }, 400);
      if (instructions.length > 50) return json({ error: "too_many_instructions" }, 400);
      // Resolve every document to text first (no writes yet).
      const texts: string[] = [];
      for (const doc of documents) {
        const title = typeof doc.title === "string" ? doc.title.trim() : "";
        const text = typeof doc.text === "string" ? doc.text.trim() : "";
        const url = typeof doc.url === "string" ? doc.url.trim() : "";
        if (!text && !url) return json({ error: "bad_request", detail: "har document me text ya url chahiye" }, 400);
        if (text) {
          texts.push(title ? `${title}\n${text}` : text);
        } else {
          const fetched = await fetchTrainUrl(url);
          if (!fetched.ok) return json({ error: fetched.error }, 400);
          texts.push(title ? `${title}\n${fetched.text}` : fetched.text);
        }
      }
      const chunks: string[] = [];
      for (const text of texts) {
        for (const chunk of chunkTrainText(text)) {
          if (chunks.length >= 50) return json({ error: "too_many_chunks" }, 400);
          chunks.push(chunk);
        }
      }
      const cleanInstructions: string[] = [];
      for (const inst of instructions) {
        const text = typeof inst.text === "string" ? inst.text.trim() : "";
        if (!text) return json({ error: "bad_request", detail: "khali instruction nahi" }, 400);
        if (text.length > 2000) return json({ error: "instruction_too_long" }, 400);
        cleanInstructions.push(text);
      }
      // Embed + store document chunks (kind 'admin_training' always —
      // Main recall queries this kind; a passed kind is ignored).
      const memoryIds: number[] = [];
      for (let i = 0; i < chunks.length; i++) {
        const emb = await embedText(
          {
            db: env.DB,
            masterKeyB64: env.KEY_ENC_SECRET,
            founderKey: env.FOUNDER_GEMINI_KEY,
            config: loadRouterConfig(env),
          },
          tenantId,
          chunks[i],
          `train-${Date.now()}-${i}`,
        );
        if (!emb.ok) {
          const status =
            emb.error_code === "byok_required" ? 402 : emb.error_code === "tenant_not_found" ? 404 : 502;
          return json({ error: emb.error_code, detail: emb.error }, status);
        }
        memoryIds.push(await storeMemory(env.DB, tenantId, chunks[i], "admin_training", emb.embedding));
      }
      // Instructions -> learned_patterns (insert or bump, admin wins).
      const patternIds: string[] = [];
      const nowMs = Date.now();
      for (const text of cleanInstructions) {
        const hash = await sha256Hex(text);
        const existing = await env.DB.prepare(
          "SELECT id, use_count FROM learned_patterns WHERE template_hash = ?",
        )
          .bind(hash)
          .first<{ id: string; use_count: number }>();
        if (existing) {
          await env.DB.prepare(
            "UPDATE learned_patterns SET use_count = ?, last_seen = ?, approved = ?, source = ? WHERE id = ?",
          )
            .bind((existing.use_count ?? 1) + 1, nowMs, 1, "admin", existing.id)
            .run();
          patternIds.push(existing.id);
        } else {
          const id = newPatternId();
          await env.DB.prepare(
            "INSERT INTO learned_patterns (id, template_hash, template, use_count, first_seen, last_seen, approved, source) VALUES (?, ?, ?, 1, ?, ?, 1, 'admin')",
          )
            .bind(id, hash, text, nowMs, nowMs)
            .run();
          patternIds.push(id);
        }
      }
      await insertTrace(env.DB, tenantId, "", "admin_train", {
        memories_added: memoryIds.length,
        patterns_added: patternIds.length,
      });
      const push = await fanOutMemoryPush(env, tenantId, {
        type: "MEMORY_PUSH",
        tenant_id: tenantId,
        memory_ids: memoryIds,
        patterns_added: patternIds.length,
        at: nowMs,
      });
      return json({
        ok: true,
        tenant_id: tenantId,
        patterns_added: patternIds.length,
        memories_added: memoryIds.length,
        memory_ids: memoryIds,
        pattern_ids: patternIds,
        push,
      });
    }

    // Pairing: init (licence-verified, rate-limited).
    if (path === "/api/pairing/init" && method === "POST") {
      const rl = await checkRateLimit(env, "pairingInit", clientIp(request));
      if (!rl.allowed) return rateLimited(rl);
      const body = await readJson(request);
      const deviceId = typeof body.device_id === "string" ? body.device_id : "";
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      const licenceKey = typeof body.licence_key === "string" ? body.licence_key : "";
      if (!deviceId || !licenceKey) return json({ error: "bad_request" }, 400);
      const licensed = await verifyLicenceKey(env.DB, licenceKey);
      if (!licensed) return json({ error: "licence_invalid" }, 403);
      // 2b-1: tenant_id is OPTIONAL — the app cannot know it (licences
      // has no tenant_id). Derive a stable D1-local label when absent.
      const resolvedTenantId = tenantId || (await deriveTenantId(licenceKey));
      const issued = await issuePairingToken(env.DB, deviceId, resolvedTenantId);
      return json({ ok: true, token: issued.token, code: issued.code, expires_at: issued.expiresAt });
    }

    // Pairing: code derive (second screen match-confirm).
    if (path === "/api/pairing/code" && method === "GET") {
      const token = url.searchParams.get("token") ?? "";
      if (!token) return json({ error: "bad_request" }, 400);
      return json({ ok: true, code: await deriveSixDigit(token) });
    }

    // Pairing: register (one-time token + public key).
    if (path === "/api/pairing/register" && method === "POST") {
      const rl = await checkRateLimit(env, "pairingRegister", clientIp(request));
      if (!rl.allowed) return rateLimited(rl);
      const body = await readJson(request);
      const token = typeof body.token === "string" ? body.token : "";
      const deviceId = typeof body.device_id === "string" ? body.device_id : "";
      const publicKey = typeof body.public_key === "string" ? body.public_key : "";
      if (!token || !deviceId || !publicKey) return json({ error: "bad_request" }, 400);
      const consumed = await consumePairingToken(env.DB, token);
      if (!consumed || consumed.device_id !== deviceId) {
        return json({ error: "token_invalid" }, 403);
      }
      // Phase 4 — devices cap (T-C8/C9) + device-change velocity flag (T-A3).
      // Derived `lic-` tenants have no tenants row — plan defaults to free.
      // Re-register of an already-paired device never counts against the cap.
      const existingDevice = await getDevice(env.DB, deviceId);
      if (!existingDevice || existingDevice.tenant_id !== consumed.tenant_id) {
        const tenantRow = await getTenant(env.DB, consumed.tenant_id);
        const planTier = tenantRow?.plan_tier ?? "free";
        const deviceCount = await countEnabledDevices(env.DB, consumed.tenant_id);
        if (deviceCount >= planLimits(planTier).devices) {
          return json(
            { error: "device_limit", detail: "Device limit khatam — purana device unpair karo ya upgrade karo" },
            403,
          );
        }
        // Velocity flag (trace only — flag ≠ block, licence keeps working).
        const recent = await env.DB
          .prepare("SELECT device_id, paired_at FROM devices WHERE tenant_id = ?")
          .bind(consumed.tenant_id)
          .all<{ device_id: string; paired_at: number }>();
        const distinct30d = new Set(
          (recent.results ?? []).filter((d) => d.paired_at >= Date.now() - 30 * 24 * 60 * 60_000).map((d) => d.device_id),
        );
        if (distinct30d.size >= 4) {
          // This register would be the 5th distinct device in 30 days.
          await insertTrace(env.DB, consumed.tenant_id, deviceId, "device_velocity_flag", {
            device_count_30d: distinct30d.size + 1,
          });
        }
      }
      await registerDevice(env.DB, deviceId, consumed.tenant_id, publicKey);
      // M-4 §4.5: pairing-time hub key delivery (device stores it in
      // EncryptedSharedPreferences; old apps ignore the extra fields).
      // Secret missing/invalid -> fields omitted, pairing still succeeds.
      const hubKey = await getHubPublicKey(env);
      return json({
        ok: true,
        device_id: deviceId,
        ...(hubKey ? { hub_public_key: hubKey.publicKeyB64, key_id: hubKey.keyId } : {}),
      });
    }

    // R4.1 — Pairing AUTO (licence activation me merge): the app
    // generates its Ed25519 keypair locally, then calls this ONE route
    // with the licence key + device id + public key. The hub verifies
    // the licence (same trust as /api/pairing/init, which already
    // issues a token on licence-key alone), resolves the tenant, and
    // registers the device — no 6-digit code for the user to type.
    // The manual code path (/api/pairing/init + /api/pairing/register)
    // stays as the fallback when auto fails. Re-pairing an already
    // paired device is idempotent (registerDevice upserts, no cap hit).
    if (path === "/api/pairing/auto" && method === "POST") {
      const rl = await checkRateLimit(env, "pairingInit", clientIp(request));
      if (!rl.allowed) return rateLimited(rl);
      const body = await readJson(request);
      const deviceId = typeof body.device_id === "string" ? body.device_id : "";
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      const licenceKey = typeof body.licence_key === "string" ? body.licence_key : "";
      const publicKey = typeof body.public_key === "string" ? body.public_key : "";
      if (!deviceId || !licenceKey || !publicKey) return json({ error: "bad_request" }, 400);
      const licensed = await verifyLicenceKey(env.DB, licenceKey);
      if (!licensed) return json({ error: "licence_invalid" }, 403);
      const resolvedTenantId = tenantId || (await deriveTenantId(licenceKey));
      const existingDevice = await getDevice(env.DB, deviceId);
      if (!existingDevice || existingDevice.tenant_id !== resolvedTenantId) {
        const tenantRow = await getTenant(env.DB, resolvedTenantId);
        const planTier = tenantRow?.plan_tier ?? "free";
        const deviceCount = await countEnabledDevices(env.DB, resolvedTenantId);
        if (deviceCount >= planLimits(planTier).devices) {
          return json(
            { error: "device_limit", detail: "Device limit khatam — purana device unpair karo ya upgrade karo" },
            403,
          );
        }
      }
      await registerDevice(env.DB, deviceId, resolvedTenantId, publicKey);
      await insertTrace(env.DB, resolvedTenantId, deviceId, "pairing_auto", { auto: true });
      const hubKey = await getHubPublicKey(env);
      return json({
        ok: true,
        paired: true,
        device_id: deviceId,
        tenant_id: resolvedTenantId,
        ...(hubKey ? { hub_public_key: hubKey.publicKeyB64, key_id: hubKey.keyId } : {}),
      });
    }

    // Sync proxy (paired + signed).
    if (path === "/api/sync" && method === "POST") {
      const body = await readJson(request);
      const deviceId = typeof body.device_id === "string" ? body.device_id : "";
      const rl = await checkRateLimit(env, "sync", deviceId || clientIp(request));
      if (!rl.allowed) return rateLimited(rl);
      const syncReq = body as unknown as SyncRequest;
      if (!deviceId || !syncReq.table || !Array.isArray(syncReq.rows)) {
        return json({ error: "bad_request" }, 400);
      }
      const rawRowsJson = JSON.stringify(syncReq.rows);
      let embedConfig;
      try {
        embedConfig = loadRouterConfig(env);
      } catch {
        embedConfig = undefined;
      }
      const result = await handleSync(env.DB, syncReq, rawRowsJson, {
        db: env.DB,
        masterKeyB64: env.KEY_ENC_SECRET,
        founderKey: env.FOUNDER_GEMINI_KEY,
        config: embedConfig,
      });
      return json(result, result.ok ? 200 : 403);
    }

    // Cron tick (secret-gated). Same runner as the Cloudflare Cron
    // Trigger (B-3) — behaviour identical in both paths.
    if (path === "/api/cron/tick" && method === "POST") {
      if (!env.CRON_SECRET || !constantTimeEqual(request.headers.get("x-cron-secret") ?? "", env.CRON_SECRET)) {
        return json({ error: "unauthorized" }, 401);
      }
      const result = await runCronTick(env, "http");
      return json(result);
    }

    // LLM router (Phase 3, stage 3a) — internal-secret gated, server-to-server only.
    // The phone never calls this directly; hub-internal callers (doc pipeline,
    // browser agent, cron-driven agent steps) call routeLlm() as a function
    // or via this route with the internal secret.
    if (path === "/api/llm/route" && method === "POST") {
      if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await readJson(request);
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      const rl = await checkRateLimit(env, "llmRoute", tenantId || clientIp(request));
      if (!rl.allowed) return rateLimited(rl);
      let config;
      try {
        config = loadRouterConfig(env);
      } catch {
        return json({ error: "router_config_error" }, 500);
      }
      const result = await routeLlm(
        {
          db: env.DB,
          masterKeyB64: env.KEY_ENC_SECRET,
          founderKey: env.FOUNDER_GEMINI_KEY,
          founderGroqKey: env.FOUNDER_GROQ_KEY,
          config,
        },
        {
          tenant_id: tenantId,
          device_id: typeof body.device_id === "string" ? body.device_id : undefined,
          turn_id: typeof body.turn_id === "string" ? body.turn_id : "",
          kind: (typeof body.kind === "string" ? body.kind : "quick_command") as RequestKind,
          messages: Array.isArray(body.messages) ? body.messages : [],
          system: typeof body.system === "string" ? body.system : undefined,
          response_schema:
            body.response_schema && typeof body.response_schema === "object"
              ? (body.response_schema as Record<string, unknown>)
              : undefined,
        },
      );
      if (result.ok) {
        // G-17: one Langfuse trace per successful LLM turn (metadata
        // only — never prompt/response text). Registered with
        // ctx.waitUntil: a bare void call is dropped by the runtime
        // once the Response returns (live-proven: the first llm_route
        // trace never landed).
        observe(
          ctx,
          trace(env, "llm_route", {
            tenant_id: tenantId,
            kind: typeof body.kind === "string" ? body.kind : "quick_command",
            turn_id: typeof body.turn_id === "string" ? body.turn_id : "",
          }),
        );
        return json(result);
      }
      const code = result.error_code ?? "upstream_error";
      const status =
        code === "byok_required"
          ? 402
          : code === "replies_cap" || code === "turn_calls_cap" || code === "plan_docs_not_allowed"
            ? 429
            : code === "tenant_not_found"
              ? 404
              : code === "bad_request" || code === "invalid_key" || code === "live_not_routed"
                ? 400
                : 502;
      return json({ error: code, detail: result.error ?? undefined }, status);
    }

    // LLM turn-complete (internal-secret gated): success => 1 reply counted.
    if (path === "/api/llm/turn-complete" && method === "POST") {
      if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await readJson(request);
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      const turnId = typeof body.turn_id === "string" ? body.turn_id : "";
      if (!tenantId || !turnId || typeof body.success !== "boolean") {
        return json({ error: "bad_request" }, 400);
      }
      await completeTurn(env.DB, tenantId, turnId, body.success);
      // R4.9 — 80% cap-warning email (replies/mo only), best-effort:
      // a warning failure never fails the turn-complete. One email per
      // tenant+period (cap_warnings dedupe in maybeSendCapWarning).
      if (body.success) {
        try {
          await maybeSendCapWarning(env, env.DB, tenantId);
        } catch {
          // Warning is advisory; the turn result stands.
        }
      }
      return json({ ok: true });
    }

    // Tenant BYOK key management (admin-token gated; LLM_ADMIN_TOKEN).
    // Key is validated (tiny Gemini call / Groq models-list call) then
    // AES-GCM encrypted into D1. The key value is NEVER echoed back,
    // logged, or stored plaintext. Groq routes mirror the Gemini ones
    // (R3): /groq-key + /groq-key-status, column tenants.groq_key_enc.
    if (path.startsWith("/api/tenants/") && (path.endsWith("/key") || path.endsWith("/key-status") || path.endsWith("/groq-key") || path.endsWith("/groq-key-status"))) {
      if (!env.LLM_ADMIN_TOKEN || request.headers.get("x-admin-token") !== env.LLM_ADMIN_TOKEN) {
        return json({ error: "unauthorized" }, 401);
      }
      const parts = path.split("/").filter(Boolean); // api, tenants, :id, key[-status] | groq-key[-status]
      const tenantId = parts[2] ?? "";
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const isGroq = path.endsWith("/groq-key") || path.endsWith("/groq-key-status");
      if (method === "GET" && path.endsWith("/key-status")) {
        return json({ ok: true, has_key: !!tenant.gemini_key_enc, billing_mode: tenant.billing_mode });
      }
      if (method === "GET" && path.endsWith("/groq-key-status")) {
        return json({ ok: true, has_groq_key: !!tenant.groq_key_enc });
      }
      if (method === "DELETE" && path.endsWith("/key")) {
        await env.DB.prepare("UPDATE tenants SET gemini_key_enc = NULL WHERE id = ?").bind(tenantId).run();
        // R1 (N-7 fix): every key set/delete writes an audit row (the
        // key VALUE is never recorded — only the fact).
        await insertKeyAudit(env.DB, { tenantId, keyKind: "gemini", action: "delete" });
        return json({ ok: true });
      }
      if (method === "DELETE" && path.endsWith("/groq-key")) {
        await env.DB.prepare("UPDATE tenants SET groq_key_enc = NULL WHERE id = ?").bind(tenantId).run();
        await insertKeyAudit(env.DB, { tenantId, keyKind: "groq", action: "delete" });
        return json({ ok: true });
      }
      if (method === "POST" && (path.endsWith("/key") || path.endsWith("/groq-key"))) {
        const body = await readJson(request);
        const rawKey = isGroq ? body.groq_key : body.gemini_key;
        const key = typeof rawKey === "string" ? rawKey : "";
        const billingMode = typeof body.billing_mode === "string" ? body.billing_mode : tenant.billing_mode;
        if (!key) return json({ error: "bad_request" }, 400);
        if (!isGroq && billingMode === "founder_pays" && !env.FOUNDER_GEMINI_KEY) {
          return json({ error: "founder_pays_not_enabled" }, 400);
        }
        if (!env.KEY_ENC_SECRET) return json({ error: "key_vault_not_configured" }, 500);
        const valid = isGroq ? await validateGroqKey(key) : await validateGeminiKey(key);
        if (!valid) return json({ error: "invalid_key" }, 400);
        const master = await importMasterKey(env.KEY_ENC_SECRET);
        const enc = await encryptTenantKey(master, key);
        if (isGroq) {
          await env.DB.prepare("UPDATE tenants SET groq_key_enc = ? WHERE id = ?").bind(enc, tenantId).run();
          await insertKeyAudit(env.DB, { tenantId, keyKind: "groq", action: "set" });
          return json({ ok: true });
        }
        await env.DB
          .prepare("UPDATE tenants SET gemini_key_enc = ?, billing_mode = ? WHERE id = ?")
          .bind(enc, billingMode, tenantId)
          .run();
        await insertKeyAudit(env.DB, { tenantId, keyKind: "gemini", action: "set" });
        return json({ ok: true, billing_mode: billingMode });
      }
    }

    // --- R1: Main Executor + GitHub proxy (hybrid core) ---
    // Phone-facing routes use docs-style auth: x-internal-secret (agent
    // caller) OR paired device + Ed25519 signature (x-device-id /
    // x-nonce / x-ts / x-signature; POST signs sortedJson(body), GET
    // signs the path). /api/main/run is x-admin-token; /api/main/step
    // is x-internal-secret (cron tick + admin).
    //
    // Token contract (user question 2026-11-23 ~13:00 IST): WITH the
    // admin GitHub token, Main reads repo code, creates branches,
    // commits + pushes fixes, opens PRs, polls CI check-runs, reads
    // failing-check output, and sends the update notice. WITHOUT it,
    // Main runs PROPOSE-ONLY (dry-run): research + draft patch + PR
    // body + evidence bundle, queued — no push, no PR, no authenticated
    // calls. The loop goes live the moment the token is set as a Worker
    // secret, no rebuild.
    if (path === "/api/escalate" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "mainEscalate", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const goal = typeof body.goal === "string" ? body.goal.trim() : "";
      const repo = typeof body.repo === "string" ? body.repo.trim() : "";
      if (!goal || !repo) return json({ error: "bad_request", detail: "goal + repo chahiye" }, 400);
      const created = await createMainJob(env, {
        tenantId,
        deviceId: auth.device_id ?? undefined,
        ask: goal,
        repo,
      });
      if (!created.ok) {
        const status = created.error === "tenant_not_found" ? 404 : created.error === "daily_job_cap" ? 429 : 400;
        return json({ error: created.error, detail: created.detail }, status);
      }
      // Escalation context (what the phone tried, what went wrong) is
      // stored as a transcript entry — the architect reads it with the
      // job. Personal content must already be stripped by the phone;
      // the hub truncates every field to 5,000 chars as a backstop.
      const ctx = ["tried", "error", "need"]
        .map((k) => (typeof body[k] === "string" && body[k].trim() ? `${k}: ${String(body[k]).slice(0, 5000)}` : ""))
        .filter(Boolean)
        .join("\n");
      if (ctx) {
        await appendTranscript(env.DB, created.job, { phase: "escalation", note: ctx });
      }
      return json({ ok: true, job_id: created.job.id, status: created.job.status, mode: created.job.mode });
    }

    if (path.startsWith("/api/main/jobs/") && method === "GET") {
      const jobId = path.split("/").filter(Boolean)[3] ?? "";
      // Admin token sees any job; a device sees only its own tenant's
      // jobs; x-internal-secret callers are admin-equivalent (no tenant
      // scoping — same as the other agent routes).
      const adminOk = !!env.LLM_ADMIN_TOKEN && request.headers.get("x-admin-token") === env.LLM_ADMIN_TOKEN;
      let tenantId: string | undefined;
      if (!adminOk) {
        const auth = await authorizeDocsRequest(env.DB, {
          internalSecret: env.INTERNAL_SECRET,
          internalHeader: request.headers.get("x-internal-secret"),
          deviceId: request.headers.get("x-device-id") ?? "",
          nonce: request.headers.get("x-nonce"),
          ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
          sig: request.headers.get("x-signature"),
          payloadRaw: path,
        });
        if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
        tenantId = auth.tenant_id;
      }
      const job = await getMainJob(env.DB, jobId);
      if (!job) return json({ error: "job_not_found" }, 404);
      if (tenantId && job.tenant_id !== tenantId) return json({ error: "forbidden" }, 403);
      const entries = parseTranscript(job);
      let plan: unknown = null;
      try {
        plan = job.plan ? JSON.parse(job.plan) : null;
      } catch {
        plan = null;
      }
      return json({
        ok: true,
        job: {
          id: job.id,
          tenant_id: job.tenant_id,
          ask: job.ask,
          repo: job.repo,
          base_branch: job.base_branch,
          branch: job.branch,
          status: job.status,
          mode: job.mode,
          pr_url: job.pr_url,
          pr_number: job.pr_number,
          ci_status: job.ci_status,
          scan_verdict: job.scan_verdict,
          llm_calls: job.llm_calls,
          steps_used: job.steps_used,
          retries_used: job.retries_used,
          error: job.error,
          error_code: job.error_code,
          created_at: job.created_at,
          updated_at: job.updated_at,
          plan,
          transcript: entries.slice(-50),
        },
      });
    }

    if (path === "/api/main/run" && method === "POST") {
      if (!env.LLM_ADMIN_TOKEN || request.headers.get("x-admin-token") !== env.LLM_ADMIN_TOKEN) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await readJson(request);
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      const ask = typeof body.ask === "string" ? body.ask : "";
      const repo = typeof body.repo === "string" ? body.repo : "";
      if (!tenantId || !ask || !repo) return json({ error: "bad_request" }, 400);
      const snapshotFiles = Array.isArray(body.snapshot_files)
        ? (body.snapshot_files as { path: string; content: string }[])
        : undefined;
      const created = await createMainJob(env, {
        tenantId,
        deviceId: typeof body.device_id === "string" ? body.device_id : undefined,
        ask,
        repo,
        baseBranch: typeof body.base_branch === "string" ? body.base_branch : undefined,
        snapshotFiles,
      });
      if (!created.ok) {
        const status = created.error === "tenant_not_found" ? 404 : created.error === "daily_job_cap" ? 429 : 400;
        return json({ error: created.error, detail: created.detail }, status);
      }
      // Run up to 3 steps inline (bounded — one step is one LLM call +
      // at most one commit); the cron tick continues the job after.
      let job = created.job;
      let note = "";
      for (let i = 0; i < MAIN_INLINE_STEPS_PER_RUN; i++) {
        const stepped = await runMainStep(env, job.id);
        if (!stepped.ok) {
          note = stepped.detail ?? stepped.error;
          break;
        }
        job = stepped.job;
        note = stepped.note ?? "";
        if (["pr_open", "pr_open_needs_work", "parked", "partial", "failed", "blocked_token"].includes(job.status)) break;
      }
      return json({ ok: true, job_id: job.id, status: job.status, mode: job.mode, note });
    }

    if (path === "/api/main/step" && method === "POST") {
      if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await readJson(request);
      const jobId = typeof body.job_id === "string" ? body.job_id : "";
      if (!jobId) return json({ error: "bad_request" }, 400);
      const stepped = await runMainStep(env, jobId, { resume: body.resume === true });
      if (!stepped.ok) {
        const status =
          stepped.error === "job_not_found"
            ? 404
            : stepped.error === "github_token_not_configured"
              ? 503
              : 400;
        return json({ error: stepped.error, detail: stepped.detail, retryable: stepped.retryable ?? false }, status);
      }
      return json({ ok: true, job_id: stepped.job.id, status: stepped.job.status, mode: stepped.job.mode, note: stepped.note });
    }

    if (path === "/api/github/fetch" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "githubFetch", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const owner = typeof body.owner === "string" ? body.owner : "";
      const repo = typeof body.repo === "string" ? body.repo : "";
      const filePath = typeof body.path === "string" ? body.path : "";
      if (!owner || !repo || !filePath) return json({ error: "bad_request" }, 400);
      const ref = typeof body.ref === "string" ? body.ref : undefined;
      const file = await getFileContent(env, owner, repo, filePath, ref);
      if (!file.ok) {
        const status =
          file.error === "not_found" ? 404 : file.error === "rate_limited" ? 429 : 502;
        return json({ error: file.error, detail: file.detail }, status);
      }
      if (!file.data) return json({ error: "not_found" }, 404);
      return json({ ok: true, content: file.data.content, sha: file.data.sha, size: file.data.size });
    }

    if (path === "/api/github/pr-request" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "githubPr", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const owner = typeof body.owner === "string" ? body.owner : "";
      const repo = typeof body.repo === "string" ? body.repo : "";
      const title = typeof body.title === "string" ? body.title : "";
      const prBody = typeof body.body === "string" ? body.body : "";
      const head = typeof body.head === "string" ? body.head : "";
      const base = typeof body.base === "string" ? body.base : "main";
      if (!owner || !repo || !title || !head) return json({ error: "bad_request" }, 400);
      if (!isWriteRepo(owner, repo)) {
        return json({ error: "repo_not_writable", detail: "PRs only for raj3kk/jarvis-agent-app and raj3kk/omnijarvis-server" }, 403);
      }
      if (!isGitHubConfigured(env)) {
        return json({ error: "github_not_configured", detail: "Admin token set hone tak PR nahi khul sakta — propose-only." }, 503);
      }
      const pr = await createPullRequest(env, owner, repo, {
        title: title.slice(0, 200),
        body: prBody.slice(0, 20000),
        head,
        base,
      });
      if (!pr.ok) {
        const status = pr.error === "not_found" ? 404 : pr.error === "rate_limited" ? 429 : 502;
        return json({ error: pr.error }, status);
      }
      return json({ ok: true, pr_url: pr.data.html_url, pr_number: pr.data.number });
    }

    // --- Doc pipeline (Phase 3, stage 3b) ---
    // Auth: x-internal-secret (agent caller) OR paired device + Ed25519
    // signature (headers x-device-id / x-nonce / x-ts / x-signature).
    // JSON routes sign sortedJson(body); ingest signs the file's sha256.
    // Free tier: doc extraction blocked (ingest + extract double-check).
    // Rate limit: `docs` budget, 30/min/tenant.
    if (path === "/api/docs/verify" || path.startsWith("/api/docs/verify/")) {
      if (method !== "GET") return json({ error: "not_found" }, 404);
      const hash = path.split("/").filter(Boolean).pop() ?? "";
      if (!/^[0-9a-f]{64}$/.test(hash)) return json({ error: "invalid_hash" }, 400);
      const cert = await getCertificateByHash(env.DB, hash);
      if (!cert) return json({ ok: false, valid: false, error: "not_found" }, 404);
      // Public, hash-only lookup — no tenant/device/PII in the response.
      return json({ ok: true, valid: true, hash: cert.payload_hash, created_at: cert.created_at });
    }

    if (path === "/api/docs/ingest" && method === "POST") {
      let form: FormData;
      try {
        form = await request.formData();
      } catch {
        return json({ error: "bad_request" }, 400);
      }
      // form.get() narrows oddly under workers-types (File vs string);
      // cast explicitly — the arrayBuffer check proves it is a File.
      const file = form.get("file") as unknown as File | null;
      if (!file || typeof file.arrayBuffer !== "function") return json({ error: "file_required" }, 400);
      const fileBytes = new Uint8Array(await file.arrayBuffer());
      if (fileBytes.byteLength > MAX_INGEST_BYTES) {
        return json({ error: "file_too_large" }, 413);
      }
      const fileHash = await sha256HexBytes(fileBytes.buffer as ArrayBuffer);
      const deviceId = request.headers.get("x-device-id") ?? (typeof form.get("device_id") === "string" ? (form.get("device_id") as string) : "");
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId,
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: fileHash,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof form.get("tenant_id") === "string" ? (form.get("tenant_id") as string) : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const allowed = await docsAllowedForTenant(env.DB, tenantId);
      if (!allowed.allowed) {
        return json({ error: allowed.error ?? "plan_docs_not_allowed" }, allowed.error === "tenant_not_found" ? 404 : 403);
      }
      const rl = await checkRateLimit(env, "docs", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const isPdf =
        (file.name ?? "").toLowerCase().endsWith(".pdf") ||
        (fileBytes[0] === 0x25 && fileBytes[1] === 0x50 && fileBytes[2] === 0x44 && fileBytes[3] === 0x46);
      const renderPath = isPdf ? "/doc/extract" : "/doc/ocr";
      const fwd = new FormData();
      fwd.append("file", new File([fileBytes], file.name || "upload", { type: file.type || "application/octet-stream" }));
      const render = await forwardToRender(env, renderPath, { method: "POST", body: fwd });
      if (!render.ok) {
        const status = render.error === "render_not_configured" ? 503 : 502;
        return json(
          { error: render.error ?? "render_error", ...(render.warmingUp ? { hint: "render_warming_up" } : {}) },
          status,
        );
      }
      const rj = render.json ?? {};
      const consent = (allowed.tenant?.pii_consent ?? 0) === 1;
      const text = typeof rj.text === "string" ? redactPiiText(rj.text, consent) : "";
      const jobId = await createDocJob(env.DB, {
        tenant_id: tenantId,
        device_id: auth.device_id ?? deviceId,
        kind: isPdf ? "extract" : "ocr",
        source_name: file.name || null,
      });
      await updateDocJob(env.DB, jobId, {
        status: "ingested",
        result_json: JSON.stringify({ pages: rj.pages ?? null, text, tables: rj.tables ?? undefined }),
        confidence: typeof rj.confidence === "number" ? rj.confidence : null,
      });
      return json({
        ok: true,
        doc_job_id: jobId,
        kind: isPdf ? "extract" : "ocr",
        pages: rj.pages ?? null,
        text,
        confidence: typeof rj.confidence === "number" ? rj.confidence : null,
      });
    }

    if (path === "/api/docs/extract" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const allowed = await docsAllowedForTenant(env.DB, tenantId);
      if (!allowed.allowed) {
        return json({ error: allowed.error ?? "plan_docs_not_allowed" }, allowed.error === "tenant_not_found" ? 404 : 403);
      }
      const rl = await checkRateLimit(env, "docs", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const schema = body.schema && typeof body.schema === "object" ? (body.schema as Record<string, unknown>) : { properties: {} };
      let text = typeof body.text === "string" ? body.text : "";
      const docJobId = typeof body.doc_job_id === "number" ? body.doc_job_id : null;
      if (!text && docJobId !== null) {
        const job = await getDocJob(env.DB, docJobId);
        if (!job) return json({ error: "doc_job_not_found" }, 404);
        if (job.tenant_id !== tenantId) return json({ error: "forbidden" }, 403);
        try {
          const prev = JSON.parse(job.result_json ?? "{}") as Record<string, unknown>;
          text = typeof prev.text === "string" ? prev.text : "";
        } catch {
          text = "";
        }
      }
      if (!text) return json({ error: "text_required" }, 400);
      const consent = (allowed.tenant?.pii_consent ?? 0) === 1;
      const result = await extractStructured({
        db: env.DB,
        masterKeyB64: env.KEY_ENC_SECRET,
        founderKey: env.FOUNDER_GEMINI_KEY,
        config: loadRouterConfig(env),
        tenant_id: tenantId,
        device_id: auth.device_id,
        turn_id: typeof body.turn_id === "string" && body.turn_id ? body.turn_id : `doc-${Date.now()}`,
        text,
        schema,
      });
      if (!result.ok) {
        const code = result.error_code ?? "extraction_failed";
        const status =
          code === "byok_required" ? 402 : code === "plan_docs_not_allowed" ? 403 : code === "tenant_not_found" ? 404 : 502;
        return json({ error: code, detail: result.error ?? undefined }, status);
      }
      const fields = redactFields(result.fields ?? {}, consent);
      if (docJobId !== null) {
        await updateDocJob(env.DB, docJobId, {
          status: "extracted",
          result_json: JSON.stringify({ fields, missing: result.missing ?? [] }),
          confidence: result.confidence ?? null,
        });
      }
      return json({ ok: true, doc_job_id: docJobId, fields, missing: result.missing ?? [], confidence: result.confidence ?? 0 });
    }

    if (path === "/api/docs/confirm" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      const docJobId = typeof body.doc_job_id === "number" ? body.doc_job_id : null;
      if (!tenantId || docJobId === null) return json({ error: "bad_request" }, 400);
      const allowed = await docsAllowedForTenant(env.DB, tenantId);
      if (!allowed.allowed) {
        return json({ error: allowed.error ?? "plan_docs_not_allowed" }, allowed.error === "tenant_not_found" ? 404 : 403);
      }
      const job = await getDocJob(env.DB, docJobId);
      if (!job) return json({ error: "doc_job_not_found" }, 404);
      if (job.tenant_id !== tenantId) return json({ error: "forbidden" }, 403);
      const fields = (body.fields && typeof body.fields === "object" ? body.fields : {}) as Record<string, unknown>;
      const corrections = (body.corrections && typeof body.corrections === "object" ? body.corrections : {}) as Record<string, unknown>;
      const merged = { ...fields, ...corrections };
      const required = Array.isArray(body.required)
        ? (body.required as unknown[]).filter((x): x is string => typeof x === "string")
        : Object.keys(merged);
      const missing = required.filter((f) => merged[f] === undefined || merged[f] === null || merged[f] === "");
      const consent = (allowed.tenant?.pii_consent ?? 0) === 1;
      const redacted = redactFields(merged, consent);
      if (missing.length > 0) {
        // One card, one click: missing fields come back WITH the merged
        // record (no piecemeal questions) — client shows one card.
        return json({ ok: false, error: "missing_fields", missing, fields: redacted });
      }
      await updateDocJob(env.DB, docJobId, { status: "confirmed", result_json: JSON.stringify({ fields: redacted }) });
      return json({ ok: true, doc_job_id: docJobId, status: "confirmed", fields: redacted });
    }

    if (path === "/api/docs/certificate" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      const docJobId = typeof body.doc_job_id === "number" ? body.doc_job_id : null;
      if (!tenantId || docJobId === null) return json({ error: "bad_request" }, 400);
      const allowed = await docsAllowedForTenant(env.DB, tenantId);
      if (!allowed.allowed) {
        return json({ error: allowed.error ?? "plan_docs_not_allowed" }, allowed.error === "tenant_not_found" ? 404 : 403);
      }
      const rl = await checkRateLimit(env, "docs", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const job = await getDocJob(env.DB, docJobId);
      if (!job) return json({ error: "doc_job_not_found" }, 404);
      if (job.tenant_id !== tenantId) return json({ error: "forbidden" }, 403);
      if (job.status !== "confirmed") return json({ error: "doc_not_confirmed" }, 409);
      const html = typeof body.html === "string" ? body.html : "";
      if (!html) return json({ error: "html_required" }, 400);
      let payloadObj: Record<string, unknown>;
      try {
        const stored = JSON.parse(job.result_json ?? "{}") as Record<string, unknown>;
        payloadObj =
          body.payload && typeof body.payload === "object"
            ? (body.payload as Record<string, unknown>)
            : ((stored.fields as Record<string, unknown> | undefined) ?? stored);
      } catch {
        return json({ error: "bad_payload" }, 400);
      }
      const consent = (allowed.tenant?.pii_consent ?? 0) === 1;
      const redactedPayload = redactFields(payloadObj as Record<string, unknown>, consent);
      const canonical = canonicalPayload(redactedPayload);
      const hash = await sha256Hex(canonical);
      const verifyUrl = new URL(request.url).origin + "/api/docs/verify";
      const form = new URLSearchParams();
      form.set("html", html);
      form.set("payload", canonical);
      form.set("verify_url", verifyUrl);
      const render = await forwardToRender(env, "/doc/certificate", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      });
      if (!render.ok) {
        const status = render.error === "render_not_configured" ? 503 : 502;
        return json(
          { error: render.error ?? "render_error", ...(render.warmingUp ? { hint: "render_warming_up" } : {}) },
          status,
        );
      }
      const rj = render.json ?? {};
      if (rj.hash && rj.hash !== hash) {
        return json({ error: "hash_mismatch" }, 502);
      }
      if (typeof rj.pdf_base64 !== "string") {
        return json({ error: "render_error" }, 502);
      }
      const pdfUrl = `${resolveWorkerBase(env)}/doc/certificate?hash=${hash}`;
      try {
        await insertCertificate(env.DB, { tenant_id: tenantId, doc_job_id: docJobId, payload_hash: hash, pdf_url: pdfUrl });
      } catch (e) {
        // payload_hash UNIQUE (live D1): duplicate = same certificate —
        // return the existing one instead of failing.
        if (!String((e as Error)?.message ?? e).includes("UNIQUE")) throw e;
      }
      return json({
        ok: true,
        hash,
        pdf_base64: rj.pdf_base64,
        pages: rj.pages ?? null,
        verify_url: `${verifyUrl}/${hash}`,
      });
    }

    // --- Browser agent (Phase 3, stage 3c) ---
    // Executor default PhoneWebView (hosting proof FAIL — Render
    // refuses, E2B gated until an account exists). Internal-secret
    // gated; the device reports captcha via signed WS messages (DO),
    // not these routes. Rate limit: `browser` budget, 30/min/tenant.
    if (path === "/api/browser/task" && method === "POST") {
      if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await readJson(request);
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      const deviceId = typeof body.device_id === "string" ? body.device_id : "";
      const taskName = typeof body.task_name === "string" ? body.task_name : "";
      if (!tenantId || !deviceId || !taskName) return json({ error: "bad_request" }, 400);
      const device = await getDevice(env.DB, deviceId);
      if (!device || device.enabled === 0) return json({ error: "device_not_paired" }, 403);
      const rl = await checkRateLimit(env, "browser", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const result = await executeBrowserTask(env.DB, {
        tenant_id: tenantId,
        device_id: deviceId,
        task_name: taskName,
        site: typeof body.site === "string" ? body.site : null,
        url: typeof body.url === "string" ? body.url : null,
        provider: typeof body.provider === "string" ? body.provider : null,
      });
      if (!result.ok) return json({ error: result.error, detail: result.reason }, 503);
      return json({ ok: true, task_id: result.task_id, provider: result.provider, status: result.status });
    }

    if (path === "/api/browser/assist" && method === "POST") {
      if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await readJson(request);
      const taskId = typeof body.task_id === "string" ? body.task_id : "";
      if (!taskId) return json({ error: "bad_request" }, 400);
      const task = await getBrowserTask(env.DB, taskId);
      if (!task) return json({ error: "task_not_found" }, 404);
      const rl = await checkRateLimit(env, "browser", task.tenant_id);
      if (!rl.allowed) return rateLimited(rl);
      const assist = await requestCaptchaAssist(env.DB, taskId);
      if (!assist.ok) {
        if (assist.error === "task_not_found") return json({ error: "task_not_found" }, 404);
        if (assist.error === "task_closed") return json({ error: "task_closed", status: assist.status }, 409);
        // assist_cap_reached: task auto-paused, NO event is sent.
        await insertTrace(
          env.DB,
          task.tenant_id,
          task.device_id,
          "captcha_assist",
          captchaAssistTrace(task.id, task.site, { outcome: "cap_reached", assist_count: assist.assist_count }),
        );
        return json({
          ok: false,
          error: "assist_cap_reached",
          assist_count: assist.assist_count,
          status: "paused",
        });
      }
      const screenshotB64 = typeof body.screenshot_b64 === "string" ? body.screenshot_b64 : null;
      const { event, screenshotDropped } = buildCaptchaAssistEvent(task, screenshotB64);
      const delivered = await dispatchCaptchaAssist(env, task.device_id, event);
      await insertTrace(
        env.DB,
        task.tenant_id,
        task.device_id,
        "captcha_assist",
        captchaAssistTrace(task.id, task.site, { outcome: "requested", assist_count: assist.assist_count }),
      );
      return json({
        ok: true,
        task_id: taskId,
        assist_count: assist.assist_count,
        status: "awaiting_user",
        delivered: delivered.sent,
        queued: !delivered.sent,
        screenshot_dropped: screenshotDropped,
      });
    }

    if (path === "/api/browser/resolve" && method === "POST") {
      // Human-assist resolution AND captcha solve-outcome link-back (U12).
      // Body: { task_id?, solve_id?, solved: boolean, aborted?, duration_s?,
      //         tenant_id? }. At least one of task_id / solve_id is required.
      // Auth: x-internal-secret (agent) OR a paired device signature — the
      // phone reports the solve outcome itself after submitting the answer.
      // A device caller may only resolve/link rows of its own tenant.
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const taskId = typeof body.task_id === "string" ? body.task_id : "";
      const solveId = typeof body.solve_id === "string" ? body.solve_id : "";
      if ((!taskId && !solveId) || typeof body.solved !== "boolean") return json({ error: "bad_request" }, 400);
      const solved = body.solved === true;
      const tenantId =
        auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      // U12: link the auto-solve outcome back to its solve_id. Only a row
      // still in outcome 'submitted' relinks (idempotent — a second
      // report finds nothing and returns solve_linked:false).
      let solveLinked = false;
      if (solveId) {
        solveLinked = (await linkSolveOutcome(env.DB, solveId, solved, tenantId || undefined)).linked;
      }
      if (!taskId) return json({ ok: true, solve_id: solveId, solve_linked: solveLinked });
      const task = await getBrowserTask(env.DB, taskId);
      if (!task) return json({ error: "task_not_found" }, 404);
      if (auth.tenant_id && task.tenant_id !== auth.tenant_id) {
        return json({ error: "forbidden" }, 403);
      }
      const outcome: AssistOutcome =
        body.aborted === true ? "aborted" : solved ? "solved" : "timeout";
      const res = await resolveCaptchaAssist(env.DB, taskId, outcome);
      if (!res.ok) return json({ error: "task_not_found" }, 404);
      await insertTrace(
        env.DB,
        task.tenant_id,
        task.device_id,
        "captcha_assist",
        captchaAssistTrace(task.id, task.site, {
          solved,
          duration_s: typeof body.duration_s === "number" ? body.duration_s : undefined,
          outcome,
        }),
      );
      return json({ ok: true, task_id: taskId, status: res.status, solve_id: solveId || undefined, solve_linked: solveLinked });
    }

    // --- Captcha auto-solve (D3 LOCKED 2026-11-22, DESIGN §2) ---
    // Device-signed (same pattern as /api/docs/*): the device initiates
    // this call, so x-internal-secret is NOT accepted as the auth —
    // authorizeDocsRequest accepts it for agent callers, and the
    // device path requires the Ed25519 signature. A request without a
    // valid device signature is 401; an unpaired device is 403.
    // The hub runs the vision chain and returns the answer; the device
    // applies it to the live page (the hub never sees a solution token).
    if (path === "/api/captcha/solve" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "captcha_solve", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const validated = validateSolveRequest(body);
      if (!validated.ok) return json({ error: "bad_request" }, 400);
      let config;
      try {
        config = loadRouterConfig(env);
      } catch {
        return json({ error: "router_config_error" }, 500);
      }
      const result = await solveCaptcha(
        {
          db: env.DB,
          masterKeyB64: env.KEY_ENC_SECRET,
          founderKey: env.FOUNDER_GEMINI_KEY,
          founderGroqKey: env.FOUNDER_GROQ_KEY,
          config,
        },
        {
          tenant_id: tenantId,
          device_id: auth.device_id ?? "",
          task_id: validated.value.task_id,
          site: validated.value.site,
          challenge_type: validated.value.challenge_type,
          image_b64: validated.value.image_b64,
        },
      );
      // byok_required is the one failure that is also an HTTP error
      // (402, DESIGN §2.4) — the body still carries ok:false +
      // fallback human_assist so the client treats it as a normal
      // fallback. Every other failure is 200 ok:false.
      if (!result.ok && result.error === "byok_required") return json(result, 402);
      return json(result);
    }

    // --- FCM push (1.12.0) ---
    // Register: the app sends its Firebase registration token after
    // pairing (device-signed, same pattern as captcha/solve). The
    // token is a push address — never logged, never returned.
    if (path === "/api/fcm/register" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const deviceId = auth.device_id ?? "";
      const token = typeof body.fcm_token === "string" ? body.fcm_token : "";
      if (!deviceId || !token || token.length > 4096) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "fcm_register", deviceId);
      if (!rl.allowed) return rateLimited(rl);
      const device = await getDevice(env.DB, deviceId);
      if (!device) return json({ error: "device_not_paired" }, 403);
      await registerFcmToken(env.DB, deviceId, device.tenant_id, token);
      return json({ ok: true, registered: true });
    }

    // Send: internal-secret ONLY (admin test + future cron/job
    // triggers). Device-triggered sends are NOT in v1. Every outcome
    // is 200 ok:false except auth/unpaired/bad-request — a failed
    // send is a normal outcome with a D1 audit row, never a crash.
    if (path === "/api/fcm/send" && method === "POST") {
      if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await readJson(request);
      const deviceId = typeof body.device_id === "string" ? body.device_id : "";
      const title = typeof body.title === "string" ? body.title : "";
      const text = typeof body.body === "string" ? body.body : "";
      const kind = typeof body.kind === "string" ? body.kind : "test";
      if (!deviceId || !title || title.length > 500 || text.length > 500) {
        return json({ error: "bad_request" }, 400);
      }
      const device = await getDevice(env.DB, deviceId);
      if (!device || device.enabled === 0) return json({ error: "device_not_paired" }, 403);
      const rl = await checkRateLimit(env, "fcm_send", deviceId);
      if (!rl.allowed) return rateLimited(rl);
      const data =
        body.data && typeof body.data === "object" && !Array.isArray(body.data)
          ? (body.data as Record<string, unknown>)
          : {};
      const dataStrings: Record<string, string> = {};
      for (const [k, v] of Object.entries(data)) {
        if (typeof v === "string" && k.length <= 64 && v.length <= 500) dataStrings[k] = v;
      }
      const result = await sendFcm(env, env.DB, {
        tenantId: device.tenant_id,
        deviceId,
        title,
        body: text,
        kind,
        data: dataStrings,
      });
      return json(result);
    }

    // Status: internal-secret ONLY — has this device registered a
    // token yet? (Parent-side check before attempting a live send.)
    if (path === "/api/fcm/status" && method === "GET") {
      if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
        return json({ error: "unauthorized" }, 401);
      }
      const deviceId = url.searchParams.get("device_id") ?? "";
      if (!deviceId) return json({ error: "bad_request" }, 400);
      const reg = await getFcmRegistration(env.DB, deviceId);
      return json({
        ok: true,
        device_id: deviceId,
        registered: reg !== null,
        updated_at: reg?.updated_at ?? null,
      });
    }

    // --- Skill registry + memory (Phase 3, stage 3d) ---
    // Skills: submit is ALWAYS quarantined (no auto-approve path exists);
    // review is admin-only (LLM_ADMIN_TOKEN); approve needs a clean Render
    // AST scan re-run + Ed25519 sign (SKILL_SIGN_SECRET). Library is
    // approved-only (Free = 1 skill, Pro/Business = full library).
    // Memory: D1-backed vectors (JS cosine, cap 500/tenant, FIFO evict).
    // Qdrant is env-gated and NOT live — D1 fallback, honest errors.
    if (path === "/api/skills/submit" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const validated = validateSkillManifest(body.manifest);
      if (!validated.ok) return json({ error: "bad_manifest", detail: validated.error }, 400);
      const manifest = validated.manifest;
      // Self-extension (§6.2): template-only strip-check. A self-added
      // skill template may carry step ACTION names only — a step with a
      // target/input is user content and is rejected, never stored.
      if (selfExtendedTemplateHasUserContent(manifest)) {
        return json({ error: "contains_user_content" }, 400);
      }
      // Self-extension (§6.2): validate a carried research candidate.
      const candidateRaw = (manifest as unknown as Record<string, unknown>).researchCandidate;
      if (candidateRaw !== undefined) {
        const candidate = validateResearchCandidate(candidateRaw);
        if (!candidate.ok) {
          return json({ error: "bad_research_candidate", detail: candidate.error }, 400);
        }
      }
      // Self-extension (§6.2): server-side classification mirror, echoed
      // for the audit trail. It is NEVER trusted for approval — submit
      // always lands quarantined below, whatever it says.
      const classification = classifySkillClass(manifest);
      if (
        typeof manifest.code === "string" &&
        new TextEncoder().encode(manifest.code).byteLength > MAX_SKILL_CODE_BYTES
      ) {
        return json({ error: "code_too_large" }, 400);
      }
      const rl = await checkRateLimit(env, "skills", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      // U13 — plan cap on SUBMIT (the library route already caps Free's
      // read at 1 approved skill; this caps how many a tenant may have
      // live at once). Active = quarantined + approved; rejected does
      // not count, so a rejected submitter may try again. Free = 1,
      // Pro/Business = uncapped (planLimits().skills).
      const activeCount = await countActiveSkillsByTenant(env.DB, tenantId);
      if (activeCount >= planLimits(tenant.plan_tier).skills) {
        return json(
          {
            error: "skills_submit_cap",
            detail: `Free plan me 1 skill submit kar sakte ho — pehli skill approve/reject hone ke baad dobara submit karo.`,
            plan_tier: tenant.plan_tier,
            active: activeCount,
          },
          403,
        );
      }
      const skillId = newSkillId();
      const nowMs = Date.now();
      await insertSkill(env.DB, {
        id: skillId,
        manifest: JSON.stringify(manifest),
        submitted_by: tenantId,
        created_at: nowMs,
      });
      // Advisory scan only: a pending scan never blocks the submit.
      const scan = await scanSkillCode(env, typeof manifest.code === "string" ? manifest.code : null);
      await insertTrace(env.DB, tenantId, auth.device_id ?? "", "skill_submit", {
        skill_id: skillId,
        scan_status: scan.status,
        findings_count: scan.findings.length,
        classification: classification.classification,
        classification_reason: classification.reason,
      });
      return json({ ok: true, skill_id: skillId, status: "quarantined", scan, classification });
    }

    if (path === "/api/skills/review" && method === "POST") {
      if (!env.LLM_ADMIN_TOKEN || request.headers.get("x-admin-token") !== env.LLM_ADMIN_TOKEN) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await readJson(request);
      const skillId = typeof body.skill_id === "string" ? body.skill_id : "";
      const decision = typeof body.decision === "string" ? body.decision : "";
      const reason = typeof body.reason === "string" ? body.reason : "";
      const reviewer =
        typeof body.reviewer === "string" && body.reviewer.trim() ? body.reviewer : "admin";
      if (!skillId || (decision !== "approved" && decision !== "rejected")) {
        return json({ error: "bad_request" }, 400);
      }
      if (decision === "rejected" && !reason.trim()) {
        return json({ error: "reason_required" }, 400);
      }
      const rl = await checkRateLimit(env, "skills", "admin");
      if (!rl.allowed) return rateLimited(rl);
      const skill = await getSkill(env.DB, skillId);
      if (!skill) return json({ error: "skill_not_found" }, 404);
      if (skill.status !== "quarantined") {
        return json({ error: "skill_not_quarantined", status: skill.status }, 409);
      }
      let manifest: Record<string, unknown>;
      try {
        manifest = JSON.parse(skill.manifest) as Record<string, unknown>;
      } catch {
        return json({ error: "bad_manifest" }, 500);
      }
      if (decision === "approved") {
        // Authoritative re-scan: approve is BLOCKED unless the scan is
        // provably clean. Render unset -> 503 scan_unavailable.
        const scan = await scanSkillCode(
          env,
          typeof manifest.code === "string" ? manifest.code : null,
        );
        if (scan.status === "pending") {
          return json({ error: "scan_unavailable", detail: scan.error ?? undefined }, 503);
        }
        if (scan.status === "findings") {
          // Blocked attempt, NOT a decision: no review row is written,
          // the skill stays quarantined.
          await insertTrace(env.DB, skill.submitted_by ?? "", "", "skill_review_blocked", {
            skill_id: skillId,
            findings_count: scan.findings.length,
          });
          return json({ error: "scan_findings", findings: scan.findings }, 409);
        }
        if (!env.SKILL_SIGN_SECRET) {
          return json({ error: "skill_sign_not_configured" }, 500);
        }
        let priv: CryptoKey;
        try {
          priv = await importPrivateKey(env.SKILL_SIGN_SECRET);
        } catch {
          return json({ error: "skill_sign_not_configured" }, 500);
        }
        const hash = await manifestHash(manifest as unknown as SkillManifest);
        const signature = await signSkill(priv, skillId, hash);
        const publicKey = await getSkillPublicKey(env);
        if (!publicKey) return json({ error: "skill_sign_not_configured" }, 500);
        const nowMs = Date.now();
        await insertSkillSignature(env.DB, {
          skill_id: skillId,
          signature,
          public_key: publicKey,
          signed_at: nowMs,
        });
        await setSkillStatus(env.DB, skillId, "approved");
        await insertSkillReview(env.DB, {
          skill_id: skillId,
          reviewer,
          decision: "approved",
          reason,
          created_at: nowMs,
        });
        await insertTrace(env.DB, skill.submitted_by ?? "", "", "skill_review", {
          skill_id: skillId,
          decision: "approved",
        });
        // U13 — server→phone push: tell the submitter's latest device the
        // skill was approved, so it can pull it via /api/skills/sync.
        // Best-effort only: the approval is already recorded above, and
        // a missing device / unconfigured FCM must never fail the review.
        try {
          const latestDevice = await env.DB.prepare(
            "SELECT device_id FROM devices WHERE tenant_id = ? AND enabled = 1 ORDER BY last_seen DESC LIMIT 1",
          )
            .bind(skill.submitted_by ?? "")
            .first<{ device_id: string }>();
          if (latestDevice) {
            await sendFcm(env, env.DB, {
              tenantId: skill.submitted_by ?? "",
              deviceId: latestDevice.device_id,
              title: "Skill approved",
              body: "Your skill was approved and is ready to use.",
              kind: "skill_approved",
              data: { skill_id: skillId },
            });
          }
        } catch {
          /* push is advisory; the approval stands either way */
        }
        return json({ ok: true, skill_id: skillId, status: "approved", signature, public_key: publicKey });
      }
      const nowMs = Date.now();
      await setSkillStatus(env.DB, skillId, "rejected");
      await insertSkillReview(env.DB, {
        skill_id: skillId,
        reviewer,
        decision: "rejected",
        reason,
        created_at: nowMs,
      });
      await insertTrace(env.DB, skill.submitted_by ?? "", "", "skill_review", {
        skill_id: skillId,
        decision: "rejected",
      });
      return json({ ok: true, skill_id: skillId, status: "rejected" });
    }

    // R4.11 (U8-SERVER) — device-signed "user approved" signal.
    // The phone's approval card calls this after its phone-side record.
    // It records the user's approval (skill_reviews, decision
    // "user_approved") and NOTHING else: the skill STAYS quarantined —
    // the frozen rule (approve needs a clean Render scan + admin
    // review) is untouched. The admin review queue reads the signal;
    // the phone pulls the outcome via /api/skills/sync after review.
    // Idempotent: the same device approving the same skill twice
    // returns deduped:true with one review row.
    if (path === "/api/skills/approve" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const skillId = typeof body.skill_id === "string" ? body.skill_id : "";
      if (!skillId) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "skills", auth.device_id ?? clientIp(request));
      if (!rl.allowed) return rateLimited(rl);
      const skill = await getSkill(env.DB, skillId);
      if (!skill) return json({ error: "skill_not_found" }, 404);
      const deviceId = auth.device_id ?? "";
      const tenantId = auth.tenant_id ?? skill.submitted_by ?? "";
      const rec = await recordUserApproval(env.DB, { skillId, tenantId, deviceId });
      await insertTrace(env.DB, tenantId, deviceId, "skill_user_approved", { skill_id: skillId, deduped: rec.deduped });
      return json({
        ok: true,
        skill_id: skillId,
        status: skill.status,
        user_approved: true,
        deduped: rec.deduped,
        note: "Recorded. The skill stays quarantined until a clean scan + admin review approves it.",
      });
    }

    if (path === "/api/skills/library" && method === "GET") {
      const tenantId = url.searchParams.get("tenant_id") ?? "";
      // GET has no body: the signed payload is the frozen string
      // `library:<tenant_id>` (docs-style Ed25519, or internal-secret).
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? "",
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: `library:${tenantId}`,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const resolvedTenant = auth.tenant_id ?? tenantId;
      if (!resolvedTenant) return json({ error: "bad_request" }, 400);
      if (auth.tenant_id && tenantId && auth.tenant_id !== tenantId) {
        return json({ error: "forbidden" }, 403);
      }
      const tenant = await getTenant(env.DB, resolvedTenant);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const rl = await checkRateLimit(env, "skills", resolvedTenant);
      if (!rl.allowed) return rateLimited(rl);
      const approved = await listApprovedSkills(env.DB);
      // D2 plan cap: Free = first 1 approved skill; Pro/Business = library.
      const capped = tenant.plan_tier === "free" ? approved.slice(0, 1) : approved;
      const skills: Array<Record<string, unknown>> = [];
      for (const s of capped) {
        let manifestObj: unknown;
        try {
          manifestObj = JSON.parse(s.manifest);
        } catch {
          await insertTrace(env.DB, resolvedTenant, "", "skill_library_skip", { skill_id: s.id });
          continue;
        }
        const sig = await getSkillSignature(env.DB, s.id);
        skills.push({
          id: s.id,
          manifest: manifestObj,
          status: s.status,
          signature: sig?.signature ?? null,
          public_key: sig?.public_key ?? (await getSkillPublicKey(env)),
        });
      }
      return json({ ok: true, plan_tier: tenant.plan_tier, skills, count: skills.length });
    }

    if (path === "/api/skills/sync" && method === "GET") {
      // U13 — server→phone push, pull half: the phone polls this after
      // an approval push (or on a schedule) to fetch newly approved
      // skills without re-pulling the whole library. ?since=<ms> =
      // created_at watermark; 0/absent = all approved skills.
      const tenantId = url.searchParams.get("tenant_id") ?? "";
      const sinceMs = Number(url.searchParams.get("since") ?? "0") || 0;
      // GET has no body: the signed payload is the frozen string
      // `sync:<tenant_id>:<since>` (docs-style Ed25519, or internal-secret).
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? "",
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: `sync:${tenantId}:${sinceMs}`,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const resolvedTenant = auth.tenant_id ?? tenantId;
      if (!resolvedTenant) return json({ error: "bad_request" }, 400);
      if (auth.tenant_id && tenantId && auth.tenant_id !== tenantId) {
        return json({ error: "forbidden" }, 403);
      }
      const tenant = await getTenant(env.DB, resolvedTenant);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const rl = await checkRateLimit(env, "skills", resolvedTenant);
      if (!rl.allowed) return rateLimited(rl);
      const approved = await listApprovedSkillsSince(env.DB, sinceMs);
      const skills: Array<Record<string, unknown>> = [];
      for (const s of approved) {
        let manifestObj: unknown;
        try {
          manifestObj = JSON.parse(s.manifest);
        } catch {
          await insertTrace(env.DB, resolvedTenant, "", "skill_sync_skip", { skill_id: s.id });
          continue;
        }
        const sig = await getSkillSignature(env.DB, s.id);
        skills.push({
          id: s.id,
          manifest: manifestObj,
          status: s.status,
          signature: sig?.signature ?? null,
          public_key: sig?.public_key ?? (await getSkillPublicKey(env)),
          created_at: s.created_at,
        });
      }
      return json({ ok: true, plan_tier: tenant.plan_tier, since: sinceMs, skills, count: skills.length });
    }

    // --- Diagnostics read endpoints (U15, hub v17) ---
    // GET /api/traces — a tenant's own traces, newest first. Device-signed
    // (or internal-secret); a device caller reads only its own tenant.
    // ?kind= filters by trace kind; ?limit= caps the rows (default 50,
    // max 200). Detail is parsed JSON when it parses, else the raw string.
    if (path === "/api/traces" && method === "GET") {
      const tenantId = url.searchParams.get("tenant_id") ?? "";
      const kind = url.searchParams.get("kind") ?? "";
      const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? "50") || 50, 1), 200);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? "",
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: `traces:${tenantId}:${kind}:${limit}`,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const resolvedTenant = auth.tenant_id ?? tenantId;
      if (!resolvedTenant) return json({ error: "bad_request" }, 400);
      if (auth.tenant_id && tenantId && auth.tenant_id !== tenantId) {
        return json({ error: "forbidden" }, 403);
      }
      type TraceRow = { id: number; tenant_id: string; device_id: string; kind: string; detail: string; created_at: number };
      const rows = kind
        ? await env.DB.prepare(
            "SELECT id, tenant_id, device_id, kind, detail, created_at FROM traces WHERE tenant_id = ? AND kind = ? ORDER BY id DESC LIMIT 200",
          )
            .bind(resolvedTenant, kind)
            .all<TraceRow>()
        : await env.DB.prepare(
            "SELECT id, tenant_id, device_id, kind, detail, created_at FROM traces WHERE tenant_id = ? ORDER BY id DESC LIMIT 200",
          )
            .bind(resolvedTenant)
            .all<TraceRow>();
      const traces = (rows.results ?? []).slice(0, limit).map((r) => {
        let detail: unknown = r.detail;
        try {
          detail = JSON.parse(r.detail);
        } catch {
          /* keep the raw string */
        }
        return { id: r.id, tenant_id: r.tenant_id, device_id: r.device_id, kind: r.kind, detail, created_at: r.created_at };
      });
      return json({ ok: true, tenant_id: resolvedTenant, kind: kind || undefined, traces, count: traces.length });
    }

    // GET /api/cron/status — admin: tick health from the system
    // cron_trigger traces + scheduled-job counts. The tick trace is
    // written only for Cloudflare Cron Trigger ticks (source cf-cron);
    // a hub ticked only over HTTP shows last_tick_at stale — that
    // staleness IS the signal (the CF trigger may be down).
    if (path === "/api/cron/status" && method === "GET") {
      if (!env.LLM_ADMIN_TOKEN || request.headers.get("x-admin-token") !== env.LLM_ADMIN_TOKEN) {
        return json({ error: "unauthorized" }, 401);
      }
      const nowMs = Date.now();
      const hourAgo = nowMs - 3_600_000;
      const lastTicks = await env.DB.prepare(
        "SELECT detail, created_at FROM traces WHERE tenant_id = ? AND kind = ? ORDER BY id DESC LIMIT 2",
      )
        .bind("system", "cron_trigger")
        .all<{ detail: string; created_at: number }>();
      const lastTwo = lastTicks.results ?? [];
      const recentTicks = await env.DB.prepare(
        "SELECT created_at FROM traces WHERE tenant_id = ? AND kind = ? AND created_at >= ? ORDER BY id DESC LIMIT 20",
      )
        .bind("system", "cron_trigger", hourAgo)
        .all<{ created_at: number }>();
      const ticksLastHour = (recentTicks.results ?? []).length;
      let lastTickSource: string | null = null;
      if (lastTwo[0]) {
        try {
          const d = JSON.parse(lastTwo[0].detail) as { source?: string };
          lastTickSource = typeof d.source === "string" ? d.source : null;
        } catch {
          lastTickSource = null;
        }
      }
      const cadenceS =
        lastTwo.length >= 2
          ? Math.round((lastTwo[0].created_at - lastTwo[1].created_at) / 1000)
          : null;
      const jobs = await env.DB.prepare("SELECT id, enabled, next_run_at FROM scheduled_jobs").all<{
        id: string;
        enabled: number;
        next_run_at: number | null;
      }>();
      const allJobs = jobs.results ?? [];
      const enabledJobs = allJobs.filter((j) => j.enabled === 1).length;
      const dueJobs = allJobs.filter(
        (j) => j.enabled === 1 && j.next_run_at !== null && j.next_run_at <= nowMs,
      ).length;
      return json({
        ok: true,
        last_tick_at: lastTwo[0]?.created_at ?? null,
        last_tick_source: lastTickSource,
        cadence_s: cadenceS,
        ticks_last_hour: ticksLastHour,
        enabled_jobs: enabledJobs,
        due_jobs: dueJobs,
        total_jobs: allJobs.length,
      });
    }

    // GET /api/observability/status — admin: which external observability
    // sinks are configured (flags only, never keys/DSNs; the Langfuse
    // host is shown only when configured).
    if (path === "/api/observability/status" && method === "GET") {
      if (!env.LLM_ADMIN_TOKEN || request.headers.get("x-admin-token") !== env.LLM_ADMIN_TOKEN) {
        return json({ error: "unauthorized" }, 401);
      }
      const langfuseConfigured = isLangfuseConfigured(env);
      return json({
        ok: true,
        langfuse: { configured: langfuseConfigured, host: langfuseConfigured ? langfuseHost(env) : null },
        sentry: { configured: isSentryConfigured(env) },
        upstash: upstashStatus(env),
      });
    }

    // POST /api/observability/probe — admin: first-use probe (G-17).
    // Awaits one Sentry event + one Langfuse trace through the live
    // senders and returns the vendor-accepted ids (null = not
    // configured, or the vendor rejected the send). ADMIN-ONLY
    // (x-admin-token). No PII: the event is a synthetic probe error,
    // the trace carries only route metadata.
    if (path === "/api/observability/probe" && method === "POST") {
      if (!env.LLM_ADMIN_TOKEN || request.headers.get("x-admin-token") !== env.LLM_ADMIN_TOKEN) {
        return json({ error: "unauthorized" }, 401);
      }
      const [sentryId, traceId] = await Promise.all([
        captureError(env, new Error("observability probe"), {
          route: "observability_probe",
          source: "g17_probe",
        }),
        trace(env, "observability_probe", { route: "observability_probe", source: "g17_probe" }),
      ]);
      return json({
        ok: true,
        sentry: { configured: isSentryConfigured(env), event_id: sentryId },
        langfuse: { configured: isLangfuseConfigured(env), trace_id: traceId },
      });
    }

    if (path === "/api/memory/store" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const content = typeof body.content === "string" ? body.content : "";
      if (!content.trim()) return json({ error: "content_required" }, 400);
      if (content.length > MAX_MEMORY_CONTENT_CHARS) return json({ error: "content_too_long" }, 400);
      const kind = typeof body.kind === "string" && body.kind.trim() ? body.kind : "fact";
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const rl = await checkRateLimit(env, "memory", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const emb = await embedText(
        {
          db: env.DB,
          masterKeyB64: env.KEY_ENC_SECRET,
          founderKey: env.FOUNDER_GEMINI_KEY,
          config: loadRouterConfig(env),
        },
        tenantId,
        content,
        `mem-${Date.now()}`,
      );
      if (!emb.ok) {
        const status =
          emb.error_code === "byok_required"
            ? 402
            : emb.error_code === "tenant_not_found"
              ? 404
              : 502;
        return json({ error: emb.error_code, detail: emb.error }, status);
      }
      const memoryId = await storeMemory(env.DB, tenantId, content, kind, emb.embedding);
      await insertTrace(env.DB, tenantId, auth.device_id ?? "", "memory_store", {
        memory_id: memoryId,
        kind,
      });
      return json({ ok: true, memory_id: memoryId, kind });
    }

    if (path === "/api/memory/search" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const query = typeof body.query === "string" ? body.query : "";
      if (!query.trim()) return json({ error: "query_required" }, 400);
      const topK =
        typeof body.top_k === "number" && Number.isFinite(body.top_k)
          ? Math.min(20, Math.max(1, Math.floor(body.top_k)))
          : 5;
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const rl = await checkRateLimit(env, "memory", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const emb = await embedText(
        {
          db: env.DB,
          masterKeyB64: env.KEY_ENC_SECRET,
          founderKey: env.FOUNDER_GEMINI_KEY,
          config: loadRouterConfig(env),
        },
        tenantId,
        query,
        `mem-${Date.now()}`,
      );
      if (!emb.ok) {
        const status =
          emb.error_code === "byok_required"
            ? 402
            : emb.error_code === "tenant_not_found"
              ? 404
              : 502;
        return json({ error: emb.error_code, detail: emb.error }, status);
      }
      const results = await searchMemories(env.DB, tenantId, emb.embedding, topK);
      return json({ ok: true, results });
    }

    if (path === "/api/memory/wipe" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const rl = await checkRateLimit(env, "memory", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const deleted = await wipeMemories(env.DB, tenantId);
      const q = qdrantStatus(env);
      return json({ ok: true, deleted, qdrant: q.configured ? "configured" : "not_configured" });
    }

    // R2.4 U20: pull endpoint for the phone — memories (newest first,
    // `since` cursor on created_at) + approved learned_patterns (admin
    // first) in one response. Device-signed (authorizeDocsRequest) or
    // x-internal-secret, same as the other /api/memory/* routes. GET has
    // no body: the signed payload is the frozen string
    // `memory-list:<tenant_id>:<since>:<limit>` (same shape as
    // /api/skills/sync). The phone calls this on start, after a
    // memory_push notice, and on Trained-tab refresh. No embeddings
    // here — plain D1 reads.
    if (path === "/api/memory/list" && method === "GET") {
      const tenantId = url.searchParams.get("tenant_id") ?? "";
      const sinceRaw = Number(url.searchParams.get("since") ?? "0");
      const since = Number.isFinite(sinceRaw) && sinceRaw > 0 ? Math.floor(sinceRaw) : 0;
      const limitRaw = Number(url.searchParams.get("limit") ?? "50");
      const limit = Number.isFinite(limitRaw) ? Math.min(200, Math.max(1, Math.floor(limitRaw))) : 50;
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? "",
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: `memory-list:${tenantId}:${since}:${limit}`,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const resolvedTenant = auth.tenant_id ?? tenantId;
      if (!resolvedTenant) return json({ error: "bad_request" }, 400);
      if (auth.tenant_id && tenantId && auth.tenant_id !== tenantId) {
        return json({ error: "forbidden" }, 403);
      }
      const tenant = await getTenant(env.DB, resolvedTenant);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const rl = await checkRateLimit(env, "memory", resolvedTenant);
      if (!rl.allowed) return rateLimited(rl);
      const memRes = await env.DB.prepare(
        "SELECT id, content, kind, created_at FROM memories WHERE tenant_id = ? AND created_at > ? ORDER BY created_at DESC LIMIT ?",
      )
        .bind(resolvedTenant, since, limit)
        .all<{ id: number; content: string; kind: string; created_at: number }>();
      const patterns = await loadApprovedPatterns(env.DB, 20);
      return json({
        ok: true,
        memories: (memRes.results ?? []).map((r) => ({ id: r.id, content: r.content, kind: r.kind, created_at: r.created_at })),
        patterns: patterns.map((p) => ({ id: p.id, template: p.template, source: p.source, use_count: p.use_count })),
        since,
      });
    }

    // --- Billing (Phase 4) — subscription + UPI + D1 ledger + caps ---
    // UPI-only (D7): pay → UTR submit → admin approve → ACTIVE. No gateway.
    // Ledger writes are D1 batches (GAP-10). Launch GATED — these routes
    // implement the flow; no paid customer is ever created by this code.
    const billingAuth = async (body: Record<string, unknown>) =>
      authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
    const isBillingAdmin = (): boolean =>
      !!env.LLM_ADMIN_TOKEN && request.headers.get("x-admin-token") === env.LLM_ADMIN_TOKEN;

    if (path === "/api/billing/subscribe" && method === "POST") {
      const body = await readJson(request);
      const auth = await billingAuth(body);
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const rl = await checkRateLimit(env, "billing", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      if (tenant.email_verified !== 1) return json({ error: "email_not_verified" }, 403);
      const planTier = typeof body.plan_tier === "string" ? body.plan_tier : "";
      const period = typeof body.billing_period === "string" ? body.billing_period : "";
      if ((planTier !== "pro" && planTier !== "business") || (period !== "monthly" && period !== "annual")) {
        return json({ error: "bad_request" }, 400);
      }
      const open = await getOpenSubscription(env.DB, tenantId);
      if (open) return json({ error: "subscription_exists", subscription_id: open.id, status: open.status }, 409);
      const vpa = await getAdminSetting(env.DB, "upi_vpa");
      if (!vpa) return json({ error: "upi_vpa_not_configured" }, 503);
      const amount = subscriptionAmountPaise(planTier as PlanTier, period as BillingPeriod);
      const sub = await createSubscription(env.DB, {
        tenant_id: tenantId,
        plan_tier: planTier as PlanTier,
        billing_period: period as BillingPeriod,
        amount_paise: amount,
      });
      return json({
        ok: true,
        subscription_id: sub.id,
        plan_tier: planTier,
        billing_period: period,
        amount_paise: amount,
        upi_link: upiLink(vpa, amount, planTier as PlanTier, period as BillingPeriod),
        status: "pending_payment",
        utr_expires_at: new Date(Date.parse(sub.created_at) + 24 * 60 * 60 * 1000).toISOString(),
      });
    }

    if (path === "/api/billing/utr" && method === "POST") {
      const body = await readJson(request);
      const auth = await billingAuth(body);
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const subscriptionId = typeof body.subscription_id === "string" ? body.subscription_id : "";
      const utr = typeof body.utr === "string" ? body.utr : "";
      if (!subscriptionId || !utr) return json({ error: "bad_request" }, 400);
      // Amount is auto-filled from the subscription (never client-editable):
      // a caller-supplied amount that differs is a mismatch, not a payment.
      const sub = await getSubscription(env.DB, subscriptionId);
      if (!sub) return json({ error: "subscription_not_found" }, 404);
      if (typeof body.amount_paise === "number" && body.amount_paise !== sub.amount_paise) {
        return json({ error: "amount_mismatch" }, 400);
      }
      const tenantId = auth.tenant_id ?? sub.tenant_id;
      if (auth.tenant_id && auth.tenant_id !== sub.tenant_id) return json({ error: "forbidden" }, 403);
      const rl = await checkRateLimit(env, "billing", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const res = await submitUtr(env.DB, {
        subscription: sub,
        utr,
        note: typeof body.note === "string" ? body.note : null,
        payment_date: typeof body.payment_date === "string" ? body.payment_date : null,
      });
      if (!res.ok) {
        const status = res.error === "invalid_utr" ? 400 : 409;
        return json({ error: res.error }, status);
      }
      return json({ ok: true, payment_id: res.payment_id, status: "utr_submitted" });
    }

    if (path === "/api/billing/admin/approve" && method === "POST") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const body = await readJson(request);
      const paymentId = typeof body.payment_id === "string" ? body.payment_id : "";
      const admin = typeof body.admin === "string" && body.admin.trim() ? body.admin : "admin";
      if (!paymentId) return json({ error: "bad_request" }, 400);
      const payment = await getPayment(env.DB, paymentId);
      if (!payment) return json({ error: "payment_not_found" }, 404);
      const sub = await getSubscription(env.DB, payment.subscription_id);
      if (!sub) return json({ error: "subscription_not_found" }, 404);
      const rl = await checkRateLimit(env, "billingAdmin", "admin");
      if (!rl.allowed) return rateLimited(rl);
      const res = await approvePayment(env.DB, { payment, subscription: sub, admin });
      if (!res.ok) return json({ error: res.error }, 409);
      if (res.already) {
        await insertTrace(env.DB, sub.tenant_id, "", "billing_approve_noop", { payment_id: paymentId });
        return json({ ok: true, already: true, subscription_id: sub.id, status: "active", expires_at: res.expires_at });
      }
      return json({ ok: true, subscription_id: sub.id, status: "active", plan_tier: sub.plan_tier, expires_at: res.expires_at });
    }

    if (path === "/api/billing/admin/reject" && method === "POST") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const body = await readJson(request);
      const paymentId = typeof body.payment_id === "string" ? body.payment_id : "";
      const reason = typeof body.reason === "string" ? body.reason : "";
      const admin = typeof body.admin === "string" && body.admin.trim() ? body.admin : "admin";
      if (!paymentId || !reason.trim()) return json({ error: !paymentId ? "bad_request" : "reason_required" }, 400);
      const payment = await getPayment(env.DB, paymentId);
      if (!payment) return json({ error: "payment_not_found" }, 404);
      const sub = await getSubscription(env.DB, payment.subscription_id);
      if (!sub) return json({ error: "subscription_not_found" }, 404);
      const res = await rejectPayment(env.DB, { payment, subscription: sub, admin, reason });
      if (!res.ok) return json({ error: res.error }, 409);
      return json({ ok: true, subscription_id: sub.id, status: "rejected" });
    }

    if (path === "/api/billing/status" && method === "GET") {
      const tenantId = url.searchParams.get("tenant_id") ?? "";
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? "",
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: `billing-status:${tenantId}`,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const resolvedTenant = auth.tenant_id ?? tenantId;
      if (!resolvedTenant) return json({ error: "bad_request" }, 400);
      if (auth.tenant_id && tenantId && auth.tenant_id !== tenantId) return json({ error: "forbidden" }, 403);
      const tenant = await getTenant(env.DB, resolvedTenant);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const period = currentPeriod(Date.now());
      const usage = await getMonthUsage(env.DB, resolvedTenant, period);
      const limits = planLimits(tenant.plan_tier);
      const warnings = capWarnings(
        {
          replies: usage.replies,
          e2b_runs: usage.e2b_runs,
          cron_jobs: await countEnabledJobs(env.DB, resolvedTenant),
          devices: await countEnabledDevices(env.DB, resolvedTenant),
        },
        tenant.plan_tier,
      );
      const active = await getActiveSubscription(env.DB, resolvedTenant);
      const latest = active ?? (await getLatestSubscription(env.DB, resolvedTenant));
      const renewalDue =
        !!active?.expires_at &&
        Date.parse(active.expires_at) - Date.now() <= 7 * 24 * 60 * 60 * 1000 &&
        Date.parse(active.expires_at) > Date.now();
      return json({
        ok: true,
        plan_tier: tenant.plan_tier,
        subscription: latest
          ? {
              id: latest.id,
              plan_tier: latest.plan_tier,
              billing_period: latest.billing_period,
              status: latest.status,
              amount_paise: latest.amount_paise,
              starts_at: latest.starts_at,
              expires_at: latest.expires_at,
            }
          : null,
        usage: {
          replies: usage.replies,
          e2b_runs: usage.e2b_runs,
          llm_calls: usage.llm_calls,
          cost_usd_micro: usage.cost_usd_micro,
          period,
        },
        limits,
        warnings,
        renewal_reminder_due: renewalDue,
        pending_downgrade_tier: tenant.pending_downgrade_tier ?? null,
      });
    }

    if (path === "/api/billing/renew" && method === "POST") {
      const body = await readJson(request);
      const auth = await billingAuth(body);
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const latest = await getLatestSubscription(env.DB, tenantId);
      if (!latest || latest.plan_tier === "free") return json({ error: "nothing_to_renew" }, 400);
      const active = await getActiveSubscription(env.DB, tenantId);
      if (active?.expires_at && Date.parse(active.expires_at) - Date.now() > 7 * 24 * 60 * 60 * 1000) {
        return json({ error: "subscription_active" }, 409);
      }
      const open = await getOpenSubscription(env.DB, tenantId);
      if (open) return json({ error: "subscription_exists", subscription_id: open.id }, 409);
      const vpa = await getAdminSetting(env.DB, "upi_vpa");
      if (!vpa) return json({ error: "upi_vpa_not_configured" }, 503);
      const amount = subscriptionAmountPaise(latest.plan_tier as PlanTier, latest.billing_period as BillingPeriod);
      const sub = await createSubscription(env.DB, {
        tenant_id: tenantId,
        plan_tier: latest.plan_tier as PlanTier,
        billing_period: latest.billing_period as BillingPeriod,
        amount_paise: amount,
      });
      // Renew = same plan continues — a pending downgrade request is withdrawn.
      await env.DB.prepare("UPDATE tenants SET pending_downgrade_tier = NULL WHERE id = ?").bind(tenantId).run();
      return json({
        ok: true,
        subscription_id: sub.id,
        plan_tier: latest.plan_tier,
        billing_period: latest.billing_period,
        amount_paise: amount,
        upi_link: upiLink(vpa, amount, latest.plan_tier as PlanTier, latest.billing_period as BillingPeriod),
        status: "pending_payment",
      });
    }

    if (path === "/api/billing/upgrade" && method === "POST") {
      const body = await readJson(request);
      const auth = await billingAuth(body);
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      const toTier = typeof body.to_tier === "string" ? body.to_tier : "";
      if (!tenantId || toTier !== "business") return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const active = await getActiveSubscription(env.DB, tenantId);
      if (!active || active.plan_tier !== "pro" || !active.starts_at || !active.expires_at) {
        return json({ error: "subscription_not_active" }, 409);
      }
      const open = await getOpenSubscription(env.DB, tenantId);
      if (open) return json({ error: "subscription_exists", subscription_id: open.id }, 409);
      const vpa = await getAdminSetting(env.DB, "upi_vpa");
      if (!vpa) return json({ error: "upi_vpa_not_configured" }, 503);
      const newPrice = subscriptionAmountPaise("business", active.billing_period as BillingPeriod);
      const { remaining_paise, charge_paise } = proratedUpgradeCharge(
        active.amount_paise,
        active.starts_at,
        active.expires_at,
        newPrice,
      );
      const sub = await createSubscription(env.DB, {
        tenant_id: tenantId,
        plan_tier: "business",
        billing_period: active.billing_period as BillingPeriod,
        amount_paise: charge_paise,
      });
      await insertTrace(env.DB, tenantId, "", "billing_upgrade", {
        from_tier: "pro",
        to_tier: "business",
        remaining_paise,
        charge_paise,
        subscription_id: sub.id,
      });
      return json({
        ok: true,
        subscription_id: sub.id,
        plan_tier: "business",
        billing_period: active.billing_period,
        amount_paise: charge_paise,
        prorated_amount_paise: charge_paise,
        remaining_paise,
        upi_link: upiLink(vpa, charge_paise, "business", active.billing_period as BillingPeriod),
        status: "pending_payment",
      });
    }

    if (path === "/api/billing/downgrade" && method === "POST") {
      const body = await readJson(request);
      const auth = await billingAuth(body);
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      const toTier = typeof body.to_tier === "string" ? body.to_tier : "";
      if (!tenantId || (toTier !== "pro" && toTier !== "free")) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const rank: Record<string, number> = { free: 0, pro: 1, business: 2 };
      if ((rank[toTier] ?? 0) >= (rank[tenant.plan_tier] ?? 0)) {
        return json({ error: "not_a_downgrade" }, 400);
      }
      // Downgrade is next-cycle only (immediate nahi) — current cycle
      // keeps running on the old plan; the sweep applies it at expiry.
      await d1Batch(env.DB, [
        env.DB.prepare("UPDATE tenants SET pending_downgrade_tier = ? WHERE id = ?").bind(toTier, tenantId),
        ledgerEventStmt(env.DB, tenantId, "downgraded", { from_tier: tenant.plan_tier, to_tier: toTier, effective: "next_cycle" }, "customer"),
      ]);
      return json({ ok: true, pending_downgrade_tier: toTier, effective: "next_cycle" });
    }

    if (path === "/api/billing/refund" && method === "POST") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const body = await readJson(request);
      const paymentId = typeof body.payment_id === "string" ? body.payment_id : "";
      const refundUtr = typeof body.refund_utr === "string" ? body.refund_utr : "";
      const reason = typeof body.reason === "string" ? body.reason : "";
      const admin = typeof body.admin === "string" && body.admin.trim() ? body.admin : "admin";
      if (!paymentId || !refundUtr || !reason.trim()) return json({ error: "bad_request" }, 400);
      if (!isValidUtr(refundUtr)) return json({ error: "invalid_utr" }, 400);
      const payment = await getPayment(env.DB, paymentId);
      if (!payment) return json({ error: "payment_not_found" }, 404);
      const sub = await getSubscription(env.DB, payment.subscription_id);
      if (!sub) return json({ error: "subscription_not_found" }, 404);
      const amount = typeof body.amount_paise === "number" ? body.amount_paise : payment.amount_paise;
      const res = await recordRefund(env.DB, {
        payment,
        subscription: sub,
        refund_utr: refundUtr,
        amount_paise: amount,
        reason,
        admin,
      });
      if (!res.ok) return json({ error: res.error }, res.error === "payment_not_approved" ? 409 : 400);
      if (amount === payment.amount_paise && sub.status === "active") {
        await env.DB.prepare("UPDATE tenants SET plan_tier = ? WHERE id = ?").bind("free", payment.tenant_id).run();
      }
      return json({ ok: true, refund_id: res.refund_id });
    }

    if (path === "/api/billing/verify-email/request" && method === "POST") {
      const body = await readJson(request);
      const auth = await billingAuth(body);
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      const email = typeof body.email === "string" ? body.email : "";
      if (!tenantId || !email.includes("@")) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const res = await requestEmailVerification(env.DB, { tenant, email });
      if (!res.ok) return json({ error: res.error }, res.error === "already_verified" ? 409 : 400);
      // Resend send (#52): the token goes to the email ONLY — it is
      // never in this response. email:"not_configured" when no
      // RESEND_API_KEY (honest; token stays pending, god-mode verify
      // still exists); email:"failed" on cap/429 (recorded in D1).
      const sent = await sendVerificationEmail(env, env.DB, { tenant, email, token: res.token });
      return json({
        ok: true,
        verification_pending: true,
        email: sent.ok ? "sent" : sent.error === "not_configured" ? "not_configured" : "failed",
        ...(sent.ok ? {} : { email_error: sent.error }),
      });
    }

    // GET confirm: the email link target (links are GET by nature).
    // Same confirmEmailVerification as the POST route — token is a
    // one-time 24h hash-checked token, never logged or stored plaintext.
    if (path === "/api/billing/verify-email/confirm" && method === "GET") {
      const url = new URL(request.url);
      const tenantId = url.searchParams.get("tenant_id") ?? "";
      const token = url.searchParams.get("token") ?? "";
      if (!tenantId || !token) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const res = await confirmEmailVerification(env.DB, { tenant, token });
      if (!res.ok) return json({ error: res.error }, 400);
      return json({ ok: true, email_verified: true });
    }

    if (path === "/api/billing/verify-email/confirm" && method === "POST") {
      const body = await readJson(request);
      const auth = await billingAuth(body);
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      const token = typeof body.token === "string" ? body.token : "";
      if (!tenantId || !token) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const res = await confirmEmailVerification(env.DB, { tenant, token });
      if (!res.ok) return json({ error: res.error }, 400);
      return json({ ok: true, email_verified: true });
    }

    if (path === "/api/billing/wipe" && method === "POST") {
      const body = await readJson(request);
      let tenantId = "";
      if (isBillingAdmin()) {
        tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      } else {
        const auth = await billingAuth(body);
        if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
        tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
        if (auth.tenant_id && tenantId && auth.tenant_id !== tenantId) return json({ error: "forbidden" }, 403);
      }
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const res = await wipeTenant(env.DB, tenantId);
      return json({ ok: true, deleted: res.counts, qdrant: res.qdrant, b2: res.b2 });
    }

    // --- Admin panel (API — no HTML UI; server-only scope) ---
    if (path === "/api/billing/admin/pending" && method === "GET") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const rows = await env.DB
        .prepare("SELECT id, subscription_id, tenant_id, utr, amount_paise, method, status, admin_note, created_at FROM payments WHERE status = ? ORDER BY created_at ASC")
        .bind("submitted")
        .all<PaymentRow>();
      const pending: Array<Record<string, unknown>> = [];
      for (const p of rows.results ?? []) {
        const tenant = await getTenant(env.DB, p.tenant_id);
        pending.push({
          payment_id: p.id,
          subscription_id: p.subscription_id,
          tenant_id: p.tenant_id,
          owner_email: tenant?.owner_email ?? null,
          utr: p.utr,
          amount_paise: p.amount_paise,
          note: p.admin_note,
          created_at: p.created_at,
        });
      }
      return json({ ok: true, pending, count: pending.length });
    }

    if (path === "/api/billing/admin/telemetry" && method === "GET") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const tenants = await env.DB
        .prepare("SELECT id, owner_email, plan_tier FROM tenants ORDER BY id ASC")
        .bind()
        .all<{ id: string; owner_email: string; plan_tier: string }>();
      const period = currentPeriod(Date.now());
      const out: Array<Record<string, unknown>> = [];
      for (const t of tenants.results ?? []) {
        const usage = await getMonthUsage(env.DB, t.id, period);
        const active = await getActiveSubscription(env.DB, t.id);
        out.push({
          tenant_id: t.id,
          owner_email: t.owner_email,
          plan_tier: t.plan_tier,
          active_subscription: active ? { id: active.id, expires_at: active.expires_at } : null,
          usage: { replies: usage.replies, e2b_runs: usage.e2b_runs, llm_calls: usage.llm_calls, cost_usd_micro: usage.cost_usd_micro },
          period,
        });
      }
      return json({ ok: true, tenants: out, count: out.length });
    }

    if (path === "/api/billing/admin/sandbox-monitor" && method === "GET") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const margin = await aggregateMarginPaise(env.DB);
      const used = await totalE2BRunsUsed(env.DB);
      const cardOnFile = (await getAdminSetting(env.DB, "e2b_card_on_file")) === "1";
      const hobbyExhausted = (await getAdminSetting(env.DB, "e2b_hobby_exhausted")) === "1";
      const threshold = e2bThresholdStatus({ aggregateMarginPaise: margin, hobbyRunsUsed: used, cardOnFile, hobbyExhausted });
      return json({
        ok: true,
        hobby_runs_used: used,
        hobby_runs_remaining: threshold.hobbyRunsRemaining,
        hobby_runway_total: E2B_HOBBY_RUNWAY_RUNS,
        aggregate_margin_paise: margin,
        aggregate_margin_inr: margin / 100,
        threshold_paise: E2B_THRESHOLD_PAISE,
        threshold_met: margin >= E2B_THRESHOLD_PAISE,
        pro_floor_open: threshold.proFloorOpen,
        pro_floor_reason: threshold.reason,
        card_on_file: cardOnFile,
        hobby_exhausted: hobbyExhausted,
      });
    }

    if (path === "/api/billing/admin/grievance" && method === "GET") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      return json({ ok: true, ...(await getGrievance(env.DB)) });
    }

    if (path === "/api/billing/admin/launch-gates" && method === "GET") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      return json({ ok: true, gates: await getLaunchGates(env.DB), launch: "GATED" });
    }

    if (path === "/api/billing/admin/settings" && method === "GET") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const rows = await env.DB
        .prepare("SELECT key, value FROM admin_settings ORDER BY key ASC")
        .bind()
        .all<{ key: string; value: string }>();
      const settings: Record<string, string> = {};
      for (const r of rows.results ?? []) settings[r.key] = r.value;
      return json({ ok: true, settings });
    }

    if (path === "/api/billing/admin/settings" && method === "POST") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const body = await readJson(request);
      if (typeof body.upi_vpa === "string") {
        if (!/^[\w.\-]{2,}@[a-zA-Z]{2,}$/.test(body.upi_vpa)) return json({ error: "invalid_vpa" }, 400);
        await setAdminSetting(env.DB, "upi_vpa", body.upi_vpa);
      }
      for (const key of ["grievance_officer_name", "grievance_officer_designation", "grievance_officer_email"] as const) {
        if (typeof body[key] === "string") await setAdminSetting(env.DB, key, body[key] as string);
      }
      if (typeof body.e2b_card_on_file === "string" && (body.e2b_card_on_file === "0" || body.e2b_card_on_file === "1")) {
        await setAdminSetting(env.DB, "e2b_card_on_file", body.e2b_card_on_file as string);
      }
      if (typeof body.e2b_hobby_exhausted === "string" && (body.e2b_hobby_exhausted === "0" || body.e2b_hobby_exhausted === "1")) {
        await setAdminSetting(env.DB, "e2b_hobby_exhausted", body.e2b_hobby_exhausted as string);
      }
      return json({ ok: true });
    }

    if (path === "/api/billing/admin/verify-email" && method === "POST") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const body = await readJson(request);
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      await env.DB
        .prepare("UPDATE tenants SET email_verified = ?, email_verify_token_hash = NULL, email_verify_expires_at = NULL WHERE id = ?")
        .bind(1, tenantId)
        .run();
      await insertTrace(env.DB, tenantId, "", "billing_godmode", { action: "verify_email", actor: "admin" });
      return json({ ok: true, email_verified: true });
    }

    // --- B2 backup (admin-only, #49) ---
    if (path === "/api/billing/admin/backup" && method === "POST") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const body = await readJson(request);
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const res = await createTenantBackup(env, env.DB, tenantId);
      if (!res.ok) {
        const status = res.error === "b2_not_configured" || res.error === "key_enc_not_configured" ? 503 : 502;
        return json({ error: res.error, ...(res.detail ? { detail: res.detail } : {}) }, status);
      }
      return json({ ok: true, backup_id: res.backup_id, b2_key: res.b2_key, size_bytes: res.size_bytes, sha256: res.sha256 });
    }

    if (path === "/api/billing/admin/backup/restore-test" && method === "POST") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const body = await readJson(request);
      const backupId = typeof body.backup_id === "string" ? body.backup_id : "";
      if (!backupId) return json({ error: "bad_request" }, 400);
      const res = await restoreTestBackup(env, env.DB, backupId);
      if (!res.ok) {
        const status = res.error === "backup_not_found" ? 404 : res.error === "b2_not_configured" || res.error === "key_enc_not_configured" ? 503 : 502;
        return json({ error: res.error, ...(res.detail ? { detail: res.detail } : {}) }, status);
      }
      return json({ ok: true, backup_id: res.backup_id, tenant_id: res.tenant_id, size_bytes: res.size_bytes, sha256: res.sha256, tables: res.tables, dry_run: true });
    }

    if (path === "/api/billing/admin/backups" && method === "GET") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const url = new URL(request.url);
      const tenantId = url.searchParams.get("tenant_id") ?? undefined;
      const rows = await listBackups(env.DB, tenantId);
      return json({ ok: true, backups: rows, count: rows.length });
    }

    // --- Resend send log (admin-only, #52) — failure visibility ---
    if (path === "/api/billing/admin/email-sends" && method === "GET") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const url = new URL(request.url);
      const tenantId = url.searchParams.get("tenant_id") ?? undefined;
      const rows = await listEmailSends(env.DB, tenantId);
      return json({ ok: true, email_sends: rows, count: rows.length });
    }

    if (path === "/api/billing/admin/god-mode" && method === "POST") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const body = await readJson(request);
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      const action = typeof body.action === "string" ? body.action : "";
      if (!tenantId || !action) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const admin = typeof body.admin === "string" && body.admin.trim() ? body.admin : "admin";
      if (action === "activate") {
        const planTier = typeof body.plan_tier === "string" ? body.plan_tier : "";
        const period = typeof body.billing_period === "string" ? body.billing_period : "monthly";
        if ((planTier !== "pro" && planTier !== "business") || (period !== "monthly" && period !== "annual")) {
          return json({ error: "bad_request" }, 400);
        }
        const nowMs = Date.now();
        const amount = subscriptionAmountPaise(planTier as PlanTier, period as BillingPeriod);
        const subId = newBillingId("sub");
        const startsAt = new Date(nowMs).toISOString();
        const expiresAt = expiryFor(nowMs, period as BillingPeriod);
        await d1Batch(env.DB, [
          env.DB
            .prepare("INSERT INTO subscriptions (id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(subId, tenantId, planTier, period, amount, "active", startsAt, expiresAt, startsAt),
          env.DB.prepare("UPDATE tenants SET plan_tier = ?, pending_downgrade_tier = NULL WHERE id = ?").bind(planTier, tenantId),
          ledgerEventStmt(env.DB, tenantId, "approved", { subscription_id: subId, plan_tier: planTier, billing_period: period, amount_paise: amount, god_mode: true, expires_at: expiresAt }, admin, nowMs),
        ]);
        await insertTrace(env.DB, tenantId, "", "billing_godmode", { action: "activate", plan_tier: planTier, actor: admin });
        return json({ ok: true, action, subscription_id: subId, status: "active", expires_at: expiresAt });
      }
      if (action === "expire") {
        const active = await getActiveSubscription(env.DB, tenantId);
        if (!active) return json({ error: "no_active_subscription" }, 409);
        await d1Batch(env.DB, [
          env.DB.prepare("UPDATE subscriptions SET status = ? WHERE id = ?").bind("expired", active.id),
          env.DB.prepare("UPDATE tenants SET plan_tier = ? WHERE id = ?").bind("free", tenantId),
          ledgerEventStmt(env.DB, tenantId, "expired", { subscription_id: active.id, reason: "god_mode_expire" }, admin),
        ]);
        await insertTrace(env.DB, tenantId, "", "billing_godmode", { action: "expire", actor: admin });
        return json({ ok: true, action, subscription_id: active.id, status: "expired" });
      }
      if (action === "downgrade") {
        const planTier = typeof body.plan_tier === "string" ? body.plan_tier : "";
        if (planTier !== "pro" && planTier !== "free") return json({ error: "bad_request" }, 400);
        await d1Batch(env.DB, [
          env.DB.prepare("UPDATE tenants SET plan_tier = ? WHERE id = ?").bind(planTier, tenantId),
          ledgerEventStmt(env.DB, tenantId, "downgraded", { to_tier: planTier, god_mode: true }, admin),
        ]);
        await insertTrace(env.DB, tenantId, "", "billing_godmode", { action: "downgrade", plan_tier: planTier, actor: admin });
        return json({ ok: true, action, plan_tier: planTier });
      }
      if (action === "deactivate_device") {
        const deviceId = typeof body.device_id === "string" ? body.device_id : "";
        if (!deviceId) return json({ error: "bad_request" }, 400);
        const device = await getDevice(env.DB, deviceId);
        if (!device || device.tenant_id !== tenantId) return json({ error: "device_not_found" }, 404);
        await env.DB.prepare("UPDATE devices SET enabled = ? WHERE device_id = ?").bind(0, deviceId).run();
        await insertTrace(env.DB, tenantId, deviceId, "billing_godmode", { action: "deactivate_device", actor: admin });
        return json({ ok: true, action, device_id: deviceId });
      }
      return json({ error: "bad_request" }, 400);
    }

    if (path === "/api/billing/admin/reconcile" && method === "POST") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const rec = await reconcileBilling(env.DB);
      return json({ ok: true, ...rec, diff_blocked: rec.diff_payments_vs_expected !== 0 });
    }

    if (path === "/api/billing/admin/retention" && method === "POST") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const deleted = await purgeOldUsage(env.DB);
      return json({ ok: true, deleted });
    }

    // --- Cron jobs (Phase 4 create route — cap-checked) ---
    if (path === "/api/billing/cron-jobs" && method === "POST") {
      const body = await readJson(request);
      const auth = await billingAuth(body);
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      const deviceId = typeof body.device_id === "string" ? body.device_id : "";
      const cronExpr = typeof body.cron_expr === "string" ? body.cron_expr : "";
      const command = typeof body.command === "string" ? body.command : "";
      if (!tenantId || !deviceId || !cronExpr || !command) return json({ error: "bad_request" }, 400);
      const device = await getDevice(env.DB, deviceId);
      if (!device || device.enabled === 0 || device.tenant_id !== tenantId) {
        return json({ error: "device_not_paired" }, 403);
      }
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const rl = await checkRateLimit(env, "billing", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const res = await createCronJob(env.DB, { tenant, device_id: deviceId, cron_expr: cronExpr, command });
      if (!res.ok) {
        return json(
          { error: res.error, detail: res.error === "cron_cap" ? "Cron limit khatam — purana band karo ya upgrade karo" : undefined },
          res.error === "cron_cap" ? 403 : 400,
        );
      }
      return json({ ok: true, job_id: res.job_id, next_run_at: res.next_run_at });
    }

    if (path === "/api/billing/cron-jobs" && method === "GET") {
      const tenantId = url.searchParams.get("tenant_id") ?? "";
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? "",
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: `billing-cron-jobs:${tenantId}`,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const resolvedTenant = auth.tenant_id ?? tenantId;
      if (!resolvedTenant) return json({ error: "bad_request" }, 400);
      if (auth.tenant_id && tenantId && auth.tenant_id !== tenantId) return json({ error: "forbidden" }, 403);
      const rows = await env.DB
        .prepare("SELECT id, tenant_id, device_id, cron_expr, command, enabled, last_run_at, next_run_at, created_at FROM scheduled_jobs WHERE tenant_id = ? ORDER BY created_at DESC")
        .bind(resolvedTenant)
        .all<Record<string, unknown>>();
      return json({ ok: true, jobs: rows.results ?? [], count: (rows.results ?? []).length });
    }

    if (path.startsWith("/api/billing/cron-jobs/") && path.endsWith("/disable") && method === "POST") {
      const body = await readJson(request);
      const auth = await billingAuth(body);
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const jobId = path.split("/").filter(Boolean)[3] ?? "";
      const job = await env.DB
        .prepare("SELECT id, tenant_id FROM scheduled_jobs WHERE id = ?")
        .bind(jobId)
        .first<{ id: string; tenant_id: string }>();
      if (!job) return json({ error: "job_not_found" }, 404);
      if (auth.tenant_id && auth.tenant_id !== job.tenant_id) return json({ error: "forbidden" }, 403);
      await env.DB.prepare("UPDATE scheduled_jobs SET enabled = ? WHERE id = ?").bind(0, jobId).run();
      return json({ ok: true, job_id: jobId, enabled: false });
    }

    // M-I-30: re-enable a disabled job (cap-checked like create; the
    // next run is recomputed from now — the stored next_run_at is stale
    // after any time disabled).
    if (path.startsWith("/api/billing/cron-jobs/") && path.endsWith("/enable") && method === "POST") {
      const body = await readJson(request);
      const auth = await billingAuth(body);
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const jobId = path.split("/").filter(Boolean)[3] ?? "";
      const job = await env.DB
        .prepare("SELECT id, tenant_id, cron_expr, enabled FROM scheduled_jobs WHERE id = ?")
        .bind(jobId)
        .first<{ id: string; tenant_id: string; cron_expr: string; enabled: number }>();
      if (!job) return json({ error: "job_not_found" }, 404);
      if (auth.tenant_id && auth.tenant_id !== job.tenant_id) return json({ error: "forbidden" }, 403);
      if (job.enabled === 1) return json({ ok: true, job_id: jobId, enabled: true });
      const tenant = await getTenant(env.DB, job.tenant_id);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const used = await countEnabledJobs(env.DB, job.tenant_id);
      if (used >= planLimits(tenant.plan_tier).cron_jobs) {
        return json({ error: "cron_cap", detail: "Cron limit khatam — purana band karo ya upgrade karo" }, 403);
      }
      const next = nextCronRun(job.cron_expr, Date.now());
      if (next === null) return json({ error: "bad_cron" }, 400);
      await env.DB.prepare("UPDATE scheduled_jobs SET enabled = ?, next_run_at = ? WHERE id = ?").bind(1, next, jobId).run();
      return json({ ok: true, job_id: jobId, enabled: true, next_run_at: next });
    }

    // M-I-30: delete a job outright (tenant-scoped; the disable route
    // only pauses). No un-delete — the app confirms before calling.
    if (path.startsWith("/api/billing/cron-jobs/") && method === "DELETE") {
      const jobId = path.split("/").filter(Boolean)[3] ?? "";
      const auth = await billingAuth({});
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const job = await env.DB
        .prepare("SELECT id, tenant_id FROM scheduled_jobs WHERE id = ?")
        .bind(jobId)
        .first<{ id: string; tenant_id: string }>();
      if (!job) return json({ error: "job_not_found" }, 404);
      if (auth.tenant_id && auth.tenant_id !== job.tenant_id) return json({ error: "forbidden" }, 403);
      await env.DB.prepare("DELETE FROM scheduled_jobs WHERE id = ?").bind(jobId).run();
      return json({ ok: true, job_id: jobId, deleted: true });
    }

    // M-I-30: NL -> cron expression. Deterministic parse first (free,
    // no LLM); LLM fallback through the existing router with a strict
    // output contract. NEVER emits an unvalidated expression — anything
    // that fails nextCronRun() is 422 unparseable. Times are the user's
    // local time; utc_offset_minutes (IST = 330) converts to UTC.
    if (path === "/api/cron/parse" && method === "POST") {
      const body = await readJson(request);
      const auth = await billingAuth(body);
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const text = typeof body.text === "string" ? body.text : "";
      if (!text.trim()) return json({ error: "bad_request" }, 400);
      const offsetRaw = typeof body.utc_offset_minutes === "number" ? body.utc_offset_minutes : 0;
      const utcOffsetMinutes = Number.isFinite(offsetRaw) && Math.abs(offsetRaw) <= 14 * 60 ? Math.trunc(offsetRaw) : 0;
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const rl = await checkRateLimit(env, "billing", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const nowMs = Date.now();
      const deterministic = parseNaturalCron(text, { utcOffsetMinutes, nowMs });
      if (deterministic) return json({ ok: true, ...deterministic });
      // LLM fallback: one quick_command call, strict contract. Any
      // router refusal (byok_required included) is an unparseable
      // parse, not a 500 — the caller retries with a clearer phrase.
      let config;
      try {
        config = loadRouterConfig(env);
      } catch {
        return json({ error: "router_config_error" }, 500);
      }
      const res = await routeLlm(
        {
          db: env.DB,
          masterKeyB64: env.KEY_ENC_SECRET,
          founderKey: env.FOUNDER_GEMINI_KEY,
          founderGroqKey: env.FOUNDER_GROQ_KEY,
          config,
        },
        {
          tenant_id: tenantId,
          turn_id: `cron-parse-${nowMs}`,
          kind: "quick_command",
          messages: [{ role: "user", text }],
          system: cronLlmSystemPrompt(utcOffsetMinutes),
        },
      );
      if (!res.ok || !res.text) {
        return json({ error: "unparseable", detail: "Time samajh nahi aaya — dobara saaf shabdon me likho (jaise: har subah 8 baje)" }, 422);
      }
      const parsed = llmParseCronText(res.text, nowMs);
      if (!parsed) {
        return json({ error: "unparseable", detail: "Time samajh nahi aaya — dobara saaf shabdon me likho (jaise: har subah 8 baje)" }, 422);
      }
      return json({ ok: true, ...parsed });
    }

    // --- E2B runs (Phase 4) ---
    if (path === "/api/e2b/run" && method === "POST") {
      if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await readJson(request);
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      const rl = await checkRateLimit(env, "e2b", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const hobbyExhausted = (await getAdminSetting(env.DB, "e2b_hobby_exhausted")) === "1";
      const res = await requestE2BRun(env.DB, {
        tenant_id: tenantId,
        plan_tier: tenant.plan_tier,
        e2bConfigured: !!env.E2B_API_KEY,
        hobbyExhausted,
        task: typeof body.task === "string" ? body.task : undefined,
      });
      if (!res.ok) {
        const status = res.error === "e2b_runs_cap" ? 429 : res.error === "tenant_not_found" ? 404 : 503;
        return json({ error: res.error, detail: res.detail, device_fallback: res.device_fallback }, status);
      }
      return json({ ok: true, run_id: res.run_id, status: "held", max_run_ms: E2B_MAX_RUN_MS });
    }

    if (path.startsWith("/api/e2b/run/") && path.endsWith("/complete") && method === "POST") {
      if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
        return json({ error: "unauthorized" }, 401);
      }
      const runId = path.split("/").filter(Boolean)[3] ?? "";
      const body = await readJson(request);
      if (typeof body.success !== "boolean") return json({ error: "bad_request" }, 400);
      const run = await getE2BRun(env.DB, runId);
      if (!run) return json({ error: "run_not_found" }, 404);
      if (run.status !== "held") return json({ error: "run_not_held", status: run.status }, 409);
      const res = await completeE2BRun(env.DB, run, body.success);
      await insertTrace(env.DB, run.tenant_id, "", "e2b_run", { run_id: runId, status: res.status });
      return json({ ok: true, run_id: runId, status: res.status });
    }

    if (path.startsWith("/api/e2b/run/") && path.endsWith("/kill") && method === "POST") {
      if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
        return json({ error: "unauthorized" }, 401);
      }
      const runId = path.split("/").filter(Boolean)[3] ?? "";
      const run = await getE2BRun(env.DB, runId);
      if (!run) return json({ error: "run_not_found" }, 404);
      if (run.status !== "held") return json({ error: "run_not_held", status: run.status }, 409);
      const res = await killE2BRun(env.DB, run);
      await insertTrace(env.DB, run.tenant_id, "", "e2b_run", { run_id: runId, status: "killed" });
      return json({ ok: true, run_id: runId, status: "killed", message: res.message });
    }

    // --- Legal pages (Phase 4, public JSON) ---
    if ((path === "/api/legal/terms" || path === "/api/legal/privacy" || path === "/api/legal/refund") && method === "GET") {
      const page = path.split("/").pop() as "terms" | "privacy" | "refund";
      return json(legalPage(page));
    }

    // WS upgrade -> DO (paired-device check first).
    if (path.startsWith("/ws/") && method === "GET") {
      const deviceId = path.slice(4).split("/")[0] ?? "";
      if (!deviceId) return json({ error: "bad_request" }, 400);
      const device = await getDevice(env.DB, deviceId);
      if (!device || device.enabled === 0) return json({ error: "device_not_paired" }, 403);
      const id = env.JARVIS_HUB.idFromName(`device:${deviceId}`);
      const stub = env.JARVIS_HUB.get(id);
      const headers = new Headers(request.headers);
      headers.set("x-expected-device", deviceId);
      return await stub.fetch(new Request(request.url, { method: request.method, headers }));
    }

    // --- Direct Google OAuth (Track E #27, Layer 8 free path) ---
    // Auth: x-internal-secret (server-to-server, tenant_id explicit)
    // OR paired device + Ed25519 signature (headers x-device-id /
    // x-nonce / x-ts / x-signature), via authorizeDocsRequest.
    // GET routes sign the path + query string (payloadRaw =
    // url.pathname + url.search); POST routes sign sortedJson(body).
    // /oauth/google/start returns JSON {auth_url} — the app opens it
    // in the browser (a redirect cannot carry the signed headers).
    // The callback is a plain browser GET, authenticated by the
    // one-time server-side state row only (standard OAuth).
    if (path === "/oauth/google/start" && method === "GET") {
      const deviceId = request.headers.get("x-device-id") ?? url.searchParams.get("device_id") ?? "";
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId,
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: url.pathname + url.search,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? url.searchParams.get("tenant_id") ?? "";
      if (!tenantId) return json({ error: "bad_request" }, 400);
      if (!isGoogleOAuthConfigured(env)) {
        return json({ error: "google_oauth_not_configured", detail: "GCP OAuth client not set up on the hub — parent step (see Track E REPORT.md)" }, 503);
      }
      const rl = await checkRateLimit(env, "googleOauthStart", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      const state = await issueOAuthState(env.DB, tenantId, auth.device_id ?? deviceId);
      return json({ ok: true, auth_url: buildAuthUrl(env, new URL(request.url).origin, state), redirect_uri: googleRedirectUri(new URL(request.url).origin) });
    }

    if (path === "/oauth/google/callback" && method === "GET") {
      const htmlPage = (title: string, body: string, status: number) =>
        new Response(
          `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head>` +
            `<body style="font-family:sans-serif;max-width:560px;margin:48px auto;padding:0 16px"><h1>${title}</h1><p>${body}</p>` +
            `<p>Tab band karke Jarvis app me wapas jao.</p></body></html>`,
          { status, headers: { "Content-Type": "text/html; charset=utf-8" } },
        );
      const code = url.searchParams.get("code") ?? "";
      const state = url.searchParams.get("state") ?? "";
      const oauthErr = url.searchParams.get("error") ?? "";
      if (oauthErr) return htmlPage("Google connect fail", `Google ne consent nahi diya (${oauthErr}). Dobara koshish karo.`, 400);
      if (!code || !state) return htmlPage("Google connect fail", "code ya state missing hai — dobara koshish karo.", 400);
      const consumed = await consumeOAuthState(env.DB, state);
      if (!consumed) return htmlPage("Google connect fail", "Ye link expire ho gaya ya pehle se use ho chuka hai — AI Brain se dobara Connect dabao.", 400);
      try {
        const origin = new URL(request.url).origin;
        const tokens = await exchangeCodeForTokens(env, code, origin);
        const email = await fetchGoogleEmail(tokens.accessToken);
        await storeGoogleTokens(env.DB, env, consumed.tenant_id, email, tokens);
        await insertTrace(env.DB, consumed.tenant_id, consumed.device_id, "google_connected", { scopes: "gmail_read_send_drive_read_write_calendar" });
        return htmlPage("Google connected", "Gmail + Drive connect ho gaya. Ab Agent Mode Gmail bhej/padh sakta hai aur Drive files padh sakta hai.", 200);
      } catch (e) {
        if (e instanceof GoogleError) {
          return htmlPage("Google connect fail", `(${e.code}) ${e.message}`, e.status === 503 ? 503 : 502);
        }
        throw e;
      }
    }

    if (path === "/api/google/status" && method === "GET") {
      const deviceId = request.headers.get("x-device-id") ?? url.searchParams.get("device_id") ?? "";
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId,
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: url.pathname + url.search,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? url.searchParams.get("tenant_id") ?? "";
      if (!tenantId) return json({ error: "bad_request" }, 400);
      return json({ ok: true, ...(await googleStatus(env.DB, env, tenantId)) });
    }

    if (path === "/api/google/gmail/send" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const to = typeof body.to === "string" ? body.to.trim() : "";
      const subject = typeof body.subject === "string" ? body.subject : "";
      const text = typeof body.body === "string" ? body.body : "";
      if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return json({ error: "bad_request", detail: "valid 'to' email required" }, 400);
      if (text.length > 100_000) return json({ error: "bad_request", detail: "body too large (100k chars)" }, 400);
      // R4.6 (D-R18) — Idempotency-Key: the app sends one per logical
      // send (content hash — see src/idempotency.ts). A replayed key
      // returns the FIRST send's message id with deduped:true and sends
      // nothing — the double-tap sends one mail. No header = no dedupe
      // (old apps keep working). The lookup runs BEFORE the rate limit:
      // a deduped replay makes no Google call, so it spends no budget.
      const idemKey = (request.headers.get("idempotency-key") ?? "").trim();
      if (idemKey) {
        if (idemKey.length > 128) return json({ error: "bad_request", detail: "Idempotency-Key too long (max 128 chars)" }, 400);
        const prior = await getIdempotencyRecord(env.DB, tenantId, idemKey);
        if (prior) return json({ ok: true, id: prior.gmail_message_id, deduped: true });
      }
      const rl = await checkRateLimit(env, "googleApi", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      try {
        const sent = await gmailSend({ db: env.DB, env, tenantId }, { to, subject, body: text });
        if (idemKey) {
          try {
            await storeIdempotencyRecord(env.DB, tenantId, idemKey, sent.id);
          } catch {
            // The mail is sent; a failed dedupe write must not fail
            // the response (worst case: a later replay re-sends).
          }
        }
        return json({ ok: true, id: sent.id, deduped: false });
      } catch (e) {
        if (e instanceof GoogleError) return json({ error: e.code, detail: e.message }, e.status);
        throw e;
      }
    }

    if (path === "/api/google/gmail/messages" && method === "GET") {
      const deviceId = request.headers.get("x-device-id") ?? url.searchParams.get("device_id") ?? "";
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId,
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: url.pathname + url.search,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? url.searchParams.get("tenant_id") ?? "";
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "googleApi", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      try {
        const messages = await gmailListMessages(
          { db: env.DB, env, tenantId },
          { q: url.searchParams.get("q") ?? undefined, maxResults: Number(url.searchParams.get("max_results") ?? 5) || 5 },
        );
        return json({ ok: true, messages });
      } catch (e) {
        if (e instanceof GoogleError) return json({ error: e.code, detail: e.message }, e.status);
        throw e;
      }
    }

    if (path.startsWith("/api/google/drive/files/") && method === "GET") {
      const fileId = decodeURIComponent(path.split("/").filter(Boolean).pop() ?? "");
      if (!fileId) return json({ error: "bad_request" }, 400);
      const deviceId = request.headers.get("x-device-id") ?? url.searchParams.get("device_id") ?? "";
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId,
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: url.pathname + url.search,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? url.searchParams.get("tenant_id") ?? "";
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "googleApi", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      try {
        const file = await driveReadFile({ db: env.DB, env, tenantId }, fileId);
        return json({ ok: true, file });
      } catch (e) {
        if (e instanceof GoogleError) return json({ error: e.code, detail: e.message }, e.status);
        throw e;
      }
    }

    // R4.8 (U27) — Drive write + Calendar. Scope trap: these need the
    // drive.file / calendar.events scopes (GOOGLE_SCOPES, R4.8). A token
    // granted before R4.8 gets google_reconnect_required (403) from
    // the helpers — the app sends the user back through consent; the
    // old token keeps working read-only.
    if (path === "/api/google/drive/upload" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "googleApi", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      try {
        const file = await driveUploadFile(
          { db: env.DB, env, tenantId },
          {
            name: typeof body.name === "string" ? body.name : "",
            mimeType: typeof body.mime_type === "string" ? body.mime_type : "application/octet-stream",
            contentBase64: typeof body.content_base64 === "string" ? body.content_base64 : "",
          },
        );
        return json({ ok: true, file });
      } catch (e) {
        if (e instanceof GoogleError) return json({ error: e.code, detail: e.message }, e.status);
        throw e;
      }
    }

    if (path === "/api/google/calendar/events" && method === "GET") {
      const deviceId = request.headers.get("x-device-id") ?? url.searchParams.get("device_id") ?? "";
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId,
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: url.pathname + url.search,
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? url.searchParams.get("tenant_id") ?? "";
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "googleApi", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      try {
        const events = await calendarListEvents(
          { db: env.DB, env, tenantId },
          { maxResults: Number(url.searchParams.get("max_results") ?? 10) || 10 },
        );
        return json({ ok: true, events });
      } catch (e) {
        if (e instanceof GoogleError) return json({ error: e.code, detail: e.message }, e.status);
        throw e;
      }
    }

    if (path === "/api/google/calendar/events" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "googleApi", tenantId);
      if (!rl.allowed) return rateLimited(rl);
      try {
        const event = await calendarCreateEvent(
          { db: env.DB, env, tenantId },
          {
            summary: typeof body.summary === "string" ? body.summary : "",
            start: typeof body.start === "string" ? body.start : "",
            end: typeof body.end === "string" ? body.end : "",
            description: typeof body.description === "string" ? body.description : undefined,
          },
        );
        return json({ ok: true, event });
      } catch (e) {
        if (e instanceof GoogleError) return json({ error: e.code, detail: e.message }, e.status);
        throw e;
      }
    }

    if (path === "/api/google/revoke" && method === "POST") {
      const body = await readJson(request);
      const auth = await authorizeDocsRequest(env.DB, {
        internalSecret: env.INTERNAL_SECRET,
        internalHeader: request.headers.get("x-internal-secret"),
        deviceId: request.headers.get("x-device-id") ?? (typeof body.device_id === "string" ? body.device_id : ""),
        nonce: request.headers.get("x-nonce"),
        ts: request.headers.get("x-ts") ? Number(request.headers.get("x-ts")) : null,
        sig: request.headers.get("x-signature"),
        payloadRaw: sortedJson(body),
      });
      if (!auth.ok) return json({ error: auth.error ?? "unauthorized" }, auth.error === "device_not_paired" ? 403 : 401);
      const tenantId = auth.tenant_id ?? (typeof body.tenant_id === "string" ? body.tenant_id : "");
      if (!tenantId) return json({ error: "bad_request" }, 400);
      try {
        await revokeGoogleTokens({ db: env.DB, env, tenantId });
        await insertTrace(env.DB, tenantId, auth.device_id ?? "", "google_revoked", {});
        return json({ ok: true, connected: false });
      } catch (e) {
        if (e instanceof GoogleError) return json({ error: e.code, detail: e.message }, e.status);
        throw e;
      }
    }

      // --- Licence web (M-I-28) — self-serve signup/login/dashboard ---
    // Passwordless email codes; the licence Worker stays the issuance
    // authority (generate/release proxied with LICENCE_ADMIN_TOKEN).
    // Licence keys are NEVER logged/traced — only the generate response
    // to the verified owner carries a fresh key, once.
    const licenceWorkerUrl = (env.LICENCE_WORKER_URL ?? LICENCE_WORKER_URL_DEFAULT).replace(/\/+$/, "");
    const licenceWebSession = async (): Promise<{ email: string } | null> => {
      const cookie = request.headers.get("cookie") ?? "";
      const m = cookie.match(new RegExp(`(?:^|;\\s*)${LICENCE_SESSION_COOKIE}=([^;]+)`));
      if (!m) return null;
      const tokenHash = await hashSessionToken(m[1]);
      const row = await env.DB.prepare("SELECT email, expires_at FROM licence_web_sessions WHERE token_hash = ?")
        .bind(tokenHash)
        .first<{ email: string; expires_at: number }>();
      if (!row || row.expires_at < Date.now()) return null;
      await env.DB.prepare("UPDATE licence_web_sessions SET last_seen_at = ? WHERE token_hash = ?")
        .bind(Date.now(), tokenHash)
        .run();
      return { email: row.email };
    };
    const licenceWebOriginOk = (): boolean => {
      const origin = request.headers.get("origin");
      if (!origin) return true; // non-browser caller — the session cookie is the credential
      try {
        return origin === new URL(request.url).origin;
      } catch {
        return false;
      }
    };
    const licenceWebDailyCap = async (): Promise<boolean> => {
      // Global code-email guard: Resend free tier is 100/day; cap at 90.
      const dayStart = Date.now() - (Date.now() % 86_400_000);
      const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM licence_email_codes WHERE created_at >= ?")
        .bind(dayStart)
        .first<{ n: number }>();
      return (row?.n ?? 0) < 90;
    };
    const licenceWebLicenceFor = async (email: string) => {
      const row = await env.DB.prepare(
        "SELECT key, user_id, device_id, status, created_at FROM licences WHERE user_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1",
      )
        .bind(email)
        .first<{ key: string; user_id: string; device_id: string | null; status: string; created_at: number }>();
      if (!row) return null;
      return {
        key_masked: maskLicenceKey(row.key),
        status: row.status,
        device_id: row.device_id,
        created_at: new Date(row.created_at).toISOString(),
      };
    };
    const licenceWorkerCall = async (
      p: string,
      body: Record<string, unknown>,
    ): Promise<{ status: number; body: Record<string, unknown> }> => {
      // M-I-28 fix (2026-11-22, proven live with a diag Worker): a Worker
      // subrequest to a *.workers.dev URL gets HTTP 404 "error code:
      // 1042" on this setup while external curl gets 200 — so the hub
      // calls the licence Worker through the LICENCE_WORKER service
      // binding, never its public URL. The public-URL fetch below is
      // only the fallback when the binding is absent (vitest / local
      // dev, where the global fetch is stubbed). The admin-token header
      // is still sent over the binding (defence in depth — the Worker
      // checks it on every generate/release).
      let res: Response;
      try {
        const init: RequestInit = {
          method: "POST",
          headers: { "x-licence-admin-token": env.LICENCE_ADMIN_TOKEN ?? "", "Content-Type": "application/json" },
          body: JSON.stringify(body),
        };
        res = env.LICENCE_WORKER
          ? await env.LICENCE_WORKER.fetch(`${licenceWorkerUrl}${p}`, init)
          : await fetch(`${licenceWorkerUrl}${p}`, init);
      } catch {
        return { status: 503, body: { error: "licence_worker_unreachable" } };
      }
      let parsed: Record<string, unknown> = {};
      try {
        parsed = (await res.json()) as Record<string, unknown>;
      } catch {
        parsed = {};
      }
      return { status: res.status, body: parsed };
    };

    if (path === "/licence" && method === "GET") {
      return new Response(licenceLandingPage(), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
    if (path === "/licence/login" && method === "GET") {
      return new Response(licenceLoginPage(), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
    if (path === "/licence/dashboard" && method === "GET") {
      const sess = await licenceWebSession();
      if (!sess) return new Response(null, { status: 302, headers: { Location: "/licence/login" } });
      const lic = await licenceWebLicenceFor(sess.email);
      return new Response(licenceDashboardPage(sess.email, lic), {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    if (path === "/licence/admin" && method === "GET") {
      return new Response(licenceAdminPage(), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    // --- R4.5: admin website v1 (hub-served, M-I-19) ---
    // Auth = licence-web email-code session + is_admin flag (owner
    // email only). No x-admin-token on these routes — the page has no
    // token to send. Key values are NEVER returned (status booleans
    // only); the Gemini key set is live-validated + encrypted like
    // POST /api/tenants/:id/key. The GitHub admin token cannot be set
    // from inside the Worker (Worker secrets come from the Cloudflare
    // API outside) — the page shows status + the owner-side step.
    if (path === "/admin" && method === "GET") {
      const sess = await licenceWebSession();
      if (!sess) return new Response(adminLoginPage(), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
      await ensureOwnerAdmin(env.DB, sess.email);
      if (!(await isAdminUser(env.DB, sess.email))) {
        return new Response(adminLoginPage(), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
      }
      return new Response(adminDashboardPage(sess.email), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    if (path === "/api/admin/overview" && method === "GET") {
      const sess = await licenceWebSession();
      if (!sess || !(await isAdminUser(env.DB, sess.email))) return json({ error: "unauthorized" }, 401);
      return json({ ok: true, ...(await adminOverview(env.DB, VERSION)) });
    }

    if (path === "/api/admin/keys" && method === "GET") {
      const sess = await licenceWebSession();
      if (!sess || !(await isAdminUser(env.DB, sess.email))) return json({ error: "unauthorized" }, 401);
      const tenant = await getTenantByOwnerEmail(env.DB);
      return json({
        ok: true,
        has_gemini_key: !!tenant?.gemini_key_enc,
        has_groq_key: !!tenant?.groq_key_enc,
        founder_gemini_key_set: !!env.FOUNDER_GEMINI_KEY,
        founder_groq_key_set: !!env.FOUNDER_GROQ_KEY,
        github_admin_token_set: !!env.GITHUB_ADMIN_TOKEN,
      });
    }

    if (path === "/api/admin/keys/gemini" && method === "POST") {
      const sess = await licenceWebSession();
      if (!sess || !(await isAdminUser(env.DB, sess.email))) return json({ error: "unauthorized" }, 401);
      const body = await readJson(request);
      const key = typeof body.gemini_key === "string" ? body.gemini_key : "";
      if (!key) return json({ error: "bad_request" }, 400);
      const tenant = await getTenantByOwnerEmail(env.DB);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      if (!env.KEY_ENC_SECRET) return json({ error: "key_vault_not_configured" }, 500);
      const valid = await validateGeminiKey(key);
      if (!valid) return json({ error: "invalid_key" }, 400);
      const master = await importMasterKey(env.KEY_ENC_SECRET);
      const enc = await encryptTenantKey(master, key);
      await env.DB.prepare("UPDATE tenants SET gemini_key_enc = ? WHERE id = ?").bind(enc, tenant.id).run();
      await insertKeyAudit(env.DB, { tenantId: tenant.id, keyKind: "gemini", action: "set", actor: "admin-website" });
      return json({ ok: true });
    }

    if ((path === "/api/licence-web/signup" || path === "/api/licence-web/login") && method === "POST") {
      const purpose = path.endsWith("/signup") ? "signup" : "login";
      const body = await readJson(request);
      const email = normalizeEmail(typeof body.email === "string" ? body.email : "");
      const valid = isValidEmail(email);
      if (!valid.ok) return json({ error: valid.error }, 400);
      const rlEmail = await checkRateLimit(env, "licenceWebSignup", email);
      if (!rlEmail.allowed) return rateLimited(rlEmail);
      const rlIp = await checkRateLimit(env, "licenceWebSignupIp", clientIp(request));
      if (!rlIp.allowed) return rateLimited(rlIp);
      const user = await env.DB.prepare("SELECT email, email_verified FROM licence_web_users WHERE email = ?")
        .bind(email)
        .first<{ email: string; email_verified: number }>();
      // Login for an unknown email: same 200 shape, no code, no row —
      // no enumeration oracle.
      if (purpose === "login" && !user) return json({ ok: true, email });
      if (!(await licenceWebDailyCap())) return json({ error: "email_daily_cap" }, 503);
      if (!user) {
        await env.DB.prepare(
          "INSERT INTO licence_web_users (email, email_verified, created_at, last_login_at) VALUES (?, 0, ?, NULL)",
        )
          .bind(email, Date.now())
          .run();
      }
      const { code, codeHash } = await newEmailCode();
      const nowMs = Date.now();
      await env.DB.prepare("DELETE FROM licence_email_codes WHERE email = ? AND purpose = ?")
        .bind(email, purpose)
        .run();
      await env.DB.prepare(
        "INSERT INTO licence_email_codes (email, purpose, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, ?, 0, ?)",
      )
        .bind(email, purpose, codeHash, nowMs + LICENCE_CODE_TTL_MS, nowMs)
        .run();
      // R1 (N-2 fix): licence-web codes were sent with raw sendEmail —
      // no email_sends row, so the sends were invisible to the audit.
      // sendEmailWithRecord records every send (tenant "licence-web" is
      // the pseudo-tenant for the daily cap — no tenant exists yet at
      // signup/login time).
      const sent = await sendEmailWithRecord(env, env.DB, { tenantId: "licence-web", kind: "licence_web_code", to: email, ...licenceCodeEmailContent(code, purpose as "signup" | "login") });
      if (!sent.ok) {
        await env.DB.prepare("DELETE FROM licence_email_codes WHERE email = ? AND purpose = ?")
          .bind(email, purpose)
          .run();
        return json({ error: sent.error === "not_configured" ? "email_not_configured" : "email_failed" }, 503);
      }
      return json({ ok: true, email });
    }

    if (path === "/api/licence-web/verify" && method === "POST") {
      const body = await readJson(request);
      const email = normalizeEmail(typeof body.email === "string" ? body.email : "");
      const code = typeof body.code === "string" ? body.code : "";
      const purpose = body.purpose === "login" ? "login" : "signup";
      if (!email || !code) return json({ error: "bad_request" }, 400);
      const rl = await checkRateLimit(env, "licenceWebVerify", email);
      if (!rl.allowed) return rateLimited(rl);
      const row = await env.DB.prepare(
        "SELECT code_hash, expires_at, attempts FROM licence_email_codes WHERE email = ? AND purpose = ?",
      )
        .bind(email, purpose)
        .first<{ code_hash: string; expires_at: number; attempts: number }>();
      if (!row || row.expires_at < Date.now() || row.attempts >= LICENCE_CODE_MAX_ATTEMPTS) {
        return json({ error: "verification_failed", detail: "Code galat ya expire ho gaya — naya code mangao" }, 400);
      }
      if (!(await verifyEmailCode(code, row.code_hash))) {
        await env.DB.prepare("UPDATE licence_email_codes SET attempts = ? WHERE email = ? AND purpose = ?")
          .bind(row.attempts + 1, email, purpose)
          .run();
        return json({ error: "verification_failed", detail: "Code galat hai — dobara try karo" }, 400);
      }
      await env.DB.prepare("DELETE FROM licence_email_codes WHERE email = ? AND purpose = ?")
        .bind(email, purpose)
        .run();
      const user = await env.DB.prepare("SELECT email, email_verified FROM licence_web_users WHERE email = ?")
        .bind(email)
        .first<{ email: string; email_verified: number }>();
      if (!user) return json({ error: "verification_failed" }, 400);
      const nowMs = Date.now();
      if (purpose === "signup") {
        await env.DB.prepare("UPDATE licence_web_users SET email_verified = ?, last_login_at = ? WHERE email = ?")
          .bind(1, nowMs, email)
          .run();
      } else {
        if (user.email_verified !== 1) return json({ error: "email_not_verified" }, 403);
        await env.DB.prepare("UPDATE licence_web_users SET last_login_at = ? WHERE email = ?")
          .bind(nowMs, email)
          .run();
      }
      const { token, tokenHash } = await newSessionToken();
      await env.DB.prepare(
        "INSERT INTO licence_web_sessions (token_hash, email, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?)",
      )
        .bind(tokenHash, email, nowMs, nowMs + LICENCE_SESSION_TTL_MS, nowMs)
        .run();
      await insertTrace(env.DB, email, "", "licence_web_verify", { purpose });
      return json({ ok: true, email }, 200, { "Set-Cookie": sessionCookie(token, Math.floor(LICENCE_SESSION_TTL_MS / 1000)) });
    }

    if (path === "/api/licence-web/logout" && method === "POST") {
      const cookie = request.headers.get("cookie") ?? "";
      const m = cookie.match(new RegExp(`(?:^|;\\s*)${LICENCE_SESSION_COOKIE}=([^;]+)`));
      if (m) {
        const tokenHash = await hashSessionToken(m[1]);
        await env.DB.prepare("DELETE FROM licence_web_sessions WHERE token_hash = ?").bind(tokenHash).run();
      }
      return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
    }

    if (path === "/api/licence-web/me" && method === "GET") {
      const sess = await licenceWebSession();
      if (!sess) return json({ error: "unauthorized" }, 401);
      const user = await env.DB.prepare("SELECT email_verified FROM licence_web_users WHERE email = ?")
        .bind(sess.email)
        .first<{ email_verified: number }>();
      const lic = await licenceWebLicenceFor(sess.email);
      return json({ ok: true, email: sess.email, verified: user?.email_verified === 1, licence: lic });
    }

    if (path === "/api/licence-web/generate" && method === "POST") {
      if (!licenceWebOriginOk()) return json({ error: "forbidden" }, 403);
      const sess = await licenceWebSession();
      if (!sess) return json({ error: "unauthorized" }, 401);
      const rl = await checkRateLimit(env, "licenceWebGenerate", sess.email);
      if (!rl.allowed) return rateLimited(rl);
      const user = await env.DB.prepare("SELECT email_verified FROM licence_web_users WHERE email = ?")
        .bind(sess.email)
        .first<{ email_verified: number }>();
      if (!user || user.email_verified !== 1) return json({ error: "email_not_verified" }, 403);
      if (!env.LICENCE_ADMIN_TOKEN) return json({ error: "licence_not_configured" }, 503);
      const res = await licenceWorkerCall("/api/licence/generate", { user_id: sess.email });
      if (res.status !== 200) return json(res.body, res.status); // 403 licence_revoked passes through verbatim
      const lic = res.body.licence as Record<string, unknown> | undefined;
      if (!lic) return json({ error: "generate_failed" }, 500);
      const existing = res.body.existing === true;
      await insertTrace(env.DB, sess.email, "", "licence_web_generate", { existing });
      if (existing) {
        // Existing licence: masked only — the full key is shown once,
        // at fresh issuance, never again.
        return json({
          ok: true,
          existing: true,
          licence: {
            key_masked: maskLicenceKey(String(lic.key ?? "")),
            user_id: lic.user_id,
            device_id: lic.device_id ?? null,
            status: lic.status,
            created_at: lic.created_at,
          },
        });
      }
      return json({ ok: true, existing: false, licence: lic });
    }

    if (path === "/api/licence-web/release" && method === "POST") {
      if (!licenceWebOriginOk()) return json({ error: "forbidden" }, 403);
      const sess = await licenceWebSession();
      if (!sess) return json({ error: "unauthorized" }, 401);
      if (!env.LICENCE_ADMIN_TOKEN) return json({ error: "licence_not_configured" }, 503);
      const row = await env.DB.prepare("SELECT key FROM licences WHERE user_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1")
        .bind(sess.email)
        .first<{ key: string }>();
      if (!row) return json({ error: "licence_not_found" }, 404);
      const res = await licenceWorkerCall("/api/licence/release", { key: row.key });
      if (res.status !== 200) return json(res.body, res.status);
      await insertTrace(env.DB, sess.email, "", "licence_web_release", {});
      return json({ ok: true, released: true });
    }

    if (path === "/api/licence-web/admin/licences" && method === "GET") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") ?? "20") || 20));
      const offset = Math.max(0, Number(url.searchParams.get("offset") ?? "0") || 0);
      // limit/offset are clamped integers above, interpolated (not bound)
      // because the test FakeD1 only parses literal LIMIT (no OFFSET);
      // real D1 accepts literals identically. Never a raw user string.
      // OFFSET is applied in JS after fetching limit+offset rows.
      const rows = await env.DB.prepare(
        `SELECT key, user_id, device_id, status, created_at FROM licences ORDER BY created_at DESC LIMIT ${limit + offset}`,
      ).all<Record<string, unknown>>();
      const all = rows.results ?? [];
      const page = all.slice(offset, offset + limit);
      return json({ ok: true, licences: page, count: page.length });
    }

    if (path === "/api/licence-web/admin/revoke" && method === "POST") {
      if (!isBillingAdmin()) return json({ error: "unauthorized" }, 401);
      const body = await readJson(request);
      const key = typeof body.key === "string" ? body.key.trim().toUpperCase() : "";
      if (!key) return json({ error: "bad_request" }, 400);
      const row = await env.DB.prepare("SELECT key, user_id, status FROM licences WHERE key = ?")
        .bind(key)
        .first<{ key: string; user_id: string; status: string }>();
      if (!row) return json({ error: "licence_not_found" }, 404);
      if (row.status === "revoked") return json({ ok: true, key, revoked: true, already: true });
      await env.DB.prepare("UPDATE licences SET status = ? WHERE key = ?").bind("revoked", key).run();
      await insertTrace(env.DB, row.user_id, "", "licence_web_revoke", {});
      return json({ ok: true, key, revoked: true });
    }

    return json({ error: "not_found" }, 404);
    return json({ error: "not_found" }, 404);
  } catch (e) {
    // G-17: first Sentry call site — registered with ctx.waitUntil so
    // the send survives the 500 response; captureError never throws.
    observe(ctx, captureError(env, e, { route: "handleRequest" }));
    return json({ error: "server_error", detail: String((e as Error)?.message ?? e) }, 500);
  }
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: { waitUntil(promise: Promise<unknown>): void },
  ): Promise<Response> {
    // G-17: ctx is threaded into handleRequest so observability sends
    // (Sentry catch-all, llm_route trace) survive the response via
    // waitUntil instead of being dropped by the runtime.
    return handleRequest(request, env, ctx);
  },
  // B-3: Cloudflare Cron Trigger (wrangler.toml [triggers]) — the hub
  // ticks itself every 5 min, so due scheduled_jobs fire even when
  // GitHub's scheduler drops/delays the dispatcher. Same runner as the
  // HTTP tick; idempotency prevents double-fires with GitHub ticks.
  async scheduled(
    event: { cron: string; scheduledTime: number },
    env: Env,
    ctx: { waitUntil(promise: Promise<unknown>): void },
  ): Promise<void> {
    ctx.waitUntil(
      runCronTick(env, "cf-cron", event.cron, event.scheduledTime).then(
        (r) => console.log("cf-cron tick", JSON.stringify(r)),
        (e) => console.log("cf-cron tick failed", String((e as Error)?.message ?? e)),
      ),
    );
  },
};
