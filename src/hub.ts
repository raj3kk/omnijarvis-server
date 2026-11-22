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
 * - /api/skills/submit: paired device + Ed25519 signature (docs-style)
 *   or x-internal-secret; ALWAYS quarantined, never auto-approved (3d).
 * - /api/skills/review: x-admin-token (LLM_ADMIN_TOKEN); approve needs
 *   a clean Render AST scan re-run + Ed25519 sign (SKILL_SIGN_SECRET).
 * - /api/skills/library: approved-only; Free = 1 skill, Pro/Business =
 *   full library. Quarantined skills are never listed (3d).
 * - /api/memory/*: paired device + Ed25519 or x-internal-secret;
 *   D1-backed vector store (JS cosine, cap 500/tenant). Qdrant is
 *   env-gated and NOT live (account pending) — D1 fallback (3d).
 * - /api/billing/*: subscription + UPI flow (Phase 4, UPI-only — no
 *   gateway). subscribe/utr/renew/upgrade/downgrade: paired device or
 *   x-internal-secret; /admin/*: x-admin-token (LLM_ADMIN_TOKEN).
 *   Ledger = D1 batch transactions (GAP-10 fix). Caps hard-enforced.
 * - /api/e2b/*: E2B runs (Phase 4) — x-internal-secret; no E2B account
 *   yet (U-4) so runs honestly refuse e2b_not_configured; hold/settle/
 *   release/kill + 15-min auto-kill via the billing sweep.
 * - /api/legal/*: public Terms/Privacy/Refund pages (JSON).
 * - /api/billing/cron-jobs: job create (cap-checked) + list + disable.
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
  RENDER_WORKER_URL?: string;
  E2B_API_KEY?: string; // Phase 4: unset = e2b_not_configured (U-4, no account yet)
  UPSTASH_REDIS_REST_URL?: string;
  UPSTASH_REDIS_REST_TOKEN?: string;
  LANGFUSE_PUBLIC_KEY?: string;
  LANGFUSE_SECRET_KEY?: string;
  LANGFUSE_HOST?: string;
  SENTRY_DSN?: string;
}

const SERVICE = "omnijarvis-hub";
const VERSION = "7"; // 7: self-extension server mirror (validateResearchCandidate + classifySkillClass + self_extended template strip-check; submit still always quarantined)

import { consumePairingToken, deriveSixDigit, deriveTenantId, issuePairingToken, registerDevice } from "./pairing";
import { getHubPublicKey, importPrivateKey } from "./crypto";
import { handleSync, type SyncRequest } from "./sync";
import { constantTimeEqual, handleTick, type DispatchStep } from "./cron";
import { checkRateLimit } from "./ratelimit";
import { d1Batch, getDevice, getTenant, insertTrace, verifyLicenceKey } from "./db";
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
  getSkill,
  getSkillPublicKey,
  getSkillSignature,
  insertSkill,
  insertSkillReview,
  insertSkillSignature,
  listApprovedSkills,
  manifestHash,
  newSkillId,
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

/**
 * Shared cron-tick runner (B-3: GitHub scheduler bypass).
 * Used by BOTH entry points so the behaviour is identical:
 *  - POST /api/cron/tick (GitHub Actions dispatcher, header-secret gated)
 *  - Cloudflare Cron Trigger (scheduled(), Worker's own CRON_SECRET)
 * The tick itself is idempotent (cron.ts: cron_fire trace per job+minute),
 * so a GitHub tick and a Cloudflare tick in the same minute never
 * double-fire a job. Billing sweeps run after the tick in both paths.
 */
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
  const result = await handleTick(env.DB, env, env.CRON_SECRET ?? null, dispatch);
  const sweeps = await runBillingSweeps(env.DB);
  return { ...result, billing_sweeps: sweeps };
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
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

    // Pairing: init (licence-verified, rate-limited).
    if (path === "/api/pairing/init" && method === "POST") {
      const rl = await checkRateLimit(env, "pairingInit", clientIp(request));
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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

    // Sync proxy (paired + signed).
    if (path === "/api/sync" && method === "POST") {
      const body = await readJson(request);
      const deviceId = typeof body.device_id === "string" ? body.device_id : "";
      const rl = await checkRateLimit(env, "sync", deviceId || clientIp(request));
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
      const syncReq = body as unknown as SyncRequest;
      if (!deviceId || !syncReq.table || !Array.isArray(syncReq.rows)) {
        return json({ error: "bad_request" }, 400);
      }
      const rawRowsJson = JSON.stringify(syncReq.rows);
      const result = await handleSync(env.DB, syncReq, rawRowsJson);
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (result.ok) return json(result);
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
        return json({ ok: true });
      }
      if (method === "DELETE" && path.endsWith("/groq-key")) {
        await env.DB.prepare("UPDATE tenants SET groq_key_enc = NULL WHERE id = ?").bind(tenantId).run();
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
          return json({ ok: true });
        }
        await env.DB
          .prepare("UPDATE tenants SET gemini_key_enc = ?, billing_mode = ? WHERE id = ?")
          .bind(enc, billingMode, tenantId)
          .run();
        return json({ ok: true, billing_mode: billingMode });
      }
      return json({ error: "not_found" }, 404);
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      const pdfUrl = `${(env.RENDER_WORKER_URL ?? "").replace(/\/+$/, "")}/doc/certificate?hash=${hash}`;
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await readJson(request);
      const taskId = typeof body.task_id === "string" ? body.task_id : "";
      if (!taskId || typeof body.solved !== "boolean") return json({ error: "bad_request" }, 400);
      const task = await getBrowserTask(env.DB, taskId);
      if (!task) return json({ error: "task_not_found" }, 404);
      const outcome: AssistOutcome =
        body.aborted === true ? "aborted" : body.solved === true ? "solved" : "timeout";
      const res = await resolveCaptchaAssist(env.DB, taskId, outcome);
      if (!res.ok) return json({ error: "task_not_found" }, 404);
      await insertTrace(
        env.DB,
        task.tenant_id,
        task.device_id,
        "captcha_assist",
        captchaAssistTrace(task.id, task.site, {
          solved: body.solved === true,
          duration_s: typeof body.duration_s === "number" ? body.duration_s : undefined,
          outcome,
        }),
      );
      return json({ ok: true, task_id: taskId, status: res.status });
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
      const deleted = await wipeMemories(env.DB, tenantId);
      const q = qdrantStatus(env);
      return json({ ok: true, deleted, qdrant: q.configured ? "configured" : "not_configured" });
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      // Email send is NOT wired (U-6 — no Resend/SMTP in this Worker):
      // the token hash + 24h expiry are stored; delivery is an open item.
      return json({ ok: true, verification_pending: true });
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
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

    return json({ error: "not_found" }, 404);
  } catch (e) {
    return json({ error: "server_error", detail: String((e as Error)?.message ?? e) }, 500);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
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
