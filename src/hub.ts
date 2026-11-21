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
  ROUTER_CONFIG?: string;
  RENDER_WORKER_URL?: string;
  UPSTASH_REDIS_REST_URL?: string;
  UPSTASH_REDIS_REST_TOKEN?: string;
  LANGFUSE_PUBLIC_KEY?: string;
  LANGFUSE_SECRET_KEY?: string;
  LANGFUSE_HOST?: string;
  SENTRY_DSN?: string;
}

const SERVICE = "omnijarvis-hub";
const VERSION = "3d"; // 3d: skill registry (quarantine-first + Ed25519 sign) + memory API (D1 vectors, Qdrant env-gated)

import { consumePairingToken, deriveSixDigit, deriveTenantId, issuePairingToken, registerDevice } from "./pairing";
import { getHubPublicKey, importPrivateKey } from "./crypto";
import { handleSync, type SyncRequest } from "./sync";
import { handleTick, type DispatchStep } from "./cron";
import { checkRateLimit } from "./ratelimit";
import { getDevice, getTenant, insertTrace, verifyLicenceKey } from "./db";
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
import { completeTurn, loadRouterConfig, routeLlm, validateGeminiKey, type RequestKind } from "./router";
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
  setSkillStatus,
  signSkill,
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

    // Cron tick (secret-gated).
    if (path === "/api/cron/tick" && method === "POST") {
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
      const result = await handleTick(env.DB, env, request.headers.get("x-cron-secret"), dispatch);
      if (!result.ok && result.error === "unauthorized") return json({ error: "unauthorized" }, 401);
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
    // Key is validated (tiny Gemini call) then AES-GCM encrypted into D1.
    // The key value is NEVER echoed back, logged, or stored plaintext.
    if (path.startsWith("/api/tenants/") && (path.endsWith("/key") || path.endsWith("/key-status"))) {
      if (!env.LLM_ADMIN_TOKEN || request.headers.get("x-admin-token") !== env.LLM_ADMIN_TOKEN) {
        return json({ error: "unauthorized" }, 401);
      }
      const parts = path.split("/").filter(Boolean); // api, tenants, :id, key[-status]
      const tenantId = parts[2] ?? "";
      if (!tenantId) return json({ error: "bad_request" }, 400);
      const tenant = await getTenant(env.DB, tenantId);
      if (!tenant) return json({ error: "tenant_not_found" }, 404);
      if (method === "GET" && path.endsWith("/key-status")) {
        return json({ ok: true, has_key: !!tenant.gemini_key_enc, billing_mode: tenant.billing_mode });
      }
      if (method === "DELETE" && path.endsWith("/key")) {
        await env.DB.prepare("UPDATE tenants SET gemini_key_enc = NULL WHERE id = ?").bind(tenantId).run();
        return json({ ok: true });
      }
      if (method === "POST" && path.endsWith("/key")) {
        const body = await readJson(request);
        const key = typeof body.gemini_key === "string" ? body.gemini_key : "";
        const billingMode = typeof body.billing_mode === "string" ? body.billing_mode : tenant.billing_mode;
        if (!key) return json({ error: "bad_request" }, 400);
        if (billingMode === "founder_pays" && !env.FOUNDER_GEMINI_KEY) {
          return json({ error: "founder_pays_not_enabled" }, 400);
        }
        if (!env.KEY_ENC_SECRET) return json({ error: "key_vault_not_configured" }, 500);
        const valid = await validateGeminiKey(key);
        if (!valid) return json({ error: "invalid_key" }, 400);
        const master = await importMasterKey(env.KEY_ENC_SECRET);
        const enc = await encryptTenantKey(master, key);
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
      });
      return json({ ok: true, skill_id: skillId, status: "quarantined", scan });
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
};
