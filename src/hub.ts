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
 */
import { JarvisHub } from "./do/JarvisHub";

export { JarvisHub };

export interface Env {
  JARVIS_HUB: DurableObjectNamespace;
  DB: D1Database;
  INTERNAL_SECRET?: string;
  CRON_SECRET?: string;
  KEY_ENC_SECRET?: string;
  LLM_ADMIN_TOKEN?: string;
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
const VERSION = "3b";

import { consumePairingToken, deriveSixDigit, deriveTenantId, issuePairingToken, registerDevice } from "./pairing";
import { handleSync, type SyncRequest } from "./sync";
import { handleTick, type DispatchStep } from "./cron";
import { checkRateLimit } from "./ratelimit";
import { getDevice, getTenant, verifyLicenceKey } from "./db";
import { completeTurn, loadRouterConfig, routeLlm, validateGeminiKey, type RequestKind } from "./router";
import { encryptTenantKey, importMasterKey } from "./keyvault";
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
      return json({ ok: true, device_id: deviceId });
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
