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
 */
import { JarvisHub } from "./do/JarvisHub";

export { JarvisHub };

export interface Env {
  JARVIS_HUB: DurableObjectNamespace;
  DB: D1Database;
  INTERNAL_SECRET?: string;
  CRON_SECRET?: string;
  UPSTASH_REDIS_REST_URL?: string;
  UPSTASH_REDIS_REST_TOKEN?: string;
  LANGFUSE_PUBLIC_KEY?: string;
  LANGFUSE_SECRET_KEY?: string;
  LANGFUSE_HOST?: string;
  SENTRY_DSN?: string;
}

const SERVICE = "omnijarvis-hub";
const VERSION = "2b-1-d1";

import { consumePairingToken, deriveSixDigit, deriveTenantId, issuePairingToken, registerDevice } from "./pairing";
import { handleSync, type SyncRequest } from "./sync";
import { handleTick, type DispatchStep } from "./cron";
import { checkRateLimit } from "./ratelimit";
import { getDevice, verifyLicenceKey } from "./db";

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
