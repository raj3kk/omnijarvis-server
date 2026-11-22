/**
 * fcm.ts — Firebase Cloud Messaging (FCM v1) send wiring (1.12.0).
 *
 * Before this file: ZERO Firebase/FCM code existed anywhere in the
 * Worker or the app (R4 audit finding). This module is the send path:
 * service-account key -> Google OAuth2 access token (RS256 JWT, pure
 * WebCrypto — no SDK, no new dependency) -> FCM v1 messages:send.
 *
 * Env (Workers secret — NAME only, never the value):
 * - FIREBASE_SERVICE_ACCOUNT_JSON (secret): the whole service-account
 *   JSON as one secret. Unset/malformed = not_configured, sends
 *   honestly refuse; nothing is ever faked.
 *
 * Hard rules (same as email.ts):
 * - The service-account key and every FCM token are NEVER logged,
 *   never returned in a response, never stored in traces. Error
 *   strings carry only the FCM status enum / HTTP code — never a
 *   response body that could contain a token.
 * - sendFcm never throws for HTTP/fetch failures; every attempt is
 *   recorded in D1 (fcm_sends) with an honest status.
 * - FCM 404 UNREGISTERED deletes the stale token row (the device
 *   re-registers on next app start via onNewToken / app-start fetch).
 */
import type { D1Like } from "./db";
import { newBillingId } from "./billing";

export interface FcmEnv {
  FIREBASE_SERVICE_ACCOUNT_JSON?: string;
}

export const FCM_MESSAGING_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
export const FCM_SEND_URL = (projectId: string): string =>
  `https://fcm.googleapis.com/v1/projects/${projectId}/messages:send`;

/** Access-token cache: module-level, per-isolate (Workers may run
 * many isolates — worst case one mint per send; correct, just
 * slower). Refresh 5 min before expiry. */
const TOKEN_CACHE_REFRESH_MS = 300_000;
let cachedToken: { token: string; expMs: number; projectId: string } | null = null;

export function clearFcmTokenCache(): void {
  cachedToken = null;
}

export interface ServiceAccount {
  project_id: string;
  client_email: string;
  private_key: string;
  private_key_id?: string;
  token_uri: string;
}

export function parseServiceAccount(env: FcmEnv): ServiceAccount | null {
  const raw = env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<ServiceAccount>;
    if (
      typeof parsed.project_id !== "string" ||
      !parsed.project_id ||
      typeof parsed.client_email !== "string" ||
      !parsed.client_email ||
      typeof parsed.private_key !== "string" ||
      !parsed.private_key.includes("BEGIN PRIVATE KEY") ||
      typeof parsed.token_uri !== "string" ||
      !parsed.token_uri
    ) {
      return null;
    }
    return parsed as ServiceAccount;
  } catch {
    return null;
  }
}

export function isFcmConfigured(env: FcmEnv): boolean {
  return parseServiceAccount(env) !== null;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export type MintResult =
  | { ok: true; token: string; projectId: string }
  | { ok: false; error: "not_configured" | "token_mint_failed"; detail?: string };

/**
 * Mint a Google OAuth2 access token from the service account.
 * Pure WebCrypto RS256: header {alg RS256, typ JWT, kid} + claims
 * {iss, scope, aud=token_uri, exp, iat}, POST token_uri with
 * grant_type jwt-bearer. Returns the token; the caller never sees
 * the key. `nowMs` is injectable for tests.
 */
export async function mintAccessToken(
  env: FcmEnv,
  nowMs = Date.now(),
): Promise<MintResult> {
  const sa = parseServiceAccount(env);
  if (!sa) return { ok: false, error: "not_configured" };
  if (cachedToken && cachedToken.projectId === sa.project_id && nowMs < cachedToken.expMs - TOKEN_CACHE_REFRESH_MS) {
    return { ok: true, token: cachedToken.token, projectId: sa.project_id };
  }
  const nowSec = Math.floor(nowMs / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: sa.private_key_id ?? "" };
  const claims = {
    iss: sa.client_email,
    scope: FCM_MESSAGING_SCOPE,
    aud: sa.token_uri,
    exp: nowSec + 3600,
    iat: nowSec,
  };
  const enc = new TextEncoder();
  const input = `${base64UrlEncode(enc.encode(JSON.stringify(header)))}.${base64UrlEncode(enc.encode(JSON.stringify(claims)))}`;
  let signature: ArrayBuffer;
  try {
    const der = pemToDer(sa.private_key);
    const key = await crypto.subtle.importKey(
      "pkcs8",
      der.buffer as ArrayBuffer,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
    signature = await crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      key,
      enc.encode(input),
    );
  } catch {
    return { ok: false, error: "token_mint_failed", detail: "key_import_or_sign_failed" };
  }
  const jwt = `${input}.${base64UrlEncode(new Uint8Array(signature))}`;
  let res: Response;
  try {
    res = await fetch(sa.token_uri, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: jwt,
      }),
    });
  } catch {
    return { ok: false, error: "token_mint_failed", detail: "fetch_failed" };
  }
  if (!res.ok) {
    return { ok: false, error: "token_mint_failed", detail: `token_endpoint:${res.status}` };
  }
  let body: { access_token?: string; expires_in?: number };
  try {
    body = (await res.json()) as { access_token?: string; expires_in?: number };
  } catch {
    return { ok: false, error: "token_mint_failed", detail: "bad_token_response" };
  }
  if (!body.access_token) {
    return { ok: false, error: "token_mint_failed", detail: "no_access_token" };
  }
  const expiresInMs = (body.expires_in ?? 3600) * 1000;
  cachedToken = { token: body.access_token, expMs: nowMs + expiresInMs, projectId: sa.project_id };
  return { ok: true, token: body.access_token, projectId: sa.project_id };
}

// --- D1 record (fcm_tokens + fcm_sends, migration 0012) ---

export async function registerFcmToken(
  db: D1Like,
  deviceId: string,
  tenantId: string,
  token: string,
  nowMs = Date.now(),
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO fcm_tokens (device_id, tenant_id, token, updated_at) VALUES (?, ?, ?, ?) " +
        "ON CONFLICT(device_id) DO UPDATE SET tenant_id = excluded.tenant_id, token = excluded.token, updated_at = excluded.updated_at",
    )
    .bind(deviceId, tenantId, token, nowMs)
    .run();
}

export interface FcmRegistration {
  device_id: string;
  tenant_id: string;
  updated_at: number;
}

export async function getFcmRegistration(
  db: D1Like,
  deviceId: string,
): Promise<FcmRegistration | null> {
  const row = await db
    .prepare("SELECT device_id, tenant_id, updated_at FROM fcm_tokens WHERE device_id = ?")
    .bind(deviceId)
    .first<FcmRegistration>();
  return row;
}

export async function getFcmToken(
  db: D1Like,
  deviceId: string,
): Promise<string | null> {
  const row = await db
    .prepare("SELECT token FROM fcm_tokens WHERE device_id = ?")
    .bind(deviceId)
    .first<{ token: string }>();
  return row?.token ?? null;
}

export async function deleteFcmToken(db: D1Like, deviceId: string): Promise<void> {
  await db.prepare("DELETE FROM fcm_tokens WHERE device_id = ?").bind(deviceId).run();
}

export type FcmSendStatus = "sent" | "failed" | "not_configured" | "no_token";

export async function recordFcmSend(
  db: D1Like,
  opts: {
    tenantId: string;
    deviceId: string;
    kind: string;
    status: FcmSendStatus;
    fcmMessageId?: string | null;
    error?: string | null;
    nowMs?: number;
  },
): Promise<string> {
  const id = newBillingId("fcm");
  await db
    .prepare(
      "INSERT INTO fcm_sends (id, tenant_id, device_id, kind, status, fcm_message_id, error, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id, opts.tenantId, opts.deviceId, opts.kind, opts.status, opts.fcmMessageId ?? null, opts.error ?? null, opts.nowMs ?? Date.now())
    .run();
  return id;
}

export type FcmSendResult =
  | { ok: true; message_id: string; fcm_send_id: string }
  | {
      ok: false;
      error: "not_configured" | "no_token" | "token_mint_failed" | "fcm_error" | "fetch_failed";
      status?: number;
      detail?: string;
      fcm_send_id: string | null;
    };

export interface SendFcmOpts {
  tenantId: string;
  deviceId: string;
  title: string;
  body: string;
  kind?: string;
  data?: Record<string, string>;
  nowMs?: number;
}

/**
 * Send one data-only push to a paired device. Data-only (no
 * `notification` payload) so the app renders it — display control
 * stays on-device. Returns the FCM message name on success.
 * Never throws for HTTP/fetch failures. The error string carries
 * only the FCM status enum / HTTP code — never a response body.
 */
export async function sendFcm(
  env: FcmEnv,
  db: D1Like,
  opts: SendFcmOpts,
): Promise<FcmSendResult> {
  const kind = opts.kind ?? "test";
  const nowMs = opts.nowMs ?? Date.now();
  if (!isFcmConfigured(env)) {
    let id: string | null = null;
    try {
      id = await recordFcmSend(db, { tenantId: opts.tenantId, deviceId: opts.deviceId, kind, status: "not_configured", error: "fcm_not_configured", nowMs });
    } catch {
      id = null;
    }
    return { ok: false, error: "not_configured", fcm_send_id: id };
  }
  const token = await getFcmToken(db, opts.deviceId);
  if (!token) {
    let id: string | null = null;
    try {
      id = await recordFcmSend(db, { tenantId: opts.tenantId, deviceId: opts.deviceId, kind, status: "no_token", error: "no_token_registered", nowMs });
    } catch {
      id = null;
    }
    return { ok: false, error: "no_token", fcm_send_id: id };
  }
  const minted = await mintAccessToken(env, nowMs);
  if (!minted.ok) {
    let id: string | null = null;
    try {
      id = await recordFcmSend(db, { tenantId: opts.tenantId, deviceId: opts.deviceId, kind, status: "failed", error: `token_mint_failed:${minted.detail ?? ""}`.slice(0, 120), nowMs });
    } catch {
      id = null;
    }
    return { ok: false, error: "token_mint_failed", detail: minted.detail, fcm_send_id: id };
  }
  const data: Record<string, string> = {
    title: opts.title,
    body: opts.body,
    kind,
    ...(opts.data ?? {}),
  };
  let res: Response;
  try {
    res = await fetch(FCM_SEND_URL(minted.projectId), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${minted.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        message: { token, data, android: { priority: "HIGH" } },
      }),
    });
  } catch {
    let id: string | null = null;
    try {
      id = await recordFcmSend(db, { tenantId: opts.tenantId, deviceId: opts.deviceId, kind, status: "failed", error: "fetch_failed", nowMs });
    } catch {
      id = null;
    }
    return { ok: false, error: "fetch_failed", fcm_send_id: id };
  }
  if (!res.ok) {
    // Parse only the status enum (safe); never echo the body.
    let fcmStatus = "";
    try {
      const errBody = (await res.json()) as { error?: { status?: string; message?: string } };
      fcmStatus = errBody.error?.status ?? "";
    } catch {
      fcmStatus = "";
    }
    const errorLabel = `fcm_error:${res.status}${fcmStatus ? `:${fcmStatus}` : ""}`.slice(0, 120);
    if (res.status === 404 && fcmStatus === "UNREGISTERED") {
      // Stale token: the device re-registers on next app start.
      try {
        await deleteFcmToken(db, opts.deviceId);
      } catch {
        // Best-effort cleanup — the failure record below still lands.
      }
    }
    let id: string | null = null;
    try {
      id = await recordFcmSend(db, { tenantId: opts.tenantId, deviceId: opts.deviceId, kind, status: "failed", error: errorLabel, nowMs });
    } catch {
      id = null;
    }
    return { ok: false, error: "fcm_error", status: res.status, detail: fcmStatus || undefined, fcm_send_id: id };
  }
  let messageId = "";
  try {
    messageId = ((await res.json()) as { name?: string }).name ?? "";
  } catch {
    messageId = "";
  }
  let id: string | null = null;
  try {
    id = await recordFcmSend(db, { tenantId: opts.tenantId, deviceId: opts.deviceId, kind, status: "sent", fcmMessageId: messageId || null, nowMs });
  } catch {
    id = null;
  }
  return { ok: true, message_id: messageId, fcm_send_id: id ?? "" };
}
