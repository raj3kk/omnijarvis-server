/**
 * google.ts — Direct Google OAuth (Gmail + Drive), Track E item #27.
 *
 * The Layer 8 free path, replacing Nango (Elastic 2.0 — correctly not
 * used). Google's own APIs are free; the only prerequisite is a GCP
 * OAuth client (client ID + secret), created by the parent in the GCP
 * console — this code is fully env-gated on GOOGLE_OAUTH_CLIENT_ID +
 * GOOGLE_OAUTH_CLIENT_SECRET and works with no keys present (honest
 * `google_oauth_not_configured` errors, never fake success).
 *
 * Flow: /oauth/google/start (signed device) -> Google consent ->
 * /oauth/google/callback -> token exchange -> encrypted store in D1
 * (`google_tokens`, migration 0010) -> refresh on expiry -> revoke.
 * Token encryption reuses the keyvault.ts AES-GCM envelope (master key
 * KEY_ENC_SECRET, same as gemini_key_enc / groq_key_enc).
 *
 * Scopes (minimal, see DESIGN.md §2): gmail.readonly + gmail.send +
 * drive.readonly (+ `email` so the userinfo call can resolve the
 * connected account's address). R4.8 adds drive.file (upload/create —
 * app-created files only, least privilege) + calendar.events (list +
 * create). No gmail.modify, no full-drive scope. A token granted
 * BEFORE R4.8 has drive.readonly only — Drive write / Calendar calls
 * with it get a clean `google_reconnect_required` (403) and the app
 * sends the user back through consent; the old token keeps working
 * read-only until then (nothing is broken by the scope change).
 *
 * Tenant isolation: the tenant is NEVER taken from a client-supplied
 * tenant_id on API routes — signed device requests resolve it via
 * getDevice(device_id).tenant_id (authorizeDocsRequest pattern);
 * x-internal-secret callers pass tenant_id explicitly. The callback
 * trusts only the server-side one-time state row.
 *
 * `fetchFn` is injectable (router.ts pattern) so vitest can mock
 * Google without network. No token value is ever logged or returned
 * (status returns email + scopes + expiry only).
 */
import { base64ToBytes, bytesToBase64 } from "./crypto";
import type { D1Like } from "./db";
import { decryptTenantKey, encryptTenantKey, importMasterKey } from "./keyvault";

export const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
export const GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";
export const GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
export const GOOGLE_GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1/users/me";
export const GOOGLE_DRIVE_BASE = "https://www.googleapis.com/drive/v3/files";
export const GOOGLE_DRIVE_UPLOAD_BASE = "https://www.googleapis.com/upload/drive/v3/files";
export const GOOGLE_CALENDAR_BASE = "https://www.googleapis.com/calendar/v3/calendars/primary/events";

/** Minimal scopes — see DESIGN.md §2 for the justification of each. */
export const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/drive.readonly",
  // R4.8 (U27): Drive write via drive.file (app-created files only) +
  // Calendar events. Old tokens (drive.readonly) get a clean
  // google_reconnect_required on write calls — see driveUploadFile.
  "https://www.googleapis.com/auth/drive.file",
  "https://www.googleapis.com/auth/calendar.events",
  "email",
];

/** One-time OAuth state rows: a human is in the loop (consent screen). */
export const OAUTH_STATE_TTL_MS = 600_000; // 10 min
/** Refresh when the access token dies within this window. */
export const REFRESH_SKEW_MS = 60_000; // 60 s
/** Drive content cap for agent steps — larger files return metadata only. */
export const DRIVE_MAX_BYTES = 512 * 1024; // 512 KB
/** Drive upload cap (decoded bytes) — v1 bound, documented in BUILD_NOTES. */
export const DRIVE_UPLOAD_MAX_BYTES = 1024 * 1024; // 1 MB
/** Gmail list cap for agent steps. */
export const GMAIL_MAX_RESULTS = 10;

export interface GoogleEnv {
  GOOGLE_OAUTH_CLIENT_ID?: string;
  GOOGLE_OAUTH_CLIENT_SECRET?: string;
  KEY_ENC_SECRET?: string;
}

export function isGoogleOAuthConfigured(env: GoogleEnv): boolean {
  return Boolean(env.GOOGLE_OAUTH_CLIENT_ID && env.GOOGLE_OAUTH_CLIENT_SECRET);
}

/** Redirect URI — must be registered verbatim in the GCP OAuth client. */
export function googleRedirectUri(origin: string): string {
  return `${origin.replace(/\/+$/, "")}/oauth/google/callback`;
}

export class GoogleError extends Error {
  code: string;
  status: number;
  constructor(code: string, status: number, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

function notConfigured(): GoogleError {
  return new GoogleError("google_oauth_not_configured", 503, "Google OAuth is not configured on the hub (GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET missing)");
}

function notConnected(): GoogleError {
  return new GoogleError("google_not_connected", 404, "No Google account connected for this tenant — connect in AI Brain > Google");
}

/** Consent URL. Throws GoogleError(google_oauth_not_configured) with no keys. */
export function buildAuthUrl(env: GoogleEnv, origin: string, state: string): string {
  if (!isGoogleOAuthConfigured(env)) throw notConfigured();
  const params = new URLSearchParams({
    client_id: env.GOOGLE_OAUTH_CLIENT_ID as string,
    redirect_uri: googleRedirectUri(origin),
    response_type: "code",
    scope: GOOGLE_SCOPES.join(" "),
    // offline = refresh token; prompt=consent = a refresh token is
    // returned on EVERY grant (Google only sends one on the first
    // grant otherwise — a re-connect after revoke would silently
    // yield no refresh token and break background refresh).
    access_type: "offline",
    prompt: "consent",
    state,
  });
  return `${GOOGLE_AUTH_URL}?${params.toString()}`;
}

// --- One-time state rows (D1 google_oauth_states, pairing_tokens shape) ---

export async function issueOAuthState(db: D1Like, tenantId: string, deviceId: string): Promise<string> {
  const state = [...crypto.getRandomValues(new Uint8Array(16))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  await db
    .prepare("INSERT INTO google_oauth_states (state, tenant_id, device_id, expires_at) VALUES (?, ?, ?, ?)")
    .bind(state, tenantId, deviceId, Date.now() + OAUTH_STATE_TTL_MS)
    .run();
  return state;
}

export async function consumeOAuthState(
  db: D1Like,
  state: string,
): Promise<{ tenant_id: string; device_id: string } | null> {
  const row = await db
    .prepare("SELECT state, tenant_id, device_id, expires_at FROM google_oauth_states WHERE state = ?")
    .bind(state)
    .first<{ state: string; tenant_id: string; device_id: string; expires_at: number }>();
  if (!row) return null;
  // One-time use: delete first (a replayed state finds no row).
  await db.prepare("DELETE FROM google_oauth_states WHERE state = ?").bind(state).run();
  if (row.expires_at < Date.now()) return null;
  return { tenant_id: row.tenant_id, device_id: row.device_id };
}

// --- Token exchange + vault (D1 google_tokens, migration 0010) ---

export interface TokenSet {
  accessToken: string;
  refreshToken: string;
  expiresAt: number; // unix ms
  scopes: string;
}

async function postForm(
  fetchFn: typeof fetch,
  url: string,
  params: Record<string, string>,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetchFn(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
  let parsed: Record<string, unknown> = {};
  try {
    parsed = (await res.json()) as Record<string, unknown>;
  } catch {
    parsed = {};
  }
  return { status: res.status, json: parsed };
}

/** Authorization-code exchange. Throws on any non-2xx (no partial state). */
export async function exchangeCodeForTokens(
  env: GoogleEnv,
  code: string,
  origin: string,
  fetchFn: typeof fetch = fetch,
): Promise<TokenSet> {
  if (!isGoogleOAuthConfigured(env)) throw notConfigured();
  const { status, json } = await postForm(fetchFn, GOOGLE_TOKEN_URL, {
    code,
    client_id: env.GOOGLE_OAUTH_CLIENT_ID as string,
    client_secret: env.GOOGLE_OAUTH_CLIENT_SECRET as string,
    redirect_uri: googleRedirectUri(origin),
    grant_type: "authorization_code",
  });
  if (status < 200 || status >= 300 || typeof json.access_token !== "string") {
    throw new GoogleError(
      "google_token_exchange_failed",
      502,
      `Google token exchange failed (HTTP ${status})`,
    );
  }
  if (typeof json.refresh_token !== "string" || !json.refresh_token) {
    // prompt=consent should always yield one; if Google ever doesn't,
    // say so honestly instead of storing a vault row that can never
    // refresh.
    throw new GoogleError(
      "google_no_refresh_token",
      502,
      "Google did not return a refresh token — re-connect and approve offline access",
    );
  }
  const expiresIn = typeof json.expires_in === "number" ? json.expires_in : 3600;
  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token,
    expiresAt: Date.now() + expiresIn * 1000,
    scopes: typeof json.scope === "string" ? json.scope : GOOGLE_SCOPES.join(" "),
  };
}

export async function fetchGoogleEmail(accessToken: string, fetchFn: typeof fetch = fetch): Promise<string> {
  const res = await fetchFn(GOOGLE_USERINFO_URL, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new GoogleError("google_userinfo_failed", 502, `Google userinfo failed (HTTP ${res.status})`);
  const body = (await res.json()) as Record<string, unknown>;
  if (typeof body.email !== "string" || !body.email) {
    throw new GoogleError("google_userinfo_failed", 502, "Google userinfo returned no email");
  }
  return body.email;
}

async function masterKeyOrThrow(env: GoogleEnv) {
  if (!env.KEY_ENC_SECRET) {
    throw new GoogleError("key_enc_not_configured", 503, "KEY_ENC_SECRET is not configured on the hub");
  }
  return importMasterKey(env.KEY_ENC_SECRET);
}

/** Encrypt + upsert one Google account per tenant (single-owner product). */
export async function storeGoogleTokens(
  db: D1Like,
  env: GoogleEnv,
  tenantId: string,
  email: string,
  tokens: TokenSet,
): Promise<void> {
  const master = await masterKeyOrThrow(env);
  const accessEnc = await encryptTenantKey(master, tokens.accessToken);
  const refreshEnc = await encryptTenantKey(master, tokens.refreshToken);
  const now = Date.now();
  await db
    .prepare(
      "INSERT INTO google_tokens (tenant_id, google_email, access_token_enc, refresh_token_enc, scopes, expires_at, created_at, updated_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(tenant_id) DO UPDATE SET google_email = excluded.google_email, access_token_enc = excluded.access_token_enc, " +
        "refresh_token_enc = excluded.refresh_token_enc, scopes = excluded.scopes, expires_at = excluded.expires_at, updated_at = excluded.updated_at",
    )
    .bind(tenantId, email, accessEnc, refreshEnc, tokens.scopes, tokens.expiresAt, now, now)
    .run();
}

export interface StoredGoogleTokens {
  tenant_id: string;
  google_email: string;
  accessToken: string;
  refreshToken: string;
  scopes: string;
  expiresAt: number;
}

export async function loadGoogleTokens(
  db: D1Like,
  env: GoogleEnv,
  tenantId: string,
): Promise<StoredGoogleTokens | null> {
  const row = await db
    .prepare("SELECT tenant_id, google_email, access_token_enc, refresh_token_enc, scopes, expires_at FROM google_tokens WHERE tenant_id = ?")
    .bind(tenantId)
    .first<{
      tenant_id: string;
      google_email: string;
      access_token_enc: string;
      refresh_token_enc: string;
      scopes: string;
      expires_at: number;
    }>();
  if (!row) return null;
  const master = await masterKeyOrThrow(env);
  let accessToken: string;
  let refreshToken: string;
  try {
    accessToken = await decryptTenantKey(master, row.access_token_enc);
    refreshToken = await decryptTenantKey(master, row.refresh_token_enc);
  } catch {
    // Master-key rotation makes old envelopes undecryptable (keyvault
    // § rotation note) — the tenant must re-connect, not get a 500.
    throw new GoogleError("google_token_decrypt_failed", 401, "Stored Google tokens cannot be decrypted — re-connect in AI Brain > Google");
  }
  return {
    tenant_id: row.tenant_id,
    google_email: row.google_email,
    accessToken,
    refreshToken,
    scopes: row.scopes,
    expiresAt: row.expires_at,
  };
}

/** Public status shape — tokens are NEVER returned. */
export async function googleStatus(
  db: D1Like,
  env: GoogleEnv,
  tenantId: string,
): Promise<{ configured: boolean; connected: boolean; email?: string; scopes?: string; expires_at?: number }> {
  if (!isGoogleOAuthConfigured(env)) return { configured: false, connected: false };
  const row = await db
    .prepare("SELECT google_email, scopes, expires_at FROM google_tokens WHERE tenant_id = ?")
    .bind(tenantId)
    .first<{ google_email: string; scopes: string; expires_at: number }>();
  if (!row) return { configured: true, connected: false };
  return { configured: true, connected: true, email: row.google_email, scopes: row.scopes, expires_at: row.expires_at };
}

// --- Refresh (transparent to callers) ---

export interface GoogleApiDeps {
  db: D1Like;
  env: GoogleEnv;
  tenantId: string;
  fetchFn?: typeof fetch;
}

async function refreshAccessToken(
  deps: GoogleApiDeps,
  stored: StoredGoogleTokens,
): Promise<StoredGoogleTokens> {
  const fetchFn = deps.fetchFn ?? fetch;
  if (!isGoogleOAuthConfigured(deps.env)) throw notConfigured();
  const { status, json } = await postForm(fetchFn, GOOGLE_TOKEN_URL, {
    grant_type: "refresh_token",
    refresh_token: stored.refreshToken,
    client_id: deps.env.GOOGLE_OAUTH_CLIENT_ID as string,
    client_secret: deps.env.GOOGLE_OAUTH_CLIENT_SECRET as string,
  });
  if (status < 200 || status >= 300 || typeof json.access_token !== "string") {
    const err = typeof json.error === "string" ? json.error : "";
    if (err === "invalid_grant") {
      // User revoked at Google (or the grant died) — the stored row is
      // dead. Delete it so status honestly reports not-connected and
      // the app prompts a re-connect instead of retrying forever.
      await deps.db.prepare("DELETE FROM google_tokens WHERE tenant_id = ?").bind(deps.tenantId).run();
      throw notConnected();
    }
    throw new GoogleError("google_refresh_failed", 502, `Google token refresh failed (HTTP ${status})`);
  }
  const expiresIn = typeof json.expires_in === "number" ? json.expires_in : 3600;
  const next: StoredGoogleTokens = {
    ...stored,
    accessToken: json.access_token,
    // Google rotates refresh tokens only sometimes — keep the old one
    // unless a new one arrives.
    refreshToken: typeof json.refresh_token === "string" && json.refresh_token ? json.refresh_token : stored.refreshToken,
    expiresAt: Date.now() + expiresIn * 1000,
  };
  await storeGoogleTokens(deps.db, deps.env, deps.tenantId, next.google_email, {
    accessToken: next.accessToken,
    refreshToken: next.refreshToken,
    expiresAt: next.expiresAt,
    scopes: next.scopes,
  });
  return next;
}

/** Valid access token for the tenant, refreshing transparently when due. */
export async function getValidAccessToken(deps: GoogleApiDeps): Promise<StoredGoogleTokens> {
  if (!isGoogleOAuthConfigured(deps.env)) throw notConfigured();
  const stored = await loadGoogleTokens(deps.db, deps.env, deps.tenantId);
  if (!stored) throw notConnected();
  if (stored.expiresAt - Date.now() < REFRESH_SKEW_MS) {
    return refreshAccessToken(deps, stored);
  }
  return stored;
}

async function googleFetch(
  deps: GoogleApiDeps,
  url: string,
  init: RequestInit = {},
): Promise<{ status: number; json: unknown; text: string }> {
  const fetchFn = deps.fetchFn ?? fetch;
  const stored = await getValidAccessToken(deps);
  const res = await fetchFn(url, {
    ...init,
    headers: { Authorization: `Bearer ${stored.accessToken}`, ...(init.headers ?? {}) },
  });
  const text = await res.text();
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }
  if (res.status === 401) {
    // One refresh + one retry (a token can die between the expiry
    // check and the call). A second 401 is the true answer.
    const refreshed = await refreshAccessToken(deps, stored);
    const retry = await fetchFn(url, {
      ...init,
      headers: { Authorization: `Bearer ${refreshed.accessToken}`, ...(init.headers ?? {}) },
    });
    const retryText = await retry.text();
    let retryParsed: unknown = null;
    try {
      retryParsed = JSON.parse(retryText);
    } catch {
      retryParsed = null;
    }
    if (retry.status === 401) throw notConnected();
    return { status: retry.status, json: retryParsed, text: retryText };
  }
  return { status: res.status, json: parsed, text };
}

function googleApiError(status: number, body: unknown): GoogleError {
  const msg =
    (body as { error?: { message?: string } } | null)?.error?.message ??
    (body as { error_description?: string } | null)?.error_description ??
    `Google API error (HTTP ${status})`;
  return new GoogleError("google_api_error", 502, String(msg).slice(0, 300));
}

// --- Revoke ---

export async function revokeGoogleTokens(deps: GoogleApiDeps): Promise<{ connected: boolean }> {
  const stored = await loadGoogleTokens(deps.db, deps.env, deps.tenantId).catch((e) => {
    if (e instanceof GoogleError && e.code === "google_token_decrypt_failed") return null;
    throw e;
  });
  // Best-effort revoke at Google first, then delete locally whatever
  // happens — a row for a dead grant must not linger.
  if (stored) {
    try {
      await (deps.fetchFn ?? fetch)(GOOGLE_REVOKE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: stored.refreshToken }).toString(),
      });
    } catch {
      // Network failure revoking at Google: local delete still runs —
      // the user asked to disconnect, and the refresh token is useless
      // without the stored row. Google-side revocation can also be
      // done by the user in their Google account settings.
    }
  }
  await deps.db.prepare("DELETE FROM google_tokens WHERE tenant_id = ?").bind(deps.tenantId).run();
  return { connected: false };
}

// --- Gmail helpers (agent steps GMAIL_SEND / GMAIL_READ) ---

function base64UrlEncode(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function buildRawEmail(to: string, subject: string, body: string): string {
  const raw = `To: ${to}\r\nSubject: ${subject}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${body}`;
  return base64UrlEncode(new TextEncoder().encode(raw));
}

export async function gmailSend(
  deps: GoogleApiDeps,
  input: { to: string; subject: string; body: string },
): Promise<{ id: string }> {
  const sent = await googleFetch(deps, `${GOOGLE_GMAIL_BASE}/messages/send`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw: buildRawEmail(input.to, input.subject, input.body) }),
  });
  const parsed = sent.json as Record<string, unknown> | null;
  if (sent.status < 200 || sent.status >= 300 || typeof parsed?.id !== "string") {
    throw googleApiError(sent.status, sent.json);
  }
  return { id: parsed.id };
}

export interface GmailMessageSummary {
  id: string;
  subject: string;
  from: string;
  date: string;
  snippet: string;
  body: string;
}

function headerValue(headers: Array<{ name?: string; value?: string }>, name: string): string {
  const found = (headers ?? []).find((h) => (h.name ?? "").toLowerCase() === name.toLowerCase());
  return found?.value ?? "";
}

function decodeBase64Url(data: string): string {
  const b64 = data.replace(/-/g, "+").replace(/_/g, "/");
  try {
    return new TextDecoder().decode(base64ToBytes(b64));
  } catch {
    return "";
  }
}

/** Walk a Gmail payload tree for the first text/plain part. */
function extractTextBody(payload: Record<string, unknown> | undefined): string {
  if (!payload) return "";
  const mime = payload.mimeType as string | undefined;
  const bodyObj = payload.body as { data?: unknown } | undefined;
  if (mime === "text/plain" && typeof bodyObj?.data === "string") {
    return decodeBase64Url(bodyObj.data);
  }
  const parts = payload.parts as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(parts)) {
    for (const part of parts) {
      const text = extractTextBody(part);
      if (text) return text;
    }
  }
  return "";
}

export async function gmailListMessages(
  deps: GoogleApiDeps,
  input: { q?: string; maxResults?: number },
): Promise<GmailMessageSummary[]> {
  const fetchFn = deps.fetchFn ?? fetch;
  const max = Math.min(Math.max(input.maxResults ?? 5, 1), GMAIL_MAX_RESULTS);
  const params = new URLSearchParams({ maxResults: String(max) });
  if (input.q) params.set("q", input.q);
  const list = await googleFetch(deps, `${GOOGLE_GMAIL_BASE}/messages?${params.toString()}`);
  if (list.status !== 200) throw googleApiError(list.status, list.json);
  const ids = ((list.json as { messages?: Array<{ id?: string }> } | null)?.messages ?? [])
    .map((m) => m.id)
    .filter((id): id is string => typeof id === "string");
  const out: GmailMessageSummary[] = [];
  for (const id of ids) {
    const one = await googleFetch(deps, `${GOOGLE_GMAIL_BASE}/messages/${encodeURIComponent(id)}?format=full`);
    if (one.status !== 200) continue; // one unreadable message must not fail the whole list
    const msg = one.json as Record<string, unknown>;
    const payload = msg.payload as Record<string, unknown> | undefined;
    const headers = (payload?.headers as Array<{ name?: string; value?: string }>) ?? [];
    out.push({
      id,
      subject: headerValue(headers, "Subject"),
      from: headerValue(headers, "From"),
      date: headerValue(headers, "Date"),
      snippet: typeof msg.snippet === "string" ? msg.snippet : "",
      body: extractTextBody(payload).slice(0, 8000),
    });
  }
  return out;
}

// --- Drive helper (agent step DRIVE_READ) ---

export interface DriveFileResult {
  id: string;
  name: string;
  mimeType: string;
  size?: number;
  text: string | null;
  content_note?: string;
}

function isGoogleNativeDoc(mimeType: string): boolean {
  return mimeType.startsWith("application/vnd.google-apps.");
}

export async function driveReadFile(deps: GoogleApiDeps, fileId: string): Promise<DriveFileResult> {
  const meta = await googleFetch(
    deps,
    `${GOOGLE_DRIVE_BASE}/${encodeURIComponent(fileId)}?fields=id,name,mimeType,size`,
  );
  if (meta.status !== 200) throw googleApiError(meta.status, meta.json);
  const m = meta.json as { id?: string; name?: string; mimeType?: string; size?: string };
  const name = m.name ?? fileId;
  const mimeType = m.mimeType ?? "application/octet-stream";
  const size = typeof m.size === "string" ? Number(m.size) : undefined;
  if (size !== undefined && size > DRIVE_MAX_BYTES) {
    return { id: fileId, name, mimeType, size, text: null, content_note: "content_too_large" };
  }
  let rawText: string;
  if (isGoogleNativeDoc(mimeType)) {
    // Native Docs/Sheets/Slides have no binary content — export as text.
    const exported = await googleFetch(
      deps,
      `${GOOGLE_DRIVE_BASE}/${encodeURIComponent(fileId)}/export?mimeType=text/plain`,
    );
    if (exported.status !== 200) throw googleApiError(exported.status, exported.json);
    rawText = exported.text;
  } else {
    const media = await googleFetch(deps, `${GOOGLE_DRIVE_BASE}/${encodeURIComponent(fileId)}?alt=media`);
    if (media.status !== 200) throw googleApiError(media.status, media.json);
    rawText = media.text;
  }
  if (rawText.length > DRIVE_MAX_BYTES) {
    return { id: fileId, name, mimeType, size, text: null, content_note: "content_too_large" };
  }
  // Binary content decodes lossily (res.text() inserts U+FFFD for
  // invalid UTF-8) — report honestly instead of returning garbage.
  if (rawText.includes("\uFFFD")) {
    return { id: fileId, name, mimeType, size, text: null, content_note: "binary_or_undecodable" };
  }
  return { id: fileId, name, mimeType, size, text: rawText };
}

// --- Drive write + Calendar (R4.8, U27) ---
//
// SCOPE TRAP (read before calling): Drive write needs the drive.file
// scope and Calendar needs calendar.events — both added to
// GOOGLE_SCOPES in R4.8. A token granted before R4.8 has drive.readonly
// only: Google answers 403 insufficientPermissions, and these
// functions translate that into GoogleError("google_reconnect_required",
// 403) — the app sends the user back through consent. The old token
// keeps working read-only; nothing is broken, nothing is faked.

export interface DriveUploadResult {
  id: string;
  name: string;
  mimeType: string;
}

function scopeInsufficientError(action: string): GoogleError {
  return new GoogleError(
    "google_reconnect_required",
    403,
    `${action} needs a new Google consent (Drive write / Calendar scope) — reconnect in AI Brain > Google`,
  );
}

/**
 * Upload a file to Drive (multipart upload, drive.file scope — the
 * file lands in the user's Drive, created by Jarvis). contentBase64
 * is standard base64 of the file bytes; decoded size is capped at
 * DRIVE_UPLOAD_MAX_BYTES.
 */
export async function driveUploadFile(
  deps: GoogleApiDeps,
  input: { name: string; mimeType: string; contentBase64: string },
): Promise<DriveUploadResult> {
  const name = (input.name ?? "").trim();
  if (!name || name.length > 255) {
    throw new GoogleError("bad_request", 400, "A file name (max 255 chars) is required");
  }
  const mimeType = (input.mimeType ?? "application/octet-stream").trim() || "application/octet-stream";
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(input.contentBase64 ?? "");
  } catch {
    throw new GoogleError("bad_request", 400, "contentBase64 is not valid base64");
  }
  if (bytes.length > DRIVE_UPLOAD_MAX_BYTES) {
    throw new GoogleError("bad_request", 400, `File too large for Drive upload (max ${DRIVE_UPLOAD_MAX_BYTES} bytes decoded)`);
  }
  const boundary = "jarvis-drive-upload-7f3a";
  const meta = JSON.stringify({ name, mimeType });
  const body =
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${meta}\r\n` +
    `--${boundary}\r\nContent-Type: ${mimeType}\r\nContent-Transfer-Encoding: base64\r\n\r\n${input.contentBase64}\r\n` +
    `--${boundary}--`;
  const uploaded = await googleFetch(deps, `${GOOGLE_DRIVE_UPLOAD_BASE}?uploadType=multipart`, {
    method: "POST",
    headers: { "Content-Type": `multipart/related; boundary=${boundary}` },
    body,
  });
  if (uploaded.status === 403) throw scopeInsufficientError("Drive upload");
  const parsed = uploaded.json as Record<string, unknown> | null;
  if (uploaded.status < 200 || uploaded.status >= 300 || typeof parsed?.id !== "string") {
    throw googleApiError(uploaded.status, uploaded.json);
  }
  return { id: parsed.id, name: typeof parsed.name === "string" ? parsed.name : name, mimeType: typeof parsed.mimeType === "string" ? parsed.mimeType : mimeType };
}

export interface CalendarEventSummary {
  id: string;
  summary: string;
  start: string;
  end: string;
  htmlLink?: string;
}

function toCalendarSummary(ev: Record<string, unknown>): CalendarEventSummary {
  const start = ev.start as { dateTime?: string; date?: string } | undefined;
  const end = ev.end as { dateTime?: string; date?: string } | undefined;
  return {
    id: typeof ev.id === "string" ? ev.id : "",
    summary: typeof ev.summary === "string" ? ev.summary : "(no title)",
    start: start?.dateTime ?? start?.date ?? "",
    end: end?.dateTime ?? end?.date ?? "",
    htmlLink: typeof ev.htmlLink === "string" ? ev.htmlLink : undefined,
  };
}

/** Upcoming events on the primary calendar, soonest first. */
export async function calendarListEvents(
  deps: GoogleApiDeps,
  input: { maxResults?: number } = {},
): Promise<CalendarEventSummary[]> {
  const max = Math.min(Math.max(input.maxResults ?? 10, 1), 50);
  const params = new URLSearchParams({
    maxResults: String(max),
    timeMin: new Date().toISOString(),
    singleEvents: "true",
    orderBy: "startTime",
  });
  const res = await googleFetch(deps, `${GOOGLE_CALENDAR_BASE}?${params.toString()}`);
  if (res.status === 403) throw scopeInsufficientError("Calendar read");
  if (res.status !== 200) throw googleApiError(res.status, res.json);
  const items = ((res.json as { items?: Array<Record<string, unknown>> } | null)?.items ?? []) as Array<Record<string, unknown>>;
  return items.map(toCalendarSummary);
}

/**
 * Create an event on the primary calendar. start/end are RFC 3339
 * date-times (e.g. 2026-11-24T10:00:00+05:30). Returns the created
 * event (id + link for the user to open).
 */
export async function calendarCreateEvent(
  deps: GoogleApiDeps,
  input: { summary: string; start: string; end: string; description?: string },
): Promise<CalendarEventSummary> {
  const summary = (input.summary ?? "").trim();
  if (!summary || summary.length > 500) {
    throw new GoogleError("bad_request", 400, "An event title (max 500 chars) is required");
  }
  const start = (input.start ?? "").trim();
  const end = (input.end ?? "").trim();
  if (!start || !end || Number.isNaN(Date.parse(start)) || Number.isNaN(Date.parse(end))) {
    throw new GoogleError("bad_request", 400, "start and end must be RFC 3339 date-times");
  }
  const created = await googleFetch(deps, GOOGLE_CALENDAR_BASE, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      summary,
      description: input.description ?? undefined,
      start: { dateTime: start },
      end: { dateTime: end },
    }),
  });
  if (created.status === 403) throw scopeInsufficientError("Calendar create");
  const parsed = created.json as Record<string, unknown> | null;
  if (created.status < 200 || created.status >= 300 || typeof parsed?.id !== "string") {
    throw googleApiError(created.status, created.json);
  }
  return toCalendarSummary(parsed);
}
