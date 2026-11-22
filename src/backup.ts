/**
 * backup.ts — Backblaze B2 backup (open-source completeness #49).
 *
 * S3-compatible B2 client built on fetch + SigV4 signing (WebCrypto) —
 * no SDK, no new dependency. Env-gated: without a B2 account the
 * functions honestly return b2_not_configured and no fetch happens.
 * Live proof needs a B2 account — a parent/browser step (no card).
 *
 * Env (Workers secrets / vars — NAMES only, never values):
 * - B2_ENDPOINT (var): S3 endpoint, e.g.
 *   https://s3.us-west-002.backblazeb2.com (region is derived from it
 *   when it matches s3.<region>.backblazeb2.com, else B2_REGION).
 * - B2_REGION (var): e.g. us-west-002 (only needed when the endpoint
 *   hostname does not carry the region).
 * - B2_BUCKET (var): bucket name.
 * - B2_KEY_ID (secret) + B2_APPLICATION_KEY (secret): B2 application
 *   key with write access to the bucket.
 * - KEY_ENC_SECRET (secret): the existing keyvault master key — the
 *   export is encrypted with the SAME AES-GCM envelope as tenant keys
 *   (src/keyvault.ts, iv 12B || ciphertext, base64). No new crypto.
 *
 * What is backed up: a JSON export of the tenant's D1 rows
 * (exportTenantData). A SQLite file dump is not feasible inside a
 * Worker (no file writer / sqlite3); JSON is the implemented form —
 * every tenant-scoped table, tenant-isolated. Excluded on purpose:
 * licences (user_id-opaque, not tenant-mapped — same as wipeTenant),
 * skill_reviews / skill_signatures (admin-level, keyed by skill_id),
 * sessions / nonces / pending_steps (ephemeral device runtime state),
 * admin_settings (instance-level, not tenant data).
 *
 * Restore-test is a read-only dry-run: download → decrypt → SHA-256
 * integrity check against the stored hash → JSON parse → tenant +
 * table counts verified. It writes NOTHING to D1.
 */
import type { D1Like } from "./db";
import { newBillingId } from "./billing";
import { decryptTenantKey, encryptTenantKey, importMasterKey } from "./keyvault";
import { sha256Hex } from "./docs";

export interface B2Env {
  B2_ENDPOINT?: string;
  B2_REGION?: string;
  B2_BUCKET?: string;
  B2_KEY_ID?: string;
  B2_APPLICATION_KEY?: string;
  KEY_ENC_SECRET?: string;
}

export function b2Region(env: B2Env): string | null {
  if (env.B2_REGION) return env.B2_REGION;
  // R-6 live proof (2026-11-22): B2_S3_ENDPOINT is stored as a BARE
  // HOSTNAME (`s3.us-west-002.backblazeb2.com`, no scheme) — the old
  // regex required `^https?://`, so the region derived to null and
  // isB2Configured() was false → 503 b2_not_configured with all four
  // secrets set. Prepend https:// when no scheme is present, then
  // match as before. Full URLs, bare hosts, and trailing paths all work.
  const endpoint = (env.B2_ENDPOINT ?? "").trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(endpoint) ? endpoint : `https://${endpoint}`;
  const m = withScheme.match(/^https?:\/\/s3\.([^.]+)\.backblazeb2\.com/i);
  return m ? m[1] : null;
}

export function isB2Configured(env: B2Env): boolean {
  return Boolean(env.B2_ENDPOINT && env.B2_BUCKET && env.B2_KEY_ID && env.B2_APPLICATION_KEY && b2Region(env));
}

export function b2Status(env: B2Env): "configured" | "not_configured" {
  return isB2Configured(env) ? "configured" : "not_configured";
}

// --- SigV4 (S3) — pure helpers, deterministic given the inputs ---

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hmacSha256(key: Uint8Array, data: string): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(data));
  return new Uint8Array(sig);
}

export function amzDates(nowMs = Date.now()): { amzDate: string; dateStamp: string } {
  const d = new Date(nowMs);
  const p = (n: number) => String(n).padStart(2, "0");
  const dateStamp = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}`;
  const amzDate = `${dateStamp}T${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return { amzDate, dateStamp };
}

export interface SignS3Opts {
  method: "GET" | "PUT";
  endpoint: string;
  bucket: string;
  objectKey: string;
  region: string;
  keyId: string;
  secret: string;
  body: Uint8Array;
  nowMs?: number;
}

/**
 * Build the SigV4 Authorization + x-amz-* headers for one S3 request.
 * Deterministic for fixed inputs (vitest cross-checks the signature
 * against Node's node:crypto HMAC independently).
 */
export async function signS3Request(opts: SignS3Opts): Promise<Record<string, string>> {
  const { amzDate, dateStamp } = amzDates(opts.nowMs);
  const host = new URL(opts.endpoint).host;
  const uri = `/${opts.bucket}/${opts.objectKey.split("/").map(encodeURIComponent).join("/")}`;
  // subtle.digest on the Uint8Array view itself (offset-safe).
  const payloadDigest = await crypto.subtle.digest("SHA-256", opts.body as BufferSource);
  const payloadHash = hex(new Uint8Array(payloadDigest));
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  const canonicalRequest = [opts.method, uri, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${dateStamp}/${opts.region}/s3/aws4_request`;
  const canonicalHash = await sha256Hex(canonicalRequest);
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, canonicalHash].join("\n");
  const kDate = await hmacSha256(new TextEncoder().encode(`AWS4${opts.secret}`), dateStamp);
  const kRegion = await hmacSha256(kDate, opts.region);
  const kService = await hmacSha256(kRegion, "s3");
  const kSigning = await hmacSha256(kService, "aws4_request");
  const signature = hex(await hmacSha256(kSigning, stringToSign));
  return {
    Authorization: `AWS4-HMAC-SHA256 Credential=${opts.keyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
  };
}

async function b2Fetch(
  env: B2Env,
  method: "GET" | "PUT",
  objectKey: string,
  body?: Uint8Array,
): Promise<{ ok: boolean; status: number; body: Uint8Array; detail: string }> {
  const region = b2Region(env)!;
  const headers = await signS3Request({
    method,
    endpoint: env.B2_ENDPOINT!,
    bucket: env.B2_BUCKET!,
    objectKey,
    region,
    keyId: env.B2_KEY_ID!,
    secret: env.B2_APPLICATION_KEY!,
    body: body ?? new Uint8Array(0),
  });
  const url = `${env.B2_ENDPOINT!.replace(/\/+$/, "")}/${env.B2_BUCKET}/${objectKey.split("/").map(encodeURIComponent).join("/")}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: { ...headers, "Content-Type": "application/octet-stream" },
      body: body,
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    return { ok: false, status: 0, body: new Uint8Array(0), detail: "fetch_failed" };
  }
  const buf = new Uint8Array(await res.arrayBuffer());
  let detail = "";
  if (!res.ok) {
    try {
      detail = new TextDecoder().decode(buf).slice(0, 200);
    } catch {
      detail = "";
    }
  }
  return { ok: res.ok, status: res.status, body: buf, detail };
}

// --- D1 export (tenant-scoped, JSON) ---

/** Tenant-scoped tables: [table, where-column]. sync_state is per-device. */
const EXPORT_TABLES: Array<{ table: string; column: string }> = [
  { table: "tenants", column: "id" },
  { table: "devices", column: "tenant_id" },
  { table: "scheduled_jobs", column: "tenant_id" },
  { table: "subscriptions", column: "tenant_id" },
  { table: "payments", column: "tenant_id" },
  { table: "refunds", column: "tenant_id" },
  { table: "ledger_events", column: "tenant_id" },
  { table: "llm_usage", column: "tenant_id" },
  { table: "usage_counters", column: "tenant_id" },
  { table: "traces", column: "tenant_id" },
  { table: "memories", column: "tenant_id" },
  { table: "doc_jobs", column: "tenant_id" },
  { table: "certificates", column: "tenant_id" },
  { table: "browser_tasks", column: "tenant_id" },
  { table: "global_skills", column: "submitted_by" },
  { table: "pairing_tokens", column: "tenant_id" },
  { table: "email_sends", column: "tenant_id" },
  { table: "backups", column: "tenant_id" },
];

export interface TenantExport {
  version: 1;
  tenant_id: string;
  exported_at: string;
  tables: Record<string, Array<Record<string, unknown>>>;
}

export async function exportTenantData(db: D1Like, tenantId: string, nowMs = Date.now()): Promise<TenantExport> {
  const tables: Record<string, Array<Record<string, unknown>>> = {};
  for (const { table, column } of EXPORT_TABLES) {
    const res = await db
      .prepare(`SELECT * FROM ${table} WHERE ${column} = ?`)
      .bind(tenantId)
      .all<Record<string, unknown>>();
    tables[table] = res.results ?? [];
  }
  // sync_state is per-device: one query per device of this tenant.
  const devices = tables.devices ?? [];
  const syncRows: Array<Record<string, unknown>> = [];
  for (const d of devices) {
    const res = await db
      .prepare("SELECT * FROM sync_state WHERE device_id = ?")
      .bind(d.device_id)
      .all<Record<string, unknown>>();
    syncRows.push(...(res.results ?? []));
  }
  tables.sync_state = syncRows;
  return { version: 1, tenant_id: tenantId, exported_at: new Date(nowMs).toISOString(), tables };
}

// --- Backup record (backups table, migration 0009) ---

export interface BackupRow {
  id: string;
  tenant_id: string;
  kind: string;
  b2_key: string;
  size_bytes: number;
  sha256: string;
  status: string;
  created_at: number;
}

async function recordBackup(
  db: D1Like,
  row: Omit<BackupRow, "created_at"> & { created_at?: number },
): Promise<void> {
  await db
    .prepare("INSERT INTO backups (id, tenant_id, kind, b2_key, size_bytes, sha256, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(row.id, row.tenant_id, row.kind, row.b2_key, row.size_bytes, row.sha256, row.status, row.created_at ?? Date.now())
    .run();
}

export async function listBackups(db: D1Like, tenantId?: string, limit = 50): Promise<BackupRow[]> {
  const n = Math.min(Math.max(Math.floor(limit) || 50, 1), 200);
  const rows = tenantId
    ? await db
        .prepare(`SELECT id, tenant_id, kind, b2_key, size_bytes, sha256, status, created_at FROM backups WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ${n}`)
        .bind(tenantId)
        .all<BackupRow>()
    : await db
        .prepare(`SELECT id, tenant_id, kind, b2_key, size_bytes, sha256, status, created_at FROM backups ORDER BY created_at DESC LIMIT ${n}`)
        .bind()
        .all<BackupRow>();
  return rows.results ?? [];
}

// --- Create backup: export → encrypt (keyvault AES-GCM) → PUT to B2 ---

export type BackupResult =
  | { ok: true; backup_id: string; b2_key: string; size_bytes: number; sha256: string }
  | {
      ok: false;
      error: "b2_not_configured" | "key_enc_not_configured" | "b2_error" | "fetch_failed";
      status?: number;
      detail?: string;
    };

export async function createTenantBackup(
  env: B2Env,
  db: D1Like,
  tenantId: string,
  nowMs = Date.now(),
): Promise<BackupResult> {
  if (!isB2Configured(env)) return { ok: false, error: "b2_not_configured" };
  if (!env.KEY_ENC_SECRET) return { ok: false, error: "key_enc_not_configured" };
  const backupId = newBillingId("bak");
  const b2Key = `backups/${tenantId}/${backupId}.json.enc`;
  const exported = await exportTenantData(db, tenantId, nowMs);
  const plaintext = JSON.stringify(exported);
  const sha = await sha256Hex(plaintext);
  let envelope: string;
  try {
    const master = await importMasterKey(env.KEY_ENC_SECRET);
    envelope = await encryptTenantKey(master, plaintext);
  } catch {
    return { ok: false, error: "key_enc_not_configured", detail: "master key import failed" };
  }
  const body = new TextEncoder().encode(envelope);
  const put = await b2Fetch(env, "PUT", b2Key, body);
  if (!put.ok) {
    try {
      await recordBackup(db, { id: backupId, tenant_id: tenantId, kind: "tenant_export", b2_key: b2Key, size_bytes: body.length, sha256: sha, status: "failed", created_at: nowMs });
    } catch {
      // Record failure must not mask the B2 result.
    }
    return { ok: false, error: put.detail === "fetch_failed" ? "fetch_failed" : "b2_error", status: put.status || undefined, detail: put.detail };
  }
  await recordBackup(db, { id: backupId, tenant_id: tenantId, kind: "tenant_export", b2_key: b2Key, size_bytes: body.length, sha256: sha, status: "ok", created_at: nowMs });
  return { ok: true, backup_id: backupId, b2_key: b2Key, size_bytes: body.length, sha256: sha };
}

// --- Restore-test: download → decrypt → verify (read-only dry-run) ---

export type RestoreTestResult =
  | {
      ok: true;
      backup_id: string;
      tenant_id: string;
      size_bytes: number;
      sha256: string;
      tables: Record<string, number>;
    }
  | {
      ok: false;
      error:
        | "b2_not_configured"
        | "key_enc_not_configured"
        | "backup_not_found"
        | "b2_error"
        | "fetch_failed"
        | "decrypt_failed"
        | "integrity_failed"
        | "parse_failed"
        | "tenant_mismatch";
      status?: number;
      detail?: string;
    };

export async function restoreTestBackup(env: B2Env, db: D1Like, backupId: string): Promise<RestoreTestResult> {
  if (!isB2Configured(env)) return { ok: false, error: "b2_not_configured" };
  if (!env.KEY_ENC_SECRET) return { ok: false, error: "key_enc_not_configured" };
  const row = await db
    .prepare("SELECT id, tenant_id, kind, b2_key, size_bytes, sha256, status, created_at FROM backups WHERE id = ?")
    .bind(backupId)
    .first<BackupRow>();
  if (!row) return { ok: false, error: "backup_not_found" };
  const get = await b2Fetch(env, "GET", row.b2_key);
  if (!get.ok) {
    return { ok: false, error: get.detail === "fetch_failed" ? "fetch_failed" : "b2_error", status: get.status || undefined, detail: get.detail };
  }
  let plaintext: string;
  try {
    const master = await importMasterKey(env.KEY_ENC_SECRET);
    plaintext = await decryptTenantKey(master, new TextDecoder().decode(get.body));
  } catch {
    return { ok: false, error: "decrypt_failed" };
  }
  const sha = await sha256Hex(plaintext);
  if (sha !== row.sha256) return { ok: false, error: "integrity_failed" };
  let parsed: TenantExport;
  try {
    parsed = JSON.parse(plaintext) as TenantExport;
  } catch {
    return { ok: false, error: "parse_failed" };
  }
  if (parsed.version !== 1 || parsed.tenant_id !== row.tenant_id) return { ok: false, error: "tenant_mismatch" };
  const tables: Record<string, number> = {};
  for (const [name, rows] of Object.entries(parsed.tables ?? {})) tables[name] = rows.length;
  // Dry-run only: NOTHING is written to D1 here.
  return { ok: true, backup_id: row.id, tenant_id: row.tenant_id, size_bytes: row.size_bytes, sha256: row.sha256, tables };
}
