/**
 * docs.ts — Doc pipeline helpers (Phase 3, stage 3b).
 *
 * Worker routes live in hub.ts; the pure/testable logic lives here:
 *  - PII redaction (consent-gated; Aadhaar/PAN patterns in free text)
 *  - Render worker forwarding (30s timeout + 1 retry after 5s, then an
 *    honest error — cold-start hint `render_warming_up`, never silent)
 *  - doc_jobs / certificates D1 helpers (D1 migration 0004)
 *  - Paired-device signed auth for docs routes (sync-style Ed25519;
 *    canonical string = device_id + nonce + ts + payload, crypto.ts)
 *  - Structured extraction via the 3a router (kind `doc_extraction` —
 *    the route table is NOT redefined here; routeLlm() is called)
 *
 * PII RULE (frozen): PII fields are stored in doc_jobs.result_json
 * ONLY when tenants.pii_consent = 1; otherwise they are replaced with
 * `[REDACTED]`. PII never appears in logs/traces. No real Aadhaar/PAN
 * is ever generated or stored by tests — fixtures use invented values.
 */
import type { D1Like } from "./db";
import { getDevice, getTenant } from "./db";
import { isTimestampFresh, verifySignature } from "./crypto";
import { loadRouterConfig, routeLlm, type RouterDeps } from "./router";

export const DOCS_RATE_LIMIT = "docs" as const;
export const RENDER_TIMEOUT_MS = 30_000;
export const RENDER_RETRY_DELAY_MS = 5_000;
export const MAX_INGEST_BYTES = 5 * 1024 * 1024;
export const MAX_EXTRACT_PAGES = 20;
export const REDACTED = "[REDACTED]";

/** Field keys treated as PII (DPDP consent-gated). Matching is by
 *  whole underscore-token: `pan` matches `pan_number` but NOT
 *  `company` (substring trap). */
const PII_TOKENS = new Set(["aadhaar", "pan", "account", "ifsc", "passport", "voter"]);
const PII_KEYS = new Set(["aadhaar_number", "pan_number", "pan_card", "account_number"]);

export function isPiiField(key: string): boolean {
  const lower = key.toLowerCase();
  if (PII_KEYS.has(lower)) return true;
  if (lower.includes("aadhaar")) return true;
  const tokens = lower.split(/[^a-z0-9]+/).filter(Boolean);
  return tokens.some((t) => PII_TOKENS.has(t));
}

/** Redact PII values in a fields object when consent is off. */
export function redactFields(
  fields: Record<string, unknown>,
  piiConsent: boolean,
): Record<string, unknown> {
  if (piiConsent) return fields;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    out[k] = isPiiField(k) ? REDACTED : v;
  }
  return out;
}

/** Redact Aadhaar/PAN-shaped values inside free text (OCR text,
 *  result_json) when consent is off. Patterns only — never a lookup. */
export function redactPiiText(text: string, piiConsent: boolean): string {
  if (piiConsent) return text;
  return text
    .replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, REDACTED)
    .replace(/\b[A-Z]{5}[0-9]{4}[A-Z]\b/g, REDACTED);
}

/** Canonical JSON for hashing: sorted keys, compact separators. */
export function canonicalPayload(payload: Record<string, unknown>): string {
  const sorted = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sorted);
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v as Record<string, unknown>).sort()) {
        out[k] = sorted((v as Record<string, unknown>)[k]);
      }
      return out;
    }
    return v;
  };
  return JSON.stringify(sorted(payload));
}

export async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** SHA-256 hex of raw bytes (ingest file hash for signed auth). */
export async function sha256HexBytes(bytes: ArrayBuffer): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface DocJobRow {
  id: number;
  tenant_id: string;
  device_id: string;
  kind: string;
  status: string;
  source_name: string | null;
  result_json: string | null;
  confidence: number | null;
  created_at: number;
}

export async function createDocJob(
  db: D1Like,
  job: { tenant_id: string; device_id: string; kind: string; source_name?: string | null },
  nowMs = Date.now(),
): Promise<number> {
  await db
    .prepare(
      "INSERT INTO doc_jobs (tenant_id, device_id, kind, status, source_name, result_json, confidence, created_at) " +
        "VALUES (?, ?, ?, ?, ?, NULL, NULL, ?)",
    )
    .bind(job.tenant_id, job.device_id, job.kind, "ingested", job.source_name ?? null, nowMs)
    .run();
  const row = await db
    .prepare("SELECT id FROM doc_jobs WHERE tenant_id = ? AND device_id = ? AND created_at = ?")
    .bind(job.tenant_id, job.device_id, nowMs)
    .first<{ id: number }>();
  if (!row) throw new Error("doc job insert failed");
  return row.id;
}

export async function getDocJob(db: D1Like, id: number): Promise<DocJobRow | null> {
  return await db
    .prepare(
      "SELECT id, tenant_id, device_id, kind, status, source_name, result_json, confidence, created_at " +
        "FROM doc_jobs WHERE id = ?",
    )
    .bind(id)
    .first<DocJobRow>();
}

export async function updateDocJob(
  db: D1Like,
  id: number,
  patch: { status?: string; result_json?: string | null; confidence?: number | null },
): Promise<void> {
  const sets: string[] = [];
  const args: unknown[] = [];
  if (patch.status !== undefined) {
    sets.push("status = ?");
    args.push(patch.status);
  }
  if (patch.result_json !== undefined) {
    sets.push("result_json = ?");
    args.push(patch.result_json);
  }
  if (patch.confidence !== undefined) {
    sets.push("confidence = ?");
    args.push(patch.confidence);
  }
  if (sets.length === 0) return;
  args.push(id);
  await db.prepare(`UPDATE doc_jobs SET ${sets.join(", ")} WHERE id = ?`).bind(...args).run();
}

export async function insertCertificate(
  db: D1Like,
  cert: { tenant_id: string; doc_job_id: number; payload_hash: string; pdf_url: string },
  nowMs = Date.now(),
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO certificates (tenant_id, doc_job_id, payload_hash, pdf_url, created_at) " +
        "VALUES (?, ?, ?, ?, ?)",
    )
    .bind(cert.tenant_id, cert.doc_job_id, cert.payload_hash, cert.pdf_url, nowMs)
    .run();
}

export async function getCertificateByHash(
  db: D1Like,
  hash: string,
): Promise<{ payload_hash: string; created_at: number } | null> {
  return await db
    .prepare("SELECT payload_hash, created_at FROM certificates WHERE payload_hash = ?")
    .bind(hash)
    .first<{ payload_hash: string; created_at: number }>();
}

// --- Render forwarding (cold-start aware, honest errors) ---

export interface RenderEnv {
  RENDER_WORKER_URL?: string;
}

export interface RenderResult {
  ok: boolean;
  status: number;
  json: Record<string, unknown> | null;
  error?: string;
  warmingUp?: boolean;
}

/**
 * Forward one call to the Render worker. 30s timeout (matches the OCR
 * cap); on timeout/network error, ONE retry after 5s (Render free tier
 * cold start is ~30-60s after 15-min sleep) — then an honest error with
 * `render_warming_up` hint. RENDER_WORKER_URL unset = `render_not_configured`
 * (never a silent fail). `fetchFn` is injectable for vitest.
 */
export async function forwardToRender(
  env: RenderEnv,
  path: string,
  init: RequestInit,
  opts: { fetchFn?: typeof fetch; sleepFn?: (ms: number) => Promise<void> } = {},
): Promise<RenderResult> {
  const base = (env.RENDER_WORKER_URL ?? "").replace(/\/+$/, "");
  if (!base) return { ok: false, status: 503, json: null, error: "render_not_configured" };
  const doFetch = opts.fetchFn ?? fetch;
  const sleep = opts.sleepFn ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  let lastError = "render_unreachable";
  for (let attempt = 0; attempt < 2; attempt++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), RENDER_TIMEOUT_MS);
    try {
      const res = await doFetch(`${base}${path}`, { ...init, signal: ctrl.signal });
      const text = await res.text();
      let parsed: Record<string, unknown> | null = null;
      try {
        parsed = JSON.parse(text) as Record<string, unknown>;
      } catch {
        parsed = null;
      }
      return { ok: res.ok, status: res.status, json: parsed };
    } catch (e) {
      lastError = (e as Error)?.name === "AbortError" ? "render_timeout" : "render_unreachable";
      if (attempt === 0) await sleep(RENDER_RETRY_DELAY_MS);
    } finally {
      clearTimeout(timer);
    }
  }
  return { ok: false, status: 502, json: null, error: lastError, warmingUp: true };
}

// --- Docs signed auth (paired device + Ed25519, or internal secret) ---

export interface DocsAuth {
  ok: boolean;
  tenant_id?: string;
  device_id?: string;
  error?: string;
}

/**
 * Authorize a docs call. Agent callers pass x-internal-secret.
 * Device callers pass x-device-id + x-nonce + x-ts + x-signature, where
 * the signature covers canonicalString(device_id, nonce, ts, payloadRaw)
 * (crypto.ts — same canonical form as /api/sync). payloadRaw is the
 * caller-supplied canonical payload: sorted-JSON of the request body
 * (JSON routes) or the sha256 hex of the uploaded file (ingest).
 * Unpaired/disabled device or bad/old signature = fail-closed.
 */
export async function authorizeDocsRequest(
  db: D1Like,
  opts: {
    internalSecret?: string;
    internalHeader?: string | null;
    deviceId: string;
    nonce?: string | null;
    ts?: number | null;
    sig?: string | null;
    payloadRaw: string;
    nowMs?: number;
  },
): Promise<DocsAuth> {
  if (opts.internalSecret && opts.internalHeader === opts.internalSecret) {
    return { ok: true, device_id: opts.deviceId || undefined };
  }
  const deviceId = opts.deviceId;
  if (!deviceId || !opts.nonce || !opts.ts || !opts.sig) {
    return { ok: false, error: "unauthorized" };
  }
  const device = await getDevice(db, deviceId);
  if (!device || device.enabled === 0) {
    return { ok: false, error: "device_not_paired" };
  }
  const now = opts.nowMs ?? Date.now();
  if (!isTimestampFresh(opts.ts, now)) {
    return { ok: false, error: "stale_timestamp" };
  }
  const valid = await verifySignature(
    device.public_key,
    opts.sig,
    deviceId,
    opts.nonce,
    opts.ts,
    opts.payloadRaw,
  );
  if (!valid) return { ok: false, error: "bad_signature" };
  return { ok: true, tenant_id: device.tenant_id, device_id: deviceId };
}

/** Sorted-keys JSON (stable payload for docs signatures). */
export function sortedJson(value: unknown): string {
  return canonicalPayload(value as Record<string, unknown>);
}

// --- Structured extraction via the 3a router (doc_extraction kind) ---

export interface ExtractInput {
  db: D1Like;
  masterKeyB64?: string;
  founderKey?: string;
  config?: RouterDeps["config"];
  fetchFn?: typeof fetch;
  tenant_id: string;
  device_id?: string;
  turn_id: string;
  text: string;
  schema: Record<string, unknown>;
}

/**
 * Run OCR text through the router's doc_extraction kind (3.5 -> 3.1
 * BYOK, P0 3a.1 chains). The router enforces the Free-plan docs block
 * itself (`plan_docs_not_allowed`); hub routes double-check before calling.
 * Returns parsed fields + missing[] + confidence (0-1).
 */
export async function extractStructured(input: ExtractInput): Promise<{
  ok: boolean;
  fields?: Record<string, unknown>;
  missing?: string[];
  confidence?: number;
  error?: string;
  error_code?: string;
}> {
  const schema = input.schema;
  const fieldNames = Object.keys((schema.properties as Record<string, unknown> | undefined) ?? {});
  const result = await routeLlm(
    {
      db: input.db,
      fetchFn: input.fetchFn,
      sleepFn: async () => {},
      masterKeyB64: input.masterKeyB64,
      founderKey: input.founderKey,
      config: input.config ?? loadRouterConfig({}),
    },
    {
      tenant_id: input.tenant_id,
      device_id: input.device_id,
      turn_id: input.turn_id,
      kind: "doc_extraction",
      messages: [
        {
          role: "user",
          text:
            "Extract the fields from this document text as JSON. " +
            "Reply with ONLY a JSON object with keys: fields (object), " +
            "confidence (0-1). Missing fields must be absent from fields.\n\n" +
            `Schema fields: ${fieldNames.join(", ")}\n\nDocument text:\n${input.text}`,
        },
      ],
      response_schema: {
        type: "object",
        properties: {
          fields: { type: "object" },
          confidence: { type: "number" },
        },
        required: ["fields"],
      },
    },
  );
  if (!result.ok || !result.text) {
    return { ok: false, error: result.error ?? "extraction_failed", error_code: result.error_code };
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(result.text) as Record<string, unknown>;
  } catch {
    return { ok: false, error: "bad_router_json", error_code: "bad_router_json" };
  }
  const fields = (parsed.fields as Record<string, unknown> | undefined) ?? {};
  const missing = fieldNames.filter((f) => fields[f] === undefined || fields[f] === null || fields[f] === "");
  const confidence =
    typeof parsed.confidence === "number"
      ? parsed.confidence
      : fieldNames.length > 0
        ? (fieldNames.length - missing.length) / fieldNames.length
        : 0;
  return { ok: true, fields, missing, confidence };
}

/** Tenant plan check shared by ingest/extract: Free tier = no docs. */
export async function docsAllowedForTenant(
  db: D1Like,
  tenantId: string,
): Promise<{ allowed: boolean; tenant?: Awaited<ReturnType<typeof getTenant>>; error?: string }> {
  const tenant = await getTenant(db, tenantId);
  if (!tenant) return { allowed: false, error: "tenant_not_found" };
  if (tenant.plan_tier === "free") return { allowed: false, tenant, error: "plan_docs_not_allowed" };
  return { allowed: true, tenant };
}
