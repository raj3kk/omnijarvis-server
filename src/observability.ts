/**
 * observability.ts — Langfuse + Sentry wiring (env-gated, fetch-only).
 *
 * 2a-4 / completeness #55 + #56: the 2a-2 no-op stubs are now real
 * fetch-based senders. NO SDK dependency (bundle stays small).
 *
 * - Langfuse: OTel POST {host}/api/public/otel/v1/traces, Basic auth
 *   base64(public_key:secret_key), header x-langfuse-ingestion-version: 4
 *   (real-time; without it, directly ingested data can lag ~10 min).
 *   One root span per trace (W3C 32-hex trace id, 16-hex span id).
 *   The v3 batch API (POST /api/public/ingestion) was REMOVED by
 *   Langfuse on 2026-11-16 (LANGFUSE_V3_API_REMOVED) — G-17 fix rewrote
 *   the sender to OTel. Host default https://cloud.langfuse.com; env
 *   LANGFUSE_HOST (or LANGFUSE_BASE_URL, the signups.env name) overrides it.
 * - Sentry: POST <dsn-host>/api/<project_id>/envelope/ with an
 *   X-Sentry-Auth header; envelope = header line + item header line
 *   + event JSON (newline-delimited, no trailing newline required).
 *
 * FAILURE POSTURE (frozen): either sender NEVER throws and NEVER blocks
 * the request path — on any failure it logs one short line (name +
 * status only, never payload content — memory/PII rule) and resolves.
 * Env unset = silent no-op (same as before wiring).
 * Both senders return the vendor-accepted id (trace id / event id) on
 * success, null when not configured or when the vendor rejected the
 * send — the id is what the admin probe route reports (G-17).
 *
 * `fetchFn` is injectable for vitest; production uses global fetch.
 */

export interface ObservabilityEnv {
  LANGFUSE_PUBLIC_KEY?: string;
  LANGFUSE_SECRET_KEY?: string;
  LANGFUSE_HOST?: string;
  LANGFUSE_BASE_URL?: string;
  SENTRY_DSN?: string;
}

export interface ObservabilityOpts {
  fetchFn?: typeof fetch;
}

export const DEFAULT_LANGFUSE_HOST = "https://cloud.langfuse.com";

export function langfuseHost(env: ObservabilityEnv): string {
  const raw = (env.LANGFUSE_HOST ?? env.LANGFUSE_BASE_URL ?? "").trim();
  return raw ? raw.replace(/\/+$/, "") : DEFAULT_LANGFUSE_HOST;
}

export function isLangfuseConfigured(env: ObservabilityEnv): boolean {
  return Boolean(env.LANGFUSE_PUBLIC_KEY && env.LANGFUSE_SECRET_KEY);
}

export function isSentryConfigured(env: ObservabilityEnv): boolean {
  return Boolean(env.SENTRY_DSN && parseSentryDsn(env.SENTRY_DSN));
}

export function isObservabilityOn(env: ObservabilityEnv): boolean {
  return Boolean(env.LANGFUSE_PUBLIC_KEY || env.SENTRY_DSN);
}

function newEventId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** W3C trace id: 32 lowercase hex chars (same shape as a Sentry event id). */
function newTraceId(): string {
  return newEventId();
}

/** W3C span id: 16 lowercase hex chars. */
function newSpanId(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

type OtelValue =
  | { stringValue: string }
  | { boolValue: boolean }
  | { intValue: string }
  | { doubleValue: number };

/** OTLP AnyValue — scalars only; objects/arrays are never sent (PII rule). */
function otelValue(v: unknown): OtelValue {
  if (typeof v === "boolean") return { boolValue: v };
  if (typeof v === "number") {
    return Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v };
  }
  if (typeof v === "string") return { stringValue: v };
  const asJson = JSON.stringify(v);
  return { stringValue: typeof asJson === "string" ? asJson : "null" };
}

/**
 * Trace one named event to Langfuse as a single root OTel span.
 * `data` is metadata only — callers MUST NOT pass prompt/response
 * text or memory content (PII rule, same as memory.ts). Non-scalar
 * values are dropped, never serialised. Returns the trace id the
 * vendor accepted, or null when not configured / rejected.
 */
export async function trace(
  env: ObservabilityEnv,
  name: string,
  data: Record<string, unknown>,
  opts: ObservabilityOpts = {},
): Promise<string | null> {
  if (!isLangfuseConfigured(env)) return null;
  const fetchFn = opts.fetchFn ?? fetch;
  const traceId = newTraceId();
  const spanId = newSpanId();
  const startMs = Date.now();
  const startNs = `${BigInt(startMs) * 1000000n}`;
  const endNs = `${BigInt(startMs) * 1000000n + 1000000n}`; // +1 ms
  const attributes: Array<{ key: string; value: OtelValue }> = [];
  for (const [k, v] of Object.entries(data)) {
    if (typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean") continue;
    attributes.push({ key: k, value: otelValue(v) });
    // Trace-level metadata (Langfuse: langfuse.trace.metadata.* becomes
    // a filterable top-level key on the trace).
    attributes.push({ key: `langfuse.trace.metadata.${k}`, value: otelValue(v) });
  }
  const body = {
    resourceSpans: [
      {
        resource: { attributes: [{ key: "service.name", value: { stringValue: "omnijarvis-hub" } }] },
        scopeSpans: [
          {
            scope: { name: "omnijarvis-hub" },
            spans: [
              {
                traceId,
                spanId,
                name,
                startTimeUnixNano: startNs,
                endTimeUnixNano: endNs,
                attributes,
              },
            ],
          },
        ],
      },
    ],
  };
  try {
    const res = await fetchFn(`${langfuseHost(env)}/api/public/otel/v1/traces`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${btoa(`${env.LANGFUSE_PUBLIC_KEY}:${env.LANGFUSE_SECRET_KEY}`)}`,
        "Content-Type": "application/json",
        "x-langfuse-ingestion-version": "4",
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      console.warn(`[observability] langfuse trace failed: ${name} status=${res.status}`);
      return null;
    }
    return traceId;
  } catch {
    console.warn(`[observability] langfuse trace failed: ${name} network_error`);
    return null;
  }
}

// --- Sentry ---

export interface ParsedSentryDsn {
  publicKey: string;
  host: string;
  projectId: string;
}

/**
 * Parse a Sentry DSN (`https://<public_key>@<host>/<project_id>`).
 * Returns null for anything malformed (never throws).
 */
export function parseSentryDsn(dsn: string): ParsedSentryDsn | null {
  try {
    const url = new URL(dsn);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    const publicKey = url.username;
    const projectId = url.pathname.replace(/^\/+|\/+$/g, "");
    if (!publicKey || !projectId || !url.hostname) return null;
    if (projectId.includes("/")) return null;
    return { publicKey, host: url.host, projectId };
  } catch {
    return null;
  }
}

function sentryEnvelopeEndpoint(dsn: ParsedSentryDsn, protocol: string): string {
  return `${protocol}://${dsn.host}/api/${dsn.projectId}/envelope/`;
}

/** Error message extraction — type + value only, no stack/secret leak. */
export function describeError(error: unknown): { type: string; value: string } {
  if (error instanceof Error) return { type: error.name || "Error", value: error.message };
  if (typeof error === "string") return { type: "Error", value: error };
  return { type: "Error", value: "unknown error" };
}

/**
 * Send one error event to Sentry as an envelope. `context` is tags
 * only (tenant_id / route / kind — never message content or secrets).
 * Returns the vendor-accepted event id on success (the id from the
 * ingest response, falling back to the generated one on a 2xx with a
 * non-JSON body), or null when not configured / rejected.
 */
export async function captureError(
  env: ObservabilityEnv,
  error: unknown,
  context: Record<string, unknown> = {},
  opts: ObservabilityOpts = {},
): Promise<string | null> {
  const parsed = env.SENTRY_DSN ? parseSentryDsn(env.SENTRY_DSN) : null;
  if (!parsed) return null;
  const fetchFn = opts.fetchFn ?? fetch;
  const protocol = env.SENTRY_DSN!.startsWith("http://") ? "http" : "https";
  const eventId = newEventId();
  const { type, value } = describeError(error);
  const tags: Record<string, string> = {};
  for (const [k, v] of Object.entries(context)) {
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") tags[k] = String(v);
  }
  const header = { event_id: eventId, sent_at: new Date().toISOString() };
  const itemHeader = { type: "event", content_type: "application/json" };
  const event = {
    event_id: eventId,
    timestamp: Date.now() / 1000,
    level: "error",
    platform: "javascript",
    sdk: { name: "omnijarvis-hub", version: "6" },
    exception: { values: [{ type, value }] },
    tags,
  };
  const envelope = `${JSON.stringify(header)}\n${JSON.stringify(itemHeader)}\n${JSON.stringify(event)}`;
  try {
    const res = await fetchFn(sentryEnvelopeEndpoint(parsed, protocol), {
      method: "POST",
      headers: {
        "Content-Type": "application/x-sentry-envelope",
        "X-Sentry-Auth":
          `Sentry sentry_version=7, sentry_client=omnijarvis-hub/6, sentry_key=${parsed.publicKey}`,
      },
      body: envelope,
    });
    if (!res.ok) {
      console.warn(`[observability] sentry capture failed: status=${res.status}`);
      return null;
    }
    // The ingest response carries the accepted event id; fall back to
    // the generated one on a 2xx with a non-JSON body.
    try {
      const accepted = (await res.json()) as { id?: unknown };
      if (typeof accepted?.id === "string" && accepted.id) return accepted.id;
    } catch {
      // Non-JSON 2xx — the generated id is what Sentry accepted.
    }
    return eventId;
  } catch {
    console.warn("[observability] sentry capture failed: network_error");
    return null;
  }
}
