/**
 * observability.ts — Langfuse + Sentry wiring (env-gated, fetch-only).
 *
 * 2a-4 / completeness #55 + #56: the 2a-2 no-op stubs are now real
 * fetch-based senders. NO SDK dependency (bundle stays small).
 *
 * - Langfuse: POST {host}/api/public/ingestion, Basic auth
 *   base64(public_key:secret_key), body { batch: [trace-create] }.
 *   Host default https://cloud.langfuse.com; env LANGFUSE_HOST (or
 *   LANGFUSE_BASE_URL, the signups.env name) overrides it.
 * - Sentry: POST <dsn-host>/api/<project_id>/envelope/ with an
 *   X-Sentry-Auth header; envelope = header line + item header line
 *   + event JSON (newline-delimited, no trailing newline required).
 *
 * FAILURE POSTURE (frozen): either sender NEVER throws and NEVER blocks
 * the request path — on any failure it logs one short line (name +
 * status only, never payload content — memory/PII rule) and resolves.
 * Env unset = silent no-op (same as before wiring).
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

function newId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }
}

function newEventId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Trace one named event to Langfuse as a trace-create event.
 * `data` is metadata only — callers MUST NOT pass prompt/response
 * text or memory content (PII rule, same as memory.ts).
 */
export async function trace(
  env: ObservabilityEnv,
  name: string,
  data: Record<string, unknown>,
  opts: ObservabilityOpts = {},
): Promise<void> {
  if (!isLangfuseConfigured(env)) return;
  const fetchFn = opts.fetchFn ?? fetch;
  const traceId = newId();
  const now = new Date().toISOString();
  const body = {
    batch: [
      {
        id: newId(),
        timestamp: now,
        type: "trace-create",
        body: { id: traceId, name, metadata: data, timestamp: now },
      },
    ],
  };
  try {
    const res = await fetchFn(`${langfuseHost(env)}/api/public/ingestion`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${btoa(`${env.LANGFUSE_PUBLIC_KEY}:${env.LANGFUSE_SECRET_KEY}`)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) console.warn(`[observability] langfuse trace failed: ${name} status=${res.status}`);
  } catch {
    console.warn(`[observability] langfuse trace failed: ${name} network_error`);
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
 */
export async function captureError(
  env: ObservabilityEnv,
  error: unknown,
  context: Record<string, unknown> = {},
  opts: ObservabilityOpts = {},
): Promise<void> {
  const parsed = env.SENTRY_DSN ? parseSentryDsn(env.SENTRY_DSN) : null;
  if (!parsed) return;
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
    if (!res.ok) console.warn(`[observability] sentry capture failed: status=${res.status}`);
  } catch {
    console.warn("[observability] sentry capture failed: network_error");
  }
}
