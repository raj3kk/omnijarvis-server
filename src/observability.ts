/**
 * observability.ts — Langfuse + Sentry wiring (env-gated).
 *
 * 2a-2 me: no-op stubs (accounts abhi nahi hain — parent browser task se
 * signups honge, 2a-4 me wiring). Interface frozen hai taaki routes
 * abhi se trace()/captureError() call kar sakein bina har jagah
 * env-check likhe. Keys aate hi 2a-4 me fetch-based sender bharo
 * (koi SDK dependency abhi nahi — bundle chhota rakho).
 */

export interface ObservabilityEnv {
  LANGFUSE_PUBLIC_KEY?: string;
  LANGFUSE_SECRET_KEY?: string;
  LANGFUSE_HOST?: string;
  SENTRY_DSN?: string;
}

export function isObservabilityOn(env: ObservabilityEnv): boolean {
  return Boolean(env.LANGFUSE_PUBLIC_KEY || env.SENTRY_DSN);
}

export async function trace(
  _env: ObservabilityEnv,
  _name: string,
  _data: Record<string, unknown>,
): Promise<void> {
  // 2a-4: Langfuse ingestion API (POST /api/public/ingestion).
}

export async function captureError(
  _env: ObservabilityEnv,
  _error: unknown,
  _context: Record<string, unknown> = {},
): Promise<void> {
  // 2a-4: Sentry envelope API (POST <dsn>/envelope) ya @sentry/cloudflare.
}
