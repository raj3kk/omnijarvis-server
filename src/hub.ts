/**
 * omnijarvis-hub — Cloudflare Worker entry (control plane).
 *
 * Stage 2a-1 skeleton: health + status routes only. Pairing / sync /
 * cron / keep-alive routes land in 2a-2. Licence routes live in the
 * SEPARATE `jarvis-licence` Worker (Phase 0) — unhe yahan port mat karo.
 */
import { JarvisHub } from "./do/JarvisHub";

export { JarvisHub };

export interface Env {
  JARVIS_HUB: DurableObjectNamespace;
  DB: D1Database;
}

const SERVICE = "omnijarvis-hub";
const VERSION = "2a-1";

/**
 * Pure route dispatch (no env access) — vitest se testable hai
 * bina Workers runtime ke.
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

export default {
  async fetch(request: Request, _env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      return route(url.pathname);
    } catch (e) {
      return Response.json(
        { error: "server_error", detail: String((e as Error)?.message ?? e) },
        { status: 500 },
      );
    }
  },
};
