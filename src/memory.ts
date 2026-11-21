/**
 * memory.ts — Memory API helpers (Phase 3, stage 3d).
 *
 * The vector store in Phase 3 is D1 (`memories` table, 0006): vectors as
 * JSON TEXT, JS cosine similarity, cap 500 memories/tenant (FIFO eviction),
 * tenant-isolated. Qdrant swaps in later through the MemoryStore interface
 * — one place, no route changes.
 *
 * Qdrant (honest scope): the account does NOT exist yet (parent browser
 * task, U-3). `qdrantStatus()` is env-gated (`QDRANT_URL` + `QDRANT_API_KEY`
 * both set = configured); the qdrant* stubs return an honest
 * `qdrant_not_configured` error when unset and NEVER fake a success.
 * Memory routes use the D1 store; they do not call the Qdrant stubs.
 *
 * Mem0 extraction (Render worker `/mem/extract` -> hub `/api/llm/route`)
 * is NOT built in 3d: the Render deploy is pending (U-2) and Render-side
 * INTERNAL_SECRET provisioning does not exist yet. Open item, not a claim.
 *
 * Embeddings come from the 3a router (kind `embeddings`,
 * gemini-embedding-001, no fallback) — the router's own pre-checks
 * (tenant exists / BYOK key / caps) apply for free; `byok_required`
 * (402) etc. are forwarded honestly by the hub routes.
 *
 * PII RULE: memory `content` NEVER appears in traces/logs — traces carry
 * only {tenant_id, memory_id, kind}. Wipe = DELETE WHERE tenant_id (DPDP).
 */
import type { D1Like } from "./db";
import { loadRouterConfig, routeLlm, type RouterDeps } from "./router";

/** Hard cap: memories per tenant (FIFO eviction of the oldest row). */
export const MEMORY_CAP_PER_TENANT = 500;
/** Max memory content length (chars) — longer is a 400, not a truncate. */
export const MAX_MEMORY_CONTENT_CHARS = 4000;

export interface MemoryRow {
  id: number;
  tenant_id: string;
  content: string;
  embedding: string | null;
  kind: string;
  created_at: number;
}

export interface MemoryHit {
  id: number;
  content: string;
  kind: string;
  score: number;
  created_at: number;
}

/**
 * Cosine similarity. Identical -> 1, orthogonal -> 0, opposite -> -1.
 * Zero-length / zero-norm vectors -> 0 (never NaN — a bad embedding
 * scores 0 and sorts last instead of crashing the search).
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length === 0 || b.length === 0) return 0;
  const n = Math.min(a.length, b.length);
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < n; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

// --- Embeddings via the 3a router ---

export interface EmbedDeps {
  db: D1Like;
  masterKeyB64?: string;
  founderKey?: string;
  config?: RouterDeps["config"];
  fetchFn?: typeof fetch;
}

export async function embedText(
  deps: EmbedDeps,
  tenantId: string,
  text: string,
  turnId: string,
): Promise<{ ok: true; embedding: number[] } | { ok: false; error: string; error_code: string }> {
  const result = await routeLlm(
    {
      db: deps.db,
      fetchFn: deps.fetchFn,
      masterKeyB64: deps.masterKeyB64,
      founderKey: deps.founderKey,
      config: deps.config ?? loadRouterConfig({}),
    },
    { tenant_id: tenantId, turn_id: turnId, kind: "embeddings", messages: [{ role: "user", text }] },
  );
  if (!result.ok || !result.embedding) {
    return { ok: false, error: result.error ?? "embedding_failed", error_code: result.error_code ?? "embedding_failed" };
  }
  return { ok: true, embedding: result.embedding };
}

// --- D1 memory store (the Phase 3 store) ---

/**
 * Store one memory. At the 500/tenant cap the OLDEST memory is evicted
 * first (FIFO), so the count never exceeds the cap and the store keeps
 * working instead of refusing. Returns the new memory id.
 */
export async function storeMemory(
  db: D1Like,
  tenantId: string,
  content: string,
  kind: string,
  embedding: number[],
  nowMs = Date.now(),
): Promise<number> {
  const countRow = await db
    .prepare("SELECT COUNT(*) AS n FROM memories WHERE tenant_id = ?")
    .bind(tenantId)
    .first<{ n: number }>();
  if ((countRow?.n ?? 0) >= MEMORY_CAP_PER_TENANT) {
    const oldest = await db
      .prepare("SELECT id FROM memories WHERE tenant_id = ? ORDER BY created_at ASC LIMIT 1")
      .bind(tenantId)
      .first<{ id: number }>();
    if (oldest) {
      await db.prepare("DELETE FROM memories WHERE id = ?").bind(oldest.id).run();
    }
  }
  await db
    .prepare("INSERT INTO memories (tenant_id, content, embedding, kind, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(tenantId, content, JSON.stringify(embedding), kind, nowMs)
    .run();
  const row = await db
    .prepare("SELECT id FROM memories WHERE tenant_id = ? AND created_at = ? ORDER BY id DESC LIMIT 1")
    .bind(tenantId, nowMs)
    .first<{ id: number }>();
  if (!row) throw new Error("memory insert failed");
  return row.id;
}

/**
 * Search a tenant's memories by cosine similarity to the query embedding.
 * Memories with a missing/unparseable embedding score 0 (never crash).
 * Returns at most topK hits, best score first.
 */
export async function searchMemories(
  db: D1Like,
  tenantId: string,
  queryEmbedding: number[],
  topK: number,
): Promise<MemoryHit[]> {
  const res = await db
    .prepare("SELECT id, tenant_id, content, embedding, kind, created_at FROM memories WHERE tenant_id = ?")
    .bind(tenantId)
    .all<MemoryRow>();
  const rows = res.results ?? [];
  const scored: MemoryHit[] = rows.map((r) => {
    let emb: number[] | null = null;
    try {
      const parsed: unknown = JSON.parse(r.embedding ?? "null");
      if (Array.isArray(parsed) && parsed.every((v) => typeof v === "number")) emb = parsed as number[];
    } catch {
      emb = null;
    }
    return {
      id: r.id,
      content: r.content,
      kind: r.kind,
      score: emb ? cosineSimilarity(queryEmbedding, emb) : 0,
      created_at: r.created_at,
    };
  });
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, Math.max(1, topK));
}

/** DPDP wipe: delete ALL of a tenant's memories. Returns the count deleted. */
export async function wipeMemories(db: D1Like, tenantId: string): Promise<number> {
  const countRow = await db
    .prepare("SELECT COUNT(*) AS n FROM memories WHERE tenant_id = ?")
    .bind(tenantId)
    .first<{ n: number }>();
  const n = countRow?.n ?? 0;
  await db.prepare("DELETE FROM memories WHERE tenant_id = ?").bind(tenantId).run();
  return n;
}

// --- Qdrant (env-gated stubs — the account does not exist yet) ---

export interface QdrantEnv {
  QDRANT_URL?: string;
  QDRANT_API_KEY?: string;
}

/** Configured ONLY when BOTH QDRANT_URL and QDRANT_API_KEY are set. */
export function qdrantStatus(env: QdrantEnv): { configured: boolean } {
  return { configured: Boolean(env.QDRANT_URL && env.QDRANT_API_KEY) };
}

export interface QdrantResult {
  ok: boolean;
  error?: string;
}

/**
 * Qdrant upsert stub. Unset env -> `qdrant_not_configured`. Set env but
 * no live account yet -> `qdrant_not_live` (honest: there is no real
 * Qdrant client in 3d, and no fake success is ever returned).
 */
export async function qdrantUpsert(
  env: QdrantEnv,
  _tenantId: string,
  _memoryId: number,
  _embedding: number[],
): Promise<QdrantResult> {
  if (!qdrantStatus(env).configured) return { ok: false, error: "qdrant_not_configured" };
  return { ok: false, error: "qdrant_not_live" };
}

/** Qdrant query stub — same honest errors as qdrantUpsert. */
export async function qdrantQuery(
  env: QdrantEnv,
  _tenantId: string,
  _queryEmbedding: number[],
  _topK: number,
): Promise<QdrantResult & { hits?: MemoryHit[] }> {
  if (!qdrantStatus(env).configured) return { ok: false, error: "qdrant_not_configured" };
  return { ok: false, error: "qdrant_not_live" };
}
