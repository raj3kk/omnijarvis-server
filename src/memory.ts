/**
 * memory.ts — Memory API helpers (Phase 3, stage 3d).
 *
 * The vector store in Phase 3 is D1 (`memories` table, 0006): vectors as
 * JSON TEXT, JS cosine similarity, cap 2000 memories/tenant (FIFO eviction, R2.5 D-R16 — was 500),
 * tenant-isolated. Qdrant swaps in later through the MemoryStore interface
 * — one place, no route changes.
 *
 * Qdrant (completeness #30, Track A): the account EXISTS (keys in
 * `.secrets/signups.env`) and the real REST client lives below —
 * create-collection-if-missing, upsert, search — env-gated
 * (`QDRANT_URL` + `QDRANT_API_KEY` both set = configured). Unset env
 * -> honest `qdrant_not_configured`; any live failure ->
 * `qdrant_error` (never a fake success). D1 REMAINS the default
 * store: memory routes use the D1 store and do not call Qdrant;
 * Qdrant is the upgrade path through the same function seam.
 *
 * Mem0 extraction (Render worker `/mem/extract` -> hub `/api/llm/route`)
 * is NOT built in 3d: the Render deploy is pending (U-2) and Render-side
 * INTERNAL_SECRET provisioning does not exist yet. Open item, not a claim.
 * R2.8: the Render worker is LIVE (v3b) and /mem/extract is verified
 * against real traffic in the R2 build notes — see there, not here.
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

/** Hard cap: memories per tenant (FIFO eviction of the oldest row).
 * R2.5 (D-R16, decided): 500 -> 2,000 — Trained Jarvis + admin training
 * need headroom; the cap is a const, not schema (no migration). */
export const MEMORY_CAP_PER_TENANT = 2000;
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
 * Store one memory. At the 2000/tenant cap (R2.5, was 500) the OLDEST
 * memory is evicted first (FIFO), so the count never exceeds the cap
 * and the store keeps working instead of refusing. Returns the new
 * memory id.
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

/**
 * R2.3: list a tenant's memories of one kind, newest first.
 * Used by Main run-start recall (kind 'admin_training', cap 10) and by
 * /api/memory/list. Content IS returned (callers are the tenant's own
 * Main job / device) — never put it in traces (PII rule, file header).
 */
export async function listMemoriesByKind(
  db: D1Like,
  tenantId: string,
  kind: string,
  limit: number,
): Promise<MemoryHit[]> {
  const res = await db
    .prepare(
      "SELECT id, content, kind, created_at FROM memories WHERE tenant_id = ? AND kind = ? ORDER BY created_at DESC LIMIT ?",
    )
    .bind(tenantId, kind, Math.max(1, Math.floor(limit)))
    .all<{ id: number; content: string; kind: string; created_at: number }>();
  return (res.results ?? []).map((r) => ({ id: r.id, content: r.content, kind: r.kind, score: 0, created_at: r.created_at }));
}

export interface ApprovedPattern {
  id: string;
  template: string;
  source: string;
  use_count: number;
}

/**
 * R2.3: approved learned patterns for Main run-start recall.
 * `learned_patterns` has NO tenant column (templates only, global) —
 * admin rows first, then highest use_count. Cap 20. Admin training
 * (source='admin', approved=1 at insert) outranks user-learned rows;
 * on a conflict the admin row wins and the Talker says so.
 */
export async function loadApprovedPatterns(db: D1Like, limit: number): Promise<ApprovedPattern[]> {
  const out: ApprovedPattern[] = [];
  const cap = Math.max(1, Math.floor(limit));
  const admin = await db
    .prepare(
      "SELECT id, template, source, use_count FROM learned_patterns WHERE approved = 1 AND source = ? ORDER BY use_count DESC LIMIT ?",
    )
    .bind("admin", cap)
    .all<ApprovedPattern>();
  out.push(...(admin.results ?? []));
  if (out.length < cap) {
    const user = await db
      .prepare(
        "SELECT id, template, source, use_count FROM learned_patterns WHERE approved = 1 AND source = ? ORDER BY use_count DESC LIMIT ?",
      )
      .bind("user", cap - out.length)
      .all<ApprovedPattern>();
    out.push(...(user.results ?? []));
  }
  return out;
}

// --- Qdrant (real REST client, env-gated — completeness #30) ---

export interface QdrantEnv {
  QDRANT_URL?: string;
  QDRANT_API_KEY?: string;
}

export interface QdrantOpts {
  fetchFn?: typeof fetch;
}

/** Qdrant collection for tenant memories (one collection, tenant filter). */
export const QDRANT_COLLECTION = "omnijarvis_memories";

/** Configured ONLY when BOTH QDRANT_URL and QDRANT_API_KEY are set. */
export function qdrantStatus(env: QdrantEnv): { configured: boolean } {
  return { configured: Boolean(env.QDRANT_URL && env.QDRANT_API_KEY) };
}

export interface QdrantResult {
  ok: boolean;
  error?: string;
}

function qdrantBase(env: QdrantEnv): string {
  return (env.QDRANT_URL ?? "").replace(/\/+$/, "");
}

function qdrantHeaders(env: QdrantEnv): Record<string, string> {
  return { "api-key": env.QDRANT_API_KEY ?? "", "Content-Type": "application/json" };
}

/**
 * Ensure the collection exists with the embedding's vector size
 * (Cosine distance). GET 200 = exists; GET 404 = PUT-create; any
 * other status / network failure = false (caller returns qdrant_error).
 * R-15 live proof (2026-11-22): the cluster runs strict mode
 * (`unindexed_filtering_retrieve:false`), so a tenant-filtered search
 * 400s ("Index required but not found for tenant_id") unless the
 * `tenant_id` keyword payload index exists — NOTHING created it before.
 * This function now also ensures that index: on an existing collection
 * it reads `payload_schema` from the GET and creates the index only
 * when missing; on a fresh collection it creates the index right
 * after the PUT. Index-create failure = false (fail closed — an
 * upsert that can never be searched is not a success).
 */
export async function qdrantEnsureCollection(
  env: QdrantEnv,
  vectorSize: number,
  opts: QdrantOpts = {},
): Promise<boolean> {
  const fetchFn = opts.fetchFn ?? fetch;
  const base = qdrantBase(env);
  try {
    const get = await fetchFn(`${base}/collections/${QDRANT_COLLECTION}`, {
      headers: qdrantHeaders(env),
    });
    if (get.ok) {
      let schema: Record<string, unknown> | null = null;
      try {
        const data = (await get.json()) as { result?: { payload_schema?: Record<string, unknown> } };
        schema = data?.result?.payload_schema ?? null;
      } catch {
        schema = null; // unparseable body: attempt the index PUT, fail closed if it errors
      }
      return qdrantEnsureTenantIndex(env, base, fetchFn, schema);
    }
    if (get.status !== 404) return false;
    const put = await fetchFn(`${base}/collections/${QDRANT_COLLECTION}`, {
      method: "PUT",
      headers: qdrantHeaders(env),
      body: JSON.stringify({ vectors: { size: vectorSize, distance: "Cosine" } }),
    });
    if (!put.ok) return false;
    // Fresh collection has no payload indexes at all.
    return qdrantEnsureTenantIndex(env, base, fetchFn, {});
  } catch {
    return false;
  }
}

/**
 * Ensure the `tenant_id` keyword payload index exists. When the
 * collection's `payload_schema` is known and already lists tenant_id,
 * no request is made. Otherwise PUT the index (R-15 proof: this exact
 * call — `{field_name:"tenant_id",field_schema:"keyword"}` — turned a
 * 400 filtered search into a 200 with score 1.0000001).
 */
async function qdrantEnsureTenantIndex(
  env: QdrantEnv,
  base: string,
  fetchFn: typeof fetch,
  payloadSchema: Record<string, unknown> | null,
): Promise<boolean> {
  if (payloadSchema && "tenant_id" in payloadSchema) return true;
  try {
    const res = await fetchFn(`${base}/collections/${QDRANT_COLLECTION}/index`, {
      method: "PUT",
      headers: qdrantHeaders(env),
      body: JSON.stringify({ field_name: "tenant_id", field_schema: "keyword" }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Qdrant point id = the D1 memory id, as an unsigned integer.
 * R-15 live proof (2026-11-22): the old `"${tenantId}:${memoryId}"`
 * STRING id 400s on upsert ("not a valid point ID, valid values are
 * either an unsigned integer or a UUID"); integer 9001 upserted 200
 * acknowledged. The integer is safe across tenants: `memories.id` is
 * `INTEGER PRIMARY KEY AUTOINCREMENT`, globally unique per table, and
 * the tenant is carried in the payload (`tenant_id`) which the search
 * filter matches on — the id itself never needs to encode the tenant.
 */
function qdrantPointId(memoryId: number): number {
  return memoryId;
}

/**
 * Qdrant upsert. Unset env -> `qdrant_not_configured`. Any live
 * failure (collection create / upsert non-ok / network) ->
 * `qdrant_error` — never a fake success. `meta.content`/`meta.kind`
 * land in the point payload so search can return hits without a
 * second D1 read; omit them and the payload carries empty content.
 */
export async function qdrantUpsert(
  env: QdrantEnv,
  tenantId: string,
  memoryId: number,
  embedding: number[],
  meta: { content?: string; kind?: string; created_at?: number } = {},
  opts: QdrantOpts = {},
): Promise<QdrantResult> {
  if (!qdrantStatus(env).configured) return { ok: false, error: "qdrant_not_configured" };
  if (!Number.isFinite(memoryId) || embedding.length === 0) {
    return { ok: false, error: "qdrant_error" };
  }
  const fetchFn = opts.fetchFn ?? fetch;
  const base = qdrantBase(env);
  try {
    const ensured = await qdrantEnsureCollection(env, embedding.length, opts);
    if (!ensured) return { ok: false, error: "qdrant_error" };
    const res = await fetchFn(`${base}/collections/${QDRANT_COLLECTION}/points`, {
      method: "PUT",
      headers: qdrantHeaders(env),
      body: JSON.stringify({
        points: [
          {
            id: qdrantPointId(memoryId),
            vector: embedding,
            payload: {
              tenant_id: tenantId,
              memory_id: memoryId,
              kind: meta.kind ?? "fact",
              content: meta.content ?? "",
              created_at: meta.created_at ?? 0,
            },
          },
        ],
      }),
    });
    if (!res.ok) return { ok: false, error: "qdrant_error" };
    return { ok: true };
  } catch {
    return { ok: false, error: "qdrant_error" };
  }
}

/**
 * Qdrant vector search, tenant-filtered. Unset env ->
 * `qdrant_not_configured`; missing collection -> `qdrant_error`
 * (search never auto-creates — an empty store is a D1 matter, and
 * creating a collection on a read would hide a misconfiguration).
 * Hits map the stored payload back to MemoryHit shape.
 */
export async function qdrantQuery(
  env: QdrantEnv,
  tenantId: string,
  queryEmbedding: number[],
  topK: number,
  opts: QdrantOpts = {},
): Promise<QdrantResult & { hits?: MemoryHit[] }> {
  if (!qdrantStatus(env).configured) return { ok: false, error: "qdrant_not_configured" };
  if (queryEmbedding.length === 0) return { ok: false, error: "qdrant_error" };
  const fetchFn = opts.fetchFn ?? fetch;
  const base = qdrantBase(env);
  try {
    const res = await fetchFn(`${base}/collections/${QDRANT_COLLECTION}/points/search`, {
      method: "POST",
      headers: qdrantHeaders(env),
      body: JSON.stringify({
        vector: queryEmbedding,
        filter: { must: [{ key: "tenant_id", match: { value: tenantId } }] },
        limit: Math.max(1, topK),
        with_payload: true,
      }),
    });
    if (!res.ok) return { ok: false, error: "qdrant_error" };
    const data = (await res.json()) as {
      result?: Array<{ id: unknown; score?: number; payload?: Record<string, unknown> }>;
    };
    const hits: MemoryHit[] = (data.result ?? []).map((r) => {
      const p = r.payload ?? {};
      return {
        id: typeof p.memory_id === "number" ? p.memory_id : 0,
        content: typeof p.content === "string" ? p.content : "",
        kind: typeof p.kind === "string" ? p.kind : "fact",
        score: typeof r.score === "number" ? r.score : 0,
        created_at: typeof p.created_at === "number" ? p.created_at : 0,
      };
    });
    return { ok: true, hits };
  } catch {
    return { ok: false, error: "qdrant_error" };
  }
}
