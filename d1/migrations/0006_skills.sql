-- OmniJarvis D1 migration 0006 — skill registry reviews/signatures + memories (Phase 3, stage 3d).
-- Pehle-Jaanch phase-3/3d §2a. NUMBER NOTE: PEHLE_JAANCH_PHASE3 §6 said "0005_skills.sql",
-- but 0005 was taken by 3c (0005_browser.sql, live applied) — this migration is 0006.
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + indexes only.
-- global_skills already exists (0002: id, manifest, status quarantined/approved/rejected,
-- submitted_by, created_at) — it is NOT touched here.
-- Skill rule (frozen): submit is ALWAYS quarantined; approve needs a clean AST scan
-- (Render /doc/scan re-run at review time) + Ed25519 sign (SKILL_SIGN_SECRET).
-- Memory rule (frozen): D1 is the vector store in Phase 3 (vectors JSON TEXT,
-- JS cosine, cap 500 memories/tenant with FIFO eviction, tenant-isolated).
-- Qdrant is NOT live (account pending, parent-side) — no Qdrant table/column here.

-- skill_reviews: one row per human admin decision (approve/reject + reason).
CREATE TABLE IF NOT EXISTS skill_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  skill_id TEXT NOT NULL,
  reviewer TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
  reason TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_skill_reviews_skill ON skill_reviews(skill_id, created_at);

-- skill_signatures: one row per approved skill (Ed25519 signature over
-- `skill:<skill_id>\n<manifest_hash>`, public key for client verify).
CREATE TABLE IF NOT EXISTS skill_signatures (
  skill_id TEXT PRIMARY KEY,
  signature TEXT NOT NULL,
  public_key TEXT NOT NULL,
  signed_at INTEGER NOT NULL
);

-- memories: D1-backed vector store (Phase 3). embedding is JSON TEXT
-- (number[]); kind defaults to 'fact'. Cap 500/tenant enforced in code
-- (FIFO eviction of the oldest row), not by a DB constraint.
CREATE TABLE IF NOT EXISTS memories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  content TEXT NOT NULL,
  embedding TEXT,
  kind TEXT NOT NULL DEFAULT 'fact',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memories_tenant ON memories(tenant_id, created_at);
