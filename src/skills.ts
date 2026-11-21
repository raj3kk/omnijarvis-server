/**
 * skills.ts — Skill registry helpers (Phase 3, stage 3d).
 *
 * Worker routes live in hub.ts; the pure/testable logic lives here:
 *  - Manifest schema validation (frozen: name/version/trigger/steps + optional
 *    description/evidence/requirements/code; extra keys allowed).
 *  - AST scan via the Render worker (3b `/doc/scan`, forwardToRender reuse).
 *    Submit-time scan is ADVISORY; review-time re-scan is AUTHORITATIVE.
 *  - Ed25519 sign/verify for approved skills (SKILL_SIGN_SECRET, PKCS8
 *    base64 — crypto.ts primitives reuse; message `skill:<id>\n<hash>`).
 *  - D1 helpers for global_skills (0002, HAVE) + skill_reviews +
 *    skill_signatures (0006).
 *
 * QUARANTINE RULE (frozen): submit ALWAYS lands quarantined. There is no
 * auto-approve path anywhere in this file. Approve needs a clean scan
 * (re-run at review time) + a signature. A manifest's `code` field is the
 * scan target; a manifest without `code` is vacuous-clean (`no_code`).
 *
 * Auth is NOT invented here: hub routes reuse docs.ts
 * authorizeDocsRequest() (internal-secret OR paired device + Ed25519).
 */
import type { D1Like } from "./db";
import {
  base64ToBytes,
  bytesToBase64,
  deriveHubPublicKeyB64,
  importPrivateKey,
  randomNonceHex,
} from "./crypto";
import { canonicalPayload, forwardToRender, sha256Hex, type RenderEnv } from "./docs";

/** Render /doc/scan cap (main.py MAX_SCAN_BYTES = 512 KB). */
export const MAX_SKILL_CODE_BYTES = 512 * 1024;

export interface SkillManifest {
  name: string;
  version: string;
  trigger: string;
  steps: Array<Record<string, unknown>>;
  description?: string;
  evidence?: Record<string, unknown>;
  requirements?: Record<string, unknown> | unknown[];
  code?: string;
  [key: string]: unknown;
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

/**
 * Validate a submitted manifest against the frozen schema. Returns the
 * typed manifest on success; on failure the FIRST violated rule (field
 * name only — never manifest content, never logged).
 */
export function validateSkillManifest(
  input: unknown,
): { ok: true; manifest: SkillManifest } | { ok: false; error: string } {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, error: "manifest must be an object" };
  }
  const m = input as Record<string, unknown>;
  if (!isNonEmptyString(m.name)) return { ok: false, error: "manifest.name is required" };
  if (!isNonEmptyString(m.version)) return { ok: false, error: "manifest.version is required" };
  if (!isNonEmptyString(m.trigger)) return { ok: false, error: "manifest.trigger is required" };
  if (!Array.isArray(m.steps) || m.steps.length === 0) {
    return { ok: false, error: "manifest.steps must be a non-empty array" };
  }
  for (let i = 0; i < m.steps.length; i++) {
    const step = m.steps[i] as Record<string, unknown> | null;
    if (!step || typeof step !== "object" || Array.isArray(step) || !isNonEmptyString(step.action)) {
      return { ok: false, error: `manifest.steps[${i}].action is required` };
    }
  }
  if (m.description !== undefined && typeof m.description !== "string") {
    return { ok: false, error: "manifest.description must be a string" };
  }
  if (m.evidence !== undefined && (typeof m.evidence !== "object" || m.evidence === null || Array.isArray(m.evidence))) {
    return { ok: false, error: "manifest.evidence must be an object" };
  }
  if (
    m.requirements !== undefined &&
    (typeof m.requirements !== "object" || m.requirements === null)
  ) {
    return { ok: false, error: "manifest.requirements must be an object or array" };
  }
  if (m.code !== undefined && typeof m.code !== "string") {
    return { ok: false, error: "manifest.code must be a string" };
  }
  return { ok: true, manifest: input as SkillManifest };
}

/** Server-generated skill id: `skl-` + 16 hex (browser taskId pattern). */
export function newSkillId(): string {
  return `skl-${randomNonceHex(8)}`;
}

/** SHA-256 hex of the canonical (sorted-keys) manifest JSON. */
export async function manifestHash(manifest: SkillManifest): Promise<string> {
  return sha256Hex(canonicalPayload(manifest as unknown as Record<string, unknown>));
}

// --- Ed25519 skill signing (SKILL_SIGN_SECRET) ---

/** Canonical signed message (frozen): `skill:<skill_id>\n<manifest_hash>`. */
export function skillSignMessage(skillId: string, manifestHashValue: string): string {
  return `skill:${skillId}\n${manifestHashValue}`;
}

export async function signSkill(
  privateKey: CryptoKey,
  skillId: string,
  manifestHashValue: string,
): Promise<string> {
  const data = new TextEncoder().encode(skillSignMessage(skillId, manifestHashValue));
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, data);
  return bytesToBase64(new Uint8Array(sig));
}

export async function verifySkillSignature(
  publicKeyB64: string,
  skillId: string,
  manifestHashValue: string,
  signatureB64: string,
): Promise<boolean> {
  try {
    const raw = base64ToBytes(publicKeyB64);
    const key = await crypto.subtle.importKey(
      "raw",
      raw.buffer as ArrayBuffer,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const sig = base64ToBytes(signatureB64);
    const data = new TextEncoder().encode(skillSignMessage(skillId, manifestHashValue));
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig.buffer as ArrayBuffer, data);
  } catch {
    return false; // fail-closed: malformed key/signature = reject
  }
}

export interface SkillSignEnv {
  SKILL_SIGN_SECRET?: string;
  SKILL_SIGN_PUBLIC_KEY?: string;
}

/**
 * Public key for skill verification: prefer the SKILL_SIGN_PUBLIC_KEY env
 * value; else derive it from SKILL_SIGN_SECRET; null when neither works.
 * The private value is never returned, logged, or stored.
 */
export async function getSkillPublicKey(env: SkillSignEnv): Promise<string | null> {
  if (env.SKILL_SIGN_PUBLIC_KEY) return env.SKILL_SIGN_PUBLIC_KEY;
  if (!env.SKILL_SIGN_SECRET) return null;
  try {
    const priv = await importPrivateKey(env.SKILL_SIGN_SECRET);
    return await deriveHubPublicKeyB64(priv);
  } catch {
    return null;
  }
}

// --- AST scan via the Render worker (3b /doc/scan) ---

export interface ScanFinding {
  line: number;
  pattern: string;
  detail: string;
}

export interface ScanResult {
  status: "clean" | "findings" | "pending";
  findings: ScanFinding[];
  error?: string;
  note?: string;
}

/**
 * Scan a skill's Python `code` through Render POST /doc/scan.
 * - No code -> vacuous-clean (`no_code`): a manifest-only skill has
 *   nothing to AST-scan.
 * - RENDER_WORKER_URL unset -> `pending` + `render_not_configured`
 *   (honest; the caller decides whether that blocks — submit: no,
 *   approve: yes).
 * - Any other Render failure -> `pending` + the error (never a fake clean).
 * `fetchFn`/`sleepFn` are injectable for vitest (forwardToRender pattern).
 */
export async function scanSkillCode(
  env: RenderEnv,
  code: string | null | undefined,
  opts: { fetchFn?: typeof fetch; sleepFn?: (ms: number) => Promise<void> } = {},
): Promise<ScanResult> {
  if (!code) return { status: "clean", findings: [], note: "no_code" };
  const form = new FormData();
  form.append("file", new File([code], "skill.py", { type: "text/x-python" }));
  const res = await forwardToRender(env, "/doc/scan", { method: "POST", body: form }, opts);
  if (!res.ok) {
    return { status: "pending", findings: [], error: res.error ?? "render_error" };
  }
  const findings = Array.isArray((res.json ?? {}).findings)
    ? ((res.json as Record<string, unknown>).findings as ScanFinding[])
    : [];
  return { status: findings.length > 0 ? "findings" : "clean", findings };
}

// --- D1 helpers (global_skills is 0002; reviews/signatures are 0006) ---

export interface SkillRow {
  id: string;
  manifest: string;
  status: string;
  submitted_by: string | null;
  created_at: number;
}

export async function insertSkill(
  db: D1Like,
  skill: { id: string; manifest: string; submitted_by: string; created_at: number },
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO global_skills (id, manifest, status, submitted_by, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(skill.id, skill.manifest, "quarantined", skill.submitted_by, skill.created_at)
    .run();
}

export async function getSkill(db: D1Like, skillId: string): Promise<SkillRow | null> {
  return await db
    .prepare("SELECT id, manifest, status, submitted_by, created_at FROM global_skills WHERE id = ?")
    .bind(skillId)
    .first<SkillRow>();
}

/** Approved-only list, oldest first (Free plan takes slice(0, 1) of this). */
export async function listApprovedSkills(db: D1Like): Promise<SkillRow[]> {
  const res = await db
    .prepare(
      "SELECT id, manifest, status, submitted_by, created_at FROM global_skills " +
        "WHERE status = ? ORDER BY created_at ASC",
    )
    .bind("approved")
    .all<SkillRow>();
  return res.results ?? [];
}

export async function setSkillStatus(db: D1Like, skillId: string, status: string): Promise<void> {
  await db.prepare("UPDATE global_skills SET status = ? WHERE id = ?").bind(status, skillId).run();
}

export async function insertSkillReview(
  db: D1Like,
  review: { skill_id: string; reviewer: string; decision: string; reason: string; created_at: number },
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO skill_reviews (skill_id, reviewer, decision, reason, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(review.skill_id, review.reviewer, review.decision, review.reason, review.created_at)
    .run();
}

export async function insertSkillSignature(
  db: D1Like,
  sig: { skill_id: string; signature: string; public_key: string; signed_at: number },
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO skill_signatures (skill_id, signature, public_key, signed_at) VALUES (?, ?, ?, ?)",
    )
    .bind(sig.skill_id, sig.signature, sig.public_key, sig.signed_at)
    .run();
}

export async function getSkillSignature(
  db: D1Like,
  skillId: string,
): Promise<{ skill_id: string; signature: string; public_key: string; signed_at: number } | null> {
  return await db
    .prepare("SELECT skill_id, signature, public_key, signed_at FROM skill_signatures WHERE skill_id = ?")
    .bind(skillId)
    .first<{ skill_id: string; signature: string; public_key: string; signed_at: number }>();
}
