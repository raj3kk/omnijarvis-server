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
 * ANTHROPIC SKILLS FORMAT (completeness #9): alongside the v1 JSON
 * manifest, `validateSkillManifest` accepts an Anthropic SKILL.md
 * document (YAML frontmatter `name` / `description` /
 * `allowed-tools` + Markdown instruction body) — passed either as a
 * raw string or as an object with `format: "anthropic"`. It is
 * normalised to a v1 manifest: `version` defaults to "1.0.0"
 * (Anthropic frontmatter has no version), `trigger` defaults to the
 * skill name (the invocation name), `steps` defaults to a single
 * `follow-skill-instructions` pointer step, and the Markdown body is
 * kept verbatim in `instructions`. Nothing about the v1 rules changes.
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
  /** Anthropic-format skills only: "anthropic" + normalised fields. */
  format?: string;
  allowed_tools?: string[];
  instructions?: string;
  [key: string]: unknown;
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

/**
 * Validate a submitted manifest against the frozen schema. Returns the
 * typed manifest on success; on failure the FIRST violated rule (field
 * name only — never manifest content, never logged).
 *
 * Accepts three shapes (completeness #9):
 *  1. v1 JSON manifest object (frozen rules below, unchanged).
 *  2. An Anthropic SKILL.md document as a raw string (frontmatter +
 *     Markdown body) — parsed by parseAnthropicSkillMd.
 *  3. An object with `format: "anthropic"` (name/description/
 *     allowed_tools) — normalised to v1 (version/trigger/steps
 *     defaulted, instructions kept).
 */
export function validateSkillManifest(
  input: unknown,
): { ok: true; manifest: SkillManifest } | { ok: false; error: string } {
  if (typeof input === "string") return parseAnthropicSkillMd(input);
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, error: "manifest must be an object" };
  }
  const m = input as Record<string, unknown>;
  if (m.format === "anthropic") return validateAnthropicManifest(m);
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

// --- Anthropic SKILL.md format (completeness #9) ---

function unquoteFrontmatterValue(v: string): string {
  const t = v.trim();
  if (t.length >= 2 && ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")))) {
    return t.slice(1, -1);
  }
  return t;
}

/**
 * Parse the YAML frontmatter block of an Anthropic SKILL.md file.
 * Tiny hand-rolled parser (no YAML dep): supports `key: value`
 * lines (quoted or plain) and `allowed-tools` as either a
 * comma-separated value or a `- item` list. Unknown keys are kept
 * verbatim as strings. Returns the raw map + the key order seen.
 */
function parseSkillFrontmatter(
  block: string,
): { ok: true; fields: Record<string, unknown> } | { ok: false; error: string } {
  const fields: Record<string, unknown> = {};
  const seen = new Set<string>();
  let listKey: string | null = null;
  for (const rawLine of block.split("\n")) {
    const line = rawLine.replace(/\r$/, "");
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const listMatch = /^(\s*)-\s+(.+)$/.exec(line);
    if (listMatch) {
      if (!listKey) return { ok: false, error: "frontmatter list item without a key" };
      const arr = fields[listKey] as string[];
      const item = unquoteFrontmatterValue(listMatch[2]);
      if (!item) return { ok: false, error: `frontmatter.${listKey} entries must be non-empty` };
      arr.push(item);
      continue;
    }
    listKey = null;
    const kvMatch = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line);
    if (!kvMatch) return { ok: false, error: "frontmatter line is not key: value" };
    const key = kvMatch[1];
    if (seen.has(key)) return { ok: false, error: `frontmatter duplicate key: ${key}` };
    seen.add(key);
    const value = kvMatch[2].trim();
    if (value === "") {
      // Key with no inline value: a `- item` list may follow.
      fields[key] = [];
      listKey = key;
    } else {
      fields[key] = unquoteFrontmatterValue(value);
    }
  }
  return { ok: true, fields };
}

/** Normalise `allowed-tools` (string or list) to a string array. */
function normaliseAllowedTools(
  raw: unknown,
): { ok: true; tools: string[] } | { ok: false; error: string } {
  if (raw === undefined) return { ok: true, tools: [] };
  if (typeof raw === "string") {
    const parts = raw.split(",");
    if (parts.some((t) => !t.trim())) {
      return { ok: false, error: "frontmatter.allowed-tools entries must be non-empty" };
    }
    return { ok: true, tools: parts.map((t) => t.trim()) };
  }
  if (Array.isArray(raw)) {
    if (!raw.every((t) => typeof t === "string" && t.trim())) {
      return { ok: false, error: "frontmatter.allowed-tools entries must be non-empty strings" };
    }
    return { ok: true, tools: (raw as string[]).map((t) => t.trim()) };
  }
  return { ok: false, error: "frontmatter.allowed-tools must be a string or list" };
}

/**
 * Validate + normalise an Anthropic-shaped manifest object
 * (`format: "anthropic"`). Required: non-empty `name` + `description`.
 * `allowed_tools` / `allowed-tools` (string or list) normalises to
 * `allowed_tools: string[]`. v1-only fields default: version "1.0.0",
 * trigger = name, steps = single follow-skill-instructions pointer.
 * `instructions` (the Markdown body) must be a string when present.
 */
export function validateAnthropicManifest(
  m: Record<string, unknown>,
): { ok: true; manifest: SkillManifest } | { ok: false; error: string } {
  if (!isNonEmptyString(m.name)) return { ok: false, error: "manifest.name is required" };
  if (!isNonEmptyString(m.description)) return { ok: false, error: "manifest.description is required" };
  const toolsRaw = m.allowed_tools !== undefined ? m.allowed_tools : m["allowed-tools"];
  const tools = normaliseAllowedTools(toolsRaw);
  if (!tools.ok) return { ok: false, error: tools.error };
  if (m.instructions !== undefined && typeof m.instructions !== "string") {
    return { ok: false, error: "manifest.instructions must be a string" };
  }
  if (m.version !== undefined && !isNonEmptyString(m.version)) {
    return { ok: false, error: "manifest.version must be a non-empty string" };
  }
  if (m.trigger !== undefined && !isNonEmptyString(m.trigger)) {
    return { ok: false, error: "manifest.trigger must be a non-empty string" };
  }
  const steps =
    m.steps !== undefined
      ? m.steps
      : [{ action: "follow-skill-instructions" }];
  if (!Array.isArray(steps) || steps.length === 0) {
    return { ok: false, error: "manifest.steps must be a non-empty array" };
  }
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i] as Record<string, unknown> | null;
    if (!step || typeof step !== "object" || Array.isArray(step) || !isNonEmptyString(step.action)) {
      return { ok: false, error: `manifest.steps[${i}].action is required` };
    }
  }
  const manifest: SkillManifest = {
    ...(m as Record<string, unknown>),
    format: "anthropic",
    name: (m.name as string).trim(),
    version: isNonEmptyString(m.version) ? (m.version as string) : "1.0.0",
    trigger: isNonEmptyString(m.trigger) ? (m.trigger as string) : (m.name as string).trim(),
    steps: steps as Array<Record<string, unknown>>,
    description: (m.description as string).trim(),
    allowed_tools: tools.tools,
  } as SkillManifest;
  delete (manifest as Record<string, unknown>)["allowed-tools"];
  return { ok: true, manifest };
}

/**
 * Parse a full Anthropic SKILL.md document: `---` frontmatter block
 * (name/description/allowed-tools) + Markdown instruction body.
 * Malformed input (no frontmatter, missing name/description, empty
 * body, bad frontmatter line) is rejected with a field-named error.
 */
export function parseAnthropicSkillMd(
  md: string,
): { ok: true; manifest: SkillManifest } | { ok: false; error: string } {
  if (typeof md !== "string" || !md.trim()) {
    return { ok: false, error: "skill file is empty" };
  }
  const lines = md.replace(/\r\n/g, "\n").split("\n");
  let start = 0;
  while (start < lines.length && !lines[start].trim()) start++;
  if (lines[start]?.trim() !== "---") {
    return { ok: false, error: "skill file must start with frontmatter (---)" };
  }
  let end = -1;
  for (let i = start + 1; i < lines.length; i++) {
    if (lines[i].trim() === "---") {
      end = i;
      break;
    }
  }
  if (end === -1) return { ok: false, error: "skill file frontmatter is not closed (---)" };
  const parsed = parseSkillFrontmatter(lines.slice(start + 1, end).join("\n"));
  if (!parsed.ok) return { ok: false, error: parsed.error };
  const body = lines.slice(end + 1).join("\n").trim();
  if (!body) return { ok: false, error: "skill file body is required" };
  return validateAnthropicManifest({ ...parsed.fields, format: "anthropic", instructions: body });
}

/** Server-generated skill id: `skl-` + 16 hex (browser taskId pattern). */
export function newSkillId(): string {
  return `skl-${randomNonceHex(8)}`;
}

// --- Self-extension (DESIGN §6.2, §8.2) — server-side mirror ---
//
// The phone is the researcher; the server never trusts the phone's
// classification. `validateResearchCandidate` checks the §3.2 candidate
// shape, `classifySkillClass` re-derives AUTO / APPROVAL / REJECT from
// the deterministic §3.4 signals carried on the manifest, and the
// submit strip-check enforces the template-only rule (§5.4) for
// `origin="self_extended"` submissions. Classification is echoed for
// the audit trail only — submit ALWAYS lands quarantined (frozen rule
// above); there is no auto-approve path anywhere in this file. A
// submission claiming AUTO with a forbidden signal is still
// quarantined, and the mismatch is visible in the classification echo
// + the skill_submit trace.
//
// Scan honesty: the authoritative scan is Render /doc/scan, and
// RENDER_WORKER_URL is unset live, so review-time approve of a CODE
// skill 503s `scan_unavailable` (existing S-T8 behaviour, unchanged).
// Scan-unavailable NEVER auto-approves; it stays quarantined.

/** Licence allowlist (§3.4): auto-eligible SPDX ids. */
export const SELF_EXT_LICENSE_ALLOWLIST = [
  "MIT",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "MPL-2.0",
  "CC0-1.0",
  "Unlicense",
  "Zlib",
] as const;

/** Copyleft licences (§3.4): APPROVAL-only, never auto. */
export const SELF_EXT_LICENSE_COPYLEFT = [
  "GPL-2.0",
  "GPL-3.0",
  "LGPL-2.1",
  "LGPL-3.0",
  "AGPL-3.0",
  "EPL-2.0",
] as const;

/** Closed-source / proprietary licence spellings: REJECT (C2). */
export const SELF_EXT_LICENSE_CLOSED = [
  "proprietary",
  "commercial",
  "closed-source",
  "closed_source",
  "free for personal use",
  "free-for-personal-use",
] as const;

/** Executor actions a STEP skill may use (§5.1 frozen KNOWN_ACTIONS). */
export const SELF_EXT_KNOWN_ACTIONS = [
  "OPEN_APP",
  "TAP_NODE",
  "TYPE_TEXT",
  "SCROLL",
  "NAVIGATE",
  "YOUTUBE_SEARCH",
  "YOUTUBE_PLAY",
  "MEDIA_CONTROL",
  "FLASHLIGHT",
  "VOLUME",
  "SET_ALARM",
  "WAIT",
  "SAVE_MEMORY",
  "CREATE_PROJECT",
  "WRITE_PROJECT_FILE",
  "BUILD",
  "GITHUB_PUSH",
  "SUPABASE_TABLES",
  "VERCEL_DEPLOY",
  "HTTP_CHECK",
] as const;

/** Actions that call a third-party service (§8.2 C6). */
export const SELF_EXT_NETWORK_ACTIONS = [
  "OPEN_URL",
  "YOUTUBE_SEARCH",
  "YOUTUBE_PLAY",
  "HTTP_CHECK",
] as const;

/** Max steps per STEP skill (§8 S7). */
export const SELF_EXT_MAX_STEPS = 20;

/** Max published artifact size for a CODE proposal (§3.4): 10 MB. */
export const SELF_EXT_MAX_ARTIFACT_BYTES = 10 * 1024 * 1024;

/** Maintenance is stale past this age (§3.4): 24 months. */
export const SELF_EXT_STALE_MS = 24 * 30 * 24 * 60 * 60 * 1000;

/** Allowlisted research hosts (§3.3). Exact hosts, plus *.apache.org / *.gnu.org. */
const SELF_EXT_ALLOWED_HOSTS = new Set([
  "github.com",
  "raw.githubusercontent.com",
  "gitlab.com",
  "opensource.org",
  "spdx.org",
  "repo.maven.apache.org",
  "plugins.gradle.org",
  "dl.google.com",
]);

function isAllowlistedResearchUrl(value: unknown): value is string {
  if (typeof value !== "string" || !value.trim()) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  const host = url.hostname.toLowerCase();
  if (SELF_EXT_ALLOWED_HOSTS.has(host)) return true;
  return host.endsWith(".apache.org") || host.endsWith(".gnu.org");
}

export interface ResearchCandidate {
  name: string;
  sourceUrl: string;
  licence: string;
  licenceUrl?: string | null;
  costUsd: string;
  needsCard: boolean;
  needsAccount: boolean;
  needsNetwork: boolean;
  kind: "STEP" | "CODE";
  sources?: string[];
  evidence?: string[];
  lastUpdated?: string | null;
  sizeBytes?: number | null;
  hostRequirements?: string[];
  stale?: boolean;
  code?: string;
  [key: string]: unknown;
}

/**
 * Validate a §3.2 research candidate. Returns the typed candidate on
 * success; on failure the FIRST violated rule (field name only — never
 * candidate content, never logged). Licence must be a known SPDX id
 * (allowlist ∪ copyleft) or "UNKNOWN": anything else is not an SPDX id
 * for our purposes and is rejected here rather than classified later.
 */
export function validateResearchCandidate(
  input: unknown,
): { ok: true; candidate: ResearchCandidate } | { ok: false; error: string } {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, error: "candidate must be an object" };
  }
  const c = input as Record<string, unknown>;
  if (!isNonEmptyString(c.name)) return { ok: false, error: "candidate.name is required" };
  if (!isAllowlistedResearchUrl(c.sourceUrl)) {
    return { ok: false, error: "candidate.sourceUrl must be an allowlisted URL" };
  }
  if (
    c.licenceUrl !== undefined &&
    c.licenceUrl !== null &&
    !isAllowlistedResearchUrl(c.licenceUrl)
  ) {
    return { ok: false, error: "candidate.licenceUrl must be an allowlisted URL" };
  }
  if (typeof c.licence !== "string" || !c.licence.trim()) {
    return { ok: false, error: "candidate.licence is required" };
  }
  const licence = c.licence.trim();
  if (
    licence !== "UNKNOWN" &&
    !(SELF_EXT_LICENSE_ALLOWLIST as readonly string[]).includes(licence) &&
    !(SELF_EXT_LICENSE_COPYLEFT as readonly string[]).includes(licence)
  ) {
    return { ok: false, error: "candidate.licence must be an SPDX id or UNKNOWN" };
  }
  if (!isNonEmptyString(c.costUsd)) return { ok: false, error: "candidate.costUsd is required" };
  if (typeof c.needsCard !== "boolean") return { ok: false, error: "candidate.needsCard must be a boolean" };
  if (typeof c.needsAccount !== "boolean") {
    return { ok: false, error: "candidate.needsAccount must be a boolean" };
  }
  if (typeof c.needsNetwork !== "boolean") {
    return { ok: false, error: "candidate.needsNetwork must be a boolean" };
  }
  if (c.kind !== "STEP" && c.kind !== "CODE") {
    return { ok: false, error: "candidate.kind must be STEP or CODE" };
  }
  if (c.sources !== undefined) {
    if (!Array.isArray(c.sources) || c.sources.length > 5) {
      return { ok: false, error: "candidate.sources must be an array of at most 5 URLs" };
    }
    for (const s of c.sources) {
      if (!isAllowlistedResearchUrl(s)) {
        return { ok: false, error: "candidate.sources must be allowlisted URLs" };
      }
    }
  }
  if (c.evidence !== undefined) {
    if (
      !Array.isArray(c.evidence) ||
      c.evidence.length > 5 ||
      c.evidence.some((e) => typeof e !== "string" || e.length > 200)
    ) {
      return { ok: false, error: "candidate.evidence must be at most 5 strings of at most 200 chars" };
    }
  }
  if (
    c.lastUpdated !== undefined &&
    c.lastUpdated !== null &&
    typeof c.lastUpdated !== "string"
  ) {
    return { ok: false, error: "candidate.lastUpdated must be a string or null" };
  }
  if (
    c.sizeBytes !== undefined &&
    c.sizeBytes !== null &&
    (typeof c.sizeBytes !== "number" || !Number.isFinite(c.sizeBytes) || c.sizeBytes < 0)
  ) {
    return { ok: false, error: "candidate.sizeBytes must be a non-negative number" };
  }
  if (
    c.hostRequirements !== undefined &&
    (!Array.isArray(c.hostRequirements) || c.hostRequirements.some((h) => typeof h !== "string"))
  ) {
    return { ok: false, error: "candidate.hostRequirements must be an array of strings" };
  }
  if (c.stale !== undefined && typeof c.stale !== "boolean") {
    return { ok: false, error: "candidate.stale must be a boolean" };
  }
  if (c.code !== undefined && typeof c.code !== "string") {
    return { ok: false, error: "candidate.code must be a string" };
  }
  if (
    typeof c.code === "string" &&
    new TextEncoder().encode(c.code).byteLength > MAX_SKILL_CODE_BYTES
  ) {
    return { ok: false, error: "candidate.code exceeds 512 KB" };
  }
  return { ok: true, candidate: input as ResearchCandidate };
}

// --- Server-side classification mirror (§8.2) ---

export type SkillClass = "AUTO" | "APPROVAL" | "REJECT";

export interface SkillClassification {
  classification: SkillClass;
  reason: string;
  kind: "STEP" | "CODE";
}

const CREDENTIAL_RE =
  /api[_-]?key|password|\botp\b|\btoken\b|secret|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/i;
const CONFIRMATION_TARGET_RE =
  /\b(send|pay|buy|purchase|checkout|delete|remove|confirm order|place order)\b/i;
/** Malicious-pattern pre-scan families (§6.1), in first-hit order. */
const SCAN_PATTERNS: Array<{ re: RegExp; pattern: string }> = [
  { re: /eval\s*\(/, pattern: "eval(" },
  { re: /exec\s*\(/, pattern: "exec(" },
  { re: /os\.system/, pattern: "os.system" },
  { re: /subprocess/, pattern: "subprocess" },
  { re: /requests\.post/, pattern: "requests.post" },
  { re: /child_process/, pattern: "child_process" },
  { re: /DexClassLoader/, pattern: "DexClassLoader" },
  { re: /Runtime\.exec/, pattern: "Runtime.exec" },
  { re: /api[_-]?key\s*=/i, pattern: "credential_assignment" },
  { re: /password\s*=/i, pattern: "credential_assignment" },
  { re: /token\s*=\s*["']/, pattern: "credential_assignment" },
];

function stepText(step: Record<string, unknown>): string {
  return [step.action, step.target, step.input, step.text]
    .filter((v) => typeof v === "string")
    .join(" ");
}

function scanHit(steps: Array<Record<string, unknown>>, code?: string): string | null {
  const haystacks = steps.map(stepText);
  if (typeof code === "string" && code) haystacks.push(code);
  for (const { re, pattern } of SCAN_PATTERNS) {
    if (haystacks.some((h) => re.test(h))) return pattern;
  }
  return null;
}

function isStale(lastUpdated: unknown, staleFlag: unknown): boolean {
  if (staleFlag === true) return true;
  if (typeof lastUpdated !== "string" || !lastUpdated.trim()) return false;
  const ms = Date.parse(lastUpdated);
  if (Number.isNaN(ms)) return false;
  return Date.now() - ms > SELF_EXT_STALE_MS;
}

/**
 * Server-side mirror of the app CapabilityClassifier decision table
 * (§8.2). First match wins; a REJECT is never downgraded by a later
 * row. Signals come from the manifest's `researchCandidate` / `candidate`
 * extra keys and its `provenance` (§5.3), plus the step list — never
 * from the phone's own claimed classification.
 *
 * Two deliberate readings of the design text, both fail-closed:
 * - C9 as written ("stale AND lastUpdated == null") can never fire
 *   (a null date has no age); it is read as stale (date > 24 months)
 *   OR maintenance unknowable (lastUpdated null) → APPROVAL.
 * - C2 (closed-source) is checked before C1 so a proprietary licence
 *   reports `closed_source` rather than `unknown_licence`; both REJECT.
 *
 * A manifest with no research metadata at all is NOT an error — it is
 * an ordinary learned-skill submission, which this mirror cannot call
 * AUTO: APPROVAL `no_research_metadata` (fail-closed, never AUTO).
 */
export function classifySkillClass(manifest: SkillManifest): SkillClassification {
  const m = manifest as unknown as Record<string, unknown>;
  const candRaw = m.researchCandidate ?? m.candidate;
  const cand =
    candRaw && typeof candRaw === "object" && !Array.isArray(candRaw)
      ? (candRaw as Record<string, unknown>)
      : {};
  const provRaw = m.provenance;
  const prov =
    provRaw && typeof provRaw === "object" && !Array.isArray(provRaw)
      ? (provRaw as Record<string, unknown>)
      : {};
  const hasResearch = Object.keys(cand).length > 0 || Object.keys(prov).length > 0;
  const isSelfExtended = m.origin === "self_extended";
  if (!hasResearch && !isSelfExtended) {
    return { classification: "APPROVAL", reason: "no_research_metadata", kind: "STEP" };
  }

  const licence =
    typeof cand.licence === "string"
      ? cand.licence
      : typeof prov.licence === "string"
        ? prov.licence
        : undefined;
  const costUsd =
    typeof cand.costUsd === "string"
      ? cand.costUsd
      : typeof prov.costUsd === "string"
        ? prov.costUsd
        : undefined;
  const needsCard = cand.needsCard === true;
  const needsAccount = cand.needsAccount === true;
  const needsNetwork = cand.needsNetwork === true;
  const lastUpdated = cand.lastUpdated ?? null;
  const sizeBytes = typeof cand.sizeBytes === "number" ? cand.sizeBytes : null;
  const steps = Array.isArray(m.steps) ? (m.steps as Array<Record<string, unknown>>) : [];
  const code = typeof m.code === "string" ? m.code : undefined;

  // C2 then C1: closed-source / unknown licence → REJECT.
  if (typeof licence === "string" && (SELF_EXT_LICENSE_CLOSED as readonly string[]).includes(licence)) {
    return { classification: "REJECT", reason: "closed_source", kind: "STEP" };
  }
  if (
    licence === undefined ||
    licence === "UNKNOWN" ||
    (!(SELF_EXT_LICENSE_ALLOWLIST as readonly string[]).includes(licence) &&
      !(SELF_EXT_LICENSE_COPYLEFT as readonly string[]).includes(licence))
  ) {
    return { classification: "REJECT", reason: "unknown_licence", kind: "STEP" };
  }
  const isCopyleft = (SELF_EXT_LICENSE_COPYLEFT as readonly string[]).includes(licence);
  const isAllowlisted = (SELF_EXT_LICENSE_ALLOWLIST as readonly string[]).includes(licence);

  // C3: paid / card-required → REJECT.
  if ((costUsd !== undefined && costUsd !== "$0") || needsCard) {
    return { classification: "REJECT", reason: "paid_or_card_required", kind: "STEP" };
  }

  // C4: unknown action, explicit CODE kind, or code present → CODE path.
  const knownActions = new Set<string>(SELF_EXT_KNOWN_ACTIONS);
  const hasUnknownAction = steps.some(
    (s) => typeof s.action !== "string" || !knownActions.has(s.action),
  );
  let kind: "STEP" | "CODE" =
    cand.kind === "CODE" || code !== undefined || hasUnknownAction ? "CODE" : "STEP";

  // Incomplete research signals: the server cannot verify AUTO without
  // them — fail-closed to APPROVAL (C14 spirit), never REJECT, never AUTO.
  const signalsComplete =
    typeof cand.needsCard === "boolean" &&
    typeof cand.needsAccount === "boolean" &&
    typeof cand.needsNetwork === "boolean" &&
    costUsd !== undefined;
  if (!signalsComplete) {
    return { classification: "APPROVAL", reason: "incomplete_research_signals", kind };
  }

  // C5: account / credential signals → APPROVAL.
  const credentialStep = steps.some((s) => {
    const target = typeof s.target === "string" ? s.target : "";
    const input = typeof s.input === "string" ? s.input : "";
    return CREDENTIAL_RE.test(target) || CREDENTIAL_RE.test(input);
  });
  if (needsAccount || credentialStep) {
    return { classification: "APPROVAL", reason: "needs_account_or_credential", kind };
  }

  // C6: network / exfil risk → APPROVAL.
  const networkStep = steps.some(
    (s) =>
      typeof s.action === "string" &&
      (SELF_EXT_NETWORK_ACTIONS as readonly string[]).includes(s.action),
  );
  if (needsNetwork || networkStep) {
    return { classification: "APPROVAL", reason: "network_or_exfil_risk", kind };
  }

  // C7: sensitive (send/pay/buy/delete) action → APPROVAL.
  const sensitiveStep = steps.some((s) => {
    const action = typeof s.action === "string" ? s.action.toUpperCase() : "";
    if (/(SEND|PAY|PURCHASE|BUY|DELETE)/.test(action)) return true;
    if (action === "TAP_NODE" && typeof s.target === "string") {
      return CONFIRMATION_TARGET_RE.test(s.target);
    }
    return false;
  });
  if (sensitiveStep) {
    return { classification: "APPROVAL", reason: "sensitive_action", kind };
  }

  // C8: copyleft → APPROVAL.
  if (isCopyleft) {
    return { classification: "APPROVAL", reason: "copyleft_needs_review", kind };
  }

  // C9: stale or maintenance unknowable → APPROVAL.
  if (lastUpdated === null || isStale(lastUpdated, cand.stale)) {
    return { classification: "APPROVAL", reason: "unmaintained_unknown", kind };
  }

  // C10: size over budget → REJECT for STEP, APPROVAL for CODE.
  const codeBytes = code !== undefined ? new TextEncoder().encode(code).byteLength : 0;
  if (kind === "STEP" && (steps.length > SELF_EXT_MAX_STEPS || codeBytes > MAX_SKILL_CODE_BYTES)) {
    return { classification: "REJECT", reason: "oversize", kind };
  }
  if (kind === "CODE" && sizeBytes !== null && sizeBytes > SELF_EXT_MAX_ARTIFACT_BYTES) {
    return { classification: "APPROVAL", reason: "oversize", kind };
  }

  // C11: pre-scan hit → REJECT.
  const hit = scanHit(steps, code);
  if (hit) {
    return { classification: "REJECT", reason: `scan_hit:${hit}`, kind };
  }

  // C12: clean local STEP → AUTO.
  if (kind === "STEP" && isAllowlisted && costUsd === "$0") {
    return { classification: "AUTO", reason: "clean_local_step", kind };
  }

  // C13: CODE with no REJECT row hit → APPROVAL.
  if (kind === "CODE") {
    return { classification: "APPROVAL", reason: "code_needs_review", kind };
  }

  // C14: anything not matched → APPROVAL (fail-closed).
  return { classification: "APPROVAL", reason: "unclassified", kind };
}

/**
 * Template-only strip-check (§5.4 / §6.2): a self-added skill template
 * may carry step ACTION names only — never targets, inputs, or trigger
 * text. Returns true when an `origin="self_extended"` manifest carries
 * non-empty `target`/`input` fields on any step (user content).
 * Learned-skill submissions are untouched (the check keys on `origin`).
 * NOTE: trigger text is not checked here — the frozen manifest schema
 * requires a non-empty trigger, so the server cannot distinguish a
 * generic trigger from user trigger text; the app submitter must send a
 * generic trigger (see report).
 */
export function selfExtendedTemplateHasUserContent(manifest: SkillManifest): boolean {
  const m = manifest as unknown as Record<string, unknown>;
  if (m.origin !== "self_extended") return false;
  if (!Array.isArray(m.steps)) return false;
  return (m.steps as Array<Record<string, unknown>>).some((step) => {
    if (!step || typeof step !== "object") return false;
    const target = typeof step.target === "string" ? step.target.trim() : "";
    const input = typeof step.input === "string" ? step.input.trim() : "";
    return target.length > 0 || input.length > 0;
  });
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

/**
 * U13 — approved skills created after `sinceMs` (0 = all), oldest first.
 * The phone syncs this list after an approval push so a newly approved
 * skill lands on-device without re-pulling the whole library.
 */
export async function listApprovedSkillsSince(db: D1Like, sinceMs: number): Promise<SkillRow[]> {
  const res = await db
    .prepare(
      "SELECT id, manifest, status, submitted_by, created_at FROM global_skills " +
        "WHERE status = ? AND created_at > ? ORDER BY created_at ASC",
    )
    .bind("approved", sinceMs)
    .all<SkillRow>();
  return res.results ?? [];
}

/**
 * U13 — active submissions by one tenant (quarantined + approved).
 * Rejected skills do not count: a rejected submitter may try again.
 * JS-filtered on status (the metering.ts precedent) so the count stays
 * exact without an IN-literal in the query.
 */
export async function countActiveSkillsByTenant(db: D1Like, tenantId: string): Promise<number> {
  const res = await db
    .prepare("SELECT id, status FROM global_skills WHERE submitted_by = ?")
    .bind(tenantId)
    .all<{ id: string; status: string }>();
  return (res.results ?? []).filter(
    (r) => r.status === "quarantined" || r.status === "approved",
  ).length;
}

export async function setSkillStatus(db: D1Like, skillId: string, status: string): Promise<void> {
  await db.prepare("UPDATE global_skills SET status = ? WHERE id = ?").bind(status, skillId).run();
}

/**
 * R4.11 (U8-SERVER) — device-signed "user approved" signal.
 *
 * The phone's approval card records an approval; this persists the
 * signal server-side as a skill_reviews row (reviewer = device id,
 * decision = "user_approved"). It does NOT change the skill status:
 * the frozen quarantine rule stands — a skill leaves `quarantined`
 * only via /api/skills/review (clean Render scan + admin approval).
 * The admin review queue can read the user_approved signal and the
 * phone can pull the outcome via /api/skills/sync after review.
 * Idempotent: the same device approving the same skill twice writes
 * one row and reports deduped:true.
 */
export async function recordUserApproval(
  db: D1Like,
  opts: { skillId: string; tenantId: string; deviceId: string; nowMs?: number },
): Promise<{ deduped: boolean }> {
  const existing = await db
    .prepare("SELECT id FROM skill_reviews WHERE skill_id = ? AND reviewer = ? AND decision = ?")
    .bind(opts.skillId, opts.deviceId, "user_approved")
    .first<{ id: number | string }>();
  if (existing) return { deduped: true };
  const nowMs = opts.nowMs ?? Date.now();
  const id = `ur-${nowMs.toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  await db
    .prepare("INSERT INTO skill_reviews (id, skill_id, reviewer, decision, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(id, opts.skillId, opts.deviceId, "user_approved", "phone approval card", nowMs)
    .run();
  return { deduped: false };
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
