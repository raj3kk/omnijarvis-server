/**
 * Main Executor v1 (R1, hybrid core) — the server-side global executor.
 *
 * Shape (from the parity spec + MECHANISM_PLAN + DESIGN_MINI_SWE_LOOP):
 * mini-swe-agent loop pattern (MIT) + Aider's 4 mechanisms (Apache-2.0):
 * repo-map (line-based v1 first), architect/editor split, auto-commit
 * per change, lint+test loop (max 3 reflections — here: max 2 retries
 * per step, then the proposal ships labelled needs-work).
 *
 * Runner: Workers step-runner — one step per invocation, state in D1
 * `main_jobs` (never in Worker memory). The hub cron tick steps pending
 * jobs (max 2 per tick); the admin can also step a job via
 * POST /api/main/step. A job never merges anything: it opens a PR with
 * an evidence bundle, and only the user merges.
 *
 * What the GitHub token is FOR (user question 2026-11-23 ~13:00 IST):
 * WITH GITHUB_ADMIN_TOKEN set, Main uses the GitHub API to read repo
 * code (trees/blobs/contents), create branches, commit + push fixes,
 * open PRs, poll CI check-runs, read failing-check output, and send the
 * update notice (FCM). That IS the self-development loop (research →
 * patch → scan → CI → PR). WITHOUT the token, Main runs PROPOSE-ONLY /
 * dry-run: it researches (public-repo reads are unauthenticated but
 * rate-limited), drafts patches, prepares PR bodies + evidence bundles
 * and queues them — but it CANNOT push, cannot open PRs, and cannot do
 * authenticated reads/writes. The loop goes live the moment the token
 * is set as a Worker secret, no rebuild.
 *
 * Budgets (N3 carve-out, R1 defaults — FLAGGED: these numbers need the
 * user's word; the code enforces the defaults until then):
 * - 10 steps/job default, 20 hard (a `partial` job resumes to 20 only
 *   via an explicit admin /api/main/step {resume:true}).
 * - 40 LLM calls/job. 2 retries per step. 5 jobs/tenant/day.
 * The hub router's 5-calls/turn + replies/mo caps do NOT apply to kind
 * main_executor (router.ts carve-out) — the job budget above is the cap
 * instead, and every Main call is still metered (llm_usage rows).
 */
import { getTenant, insertTrace, type D1Like } from "./db";
import { loadRouterConfig, routeLlm } from "./router";
import {
  createBranch,
  createCommitOnBranch,
  createPullRequest,
  getBranchHead,
  getCheckSummary,
  getFileContent,
  isGitHubConfigured,
  isValidRepoSlug,
  isWriteRepo,
  listTree,
  parseRepoSlug,
  type GitHubEnv,
} from "./github";
import { scanSkillCode } from "./skills";
import type { RenderEnv } from "./docs";
import { sendFcm } from "./fcm";

export const MAIN_MAX_STEPS = 10;
export const MAIN_MAX_STEPS_HARD = 20;
export const MAIN_MAX_CALLS_PER_JOB = 40;
export const MAIN_MAX_RETRIES_PER_STEP = 2;
export const MAIN_MAX_JOBS_PER_TENANT_PER_DAY = 5;
export const MAIN_REPO_MAP_CHAR_CAP = 16_000; // ~4,000 tokens
export const MAIN_EDIT_MAX_BYTES = 64 * 1024;
export const MAIN_ASK_MAX_CHARS = 2000;
export const MAIN_SNAPSHOT_MAX_FILES = 20;
export const MAIN_SNAPSHOT_MAX_BYTES = 256 * 1024;
export const MAIN_INLINE_STEPS_PER_RUN = 3;
export const MAIN_RETRY_BACKOFF_MS = 10 * 60_000;

export interface MainEnv extends GitHubEnv, RenderEnv {
  DB: D1Like;
  KEY_ENC_SECRET?: string;
  FOUNDER_GEMINI_KEY?: string;
  FOUNDER_GROQ_KEY?: string;
  ROUTER_CONFIG?: string;
  FIREBASE_SERVICE_ACCOUNT_JSON?: string;
  nowMs?: () => number;
  idFn?: () => string;
}

export type MainJobStatus =
  | "received"
  | "planned"
  | "editing"
  | "validating"
  | "pr_open"
  | "pr_open_needs_work"
  | "parked"
  | "partial"
  | "done"
  | "failed"
  | "blocked_token";

export interface MainPlanStep {
  id: string;
  title: string;
  file: string;
  action: string;
}

export interface MainPlan {
  steps: MainPlanStep[];
  done: string[];
}

export interface TranscriptEntry {
  at: number;
  phase: string;
  note: string;
  model?: string;
  input_tokens?: number;
  output_tokens?: number;
  ms?: number;
  ok?: boolean;
  files?: { path: string; content: string }[];
  patch?: { path: string; content: string };
}

export interface MainJob {
  id: string;
  tenant_id: string;
  device_id: string | null;
  ask: string;
  repo: string;
  base_branch: string;
  branch: string | null;
  status: MainJobStatus;
  mode: "github" | "dry-run";
  plan: string | null;
  transcript: string;
  pr_url: string | null;
  pr_number: number | null;
  ci_status: string | null;
  scan_verdict: string | null;
  llm_calls: number;
  steps_used: number;
  retries_used: number;
  error: string | null;
  error_code: string | null;
  created_at: number;
  updated_at: number;
}

export type MainJobResult =
  | { ok: true; job: MainJob; note?: string }
  | { ok: false; error: string; retryable?: boolean; detail?: string };

// --- D1 helpers ---

function newJobId(env: MainEnv): string {
  if (env.idFn) return env.idFn();
  return `main-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function now(env: MainEnv): number {
  return env.nowMs ? env.nowMs() : Date.now();
}

export function parseTranscript(job: MainJob): TranscriptEntry[] {
  try {
    const arr = JSON.parse(job.transcript) as TranscriptEntry[];
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

export function parsePlan(job: MainJob): MainPlan | null {
  if (!job.plan) return null;
  try {
    const p = JSON.parse(job.plan) as MainPlan;
    if (!p || !Array.isArray(p.steps)) return null;
    return { steps: p.steps, done: Array.isArray(p.done) ? p.done : [] };
  } catch {
    return null;
  }
}

export async function getMainJob(db: D1Like, jobId: string): Promise<MainJob | null> {
  return await db
    .prepare("SELECT * FROM main_jobs WHERE id = ?")
    .bind(jobId)
    .first<MainJob>();
}

export async function listPendingMainJobs(db: D1Like, limit = 2): Promise<MainJob[]> {
  // Filtered in JS: FakeD1 has no IN (same precedent as
  // metering.countTurnCalls). Live D1 would take an IN list.
  const res = await db
    .prepare("SELECT * FROM main_jobs ORDER BY created_at ASC LIMIT 10")
    .all<MainJob>();
  const steppable: MainJobStatus[] = ["received", "planned", "editing", "validating", "blocked_token"];
  return (res.results ?? []).filter((j) => steppable.includes(j.status)).slice(0, limit);
}

export async function updateMainJob(
  db: D1Like,
  jobId: string,
  patch: Partial<Pick<MainJob, "status" | "mode" | "plan" | "transcript" | "branch" | "pr_url" | "pr_number" | "ci_status" | "scan_verdict" | "llm_calls" | "steps_used" | "retries_used" | "error" | "error_code">>,
  nowMs?: number,
): Promise<void> {
  const sets: string[] = ["updated_at = ?"];
  const values: unknown[] = [nowMs ?? Date.now()];
  for (const [k, v] of Object.entries(patch)) {
    sets.push(`${k} = ?`);
    values.push(v);
  }
  await db
    .prepare(`UPDATE main_jobs SET ${sets.join(", ")} WHERE id = ?`)
    .bind(...values, jobId)
    .run();
}

export async function appendTranscript(
  db: D1Like,
  job: MainJob,
  entry: Omit<TranscriptEntry, "at"> & { at?: number },
): Promise<void> {
  const entries = parseTranscript(job);
  entries.push({ at: entry.at ?? Date.now(), ...entry });
  // Transcript is the audit trail — cap at 200 entries so one job can
  // never grow the row without bound (oldest entries drop first).
  const capped = entries.slice(-200);
  await updateMainJob(db, job.id, { transcript: JSON.stringify(capped) });
  job.transcript = JSON.stringify(capped);
}

export async function countJobsToday(db: D1Like, tenantId: string, nowMs = Date.now()): Promise<number> {
  const dayStart = nowMs - (nowMs % 86_400_000);
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM main_jobs WHERE tenant_id = ? AND created_at >= ?")
    .bind(tenantId, dayStart)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

// --- Job creation ---

export const FORBIDDEN_PATHS = [
  ".secrets/",
  "secrets/",
  ".env",
  ".pem",
  ".key",
  ".keystore",
  ".jks",
  "google-services.json",
  "credentials",
  "signing",
];

export function isForbiddenPath(path: string): boolean {
  const lower = path.toLowerCase();
  return FORBIDDEN_PATHS.some((f) => lower.includes(f));
}

const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "github_pat", re: /ghp_[A-Za-z0-9]{20,}/ },
  { name: "groq_key", re: /gsk_[A-Za-z0-9]{20,}/ },
  { name: "google_api_key", re: /AIza[0-9A-Za-z_-]{20,}/ },
  { name: "stripe_live_key", re: /sk-live-[A-Za-z0-9]{10,}/ },
  { name: "slack_token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: "hf_token", re: /hf_[A-Za-z0-9]{20,}/ },
  { name: "private_key", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
];

export interface SnapshotFile {
  path: string;
  content: string;
}

export async function createMainJob(
  env: MainEnv,
  input: {
    tenantId: string;
    deviceId?: string;
    ask: string;
    repo: string;
    baseBranch?: string;
    snapshotFiles?: SnapshotFile[];
  },
): Promise<MainJobResult> {
  const ask = (input.ask ?? "").trim();
  if (!ask || ask.length > MAIN_ASK_MAX_CHARS) {
    return { ok: false, error: "bad_request", detail: "ask 1..2000 chars chahiye" };
  }
  if (!isValidRepoSlug(input.repo)) {
    return { ok: false, error: "invalid_repo", detail: "repo owner/name shape me chahiye" };
  }
  const tenant = await getTenant(env.DB, input.tenantId);
  if (!tenant) return { ok: false, error: "tenant_not_found" };
  const today = await countJobsToday(env.DB, input.tenantId, now(env));
  if (today >= MAIN_MAX_JOBS_PER_TENANT_PER_DAY) {
    return { ok: false, error: "daily_job_cap", detail: `Aaj ke ${MAIN_MAX_JOBS_PER_TENANT_PER_DAY} Main jobs ho chuke` };
  }
  const snapshot = input.snapshotFiles ?? [];
  if (snapshot.length > MAIN_SNAPSHOT_MAX_FILES) {
    return { ok: false, error: "bad_request", detail: `snapshot max ${MAIN_SNAPSHOT_MAX_FILES} files` };
  }
  let snapshotBytes = 0;
  for (const f of snapshot) {
    if (typeof f.path !== "string" || typeof f.content !== "string") {
      return { ok: false, error: "bad_request", detail: "snapshot file me path + content chahiye" };
    }
    if (isForbiddenPath(f.path)) {
      return { ok: false, error: "forbidden_path", detail: `snapshot me forbidden path: ${f.path}` };
    }
    snapshotBytes += f.content.length;
    if (f.content.length > MAIN_EDIT_MAX_BYTES) {
      return { ok: false, error: "bad_request", detail: `snapshot file too large: ${f.path}` };
    }
  }
  if (snapshotBytes > MAIN_SNAPSHOT_MAX_BYTES) {
    return { ok: false, error: "bad_request", detail: "snapshot total 256 KB se zyada" };
  }
  const id = newJobId(env);
  const createdAt = now(env);
  const mode = isGitHubConfigured(env) ? "github" : "dry-run";
  const transcript: TranscriptEntry[] = [
    {
      at: createdAt,
      phase: "created",
      note: `Job created (${mode} mode — ${mode === "dry-run" ? "GitHub token not set; patch will be authored + scanned, PR waits for the token" : "GitHub token set; full loop"})`,
      ...(snapshot.length > 0 ? { files: snapshot } : {}),
    },
  ];
  await env.DB.prepare(
    "INSERT INTO main_jobs (id, tenant_id, device_id, ask, repo, base_branch, branch, status, mode, plan, transcript, pr_url, pr_number, ci_status, scan_verdict, llm_calls, steps_used, retries_used, error, error_code, created_at, updated_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, NULL, 'received', ?, NULL, ?, NULL, NULL, NULL, NULL, 0, 0, 0, NULL, NULL, ?, ?)",
  )
    .bind(id, input.tenantId, input.deviceId ?? null, ask, input.repo, input.baseBranch ?? "main", mode, JSON.stringify(transcript), createdAt, createdAt)
    .run();
  const job = await getMainJob(env.DB, id);
  if (!job) return { ok: false, error: "api_error", detail: "job insert ke baad read nahi hua" };
  return { ok: true, job };
}

// --- Repo map (line-based v1; tree-sitter WASM is the follow-on) ---

const CODE_EXTS = [".kt", ".java", ".ts", ".tsx", ".js", ".jsx", ".py", ".md", ".json", ".yml", ".yaml", ".toml", ".sql", ".gradle", ".xml"];
const SKIP_DIRS = ["node_modules/", "build/", "dist/", ".gradle/", ".git/", "assets/", "Pods/"];
const SKIP_SUFFIXES = [".lock", ".apk", ".aab", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4", ".so", ".dex"];

function isMappableFile(path: string): boolean {
  if (SKIP_DIRS.some((d) => path.includes(d))) return false;
  if (SKIP_SUFFIXES.some((s) => path.toLowerCase().endsWith(s))) return false;
  return CODE_EXTS.some((e) => path.toLowerCase().endsWith(e));
}

function extractSymbols(path: string, content: string): string[] {
  const lines = content.split("\n");
  const out: string[] = [];
  const push = (s: string) => {
    if (out.length < 20 && s) out.push(s);
  };
  for (const line of lines) {
    const t = line.trim();
    if (path.endsWith(".kt") || path.endsWith(".java")) {
      const m = /^(?:public |private |internal |protected )*(?:class|object|interface|fun|val|var)\s+([A-Za-z0-9_<>]+)/.exec(t);
      if (m) push(`${t.startsWith("fun") || t.includes(" fun ") ? "fun" : "type"} ${m[1]}`);
    } else if (/\.(ts|tsx|js|jsx)$/.test(path)) {
      const m = /^(?:export )?(?:async )?(?:function|class|const|interface|type)\s+([A-Za-z0-9_]+)/.exec(t);
      if (m) push(`${m[1]}`);
    } else if (path.endsWith(".py")) {
      const m = /^(?:def|class)\s+([A-Za-z0-9_]+)/.exec(t);
      if (m) push(`${m[1]}`);
    } else if (path.endsWith(".md")) {
      const m = /^#{1,3}\s+(.+)$/.exec(t);
      if (m) push(`# ${m[1].slice(0, 60)}`);
    }
  }
  return out;
}

export interface RepoMapResult {
  map: string;
  files: number;
  symbols: number;
  truncated: boolean;
}

export async function buildRepoMap(
  env: MainEnv,
  owner: string,
  repo: string,
  ref: string,
  ask: string,
  snapshotFiles?: SnapshotFile[],
): Promise<{ ok: true; data: RepoMapResult } | { ok: false; error: string; retryable?: boolean; detail?: string }> {
  const keywords = ask
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length >= 3);
  const rank = (path: string): number => {
    const lower = path.toLowerCase();
    let score = 0;
    for (const k of keywords) if (lower.includes(k)) score += 10;
    // Small files first for map density (after keyword matches).
    return score;
  };

  let entries: { path: string; size?: number; content?: string }[] = [];
  if (snapshotFiles) {
    entries = snapshotFiles.map((f) => ({ path: f.path, size: f.content.length, content: f.content }));
  } else {
    const tree = await listTree(env, owner, repo, ref);
    if (!tree.ok) {
      return {
        ok: false,
        error: tree.error,
        retryable: tree.error === "rate_limited" || tree.error === "fetch_failed",
        detail: "repo tree read nahi hua",
      };
    }
    entries = tree.data.entries
      .filter((e) => isMappableFile(e.path))
      .map((e) => ({ path: e.path, size: e.size }));
  }

  // Keyword matches first, then smallest files.
  entries.sort((a, b) => rank(b.path) - rank(a.path) || (a.size ?? 0) - (b.size ?? 0));
  const mappable = entries.filter((e) => isMappableFile(e.path));

  // Symbols: snapshot mode has contents locally; GitHub mode fetches at
  // most 10 keyword-matching files (unauthenticated reads are 60/hour —
  // the map must never burn the budget on a full-tree fetch).
  const lines: string[] = [];
  let symbols = 0;
  let truncated = false;
  let fetched = 0;
  for (const e of mappable.slice(0, 200)) {
    let content = e.content;
    if (content === undefined && fetched < 10 && rank(e.path) > 0) {
      const file = await getFileContent(env, owner, repo, e.path, ref);
      if (file.ok && file.data) {
        content = file.data.content;
        fetched++;
      }
    }
    const syms = content !== undefined ? extractSymbols(e.path, content) : [];
    symbols += syms.length;
    const entry = `${e.path}${e.size !== undefined ? ` (${e.size} B)` : ""}${syms.length > 0 ? "\n  - " + syms.join("\n  - ") : ""}`;
    if (lines.join("\n").length + entry.length > MAIN_REPO_MAP_CHAR_CAP) {
      truncated = true;
      break;
    }
    lines.push(entry);
  }
  const map =
    `Repo: ${owner}/${repo} @ ${ref} (${mappable.length} mappable files, ${symbols} symbols${truncated ? "; TRUNCATED to the repo-map cap" : ""})\n` +
    lines.join("\n");
  return { ok: true, data: { map, files: mappable.length, symbols, truncated } };
}

// --- Scan before commit ---

export interface ScanVerdict {
  verdict: "clean" | "blocked" | "scan_unavailable";
  findings: string[];
}

export async function scanEdit(env: MainEnv, path: string, content: string): Promise<ScanVerdict> {
  if (isForbiddenPath(path)) {
    return { verdict: "blocked", findings: [`forbidden path: ${path}`] };
  }
  const secretHits = SECRET_PATTERNS.filter((p) => p.re.test(content)).map((p) => p.name);
  if (secretHits.length > 0) {
    return { verdict: "blocked", findings: secretHits.map((s) => `secret-shaped value: ${s}`) };
  }
  if (path.endsWith(".py")) {
    // AST scan via the render worker (/doc/scan) — same helper the skills
    // module uses. A worker outage is NOT a block (CI is the real test);
    // it is recorded as scan_unavailable so the PR body says so honestly.
    // fetchFn passes through so vitest can mock the worker.
    const scan = await scanSkillCode(env, content, { fetchFn: env.fetchFn });
    if (scan.status === "findings") {
      return {
        verdict: "blocked",
        findings: scan.findings.map((f) => `line ${f.line}: ${f.pattern} — ${f.detail}`),
      };
    }
    if (scan.status === "pending") {
      return { verdict: "scan_unavailable", findings: [`render scan unavailable: ${scan.error ?? "unknown"}`] };
    }
  }
  return { verdict: "clean", findings: [] };
}

// --- LLM (in-process router, kind main_executor) ---

interface LlmCallOut {
  ok: boolean;
  text?: string;
  model?: string;
  input_tokens?: number;
  output_tokens?: number;
  ms?: number;
  error?: string;
}

async function callMainLlm(
  env: MainEnv,
  job: MainJob,
  phase: string,
  system: string,
  userText: string,
): Promise<LlmCallOut> {
  if (job.llm_calls >= MAIN_MAX_CALLS_PER_JOB) {
    return { ok: false, error: "job_llm_budget_exhausted" };
  }
  let config;
  try {
    config = loadRouterConfig(env);
  } catch {
    return { ok: false, error: "router_config_error" };
  }
  const turnId = `main-${job.id}-${phase}-${job.llm_calls + 1}`;
  const started = now(env);
  const result = await routeLlm(
    {
      db: env.DB,
      fetchFn: env.fetchFn,
      masterKeyB64: env.KEY_ENC_SECRET,
      founderKey: env.FOUNDER_GEMINI_KEY,
      founderGroqKey: env.FOUNDER_GROQ_KEY,
      config,
    },
    {
      tenant_id: job.tenant_id,
      device_id: job.device_id ?? undefined,
      turn_id: turnId,
      kind: "main_executor",
      messages: [{ role: "user", text: userText }],
      system,
    },
  );
  const ms = now(env) - started;
  const out: LlmCallOut = result.ok
    ? { ok: true, text: result.text ?? "", model: result.model, input_tokens: result.input_tokens, output_tokens: result.output_tokens, ms }
    : { ok: false, error: result.error_code ?? result.error ?? "llm_failed", ms };
  // Compute once, assign (never += after the update): D1 .first() may
  // return a live row reference (FakeD1), so `job.llm_calls += 1` after
  // the UPDATE would double-count the call.
  const newCalls = job.llm_calls + 1;
  await updateMainJob(env.DB, job.id, { llm_calls: newCalls });
  job.llm_calls = newCalls;
  await appendTranscript(env.DB, job, {
    phase: `llm:${phase}`,
    note: out.ok ? `model ${out.model ?? "?"} — ${out.input_tokens ?? 0} in / ${out.output_tokens ?? 0} out` : `LLM failed: ${out.error}`,
    model: out.model,
    input_tokens: out.input_tokens,
    output_tokens: out.output_tokens,
    ms,
    ok: out.ok,
  });
  return out;
}

function stripFences(text: string): string {
  let t = text.trim();
  // Remove a single surrounding ``` fence (```json, ```kotlin, ...).
  t = t.replace(/^```[A-Za-z0-9_-]*\n/, "").replace(/\n```\s*$/, "");
  return t.trim();
}

const ARCHITECT_SYSTEM =
  "You are the architect of the OmniJarvis Main Executor. You plan small, safe code changes. " +
  "Output JSON only, no prose. Plan at most 5 steps. One file per step. Never touch secrets, credentials, keys, or licence files. " +
  "Never add dependencies. Prefer the smallest change that satisfies the ask. " +
  "If the ask is unclear or needs a decision only the user can make, return {\"question\": \"...\"} instead of a plan. " +
  "Plan shape: {\"steps\": [{\"id\": \"s1\", \"title\": \"...\", \"file\": \"path/to/file\", \"action\": \"what to change\"}]}";

const EDITOR_SYSTEM =
  "You are the editor of the OmniJarvis Main Executor. You apply one planned step to one file. " +
  "Output the COMPLETE new file content only — no diff, no prose, no fences. Keep the existing style. Minimal change. " +
  "Never insert secrets, tokens, or credentials. Never add dependencies.";

function slugifyAsk(ask: string): string {
  return ask
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40) || "task";
}

const TOKEN_UNBLOCK_INSTRUCTIONS =
  "GitHub token not set. The Main Executor authored + scanned this patch and queued the PR body — it cannot push or open the PR until the admin sets the token once as a Worker secret: " +
  "create a GitHub Personal Access Token (classic, repo scope — read + write on raj3kk/jarvis-agent-app and raj3kk/omnijarvis-server), then set it with the Cloudflare Secrets API: " +
  "PUT /accounts/{account_id}/workers/scripts/omnijarvis-hub/secrets with {\"name\": \"GITHUB_ADMIN_TOKEN\", \"text\": \"<token>\", \"type\": \"secret_text\"}. " +
  "Then re-run POST /api/main/step {\"job_id\": \"<id>\"} to resume — no rebuild needed.";

// --- Step machine ---

type StepOutcome = { done: boolean; retryable?: boolean; note: string; error?: string };

async function stepLocalize(env: MainEnv, job: MainJob): Promise<StepOutcome> {
  const parsed = parseRepoSlug(job.repo);
  if (!parsed) return { done: false, note: "invalid repo slug", error: "invalid_repo" };
  const { owner, name } = parsed;
  const snapshot = parseTranscript(job).find((e) => e.phase === "created" && e.files)?.files;
  let ref = job.base_branch;
  if (!snapshot) {
    const head = await getBranchHead(env, owner, name, job.base_branch);
    if (!head.ok) {
      return {
        done: false,
        retryable: head.error === "rate_limited" || head.error === "fetch_failed",
        note: `base branch head read failed: ${head.error}`,
        error: head.error,
      };
    }
    ref = head.data;
  }
  const mapRes = await buildRepoMap(env, owner, name, ref, job.ask, snapshot);
  if (!mapRes.ok) {
    return { done: false, retryable: mapRes.retryable, note: `repo map failed: ${mapRes.error}`, error: mapRes.error };
  }
  await appendTranscript(env.DB, job, {
    phase: "repo-map",
    note: `repo map built: ${mapRes.data.files} files, ${mapRes.data.symbols} symbols${mapRes.data.truncated ? " (truncated)" : ""}`,
  });
  const call = await callMainLlm(
    env,
    job,
    "architect",
    ARCHITECT_SYSTEM,
    `Ask: ${job.ask}\n\nRepo map:\n${mapRes.data.map}`,
  );
  if (!call.ok) {
    if (call.error === "job_llm_budget_exhausted") return { done: false, note: "job LLM budget exhausted", error: call.error };
    return { done: false, retryable: true, note: `architect call failed: ${call.error}`, error: call.error };
  }
  let parsedPlan: { steps?: unknown; question?: unknown } | null = null;
  try {
    parsedPlan = JSON.parse(stripFences(call.text ?? "")) as { steps?: unknown; question?: unknown };
  } catch {
    parsedPlan = null;
  }
  if (!parsedPlan) {
    // One retry with a stricter nudge, then park with a question.
    const retry = await callMainLlm(env, job, "architect-retry", ARCHITECT_SYSTEM, `Ask: ${job.ask}\n\nReturn JSON only — no prose, no fences. Shape: {"steps": [{"id": "s1", "title": "...", "file": "path/to/file", "action": "..."}]}`);
    if (!retry.ok) return { done: false, retryable: true, note: `architect retry failed: ${retry.error}`, error: retry.error };
    try {
      parsedPlan = JSON.parse(stripFences(retry.text ?? "")) as { steps?: unknown; question?: unknown };
    } catch {
      parsedPlan = null;
    }
  }
  if (!parsedPlan) {
    await updateMainJob(env.DB, job.id, {
      status: "parked",
      error_code: "need_info",
      error: "Main samajh nahi paya — ask ko chota aur saaf karke dobara bhejo.",
    });
    return { done: true, note: "plan unparseable — parked with a question" };
  }
  if (typeof parsedPlan.question === "string" && parsedPlan.question.trim()) {
    await updateMainJob(env.DB, job.id, {
      status: "parked",
      error_code: "need_info",
      error: parsedPlan.question.trim().slice(0, 500),
    });
    return { done: true, note: "architect asked a question — parked" };
  }
  const rawSteps = Array.isArray(parsedPlan.steps) ? parsedPlan.steps : [];
  const steps: MainPlanStep[] = [];
  for (const s of rawSteps.slice(0, 5)) {
    const step = s as { id?: unknown; title?: unknown; file?: unknown; action?: unknown };
    if (typeof step.title !== "string" || typeof step.file !== "string" || typeof step.action !== "string") continue;
    if (isForbiddenPath(step.file)) continue;
    steps.push({
      id: typeof step.id === "string" ? step.id : `s${steps.length + 1}`,
      title: step.title.slice(0, 200),
      file: step.file.slice(0, 300),
      action: step.action.slice(0, 500),
    });
  }
  if (steps.length === 0) {
    await updateMainJob(env.DB, job.id, {
      status: "parked",
      error_code: "need_info",
      error: "Plan me koi valid step nahi bana — ask ko saaf karke dobara bhejo.",
    });
    return { done: true, note: "plan had no valid steps — parked" };
  }
  const plan: MainPlan = { steps, done: [] };
  await updateMainJob(env.DB, job.id, { plan: JSON.stringify(plan), status: "planned", error: null, error_code: null });
  job.plan = JSON.stringify(plan);
  return { done: true, note: `plan ready: ${steps.length} step(s)` };
}

async function currentFileContent(
  env: MainEnv,
  job: MainJob,
  owner: string,
  name: string,
  filePath: string,
): Promise<{ ok: true; content: string; exists: boolean } | { ok: false; error: string; retryable?: boolean }> {
  const snapshot = parseTranscript(job).find((e) => e.phase === "created" && e.files)?.files;
  if (snapshot) {
    const snap = snapshot.find((f) => f.path === filePath);
    if (snap) {
      // Later patches override the snapshot content.
      const patches = parseTranscript(job).filter((e) => e.phase === "patch" && e.patch?.path === filePath);
      const latest = patches.length > 0 ? patches[patches.length - 1].patch!.content : snap.content;
      return { ok: true, content: latest, exists: true };
    }
    const patch = parseTranscript(job).find((e) => e.phase === "patch" && e.patch?.path === filePath);
    if (patch?.patch) return { ok: true, content: patch.patch.content, exists: true };
    return { ok: true, content: "", exists: false };
  }
  const ref = job.branch ?? job.base_branch;
  const file = await getFileContent(env, owner, name, filePath, ref);
  if (!file.ok) {
    return { ok: false, error: file.error, retryable: file.error === "rate_limited" || file.error === "fetch_failed" };
  }
  if (!file.data) return { ok: true, content: "", exists: false };
  return { ok: true, content: file.data.content, exists: true };
}

async function commitPatches(
  env: MainEnv,
  job: MainJob,
  owner: string,
  name: string,
  patches: { path: string; content: string }[],
  message: string,
): Promise<{ ok: true; head: string } | { ok: false; error: string; retryable?: boolean }> {
  let branch = job.branch;
  let head: string;
  const baseHead = await getBranchHead(env, owner, name, job.base_branch);
  if (!baseHead.ok) {
    return { ok: false, error: baseHead.error, retryable: baseHead.error === "rate_limited" || baseHead.error === "fetch_failed" };
  }
  if (!branch) {
    branch = `agent-mode/${slugifyAsk(job.ask)}-${job.id.slice(-6)}`;
    const created = await createBranch(env, owner, name, branch, baseHead.data);
    if (!created.ok) {
      if (created.error === "github_not_configured") return { ok: false, error: "github_not_configured" };
      return { ok: false, error: created.error, retryable: created.error === "rate_limited" || created.error === "fetch_failed" };
    }
    head = baseHead.data;
  } else {
    const headRes = await getBranchHead(env, owner, name, branch);
    if (!headRes.ok) {
      return { ok: false, error: headRes.error, retryable: headRes.error === "rate_limited" || headRes.error === "fetch_failed" };
    }
    head = headRes.data;
  }
  const commit = await createCommitOnBranch(env, owner, name, {
    branch,
    message,
    files: patches.map((p) => ({ path: p.path, contents: p.content })),
    expectedHeadOid: head,
  });
  if (!commit.ok) {
    if (commit.error === "tip_moved") {
      // One retry with a fresh head (the fast-forward guard fired).
      const fresh = await getBranchHead(env, owner, name, branch);
      if (!fresh.ok) return { ok: false, error: fresh.error, retryable: true };
      const retry = await createCommitOnBranch(env, owner, name, {
        branch,
        message,
        files: patches.map((p) => ({ path: p.path, contents: p.content })),
        expectedHeadOid: fresh.data,
      });
      if (!retry.ok) return { ok: false, error: retry.error, retryable: retry.error === "rate_limited" || retry.error === "fetch_failed" };
      await updateMainJob(env.DB, job.id, { branch });
      job.branch = branch;
      return { ok: true, head: retry.data };
    }
    if (commit.error === "github_not_configured") return { ok: false, error: "github_not_configured" };
    return { ok: false, error: commit.error, retryable: commit.error === "rate_limited" || commit.error === "fetch_failed" };
  }
  await updateMainJob(env.DB, job.id, { branch });
  job.branch = branch;
  return { ok: true, head: commit.data };
}

async function stepEdit(env: MainEnv, job: MainJob): Promise<StepOutcome> {
  const parsed = parseRepoSlug(job.repo);
  if (!parsed) return { done: false, note: "invalid repo slug", error: "invalid_repo" };
  const { owner, name } = parsed;
  const plan = parsePlan(job);
  if (!plan) return { done: false, note: "no plan on an editing job", error: "no_plan" };
  const next = plan.steps.find((s) => !plan.done.includes(s.id));
  if (!next) {
    // All steps done — chain into validation (same invocation).
    await updateMainJob(env.DB, job.id, { status: "validating" });
    job.status = "validating";
    return stepValidate(env, job);
  }
  const cur = await currentFileContent(env, job, owner, name, next.file);
  if (!cur.ok) {
    return { done: false, retryable: cur.retryable, note: `file read failed: ${cur.error}`, error: cur.error };
  }
  const isCreate = /create|new file|add/i.test(next.action) || !cur.exists;
  if (!cur.exists && !isCreate) {
    // The plan names a file that is not there and does not ask to create
    // it — skip the step (recorded) rather than failing the whole job.
    plan.done.push(next.id);
    await updateMainJob(env.DB, job.id, { plan: JSON.stringify(plan) });
    job.plan = JSON.stringify(plan);
    await appendTranscript(env.DB, job, { phase: "edit", note: `step ${next.id} skipped — file not found and action does not create it: ${next.file}` });
    return { done: true, note: `step ${next.id} skipped (file not found)` };
  }
  const call = await callMainLlm(
    env,
    job,
    "editor",
    EDITOR_SYSTEM,
    `Step: ${next.title}\nAction: ${next.action}\n\nCurrent file content (${next.file}${cur.exists ? "" : " — NEW FILE"}):\n${cur.content}\n\nReturn the complete new file content.`,
  );
  if (!call.ok) {
    if (call.error === "job_llm_budget_exhausted") return { done: false, note: "job LLM budget exhausted", error: call.error };
    return { done: false, retryable: true, note: `editor call failed: ${call.error}`, error: call.error };
  }
  const newContent = stripFences(call.text ?? "");
  if (!newContent || newContent === cur.content) {
    job.retries_used += 1;
    await updateMainJob(env.DB, job.id, { retries_used: job.retries_used });
    if (job.retries_used > MAIN_MAX_RETRIES_PER_STEP) {
      plan.done.push(next.id);
      await updateMainJob(env.DB, job.id, { plan: JSON.stringify(plan) });
      job.plan = JSON.stringify(plan);
      await appendTranscript(env.DB, job, { phase: "edit", note: `step ${next.id} dropped — editor returned no change after ${MAIN_MAX_RETRIES_PER_STEP} retries` });
      return { done: true, note: `step ${next.id} dropped (no change)` };
    }
    return { done: false, retryable: true, note: `editor returned no change (retry ${job.retries_used}/${MAIN_MAX_RETRIES_PER_STEP})`, error: "editor_no_change" };
  }
  if (newContent.length > MAIN_EDIT_MAX_BYTES) {
    return { done: false, note: "editor output exceeds the 64 KB edit cap", error: "edit_too_large" };
  }
  const scan = await scanEdit(env, next.file, newContent);
  await updateMainJob(env.DB, job.id, { scan_verdict: scan.verdict });
  job.scan_verdict = scan.verdict;
  if (scan.verdict === "blocked") {
    job.retries_used += 1;
    await updateMainJob(env.DB, job.id, { retries_used: job.retries_used });
    await appendTranscript(env.DB, job, { phase: "scan", note: `scan BLOCKED step ${next.id}: ${scan.findings.join("; ")}` });
    if (job.retries_used > MAIN_MAX_RETRIES_PER_STEP) {
      plan.done.push(next.id);
      await updateMainJob(env.DB, job.id, { plan: JSON.stringify(plan) });
      job.plan = JSON.stringify(plan);
      return { done: true, note: `step ${next.id} dropped (scan blocked after retries)` };
    }
    return { done: false, retryable: true, note: `scan blocked step ${next.id}: ${scan.findings.join("; ")}`, error: "scan_blocked" };
  }
  if (scan.verdict === "scan_unavailable") {
    await appendTranscript(env.DB, job, { phase: "scan", note: `render scan unavailable for ${next.file}: ${scan.findings.join("; ")} — proceeding; CI is the real test` });
  }
  if (job.mode === "dry-run") {
    await appendTranscript(env.DB, job, {
      phase: "patch",
      note: `patch authored for ${next.file} (dry-run — queued, not pushed)`,
      patch: { path: next.file, content: newContent },
    });
  } else {
    const committed = await commitPatches(env, job, owner, name, [{ path: next.file, content: newContent }], `Main Executor: ${next.title} (${job.id})`);
    if (!committed.ok) {
      if (committed.error === "github_not_configured") {
        // Token was removed mid-job — fall back to dry-run queuing.
        await updateMainJob(env.DB, job.id, { mode: "dry-run" });
        job.mode = "dry-run";
        await appendTranscript(env.DB, job, {
          phase: "patch",
          note: `token gone mid-job — patch for ${next.file} queued as dry-run`,
          patch: { path: next.file, content: newContent },
        });
      } else {
        return { done: false, retryable: committed.retryable, note: `commit failed: ${committed.error}`, error: committed.error };
      }
    } else {
      await appendTranscript(env.DB, job, { phase: "commit", note: `committed ${next.file} on ${job.branch} (${committed.head.slice(0, 7)})` });
    }
  }
  plan.done.push(next.id);
  const allDone = plan.steps.every((s) => plan.done.includes(s.id));
  await updateMainJob(env.DB, job.id, { plan: JSON.stringify(plan), status: allDone ? "validating" : "editing" });
  job.plan = JSON.stringify(plan);
  job.status = allDone ? "validating" : "editing";
  if (allDone) return stepValidate(env, job);
  return { done: true, note: `step ${next.id} done (${next.file})` };
}

async function stepValidate(env: MainEnv, job: MainJob): Promise<StepOutcome> {
  const parsed = parseRepoSlug(job.repo);
  if (!parsed) return { done: false, note: "invalid repo slug", error: "invalid_repo" };
  const { owner, name } = parsed;
  if (job.mode === "dry-run") {
    await updateMainJob(env.DB, job.id, { ci_status: "skipped_dry_run" });
    job.ci_status = "skipped_dry_run";
    return stepPr(env, job);
  }
  if (!job.branch) {
    // Nothing was committed (all steps skipped/dropped) — nothing to
    // validate; ship the proposal as-is with the note in the PR body.
    await updateMainJob(env.DB, job.id, { ci_status: "no_changes" });
    job.ci_status = "no_changes";
    return stepPr(env, job);
  }
  const checks = await getCheckSummary(env, owner, name, job.branch);
  if (!checks.ok) {
    return { done: false, retryable: checks.error === "rate_limited" || checks.error === "fetch_failed", note: `CI poll failed: ${checks.error}`, error: checks.error };
  }
  if (checks.data.state === "pending") {
    return { done: false, retryable: true, note: "CI still running — will re-poll next tick", error: "ci_pending" };
  }
  if (checks.data.state === "unknown") {
    await updateMainJob(env.DB, job.id, { ci_status: "unknown" });
    job.ci_status = "unknown";
    await appendTranscript(env.DB, job, { phase: "ci", note: "no CI checks on this branch — proceeding to PR with the note in the body" });
    return stepPr(env, job);
  }
  if (checks.data.state === "success") {
    await updateMainJob(env.DB, job.id, { ci_status: "success" });
    job.ci_status = "success";
    await appendTranscript(env.DB, job, { phase: "ci", note: `CI green (${checks.data.checks.length} check(s))` });
    return stepPr(env, job);
  }
  // CI failed — one fix round (max 2 retries), fed by the failing
  // checks' output, then the PR ships labelled needs-work.
  const failed = checks.data.checks.filter((c) => c.conclusion === "failure" || c.conclusion === "cancelled" || c.conclusion === "timed_out");
  await updateMainJob(env.DB, job.id, { ci_status: "failed" });
  job.ci_status = "failed";
  await appendTranscript(env.DB, job, {
    phase: "ci",
    note: `CI failed: ${failed.map((f) => `${f.name}${f.output ? ` — ${f.output}` : ""}`).join("; ")}`,
  });
  if (job.retries_used >= MAIN_MAX_RETRIES_PER_STEP) {
    return stepPr(env, job);
  }
  const plan = parsePlan(job);
  if (!plan) return stepPr(env, job);
  const lastEdited = [...parseTranscript(job)].reverse().find((e) => e.phase === "commit" || e.phase === "patch");
  const fixFile = lastEdited?.patch?.path ?? plan.steps[plan.steps.length - 1]?.file ?? "";
  if (!fixFile) return stepPr(env, job);
  const fixStep: MainPlanStep = {
    id: `fix-ci-${job.retries_used + 1}`,
    title: "Fix failing CI",
    file: fixFile,
    action: `Fix the CI failure. Failing checks: ${failed.map((f) => `${f.name}${f.output ? ` (${f.output})` : ""}`).join("; ")}. Change only what the failure needs.`,
  };
  plan.steps.push(fixStep);
  job.retries_used += 1;
  await updateMainJob(env.DB, job.id, { plan: JSON.stringify(plan), retries_used: job.retries_used, status: "editing" });
  job.plan = JSON.stringify(plan);
  job.status = "editing";
  return { done: true, note: `CI failed — fix step queued (retry ${job.retries_used}/${MAIN_MAX_RETRIES_PER_STEP})` };
}

function buildPrBody(job: MainJob, plan: MainPlan | null): string {
  const steps = plan
    ? plan.steps.map((s) => `- [${plan.done.includes(s.id) ? "x" : " "}] ${s.title} (${s.file})`).join("\n")
    : "(no plan)";
  const transcript = parseTranscript(job);
  const llmCalls = transcript.filter((e) => e.phase.startsWith("llm:"));
  const models = [...new Set(llmCalls.map((e) => e.model).filter(Boolean))].join(", ") || "none";
  const patches = transcript.filter((e) => e.phase === "patch");
  return (
    `# Main Executor proposal\n\n` +
    `Ask: ${job.ask}\n\n` +
    `## Plan\n${steps}\n\n` +
    `## Evidence\n` +
    `- Scan: ${job.scan_verdict ?? "not run"}${job.scan_verdict === "scan_unavailable" ? " (render worker unreachable — CI is the real test)" : ""}\n` +
    `- CI: ${job.ci_status ?? "not run"}\n` +
    `- LLM calls: ${job.llm_calls} (models: ${models})\n` +
    `- Steps used: ${job.steps_used}\n` +
    (patches.length > 0 ? `- Patches queued (dry-run): ${patches.map((p) => p.patch?.path).join(", ")}\n` : "") +
    `\n## Reviewer notes\n` +
    `- Proposed by the OmniJarvis Main Executor (server, global). Merge only after review.\n` +
    `- This PR was never merged by the agent — the user merges, always.\n` +
    `- Job: ${job.id} · repo ${job.repo} · base ${job.base_branch}\n`
  );
}

async function stepPr(env: MainEnv, job: MainJob): Promise<StepOutcome> {
  const parsed = parseRepoSlug(job.repo);
  if (!parsed) return { done: false, note: "invalid repo slug", error: "invalid_repo" };
  const { owner, name } = parsed;
  const plan = parsePlan(job);
  const body = buildPrBody(job, plan);
  const title = `Main Executor: ${job.ask.slice(0, 80)}`;
  if (job.mode === "dry-run") {
    await updateMainJob(env.DB, job.id, {
      status: "blocked_token",
      error_code: "github_token_not_configured",
      error: TOKEN_UNBLOCK_INSTRUCTIONS,
    });
    await appendTranscript(env.DB, job, { phase: "pr-queued", note: "PR body + evidence bundle queued (dry-run). Patch is in the transcript; the PR opens when the token is set." });
    return { done: true, note: "dry-run complete — PR queued, blocked on the GitHub token" };
  }
  if (!isWriteRepo(owner, name)) {
    // Main only writes to the two Jarvis repos. Anything else is a
    // propose-only job even with the token set (the patch stays in the
    // transcript for the phone to apply locally).
    await updateMainJob(env.DB, job.id, {
      status: "blocked_token",
      error_code: "repo_not_writable",
      error: `Main writes only to raj3kk/jarvis-agent-app and raj3kk/omnijarvis-server. ${job.repo} is propose-only — the patch is in the transcript for the phone to apply.`,
    });
    return { done: true, note: "repo not in the write allowlist — propose-only" };
  }
  if (!job.branch) {
    await updateMainJob(env.DB, job.id, { status: "partial", error_code: "no_changes", error: "Koi change commit nahi hua — PR kholne ke liye kuch nahi." });
    return { done: true, note: "no branch — nothing to PR" };
  }
  const pr = await createPullRequest(env, owner, name, { title, body, head: job.branch, base: job.base_branch });
  if (!pr.ok) {
    if (pr.error === "github_not_configured") {
      await updateMainJob(env.DB, job.id, { status: "blocked_token", error_code: "github_token_not_configured", error: TOKEN_UNBLOCK_INSTRUCTIONS });
      return { done: true, note: "token gone before PR — queued as blocked_token" };
    }
    return { done: false, retryable: pr.error === "rate_limited" || pr.error === "fetch_failed", note: `PR create failed: ${pr.error}`, error: pr.error };
  }
  const needsWork = job.ci_status === "failed";
  await updateMainJob(env.DB, job.id, {
    status: needsWork ? "pr_open_needs_work" : "pr_open",
    pr_url: pr.data.html_url,
    pr_number: pr.data.number,
    error: null,
    error_code: null,
  });
  await appendTranscript(env.DB, job, { phase: "pr", note: `PR #${pr.data.number} opened: ${pr.data.html_url}${needsWork ? " (needs-work — CI failed)" : ""}` });
  // Update notice (FCM → Talker). Best-effort: a missing token or an
  // FCM failure never fails the step.
  if (job.device_id) {
    try {
      await sendFcm(env, env.DB, {
        tenantId: job.tenant_id,
        deviceId: job.device_id,
        title: "Jarvis: proposal ready",
        body: `Main Executor ne ${job.repo} ke liye PR #${pr.data.number} banaya — review karke merge karo.`,
        kind: "main_pr",
        data: { job_id: job.id, pr_url: pr.data.html_url },
      });
    } catch {
      // FCM notice is best-effort by design.
    }
  }
  return { done: true, note: `PR #${pr.data.number} opened${needsWork ? " (needs-work)" : ""}` };
}

async function resumeBlockedToken(env: MainEnv, job: MainJob): Promise<StepOutcome> {
  const parsed = parseRepoSlug(job.repo);
  if (!parsed) return { done: false, note: "invalid repo slug", error: "invalid_repo" };
  const { owner, name } = parsed;
  const patches = parseTranscript(job)
    .filter((e) => e.phase === "patch" && e.patch)
    .map((e) => e.patch as { path: string; content: string });
  if (patches.length === 0) {
    await updateMainJob(env.DB, job.id, { status: "partial", error_code: "no_changes", error: "Queued patch nahi mila — PR kholne ke liye kuch nahi." });
    return { done: true, note: "blocked_token resumed but no queued patches" };
  }
  const committed = await commitPatches(env, job, owner, name, patches, `Main Executor: ${job.ask.slice(0, 80)} (${job.id})`);
  if (!committed.ok) {
    return { done: false, retryable: committed.retryable, note: `queued-patch commit failed: ${committed.error}`, error: committed.error };
  }
  await updateMainJob(env.DB, job.id, { mode: "github", status: "validating", error: null, error_code: null });
  job.mode = "github";
  job.status = "validating";
  await appendTranscript(env.DB, job, { phase: "commit", note: `queued patches committed on ${job.branch} (${committed.head.slice(0, 7)}) — token is live` });
  return stepValidate(env, job);
}

// --- Public step entry points ---

export async function runMainStep(
  env: MainEnv,
  jobId: string,
  opts?: { resume?: boolean },
): Promise<MainJobResult> {
  const job = await getMainJob(env.DB, jobId);
  if (!job) return { ok: false, error: "job_not_found" };
  const terminal: MainJobStatus[] = ["pr_open", "pr_open_needs_work", "done", "failed"];
  if (terminal.includes(job.status)) return { ok: false, error: "job_not_steppable", detail: `job already ${job.status}` };
  if (job.status === "parked") return { ok: false, error: "job_parked_needs_info", detail: job.error ?? undefined };
  if (job.status === "partial" && !opts?.resume) {
    return { ok: false, error: "job_partial_resume_required", detail: "resume:true ke saath dobara chalao (max 20 steps total)" };
  }
  if (job.steps_used >= MAIN_MAX_STEPS_HARD) {
    return { ok: false, error: "job_max_steps", detail: `hard cap ${MAIN_MAX_STEPS_HARD} steps reached` };
  }
  if (job.status === "partial" && opts?.resume) {
    // Resume a partial job: back to editing (stepEdit routes to
    // validating when no steps remain).
    await updateMainJob(env.DB, job.id, { status: "editing", error: null, error_code: null });
    job.status = "editing";
  }
  let outcome: StepOutcome;
  try {
    if (job.status === "blocked_token") {
      if (!isGitHubConfigured(env)) {
        return { ok: false, error: "github_token_not_configured", detail: "Token set hone tak job yahin ruka rahega — no rebuild needed when it lands." };
      }
      outcome = await resumeBlockedToken(env, job);
    } else if (job.status === "received") {
      outcome = await stepLocalize(env, job);
    } else if (job.status === "planned" || job.status === "editing") {
      outcome = await stepEdit(env, job);
    } else {
      outcome = await stepValidate(env, job);
    }
  } catch (e) {
    await insertTrace(env.DB, job.tenant_id, job.device_id ?? "", "main_step_failed", {
      job_id: job.id,
      error: String((e as Error)?.message ?? e).slice(0, 200),
    });
    return { ok: false, error: "api_error", retryable: true, detail: "step crashed — trace recorded, next tick retries" };
  }
  if (!outcome.done) {
    if (outcome.error === "job_llm_budget_exhausted") {
      await updateMainJob(env.DB, job.id, { status: "partial", error_code: "job_llm_budget_exhausted", error: `Job ka LLM budget (${MAIN_MAX_CALLS_PER_JOB} calls) khatam — resume:true se aage badha sakte ho.` });
      const updated = await getMainJob(env.DB, job.id);
      return { ok: true, job: updated ?? job, note: "job LLM budget exhausted — partial" };
    }
    if (!outcome.retryable) {
      await updateMainJob(env.DB, job.id, { status: "failed", error_code: outcome.error ?? "step_failed", error: outcome.note.slice(0, 500) });
      const updated = await getMainJob(env.DB, job.id);
      return { ok: true, job: updated ?? job, note: `job failed: ${outcome.note}` };
    }
    // Transient failure: no step consumed, no status change — the tick
    // retries after the backoff (listPendingMainJobs skips recent
    // retry notes). Record it in the transcript.
    await appendTranscript(env.DB, job, { phase: "retry", note: outcome.note });
    const updated = await getMainJob(env.DB, job.id);
    return { ok: false, error: outcome.error ?? "retryable", retryable: true, detail: outcome.note };
  }
  // A completed step consumes one step of the job budget.
  const fresh = await getMainJob(env.DB, job.id);
  const stepsUsed = (fresh?.steps_used ?? job.steps_used) + 1;
  await updateMainJob(env.DB, job.id, { steps_used: stepsUsed });
  if (stepsUsed >= MAIN_MAX_STEPS && fresh && !terminal.includes(fresh.status) && fresh.status !== "parked" && fresh.status !== "blocked_token" && fresh.status !== "partial") {
    await updateMainJob(env.DB, job.id, { status: "partial", error_code: "max_steps", error: `Default step budget (${MAIN_MAX_STEPS}) khatam — resume:true se ${MAIN_MAX_STEPS_HARD} tak badha sakte ho.` });
  }
  const finalJob = (await getMainJob(env.DB, job.id)) ?? job;
  return { ok: true, job: finalJob, note: outcome.note };
}

/**
 * Cron-tick stepper: at most 2 pending jobs, one step each. Best-effort
 * — a Main failure never breaks the tick (the caller wraps this in a
 * try/catch + trace). Jobs that failed transiently within the last
 * 10 minutes are skipped (backoff) so a stuck job never occupies a
 * slot every tick.
 */
export async function stepMainJobs(env: MainEnv): Promise<MainJobResult[]> {
  const pending = await listPendingMainJobs(env.DB, 2);
  const results: MainJobResult[] = [];
  for (const job of pending) {
    const entries = parseTranscript(job);
    const lastRetry = [...entries].reverse().find((e) => e.phase === "retry");
    if (lastRetry && now(env) - lastRetry.at < MAIN_RETRY_BACKOFF_MS) continue;
    try {
      results.push(await runMainStep(env, job.id));
    } catch (e) {
      await insertTrace(env.DB, job.tenant_id, job.device_id ?? "", "main_step_tick_failed", {
        job_id: job.id,
        error: String((e as Error)?.message ?? e).slice(0, 200),
      });
      results.push({ ok: false, error: "api_error", retryable: true });
    }
  }
  return results;
}
