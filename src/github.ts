/**
 * GitHub API client for the Main Executor (R1, hybrid core).
 *
 * The admin GitHub token lives ONLY as the hub Worker secret
 * GITHUB_ADMIN_TOKEN — it is never stored in D1, never logged, and
 * never leaves the Worker except in the Authorization header of a
 * request to api.github.com. When the token is not set, every call
 * returns { ok: false, error: "github_not_configured" } and the Main
 * Executor runs in dry-run mode (patch authored + scanned, GitHub
 * write waits for the token).
 *
 * Scope (locked by the redesign): reads may target any public repo
 * (the GitHub API itself enforces visibility — a private repo the
 * token cannot see returns 404). Reads of PUBLIC repos also work
 * WITHOUT a token (unauthenticated, 60 req/hour shared — the
 * propose-only / dry-run path: Main can still read public code,
 * research, and draft patches, but it cannot push, cannot open PRs,
 * and cannot do authenticated reads/writes). Writes (branch /
 * commit / PR) are allowed ONLY for the two Jarvis repos below AND
 * only with the token set. The hub never touches a user's own
 * GitHub — it only fetches code from GitHub to build the user's
 * app, per the user's order.
 *
 * What the token is FOR (user question 2026-11-23 ~13:00 IST):
 * with GITHUB_ADMIN_TOKEN set, the Main Executor uses the GitHub API
 * to read repo code (trees/blobs/contents), create branches, commit
 * + push fixes, open PRs, poll CI check-runs, read failing-check
 * output, and send the update notice. That IS the self-development
 * loop (research → patch → scan → CI → PR). Without it, Main runs
 * PROPOSE-ONLY: research + draft patch + PR body + evidence bundle,
 * queued — no push, no PR, no authenticated calls. The loop goes
 * live the moment the token is set as a Worker secret, no rebuild.
 */
export interface GitHubEnv {
  GITHUB_ADMIN_TOKEN?: string;
  fetchFn?: typeof fetch;
}

export const GITHUB_WRITE_REPOS = [
  "raj3kk/jarvis-agent-app",
  "raj3kk/omnijarvis-server",
] as const;

export function isGitHubConfigured(env: GitHubEnv): boolean {
  return !!env.GITHUB_ADMIN_TOKEN;
}

export function isWriteRepo(owner: string, repo: string): boolean {
  return (GITHUB_WRITE_REPOS as readonly string[]).includes(`${owner}/${repo}`);
}

export type GitHubErrorCode =
  | "github_not_configured"
  | "not_found"
  | "forbidden"
  | "rate_limited"
  | "tip_moved"
  | "too_large"
  | "invalid_repo"
  | "api_error"
  | "fetch_failed";

export type GitHubResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: GitHubErrorCode; status?: number; detail?: string };

const API_BASE = "https://api.github.com";
const MAX_FILE_BYTES = 512 * 1024;

export function isValidRepoSlug(repo: string): boolean {
  return /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repo);
}

export function parseRepoSlug(repo: string): { owner: string; name: string } | null {
  if (!isValidRepoSlug(repo)) return null;
  const [owner, name] = repo.split("/");
  return { owner, name };
}

async function ghFetch(
  env: GitHubEnv,
  path: string,
  init?: RequestInit & { requireAuth?: boolean },
): Promise<GitHubResult<Response>> {
  // Writes need the token. Reads of public repos work unauthenticated
  // (60 req/hour) — the propose-only path. A private repo without a
  // token answers 404 (GitHub enforces visibility, not us).
  if (init?.requireAuth && !env.GITHUB_ADMIN_TOKEN) {
    return { ok: false, error: "github_not_configured" };
  }
  const doFetch = env.fetchFn ?? fetch;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "omnijarvis-hub",
  };
  if (env.GITHUB_ADMIN_TOKEN) headers.Authorization = `Bearer ${env.GITHUB_ADMIN_TOKEN}`;
  let res: Response;
  try {
    res = await doFetch(`${API_BASE}${path}`, {
      ...init,
      headers: { ...headers, ...((init?.headers as Record<string, string> | undefined) ?? {}) },
    });
  } catch {
    return { ok: false, error: "fetch_failed" };
  }
  if (res.status === 401 || res.status === 403) {
    // 403 here is usually the token's rate limit (secondary limit) —
    // distinguish it so the caller can back off instead of failing.
    const remaining = res.headers.get("x-ratelimit-remaining");
    if (res.status === 403 && remaining === "0") {
      return { ok: false, error: "rate_limited", status: 403 };
    }
    return { ok: false, error: "forbidden", status: res.status };
  }
  if (res.status === 404) return { ok: false, error: "not_found", status: 404 };
  if (!res.ok) {
    // Never echo a response body (it can contain repo-internal detail).
    return { ok: false, error: "api_error", status: res.status };
  }
  return { ok: true, data: res };
}

export interface RepoInfo {
  default_branch: string;
  private: boolean;
}

export async function getRepo(
  env: GitHubEnv,
  owner: string,
  repo: string,
): Promise<GitHubResult<RepoInfo>> {
  const res = await ghFetch(env, `/repos/${owner}/${repo}`);
  if (!res.ok) return res;
  const data = (await res.data.json()) as { default_branch?: string; private?: boolean };
  return {
    ok: true,
    data: { default_branch: data.default_branch ?? "main", private: !!data.private },
  };
}

export async function getBranchHead(
  env: GitHubEnv,
  owner: string,
  repo: string,
  branch: string,
): Promise<GitHubResult<string>> {
  const res = await ghFetch(env, `/repos/${owner}/${repo}/git/ref/heads/${encodeURIComponent(branch)}`);
  if (!res.ok) return res;
  const data = (await res.data.json()) as { object?: { sha?: string } };
  if (!data.object?.sha) return { ok: false, error: "api_error" };
  return { ok: true, data: data.object.sha };
}

export interface FileContent {
  content: string;
  sha: string;
  size: number;
}

export async function getFileContent(
  env: GitHubEnv,
  owner: string,
  repo: string,
  path: string,
  ref?: string,
): Promise<GitHubResult<FileContent | null>> {
  const q = ref ? `?ref=${encodeURIComponent(ref)}` : "";
  const res = await ghFetch(env, `/repos/${owner}/${repo}/contents/${path}${q}`);
  if (!res.ok) {
    if (res.error === "not_found") return { ok: true, data: null };
    return res;
  }
  const data = (await res.data.json()) as {
    type?: string;
    encoding?: string;
    content?: string;
    sha?: string;
    size?: number;
  };
  if (data.type !== "file" || data.encoding !== "base64" || typeof data.content !== "string") {
    return { ok: false, error: "not_found", status: 404 };
  }
  if ((data.size ?? 0) > MAX_FILE_BYTES) return { ok: false, error: "too_large" };
  // Contents API returns base64 with newlines — strip them before decode.
  const clean = data.content.replace(/\s/g, "");
  let text: string;
  try {
    text = new TextDecoder().decode(
      Uint8Array.from(atob(clean), (c) => c.charCodeAt(0)),
    );
  } catch {
    return { ok: false, error: "api_error" };
  }
  return { ok: true, data: { content: text, sha: data.sha ?? "", size: data.size ?? 0 } };
}

export interface TreeEntry {
  path: string;
  type: string;
  size?: number;
}

export async function listTree(
  env: GitHubEnv,
  owner: string,
  repo: string,
  sha: string,
): Promise<GitHubResult<{ entries: TreeEntry[]; truncated: boolean }>> {
  const res = await ghFetch(env, `/repos/${owner}/${repo}/git/trees/${sha}?recursive=1`);
  if (!res.ok) return res;
  const data = (await res.data.json()) as {
    tree?: { path?: string; type?: string; size?: number }[];
    truncated?: boolean;
  };
  const entries: TreeEntry[] = (data.tree ?? [])
    .filter((e) => typeof e.path === "string" && e.type === "blob")
    .map((e) => ({ path: e.path as string, type: "blob", size: e.size }));
  return { ok: true, data: { entries, truncated: !!data.truncated } };
}

export async function createBranch(
  env: GitHubEnv,
  owner: string,
  repo: string,
  branch: string,
  fromSha: string,
): Promise<GitHubResult<string>> {
  if (!isWriteRepo(owner, repo)) return { ok: false, error: "forbidden" };
  const res = await ghFetch(env, `/repos/${owner}/${repo}/git/refs`, {
    method: "POST",
    requireAuth: true,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ref: `refs/heads/${branch}`, sha: fromSha }),
  });
  if (!res.ok) return res;
  return { ok: true, data: branch };
}

export interface CommitFile {
  path: string;
  contents: string;
}

/**
 * One GraphQL createCommitOnBranch call (the trees-API PATCH /git/refs
 * path is flaky through the egress proxy — see AGENTS.md). expectedHeadOid
 * is the fast-forward guard: on a tip move the API errors and the caller
 * retries with a fresh head (error code tip_moved).
 */
export async function createCommitOnBranch(
  env: GitHubEnv,
  owner: string,
  repo: string,
  input: {
    branch: string;
    message: string;
    files: CommitFile[];
    expectedHeadOid: string;
  },
): Promise<GitHubResult<string>> {
  if (!isWriteRepo(owner, repo)) return { ok: false, error: "forbidden" };
  const b64 = (s: string) =>
    btoa(String.fromCharCode(...new TextEncoder().encode(s)));
  const res = await ghFetch(env, "/graphql", {
    method: "POST",
    requireAuth: true,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query:
        "mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}",
      variables: {
        input: {
          branch: { repositoryNameWithOwner: `${owner}/${repo}`, branchName: input.branch },
          message: { headline: input.message },
          fileChanges: {
            additions: input.files.map((f) => ({ path: f.path, contents: b64(f.contents) })),
          },
          expectedHeadOid: input.expectedHeadOid,
        },
      },
    }),
  });
  if (!res.ok) return res;
  const data = (await res.data.json()) as {
    data?: { createCommitOnBranch?: { commit?: { oid?: string } } };
    errors?: { message?: string }[];
  };
  const oid = data.data?.createCommitOnBranch?.commit?.oid;
  if (!oid) {
    const msg = (data.errors?.[0]?.message ?? "").toLowerCase();
    if (msg.includes("expectedheadoid") || msg.includes("head")) {
      return { ok: false, error: "tip_moved", detail: "branch tip moved" };
    }
    return { ok: false, error: "api_error" };
  }
  return { ok: true, data: oid };
}

export interface PullRequest {
  number: number;
  html_url: string;
}

export async function createPullRequest(
  env: GitHubEnv,
  owner: string,
  repo: string,
  input: { title: string; body: string; head: string; base: string },
): Promise<GitHubResult<PullRequest>> {
  if (!isWriteRepo(owner, repo)) return { ok: false, error: "forbidden" };
  const res = await ghFetch(env, `/repos/${owner}/${repo}/pulls`, {
    method: "POST",
    requireAuth: true,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!res.ok) return res;
  const data = (await res.data.json()) as { number?: number; html_url?: string };
  if (typeof data.number !== "number" || !data.html_url) {
    return { ok: false, error: "api_error" };
  }
  return { ok: true, data: { number: data.number, html_url: data.html_url } };
}

export interface CheckSummary {
  state: "pending" | "success" | "failure" | "unknown";
  /** Failed checks carry their output summary (the "read failing logs"
   * step of the loop, R1 shape — full Actions log download is a
   * follow-on, not R1). */
  checks: { name: string; status: string; conclusion: string | null; output?: string }[];
}

export async function getCheckSummary(
  env: GitHubEnv,
  owner: string,
  repo: string,
  ref: string,
): Promise<GitHubResult<CheckSummary>> {
  const res = await ghFetch(
    env,
    `/repos/${owner}/${repo}/commits/${encodeURIComponent(ref)}/check-runs?per_page=100`,
  );
  if (!res.ok) return res;
  const data = (await res.data.json()) as {
    total_count?: number;
    check_runs?: {
      name?: string;
      status?: string;
      conclusion?: string | null;
      output?: { title?: string | null; summary?: string | null };
    }[];
  };
  const checks = (data.check_runs ?? []).map((c) => ({
    name: c.name ?? "?",
    status: c.status ?? "?",
    conclusion: c.conclusion ?? null,
    output:
      c.conclusion === "failure" || c.conclusion === "cancelled" || c.conclusion === "timed_out"
        ? `${c.output?.title ?? ""}\n${c.output?.summary ?? ""}`.trim().slice(0, 500) || undefined
        : undefined,
  }));
  let state: CheckSummary["state"] = "unknown";
  if (checks.length === 0) {
    state = "unknown";
  } else if (checks.some((c) => c.status === "queued" || c.status === "in_progress")) {
    state = "pending";
  } else if (checks.every((c) => c.conclusion === "success" || c.conclusion === "skipped")) {
    state = "success";
  } else if (checks.some((c) => c.conclusion === "failure" || c.conclusion === "cancelled" || c.conclusion === "timed_out")) {
    state = "failure";
  } else {
    state = "pending";
  }
  return { ok: true, data: { state, checks } };
}
