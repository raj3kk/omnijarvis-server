import { describe, expect, it } from "vitest";
import {
  createBranch,
  createCommitOnBranch,
  createPullRequest,
  getCheckSummary,
  getFileContent,
  isValidRepoSlug,
  isWriteRepo,
  listTree,
  parseRepoSlug,
} from "../src/github";

type Handler = (url: string, init?: RequestInit) => Response | null;

function mockFetch(handler: Handler): typeof fetch {
  return (async (url: unknown, init?: RequestInit) => {
    const res = handler(String(url), init);
    if (res) return res;
    return new Response(JSON.stringify({ message: "Not Found" }), { status: 404 });
  }) as unknown as typeof fetch;
}

function jsonRes(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

const TOKEN_ENV = { GITHUB_ADMIN_TOKEN: "ghp_test_token_value" };

describe("github client: scope + token", () => {
  it("writes to a non-Jarvis repo are forbidden (never touch user repos)", async () => {
    const env = { ...TOKEN_ENV, fetchFn: mockFetch(() => jsonRes({})) };
    expect(isWriteRepo("someuser", "my-app")).toBe(false);
    expect(isWriteRepo("raj3kk", "jarvis-agent-app")).toBe(true);
    expect(isWriteRepo("raj3kk", "omnijarvis-server")).toBe(true);
    const branch = await createBranch(env, "someuser", "my-app", "agent-mode/x", "abc");
    expect(branch.ok).toBe(false);
    if (!branch.ok) expect(branch.error).toBe("forbidden");
    const commit = await createCommitOnBranch(env, "someuser", "my-app", {
      branch: "agent-mode/x",
      message: "x",
      files: [{ path: "a.txt", contents: "hi" }],
      expectedHeadOid: "abc",
    });
    expect(commit.ok).toBe(false);
    if (!commit.ok) expect(commit.error).toBe("forbidden");
    const pr = await createPullRequest(env, "someuser", "my-app", {
      title: "x",
      body: "y",
      head: "agent-mode/x",
      base: "main",
    });
    expect(pr.ok).toBe(false);
    if (!pr.ok) expect(pr.error).toBe("forbidden");
  });

  it("writes without a token return github_not_configured (no invented token)", async () => {
    const env = { fetchFn: mockFetch(() => jsonRes({})) };
    const branch = await createBranch(env, "raj3kk", "jarvis-agent-app", "agent-mode/x", "abc");
    expect(branch.ok).toBe(false);
    if (!branch.ok) expect(branch.error).toBe("github_not_configured");
    const pr = await createPullRequest(env, "raj3kk", "jarvis-agent-app", {
      title: "x",
      body: "y",
      head: "agent-mode/x",
      base: "main",
    });
    expect(pr.ok).toBe(false);
    if (!pr.ok) expect(pr.error).toBe("github_not_configured");
  });

  it("public-repo reads work WITHOUT a token (unauthenticated, no Authorization header)", async () => {
    const seen: { url: string; auth: string | null }[] = [];
    const fetchFn = mockFetch((url, init) => {
      const headers = new Headers(init?.headers);
      seen.push({ url, auth: headers.get("Authorization") });
      if (url.includes("/contents/README.md")) {
        return jsonRes({
          type: "file",
          encoding: "base64",
          content: Buffer.from("# hello").toString("base64"),
          sha: "abc123",
          size: 7,
        });
      }
      return null;
    });
    const env = { fetchFn };
    const file = await getFileContent(env, "raj3kk", "jarvis-agent-app", "README.md");
    expect(file.ok).toBe(true);
    if (file.ok) {
      expect(file.data?.content).toBe("# hello");
      expect(file.data?.sha).toBe("abc123");
    }
    expect(seen.length).toBe(1);
    expect(seen[0].auth).toBeNull();
  });

  it("reads WITH a token send the Authorization header (never in a log/body)", async () => {
    const seen: { auth: string | null }[] = [];
    const fetchFn = mockFetch((_url, init) => {
      seen.push({ auth: new Headers(init?.headers).get("Authorization") });
      return jsonRes({ tree: [], truncated: false });
    });
    const env = { ...TOKEN_ENV, fetchFn };
    const tree = await listTree(env, "raj3kk", "jarvis-agent-app", "abc");
    expect(tree.ok).toBe(true);
    expect(seen[0].auth).toBe("Bearer ghp_test_token_value");
  });

  it("parseRepoSlug / isValidRepoSlug", () => {
    expect(parseRepoSlug("raj3kk/jarvis-agent-app")).toEqual({ owner: "raj3kk", name: "jarvis-agent-app" });
    expect(parseRepoSlug("not-a-slug")).toBeNull();
    expect(parseRepoSlug("a/b/c")).toBeNull();
    expect(isValidRepoSlug("raj3kk/jarvis-agent-app")).toBe(true);
    expect(isValidRepoSlug("")).toBe(false);
  });
});

describe("github client: reads", () => {
  it("getFileContent: 404 -> null (file does not exist)", async () => {
    const env = { ...TOKEN_ENV, fetchFn: mockFetch(() => null) };
    const file = await getFileContent(env, "raj3kk", "jarvis-agent-app", "NOPE.md");
    expect(file.ok).toBe(true);
    if (file.ok) expect(file.data).toBeNull();
  });

  it("getFileContent: oversize file -> too_large", async () => {
    const env = {
      ...TOKEN_ENV,
      fetchFn: mockFetch(() =>
        jsonRes({ type: "file", encoding: "base64", content: "eA==", sha: "s", size: 600 * 1024 }),
      ),
    };
    const file = await getFileContent(env, "raj3kk", "jarvis-agent-app", "big.bin");
    expect(file.ok).toBe(false);
    if (!file.ok) expect(file.error).toBe("too_large");
  });

  it("listTree: blob entries only, truncated flag passes through", async () => {
    const env = {
      ...TOKEN_ENV,
      fetchFn: mockFetch(() =>
        jsonRes({
          tree: [
            { path: "a.ts", type: "blob", size: 10 },
            { path: "dir", type: "tree" },
            { path: "b.py", type: "blob", size: 20 },
          ],
          truncated: true,
        }),
      ),
    };
    const tree = await listTree(env, "raj3kk", "omnijarvis-server", "abc");
    expect(tree.ok).toBe(true);
    if (tree.ok) {
      expect(tree.data.entries.map((e) => e.path)).toEqual(["a.ts", "b.py"]);
      expect(tree.data.truncated).toBe(true);
    }
  });
});

describe("github client: writes + CI", () => {
  it("createCommitOnBranch sends base64 contents + expectedHeadOid, returns oid", async () => {
    let sentBody = "";
    const fetchFn = mockFetch((url, init) => {
      if (url.endsWith("/graphql")) {
        sentBody = String(init?.body ?? "");
        return jsonRes({ data: { createCommitOnBranch: { commit: { oid: "def456" } } } });
      }
      return null;
    });
    const env = { ...TOKEN_ENV, fetchFn };
    const res = await createCommitOnBranch(env, "raj3kk", "omnijarvis-server", {
      branch: "agent-mode/test-abc123",
      message: "Main Executor: test",
      files: [{ path: "x.md", contents: "# hi" }],
      expectedHeadOid: "abc",
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.data).toBe("def456");
    const parsed = JSON.parse(sentBody) as { variables: { input: { expectedHeadOid: string; fileChanges: { additions: { path: string; contents: string }[] } } } };
    expect(parsed.variables.input.expectedHeadOid).toBe("abc");
    expect(parsed.variables.input.fileChanges.additions[0].path).toBe("x.md");
    expect(Buffer.from(parsed.variables.input.fileChanges.additions[0].contents, "base64").toString()).toBe("# hi");
  });

  it("createCommitOnBranch: head-mismatch error -> tip_moved (caller retries)", async () => {
    const env = {
      ...TOKEN_ENV,
      fetchFn: mockFetch(() =>
        jsonRes({ errors: [{ message: "ExpectedHeadOid does not match the current HEAD" }] }),
      ),
    };
    const res = await createCommitOnBranch(env, "raj3kk", "omnijarvis-server", {
      branch: "agent-mode/test",
      message: "x",
      files: [{ path: "x.md", contents: "hi" }],
      expectedHeadOid: "stale",
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("tip_moved");
  });

  it("createPullRequest returns number + url", async () => {
    const env = {
      ...TOKEN_ENV,
      fetchFn: mockFetch(() => jsonRes({ number: 42, html_url: "https://github.com/raj3kk/omnijarvis-server/pull/42" })),
    };
    const pr = await createPullRequest(env, "raj3kk", "omnijarvis-server", {
      title: "Main Executor: test",
      body: "evidence",
      head: "agent-mode/test",
      base: "main",
    });
    expect(pr.ok).toBe(true);
    if (pr.ok) {
      expect(pr.data.number).toBe(42);
      expect(pr.data.html_url).toContain("/pull/42");
    }
  });

  it("getCheckSummary: pending / success / failure + failing output", async () => {
    const mk = (runs: unknown[]) => ({
      ...TOKEN_ENV,
      fetchFn: mockFetch(() => jsonRes({ total_count: runs.length, check_runs: runs })),
    });
    const pending = await getCheckSummary(mk([{ name: "CI", status: "in_progress", conclusion: null }]), "raj3kk", "omnijarvis-server", "abc");
    expect(pending.ok && pending.data.state).toBe("pending");
    const success = await getCheckSummary(
      mk([
        { name: "test", status: "completed", conclusion: "success" },
        { name: "lint", status: "completed", conclusion: "skipped" },
      ]),
      "raj3kk",
      "omnijarvis-server",
      "abc",
    );
    expect(success.ok && success.data.state).toBe("success");
    const failed = await getCheckSummary(
      mk([
        { name: "test", status: "completed", conclusion: "failure", output: { title: "1 failed", summary: "src/x.ts:12 boom" } },
        { name: "lint", status: "completed", conclusion: "success" },
      ]),
      "raj3kk",
      "omnijarvis-server",
      "abc",
    );
    expect(failed.ok && failed.data.state).toBe("failure");
    if (failed.ok) {
      expect(failed.data.checks[0].output).toContain("src/x.ts:12 boom");
      expect(failed.data.checks[1].output).toBeUndefined();
    }
    const none = await getCheckSummary(mk([]), "raj3kk", "omnijarvis-server", "abc");
    expect(none.ok && none.data.state).toBe("unknown");
  });

  it("rate limit 403 (remaining 0) -> rate_limited, not forbidden", async () => {
    const env = {
      ...TOKEN_ENV,
      fetchFn: mockFetch(
        () =>
          new Response(JSON.stringify({ message: "rate limited" }), {
            status: 403,
            headers: { "x-ratelimit-remaining": "0" },
          }),
      ),
    };
    const file = await getFileContent(env, "raj3kk", "jarvis-agent-app", "README.md");
    expect(file.ok).toBe(false);
    if (!file.ok) expect(file.error).toBe("rate_limited");
  });
});
