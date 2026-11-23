import { describe, expect, it } from "vitest";
import { handleRequest, type Env } from "../src/hub";
import { FakeD1 } from "./fake-d1";

function fakeEnv(db: FakeD1, overrides: Partial<Env> = {}): Env {
  return {
    JARVIS_HUB: {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        fetch: async () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
      }),
    } as unknown as DurableObjectNamespace,
    DB: db as unknown as D1Database,
    INTERNAL_SECRET: "internal-secret-test",
    LLM_ADMIN_TOKEN: "admin-token-test",
    CRON_SECRET: "cron-secret-test",
    ...overrides,
  };
}

async function seedTenant(db: FakeD1, id: string): Promise<void> {
  await db
    .prepare("INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(id, `${id}@example.com`, "pro", "byok", Date.now())
    .run();
}

function post(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`https://hub${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

const INTERNAL = { "x-internal-secret": "internal-secret-test" };
const ADMIN = { "x-admin-token": "admin-token-test" };

describe("POST /api/escalate", () => {
  it("no auth -> 401", async () => {
    const db = new FakeD1();
    const res = await handleRequest(post("/api/escalate", { goal: "x", repo: "raj3kk/omnijarvis-server" }), fakeEnv(db));
    expect(res.status).toBe(401);
  });

  it("missing goal/repo -> 400", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const res = await handleRequest(post("/api/escalate", { goal: "", repo: "raj3kk/omnijarvis-server" }, INTERNAL), fakeEnv(db));
    expect(res.status).toBe(400);
  });

  it("valid escalation creates a dry-run job (no token in env) + stores context", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const res = await handleRequest(
      post(
        "/api/escalate",
        { tenant_id: "t-1", goal: "Fix the crash", repo: "raj3kk/omnijarvis-server", tried: "restarted", error: "NPE at line 12", need: "a fix" },
        INTERNAL,
      ),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(typeof body.job_id).toBe("string");
    expect(body.mode).toBe("dry-run");
    expect(body.status).toBe("received");
    const row = await db
      .prepare("SELECT transcript FROM main_jobs WHERE id = ?")
      .bind(String(body.job_id))
      .first<{ transcript: string }>();
    expect(row?.transcript).toContain("escalation");
    expect(row?.transcript).toContain("NPE at line 12");
  });
});

describe("GET /api/main/jobs/:id", () => {
  it("admin token reads any job; unknown id -> 404; no auth -> 401", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const created = await handleRequest(
      post("/api/escalate", { tenant_id: "t-1", goal: "x", repo: "raj3kk/omnijarvis-server" }, INTERNAL),
      fakeEnv(db),
    );
    const { job_id } = (await created.json()) as { job_id: string };
    const ok = await handleRequest(new Request(`https://hub/api/main/jobs/${job_id}`, { headers: ADMIN }), fakeEnv(db));
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as { job: { id: string; status: string; transcript: unknown[] } };
    expect(body.job.id).toBe(job_id);
    expect(body.job.status).toBe("received");
    expect(Array.isArray(body.job.transcript)).toBe(true);
    const missing = await handleRequest(new Request("https://hub/api/main/jobs/nope", { headers: ADMIN }), fakeEnv(db));
    expect(missing.status).toBe(404);
    const noAuth = await handleRequest(new Request(`https://hub/api/main/jobs/${job_id}`), fakeEnv(db));
    expect(noAuth.status).toBe(401);
  });
});

describe("POST /api/main/run + /api/main/step", () => {
  it("run without admin token -> 401; bad repo -> 400", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const noAuth = await handleRequest(
      post("/api/main/run", { tenant_id: "t-1", ask: "x", repo: "raj3kk/omnijarvis-server" }),
      fakeEnv(db),
    );
    expect(noAuth.status).toBe(401);
    const badRepo = await handleRequest(
      post("/api/main/run", { tenant_id: "t-1", ask: "x", repo: "nope" }, ADMIN),
      fakeEnv(db),
    );
    expect(badRepo.status).toBe(400);
  });

  it("run with snapshot but no LLM keys -> job created, step fails honest (byok_required, no network)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const res = await handleRequest(
      post(
        "/api/main/run",
        {
          tenant_id: "t-1",
          ask: "Add a line",
          repo: "raj3kk/omnijarvis-server",
          snapshot_files: [{ path: "README.md", content: "# Hi\n" }],
        },
        ADMIN,
      ),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(typeof body.job_id).toBe("string");
    // The architect call fails before any upstream fetch (no BYOK keys
    // on this tenant, no founder key in env) — the job stays received
    // and the note says so honestly.
    expect(body.status).toBe("received");
    expect(String(body.note)).toContain("byok_required");
  });

  it("step without internal secret -> 401; unknown job -> 404", async () => {
    const db = new FakeD1();
    const noAuth = await handleRequest(post("/api/main/step", { job_id: "x" }), fakeEnv(db));
    expect(noAuth.status).toBe(401);
    const missing = await handleRequest(post("/api/main/step", { job_id: "x" }, INTERNAL), fakeEnv(db));
    expect(missing.status).toBe(404);
  });
});

describe("POST /api/github/fetch + /api/github/pr-request", () => {
  it("fetch without auth -> 401; missing fields -> 400 (no network)", async () => {
    const db = new FakeD1();
    const noAuth = await handleRequest(
      post("/api/github/fetch", { owner: "raj3kk", repo: "jarvis-agent-app", path: "README.md" }),
      fakeEnv(db),
    );
    expect(noAuth.status).toBe(401);
    const bad = await handleRequest(post("/api/github/fetch", { owner: "raj3kk" }, INTERNAL), fakeEnv(db));
    expect(bad.status).toBe(400);
  });

  it("pr-request: non-Jarvis repo -> 403 repo_not_writable; Jarvis repo without token -> 503", async () => {
    const db = new FakeD1();
    const other = await handleRequest(
      post("/api/github/pr-request", { tenant_id: "t-1", owner: "someone", repo: "app", title: "x", head: "b" }, INTERNAL),
      fakeEnv(db),
    );
    expect(other.status).toBe(403);
    const body = (await other.json()) as Record<string, unknown>;
    expect(body.error).toBe("repo_not_writable");
    const jarvis = await handleRequest(
      post("/api/github/pr-request", { tenant_id: "t-1", owner: "raj3kk", repo: "jarvis-agent-app", title: "x", head: "b" }, INTERNAL),
      fakeEnv(db),
    );
    expect(jarvis.status).toBe(503);
    const body2 = (await jarvis.json()) as Record<string, unknown>;
    expect(body2.error).toBe("github_not_configured");
  });
});

describe("key_audit via DELETE /key + /groq-key (N-7 fix)", () => {
  it("DELETE /key writes a key_audit row (gemini/delete); DELETE /groq-key writes one (groq/delete)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const del = await handleRequest(
      new Request("https://hub/api/tenants/t-1/key", { method: "DELETE", headers: ADMIN }),
      fakeEnv(db),
    );
    expect(del.status).toBe(200);
    const delGroq = await handleRequest(
      new Request("https://hub/api/tenants/t-1/groq-key", { method: "DELETE", headers: ADMIN }),
      fakeEnv(db),
    );
    expect(delGroq.status).toBe(200);
    const rows = await db
      .prepare("SELECT key_kind, action, actor FROM key_audit WHERE tenant_id = ?")
      .bind("t-1")
      .all<{ key_kind: string; action: string; actor: string }>();
    expect(rows.results).toHaveLength(2);
    expect(rows.results.map((r) => `${r.key_kind}/${r.action}`).sort()).toEqual(["gemini/delete", "groq/delete"]);
    expect(rows.results.every((r) => r.actor === "admin")).toBe(true);
  });

  it("DELETE /key without admin token -> 401 (no audit row)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const res = await handleRequest(new Request("https://hub/api/tenants/t-1/key", { method: "DELETE" }), fakeEnv(db));
    expect(res.status).toBe(401);
    const rows = await db.prepare("SELECT * FROM key_audit WHERE tenant_id = ?").bind("t-1").all();
    expect(rows.results).toHaveLength(0);
  });
});
