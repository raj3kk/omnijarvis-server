import { describe, expect, it } from "vitest";
import { FakeD1 } from "./fake-d1";
import { bytesToBase64 } from "../src/crypto";
import { encryptTenantKey, importMasterKey } from "../src/keyvault";
import { routeLlm, type RouterDeps } from "../src/router";
import { insertKeyAudit } from "../src/db";
import {
  MAIN_MAX_CALLS_PER_JOB,
  buildPrBody,
  buildRepoMap,
  countJobsToday,
  createMainJob,
  formatTrajectoryForPr,
  getMainJob,
  listPendingMainJobs,
  parsePlan,
  parseTranscript,
  runMainStep,
  scanEdit,
  stepMainJobs,
  type MainEnv,
  type MainJob,
  type MainPlan,
} from "../src/main";

const FIXED_NOW = Date.UTC(2026, 10, 23, 12, 0, 0);

async function makeMasterKeyB64(): Promise<string> {
  const k = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
  return bytesToBase64(raw);
}

async function seedTenantWithKey(db: FakeD1, id: string, masterB64: string, plan = "pro"): Promise<void> {
  const master = await importMasterKey(masterB64);
  const enc = await encryptTenantKey(master, "TEST-GEMINI-KEY-1");
  await db
    .prepare("INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(id, `${id}@example.com`, plan, "byok", enc, FIXED_NOW)
    .run();
}

function okGemini(text: string, inTok = 100, outTok = 20): Response {
  return new Response(
    JSON.stringify({
      candidates: [{ content: { parts: [{ text }] }, finishReason: "STOP" }],
      usageMetadata: { promptTokenCount: inTok, candidatesTokenCount: outTok },
    }),
    { status: 200 },
  );
}

/**
 * One mock fetch for everything the Main loop touches: Gemini (queue of
 * reply texts, in call order), GitHub (canned REST/GraphQL), and the
 * render worker /doc/scan (findings queue). Anything else 404s.
 */
function makeMockFetch(opts: {
  geminiQueue?: string[];
  github?: (url: string, init?: RequestInit) => Response | null;
  scanFindings?: { line: number; pattern: string; detail: string }[][];
}): { fetchFn: typeof fetch; calls: { url: string; body: string; headers: string }[] } {
  const calls: { url: string; body: string; headers: string }[] = [];
  const geminiQueue = [...(opts.geminiQueue ?? [])];
  const scanQueue = [...(opts.scanFindings ?? [])];
  const fetchFn = (async (url: unknown, init?: RequestInit) => {
    const u = String(url);
    const body = typeof init?.body === "string" ? init.body : "";
    const headers = JSON.stringify(init?.headers ?? {});
    calls.push({ url: u, body, headers });
    if (u.includes("generativelanguage.googleapis.com")) {
      const text = geminiQueue.shift() ?? "[]";
      return okGemini(text);
    }
    if (u.includes("api.github.com")) {
      const res = opts.github?.(u, init);
      if (res) return res;
      return new Response(JSON.stringify({ message: "Not Found" }), { status: 404 });
    }
    if (u.includes("/doc/scan")) {
      const findings = scanQueue.shift() ?? [];
      return new Response(JSON.stringify({ findings }), { status: 200 });
    }
    return new Response(JSON.stringify({ message: "Not Found" }), { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchFn, calls };
}

function mainEnv(db: FakeD1, fetchFn: typeof fetch, extra: Partial<MainEnv> = {}): MainEnv {
  return {
    DB: db,
    fetchFn,
    nowMs: () => FIXED_NOW,
    ...extra,
  };
}

// Tests that run the LLM loop must pass the master key (KEY_ENC_SECRET)
// — routeLlm decrypts the tenant's BYOK key with it, exactly like the
// live hub env does. Without it the loop fails key_vault_not_configured.
function mainEnvWithKeys(db: FakeD1, fetchFn: typeof fetch, masterB64: string, extra: Partial<MainEnv> = {}): MainEnv {
  return mainEnv(db, fetchFn, { KEY_ENC_SECRET: masterB64, ...extra });
}

const SNAPSHOT = [
  { path: "README.md", content: "# Jarvis\n\nHello.\n" },
  { path: "src/Main.kt", content: "package com.jarvis\n\nclass Main {\n  fun run() {}\n}\n" },
];

const PLAN_JSON = JSON.stringify({
  steps: [{ id: "s1", title: "Add Troubleshooting section", file: "README.md", action: "Append a Troubleshooting section to README.md" }],
});

describe("createMainJob: validation + budgets", () => {
  it("empty ask / bad repo / unknown tenant fail closed", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const { fetchFn } = makeMockFetch({});
    const env = mainEnv(db, fetchFn);
    expect((await createMainJob(env, { tenantId: "t-1", ask: "", repo: "raj3kk/omnijarvis-server" })).ok).toBe(false);
    const badRepo = await createMainJob(env, { tenantId: "t-1", ask: "do x", repo: "not-a-slug" });
    expect(badRepo.ok).toBe(false);
    if (!badRepo.ok) expect(badRepo.error).toBe("invalid_repo");
    const noTenant = await createMainJob(env, { tenantId: "nope", ask: "do x", repo: "raj3kk/omnijarvis-server" });
    expect(noTenant.ok).toBe(false);
    if (!noTenant.ok) expect(noTenant.error).toBe("tenant_not_found");
  });

  it("daily cap: 5 jobs/tenant/day (flagged default)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const { fetchFn } = makeMockFetch({});
    const env = mainEnv(db, fetchFn);
    for (let i = 0; i < 5; i++) {
      const r = await createMainJob(env, { tenantId: "t-1", ask: `job ${i}`, repo: "raj3kk/omnijarvis-server" });
      expect(r.ok).toBe(true);
    }
    expect(await countJobsToday(db, "t-1", FIXED_NOW)).toBe(5);
    const sixth = await createMainJob(env, { tenantId: "t-1", ask: "job 5", repo: "raj3kk/omnijarvis-server" });
    expect(sixth.ok).toBe(false);
    if (!sixth.ok) expect(sixth.error).toBe("daily_job_cap");
  });

  it("forbidden snapshot path fails closed (never touch secrets)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const { fetchFn } = makeMockFetch({});
    const env = mainEnv(db, fetchFn);
    const r = await createMainJob(env, {
      tenantId: "t-1",
      ask: "do x",
      repo: "raj3kk/omnijarvis-server",
      snapshotFiles: [{ path: ".secrets/keys.env", content: "x" }],
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("forbidden_path");
  });

  it("mode is dry-run without a token, github with one", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const { fetchFn } = makeMockFetch({});
    const dry = await createMainJob(mainEnv(db, fetchFn), { tenantId: "t-1", ask: "x", repo: "raj3kk/omnijarvis-server" });
    expect(dry.ok && dry.job.mode).toBe("dry-run");
    const live = await createMainJob(mainEnv(db, fetchFn, { GITHUB_ADMIN_TOKEN: "ghp_test" }), { tenantId: "t-1", ask: "y", repo: "raj3kk/omnijarvis-server" });
    expect(live.ok && live.job.mode).toBe("github");
  });
});

describe("repo map (line-based v1)", () => {
  it("snapshot mode: ranks keyword files first, extracts symbols, caps", async () => {
    const db = new FakeD1();
    const { fetchFn } = makeMockFetch({});
    const env = mainEnv(db, fetchFn);
    const res = await buildRepoMap(env, "raj3kk", "omnijarvis-server", "main", "Main run function", SNAPSHOT);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.data.files).toBe(2);
      expect(res.data.symbols).toBeGreaterThan(0);
      expect(res.data.map).toContain("src/Main.kt");
      expect(res.data.map).toContain("Main");
      expect(res.data.truncated).toBe(false);
    }
  });
});

describe("scan before commit", () => {
  it("secret-shaped value in an edit is blocked", async () => {
    const db = new FakeD1();
    const { fetchFn } = makeMockFetch({});
    const env = mainEnv(db, fetchFn);
    const v = await scanEdit(env, "src/x.kt", 'val key = "gsk_abcdefghij1234567890"');
    expect(v.verdict).toBe("blocked");
    expect(v.findings.join(" ")).toContain("groq_key");
  });

  it("forbidden path is blocked", async () => {
    const db = new FakeD1();
    const { fetchFn } = makeMockFetch({});
    const env = mainEnv(db, fetchFn);
    const v = await scanEdit(env, "app/google-services.json", "{}");
    expect(v.verdict).toBe("blocked");
  });

  it("python file with findings is blocked; clean python is clean", async () => {
    const db = new FakeD1();
    const { fetchFn } = makeMockFetch({
      scanFindings: [[{ line: 3, pattern: "os.system", detail: "shell" }], []],
    });
    const env = mainEnv(db, fetchFn, { WORKER_URL: "https://render.test" });
    const bad = await scanEdit(env, "x.py", "import os\nos.system('x')");
    expect(bad.verdict).toBe("blocked");
    const good = await scanEdit(env, "x.py", "x = 1\n");
    expect(good.verdict).toBe("clean");
  });

  it("render worker down -> scan_unavailable (never a fake clean, never a block)", async () => {
    const db = new FakeD1();
    const { fetchFn } = makeMockFetch({});
    const env = mainEnv(db, fetchFn); // no WORKER_URL
    const v = await scanEdit(env, "x.py", "x = 1\n");
    expect(v.verdict).toBe("scan_unavailable");
  });
});

describe("N3 carve-out: main_executor is not stopped by the 5-calls/turn cap", () => {
  it("main_executor routes on a turn that already has 5 calls; quick_command refuses", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    // 5 real calls already recorded on this turn id.
    for (let i = 0; i < 5; i++) {
      await db
        .prepare("INSERT INTO llm_usage (tenant_id, turn_id, model, attempted_models, input_tokens, output_tokens, cost_usd_micro, billing_mode, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind("t-1", "main-job-1-architect-6", "gemini-3.5-flash-lite", "[]", 10, 5, 0, "byok", "ok", FIXED_NOW)
        .run();
    }
    const { fetchFn } = makeMockFetch({ geminiQueue: ["ok"] });
    const deps: RouterDeps = {
      db,
      fetchFn,
      sleepFn: async () => {},
      nowMs: () => FIXED_NOW,
      masterKeyB64: master,
    };
    const main = await routeLlm(deps, {
      tenant_id: "t-1",
      turn_id: "main-job-1-architect-6",
      kind: "main_executor",
      messages: [{ role: "user", text: "hi" }],
    });
    expect(main.ok).toBe(true);
    expect(main.text).toBe("ok");
    const quick = await routeLlm(deps, {
      tenant_id: "t-1",
      turn_id: "main-job-1-architect-6",
      kind: "quick_command",
      messages: [{ role: "user", text: "hi" }],
    });
    expect(quick.ok).toBe(false);
    expect(quick.error_code).toBe("turn_calls_cap");
  });
});

describe("dry-run full loop (no token): localize -> edit -> validate -> queued PR", () => {
  it("a 1-step job ends blocked_token with the patch + PR body queued", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const { fetchFn } = makeMockFetch({
      geminiQueue: [PLAN_JSON, "# Jarvis\n\nHello.\n\n## Troubleshooting\n\nRestart the app.\n"],
    });
    const env = mainEnvWithKeys(db, fetchFn, master);
    const created = await createMainJob(env, {
      tenantId: "t-1",
      ask: "Add a Troubleshooting section to README.md",
      repo: "raj3kk/omnijarvis-server",
      snapshotFiles: SNAPSHOT,
    });
    expect(created.ok).toBe(true);
    if (!created.ok) throw new Error("create failed");
    const jobId = created.job.id;
    const s1 = await runMainStep(env, jobId);
    if (!s1.ok) throw new Error("s1 failed: " + s1.error);
    expect(s1.job.status).toBe("planned");
    const s2 = await runMainStep(env, jobId);
    if (!s2.ok) throw new Error("s2 failed: " + s2.error);
    // Edit -> all steps done -> validate (dry-run skips CI) -> PR queued.
    expect(s2.job.status).toBe("blocked_token");
    expect(s2.job.error_code).toBe("github_token_not_configured");
    expect(s2.job.error).toContain("GITHUB_ADMIN_TOKEN");
    expect(s2.job.llm_calls).toBe(2);
    expect(s2.job.scan_verdict).toBe("clean");
    const entries = parseTranscript(s2.job);
    expect(entries.some((e) => e.phase === "patch" && e.patch?.path === "README.md")).toBe(true);
    expect(entries.some((e) => e.phase === "pr-queued")).toBe(true);
    // A blocked_token job does not step again without a token.
    const again = await runMainStep(env, jobId);
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.error).toBe("github_token_not_configured");
  });

  it("architect asks a question -> parked with need_info", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const { fetchFn } = makeMockFetch({ geminiQueue: [JSON.stringify({ question: "Kaunsa file badalna hai?" })] });
    const env = mainEnvWithKeys(db, fetchFn, master);
    const created = await createMainJob(env, { tenantId: "t-1", ask: "kuch karo", repo: "raj3kk/omnijarvis-server", snapshotFiles: SNAPSHOT });
    expect(created.ok).toBe(true);
    if (!created.ok) throw new Error("create failed");
    const s1 = await runMainStep(env, created.job.id);
    if (!s1.ok) throw new Error("s1 failed: " + s1.error);
    expect(s1.job.status).toBe("parked");
    expect(s1.job.error_code).toBe("need_info");
    expect(s1.job.error).toContain("Kaunsa file");
  });

  it("architect returns garbage twice -> parked (no crash, no fake plan)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const { fetchFn } = makeMockFetch({ geminiQueue: ["not json at all", "still not json"] });
    const env = mainEnvWithKeys(db, fetchFn, master);
    const created = await createMainJob(env, { tenantId: "t-1", ask: "kuch karo", repo: "raj3kk/omnijarvis-server", snapshotFiles: SNAPSHOT });
    expect(created.ok).toBe(true);
    if (!created.ok) throw new Error("create failed");
    const s1 = await runMainStep(env, created.job.id);
    if (!s1.ok) throw new Error("s1 failed: " + s1.error);
    expect(s1.job.status).toBe("parked");
  });
});

describe("budgets: job LLM cap + max steps", () => {
  it("llm_calls at the 40 cap -> partial with job_llm_budget_exhausted", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const { fetchFn } = makeMockFetch({ geminiQueue: ["x"] });
    const env = mainEnvWithKeys(db, fetchFn, master);
    const created = await createMainJob(env, { tenantId: "t-1", ask: "x", repo: "raj3kk/omnijarvis-server", snapshotFiles: SNAPSHOT });
    expect(created.ok).toBe(true);
    if (!created.ok) throw new Error("create failed");
    await db.prepare("UPDATE main_jobs SET llm_calls = ? WHERE id = ?").bind(MAIN_MAX_CALLS_PER_JOB, created.job.id).run();
    const s = await runMainStep(env, created.job.id);
    if (!s.ok) throw new Error("step failed: " + s.error);
    expect(s.job.status).toBe("partial");
    expect(s.job.error_code).toBe("job_llm_budget_exhausted");
  });

  it("10th step completes on a non-terminal job -> partial with max_steps", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const twoStepPlan = JSON.stringify({
      steps: [
        { id: "s1", title: "Step one", file: "README.md", action: "Append one line" },
        { id: "s2", title: "Step two", file: "src/Main.kt", action: "Add a comment" },
      ],
      done: [],
    });
    const { fetchFn } = makeMockFetch({ geminiQueue: ["# Jarvis\n\nHello.\n\nLine one.\n"] });
    const env = mainEnvWithKeys(db, fetchFn, master);
    const created = await createMainJob(env, { tenantId: "t-1", ask: "two steps", repo: "raj3kk/omnijarvis-server", snapshotFiles: SNAPSHOT });
    expect(created.ok).toBe(true);
    if (!created.ok) throw new Error("create failed");
    await db
      .prepare("UPDATE main_jobs SET plan = ?, status = ?, steps_used = ? WHERE id = ?")
      .bind(twoStepPlan, "editing", 9, created.job.id)
      .run();
    const s = await runMainStep(env, created.job.id);
    if (!s.ok) throw new Error("step failed: " + s.error);
    expect(s.job.steps_used).toBe(10);
    expect(s.job.status).toBe("partial");
    expect(s.job.error_code).toBe("max_steps");
  });
});

describe("stepMainJobs: tick stepper + retry backoff", () => {
  it("steps up to 2 pending jobs, skips a job in retry backoff", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const { fetchFn } = makeMockFetch({ geminiQueue: [PLAN_JSON] });
    const env = mainEnvWithKeys(db, fetchFn, master);
    const j1 = await createMainJob(env, { tenantId: "t-1", ask: "job one", repo: "raj3kk/omnijarvis-server", snapshotFiles: SNAPSHOT });
    const j2 = await createMainJob(env, { tenantId: "t-1", ask: "job two", repo: "raj3kk/omnijarvis-server", snapshotFiles: SNAPSHOT });
    expect(j1.ok && j2.ok).toBe(true);
    if (!j1.ok || !j2.ok) throw new Error("create failed");
    // j2 gets a fresh retry entry (backoff) — the tick must skip it.
    const job2 = await getMainJob(db, j2.job.id);
    if (!job2) throw new Error("no job2");
    const entries = parseTranscript(job2);
    entries.push({ at: FIXED_NOW, phase: "retry", note: "transient" });
    await db.prepare("UPDATE main_jobs SET transcript = ? WHERE id = ?").bind(JSON.stringify(entries), j2.job.id).run();
    const results = await stepMainJobs(env);
    expect(results.length).toBe(1);
    if (!results[0].ok) throw new Error("step failed: " + results[0].error);
    const after1 = await getMainJob(db, j1.job.id);
    expect(after1?.status).toBe("planned");
    const after2 = await getMainJob(db, j2.job.id);
    expect(after2?.status).toBe("received");
    expect(await listPendingMainJobs(db, 10)).toHaveLength(2);
  });
});

describe("key_audit (N-7 fix)", () => {
  it("insertKeyAudit records the fact, never a key value", async () => {
    const db = new FakeD1();
    const id = await insertKeyAudit(db, { tenantId: "t-1", keyKind: "gemini", action: "set" });
    expect(typeof id).toBe("string");
    const row = await db
      .prepare("SELECT * FROM key_audit WHERE id = ?")
      .bind(id)
      .first<{ tenant_id: string; key_kind: string; action: string; actor: string }>();
    expect(row?.tenant_id).toBe("t-1");
    expect(row?.key_kind).toBe("gemini");
    expect(row?.action).toBe("set");
    expect(row?.actor).toBe("admin");
  });
});

describe("mainexec-robustness (§5.2 #9): scan-feedback loop + per-step retries", () => {
  const PY_SNAPSHOT = [{ path: "x.py", content: "import os\nos.system('ls')\n" }];
  const PY_PLAN = JSON.stringify({
    steps: [{ id: "s1", title: "Replace os.system", file: "x.py", action: "Replace the os.system call with a safe alternative" }],
  });

  it("scan-blocked findings reach the editor prompt on the retry (not just the transcript)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    const { fetchFn, calls } = makeMockFetch({
      geminiQueue: [
        PY_PLAN,
        "import os\nos.system('ls')\n# changed comment\n",
        "import subprocess\nsubprocess.run(['ls'])\n",
      ],
      scanFindings: [[{ line: 3, pattern: "os.system", detail: "shell — use subprocess" }], []],
    });
    const env = mainEnvWithKeys(db, fetchFn, master, { WORKER_URL: "https://render.test" });
    const created = await createMainJob(env, {
      tenantId: "t-1",
      ask: "Replace the os.system call in x.py",
      repo: "raj3kk/omnijarvis-server",
      snapshotFiles: PY_SNAPSHOT,
    });
    expect(created.ok).toBe(true);
    if (!created.ok) throw new Error("create failed");
    const jobId = created.job.id;

    const s1 = await runMainStep(env, jobId);
    if (!s1.ok) throw new Error("s1 failed: " + s1.error);
    expect(s1.job.status).toBe("planned");

    // Editor attempt 1: content still trips the scan -> retryable, and
    // the findings are stored ON the step for the next attempt.
    const s2 = await runMainStep(env, jobId);
    expect(s2.ok).toBe(false);
    if (s2.ok) throw new Error("s2 should have been scan-blocked");
    expect(s2.error).toBe("scan_blocked");
    expect(s2.retryable).toBe(true);
    const mid = await getMainJob(db, jobId);
    const midPlan = mid ? parsePlan(mid) : null;
    expect(midPlan?.steps[0].retries).toBe(1);
    expect(midPlan?.steps[0].feedback).toContain("os.system");
    expect(midPlan?.steps[0].feedback).toContain("shell — use subprocess");
    // The job-wide CI-fix budget is untouched by the scan retry.
    expect(mid?.retries_used).toBe(0);

    // Editor attempt 2: the prompt must carry the feedback block.
    const s3 = await runMainStep(env, jobId);
    if (!s3.ok) throw new Error("s3 failed: " + s3.error);
    expect(s3.job.status).toBe("blocked_token");
    expect(s3.job.scan_verdict).toBe("clean");
    const geminiCalls = calls.filter((c) => c.url.includes("generativelanguage.googleapis.com"));
    expect(geminiCalls.length).toBe(3);
    expect(geminiCalls[2].body).toContain("Previous attempt was rejected by the scan");
    expect(geminiCalls[2].body).toContain("shell — use subprocess");
    // Feedback is consumed: the stored plan has no feedback left.
    const finalPlan = parsePlan(s3.job);
    expect(finalPlan?.steps[0].feedback).toBeUndefined();
    // Tool routing: every tool call left a trajectory entry.
    const entries = parseTranscript(s3.job);
    expect(entries.some((e) => e.phase === "tool:repo_map")).toBe(true);
    expect(entries.some((e) => e.phase === "tool:read_file")).toBe(true);
    expect(entries.some((e) => e.phase === "tool:scan_edit")).toBe(true);
  });

  it("editor no-change retries are per-step: 3rd no-change drops the step, CI budget untouched", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    // No trailing newline in the snapshot: stripFences trims the editor
    // output, so equality needs the trimmed form to match exactly.
    const nochangeSnapshot = [{ path: "README.md", content: "# Jarvis\n\nHello." }];
    const same = "# Jarvis\n\nHello.\n";
    const { fetchFn } = makeMockFetch({ geminiQueue: [PLAN_JSON, same, same, same] });
    const env = mainEnvWithKeys(db, fetchFn, master);
    const created = await createMainJob(env, {
      tenantId: "t-1",
      ask: "Append a Troubleshooting section to README.md",
      repo: "raj3kk/omnijarvis-server",
      snapshotFiles: nochangeSnapshot,
    });
    expect(created.ok).toBe(true);
    if (!created.ok) throw new Error("create failed");
    const jobId = created.job.id;

    const s1 = await runMainStep(env, jobId);
    if (!s1.ok) throw new Error("s1 failed: " + s1.error);
    expect(s1.job.status).toBe("planned");

    const r1 = await runMainStep(env, jobId);
    expect(r1.ok).toBe(false);
    if (r1.ok) throw new Error("r1 should be a retryable no-change");
    expect(r1.error).toBe("editor_no_change");
    const r2 = await runMainStep(env, jobId);
    expect(r2.ok).toBe(false);
    if (r2.ok) throw new Error("r2 should be a retryable no-change");
    expect(r2.error).toBe("editor_no_change");

    // 3rd no-change exceeds the per-step budget -> step dropped. The
    // drop returns done (pre-existing shape: the NEXT invocation
    // chains into validate), so one more step finishes the job.
    const r3 = await runMainStep(env, jobId);
    if (!r3.ok) throw new Error("r3 failed: " + r3.error);
    expect(parsePlan(r3.job)?.done).toContain("s1");
    expect(parsePlan(r3.job)?.steps[0].retries).toBe(3);
    expect(r3.job.retries_used).toBe(0);
    const r4 = await runMainStep(env, jobId);
    if (!r4.ok) throw new Error("r4 failed: " + r4.error);
    expect(r4.job.status).toBe("blocked_token");
    const plan = parsePlan(r4.job);
    expect(plan?.done).toContain("s1");
    expect(plan?.steps[0].retries).toBe(3);
    expect(r4.job.retries_used).toBe(0);
  });
});

describe("mainexec-robustness (§5.2 #15): PR body carries the trajectory", () => {
  function fakeJob(transcript: unknown[]): MainJob {
    return {
      id: "main-test-1",
      tenant_id: "t-1",
      device_id: null,
      ask: "Add a Troubleshooting section",
      repo: "raj3kk/omnijarvis-server",
      base_branch: "main",
      branch: "agent-mode/test-1",
      status: "validating",
      mode: "github",
      plan: null,
      transcript: JSON.stringify(transcript),
      pr_url: null,
      pr_number: null,
      ci_status: "success",
      scan_verdict: "clean",
      llm_calls: 2,
      steps_used: 2,
      retries_used: 0,
      error: null,
      error_code: null,
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    };
  }

  it("buildPrBody includes a Trajectory section with tool + LLM entries in order", () => {
    const job = fakeJob([
      { at: FIXED_NOW, phase: "created", note: "Job created (github mode)" },
      { at: FIXED_NOW, phase: "tool:repo_map", note: "repo=raj3kk/omnijarvis-server, ref=main → ok (108 files, 12 symbols)" },
      { at: FIXED_NOW, phase: "llm:architect", note: "model gemini-3.5-flash-lite — 100 in / 20 out" },
      { at: FIXED_NOW, phase: "tool:scan_edit", note: "path=README.md → ok (clean)" },
      { at: FIXED_NOW, phase: "commit", note: "committed README.md on agent-mode/test-1 (abc1234)" },
      { at: FIXED_NOW, phase: "tool:ci_poll", note: "repo=raj3kk/omnijarvis-server, ref=agent-mode/test-1 → ok (success (2 check(s)))" },
    ]);
    const plan: MainPlan = {
      steps: [{ id: "s1", title: "Add Troubleshooting section", file: "README.md", action: "Append" }],
      done: ["s1"],
    };
    const body = buildPrBody(job, plan);
    expect(body).toContain("## Trajectory");
    expect(body).toContain("- tool:repo_map:");
    expect(body).toContain("- llm:architect:");
    expect(body).toContain("- tool:ci_poll:");
    expect(body).toContain("## Evidence");
    expect(body).toContain("- Scan: clean");
    expect(body).toContain("- CI: success");
    // Trajectory comes before the reviewer notes.
    expect(body.indexOf("## Trajectory")).toBeLessThan(body.indexOf("## Reviewer notes"));
  });

  it("formatTrajectoryForPr keeps only the last 30 entries", () => {
    const entries = Array.from({ length: 40 }, (_, i) => ({
      at: FIXED_NOW,
      phase: `tool:step-${i}`,
      note: `entry ${i}`,
    }));
    const out = formatTrajectoryForPr(fakeJob(entries));
    const lines = out.split("\n");
    expect(lines).toHaveLength(30);
    expect(lines[0]).toContain("entry 10");
    expect(lines[29]).toContain("entry 39");
    expect(formatTrajectoryForPr(fakeJob([]))).toBe("(no trajectory recorded)");
  });
});
