/**
 * U12–U15 tests (R1, hub v17) — audit follow-ups from
 * EXISTING_PARITY_AUDIT.md §3.
 *
 * U12 captcha outcome link-back: /api/browser/resolve { solve_id, solved }
 * relinks a 'submitted' captcha_solves row to submitted_ok/submitted_wrong.
 * U13 skills submit cap (plan) + GET /api/skills/sync + FCM on approve.
 * U14 licence Worker /revoke + verify 403 licence_revoked (distinct from
 * 404 invalid_licence).
 * U15 diagnostics read endpoints: GET /api/traces + GET /api/cron/status
 * + GET /api/observability/status.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { FakeD1 } from "./fake-d1";
import { genDeviceKey, genHubKey, type DeviceKey } from "./helpers";
import { handleRequest, type Env } from "../src/hub";
import { canonicalString } from "../src/crypto";
import { sortedJson } from "../src/docs";
import { resetRateLimitFallback } from "../src/ratelimit";
import { linkSolveOutcome } from "../src/captcha";
import { insertTrace } from "../src/db";
import licenceWorker from "../licence-worker/worker.js";

const FIXED_NOW = Date.UTC(2026, 11, 23, 12, 0, 0);
const INTERNAL = { "x-internal-secret": "test-internal" };
const ADMIN = { "x-admin-token": "test-admin" };

beforeEach(() => {
  resetRateLimitFallback();
});

function fakeEnv(db: FakeD1, overrides: Partial<Env> = {}): Env {
  return {
    JARVIS_HUB: {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        fetch: async () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
      }),
    } as unknown as DurableObjectNamespace,
    DB: db as unknown as D1Database,
    INTERNAL_SECRET: "test-internal",
    CRON_SECRET: "test-cron",
    LLM_ADMIN_TOKEN: "test-admin",
    ...overrides,
  };
}

async function seedTenant(db: FakeD1, id: string, plan = "pro"): Promise<void> {
  await db
    .prepare(
      "INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id, `${id}@example.com`, plan, "byok", null, 0, FIXED_NOW)
    .run();
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string, publicKeyB64: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, publicKeyB64, FIXED_NOW, FIXED_NOW, 1)
    .run();
}

function validManifest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: "test-skill",
    version: "1.0.0",
    trigger: "on test",
    steps: [{ action: "reply", text: "hi" }],
    ...overrides,
  };
}

async function signedHeaders(key: DeviceKey, deviceId: string, payloadRaw: string) {
  const nonce = "aabbccddeeff00112233445566778899";
  const ts = Date.now();
  const sig = await key.sign(canonicalString(deviceId, nonce, ts, payloadRaw));
  return { "x-device-id": deviceId, "x-nonce": nonce, "x-ts": String(ts), "x-signature": sig };
}

async function callHub(
  db: FakeD1,
  method: string,
  path: string,
  body: unknown = null,
  headers: Record<string, string> = {},
  envOverrides: Partial<Env> = {},
): Promise<{ status: number; body: Record<string, any> }> {
  const res = await handleRequest(
    new Request(`https://hub${path}`, {
      method,
      headers: { "Content-Type": "application/json", ...headers },
      body: body === null ? null : JSON.stringify(body),
    }),
    fakeEnv(db, envOverrides),
  );
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function seedSolveRow(
  db: FakeD1,
  opts: { id: string; tenant?: string; outcome?: string; attempts?: number },
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO captcha_solves (id, tenant_id, device_id, task_id, site, challenge_type, model, confidence, outcome, attempts, latency_ms, flag_asserted, image_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(
      opts.id,
      opts.tenant ?? "t-1",
      "dev-1",
      "task-1",
      "example.com",
      "grid",
      "qwen/qwen3.8-27b",
      0.9,
      opts.outcome ?? "submitted",
      opts.attempts ?? 1,
      100,
      1,
      "deadbeef",
      FIXED_NOW,
    )
    .run();
}

async function solveOutcome(db: FakeD1, id: string): Promise<string | undefined> {
  const row = await db
    .prepare("SELECT outcome FROM captcha_solves WHERE id = ?")
    .bind(id)
    .first<{ outcome: string }>();
  return row?.outcome;
}

// --- Licence Worker call helper (mirrors tests/licence-worker.test.ts) ---
const LICENCE_ADMIN = "test-admin-token";
function licenceEnv(db: FakeD1) {
  return { DB: db as unknown as D1Database, LICENCE_ADMIN_TOKEN: LICENCE_ADMIN, PATTERNS_ADMIN_TOKEN: "test-patterns-admin" };
}
async function callLicence(
  db: FakeD1,
  method: string,
  path: string,
  body: unknown = null,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: Record<string, any> | null }> {
  const res = await licenceWorker.fetch(
    new Request(`https://licence.test${path}`, {
      method,
      headers: { "Content-Type": "application/json", "cf-connecting-ip": "1.2.3.4", ...headers },
      body: body === null ? null : JSON.stringify(body),
    }),
    licenceEnv(db),
  );
  const text = await res.text();
  let parsed: Record<string, any> | null = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    /* html status page */
  }
  return { status: res.status, body: parsed };
}
async function makeLicence(db: FakeD1, userId: string): Promise<string> {
  const r = await callLicence(db, "POST", "/api/licence/generate", { user_id: userId }, { "x-licence-admin-token": LICENCE_ADMIN });
  expect(r.status).toBe(200);
  return String(r.body!.licence.key);
}

describe("U12 linkSolveOutcome (unit)", () => {
  it("submitted -> submitted_ok on solved=true; second link is a no-op", async () => {
    const db = new FakeD1();
    await seedSolveRow(db, { id: "solve-a" });
    const first = await linkSolveOutcome(db, "solve-a", true, "t-1");
    expect(first).toEqual({ ok: true, linked: true });
    expect(await solveOutcome(db, "solve-a")).toBe("submitted_ok");
    const second = await linkSolveOutcome(db, "solve-a", true, "t-1");
    expect(second.linked).toBe(false);
    expect(await solveOutcome(db, "solve-a")).toBe("submitted_ok");
  });

  it("submitted -> submitted_wrong on solved=false; attempt-2 suffixed row links", async () => {
    const db = new FakeD1();
    await seedSolveRow(db, { id: "solve-b", outcome: "submitted_wrong", attempts: 1 });
    await seedSolveRow(db, { id: "solve-b-a2", outcome: "submitted", attempts: 2 });
    const r = await linkSolveOutcome(db, "solve-b", false, "t-1");
    expect(r.linked).toBe(true);
    expect(await solveOutcome(db, "solve-b-a2")).toBe("submitted_wrong");
    expect(await solveOutcome(db, "solve-b")).toBe("submitted_wrong");
  });

  it("non-submitted row never relinks; unknown solve_id links nothing", async () => {
    const db = new FakeD1();
    await seedSolveRow(db, { id: "solve-c", outcome: "low_confidence" });
    expect((await linkSolveOutcome(db, "solve-c", true, "t-1")).linked).toBe(false);
    expect(await solveOutcome(db, "solve-c")).toBe("low_confidence");
    expect((await linkSolveOutcome(db, "solve-missing", true, "t-1")).linked).toBe(false);
  });

  it("cross-tenant link is refused (tenant-scoped)", async () => {
    const db = new FakeD1();
    await seedSolveRow(db, { id: "solve-d", tenant: "t-1" });
    expect((await linkSolveOutcome(db, "solve-d", true, "t-2")).linked).toBe(false);
    expect(await solveOutcome(db, "solve-d")).toBe("submitted");
  });
});

describe("U12 POST /api/browser/resolve with solve_id", () => {
  it("internal-secret solve-only call links the outcome; unknown solve -> linked:false", async () => {
    const db = new FakeD1();
    await seedSolveRow(db, { id: "solve-e" });
    const r = await callHub(db, "POST", "/api/browser/resolve", { tenant_id: "t-1", solve_id: "solve-e", solved: true }, INTERNAL);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ ok: true, solve_id: "solve-e", solve_linked: true });
    expect(await solveOutcome(db, "solve-e")).toBe("submitted_ok");
    const missing = await callHub(db, "POST", "/api/browser/resolve", { tenant_id: "t-1", solve_id: "solve-nope", solved: true }, INTERNAL);
    expect(missing.status).toBe(200);
    expect(missing.body.solve_linked).toBe(false);
  });

  it("device-signed solve-only call links its own tenant; other tenant -> linked:false", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    await seedSolveRow(db, { id: "solve-f", tenant: "t-1" });
    await seedSolveRow(db, { id: "solve-g", tenant: "t-2" });
    const body = { solve_id: "solve-f", solved: false };
    const headers = await signedHeaders(key, "dev-1", sortedJson(body));
    const r = await callHub(db, "POST", "/api/browser/resolve", body, headers);
    expect(r.status).toBe(200);
    expect(r.body.solve_linked).toBe(true);
    expect(await solveOutcome(db, "solve-f")).toBe("submitted_wrong");
    const other = { solve_id: "solve-g", solved: true };
    const headers2 = await signedHeaders(key, "dev-1", sortedJson(other));
    const r2 = await callHub(db, "POST", "/api/browser/resolve", other, headers2);
    expect(r2.status).toBe(200);
    expect(r2.body.solve_linked).toBe(false);
    expect(await solveOutcome(db, "solve-g")).toBe("submitted");
  });

  it("neither task_id nor solve_id -> 400; no auth -> 401", async () => {
    const db = new FakeD1();
    const bad = await callHub(db, "POST", "/api/browser/resolve", { solved: true }, INTERNAL);
    expect(bad.status).toBe(400);
    const noAuth = await callHub(db, "POST", "/api/browser/resolve", { solve_id: "solve-e", solved: true });
    expect(noAuth.status).toBe(401);
  });
});

describe("U13 skills submit cap", () => {
  it("free tenant: 1st submit ok, 2nd -> 403 skills_submit_cap", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-free", "free");
    const first = await callHub(db, "POST", "/api/skills/submit", { tenant_id: "t-free", manifest: validManifest({ name: "s1" }) }, INTERNAL);
    expect(first.status).toBe(200);
    const second = await callHub(db, "POST", "/api/skills/submit", { tenant_id: "t-free", manifest: validManifest({ name: "s2" }) }, INTERNAL);
    expect(second.status).toBe(403);
    expect(second.body).toMatchObject({ error: "skills_submit_cap", plan_tier: "free", active: 1 });
  });

  it("pro tenant: two submits both ok (uncapped)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-pro", "pro");
    for (const name of ["p1", "p2"]) {
      const r = await callHub(db, "POST", "/api/skills/submit", { tenant_id: "t-pro", manifest: validManifest({ name }) }, INTERNAL);
      expect(r.status).toBe(200);
    }
  });

  it("rejected skills do not count toward the cap", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-free2", "free");
    await db
      .prepare("INSERT INTO global_skills (id, manifest, status, submitted_by, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind("sk-rej", JSON.stringify(validManifest({ name: "rej" })), "rejected", "t-free2", FIXED_NOW)
      .run();
    const first = await callHub(db, "POST", "/api/skills/submit", { tenant_id: "t-free2", manifest: validManifest({ name: "s1" }) }, INTERNAL);
    expect(first.status).toBe(200);
    const second = await callHub(db, "POST", "/api/skills/submit", { tenant_id: "t-free2", manifest: validManifest({ name: "s2" }) }, INTERNAL);
    expect(second.status).toBe(403);
  });
});

describe("U13 GET /api/skills/sync", () => {
  async function seedApproved(db: FakeD1, id: string, createdAt: number): Promise<void> {
    await db
      .prepare("INSERT INTO global_skills (id, manifest, status, submitted_by, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(id, JSON.stringify(validManifest({ name: id })), "approved", "t-1", createdAt)
      .run();
  }

  it("returns approved skills after since; internal-secret + device-signed", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    await seedApproved(db, "sk-old", 1000);
    await seedApproved(db, "sk-new", 3000);
    const all = await callHub(db, "GET", "/api/skills/sync?tenant_id=t-1&since=0", null, INTERNAL);
    expect(all.status).toBe(200);
    expect(all.body.count).toBe(2);
    const after = await callHub(db, "GET", "/api/skills/sync?tenant_id=t-1&since=2000", null, INTERNAL);
    expect(after.status).toBe(200);
    expect(after.body.count).toBe(1);
    expect(after.body.skills[0].id).toBe("sk-new");
    expect(after.body.skills[0].created_at).toBe(3000);
    // Device-signed with the frozen payload `sync:<tenant_id>:<since>`.
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const headers = await signedHeaders(key, "dev-1", "sync:t-1:2000");
    const signed = await callHub(db, "GET", "/api/skills/sync?tenant_id=t-1&since=2000", null, headers);
    expect(signed.status).toBe(200);
    expect(signed.body.count).toBe(1);
    const noAuth = await callHub(db, "GET", "/api/skills/sync?tenant_id=t-1&since=0");
    expect(noAuth.status).toBe(401);
  });
});

describe("U13 approve -> FCM notice to the submitter's latest device", () => {
  it("approved skill records an fcm_sends row kind=skill_approved (FCM unconfigured in test)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const hubKey = await genHubKey();
    const env = fakeEnv(db, { SKILL_SIGN_SECRET: hubKey.privateKeyB64, SKILL_SIGN_PUBLIC_KEY: hubKey.publicKeyB64 });
    // No-code manifest: scan is clean/no_code without any fetch stub.
    const sub = await callHub(db, "POST", "/api/skills/submit", { tenant_id: "t-1", manifest: validManifest() }, INTERNAL);
    expect(sub.status).toBe(200);
    const skillId = String(sub.body.skill_id);
    const res = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: skillId, decision: "approved", reason: "reviewed ok" }),
      }),
      env,
    );
    expect(res.status).toBe(200);
    const fcm = await db
      .prepare("SELECT kind, status, device_id FROM fcm_sends WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1")
      .bind("t-1")
      .first<{ kind: string; status: string; device_id: string }>();
    expect(fcm).toMatchObject({ kind: "skill_approved", status: "not_configured", device_id: "dev-1" });
  });
});

describe("U14 licence Worker /revoke + verify 403 revoked", () => {
  it("revoke -> verify 403 licence_revoked; re-revoke idempotent; unknown stays 404", async () => {
    const db = new FakeD1();
    const key = await makeLicence(db, "user-1@example.com");
    const verified = await callLicence(db, "POST", "/api/licence/verify", { key, device_id: "dev-1" });
    expect(verified.status).toBe(200);
    expect(verified.body).toMatchObject({ ok: true, bound: true });
    const revoked = await callLicence(db, "POST", "/api/licence/revoke", { key }, { "x-licence-admin-token": LICENCE_ADMIN });
    expect(revoked.status).toBe(200);
    expect(revoked.body).toMatchObject({ ok: true, revoked: true });
    const after = await callLicence(db, "POST", "/api/licence/verify", { key, device_id: "dev-1" });
    expect(after.status).toBe(403);
    expect(after.body).toMatchObject({ ok: false, error: "licence_revoked" });
    const again = await callLicence(db, "POST", "/api/licence/revoke", { key }, { "x-licence-admin-token": LICENCE_ADMIN });
    expect(again.status).toBe(200);
    expect(again.body).toMatchObject({ ok: true, revoked: true, already: true });
    const unknown = await callLicence(db, "POST", "/api/licence/verify", { key: "XXXX-XXXX-XXXX-XXXX", device_id: "dev-1" });
    expect(unknown.status).toBe(404);
    expect(unknown.body).toMatchObject({ ok: false, error: "invalid_licence" });
  });

  it("revoke: non-admin -> 403; missing key -> 400; unknown key -> 404", async () => {
    const db = new FakeD1();
    const noAdmin = await callLicence(db, "POST", "/api/licence/revoke", { key: "XXXX-XXXX-XXXX-XXXX" });
    expect(noAdmin.status).toBe(403);
    expect(noAdmin.body).toMatchObject({ error: "admin_forbidden" });
    const noKey = await callLicence(db, "POST", "/api/licence/revoke", {}, { "x-licence-admin-token": LICENCE_ADMIN });
    expect(noKey.status).toBe(400);
    const unknown = await callLicence(db, "POST", "/api/licence/revoke", { key: "XXXX-XXXX-XXXX-XXXX" }, { "x-licence-admin-token": LICENCE_ADMIN });
    expect(unknown.status).toBe(404);
    expect(unknown.body).toMatchObject({ error: "invalid_licence" });
  });
});

describe("U15 GET /api/traces", () => {
  it("tenant-scoped, newest first; kind filter + limit; cross-tenant 403; no auth 401", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    await insertTrace(db, "t-1", "dev-1", "llm_call", { model: "a" });
    await insertTrace(db, "t-1", "dev-1", "skill_submit", { skill_id: "s1" });
    await insertTrace(db, "t-1", "dev-1", "llm_call", { model: "b" });
    await insertTrace(db, "t-2", "dev-9", "llm_call", { model: "c" });
    const all = await callHub(db, "GET", "/api/traces?tenant_id=t-1", null, INTERNAL);
    expect(all.status).toBe(200);
    expect(all.body.count).toBe(3);
    expect(all.body.traces[0].kind).toBe("llm_call");
    expect(all.body.traces[0].detail).toMatchObject({ model: "b" });
    const filtered = await callHub(db, "GET", "/api/traces?tenant_id=t-1&kind=skill_submit", null, INTERNAL);
    expect(filtered.body.count).toBe(1);
    const limited = await callHub(db, "GET", "/api/traces?tenant_id=t-1&limit=1", null, INTERNAL);
    expect(limited.body.count).toBe(1);
    // Device-signed with the frozen payload `traces:<tenant_id>:<kind>:<limit>`.
    const headers = await signedHeaders(key, "dev-1", "traces:t-1::50");
    const signed = await callHub(db, "GET", "/api/traces?tenant_id=t-1", null, headers);
    expect(signed.status).toBe(200);
    expect(signed.body.count).toBe(3);
    const cross = await signedHeaders(key, "dev-1", "traces:t-2::50");
    const crossRes = await callHub(db, "GET", "/api/traces?tenant_id=t-2", null, cross);
    expect(crossRes.status).toBe(403);
    const noAuth = await callHub(db, "GET", "/api/traces?tenant_id=t-1");
    expect(noAuth.status).toBe(401);
  });
});

describe("U15 GET /api/cron/status + /api/observability/status", () => {
  it("cron status: last tick + 300s cadence + due jobs; admin-only", async () => {
    const db = new FakeD1();
    const now = Date.now();
    await db
      .prepare("INSERT INTO traces (tenant_id, device_id, kind, detail, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind("system", "hub", "cron_trigger", JSON.stringify({ source: "cf-cron", cron: "*/5 * * * *" }), now - 300_000)
      .run();
    await db
      .prepare("INSERT INTO traces (tenant_id, device_id, kind, detail, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind("system", "hub", "cron_trigger", JSON.stringify({ source: "cf-cron", cron: "*/5 * * * *" }), now)
      .run();
    await db
      .prepare("INSERT INTO scheduled_jobs (id, tenant_id, device_id, cron_expr, command, enabled, last_run_at, next_run_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .bind("job-1", "t-1", "dev-1", "0 8 * * *", "test", 1, null, now - 60_000, now)
      .run();
    const r = await callHub(db, "GET", "/api/cron/status", null, ADMIN);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      last_tick_at: now,
      last_tick_source: "cf-cron",
      cadence_s: 300,
      ticks_last_hour: 2,
      enabled_jobs: 1,
      due_jobs: 1,
      total_jobs: 1,
    });
    const noAuth = await callHub(db, "GET", "/api/cron/status");
    expect(noAuth.status).toBe(401);
  });

  it("observability status: flags only; all false when unconfigured, all true when set", async () => {
    const db = new FakeD1();
    const off = await callHub(db, "GET", "/api/observability/status", null, ADMIN);
    expect(off.status).toBe(200);
    expect(off.body).toMatchObject({
      langfuse: { configured: false, host: null },
      sentry: { configured: false },
      upstash: { configured: false },
    });
    const on = await callHub(db, "GET", "/api/observability/status", null, ADMIN, {
      LANGFUSE_PUBLIC_KEY: "pk-test",
      LANGFUSE_SECRET_KEY: "sk-test",
      SENTRY_DSN: "https://abc123@o0.ingest.sentry.io/1234567",
      UPSTASH_REDIS_REST_URL: "https://example.upstash.io",
      UPSTASH_REDIS_REST_TOKEN: "tok-test",
    });
    expect(on.status).toBe(200);
    expect(on.body).toMatchObject({
      langfuse: { configured: true, host: "https://cloud.langfuse.com" },
      sentry: { configured: true },
      upstash: { configured: true },
    });
    const noAuth = await callHub(db, "GET", "/api/observability/status");
    expect(noAuth.status).toBe(401);
  });
});
