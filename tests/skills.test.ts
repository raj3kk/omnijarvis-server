/**
 * Skills tests (Phase 3, stage 3d) — S-T1–S-T4 + S-T8–S-T10 + S-T12
 * + skills rate-limit budget unit test.
 *
 * S-T1 submit -> quarantined (scan pending when Render unset) · S-T2 unsafe
 * manifest block (approve -> 409 scan_findings, stays quarantined) ·
 * S-T3 approve + sign + verify · S-T4 library approved-only + plan caps ·
 * S-T8 scan render_not_configured (submit pending, approve 503, reject ok) ·
 * S-T9 review admin-only · S-T10 submit validation + auth · S-T12 library auth.
 * Render scan + Gemini upstreams are MOCKED (no real key in CI). Live
 * happy-path proof needs the Render deploy (parent-side, U-2).
 */
import { describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { genDeviceKey, genHubKey, type DeviceKey } from "./helpers";
import { handleRequest, type Env } from "../src/hub";
import { canonicalString } from "../src/crypto";
import { sortedJson } from "../src/docs";
import { RATE_LIMITS } from "../src/ratelimit";
import {
  manifestHash,
  validateSkillManifest,
  verifySkillSignature,
  type SkillManifest,
} from "../src/skills";

const FIXED_NOW = Date.UTC(2026, 10, 22, 1, 0, 0);
const RENDER_URL = "https://render-test.example.com";

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

async function seedTenant(db: FakeD1, opts: { id: string; plan?: string }): Promise<void> {
  await db
    .prepare(
      "INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(opts.id, `${opts.id}@example.com`, opts.plan ?? "pro", "byok", null, 0, FIXED_NOW)
    .run();
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string, publicKeyB64: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, publicKeyB64, FIXED_NOW, FIXED_NOW, 1)
    .run();
}

async function seedSkill(
  db: FakeD1,
  opts: { id: string; status: string; createdAt?: number; manifest?: Record<string, unknown> },
): Promise<void> {
  await db
    .prepare("INSERT INTO global_skills (id, manifest, status, submitted_by, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(
      opts.id,
      JSON.stringify(opts.manifest ?? validManifest({ name: opts.id })),
      opts.status,
      "t-1",
      opts.createdAt ?? FIXED_NOW,
    )
    .run();
}

/** Render /doc/scan mock: findings iff the uploaded code looks dangerous. */
function stubRenderScan(): void {
  vi.stubGlobal(
    "fetch",
    async (url: unknown, init?: { body?: unknown }) => {
      const u = String(url);
      if (u.startsWith(RENDER_URL) && u.endsWith("/doc/scan")) {
        const form = init?.body as FormData | undefined;
        const file = form?.get("file") as File | undefined;
        const text = file ? await file.text() : "";
        const dirty = text.includes("os.system") || text.includes("eval(") || text.includes("subprocess");
        const findings = dirty
          ? [{ line: 1, pattern: "os.system", detail: "os.system shell execution" }]
          : [];
        return new Response(JSON.stringify({ ok: true, findings }), { status: 200 });
      }
      return new Response(JSON.stringify({ error: "unexpected fetch " + u }), { status: 500 });
    },
  );
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

async function submitSigned(
  db: FakeD1,
  env: Env,
  key: DeviceKey,
  manifest: Record<string, unknown>,
): Promise<Response> {
  const body = { manifest };
  const headers = await signedHeaders(key, "dev-1", sortedJson(body));
  return handleRequest(
    new Request("https://hub/api/skills/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
    }),
    env,
  );
}

describe("validateSkillManifest (frozen schema)", () => {
  it("accepts a valid manifest (extra keys allowed)", () => {
    const r = validateSkillManifest(validManifest({ extra: "ok", code: "x = 1" }));
    expect(r.ok).toBe(true);
  });

  it("rejects missing name/version/trigger/steps + step without action", () => {
    expect(validateSkillManifest({})).toMatchObject({ ok: false });
    expect(validateSkillManifest(validManifest({ name: "" }))).toMatchObject({ ok: false });
    expect(validateSkillManifest(validManifest({ steps: [] }))).toMatchObject({ ok: false });
    expect(validateSkillManifest(validManifest({ steps: [{ text: "no action" }] }))).toMatchObject({
      ok: false,
    });
    expect(validateSkillManifest(validManifest({ code: 42 }))).toMatchObject({ ok: false });
  });
});

describe("S-T1 submit -> quarantined (scan pending when Render unset)", () => {
  it("signed device + code, no RENDER_WORKER_URL -> 200 quarantined, scan pending", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const res = await submitSigned(db, fakeEnv(db), key, validManifest({ code: "x = 1 + 1" }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(body.status).toBe("quarantined");
    expect((body.scan as Record<string, unknown>).status).toBe("pending");
    expect((body.scan as Record<string, unknown>).error).toBe("render_not_configured");
    const row = await db
      .prepare("SELECT status FROM global_skills WHERE id = ?")
      .bind(body.skill_id as string)
      .first<{ status: string }>();
    expect(row?.status).toBe("quarantined");
  });

  it("manifest without code -> scan clean/no_code, still quarantined", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const res = await handleRequest(
      new Request("https://hub/api/skills/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", manifest: validManifest() }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("quarantined");
    expect((body.scan as Record<string, unknown>).status).toBe("clean");
    expect((body.scan as Record<string, unknown>).note).toBe("no_code");
  });
});

describe("S-T2 unsafe manifest block", () => {
  it("dirty code submits quarantined; approve -> 409 scan_findings, no review row", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    stubRenderScan();
    const env = fakeEnv(db, { RENDER_WORKER_URL: RENDER_URL });
    const sub = await submitSigned(db, env, key, validManifest({ code: "import os\nos.system('id')" }));
    expect(sub.status).toBe(200);
    const subBody = (await sub.json()) as Record<string, unknown>;
    expect((subBody.scan as Record<string, unknown>).status).toBe("findings");
    const skillId = subBody.skill_id as string;
    const rev = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: skillId, decision: "approved", reason: "looks fine" }),
      }),
      env,
    );
    expect(rev.status).toBe(409);
    expect(((await rev.json()) as Record<string, unknown>).error).toBe("scan_findings");
    const row = await db
      .prepare("SELECT status FROM global_skills WHERE id = ?")
      .bind(skillId)
      .first<{ status: string }>();
    expect(row?.status).toBe("quarantined");
    const reviews = await db
      .prepare("SELECT COUNT(*) AS n FROM skill_reviews WHERE skill_id = ?")
      .bind(skillId)
      .first<{ n: number }>();
    expect(reviews?.n).toBe(0);
  });
});

describe("S-T3 approve + sign + verify", () => {
  it("clean scan + admin token -> approved, signature verifies, rows written", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const hubKey = await genHubKey();
    stubRenderScan();
    const env = fakeEnv(db, {
      RENDER_WORKER_URL: RENDER_URL,
      SKILL_SIGN_SECRET: hubKey.privateKeyB64,
      SKILL_SIGN_PUBLIC_KEY: hubKey.publicKeyB64,
    });
    const manifest = validManifest({ code: "x = 1 + 1" });
    const sub = await submitSigned(db, env, key, manifest);
    const skillId = ((await sub.json()) as Record<string, unknown>).skill_id as string;
    const rev = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: skillId, decision: "approved", reason: "reviewed ok" }),
      }),
      env,
    );
    expect(rev.status).toBe(200);
    const revBody = (await rev.json()) as Record<string, unknown>;
    expect(revBody.status).toBe("approved");
    expect(typeof revBody.signature).toBe("string");
    expect(revBody.public_key).toBe(hubKey.publicKeyB64);
    const hash = await manifestHash(manifest as unknown as SkillManifest);
    expect(await verifySkillSignature(hubKey.publicKeyB64, skillId, hash, revBody.signature as string)).toBe(true);
    expect(await verifySkillSignature(hubKey.publicKeyB64, skillId, "deadbeef", revBody.signature as string)).toBe(false);
    const sigRow = await db
      .prepare("SELECT signature FROM skill_signatures WHERE skill_id = ?")
      .bind(skillId)
      .first<{ signature: string }>();
    expect(sigRow?.signature).toBe(revBody.signature);
    const reviewRow = await db
      .prepare("SELECT decision, reviewer FROM skill_reviews WHERE skill_id = ?")
      .bind(skillId)
      .first<{ decision: string; reviewer: string }>();
    expect(reviewRow?.decision).toBe("approved");
    expect(reviewRow?.reviewer).toBe("admin");
  });

  it("public key derives from SKILL_SIGN_SECRET when env public key is absent", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const hubKey = await genHubKey();
    const env = fakeEnv(db, { SKILL_SIGN_SECRET: hubKey.privateKeyB64 });
    const res = await handleRequest(
      new Request("https://hub/api/skills/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", manifest: validManifest() }),
      }),
      env,
    );
    const skillId = ((await res.json()) as Record<string, unknown>).skill_id as string;
    const rev = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: skillId, decision: "approved" }),
      }),
      env,
    );
    expect(rev.status).toBe(200);
    expect(((await rev.json()) as Record<string, unknown>).public_key).toBe(hubKey.publicKeyB64);
  });

  it("reject writes a review row + status rejected, no signature row", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const env = fakeEnv(db);
    const res = await handleRequest(
      new Request("https://hub/api/skills/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", manifest: validManifest() }),
      }),
      env,
    );
    const skillId = ((await res.json()) as Record<string, unknown>).skill_id as string;
    const rev = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: skillId, decision: "rejected", reason: "unsafe pattern" }),
      }),
      env,
    );
    expect(rev.status).toBe(200);
    expect(((await rev.json()) as Record<string, unknown>).status).toBe("rejected");
    const sigRow = await db
      .prepare("SELECT skill_id FROM skill_signatures WHERE skill_id = ?")
      .bind(skillId)
      .first<{ skill_id: string }>();
    expect(sigRow).toBeNull();
  });
});

describe("S-T4 library approved-only + plan caps", () => {
  async function setupLibraryDb(): Promise<FakeD1> {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-free", plan: "free" });
    await seedTenant(db, { id: "t-pro", plan: "pro" });
    await seedSkill(db, { id: "skl-a", status: "approved", createdAt: FIXED_NOW });
    await seedSkill(db, { id: "skl-b", status: "approved", createdAt: FIXED_NOW + 1 });
    await seedSkill(db, { id: "skl-q", status: "quarantined", createdAt: FIXED_NOW + 2 });
    await seedSkill(db, { id: "skl-r", status: "rejected", createdAt: FIXED_NOW + 3 });
    return db;
  }

  it("Free -> 1 skill (earliest approved); Pro -> all approved; quarantined never listed", async () => {
    const db = await setupLibraryDb();
    const env = fakeEnv(db);
    const freeRes = await handleRequest(
      new Request("https://hub/api/skills/library?tenant_id=t-free", {
        method: "GET",
        headers: { "x-internal-secret": "test-internal" },
      }),
      env,
    );
    expect(freeRes.status).toBe(200);
    const freeBody = (await freeRes.json()) as Record<string, unknown>;
    expect(freeBody.plan_tier).toBe("free");
    expect(freeBody.count).toBe(1);
    expect(((freeBody.skills as Array<Record<string, unknown>>)[0]).id).toBe("skl-a");
    const proRes = await handleRequest(
      new Request("https://hub/api/skills/library?tenant_id=t-pro", {
        method: "GET",
        headers: { "x-internal-secret": "test-internal" },
      }),
      env,
    );
    const proBody = (await proRes.json()) as Record<string, unknown>;
    expect(proBody.count).toBe(2);
    const ids = (proBody.skills as Array<Record<string, unknown>>).map((s) => s.id);
    expect(ids).toEqual(["skl-a", "skl-b"]);
    expect(ids).not.toContain("skl-q");
    expect(ids).not.toContain("skl-r");
  });
});

describe("S-T8 scan render_not_configured", () => {
  it("approve with code + no Render -> 503 scan_unavailable; reject still allowed", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const hubKey = await genHubKey();
    const env = fakeEnv(db, {
      SKILL_SIGN_SECRET: hubKey.privateKeyB64,
      SKILL_SIGN_PUBLIC_KEY: hubKey.publicKeyB64,
    });
    const sub = await handleRequest(
      new Request("https://hub/api/skills/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", manifest: validManifest({ code: "x = 1" }) }),
      }),
      env,
    );
    const skillId = ((await sub.json()) as Record<string, unknown>).skill_id as string;
    const approve = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: skillId, decision: "approved" }),
      }),
      env,
    );
    expect(approve.status).toBe(503);
    expect(((await approve.json()) as Record<string, unknown>).error).toBe("scan_unavailable");
    const reject = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: skillId, decision: "rejected", reason: "no scan available" }),
      }),
      env,
    );
    expect(reject.status).toBe(200);
    expect(((await reject.json()) as Record<string, unknown>).status).toBe("rejected");
  });

  it("approve a no-code skill with no Render -> 200 (vacuous-clean)", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const hubKey = await genHubKey();
    const env = fakeEnv(db, {
      SKILL_SIGN_SECRET: hubKey.privateKeyB64,
      SKILL_SIGN_PUBLIC_KEY: hubKey.publicKeyB64,
    });
    const sub = await handleRequest(
      new Request("https://hub/api/skills/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", manifest: validManifest() }),
      }),
      env,
    );
    const skillId = ((await sub.json()) as Record<string, unknown>).skill_id as string;
    const rev = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: skillId, decision: "approved" }),
      }),
      env,
    );
    expect(rev.status).toBe(200);
  });
});

describe("S-T9 review admin-only", () => {
  it("no token -> 401; wrong token -> 401; reject without reason -> 400; unknown -> 404; re-decide -> 409", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const hubKey = await genHubKey();
    const env = fakeEnv(db, {
      SKILL_SIGN_SECRET: hubKey.privateKeyB64,
      SKILL_SIGN_PUBLIC_KEY: hubKey.publicKeyB64,
    });
    const sub = await handleRequest(
      new Request("https://hub/api/skills/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", manifest: validManifest() }),
      }),
      env,
    );
    const skillId = ((await sub.json()) as Record<string, unknown>).skill_id as string;
    const noToken = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ skill_id: skillId, decision: "approved" }),
      }),
      env,
    );
    expect(noToken.status).toBe(401);
    const wrongToken = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "nope" },
        body: JSON.stringify({ skill_id: skillId, decision: "approved" }),
      }),
      env,
    );
    expect(wrongToken.status).toBe(401);
    const noReason = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: skillId, decision: "rejected" }),
      }),
      env,
    );
    expect(noReason.status).toBe(400);
    const unknown = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: "skl-ghost", decision: "approved" }),
      }),
      env,
    );
    expect(unknown.status).toBe(404);
    const ok = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: skillId, decision: "approved" }),
      }),
      env,
    );
    expect(ok.status).toBe(200);
    const again = await handleRequest(
      new Request("https://hub/api/skills/review", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-token": "test-admin" },
        body: JSON.stringify({ skill_id: skillId, decision: "rejected", reason: "second look" }),
      }),
      env,
    );
    expect(again.status).toBe(409);
    expect(((await again.json()) as Record<string, unknown>).error).toBe("skill_not_quarantined");
  });
});

describe("S-T10 submit validation + auth", () => {
  it("bad manifest -> 400; bad sig -> 401; unpaired device -> 403; unknown tenant -> 404", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const env = fakeEnv(db);
    const badManifest = await handleRequest(
      new Request("https://hub/api/skills/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", manifest: { name: "x" } }),
      }),
      env,
    );
    expect(badManifest.status).toBe(400);
    expect(((await badManifest.json()) as Record<string, unknown>).error).toBe("bad_manifest");
    const body = { manifest: validManifest() };
    const badSigHeaders = await signedHeaders(key, "dev-1", sortedJson({ manifest: validManifest({ name: "other" }) }));
    const badSig = await handleRequest(
      new Request("https://hub/api/skills/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...badSigHeaders },
        body: JSON.stringify(body),
      }),
      env,
    );
    expect(badSig.status).toBe(401);
    const ghostHeaders = await signedHeaders(key, "dev-ghost", sortedJson(body));
    const ghost = await handleRequest(
      new Request("https://hub/api/skills/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...ghostHeaders },
        body: JSON.stringify(body),
      }),
      env,
    );
    expect(ghost.status).toBe(403);
    const unknownTenant = await handleRequest(
      new Request("https://hub/api/skills/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-ghost", manifest: validManifest() }),
      }),
      env,
    );
    expect(unknownTenant.status).toBe(404);
  });
});

describe("S-T12 library auth", () => {
  it("no auth -> 401; unpaired device -> 403; tenant mismatch -> 403", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    await seedTenant(db, { id: "t-2" });
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const env = fakeEnv(db);
    const noAuth = await handleRequest(
      new Request("https://hub/api/skills/library?tenant_id=t-1", { method: "GET" }),
      env,
    );
    expect(noAuth.status).toBe(401);
    const ghostHeaders = await signedHeaders(key, "dev-ghost", "library:t-1");
    const ghost = await handleRequest(
      new Request("https://hub/api/skills/library?tenant_id=t-1", {
        method: "GET",
        headers: ghostHeaders,
      }),
      env,
    );
    expect(ghost.status).toBe(403);
    const mismatchHeaders = await signedHeaders(key, "dev-1", "library:t-2");
    const mismatch = await handleRequest(
      new Request("https://hub/api/skills/library?tenant_id=t-2", {
        method: "GET",
        headers: mismatchHeaders,
      }),
      env,
    );
    expect(mismatch.status).toBe(403);
    const okHeaders = await signedHeaders(key, "dev-1", "library:t-1");
    const ok = await handleRequest(
      new Request("https://hub/api/skills/library?tenant_id=t-1", {
        method: "GET",
        headers: okHeaders,
      }),
      env,
    );
    expect(ok.status).toBe(200);
  });
});

describe("skills rate-limit budget", () => {
  it("skills = 30/min/tenant, memory = 60/min/tenant", () => {
    expect(RATE_LIMITS.skills).toEqual({ limit: 30, windowMs: 60_000 });
    expect(RATE_LIMITS.memory).toEqual({ limit: 60, windowMs: 60_000 });
  });
});
