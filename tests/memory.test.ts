/**
 * Memory tests (Phase 3, stage 3d) — S-T5–S-T7 + S-T11 + memory auth/errors.
 *
 * S-T5 memory store/search cosine · S-T6 wipe (D1 + Qdrant field) ·
 * S-T7 Qdrant not configured · S-T11 memory cap 500 (FIFO eviction).
 * Gemini embeddings are MOCKED (keyword -> fixed vector; no real key in CI).
 * Live happy-path proof needs a test BYOK key (parent-side, U-1).
 */
import { describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { genDeviceKey, type DeviceKey } from "./helpers";
import { handleRequest, type Env } from "../src/hub";
import { canonicalString } from "../src/crypto";
import { sortedJson } from "../src/docs";
import { encryptTenantKey, importMasterKey } from "../src/keyvault";
import { bytesToBase64 } from "../src/crypto";
import {
  cosineSimilarity,
  qdrantQuery,
  qdrantUpsert,
  MEMORY_CAP_PER_TENANT,
} from "../src/memory";

const FIXED_NOW = Date.UTC(2026, 10, 22, 1, 0, 0);

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

async function makeMasterKeyB64(): Promise<string> {
  const k = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
  return bytesToBase64(raw);
}

async function seedTenant(
  db: FakeD1,
  opts: { id: string; plan?: string; keyEnc?: string | null },
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(opts.id, `${opts.id}@example.com`, opts.plan ?? "pro", "byok", opts.keyEnc ?? null, 0, FIXED_NOW)
    .run();
}

async function seedTenantWithKey(db: FakeD1, id: string, masterB64: string, plan = "pro"): Promise<void> {
  const master = await importMasterKey(masterB64);
  const enc = await encryptTenantKey(master, "TEST-GEMINI-KEY-1");
  await seedTenant(db, { id, plan, keyEnc: enc });
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string, publicKeyB64: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, publicKeyB64, FIXED_NOW, FIXED_NOW, 1)
    .run();
}

/** Gemini embedContent mock: keyword -> fixed vector (deterministic cosine). */
function stubEmbed(): void {
  vi.stubGlobal(
    "fetch",
    async (url: unknown, init?: { body?: unknown }) => {
      const u = String(url);
      if (u.includes("generativelanguage.googleapis.com") && u.includes(":embedContent")) {
        const parsed = JSON.parse(String(init?.body ?? "{}")) as {
          content?: { parts?: Array<{ text?: string }> };
        };
        const text = parsed.content?.parts?.[0]?.text ?? "";
        let values: number[];
        if (/\bcat/i.test(text)) values = [1, 0];
        else if (/\bdog/i.test(text)) values = [0, 1];
        else values = [0.7071, 0.7071];
        return new Response(
          JSON.stringify({ embedding: { values }, usageMetadata: { promptTokenCount: 5 } }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({ error: "unexpected fetch " + u }), { status: 500 });
    },
  );
}

async function signedHeaders(key: DeviceKey, deviceId: string, payloadRaw: string) {
  const nonce = "aabbccddeeff00112233445566778899";
  const ts = Date.now();
  const sig = await key.sign(canonicalString(deviceId, nonce, ts, payloadRaw));
  return { "x-device-id": deviceId, "x-nonce": nonce, "x-ts": String(ts), "x-signature": sig };
}

async function postMemory(
  env: Env,
  path: string,
  body: Record<string, unknown>,
  headers: Record<string, string> = { "x-internal-secret": "test-internal" },
): Promise<Response> {
  return handleRequest(
    new Request(`https://hub${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
    }),
    env,
  );
}

describe("cosineSimilarity (pure)", () => {
  it("identical -> 1, orthogonal -> 0, opposite -> -1, zero-vector -> 0", () => {
    expect(cosineSimilarity([1, 0], [1, 0])).toBeCloseTo(1);
    expect(cosineSimilarity([1, 0], [0, 1])).toBeCloseTo(0);
    expect(cosineSimilarity([1, 0], [-1, 0])).toBeCloseTo(-1);
    expect(cosineSimilarity([0, 0], [1, 0])).toBe(0);
    expect(cosineSimilarity([], [1, 0])).toBe(0);
    expect(cosineSimilarity([1, 1], [1, 1])).toBeCloseTo(1);
  });
});

describe("S-T5 memory store/search cosine", () => {
  it("store 3 -> search 'cats' ranks the cat memories first (score 1, dog last 0)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    stubEmbed();
    const env = fakeEnv(db, { KEY_ENC_SECRET: master });
    for (const content of ["cats are cute", "dogs bark loudly", "cats sleep all day"]) {
      const res = await postMemory(env, "/api/memory/store", { tenant_id: "t-1", content });
      expect(res.status).toBe(200);
      expect(((await res.json()) as Record<string, unknown>).ok).toBe(true);
    }
    const search = await postMemory(env, "/api/memory/search", {
      tenant_id: "t-1",
      query: "cats",
      top_k: 3,
    });
    expect(search.status).toBe(200);
    const body = (await search.json()) as {
      results: Array<{ content: string; score: number; kind: string }>;
    };
    expect(body.results.length).toBe(3);
    expect(body.results[0].score).toBeCloseTo(1);
    expect(body.results[1].score).toBeCloseTo(1);
    expect(body.results[2].score).toBeCloseTo(0);
    expect(body.results[2].content).toBe("dogs bark loudly");
    expect(body.results[0].kind).toBe("fact");
  });

  it("search is tenant-isolated (other tenant's memories never leak)", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    await seedTenantWithKey(db, "t-2", master);
    stubEmbed();
    const env = fakeEnv(db, { KEY_ENC_SECRET: master });
    await postMemory(env, "/api/memory/store", { tenant_id: "t-1", content: "cats are cute" });
    const search = await postMemory(env, "/api/memory/search", { tenant_id: "t-2", query: "cats" });
    expect(search.status).toBe(200);
    expect(((await search.json()) as { results: unknown[] }).results).toEqual([]);
  });
});

describe("S-T6 wipe (D1 + Qdrant field)", () => {
  it("store 2 -> wipe -> deleted 2, qdrant not_configured, search empty", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    stubEmbed();
    const env = fakeEnv(db, { KEY_ENC_SECRET: master });
    await postMemory(env, "/api/memory/store", { tenant_id: "t-1", content: "cats are cute" });
    await postMemory(env, "/api/memory/store", { tenant_id: "t-1", content: "dogs bark loudly" });
    const wipe = await postMemory(env, "/api/memory/wipe", { tenant_id: "t-1" });
    expect(wipe.status).toBe(200);
    const wipeBody = (await wipe.json()) as Record<string, unknown>;
    expect(wipeBody.deleted).toBe(2);
    expect(wipeBody.qdrant).toBe("not_configured");
    const count = await db
      .prepare("SELECT COUNT(*) AS n FROM memories WHERE tenant_id = ?")
      .bind("t-1")
      .first<{ n: number }>();
    expect(count?.n).toBe(0);
    const search = await postMemory(env, "/api/memory/search", { tenant_id: "t-1", query: "cats" });
    expect(((await search.json()) as { results: unknown[] }).results).toEqual([]);
  });
});

describe("S-T7 Qdrant not configured", () => {
  it("empty env -> qdrant_not_configured; configured env -> qdrant_not_live (never fake success)", async () => {
    expect(await qdrantUpsert({}, "t-1", 1, [1, 0])).toEqual({ ok: false, error: "qdrant_not_configured" });
    expect(await qdrantQuery({}, "t-1", [1, 0], 5)).toEqual({ ok: false, error: "qdrant_not_configured" });
    const live = { QDRANT_URL: "https://qdrant-test.example.com", QDRANT_API_KEY: "test-key" };
    expect(await qdrantUpsert(live, "t-1", 1, [1, 0])).toEqual({ ok: false, error: "qdrant_not_live" });
    expect(await qdrantQuery(live, "t-1", [1, 0], 5)).toEqual({ ok: false, error: "qdrant_not_live" });
  });
});

describe("S-T11 memory cap 500 (FIFO eviction)", () => {
  it("500 seeded -> store 501st -> count still 500, oldest gone, newest present", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    stubEmbed();
    const env = fakeEnv(db, { KEY_ENC_SECRET: master });
    expect(MEMORY_CAP_PER_TENANT).toBe(500);
    for (let i = 0; i < 500; i++) {
      await db
        .prepare("INSERT INTO memories (tenant_id, content, embedding, kind, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind("t-1", `memory ${i}`, JSON.stringify([1, 0]), "fact", FIXED_NOW + i)
        .run();
    }
    const res = await postMemory(env, "/api/memory/store", { tenant_id: "t-1", content: "cats newest" });
    expect(res.status).toBe(200);
    const count = await db
      .prepare("SELECT COUNT(*) AS n FROM memories WHERE tenant_id = ?")
      .bind("t-1")
      .first<{ n: number }>();
    expect(count?.n).toBe(500);
    const oldest = await db
      .prepare("SELECT id FROM memories WHERE tenant_id = ? AND content = ?")
      .bind("t-1", "memory 0")
      .first<{ id: number }>();
    expect(oldest).toBeNull();
    const newest = await db
      .prepare("SELECT id FROM memories WHERE tenant_id = ? AND content = ?")
      .bind("t-1", "cats newest")
      .first<{ id: number }>();
    expect(newest).not.toBeNull();
  });
});

describe("memory auth + error paths", () => {
  it("no auth -> 401; unpaired device -> 403; empty content -> 400; no BYOK key -> 402", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenant(db, { id: "t-nokey" });
    await seedTenantWithKey(db, "t-1", master);
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    stubEmbed();
    const env = fakeEnv(db, { KEY_ENC_SECRET: master });
    const noAuth = await handleRequest(
      new Request("https://hub/api/memory/store", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenant_id: "t-1", content: "cats" }),
      }),
      env,
    );
    expect(noAuth.status).toBe(401);
    const ghostHeaders = await signedHeaders(key, "dev-ghost", sortedJson({ content: "cats" }));
    const ghost = await handleRequest(
      new Request("https://hub/api/memory/store", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...ghostHeaders },
        body: JSON.stringify({ content: "cats" }),
      }),
      env,
    );
    expect(ghost.status).toBe(403);
    const empty = await postMemory(env, "/api/memory/store", { tenant_id: "t-1", content: "  " });
    expect(empty.status).toBe(400);
    const noKey = await postMemory(env, "/api/memory/store", { tenant_id: "t-nokey", content: "cats" });
    expect(noKey.status).toBe(402);
    expect(((await noKey.json()) as Record<string, unknown>).error).toBe("byok_required");
    const unknownTenant = await postMemory(env, "/api/memory/search", { tenant_id: "t-ghost", query: "cats" });
    expect(unknownTenant.status).toBe(404);
  });
});
