/**
 * B2 backup tests (Track C, #49) — mocked fetch only, no live B2
 * account. Covers: SigV4 signature cross-checked against Node's
 * node:crypto HMAC (independent implementation), tenant export
 * isolation, encrypted upload round-trip (decrypt with the master key
 * → original JSON), B2 error + not-configured paths, restore-test
 * dry-run (writes nothing) + integrity/decrypt failures, and the hub
 * admin routes.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { createHash, createHmac } from "node:crypto";
import { FakeD1 } from "./fake-d1";
import { handleRequest, type Env } from "../src/hub";
import { resetRateLimitFallback } from "../src/ratelimit";
import { bytesToBase64 } from "../src/crypto";
import { sha256Hex } from "../src/docs";
import { decryptTenantKey, importMasterKey } from "../src/keyvault";
import { insertTrace } from "../src/db";
import {
  b2Region,
  b2Status,
  createTenantBackup,
  exportTenantData,
  listBackups,
  restoreTestBackup,
  signS3Request,
  type B2Env,
} from "../src/backup";

const NOW = Date.UTC(2026, 11, 22, 12, 0, 0);

beforeEach(() => {
  resetRateLimitFallback();
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function genMasterKeyB64(): Promise<string> {
  const k = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
  return bytesToBase64(raw);
}

const B2: B2Env = {
  B2_ENDPOINT: "https://s3.us-west-002.backblazeb2.com",
  B2_BUCKET: "test-bucket",
  B2_KEY_ID: "test-key-id",
  B2_APPLICATION_KEY: "test-application-key",
};

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

async function seedTenant(db: FakeD1, id: string, plan = "free", verified = 1): Promise<void> {
  await db
    .prepare("INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, email_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id, `${id}@example.com`, plan, "byok", null, 0, verified, NOW)
    .run();
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, "pubkey", NOW, NOW, 1)
    .run();
}

async function seedSubscription(db: FakeD1, id: string, tenantId: string): Promise<void> {
  await db
    .prepare("INSERT INTO subscriptions (id, tenant_id, plan_tier, billing_period, amount_paise, status, starts_at, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id, tenantId, "pro", "monthly", 99900, "active", "2026-11-22T00:00:00.000Z", "2026-12-22T00:00:00.000Z", "2026-11-22T00:00:00.000Z")
    .run();
}

type Json = Record<string, unknown>;

async function call(
  db: FakeD1,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = { "x-admin-token": "test-admin" },
  envOverrides: Partial<Env> = {},
): Promise<{ status: number; body: Json }> {
  const res = await handleRequest(
    new Request(`https://hub${path}`, {
      method,
      headers: { "Content-Type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    fakeEnv(db, envOverrides),
  );
  return { status: res.status, body: (await res.json()) as Json };
}

describe("b2Status / region derivation", () => {
  it("configured when endpoint+bucket+keys present (region from endpoint host)", () => {
    expect(b2Status(B2)).toBe("configured");
  });

  it("not_configured when anything is missing", () => {
    expect(b2Status({})).toBe("not_configured");
    expect(b2Status({ ...B2, B2_BUCKET: undefined })).toBe("not_configured");
    expect(b2Status({ ...B2, B2_APPLICATION_KEY: undefined })).toBe("not_configured");
    // Endpoint without a region in the host and no B2_REGION.
    expect(b2Status({ ...B2, B2_ENDPOINT: "https://s3.example.com" })).toBe("not_configured");
    expect(b2Status({ ...B2, B2_ENDPOINT: "https://s3.example.com", B2_REGION: "eu-central-003" })).toBe("configured");
  });

  it("bare hostname endpoint derives the region too (R-6: signups.env stores it scheme-less)", () => {
    // Exactly how B2_S3_ENDPOINT is stored: no scheme at all.
    expect(b2Region({ B2_ENDPOINT: "s3.us-west-002.backblazeb2.com" })).toBe("us-west-002");
    expect(b2Status({ ...B2, B2_ENDPOINT: "s3.us-west-002.backblazeb2.com" })).toBe("configured");
    // Full URL still works, as does a trailing slash.
    expect(b2Region({ B2_ENDPOINT: "https://s3.eu-central-003.backblazeb2.com" })).toBe("eu-central-003");
    expect(b2Region({ B2_ENDPOINT: "s3.eu-central-003.backblazeb2.com/" })).toBe("eu-central-003");
    // A bare non-B2 host still derives nothing.
    expect(b2Region({ B2_ENDPOINT: "s3.example.com" })).toBeNull();
    expect(b2Status({ ...B2, B2_ENDPOINT: "s3.example.com" })).toBe("not_configured");
  });
});

describe("signS3Request (SigV4)", () => {
  it("signature matches an independent node:crypto implementation (fixed inputs)", async () => {
    const nowMs = Date.UTC(2026, 10, 22, 12, 0, 0); // November (0-indexed month)
    const body = new TextEncoder().encode("hello backup");
    const headers = await signS3Request({
      method: "PUT",
      endpoint: "https://s3.us-west-002.backblazeb2.com",
      bucket: "test-bucket",
      objectKey: "backups/t-1/bak-1.json.enc",
      region: "us-west-002",
      keyId: "test-key-id",
      secret: "test-application-key",
      body,
      nowMs,
    });
    // Independent recomputation with node:crypto.
    const amzDate = "20261122T120000Z";
    const dateStamp = "20261122";
    const payloadHash = createHash("sha256").update(body).digest("hex");
    const canonicalRequest = [
      "PUT",
      "/test-bucket/backups/t-1/bak-1.json.enc",
      "",
      `host:s3.us-west-002.backblazeb2.com\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`,
      "host;x-amz-content-sha256;x-amz-date",
      payloadHash,
    ].join("\n");
    const scope = `${dateStamp}/us-west-002/s3/aws4_request`;
    const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, createHash("sha256").update(canonicalRequest).digest("hex")].join("\n");
    const hmac = (key: Buffer, data: string) => createHmac("sha256", key).update(data).digest();
    const kDate = hmac(Buffer.from("AWS4test-application-key"), dateStamp);
    const kRegion = hmac(kDate, "us-west-002");
    const kService = hmac(kRegion, "s3");
    const kSigning = hmac(kService, "aws4_request");
    const expectedSig = createHmac("sha256", kSigning).update(stringToSign).digest("hex");
    expect(headers.Authorization).toBe(
      `AWS4-HMAC-SHA256 Credential=test-key-id/${scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=${expectedSig}`,
    );
    expect(headers["x-amz-date"]).toBe(amzDate);
    expect(headers["x-amz-content-sha256"]).toBe(payloadHash);
  });

  it("deterministic: same inputs -> same headers; different body -> different signature", async () => {
    const base = {
      method: "GET" as const,
      endpoint: "https://s3.us-west-002.backblazeb2.com",
      bucket: "test-bucket",
      objectKey: "backups/t-1/bak-1.json.enc",
      region: "us-west-002",
      keyId: "test-key-id",
      secret: "test-application-key",
      nowMs: NOW,
    };
    const a = await signS3Request({ ...base, body: new Uint8Array(0) });
    const b = await signS3Request({ ...base, body: new Uint8Array(0) });
    expect(a.Authorization).toBe(b.Authorization);
    const c = await signS3Request({ ...base, body: new TextEncoder().encode("x") });
    expect(c.Authorization).not.toBe(a.Authorization);
    // GET of empty body: known SHA-256 of "".
    expect(a["x-amz-content-sha256"]).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

describe("exportTenantData (tenant isolation)", () => {
  it("exports only the tenant's rows, including per-device sync_state", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    await seedTenant(db, "t-2");
    await seedDevice(db, "dev-1", "t-1");
    await seedDevice(db, "dev-2", "t-2");
    await seedSubscription(db, "sub-1", "t-1");
    await seedSubscription(db, "sub-2", "t-2");
    await insertTrace(db, "t-1", "dev-1", "test_trace", { x: 1 });
    await insertTrace(db, "t-2", "dev-2", "test_trace", { x: 2 });
    await db.prepare("INSERT INTO sync_state (device_id, table_name, last_seq) VALUES (?, ?, ?)").bind("dev-1", "traces", 7).run();
    await db.prepare("INSERT INTO sync_state (device_id, table_name, last_seq) VALUES (?, ?, ?)").bind("dev-2", "traces", 9).run();

    const exp = await exportTenantData(db, "t-1", NOW);
    expect(exp.version).toBe(1);
    expect(exp.tenant_id).toBe("t-1");
    expect(exp.tables.tenants).toHaveLength(1);
    expect(exp.tables.devices.map((d) => d.device_id)).toEqual(["dev-1"]);
    expect(exp.tables.subscriptions.map((s) => s.id)).toEqual(["sub-1"]);
    expect(exp.tables.traces).toHaveLength(1);
    expect((exp.tables.traces[0].detail as string)).toContain('"x":1');
    expect(exp.tables.sync_state).toHaveLength(1);
    expect(exp.tables.sync_state[0].last_seq).toBe(7);
    // No t-2 data anywhere.
    expect(JSON.stringify(exp)).not.toContain("t-2");
    expect(JSON.stringify(exp)).not.toContain("dev-2");
    expect(JSON.stringify(exp)).not.toContain("sub-2");
  });
});

describe("createTenantBackup (mocked B2)", () => {
  it("PUTs an AES-GCM envelope; decrypts back to the export; backups row ok + sha256 matches", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    await seedDevice(db, "dev-1", "t-1");
    await seedSubscription(db, "sub-1", "t-1");
    const masterB64 = await genMasterKeyB64();
    const master = await importMasterKey(masterB64);
    const seen: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal(
      "fetch",
      async (url: string, init?: RequestInit) => {
        seen.push({ url, init: init ?? {} });
        return new Response("", { status: 200 });
      },
    );
    const res = await createTenantBackup({ ...B2, KEY_ENC_SECRET: masterB64 }, db, "t-1", NOW);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.backup_id.startsWith("bak-")).toBe(true);
    expect(res.b2_key).toBe(`backups/t-1/${res.backup_id}.json.enc`);
    expect(res.size_bytes).toBeGreaterThan(0);
    // One PUT, signed, to the right URL.
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe(`https://s3.us-west-002.backblazeb2.com/test-bucket/${res.b2_key}`);
    expect(seen[0].init.method).toBe("PUT");
    const headers = seen[0].init.headers as Record<string, string>;
    expect(headers.Authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=test-key-id\/\d{8}\/us-west-002\/s3\/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/);
    // Body is the keyvault envelope: decrypt -> original export JSON.
    const envelope = new TextDecoder().decode(seen[0].init.body as Uint8Array);
    const plaintext = await decryptTenantKey(master, envelope);
    expect(await sha256Hex(plaintext)).toBe(res.sha256);
    const parsed = JSON.parse(plaintext) as { tenant_id: string; tables: Record<string, unknown[]> };
    expect(parsed.tenant_id).toBe("t-1");
    expect(parsed.tables.devices).toHaveLength(1);
    expect(parsed.tables.subscriptions).toHaveLength(1);
    // D1 record.
    const rows = await listBackups(db, "t-1");
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(res.backup_id);
    expect(rows[0].status).toBe("ok");
    expect(rows[0].sha256).toBe(res.sha256);
    expect(rows[0].size_bytes).toBe(res.size_bytes);
  });

  it("B2 PUT 403 -> b2_error + failed row recorded, no throw", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const masterB64 = await genMasterKeyB64();
    vi.stubGlobal("fetch", async () => new Response("<Error><Code>AccessDenied</Code></Error>", { status: 403 }));
    const res = await createTenantBackup({ ...B2, KEY_ENC_SECRET: masterB64 }, db, "t-1", NOW);
    expect(res).toMatchObject({ ok: false, error: "b2_error", status: 403 });
    const rows = await listBackups(db, "t-1");
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("failed");
  });

  it("fetch throws -> fetch_failed, failed row still recorded", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const masterB64 = await genMasterKeyB64();
    vi.stubGlobal("fetch", async () => {
      throw new Error("down");
    });
    const res = await createTenantBackup({ ...B2, KEY_ENC_SECRET: masterB64 }, db, "t-1", NOW);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("fetch_failed");
    expect((await listBackups(db, "t-1"))[0].status).toBe("failed");
  });

  it("no B2 env -> b2_not_configured, fetch never called, no row", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const fetchMock = vi.fn(async () => new Response("", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await createTenantBackup({}, db, "t-1", NOW);
    expect(res).toEqual({ ok: false, error: "b2_not_configured" });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(await listBackups(db, "t-1")).toHaveLength(0);
  });

  it("no KEY_ENC_SECRET -> key_enc_not_configured, fetch never called", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const fetchMock = vi.fn(async () => new Response("", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await createTenantBackup(B2, db, "t-1", NOW);
    expect(res).toEqual({ ok: false, error: "key_enc_not_configured" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("restoreTestBackup (dry-run)", () => {
  async function setupBackup(): Promise<{ db: FakeD1; masterB64: string; backupId: string; envelope: string }> {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    await seedDevice(db, "dev-1", "t-1");
    await seedSubscription(db, "sub-1", "t-1");
    const masterB64 = await genMasterKeyB64();
    let envelope = "";
    vi.stubGlobal(
      "fetch",
      async (_url: string, init?: RequestInit) => {
        if (init?.method === "PUT") envelope = new TextDecoder().decode(init.body as Uint8Array);
        return new Response("", { status: 200 });
      },
    );
    const res = await createTenantBackup({ ...B2, KEY_ENC_SECRET: masterB64 }, db, "t-1", NOW);
    if (!res.ok) throw new Error("setup backup failed");
    return { db, masterB64, backupId: res.backup_id, envelope };
  }

  it("downloads, decrypts, verifies sha256 + tenant; returns table counts; writes nothing", async () => {
    const { db, masterB64, backupId, envelope } = await setupBackup();
    vi.stubGlobal(
      "fetch",
      async (url: string, init?: RequestInit) => {
        expect(init?.method).toBe("GET");
        expect(url).toContain(`/test-bucket/backups/t-1/${backupId}.json.enc`);
        return new Response(envelope, { status: 200 });
      },
    );
    const before = JSON.stringify([...db.tables.entries()].map(([k, v]) => [k, [...v.keys()]]));
    const res = await restoreTestBackup({ ...B2, KEY_ENC_SECRET: masterB64 }, db, backupId);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.backup_id).toBe(backupId);
    expect(res.tenant_id).toBe("t-1");
    expect(res.tables.devices).toBe(1);
    expect(res.tables.subscriptions).toBe(1);
    expect(res.tables.tenants).toBe(1);
    // Dry-run: D1 is byte-identical afterwards (no writes at all).
    const after = JSON.stringify([...db.tables.entries()].map(([k, v]) => [k, [...v.keys()]]));
    expect(after).toBe(before);
  });

  it("tampered stored sha256 -> integrity_failed", async () => {
    const { db, masterB64, backupId, envelope } = await setupBackup();
    await db.prepare("UPDATE backups SET sha256 = ? WHERE id = ?").bind("00".repeat(32), backupId).run();
    vi.stubGlobal("fetch", async () => new Response(envelope, { status: 200 }));
    const res = await restoreTestBackup({ ...B2, KEY_ENC_SECRET: masterB64 }, db, backupId);
    expect(res).toEqual({ ok: false, error: "integrity_failed" });
  });

  it("different master key -> decrypt_failed", async () => {
    const { db, backupId, envelope } = await setupBackup();
    const otherMaster = await genMasterKeyB64();
    vi.stubGlobal("fetch", async () => new Response(envelope, { status: 200 }));
    const res = await restoreTestBackup({ ...B2, KEY_ENC_SECRET: otherMaster }, db, backupId);
    expect(res).toEqual({ ok: false, error: "decrypt_failed" });
  });

  it("unknown backup_id -> backup_not_found (no fetch)", async () => {
    const db = new FakeD1();
    const fetchMock = vi.fn(async () => new Response("", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await restoreTestBackup({ ...B2, KEY_ENC_SECRET: await genMasterKeyB64() }, db, "bak-nope");
    expect(res).toEqual({ ok: false, error: "backup_not_found" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("B2 GET 404 -> b2_error", async () => {
    const { db, masterB64, backupId } = await setupBackup();
    vi.stubGlobal("fetch", async () => new Response("not found", { status: 404 }));
    const res = await restoreTestBackup({ ...B2, KEY_ENC_SECRET: masterB64 }, db, backupId);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe("b2_error");
      expect(res.status).toBe(404);
    }
  });
});

describe("hub admin backup routes", () => {
  it("backup without admin token -> 401; with admin token but no B2 env -> 503 b2_not_configured", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    const denied = await call(db, "POST", "/api/billing/admin/backup", { tenant_id: "t-1" }, { "x-internal-secret": "test-internal" });
    expect(denied.status).toBe(401);
    const res = await call(db, "POST", "/api/billing/admin/backup", { tenant_id: "t-1" });
    expect(res.status).toBe(503);
    expect(res.body.error).toBe("b2_not_configured");
  });

  it("full admin flow: backup -> list -> restore-test (mocked B2 stores the PUT body)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-1");
    await seedDevice(db, "dev-1", "t-1");
    const masterB64 = await genMasterKeyB64();
    const store = new Map<string, string>();
    vi.stubGlobal(
      "fetch",
      async (url: string, init?: RequestInit) => {
        if (init?.method === "PUT") {
          store.set(url, new TextDecoder().decode(init.body as Uint8Array));
          return new Response("", { status: 200 });
        }
        const body = store.get(url);
        if (!body) return new Response("missing", { status: 404 });
        return new Response(body, { status: 200 });
      },
    );
    const envOverrides = { ...B2, KEY_ENC_SECRET: masterB64 };
    const created = await call(db, "POST", "/api/billing/admin/backup", { tenant_id: "t-1" }, { "x-admin-token": "test-admin" }, envOverrides);
    expect(created.status).toBe(200);
    expect(created.body.ok).toBe(true);
    const backupId = String(created.body.backup_id);
    expect(backupId.startsWith("bak-")).toBe(true);
    const listed = await call(db, "GET", "/api/billing/admin/backups?tenant_id=t-1");
    expect(listed.status).toBe(200);
    expect(listed.body.count).toBe(1);
    const restored = await call(db, "POST", "/api/billing/admin/backup/restore-test", { backup_id: backupId }, { "x-admin-token": "test-admin" }, envOverrides);
    expect(restored.status).toBe(200);
    expect(restored.body.dry_run).toBe(true);
    expect((restored.body.tables as Record<string, number>).devices).toBe(1);
    // Unknown tenant -> 404; unknown backup -> 404.
    expect((await call(db, "POST", "/api/billing/admin/backup", { tenant_id: "t-nope" })).status).toBe(404);
    expect((await call(db, "POST", "/api/billing/admin/backup/restore-test", { backup_id: "bak-nope" }, { "x-admin-token": "test-admin" }, envOverrides)).status).toBe(404);
  });
});
