/**
 * R4 tests (hub v20) — Models + admin website + FCM triggers.
 *
 * R4.1 pairing auto-flow: licence-key verified, device registered in
 * one call, no 6-digit code; manual path untouched (pairing.test.ts).
 * R4.2 due-job FCM: handleTick onFired hook fires per fired job and a
 * throwing hook never breaks the tick.
 * R4.3 OAuth refresh: expired token refreshes transparently (mock
 * fetchFn); invalid_grant deletes the row + google_not_connected.
 * R4.5 admin website: /admin login page without a session, dashboard
 * for the owner session, 401 for others; /api/admin/overview + /keys
 * session-gated, values never returned.
 * R4.6 Gmail-send idempotency: same key replays the first result
 * (deduped:true, no second Google call); new key sends again; no
 * header = no dedupe (back-compat).
 * R4.7 cron lifecycle: create -> list -> disable -> enable -> delete.
 * R4.8 Drive write + Calendar: multipart upload + event create/list
 * (mock fetchFn); 403 -> google_reconnect_required; oversize -> 400.
 * R4.9 cap-warning email: 80% replies -> one email per period,
 * second call already_sent; below threshold -> no send.
 * R4.11 U8 server leg: device-signed approve records the signal, the
 * skill STAYS quarantined; repeat approve dedupes.
 *
 * No network, no real credentials: Google/Resend are mocked, tokens
 * are random per-run values. No secret value appears anywhere.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { genDeviceKey, type DeviceKey } from "./helpers";
import { handleRequest, type Env } from "../src/hub";
import { canonicalString } from "../src/crypto";
import { sortedJson } from "../src/docs";
import { resetRateLimitFallback } from "../src/ratelimit";
import { insertSkill } from "../src/skills";
import { handleTick } from "../src/cron";
import { currentPeriod } from "../src/metering";
import { contentIdempotencyKey } from "../src/idempotency";
import { maybeSendCapWarning } from "../src/cap-warning";
import { OWNER_ADMIN_EMAIL } from "../src/admin";
import {
  GOOGLE_SCOPES,
  GoogleError,
  calendarCreateEvent,
  calendarListEvents,
  driveUploadFile,
  getValidAccessToken,
  gmailListMessages,
  storeGoogleTokens,
  type TokenSet,
} from "../src/google";
import { newSessionToken } from "../src/licence-web";

const FIXED_NOW = Date.UTC(2026, 11, 23, 18, 0, 0);
const INTERNAL = { "x-internal-secret": "test-internal" };

function testMasterKeyB64(): string {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  let bin = "";
  for (const b of raw) bin += String.fromCharCode(b);
  return btoa(bin);
}

const MASTER = testMasterKeyB64();
const GOOGLE_ENV = {
  GOOGLE_OAUTH_CLIENT_ID: "test-client-id.apps.googleusercontent.com",
  GOOGLE_OAUTH_CLIENT_SECRET: "test-client-secret",
  KEY_ENC_SECRET: MASTER,
};

beforeEach(() => {
  resetRateLimitFallback();
});

afterEach(() => {
  vi.unstubAllGlobals();
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
    RESEND_API_KEY: "re_test_key",
    RESEND_FROM: "OmniJarvis <noreply@flow99.in>",
    ...GOOGLE_ENV,
    ...overrides,
  } as unknown as Env;
}

async function seedTenant(db: FakeD1, id: string, plan = "pro", ownerEmail?: string): Promise<void> {
  await db
    .prepare(
      "INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id, ownerEmail ?? `${id}@example.com`, plan, "byok", null, 0, FIXED_NOW)
    .run();
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string, publicKeyB64: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, publicKeyB64, FIXED_NOW, FIXED_NOW, 1)
    .run();
}

async function seedLicence(db: FakeD1, key: string, userId: string): Promise<void> {
  await db
    .prepare("INSERT INTO licences (key, user_id, device_id, status, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(key, userId, null, "active", FIXED_NOW)
    .run();
}

async function seedTokens(db: FakeD1, tenantId: string, expiresInMs = 3_600_000): Promise<TokenSet> {
  const tokens: TokenSet = {
    accessToken: `ya29.test-access-${tenantId}`,
    refreshToken: `1//test-refresh-${tenantId}`,
    expiresAt: Date.now() + expiresInMs,
    scopes: GOOGLE_SCOPES.join(" "),
  };
  await storeGoogleTokens(db, GOOGLE_ENV, tenantId, "owner@example.com", tokens);
  return tokens;
}

async function callHub(
  db: FakeD1,
  method: string,
  path: string,
  body: unknown = null,
  headers: Record<string, string> = {},
  envOverrides: Partial<Env> = {},
): Promise<{ status: number; body: Record<string, any>; text: string }> {
  const res = await handleRequest(
    new Request(`https://hub${path}`, {
      method,
      headers: { "Content-Type": "application/json", ...headers },
      body: body === null ? null : JSON.stringify(body),
    }),
    fakeEnv(db, envOverrides),
  );
  const text = await res.text();
  let parsed: Record<string, any> = {};
  try {
    parsed = JSON.parse(text) as Record<string, any>;
  } catch {
    parsed = {};
  }
  return { status: res.status, body: parsed, text };
}

async function signedHeaders(key: DeviceKey, deviceId: string, payloadRaw: string) {
  const nonce = "aabbccddeeff00112233445566778899";
  const ts = Date.now();
  const sig = await key.sign(canonicalString(deviceId, nonce, ts, payloadRaw));
  return { "x-device-id": deviceId, "x-nonce": nonce, "x-ts": String(ts), "x-signature": sig };
}

async function seedAdminSession(db: FakeD1, email: string, isAdmin = 0): Promise<{ token: string }> {
  await db
    .prepare("INSERT INTO licence_web_users (email, email_verified, is_admin, created_at, last_login_at) VALUES (?, ?, ?, ?, ?)")
    .bind(email, 1, isAdmin, FIXED_NOW, FIXED_NOW)
    .run();
  const { token, tokenHash } = await newSessionToken();
  const nowMs = Date.now();
  await db
    .prepare("INSERT INTO licence_web_sessions (token_hash, email, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?)")
    .bind(tokenHash, email, nowMs, nowMs + 30 * 24 * 60 * 60_000, nowMs)
    .run();
  return { token };
}

// ---------------------------------------------------------------- R4.1

describe("R4.1 pairing auto-flow", () => {
  it("invalid licence -> 403 licence_invalid, no device row", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    const res = await callHub(db, "POST", "/api/pairing/auto", {
      licence_key: "JARVIS-AAAA-BBBB-CCCC-DDDD",
      device_id: "dev-auto-1",
      public_key: key.publicKeyB64,
    });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe("licence_invalid");
    const row = await db.prepare("SELECT device_id FROM devices WHERE device_id = ?").bind("dev-auto-1").first();
    expect(row).toBeNull();
  });

  it("valid licence -> paired, device row, tenant derived; re-pair idempotent", async () => {
    const db = new FakeD1();
    await seedLicence(db, "JARVIS-AAAA-BBBB-CCCC-DDDD", "owner@example.com");
    const key = await genDeviceKey();
    const res = await callHub(db, "POST", "/api/pairing/auto", {
      licence_key: "JARVIS-AAAA-BBBB-CCCC-DDDD",
      device_id: "dev-auto-1",
      public_key: key.publicKeyB64,
    });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.paired).toBe(true);
    expect(res.body.device_id).toBe("dev-auto-1");
    expect(typeof res.body.tenant_id).toBe("string");
    expect(res.body.tenant_id.startsWith("lic-")).toBe(true);
    const row = await db
      .prepare("SELECT device_id, tenant_id FROM devices WHERE device_id = ?")
      .bind("dev-auto-1")
      .first<{ device_id: string; tenant_id: string }>();
    expect(row?.device_id).toBe("dev-auto-1");
    expect(row?.tenant_id).toBe(res.body.tenant_id);
    const again = await callHub(db, "POST", "/api/pairing/auto", {
      licence_key: "JARVIS-AAAA-BBBB-CCCC-DDDD",
      device_id: "dev-auto-1",
      public_key: key.publicKeyB64,
    });
    expect(again.status).toBe(200);
    expect(again.body.paired).toBe(true);
  });

  it("free derived tenant: second device -> 403 device_limit", async () => {
    const db = new FakeD1();
    await seedLicence(db, "JARVIS-AAAA-BBBB-CCCC-DDDD", "owner@example.com");
    const k1 = await genDeviceKey();
    const k2 = await genDeviceKey();
    const r1 = await callHub(db, "POST", "/api/pairing/auto", {
      licence_key: "JARVIS-AAAA-BBBB-CCCC-DDDD",
      device_id: "dev-auto-1",
      public_key: k1.publicKeyB64,
    });
    expect(r1.status).toBe(200);
    const r2 = await callHub(db, "POST", "/api/pairing/auto", {
      licence_key: "JARVIS-AAAA-BBBB-CCCC-DDDD",
      device_id: "dev-auto-2",
      public_key: k2.publicKeyB64,
    });
    expect(r2.status).toBe(403);
    expect(r2.body.error).toBe("device_limit");
  });
});

// ---------------------------------------------------------------- R4.2

describe("R4.2 due-job FCM hook (handleTick onFired)", () => {
  const ENV = { CRON_SECRET: "test-cron" };
  async function seedJob(db: FakeD1, id: string, nextRunAt: number, now: number) {
    await db
      .prepare(
        "INSERT INTO scheduled_jobs (id, tenant_id, device_id, cron_expr, command, enabled, last_run_at, next_run_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(id, "t-1", "dev-1", "0 9 * * *", "open youtube", 1, null, nextRunAt, now)
      .run();
  }

  it("fired job calls onFired once with job identity", async () => {
    const db = new FakeD1();
    const now = Date.parse("2026-11-21T09:00:00Z");
    await seedJob(db, "job-1", now - 60_000, now);
    const fired: Array<Record<string, string>> = [];
    const r = await handleTick(db, ENV, "test-cron", async () => true, now, async (job) => {
      fired.push({ ...job });
    });
    expect(r.ok).toBe(true);
    expect(r.fired).toBe(1);
    expect(fired).toEqual([{ id: "job-1", tenant_id: "t-1", device_id: "dev-1", command: "open youtube" }]);
  });

  it("a throwing onFired never breaks the tick", async () => {
    const db = new FakeD1();
    const now = Date.parse("2026-11-21T09:00:00Z");
    await seedJob(db, "job-1", now - 60_000, now);
    const r = await handleTick(db, ENV, "test-cron", async () => true, now, async () => {
      throw new Error("push exploded");
    });
    expect(r.ok).toBe(true);
    expect(r.fired).toBe(1);
  });
});

// ---------------------------------------------------------------- R4.3

describe("R4.3 OAuth refresh (mock fetchFn)", () => {
  function googleMock(map: (url: string) => { status: number; json: unknown } | null): typeof fetch {
    return (async (url: unknown, _init?: unknown) => {
      const hit = map(String(url));
      if (!hit) return new Response("not found", { status: 404 });
      return new Response(JSON.stringify(hit.json), { status: hit.status });
    }) as unknown as typeof fetch;
  }

  it("expired token refreshes transparently and the row is updated", async () => {
    const db = new FakeD1();
    const old = await seedTokens(db, "t-refresh", -60_000);
    const fetchFn = googleMock((url) => {
      if (url.includes("oauth2.googleapis.com/token")) {
        return { status: 200, json: { access_token: "ya29.refreshed-access", expires_in: 3600 } };
      }
      return null;
    });
    const valid = await getValidAccessToken({ db, env: GOOGLE_ENV, tenantId: "t-refresh", fetchFn });
    expect(valid.accessToken).toBe("ya29.refreshed-access");
    expect(valid.accessToken).not.toBe(old.accessToken);
    expect(valid.expiresAt).toBeGreaterThan(Date.now());
    const reloaded = await getValidAccessToken({ db, env: GOOGLE_ENV, tenantId: "t-refresh", fetchFn });
    expect(reloaded.accessToken).toBe("ya29.refreshed-access");
  });

  it("gmail list with an expired token refreshes, then lists", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-refresh-2", -60_000);
    const fetchFn = googleMock((url) => {
      if (url.includes("oauth2.googleapis.com/token")) {
        return { status: 200, json: { access_token: "ya29.refreshed-access-2", expires_in: 3600 } };
      }
      if (url.includes("/gmail/v1/users/me/messages?")) {
        return { status: 200, json: { messages: [{ id: "m1" }] } };
      }
      if (url.includes("/gmail/v1/users/me/messages/m1")) {
        return {
          status: 200,
          json: {
            id: "m1",
            snippet: "hi",
            payload: { mimeType: "text/plain", headers: [{ name: "Subject", value: "Hello" }], body: { data: "aGk=" } },
          },
        };
      }
      return null;
    });
    const messages = await gmailListMessages({ db, env: GOOGLE_ENV, tenantId: "t-refresh-2", fetchFn }, {});
    expect(messages).toHaveLength(1);
    expect(messages[0].subject).toBe("Hello");
  });

  it("invalid_grant deletes the row and reports google_not_connected", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-refresh-3", -60_000);
    const fetchFn = googleMock((url) => {
      if (url.includes("oauth2.googleapis.com/token")) {
        return { status: 400, json: { error: "invalid_grant", error_description: "Token has been expired or revoked." } };
      }
      return null;
    });
    await expect(getValidAccessToken({ db, env: GOOGLE_ENV, tenantId: "t-refresh-3", fetchFn })).rejects.toMatchObject({
      code: "google_not_connected",
    });
    const row = await db.prepare("SELECT tenant_id FROM google_tokens WHERE tenant_id = ?").bind("t-refresh-3").first();
    expect(row).toBeNull();
  });
});

// ---------------------------------------------------------------- R4.5

describe("R4.5 admin website", () => {
  it("GET /admin without a session -> login page (owner email shown, no dashboard)", async () => {
    const db = new FakeD1();
    const res = await callHub(db, "GET", "/admin");
    expect(res.status).toBe(200);
    expect(res.text).toContain("Admin login");
    expect(res.text).toContain(OWNER_ADMIN_EMAIL);
    expect(res.text).not.toContain("Training console");
  });

  it("owner session -> dashboard; is_admin flag is set at runtime", async () => {
    const db = new FakeD1();
    const { token } = await seedAdminSession(db, OWNER_ADMIN_EMAIL, 0);
    const res = await callHub(db, "GET", "/admin", null, { cookie: `lic_session=${token}` });
    expect(res.status).toBe(200);
    expect(res.text).toContain("Admin console");
    expect(res.text).toContain(OWNER_ADMIN_EMAIL);
    const flag = await db
      .prepare("SELECT is_admin FROM licence_web_users WHERE email = ?")
      .bind(OWNER_ADMIN_EMAIL)
      .first<{ is_admin: number }>();
    expect(flag?.is_admin).toBe(1);
  });

  it("non-owner verified session -> login page again (not admin)", async () => {
    const db = new FakeD1();
    const { token } = await seedAdminSession(db, "someone-else@example.com", 0);
    const res = await callHub(db, "GET", "/admin", null, { cookie: `lic_session=${token}` });
    expect(res.status).toBe(200);
    expect(res.text).toContain("Admin login");
    expect(res.text).not.toContain("Training console");
  });

  it("GET /api/admin/overview without a session -> 401; with owner session -> live counts, version 21", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-admin", "pro", OWNER_ADMIN_EMAIL);
    const noAuth = await callHub(db, "GET", "/api/admin/overview");
    expect(noAuth.status).toBe(401);
    const { token } = await seedAdminSession(db, OWNER_ADMIN_EMAIL, 1);
    const res = await callHub(db, "GET", "/api/admin/overview", null, { cookie: `lic_session=${token}` });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.version).toBe("21");
    expect(res.body.devices.count).toBe(0);
    expect(res.body.usage.tenant_id).toBe("t-admin");
    expect(res.body.usage.replies_cap).toBe(2500);
  });

  it("GET /api/admin/keys reports status booleans only — never a value", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-admin-2", "pro", OWNER_ADMIN_EMAIL);
    const { token } = await seedAdminSession(db, OWNER_ADMIN_EMAIL, 1);
    const res = await callHub(db, "GET", "/api/admin/keys", null, { cookie: `lic_session=${token}` });
    expect(res.status).toBe(200);
    expect(res.body.has_gemini_key).toBe(false);
    expect(res.body.has_groq_key).toBe(false);
    expect(res.body.github_admin_token_set).toBe(false);
    expect(JSON.stringify(res.body)).not.toContain("AIza");
    expect(JSON.stringify(res.body)).not.toContain("gsk_");
  });

  it("GET /health reports version 21", async () => {
    const db = new FakeD1();
    const res = await callHub(db, "GET", "/health");
    expect(res.status).toBe(200);
    expect(res.body.version).toBe("21");
  });
});

// ---------------------------------------------------------------- R4.6

describe("R4.6 Gmail-send idempotency", () => {
  it("contentIdempotencyKey is deterministic per content", async () => {
    const a = await contentIdempotencyKey("a@x.com", "Hi", "body");
    const b = await contentIdempotencyKey("a@x.com", "Hi", "body");
    const c = await contentIdempotencyKey("a@x.com", "Hi", "different body");
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toHaveLength(64);
  });

  it("same key replays the first result with deduped:true and no second Google call", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-idem", "pro");
    await seedTokens(db, "t-idem");
    let sendCalls = 0;
    vi.stubGlobal(
      "fetch",
      (async (url: unknown) => {
        if (String(url).includes("gmail.googleapis.com/gmail/v1/users/me/messages/send")) {
          sendCalls++;
          return new Response(JSON.stringify({ id: "gmail-msg-1" }), { status: 200 });
        }
        return new Response("not found", { status: 404 });
      }) as unknown as typeof fetch,
    );
    const body = { tenant_id: "t-idem", to: "friend@example.com", subject: "Hi", body: "hello" };
    const first = await callHub(db, "POST", "/api/google/gmail/send", body, { ...INTERNAL, "idempotency-key": "key-abc" });
    expect(first.status).toBe(200);
    expect(first.body.ok).toBe(true);
    expect(first.body.id).toBe("gmail-msg-1");
    expect(first.body.deduped).toBe(false);
    expect(sendCalls).toBe(1);
    const replay = await callHub(db, "POST", "/api/google/gmail/send", body, { ...INTERNAL, "idempotency-key": "key-abc" });
    expect(replay.status).toBe(200);
    expect(replay.body.ok).toBe(true);
    expect(replay.body.id).toBe("gmail-msg-1");
    expect(replay.body.deduped).toBe(true);
    expect(sendCalls).toBe(1);
    const other = await callHub(db, "POST", "/api/google/gmail/send", body, { ...INTERNAL, "idempotency-key": "key-def" });
    expect(other.status).toBe(200);
    expect(other.body.deduped).toBe(false);
    expect(sendCalls).toBe(2);
  });

  it("no Idempotency-Key header -> sends every time (back-compat)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-idem-2", "pro");
    await seedTokens(db, "t-idem-2");
    let sendCalls = 0;
    vi.stubGlobal(
      "fetch",
      (async (url: unknown) => {
        if (String(url).includes("gmail.googleapis.com/gmail/v1/users/me/messages/send")) {
          sendCalls++;
          return new Response(JSON.stringify({ id: `gmail-msg-${sendCalls}` }), { status: 200 });
        }
        return new Response("not found", { status: 404 });
      }) as unknown as typeof fetch,
    );
    const body = { tenant_id: "t-idem-2", to: "friend@example.com", subject: "Hi", body: "hello" };
    await callHub(db, "POST", "/api/google/gmail/send", body, { ...INTERNAL });
    await callHub(db, "POST", "/api/google/gmail/send", body, { ...INTERNAL });
    expect(sendCalls).toBe(2);
  });
});

// ---------------------------------------------------------------- R4.7

describe("R4.7 cron lifecycle (routes)", () => {
  it("create -> list -> disable -> enable -> delete", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-cron", "pro");
    const key = await genDeviceKey();
    await seedDevice(db, "dev-cron", "t-cron", key.publicKeyB64);
    const created = await callHub(
      db,
      "POST",
      "/api/billing/cron-jobs",
      { tenant_id: "t-cron", device_id: "dev-cron", cron_expr: "0 8 * * *", command: "subah ka kaam" },
      { ...INTERNAL },
    );
    expect(created.status).toBe(200);
    expect(created.body.ok).toBe(true);
    const jobId = created.body.job_id as string;
    expect(typeof jobId).toBe("string");
    const listed = await callHub(db, "GET", `/api/billing/cron-jobs?tenant_id=t-cron`, null, { ...INTERNAL });
    expect(listed.body.count).toBe(1);
    expect(listed.body.jobs[0].id).toBe(jobId);
    expect(listed.body.jobs[0].enabled).toBe(1);
    const disabled = await callHub(db, "POST", `/api/billing/cron-jobs/${jobId}/disable`, {}, { ...INTERNAL });
    expect(disabled.status).toBe(200);
    expect(disabled.body.enabled).toBe(false);
    const enabled = await callHub(db, "POST", `/api/billing/cron-jobs/${jobId}/enable`, {}, { ...INTERNAL });
    expect(enabled.status).toBe(200);
    expect(enabled.body.enabled).toBe(true);
    const deleted = await callHub(db, "DELETE", `/api/billing/cron-jobs/${jobId}`, null, { ...INTERNAL });
    expect(deleted.status).toBe(200);
    const listed2 = await callHub(db, "GET", `/api/billing/cron-jobs?tenant_id=t-cron`, null, { ...INTERNAL });
    expect(listed2.body.count).toBe(0);
  });
});

// ---------------------------------------------------------------- R4.8

describe("R4.8 Drive write + Calendar (mock fetchFn)", () => {
  it("GOOGLE_SCOPES includes drive.file + calendar.events", () => {
    expect(GOOGLE_SCOPES).toContain("https://www.googleapis.com/auth/drive.file");
    expect(GOOGLE_SCOPES).toContain("https://www.googleapis.com/auth/calendar.events");
    expect(GOOGLE_SCOPES).toContain("https://www.googleapis.com/auth/drive.readonly");
  });

  it("driveUploadFile posts multipart and returns the file id", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-drive");
    const seen: Array<{ url: string; init: RequestInit }> = [];
    const fetchFn = (async (url: unknown, init?: unknown) => {
      seen.push({ url: String(url), init: (init ?? {}) as RequestInit });
      return new Response(JSON.stringify({ id: "file-1", name: "notes.txt", mimeType: "text/plain" }), { status: 200 });
    }) as unknown as typeof fetch;
    const content = Buffer.from("hello drive").toString("base64");
    const res = await driveUploadFile(
      { db, env: GOOGLE_ENV, tenantId: "t-drive", fetchFn },
      { name: "notes.txt", mimeType: "text/plain", contentBase64: content },
    );
    expect(res.id).toBe("file-1");
    expect(res.name).toBe("notes.txt");
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toContain("upload/drive/v3/files?uploadType=multipart");
    expect(String((seen[0].init.headers as Record<string, string>)["Content-Type"] ?? "")).toContain("multipart/related");
    expect(String(seen[0].init.body ?? "")).toContain("notes.txt");
    expect(String(seen[0].init.body ?? "")).toContain(content);
  });

  it("driveUploadFile 403 -> google_reconnect_required (scope trap)", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-drive-2");
    const fetchFn = (async () => new Response(JSON.stringify({ error: { message: "insufficientPermissions" } }), { status: 403 })) as unknown as typeof fetch;
    await expect(
      driveUploadFile(
        { db, env: GOOGLE_ENV, tenantId: "t-drive-2", fetchFn },
        { name: "x.txt", mimeType: "text/plain", contentBase64: Buffer.from("x").toString("base64") },
      ),
    ).rejects.toMatchObject({ code: "google_reconnect_required", status: 403 });
  });

  it("driveUploadFile over the 1 MB cap -> 400, no fetch", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-drive-3");
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;
    const big = Buffer.alloc(1024 * 1024 + 1).toString("base64");
    await expect(
      driveUploadFile({ db, env: GOOGLE_ENV, tenantId: "t-drive-3", fetchFn }, { name: "big.bin", mimeType: "application/octet-stream", contentBase64: big }),
    ).rejects.toMatchObject({ code: "bad_request" });
    expect(calls).toBe(0);
  });

  it("calendarCreateEvent + calendarListEvents round-trip the mock", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-cal");
    const fetchFn = (async (url: unknown, init?: unknown) => {
      if (String(url).includes("/calendar/v3/calendars/primary/events") && (init as RequestInit)?.method === "POST") {
        const body = JSON.parse(String((init as RequestInit).body ?? "{}")) as Record<string, unknown>;
        return new Response(
          JSON.stringify({
            id: "evt-1",
            summary: body.summary,
            start: body.start,
            end: body.end,
            htmlLink: "https://calendar.google.com/event?eid=evt-1",
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          items: [
            { id: "evt-9", summary: "Chai", start: { dateTime: "2026-11-24T08:00:00+05:30" }, end: { dateTime: "2026-11-24T08:30:00+05:30" } },
          ],
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;
    const created = await calendarCreateEvent(
      { db, env: GOOGLE_ENV, tenantId: "t-cal", fetchFn },
      { summary: "Test event", start: "2026-11-24T10:00:00+05:30", end: "2026-11-24T11:00:00+05:30" },
    );
    expect(created.id).toBe("evt-1");
    expect(created.summary).toBe("Test event");
    expect(created.start).toBe("2026-11-24T10:00:00+05:30");
    const listed = await calendarListEvents({ db, env: GOOGLE_ENV, tenantId: "t-cal", fetchFn }, {});
    expect(listed).toHaveLength(1);
    expect(listed[0].summary).toBe("Chai");
  });

  it("calendarCreateEvent 403 -> google_reconnect_required", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-cal-2");
    const fetchFn = (async () => new Response(JSON.stringify({ error: { message: "insufficientPermissions" } }), { status: 403 })) as unknown as typeof fetch;
    await expect(
      calendarCreateEvent(
        { db, env: GOOGLE_ENV, tenantId: "t-cal-2", fetchFn },
        { summary: "X", start: "2026-11-24T10:00:00+05:30", end: "2026-11-24T11:00:00+05:30" },
      ),
    ).rejects.toMatchObject({ code: "google_reconnect_required" });
  });
});

// ---------------------------------------------------------------- R4.9

describe("R4.9 cap-warning email", () => {
  function resendStub(): { calls: number } {
    const state = { calls: 0 };
    vi.stubGlobal(
      "fetch",
      (async (url: unknown) => {
        if (String(url).includes("api.resend.com/emails")) {
          state.calls++;
          return new Response(JSON.stringify({ id: "re_123" }), { status: 200 });
        }
        return new Response("not found", { status: 404 });
      }) as unknown as typeof fetch,
    );
    return state;
  }

  async function seedUsage(db: FakeD1, tenantId: string, replies: number): Promise<void> {
    await db
      .prepare(
        "INSERT INTO usage_counters (tenant_id, period, replies, e2b_runs, llm_calls, input_tokens, output_tokens, cost_usd_micro) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(tenantId, currentPeriod(Date.now()), replies, 0, 0, 0, 0, 0)
      .run();
  }

  it("80% of the free cap -> one email, then already_sent (no second send)", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-cap", "free", "owner-cap@example.com");
    await seedUsage(db, "t-cap", 80);
    const stub = resendStub();
    const first = await maybeSendCapWarning({ RESEND_API_KEY: "re_test_key", RESEND_FROM: "OmniJarvis <noreply@flow99.in>" }, db, "t-cap");
    expect(first.sent).toBe(true);
    expect(stub.calls).toBe(1);
    const row = await db.prepare("SELECT id FROM cap_warnings WHERE id = ?").bind(`t-cap:${currentPeriod(Date.now())}`).first();
    expect(row).not.toBeNull();
    const second = await maybeSendCapWarning({ RESEND_API_KEY: "re_test_key", RESEND_FROM: "OmniJarvis <noreply@flow99.in>" }, db, "t-cap");
    expect(second.sent).toBe(false);
    if (!second.sent) expect(second.reason).toBe("already_sent");
    expect(stub.calls).toBe(1);
  });

  it("below 80% -> no send", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-cap-2", "free", "owner-cap2@example.com");
    await seedUsage(db, "t-cap-2", 79);
    const stub = resendStub();
    const res = await maybeSendCapWarning({ RESEND_API_KEY: "re_test_key", RESEND_FROM: "OmniJarvis <noreply@flow99.in>" }, db, "t-cap-2");
    expect(res.sent).toBe(false);
    if (!res.sent) expect(res.reason).toBe("below_threshold");
    expect(stub.calls).toBe(0);
  });

  it("unknown tenant -> tenant_not_found, no send", async () => {
    const db = new FakeD1();
    const stub = resendStub();
    const res = await maybeSendCapWarning({ RESEND_API_KEY: "re_test_key", RESEND_FROM: "OmniJarvis <noreply@flow99.in>" }, db, "no-such-tenant");
    expect(res.sent).toBe(false);
    if (!res.sent) expect(res.reason).toBe("tenant_not_found");
    expect(stub.calls).toBe(0);
  });
});

// ---------------------------------------------------------------- R4.11

describe("R4.11 U8 server leg — device-signed approve signal", () => {
  async function seedSkill(db: FakeD1): Promise<void> {
    await insertSkill(db, {
      id: "skill-r4-1",
      manifest: JSON.stringify({ name: "test-skill", version: "1.0.0", trigger: "on test", steps: [{ action: "reply", text: "hi" }] }),
      submitted_by: "t-skill",
      created_at: FIXED_NOW,
    });
  }

  it("approve records the signal, skill STAYS quarantined; repeat dedupes", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-skill", "pro");
    const key = await genDeviceKey();
    await seedDevice(db, "dev-skill", "t-skill", key.publicKeyB64);
    await seedSkill(db);
    const body = { device_id: "dev-skill", skill_id: "skill-r4-1" };
    const headers = await signedHeaders(key, "dev-skill", sortedJson(body));
    const res = await callHub(db, "POST", "/api/skills/approve", body, headers);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.status).toBe("quarantined");
    expect(res.body.user_approved).toBe(true);
    expect(res.body.deduped).toBe(false);
    const skill = await db.prepare("SELECT status FROM global_skills WHERE id = ?").bind("skill-r4-1").first<{ status: string }>();
    expect(skill?.status).toBe("quarantined");
    const reviews = await db
      .prepare("SELECT id FROM skill_reviews WHERE skill_id = ? AND decision = ?")
      .bind("skill-r4-1", "user_approved")
      .all<{ id: string }>();
    expect((reviews.results ?? []).length).toBe(1);
    const again = await callHub(db, "POST", "/api/skills/approve", body, headers);
    expect(again.status).toBe(200);
    expect(again.body.deduped).toBe(true);
    const reviews2 = await db
      .prepare("SELECT id FROM skill_reviews WHERE skill_id = ? AND decision = ?")
      .bind("skill-r4-1", "user_approved")
      .all<{ id: string }>();
    expect((reviews2.results ?? []).length).toBe(1);
  });

  it("missing skill -> 404; unsigned -> 401", async () => {
    const db = new FakeD1();
    await seedTenant(db, "t-skill-2", "pro");
    const key = await genDeviceKey();
    await seedDevice(db, "dev-skill-2", "t-skill-2", key.publicKeyB64);
    const missing = await callHub(
      db,
      "POST",
      "/api/skills/approve",
      { device_id: "dev-skill-2", skill_id: "no-such-skill" },
      await signedHeaders(key, "dev-skill-2", sortedJson({ device_id: "dev-skill-2", skill_id: "no-such-skill" })),
    );
    expect(missing.status).toBe(404);
    expect(missing.body.error).toBe("skill_not_found");
    const unsigned = await callHub(db, "POST", "/api/skills/approve", { device_id: "dev-skill-2", skill_id: "skill-r4-1" });
    expect(unsigned.status).toBe(401);
  });
});
