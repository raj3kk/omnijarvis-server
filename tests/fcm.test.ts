/**
 * FCM push tests (1.12.0, DESIGN expansion/fcm/DESIGN.md).
 * Mocked fetch only — no live Google, no network. Covers:
 * service-account parsing · RS256 JWT mint (assertion shape verified
 * by decoding the JWT the code builds) · token cache · register route
 * (signed / bad sig / unpaired / bad token) · send route (happy path
 * incl. D1 row + message_id · no_token · not_configured · UNREGISTERED
 * deletes the stale token · FCM 500 · fetch throw) · status route.
 * Live happy-path proof needs the user's paired device (parent-side).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { genDeviceKey } from "./helpers";
import { handleRequest, type Env } from "../src/hub";
import { canonicalString } from "../src/crypto";
import { sortedJson } from "../src/docs";
import { resetRateLimitFallback } from "../src/ratelimit";
import {
  clearFcmTokenCache,
  getFcmRegistration,
  isFcmConfigured,
  mintAccessToken,
  parseServiceAccount,
  sendFcm,
  type FcmEnv,
} from "../src/fcm";

const NOW = Date.UTC(2026, 11, 22, 12, 0, 0);

beforeEach(() => {
  resetRateLimitFallback();
  clearFcmTokenCache();
  vi.unstubAllGlobals();
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
    ...overrides,
  };
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string, publicKeyB64: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, publicKeyB64, NOW, NOW, 1)
    .run();
}

async function seedToken(db: FakeD1, deviceId: string, tenantId: string, token: string): Promise<void> {
  await db
    .prepare("INSERT INTO fcm_tokens (device_id, tenant_id, token, updated_at) VALUES (?, ?, ?, ?)")
    .bind(deviceId, tenantId, token, NOW)
    .run();
}

type Json = Record<string, unknown>;

async function call(
  db: FakeD1,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = { "x-internal-secret": "test-internal" },
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

async function signedCall(
  db: FakeD1,
  key: Awaited<ReturnType<typeof genDeviceKey>>,
  deviceId: string,
  path: string,
  body: Record<string, unknown>,
): Promise<{ status: number; body: Json }> {
  const nonce = "aabbccddeeff00112233445566778899";
  const ts = Date.now();
  const payloadRaw = sortedJson(body);
  const sig = await key.sign(canonicalString(deviceId, nonce, ts, payloadRaw));
  return call(db, "POST", path, body, {
    "x-device-id": deviceId,
    "x-nonce": nonce,
    "x-ts": String(ts),
    "x-signature": sig,
  });
}

/** Fake service-account JSON (test-only RSA key, generated per test). */
async function makeServiceAccountEnv(): Promise<FcmEnv> {
  const kp = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", kp.privateKey)) as ArrayBuffer);
  let bin = "";
  for (const b of pkcs8) bin += String.fromCharCode(b);
  const b64 = btoa(bin);
  const pemLines = b64.match(/.{1,64}/g)?.join("\n") ?? b64;
  const pem = `-----BEGIN PRIVATE KEY-----\n${pemLines}\n-----END PRIVATE KEY-----\n`;
  return {
    FIREBASE_SERVICE_ACCOUNT_JSON: JSON.stringify({
      type: "service_account",
      project_id: "omnijarvis-2bdd6",
      private_key_id: "test-key-id-1",
      private_key: pem,
      client_email: "firebase-adminsdk-fbsvc@omnijarvis-2bdd6.iam.gserviceaccount.com",
      client_id: "1234567890",
      auth_uri: "https://accounts.google.com/o/oauth2/auth",
      token_uri: "https://oauth2.googleapis.com/token",
    }),
  };
}

function b64urlDecodeToString(s: string): string {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  return new TextDecoder().decode(
    Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)),
  );
}

describe("parseServiceAccount / isFcmConfigured", () => {
  it("valid JSON with all fields -> parsed; missing/empty/malformed -> null", async () => {
    const env = await makeServiceAccountEnv();
    const parsed = parseServiceAccount(env);
    expect(parsed?.project_id).toBe("omnijarvis-2bdd6");
    expect(parsed?.client_email).toContain("@omnijarvis-2bdd6.iam.gserviceaccount.com");
    expect(isFcmConfigured(env)).toBe(true);
    expect(parseServiceAccount({})).toBeNull();
    expect(parseServiceAccount({ FIREBASE_SERVICE_ACCOUNT_JSON: "" })).toBeNull();
    expect(parseServiceAccount({ FIREBASE_SERVICE_ACCOUNT_JSON: "not json" })).toBeNull();
    expect(parseServiceAccount({ FIREBASE_SERVICE_ACCOUNT_JSON: JSON.stringify({ project_id: "x" }) })).toBeNull();
    expect(isFcmConfigured({})).toBe(false);
  });
});

describe("mintAccessToken (mocked token endpoint)", () => {
  it("builds a valid RS256 JWT assertion (iss/scope/aud/exp) and returns the access token", async () => {
    const env = await makeServiceAccountEnv();
    const seen: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal(
      "fetch",
      async (url: string, init?: RequestInit) => {
        seen.push({ url, init: init ?? {} });
        return new Response(JSON.stringify({ access_token: "ya29.test-token", expires_in: 3600, token_type: "Bearer" }), { status: 200 });
      },
    );
    const res = await mintAccessToken(env, NOW);
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("mint failed");
    expect(res.token).toBe("ya29.test-token");
    expect(res.projectId).toBe("omnijarvis-2bdd6");
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe("https://oauth2.googleapis.com/token");
    const body = seen[0].init.body as URLSearchParams;
    expect(body.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    const jwt = body.get("assertion") ?? "";
    const [h, p, s] = jwt.split(".");
    expect(s.length).toBeGreaterThan(10);
    const header = JSON.parse(b64urlDecodeToString(h)) as Record<string, unknown>;
    expect(header.alg).toBe("RS256");
    expect(header.kid).toBe("test-key-id-1");
    const claims = JSON.parse(b64urlDecodeToString(p)) as Record<string, unknown>;
    expect(claims.iss).toBe("firebase-adminsdk-fbsvc@omnijarvis-2bdd6.iam.gserviceaccount.com");
    expect(claims.scope).toBe("https://www.googleapis.com/auth/firebase.messaging");
    expect(claims.aud).toBe("https://oauth2.googleapis.com/token");
    expect(claims.exp).toBe(Math.floor(NOW / 1000) + 3600);
    expect(claims.iat).toBe(Math.floor(NOW / 1000));
  });

  it("second mint inside the cache window does not call fetch again", async () => {
    const env = await makeServiceAccountEnv();
    let calls = 0;
    vi.stubGlobal("fetch", async () => {
      calls++;
      return new Response(JSON.stringify({ access_token: "ya29.cached", expires_in: 3600 }), { status: 200 });
    });
    const first = await mintAccessToken(env, NOW);
    const second = await mintAccessToken(env, NOW + 60_000);
    expect(first.ok && second.ok).toBe(true);
    if (first.ok && second.ok) expect(second.token).toBe("ya29.cached");
    expect(calls).toBe(1);
  });

  it("token endpoint 400 -> token_mint_failed; not configured -> not_configured", async () => {
    const env = await makeServiceAccountEnv();
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 }));
    const bad = await mintAccessToken(env, NOW);
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.error).toBe("token_mint_failed");
    const missing = await mintAccessToken({}, NOW);
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.error).toBe("not_configured");
  });
});

describe("POST /api/fcm/register (device-signed)", () => {
  it("good signature upserts the token and returns ok; re-register replaces it", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "ten-1", key.publicKeyB64);
    const body = { device_id: "dev-1", fcm_token: "fcm-token-aaa" };
    const res = await signedCall(db, key, "dev-1", "/api/fcm/register", body);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.registered).toBe(true);
    let reg = await getFcmRegistration(db, "dev-1");
    expect(reg?.tenant_id).toBe("ten-1");
    const res2 = await signedCall(db, key, "dev-1", "/api/fcm/register", { device_id: "dev-1", fcm_token: "fcm-token-bbb" });
    expect(res2.status).toBe(200);
    reg = await getFcmRegistration(db, "dev-1");
    expect(reg).not.toBeNull();
    const row = await db.prepare("SELECT token FROM fcm_tokens WHERE device_id = ?").bind("dev-1").first<{ token: string }>();
    expect(row?.token).toBe("fcm-token-bbb");
  });

  it("bad signature -> 401; unpaired device -> 403; missing/oversized token -> 400; no auth -> 401", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    const other = await genDeviceKey();
    await seedDevice(db, "dev-1", "ten-1", key.publicKeyB64);
    // Bad signature: sign with a different key.
    const bad = await signedCall(db, other, "dev-1", "/api/fcm/register", { device_id: "dev-1", fcm_token: "tok" });
    expect(bad.status).toBe(401);
    // Unpaired device.
    const unpaired = await signedCall(db, key, "dev-9", "/api/fcm/register", { device_id: "dev-9", fcm_token: "tok" });
    expect(unpaired.status).toBe(403);
    // Missing token.
    const missing = await signedCall(db, key, "dev-1", "/api/fcm/register", { device_id: "dev-1" });
    expect(missing.status).toBe(400);
    // Oversized token.
    const big = await signedCall(db, key, "dev-1", "/api/fcm/register", { device_id: "dev-1", fcm_token: "x".repeat(4097) });
    expect(big.status).toBe(400);
    // No auth at all.
    const noAuth = await call(db, "POST", "/api/fcm/register", { device_id: "dev-1", fcm_token: "tok" }, {});
    expect(noAuth.status).toBe(401);
  });
});

describe("POST /api/fcm/send (internal-secret, mocked FCM)", () => {
  function fcmFetchMock(seen: Array<{ url: string; init: RequestInit }>, fcmStatus = 200, fcmBody: unknown = { name: "projects/omnijarvis-2bdd6/messages/msg-123" }) {
    return async (url: string, init?: RequestInit) => {
      seen.push({ url, init: init ?? {} });
      const u = String(url);
      if (u.includes("oauth2.googleapis.com/token")) {
        return new Response(JSON.stringify({ access_token: "ya29.test-token", expires_in: 3600 }), { status: 200 });
      }
      if (u.includes("fcm.googleapis.com")) {
        return new Response(JSON.stringify(fcmBody), { status: fcmStatus });
      }
      throw new Error(`unexpected fetch ${u}`);
    };
  }

  it("happy path: data-only message, Bearer token, HIGH priority, D1 row sent + message_id", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "ten-1", key.publicKeyB64);
    await seedToken(db, "dev-1", "ten-1", "fcm-token-aaa");
    const env = await makeServiceAccountEnv();
    const seen: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal("fetch", fcmFetchMock(seen));
    const res = await call(
      db,
      "POST",
      "/api/fcm/send",
      { device_id: "dev-1", title: "Jarvis test", body: "Hello from the hub", kind: "test" },
      { "x-internal-secret": "test-internal" },
      env,
    );
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.message_id).toBe("projects/omnijarvis-2bdd6/messages/msg-123");
    const fcmCall = seen.find((s) => String(s.url).includes("fcm.googleapis.com"));
    expect(fcmCall).toBeDefined();
    expect((fcmCall!.init.headers as Record<string, string>).Authorization).toBe("Bearer ya29.test-token");
    const sentBody = JSON.parse(String(fcmCall!.init.body)) as Record<string, Record<string, unknown>>;
    expect(sentBody.message.token).toBe("fcm-token-aaa");
    expect((sentBody.message.data as Record<string, string>).title).toBe("Jarvis test");
    expect((sentBody.message.data as Record<string, string>).body).toBe("Hello from the hub");
    expect((sentBody.message.data as Record<string, string>).kind).toBe("test");
    expect(sentBody.message.notification).toBeUndefined();
    expect((sentBody.message.android as Record<string, string>).priority).toBe("HIGH");
    const row = await db.prepare("SELECT status, fcm_message_id FROM fcm_sends WHERE device_id = ?").bind("dev-1").first<{ status: string; fcm_message_id: string }>();
    expect(row?.status).toBe("sent");
    expect(row?.fcm_message_id).toBe("projects/omnijarvis-2bdd6/messages/msg-123");
  });

  it("no internal secret -> 401; unpaired device -> 403; missing title -> 400", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "ten-1", key.publicKeyB64);
    const env = await makeServiceAccountEnv();
    const noSecret = await call(db, "POST", "/api/fcm/send", { device_id: "dev-1", title: "t", body: "b" }, {}, env);
    expect(noSecret.status).toBe(401);
    const unpaired = await call(db, "POST", "/api/fcm/send", { device_id: "dev-9", title: "t", body: "b" }, { "x-internal-secret": "test-internal" }, env);
    expect(unpaired.status).toBe(403);
    const noTitle = await call(db, "POST", "/api/fcm/send", { device_id: "dev-1", body: "b" }, { "x-internal-secret": "test-internal" }, env);
    expect(noTitle.status).toBe(400);
  });

  it("no token registered -> 200 ok:false no_token + D1 row; not configured -> not_configured + row", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "ten-1", key.publicKeyB64);
    const env = await makeServiceAccountEnv();
    const seen: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal("fetch", fcmFetchMock(seen));
    const noToken = await call(db, "POST", "/api/fcm/send", { device_id: "dev-1", title: "t", body: "b" }, { "x-internal-secret": "test-internal" }, env);
    expect(noToken.status).toBe(200);
    expect(noToken.body.ok).toBe(false);
    expect(noToken.body.error).toBe("no_token");
    let row = await db.prepare("SELECT status FROM fcm_sends WHERE device_id = ?").bind("dev-1").first<{ status: string }>();
    expect(row?.status).toBe("no_token");
    // Not configured: fresh device with a token but no service-account env.
    await seedDevice(db, "dev-2", "ten-1", key.publicKeyB64);
    await seedToken(db, "dev-2", "ten-1", "fcm-token-bbb");
    const notCfg = await call(db, "POST", "/api/fcm/send", { device_id: "dev-2", title: "t", body: "b" }, { "x-internal-secret": "test-internal" }, {});
    expect(notCfg.status).toBe(200);
    expect(notCfg.body.error).toBe("not_configured");
    row = await db.prepare("SELECT status FROM fcm_sends WHERE device_id = ?").bind("dev-2").first<{ status: string }>();
    expect(row?.status).toBe("not_configured");
  });

  it("FCM 404 UNREGISTERED deletes the stale token row + failed row; FCM 500 -> fcm_error; fetch throw -> fetch_failed", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "ten-1", key.publicKeyB64);
    await seedToken(db, "dev-1", "ten-1", "fcm-token-stale");
    const env = await makeServiceAccountEnv();
    const seen: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal(
      "fetch",
      fcmFetchMock(seen, 404, { error: { code: 404, message: "Requested entity was not found.", status: "UNREGISTERED" } }),
    );
    const unreg = await call(db, "POST", "/api/fcm/send", { device_id: "dev-1", title: "t", body: "b" }, { "x-internal-secret": "test-internal" }, env);
    expect(unreg.status).toBe(200);
    expect(unreg.body.ok).toBe(false);
    expect(unreg.body.error).toBe("fcm_error");
    expect(await getFcmRegistration(db, "dev-1")).toBeNull();
    let row = await db.prepare("SELECT status, error FROM fcm_sends WHERE device_id = ?").bind("dev-1").first<{ status: string; error: string }>();
    expect(row?.status).toBe("failed");
    expect(row?.error).toContain("UNREGISTERED");
    // FCM 500.
    await seedToken(db, "dev-1", "ten-1", "fcm-token-aaa");
    vi.stubGlobal("fetch", fcmFetchMock(seen, 500, { error: { code: 500, message: "Internal error.", status: "INTERNAL" } }));
    const err500 = await call(db, "POST", "/api/fcm/send", { device_id: "dev-1", title: "t", body: "b" }, { "x-internal-secret": "test-internal" }, env);
    expect(err500.body.ok).toBe(false);
    expect(err500.body.error).toBe("fcm_error");
    expect(err500.body.status).toBe(500);
    // Fetch throw.
    vi.stubGlobal("fetch", async () => {
      throw new Error("network down");
    });
    const thrown = await call(db, "POST", "/api/fcm/send", { device_id: "dev-1", title: "t", body: "b" }, { "x-internal-secret": "test-internal" }, env);
    expect(thrown.body.ok).toBe(false);
    expect(thrown.body.error).toBe("fetch_failed");
    const lastRow = await db.prepare("SELECT status FROM fcm_sends WHERE device_id = ? ORDER BY created_at DESC").bind("dev-1").first<{ status: string }>();
    expect(lastRow?.status).toBe("failed");
  });
});

describe("GET /api/fcm/status (internal-secret)", () => {
  it("registered true with updated_at when a token exists, false otherwise; no secret -> 401", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "ten-1", key.publicKeyB64);
    await seedToken(db, "dev-1", "ten-1", "fcm-token-aaa");
    const yes = await call(db, "GET", "/api/fcm/status?device_id=dev-1");
    expect(yes.status).toBe(200);
    expect(yes.body.registered).toBe(true);
    expect(typeof yes.body.updated_at).toBe("number");
    const no = await call(db, "GET", "/api/fcm/status?device_id=dev-9");
    expect(no.body.registered).toBe(false);
    expect(no.body.updated_at).toBeNull();
    const unauth = await call(db, "GET", "/api/fcm/status?device_id=dev-1", undefined, {});
    expect(unauth.status).toBe(401);
  });
});

describe("sendFcm unit (mocked fetch, no hub)", () => {
  it("records not_configured without calling fetch", async () => {
    const db = new FakeD1();
    let calls = 0;
    vi.stubGlobal("fetch", async () => {
      calls++;
      return new Response("{}", { status: 200 });
    });
    const res = await sendFcm({}, db, { tenantId: "ten-1", deviceId: "dev-1", title: "t", body: "b" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("not_configured");
    expect(calls).toBe(0);
    const row = await db.prepare("SELECT status FROM fcm_sends WHERE device_id = ?").bind("dev-1").first<{ status: string }>();
    expect(row?.status).toBe("not_configured");
  });
});
