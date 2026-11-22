/**
 * google.test.ts — Track E #27: direct Google OAuth (Gmail + Drive).
 * All Google HTTP is mocked (fetchFn / stubbed global fetch) — no
 * network, no real credentials. No secret value appears anywhere:
 * the test master key + tokens are random per-run values.
 */
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { handleRequest, type Env } from "../src/hub";
import { FakeD1 } from "./fake-d1";
import { genDeviceKey } from "./helpers";
import { canonicalString } from "../src/crypto";
import { resetRateLimitFallback } from "../src/ratelimit";
import {
  GOOGLE_SCOPES,
  buildAuthUrl,
  consumeOAuthState,
  driveReadFile,
  exchangeCodeForTokens,
  getValidAccessToken,
  gmailListMessages,
  gmailSend,
  googleStatus,
  issueOAuthState,
  loadGoogleTokens,
  storeGoogleTokens,
  GoogleError,
  type TokenSet,
} from "../src/google";

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

function fakeEnv(db: FakeD1, overrides: Partial<Env> = {}): Env {
  return {
    JARVIS_HUB: { idFromName: (n: string) => ({ name: n }), get: () => ({ fetch: async () => new Response("{}") }) } as unknown as DurableObjectNamespace,
    DB: db as unknown as D1Database,
    INTERNAL_SECRET: "internal-secret",
    CRON_SECRET: "cron-secret",
    ...GOOGLE_ENV,
    ...overrides,
  } as Env;
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string, publicKeyB64: string) {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, publicKeyB64, Date.now(), Date.now(), 1)
    .run();
}

async function seedTokens(db: FakeD1, tenantId: string, email = "owner@example.com", expiresInMs = 3_600_000): Promise<TokenSet> {
  const tokens: TokenSet = {
    accessToken: `ya29.test-access-${tenantId}`,
    refreshToken: `1//test-refresh-${tenantId}`,
    expiresAt: Date.now() + expiresInMs,
    scopes: GOOGLE_SCOPES.join(" "),
  };
  await storeGoogleTokens(db, GOOGLE_ENV, tenantId, email, tokens);
  return tokens;
}

/** Signed headers for a GET route (payloadRaw = path + query). */
async function signedGetHeaders(
  key: Awaited<ReturnType<typeof genDeviceKey>>,
  deviceId: string,
  pathAndQuery: string,
) {
  const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const ts = Date.now();
  const sig = await key.sign(canonicalString(deviceId, nonce, ts, pathAndQuery));
  return { "x-device-id": deviceId, "x-nonce": nonce, "x-ts": String(ts), "x-signature": sig };
}

/** Mock fetch routing by URL (token exchange / userinfo / gmail / drive). */
function mockGoogleFetch(handlers: Array<{ match: (url: string, init?: RequestInit) => boolean; response: (url: string, init?: RequestInit) => { status: number; body: unknown } }>): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    const u = String(url);
    for (const h of handlers) {
      if (h.match(u, init)) {
        const r = h.response(u, init);
        return new Response(JSON.stringify(r.body), { status: r.status, headers: { "Content-Type": "application/json" } });
      }
    }
    return new Response(JSON.stringify({ error: "not_mocked", url: u }), { status: 404 });
  }) as unknown as typeof fetch;
}

beforeEach(() => resetRateLimitFallback());
afterEach(() => vi.unstubAllGlobals());

describe("migration 0010 (Google OAuth vault)", () => {
  const SQL = readFileSync(new URL("../d1/migrations/0010_google_oauth.sql", import.meta.url), "utf8");
  it("creates google_tokens + google_oauth_states (IF NOT EXISTS)", () => {
    expect(SQL).toContain("CREATE TABLE IF NOT EXISTS google_tokens (");
    expect(SQL).toContain("CREATE TABLE IF NOT EXISTS google_oauth_states (");
    expect(SQL).toContain("tenant_id TEXT PRIMARY KEY");
    expect(SQL).toContain("access_token_enc TEXT NOT NULL");
    expect(SQL).toContain("refresh_token_enc TEXT NOT NULL");
  });
  it("is non-destructive", () => {
    const code = SQL.replace(/--[^\n]*/g, "");
    expect(code).not.toMatch(/DROP\s+TABLE/i);
    expect(code).not.toMatch(/TRUNCATE/i);
    expect(code).not.toMatch(/DELETE\s+FROM/i);
  });
});

describe("buildAuthUrl", () => {
  it("consent URL shape: auth host, client, redirect, offline + consent, minimal scopes", () => {
    const url = new URL(buildAuthUrl(GOOGLE_ENV, "https://omnijarvis-hub.rajraj3kk.workers.dev", "state-123"));
    expect(url.origin + url.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(url.searchParams.get("client_id")).toBe(GOOGLE_ENV.GOOGLE_OAUTH_CLIENT_ID);
    expect(url.searchParams.get("redirect_uri")).toBe("https://omnijarvis-hub.rajraj3kk.workers.dev/oauth/google/callback");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("access_type")).toBe("offline");
    expect(url.searchParams.get("prompt")).toBe("consent");
    expect(url.searchParams.get("state")).toBe("state-123");
    const scopes = url.searchParams.get("scope")?.split(" ") ?? [];
    expect(scopes).toContain("https://www.googleapis.com/auth/gmail.readonly");
    expect(scopes).toContain("https://www.googleapis.com/auth/gmail.send");
    expect(scopes).toContain("https://www.googleapis.com/auth/drive.readonly");
    expect(scopes).not.toContain("https://www.googleapis.com/auth/gmail.modify");
    expect(scopes).not.toContain("https://www.googleapis.com/auth/drive");
  });
  it("no client id/secret -> google_oauth_not_configured (honest, never fake success)", () => {
    expect(() => buildAuthUrl({}, "https://hub.example", "s")).toThrowError(GoogleError);
    try {
      buildAuthUrl({}, "https://hub.example", "s");
    } catch (e) {
      expect((e as GoogleError).code).toBe("google_oauth_not_configured");
      expect((e as GoogleError).status).toBe(503);
    }
  });
});

describe("OAuth state rows", () => {
  it("issue -> consume round-trips; second consume is null (one-time)", async () => {
    const db = new FakeD1();
    const state = await issueOAuthState(db, "t-1", "dev-1");
    expect(state).toMatch(/^[0-9a-f]{32}$/);
    expect(await consumeOAuthState(db, state)).toEqual({ tenant_id: "t-1", device_id: "dev-1" });
    expect(await consumeOAuthState(db, state)).toBeNull();
  });
  it("unknown state -> null", async () => {
    const db = new FakeD1();
    expect(await consumeOAuthState(db, "nope")).toBeNull();
  });
  it("expired state -> null (row still consumed, never reusable)", async () => {
    const db = new FakeD1();
    const state = await issueOAuthState(db, "t-1", "dev-1");
    await db.prepare("UPDATE google_oauth_states SET expires_at = ? WHERE state = ?").bind(Date.now() - 1000, state).run();
    expect(await consumeOAuthState(db, state)).toBeNull();
    expect(await consumeOAuthState(db, state)).toBeNull();
  });
});

describe("exchangeCodeForTokens (mocked fetch)", () => {
  it("success returns access + refresh + expiry", async () => {
    const fetchFn = mockGoogleFetch([
      {
        match: (u) => u.includes("oauth2.googleapis.com/token"),
        response: () => ({ status: 200, body: { access_token: "ya29.a", refresh_token: "1//r", expires_in: 3599, scope: GOOGLE_SCOPES.join(" ") } }),
      },
    ]);
    const tokens = await exchangeCodeForTokens(GOOGLE_ENV, "auth-code", "https://hub.example", fetchFn);
    expect(tokens.accessToken).toBe("ya29.a");
    expect(tokens.refreshToken).toBe("1//r");
    expect(tokens.expiresAt).toBeGreaterThan(Date.now());
  });
  it("Google 400 -> google_token_exchange_failed", async () => {
    const fetchFn = mockGoogleFetch([
      { match: (u) => u.includes("oauth2.googleapis.com/token"), response: () => ({ status: 400, body: { error: "invalid_grant" } }) },
    ]);
    await expect(exchangeCodeForTokens(GOOGLE_ENV, "bad-code", "https://hub.example", fetchFn)).rejects.toMatchObject({ code: "google_token_exchange_failed" });
  });
  it("no refresh token in response -> google_no_refresh_token (never store an unrefreshable row)", async () => {
    const fetchFn = mockGoogleFetch([
      { match: (u) => u.includes("oauth2.googleapis.com/token"), response: () => ({ status: 200, body: { access_token: "ya29.a", expires_in: 3600 } }) },
    ]);
    await expect(exchangeCodeForTokens(GOOGLE_ENV, "code", "https://hub.example", fetchFn)).rejects.toMatchObject({ code: "google_no_refresh_token" });
  });
});

describe("token vault (D1, AES-GCM envelope)", () => {
  it("store -> load round-trips plaintext; status reports connected WITHOUT tokens", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-1", "owner@example.com");
    const loaded = await loadGoogleTokens(db, GOOGLE_ENV, "t-1");
    expect(loaded?.accessToken).toBe("ya29.test-access-t-1");
    expect(loaded?.refreshToken).toBe("1//test-refresh-t-1");
    expect(loaded?.google_email).toBe("owner@example.com");
    const status = await googleStatus(db, GOOGLE_ENV, "t-1");
    expect(status).toEqual({ configured: true, connected: true, email: "owner@example.com", scopes: GOOGLE_SCOPES.join(" "), expires_at: loaded?.expiresAt });
    expect(JSON.stringify(status)).not.toContain("ya29.");
    expect(JSON.stringify(status)).not.toContain("1//test-refresh");
    // Stored envelope is ciphertext, never the plaintext token.
    const row = await db.prepare("SELECT access_token_enc FROM google_tokens WHERE tenant_id = ?").bind("t-1").first<{ access_token_enc: string }>();
    expect(row?.access_token_enc).not.toContain("ya29.test-access");
  });
  it("status: no row -> connected:false; no env -> configured:false", async () => {
    const db = new FakeD1();
    expect(await googleStatus(db, GOOGLE_ENV, "t-none")).toEqual({ configured: true, connected: false });
    expect(await googleStatus(db, {}, "t-none")).toEqual({ configured: false, connected: false });
  });
  it("second connect upserts (one account per tenant, no duplicate row)", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-1", "first@example.com");
    await seedTokens(db, "t-1", "second@example.com");
    const loaded = await loadGoogleTokens(db, GOOGLE_ENV, "t-1");
    expect(loaded?.google_email).toBe("second@example.com");
    const count = await db.prepare("SELECT COUNT(*) AS n FROM google_tokens WHERE tenant_id = ?").bind("t-1").first<{ n: number }>();
    expect(count?.n).toBe(1);
  });
});

describe("refresh on expiry", () => {
  it("fresh token returned as-is (no Google call)", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-1");
    const fetchFn = mockGoogleFetch([]);
    const got = await getValidAccessToken({ db, env: GOOGLE_ENV, tenantId: "t-1", fetchFn });
    expect(got.accessToken).toBe("ya29.test-access-t-1");
  });
  it("expired token refreshes and the row is updated", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-1", "owner@example.com", -1000); // already expired
    const fetchFn = mockGoogleFetch([
      { match: (u) => u.includes("oauth2.googleapis.com/token"), response: () => ({ status: 200, body: { access_token: "ya29.refreshed", expires_in: 3600 } }) },
    ]);
    const got = await getValidAccessToken({ db, env: GOOGLE_ENV, tenantId: "t-1", fetchFn });
    expect(got.accessToken).toBe("ya29.refreshed");
    const reloaded = await loadGoogleTokens(db, GOOGLE_ENV, "t-1");
    expect(reloaded?.accessToken).toBe("ya29.refreshed");
    expect(reloaded?.refreshToken).toBe("1//test-refresh-t-1"); // kept when Google sends none
  });
  it("invalid_grant on refresh deletes the row and throws google_not_connected", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-1", "owner@example.com", -1000);
    const fetchFn = mockGoogleFetch([
      { match: (u) => u.includes("oauth2.googleapis.com/token"), response: () => ({ status: 400, body: { error: "invalid_grant" } }) },
    ]);
    await expect(getValidAccessToken({ db, env: GOOGLE_ENV, tenantId: "t-1", fetchFn })).rejects.toMatchObject({ code: "google_not_connected" });
    expect(await loadGoogleTokens(db, GOOGLE_ENV, "t-1")).toBeNull();
  });
  it("no stored tokens -> google_not_connected", async () => {
    const db = new FakeD1();
    await expect(getValidAccessToken({ db, env: GOOGLE_ENV, tenantId: "t-none", fetchFn: mockGoogleFetch([]) })).rejects.toMatchObject({ code: "google_not_connected" });
  });
});

describe("Gmail helpers (mocked fetch)", () => {
  it("gmailSend posts base64url RFC822 with To/Subject", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-1");
    let capturedRaw = "";
    const fetchFn = mockGoogleFetch([
      {
        match: (u, init) => u.includes("/messages/send") && init?.method === "POST",
        response: (_u, init) => {
          capturedRaw = (JSON.parse(String(init?.body)) as { raw: string }).raw;
          return { status: 200, body: { id: "msg-123" } };
        },
      },
    ]);
    const sent = await gmailSend({ db, env: GOOGLE_ENV, tenantId: "t-1", fetchFn }, { to: "a@example.com", subject: "Hi", body: "hello" });
    expect(sent.id).toBe("msg-123");
    const decoded = new TextDecoder().decode(Uint8Array.from(atob(capturedRaw.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));
    expect(decoded).toContain("To: a@example.com");
    expect(decoded).toContain("Subject: Hi");
    expect(decoded).toContain("hello");
  });
  it("gmailListMessages parses subject/from/body from format=full", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-1");
    const bodyB64 = btoa("Hello from the body").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const fetchFn = mockGoogleFetch([
      { match: (u) => u.includes("/messages?"), response: () => ({ status: 200, body: { messages: [{ id: "m1" }] } }) },
      {
        match: (u) => u.includes("/messages/m1?"),
        response: () => ({
          status: 200,
          body: { id: "m1", snippet: "Hello from the", payload: { mimeType: "text/plain", headers: [{ name: "Subject", value: "Test subj" }, { name: "From", value: "b@example.com" }, { name: "Date", value: "Sun, 22 Nov 2026" }], body: { data: bodyB64 } } },
        }),
      },
    ]);
    const msgs = await gmailListMessages({ db, env: GOOGLE_ENV, tenantId: "t-1", fetchFn }, { q: "test" });
    expect(msgs).toHaveLength(1);
    expect(msgs[0].subject).toBe("Test subj");
    expect(msgs[0].from).toBe("b@example.com");
    expect(msgs[0].body).toBe("Hello from the body");
  });
});

describe("Drive helper (mocked fetch)", () => {
  it("native Google Doc exports as text/plain", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-1");
    const fetchFn = (async (url: string) => {
      const u = String(url);
      if (u.includes("/export?")) return new Response("doc text here", { status: 200 });
      return new Response(JSON.stringify({ id: "f1", name: "Notes", mimeType: "application/vnd.google-apps.document" }), { status: 200 });
    }) as unknown as typeof fetch;
    const file = await driveReadFile({ db, env: GOOGLE_ENV, tenantId: "t-1", fetchFn }, "f1");
    expect(file.name).toBe("Notes");
    expect(file.text).toBe("doc text here");
  });
  it("oversize file returns metadata + content_too_large (never truncated silently)", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-1");
    const fetchFn = mockGoogleFetch([
      { match: (u) => u.includes("/files/big"), response: () => ({ status: 200, body: { id: "big", name: "big.bin", mimeType: "application/octet-stream", size: String(2 * 1024 * 1024) } }) },
    ]);
    const file = await driveReadFile({ db, env: GOOGLE_ENV, tenantId: "t-1", fetchFn }, "big");
    expect(file.text).toBeNull();
    expect(file.content_note).toBe("content_too_large");
  });
});

describe("hub routes (handleRequest, mocked global fetch)", () => {
  it("GET /oauth/google/start without env -> 503 google_oauth_not_configured", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-start-1", key.publicKeyB64);
    const path = "/oauth/google/start?device_id=dev-1";
    const res = await handleRequest(
      new Request(`https://hub.example${path}`, { headers: await signedGetHeaders(key, "dev-1", path) }),
      fakeEnv(db, { GOOGLE_OAUTH_CLIENT_ID: undefined, GOOGLE_OAUTH_CLIENT_SECRET: undefined }),
    );
    expect(res.status).toBe(503);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("google_oauth_not_configured");
  });

  it("GET /oauth/google/start signed -> 200 auth_url; callback full flow stores tokens + HTML success", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-start-2", key.publicKeyB64);
    const path = "/oauth/google/start?device_id=dev-1";
    const startRes = await handleRequest(
      new Request(`https://hub.example${path}`, { headers: await signedGetHeaders(key, "dev-1", path) }),
      fakeEnv(db),
    );
    expect(startRes.status).toBe(200);
    const startBody = (await startRes.json()) as { auth_url: string; redirect_uri: string };
    const state = new URL(startBody.auth_url).searchParams.get("state") ?? "";
    expect(state).toMatch(/^[0-9a-f]{32}$/);
    expect(startBody.redirect_uri).toBe("https://hub.example/oauth/google/callback");

    vi.stubGlobal("fetch", mockGoogleFetch([
      { match: (u) => u.includes("oauth2.googleapis.com/token"), response: () => ({ status: 200, body: { access_token: "ya29.cb", refresh_token: "1//cb", expires_in: 3600, scope: GOOGLE_SCOPES.join(" ") } }) },
      { match: (u) => u.includes("oauth2/v2/userinfo"), response: () => ({ status: 200, body: { email: "owner@example.com" } }) },
    ]));
    const cbRes = await handleRequest(
      new Request(`https://hub.example/oauth/google/callback?code=auth-code&state=${state}`),
      fakeEnv(db),
    );
    expect(cbRes.status).toBe(200);
    expect(cbRes.headers.get("Content-Type")).toContain("text/html");
    expect(await cbRes.text()).toContain("Google connected");
    const stored = await loadGoogleTokens(db, GOOGLE_ENV, "t-start-2");
    expect(stored?.accessToken).toBe("ya29.cb");
    expect(stored?.google_email).toBe("owner@example.com");
  });

  it("GET /oauth/google/callback with unknown state -> HTML 400 (no tokens stored)", async () => {
    const db = new FakeD1();
    const res = await handleRequest(
      new Request("https://hub.example/oauth/google/callback?code=x&state=deadbeef"),
      fakeEnv(db),
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("expire");
  });

  it("GET /api/google/status signed -> connected:true with email, no tokens; unsigned -> 401", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-status-1", key.publicKeyB64);
    await seedTokens(db, "t-status-1");
    const path = "/api/google/status?device_id=dev-1";
    const res = await handleRequest(
      new Request(`https://hub.example${path}`, { headers: await signedGetHeaders(key, "dev-1", path) }),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(body.connected).toBe(true);
    expect(body.email).toBe("owner@example.com");
    expect(JSON.stringify(body)).not.toContain("ya29.");

    const unauth = await handleRequest(new Request("https://hub.example/api/google/status?device_id=dev-1"), fakeEnv(db));
    expect(unauth.status).toBe(401);
  });

  it("POST /api/google/gmail/send via x-internal-secret -> 200 id; bad 'to' -> 400", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-send-1");
    vi.stubGlobal("fetch", mockGoogleFetch([
      { match: (u) => u.includes("/messages/send"), response: () => ({ status: 200, body: { id: "msg-9" } }) },
    ]));
    const env = fakeEnv(db);
    const ok = await handleRequest(
      new Request("https://hub.example/api/google/gmail/send", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "internal-secret" },
        body: JSON.stringify({ tenant_id: "t-send-1", to: "a@example.com", subject: "S", body: "B" }),
      }),
      env,
    );
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as Record<string, unknown>).id).toBe("msg-9");
    const bad = await handleRequest(
      new Request("https://hub.example/api/google/gmail/send", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "internal-secret" },
        body: JSON.stringify({ tenant_id: "t-send-1", to: "not-an-email", subject: "S", body: "B" }),
      }),
      env,
    );
    expect(bad.status).toBe(400);
  });

  it("POST /api/google/revoke deletes the row and reports connected:false (idempotent)", async () => {
    const db = new FakeD1();
    await seedTokens(db, "t-revoke-1");
    vi.stubGlobal("fetch", mockGoogleFetch([
      { match: (u) => u.includes("oauth2.googleapis.com/revoke"), response: () => ({ status: 200, body: {} }) },
    ]));
    const env = fakeEnv(db);
    const mkReq = () =>
      new Request("https://hub.example/api/google/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "internal-secret" },
        body: JSON.stringify({ tenant_id: "t-revoke-1" }),
      });
    const res = await handleRequest(mkReq(), env);
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>).connected).toBe(false);
    expect(await loadGoogleTokens(db, GOOGLE_ENV, "t-revoke-1")).toBeNull();
    const again = await handleRequest(mkReq(), env);
    expect(again.status).toBe(200);
  });
});
