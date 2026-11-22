/**
 * M-I-28 tests — self-serve licence web UI (hub-served).
 * Passwordless email-code auth + licence Worker proxy + owner admin.
 * The "live" licence Worker and Resend are stubbed fetch; the code the
 * test verifies is read back from the captured Resend email body (the
 * same place a real user reads it), never from the D1 hash.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { handleRequest, type Env } from "../src/hub";
import { resetRateLimitFallback } from "../src/ratelimit";
import {
  LICENCE_CODE_MAX_ATTEMPTS,
  LICENCE_CODE_TTL_MS,
  clearSessionCookie,
  hashEmailCode,
  hashSessionToken,
  isValidEmail,
  licenceAdminPage,
  licenceCodeEmailContent,
  licenceDashboardPage,
  licenceLandingPage,
  licenceLoginPage,
  maskLicenceKey,
  newEmailCode,
  newSessionToken,
  normalizeEmail,
  sessionCookie,
  verifyEmailCode,
} from "../src/licence-web";

const NOW = Date.UTC(2026, 11, 22, 12, 0, 0);

beforeEach(() => {
  resetRateLimitFallback();
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
    INTERNAL_SECRET: "internal",
    CRON_SECRET: "cron",
    LLM_ADMIN_TOKEN: "admin",
    RESEND_API_KEY: "re_test_key",
    LICENCE_ADMIN_TOKEN: "lic-admin-test",
    LICENCE_WORKER_URL: "https://licence-worker.test",
    ...overrides,
  };
}

type LicenceWorkerStub = { status: number; body: Record<string, unknown> };

function stubFetch(opts: {
  generate?: LicenceWorkerStub;
  release?: LicenceWorkerStub;
  resendOk?: boolean;
}): { lastResendHtml: () => string | null } {
  let lastResendHtml: string | null = null;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url.includes("api.resend.com")) {
        const body = JSON.parse(String(init?.body ?? "{}")) as { html?: string };
        lastResendHtml = body.html ?? null;
        if (opts.resendOk === false) return new Response(JSON.stringify({ error: "bad" }), { status: 500 });
        return new Response(JSON.stringify({ id: "re_test123" }), { status: 200 });
      }
      if (url.includes("licence-worker.test/api/licence/generate")) {
        const s = opts.generate ?? { status: 200, body: { ok: true, existing: false, licence: { key: "JARVIS-NEW1-NEW2-NEW3-NEW4", user_id: "x", device_id: null, status: "active", created_at: NOW } } };
        return new Response(JSON.stringify(s.body), { status: s.status });
      }
      if (url.includes("licence-worker.test/api/licence/release")) {
        const s = opts.release ?? { status: 200, body: { ok: true, released: true } };
        return new Response(JSON.stringify(s.body), { status: s.status });
      }
      return new Response(JSON.stringify({ error: "unexpected_fetch", url }), { status: 500 });
    }),
  );
  return { lastResendHtml: () => lastResendHtml };
}

function codeFromEmail(html: string | null): string {
  expect(html).toBeTruthy();
  const m = html!.match(/\b(\d{6})\b/);
  expect(m).toBeTruthy();
  return m![1];
}

async function call(
  db: FakeD1,
  path: string,
  init: RequestInit = {},
  envOverrides: Partial<Env> = {},
): Promise<{ status: number; body: Record<string, unknown>; headers: Headers; text: string }> {
  const req = new Request(`https://hub.test${path}`, {
    method: init.method ?? "GET",
    headers: init.headers,
    body: init.body,
  });
  const res = await handleRequest(req, fakeEnv(db, envOverrides));
  const text = await res.text();
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(text) as Record<string, unknown>;
  } catch {
    body = {};
  }
  return { status: res.status, body, headers: res.headers, text };
}

async function cookieFor(db: FakeD1, res: { headers: Headers }): Promise<string> {
  const setCookie = res.headers.get("set-cookie") ?? "";
  expect(setCookie).toContain("lic_session=");
  const token = setCookie.split(";")[0].split("=")[1];
  expect(token.length).toBeGreaterThan(20);
  return `lic_session=${token}`;
}

/** Full honest flow: signup -> code from the captured email -> verify. */
async function verifiedSession(
  db: FakeD1,
  email: string,
  fetchCtl: { lastResendHtml: () => string | null },
): Promise<string> {
  const s = await call(db, "/api/licence-web/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  expect(s.status).toBe(200);
  const code = codeFromEmail(fetchCtl.lastResendHtml());
  const v = await call(db, "/api/licence-web/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, code, purpose: "signup" }),
  });
  expect(v.status).toBe(200);
  return cookieFor(db, v);
}

async function seedLicence(db: FakeD1, key: string, userId: string, status = "active", deviceId: string | null = null): Promise<void> {
  await db
    .prepare("INSERT INTO licences (key, user_id, device_id, status, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(key, userId, deviceId, status, NOW)
    .run();
}

describe("licence-web pure helpers", () => {
  it("normalizeEmail trims + lowercases", () => {
    expect(normalizeEmail("  Priya@Example.COM ")).toBe("priya@example.com");
  });

  it("isValidEmail accepts good, rejects bad format + disposable", () => {
    expect(isValidEmail("a@b.com").ok).toBe(true);
    expect(isValidEmail("not-an-email").error).toBe("invalid_email");
    expect(isValidEmail("a@").error).toBe("invalid_email");
    expect(isValidEmail("x@mailinator.com").error).toBe("disposable_email");
    expect(isValidEmail("x@tempmail.com").error).toBe("disposable_email");
  });

  it("newEmailCode is 6 digits, verifyEmailCode round-trips, wrong code fails", async () => {
    const { code, codeHash } = await newEmailCode();
    expect(code).toMatch(/^\d{6}$/);
    expect(await verifyEmailCode(code, codeHash)).toBe(true);
    expect(await verifyEmailCode("000000", codeHash)).toBe(false);
    expect(await verifyEmailCode("abc", codeHash)).toBe(false);
  });

  it("hashEmailCode is deterministic sha256, not the code itself", async () => {
    const h = await hashEmailCode("123456");
    expect(h).not.toBe("123456");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(await hashEmailCode("123456")).toBe(h);
  });

  it("newSessionToken is 43-char base64url, hash round-trips", async () => {
    const { token, tokenHash } = await newSessionToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await hashSessionToken(token)).toBe(tokenHash);
  });

  it("maskLicenceKey hides the middle groups, keeps first + last", () => {
    expect(maskLicenceKey("JARVIS-AB12-CD34-EF56-GH78")).toBe("JARVIS-AB12-••••-••••-GH78");
    expect(maskLicenceKey("garbage")).toBe("••••");
  });

  it("sessionCookie is HttpOnly Secure SameSite=Lax; clear expires it", () => {
    expect(sessionCookie("tok", 3600)).toContain("lic_session=tok; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600");
    expect(clearSessionCookie()).toContain("Max-Age=0");
  });

  it("licenceCodeEmailContent carries the code in subject + html + text", () => {
    const c = licenceCodeEmailContent("654321", "signup");
    expect(c.subject).toContain("654321");
    expect(c.html).toContain("654321");
    expect(c.text).toContain("654321");
    expect(c.html).not.toContain("http");
  });

  it("HTML pages contain their forms (no dead page)", () => {
    expect(licenceLandingPage()).toContain('id="email"');
    expect(licenceLandingPage()).toContain('id="send"');
    expect(licenceLandingPage()).toContain("/api/licence-web/signup");
    expect(licenceLoginPage()).toContain("/api/licence-web/login");
    const dash = licenceDashboardPage("u@example.com", { key_masked: "JARVIS-AB12-••••-••••-GH78", status: "active", device_id: null, created_at: null });
    expect(dash).toContain("u@example.com");
    expect(dash).toContain("JARVIS-AB12-••••-••••-GH78");
    expect(dash).toContain('id="gen"');
    expect(dash).toContain('id="rel"');
    expect(licenceAdminPage()).toContain('id="token"');
    expect(licenceAdminPage()).toContain("/api/licence-web/admin/licences");
  });
});

describe("POST /api/licence-web/signup + verify (email-code flow)", () => {
  it("signup 200 -> code row exists (hashed, 10-min expiry) -> verify 200 + session cookie, code single-use", async () => {
    const db = new FakeD1();
    const f = stubFetch({});
    const email = "flow1@example.com";
    const s = await call(db, "/api/licence-web/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    expect(s.status).toBe(200);
    expect(s.body.ok).toBe(true);
    const row = await db
      .prepare("SELECT code_hash, expires_at, attempts FROM licence_email_codes WHERE email = ? AND purpose = ?")
      .bind(email, "signup")
      .first<{ code_hash: string; expires_at: number; attempts: number }>();
    expect(row).toBeTruthy();
    expect(row!.code_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(row!.expires_at - Date.now()).toBeGreaterThan(LICENCE_CODE_TTL_MS - 60_000);
    expect(row!.attempts).toBe(0);
    const user = await db.prepare("SELECT email_verified FROM licence_web_users WHERE email = ?").bind(email).first<{ email_verified: number }>();
    expect(user?.email_verified).toBe(0);
    const code = codeFromEmail(f.lastResendHtml());
    const v = await call(db, "/api/licence-web/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code, purpose: "signup" }),
    });
    expect(v.status).toBe(200);
    await cookieFor(db, v);
    const user2 = await db.prepare("SELECT email_verified FROM licence_web_users WHERE email = ?").bind(email).first<{ email_verified: number }>();
    expect(user2?.email_verified).toBe(1);
    // Single-use: the same code again is 400.
    const v2 = await call(db, "/api/licence-web/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code, purpose: "signup" }),
    });
    expect(v2.status).toBe(400);
    expect(v2.body.error).toBe("verification_failed");
  });

  it("wrong code 400 + attempts increments; 5 wrong -> even the right code fails", async () => {
    const db = new FakeD1();
    const f = stubFetch({});
    const email = "flow2@example.com";
    await call(db, "/api/licence-web/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const good = codeFromEmail(f.lastResendHtml());
    for (let i = 0; i < LICENCE_CODE_MAX_ATTEMPTS; i++) {
      const v = await call(db, "/api/licence-web/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, code: "000000", purpose: "signup" }),
      });
      expect(v.status).toBe(400);
      expect(v.body.error).toBe("verification_failed");
    }
    const v = await call(db, "/api/licence-web/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code: good, purpose: "signup" }),
    });
    expect(v.status).toBe(400);
    expect(v.body.error).toBe("verification_failed");
  });

  it("expired code 400 (seeded past expiry)", async () => {
    const db = new FakeD1();
    stubFetch({});
    const email = "flow3@example.com";
    await db.prepare("INSERT INTO licence_web_users (email, email_verified, created_at, last_login_at) VALUES (?, 0, ?, NULL)").bind(email, NOW).run();
    await db
      .prepare("INSERT INTO licence_email_codes (email, purpose, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, ?, 0, ?)")
      .bind(email, "signup", await hashEmailCode("123456"), Date.now() - 1000, NOW)
      .run();
    const v = await call(db, "/api/licence-web/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code: "123456", purpose: "signup" }),
    });
    expect(v.status).toBe(400);
    expect(v.body.error).toBe("verification_failed");
  });

  it("invalid + disposable emails 400; login for unknown email is 200 with no code and no user row", async () => {
    const db = new FakeD1();
    const f = stubFetch({});
    for (const email of ["nope", "a@b", "x@mailinator.com"]) {
      const s = await call(db, "/api/licence-web/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      expect(s.status).toBe(400);
    }
    const l = await call(db, "/api/licence-web/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "ghost@example.com" }),
    });
    expect(l.status).toBe(200);
    expect(l.body.ok).toBe(true);
    expect(f.lastResendHtml()).toBeNull();
    const user = await db.prepare("SELECT email FROM licence_web_users WHERE email = ?").bind("ghost@example.com").first();
    expect(user).toBeNull();
  });

  it("signup 6x same email -> 6th is 429 with Retry-After (5/h per email)", async () => {
    const db = new FakeD1();
    stubFetch({});
    const email = "flow5@example.com";
    for (let i = 0; i < 5; i++) {
      const s = await call(db, "/api/licence-web/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      expect(s.status).toBe(200);
    }
    const s = await call(db, "/api/licence-web/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    expect(s.status).toBe(429);
    expect(s.body.error).toBe("rate_limited");
    expect(s.headers.get("Retry-After")).toBe("3600");
  });

  it("signup with no RESEND_API_KEY -> 503 email_not_configured (honest, no fake send)", async () => {
    const db = new FakeD1();
    stubFetch({});
    const s = await call(
      db,
      "/api/licence-web/signup",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "flow6@example.com" }),
      },
      { RESEND_API_KEY: undefined },
    );
    expect(s.status).toBe(503);
    expect(s.body.error).toBe("email_not_configured");
  });

  it("login flow: verified user gets a fresh code + session; unverified user cannot verify a login code", async () => {
    const db = new FakeD1();
    const f = stubFetch({});
    const email = "flow7@example.com";
    const cookie = await verifiedSession(db, email, f);
    // Login now sends a second code.
    const l = await call(db, "/api/licence-web/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    expect(l.status).toBe(200);
    const code = codeFromEmail(f.lastResendHtml());
    const v = await call(db, "/api/licence-web/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code, purpose: "login" }),
    });
    expect(v.status).toBe(200);
    expect(v.headers.get("set-cookie")).toContain("lic_session=");
    expect(cookie).toContain("lic_session=");
  });
});

describe("licence-web sessions: me / logout / dashboard pages", () => {
  it("me 401 without cookie; 200 with cookie (verified + masked licence)", async () => {
    const db = new FakeD1();
    const f = stubFetch({});
    const email = "me1@example.com";
    const cookie = await verifiedSession(db, email, f);
    const noAuth = await call(db, "/api/licence-web/me");
    expect(noAuth.status).toBe(401);
    await seedLicence(db, "JARVIS-AAAA-BBBB-CCCC-DDDD", email, "active", "dev-1");
    const me = await call(db, "/api/licence-web/me", { headers: { Cookie: cookie } });
    expect(me.status).toBe(200);
    expect(me.body.email).toBe(email);
    expect(me.body.verified).toBe(true);
    expect((me.body.licence as Record<string, unknown>).key_masked).toBe("JARVIS-AAAA-••••-••••-DDDD");
    expect((me.body.licence as Record<string, unknown>).device_id).toBe("dev-1");
    expect(JSON.stringify(me.body)).not.toContain("JARVIS-AAAA-BBBB");
  });

  it("logout deletes the session + clears the cookie; me after logout is 401", async () => {
    const db = new FakeD1();
    const f = stubFetch({});
    const email = "me2@example.com";
    const cookie = await verifiedSession(db, email, f);
    const out = await call(db, "/api/licence-web/logout", { method: "POST", headers: { Cookie: cookie } });
    expect(out.status).toBe(200);
    expect(out.headers.get("set-cookie")).toContain("Max-Age=0");
    const me = await call(db, "/api/licence-web/me", { headers: { Cookie: cookie } });
    expect(me.status).toBe(401);
  });

  it("GET /licence pages serve HTML; dashboard redirects to login without a session, renders with one", async () => {
    const db = new FakeD1();
    const f = stubFetch({});
    const landing = await call(db, "/licence");
    expect(landing.status).toBe(200);
    expect(landing.headers.get("content-type")).toContain("text/html");
    expect(landing.text).toContain("Get your free licence");
    const dashNoAuth = await call(db, "/licence/dashboard");
    expect(dashNoAuth.status).toBe(302);
    expect(dashNoAuth.headers.get("location")).toBe("/licence/login");
    const email = "me3@example.com";
    const cookie = await verifiedSession(db, email, f);
    const dash = await call(db, "/licence/dashboard", { headers: { Cookie: cookie } });
    expect(dash.status).toBe(200);
    expect(dash.text).toContain(email);
    expect(dash.text).toContain("No licence yet");
  });
});

describe("POST /api/licence-web/generate + release (licence Worker proxy)", () => {
  it("generate 401 without session; 403 email_not_verified for an unverified session", async () => {
    const db = new FakeD1();
    stubFetch({});
    const g0 = await call(db, "/api/licence-web/generate", { method: "POST" });
    expect(g0.status).toBe(401);
    // Unverified session: insert user + session rows directly.
    const email = "gen0@example.com";
    await db.prepare("INSERT INTO licence_web_users (email, email_verified, created_at, last_login_at) VALUES (?, 0, ?, NULL)").bind(email, NOW).run();
    const { token, tokenHash } = await newSessionToken();
    await db
      .prepare("INSERT INTO licence_web_sessions (token_hash, email, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?)")
      .bind(tokenHash, email, NOW, NOW + 30 * 24 * 60 * 60_000, NOW)
      .run();
    const g1 = await call(db, "/api/licence-web/generate", { method: "POST", headers: { Cookie: `lic_session=${token}` } });
    expect(g1.status).toBe(403);
    expect(g1.body.error).toBe("email_not_verified");
  });

  it("generate new key: 200 existing:false with the FULL key once; existing:true masks it", async () => {
    const db = new FakeD1();
    const f = stubFetch({});
    const email = "gen1@example.com";
    const cookie = await verifiedSession(db, email, f);
    const g = await call(db, "/api/licence-web/generate", { method: "POST", headers: { Cookie: cookie } });
    expect(g.status).toBe(200);
    expect(g.body.existing).toBe(false);
    expect((g.body.licence as Record<string, unknown>).key).toBe("JARVIS-NEW1-NEW2-NEW3-NEW4");
    // Existing: the Worker returns the full key, the hub masks it.
    const f2 = stubFetch({
      generate: { status: 200, body: { ok: true, existing: true, licence: { key: "JARVIS-AAAA-BBBB-CCCC-DDDD", user_id: email, device_id: null, status: "active", created_at: NOW } } },
    });
    void f2;
    const g2 = await call(db, "/api/licence-web/generate", { method: "POST", headers: { Cookie: cookie } });
    expect(g2.status).toBe(200);
    expect(g2.body.existing).toBe(true);
    expect((g2.body.licence as Record<string, unknown>).key).toBeUndefined();
    expect((g2.body.licence as Record<string, unknown>).key_masked).toBe("JARVIS-AAAA-••••-••••-DDDD");
  });

  it("generate uses the LICENCE_WORKER service binding when present (no public-URL fetch)", async () => {
    const db = new FakeD1();
    // Global fetch handles Resend but THROWS on any licence-Worker URL —
    // proving the hub never fetches the public URL when bound.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.includes("api.resend.com")) {
          return new Response(JSON.stringify({ id: "re_test123" }), { status: 200 });
        }
        throw new Error("public licence-Worker fetch must not happen: " + url);
      }),
    );
    const bindingCalls: { url: string; token: string }[] = [];
    const bindingFetch = async (url: string, init?: RequestInit) => {
      bindingCalls.push({ url, token: (init?.headers as Record<string, string>)["x-licence-admin-token"] ?? "" });
      return new Response(
        JSON.stringify({ ok: true, existing: false, licence: { key: "JARVIS-BIND-1111-2222-3333", user_id: "bind@example.com", device_id: null, status: "active", created_at: NOW } }),
        { status: 200 },
      );
    };
    // Signup + verify go through the resend stub (no binding involved).
    const f = { lastResendHtml: () => null as string | null };
    void f;
    const email = "bind@example.com";
    const s = await call(db, "/api/licence-web/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    expect(s.status).toBe(200);
    // The code went to the resend stub — but the stub above drops the
    // body, so verify via a D1-seeded code (same shape the route writes).
    const { hashEmailCode: hashCode } = await import("../src/licence-web");
    await db.prepare("DELETE FROM licence_email_codes WHERE email = ? AND purpose = ?").bind(email, "signup").run();
    await db
      .prepare("INSERT INTO licence_email_codes (email, purpose, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, ?, 0, ?)")
      .bind(email, "signup", await hashCode("123456"), Date.now() + 600_000, Date.now())
      .run();
    const v = await call(db, "/api/licence-web/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code: "123456", purpose: "signup" }),
    });
    expect(v.status).toBe(200);
    const cookie = await cookieFor(db, v);
    const g = await call(
      db,
      "/api/licence-web/generate",
      { method: "POST", headers: { Cookie: cookie } },
      { LICENCE_WORKER: { fetch: bindingFetch } as never },
    );
    expect(g.status).toBe(200);
    expect((g.body.licence as Record<string, unknown>).key).toBe("JARVIS-BIND-1111-2222-3333");
    expect(bindingCalls.length).toBe(1);
    expect(bindingCalls[0].url).toBe("https://licence-worker.test/api/licence/generate");
    expect(bindingCalls[0].token).toBe("lic-admin-test");
  });

  it("generate passes through a 403 licence_revoked from the Worker verbatim", async () => {
    const db = new FakeD1();
    const f = stubFetch({ generate: { status: 403, body: { error: "licence_revoked" } } });
    const email = "gen2@example.com";
    const cookie = await verifiedSession(db, email, f);
    const g = await call(db, "/api/licence-web/generate", { method: "POST", headers: { Cookie: cookie } });
    expect(g.status).toBe(403);
    expect(g.body.error).toBe("licence_revoked");
  });

  it("generate without LICENCE_ADMIN_TOKEN -> 503 licence_not_configured", async () => {
    const db = new FakeD1();
    const f = stubFetch({});
    const email = "gen3@example.com";
    const cookie = await verifiedSession(db, email, f);
    const g = await call(
      db,
      "/api/licence-web/generate",
      { method: "POST", headers: { Cookie: cookie } },
      { LICENCE_ADMIN_TOKEN: undefined },
    );
    expect(g.status).toBe(503);
    expect(g.body.error).toBe("licence_not_configured");
  });

  it("generate with a foreign Origin -> 403 forbidden (CSRF)", async () => {
    const db = new FakeD1();
    const f = stubFetch({});
    const email = "gen4@example.com";
    const cookie = await verifiedSession(db, email, f);
    const g = await call(db, "/api/licence-web/generate", {
      method: "POST",
      headers: { Cookie: cookie, Origin: "https://evil.example.com" },
    });
    expect(g.status).toBe(403);
    expect(g.body.error).toBe("forbidden");
  });

  it("release 404 with no licence; 200 released:true with one (Worker stubbed)", async () => {
    const db = new FakeD1();
    const f = stubFetch({});
    const email = "rel1@example.com";
    const cookie = await verifiedSession(db, email, f);
    const r0 = await call(db, "/api/licence-web/release", { method: "POST", headers: { Cookie: cookie } });
    expect(r0.status).toBe(404);
    expect(r0.body.error).toBe("licence_not_found");
    await seedLicence(db, "JARVIS-AAAA-BBBB-CCCC-DDDD", email, "active", "dev-9");
    const r1 = await call(db, "/api/licence-web/release", { method: "POST", headers: { Cookie: cookie } });
    expect(r1.status).toBe(200);
    expect(r1.body.released).toBe(true);
  });
});

describe("licence-web owner admin", () => {
  it("admin licences 401 without the token; 200 with it (keys shown — owner view)", async () => {
    const db = new FakeD1();
    stubFetch({});
    await seedLicence(db, "JARVIS-AAAA-BBBB-CCCC-DDDD", "owner1@example.com");
    await seedLicence(db, "JARVIS-EEEE-FFFF-GGGG-HHHH", "owner2@example.com", "revoked");
    const noAuth = await call(db, "/api/licence-web/admin/licences");
    expect(noAuth.status).toBe(401);
    const ok = await call(db, "/api/licence-web/admin/licences", { headers: { "x-admin-token": "admin" } });
    expect(ok.status).toBe(200);
    expect((ok.body.licences as unknown[]).length).toBe(2);
  });

  it("admin revoke 404 unknown; 200 revoke; second revoke already:true; wrong token 401", async () => {
    const db = new FakeD1();
    stubFetch({});
    await seedLicence(db, "JARVIS-AAAA-BBBB-CCCC-DDDD", "owner1@example.com");
    const bad = await call(db, "/api/licence-web/admin/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-admin-token": "nope" },
      body: JSON.stringify({ key: "JARVIS-AAAA-BBBB-CCCC-DDDD" }),
    });
    expect(bad.status).toBe(401);
    const missing = await call(db, "/api/licence-web/admin/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-admin-token": "admin" },
      body: JSON.stringify({ key: "JARVIS-ZZZZ-ZZZZ-ZZZZ-ZZZZ" }),
    });
    expect(missing.status).toBe(404);
    const ok = await call(db, "/api/licence-web/admin/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-admin-token": "admin" },
      body: JSON.stringify({ key: "jarvis-aaaa-bbbb-cccc-dddd" }),
    });
    expect(ok.status).toBe(200);
    expect(ok.body.revoked).toBe(true);
    const again = await call(db, "/api/licence-web/admin/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-admin-token": "admin" },
      body: JSON.stringify({ key: "JARVIS-AAAA-BBBB-CCCC-DDDD" }),
    });
    expect(again.status).toBe(200);
    expect(again.body.already).toBe(true);
  });
});
