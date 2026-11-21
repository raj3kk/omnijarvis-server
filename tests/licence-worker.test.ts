/**
 * licence-worker.test.ts — jarvis-licence Worker (D1) routes on local D1.
 * The Worker source lives in the repo at licence-worker/worker.js
 * (moved here at stage 3 so CI can import it); the D1 fake is shared
 * with the hub tests. Mirrors the pre-deploy node harness (40 cases)
 * plus the live-verify matrix (17 cases).
 */
import { describe, expect, it } from "vitest";
import worker from "../licence-worker/worker.js";
import { FakeD1 } from "./fake-d1";

const ADMIN = "test-admin-token";
const PAT_ADMIN = "test-patterns-admin";

function env(db: FakeD1) {
  return { DB: db as unknown as D1Database, LICENCE_ADMIN_TOKEN: ADMIN, PATTERNS_ADMIN_TOKEN: PAT_ADMIN };
}

async function call(
  db: FakeD1,
  method: string,
  path: string,
  body: unknown = null,
  headers: Record<string, string> = {},
) {
  const res = await worker.fetch(
    new Request(`https://licence.test${path}`, {
      method,
      headers: { "Content-Type": "application/json", "cf-connecting-ip": "1.2.3.4", ...headers },
      body: body === null ? null : JSON.stringify(body),
    }),
    env(db),
  );
  const text = await res.text();
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    /* html status page */
  }
  return { status: res.status, body: parsed as Record<string, any> | null, text };
}

async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const STEPS = [
  { action: "OPEN_APP", target_kind: "APP" },
  { action: "SEARCH", target_kind: "SEARCH_BOX" },
];

async function makeLicence(db: FakeD1, userId: string): Promise<string> {
  const r = await call(db, "POST", "/api/licence/generate", { user_id: userId }, { "x-licence-admin-token": ADMIN });
  expect(r.status).toBe(200);
  return String(r.body!.licence.key);
}

describe("licence Worker (D1) — status page + verify", () => {
  it("GET / -> 200 html, D1 store", async () => {
    const db = new FakeD1();
    const r = await call(db, "GET", "/");
    expect(r.status).toBe(200);
    expect(r.text).toContain("Jarvis Licence Server");
    expect(r.text).toContain("D1");
  });

  it("verify: empty -> 400, unknown -> 404", async () => {
    const db = new FakeD1();
    let r = await call(db, "POST", "/api/licence/verify", {});
    expect(r.status).toBe(400);
    expect(r.body!.error).toBe("missing_key_or_device");
    r = await call(db, "POST", "/api/licence/verify", { key: "JARVIS-AAAA-AAAA-AAAA-AAAA", device_id: "d1" });
    expect(r.status).toBe(404);
    expect(r.body!.error).toBe("invalid_licence");
  });

  it("verify: bind, re-verify, mismatch 409", async () => {
    const db = new FakeD1();
    const key = await makeLicence(db, "owner-1@example.com");
    let r = await call(db, "POST", "/api/licence/verify", { key, device_id: "dev-A" });
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ ok: true, bound: true });
    r = await call(db, "POST", "/api/licence/verify", { key, device_id: "dev-B" });
    expect(r.status).toBe(409);
    expect(r.body!.error).toBe("device_mismatch");
    r = await call(db, "POST", "/api/licence/verify", { key, device_id: "dev-A" });
    expect(r.status).toBe(200);
  });
});

describe("licence Worker (D1) — generate / status / release", () => {
  it("generate: no token -> 403, no user_id -> 400, again -> existing", async () => {
    const db = new FakeD1();
    let r = await call(db, "POST", "/api/licence/generate", { user_id: "u1" });
    expect(r.status).toBe(403);
    expect(r.body!.error).toBe("admin_forbidden");
    r = await call(db, "POST", "/api/licence/generate", {}, { "x-licence-admin-token": ADMIN });
    expect(r.status).toBe(400);
    expect(r.body!.error).toBe("missing_user_id");
    r = await call(db, "POST", "/api/licence/generate", { user_id: "u1" }, { "x-licence-admin-token": ADMIN });
    expect(r.status).toBe(200);
    expect(r.body!.existing).toBe(false);
    expect(String(r.body!.licence.key)).toMatch(/^JARVIS-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect(typeof r.body!.licence.created_at).toBe("string");
    const key = String(r.body!.licence.key);
    r = await call(db, "POST", "/api/licence/generate", { user_id: "u1" }, { "x-licence-admin-token": ADMIN });
    expect(r.body!.existing).toBe(true);
    expect(r.body!.licence.key).toBe(key);
  });

  it("generate: revoked user -> 403 licence_revoked", async () => {
    const db = new FakeD1();
    await db
      .prepare("INSERT INTO licences (key, user_id, device_id, status, created_at) VALUES (?, ?, NULL, 'revoked', ?)")
      .bind("JARVIS-REVOKED-TEST-0001", "owner-3@example.com", Date.now())
      .run();
    const r = await call(db, "POST", "/api/licence/generate", { user_id: "owner-3@example.com" }, { "x-licence-admin-token": ADMIN });
    expect(r.status).toBe(403);
    expect(r.body!.error).toBe("licence_revoked");
  });

  it("status: key+device ok, wrong device 401, admin+key ok, none 401", async () => {
    const db = new FakeD1();
    const key = await makeLicence(db, "owner-1@example.com");
    await call(db, "POST", "/api/licence/verify", { key, device_id: "dev-A" });
    let r = await call(db, "GET", `/api/licence/status?key=${key}&device_id=dev-A`);
    expect(r.status).toBe(200);
    expect(r.body!.licence.key).toBe(key);
    r = await call(db, "GET", `/api/licence/status?key=${key}&device_id=dev-B`);
    expect(r.status).toBe(401);
    r = await call(db, "GET", `/api/licence/status?key=${key}`, null, { "x-licence-admin-token": ADMIN });
    expect(r.status).toBe(200);
    expect(r.body!.licence.key).toBe(key);
    r = await call(db, "GET", "/api/licence/status");
    expect(r.status).toBe(401);
  });

  it("release: wrong device 409, key+device ok, again not_bound, rebind works; admin paths", async () => {
    const db = new FakeD1();
    const key = await makeLicence(db, "owner-1@example.com");
    await call(db, "POST", "/api/licence/verify", { key, device_id: "dev-A" });
    let r = await call(db, "POST", "/api/licence/release", { key, device_id: "dev-B" });
    expect(r.status).toBe(409);
    expect(r.body!.error).toBe("device_mismatch");
    r = await call(db, "POST", "/api/licence/release", { key, device_id: "dev-A" });
    expect(r.status).toBe(200);
    expect(r.body!.via).toBe("key_device");
    r = await call(db, "POST", "/api/licence/release", { key, device_id: "dev-A" });
    expect(r.status).toBe(409);
    expect(r.body!.error).toBe("not_bound");
    r = await call(db, "POST", "/api/licence/verify", { key, device_id: "dev-A" });
    expect(r.status).toBe(200);

    const key2 = await makeLicence(db, "owner-2@example.com");
    await call(db, "POST", "/api/licence/verify", { key: key2, device_id: "dev-C" });
    r = await call(db, "POST", "/api/licence/release", { key: key2, user_id: "someone-else@example.com" }, { "x-licence-admin-token": ADMIN });
    expect(r.status).toBe(403);
    expect(r.body!.error).toBe("licence_owner_mismatch");
    r = await call(db, "POST", "/api/licence/release", { key: key2, user_id: "owner-2@example.com" }, { "x-licence-admin-token": ADMIN });
    expect(r.status).toBe(200);
    expect(r.body!.via).toBe("admin_and_key");
    r = await call(db, "POST", "/api/licence/release", {});
    expect(r.status).toBe(401);
  });
});

describe("licence Worker (D1) — patterns", () => {
  it("post: auth, validation, bump; get: unapproved hidden, approved shown; delete", async () => {
    const db = new FakeD1();
    const key = await makeLicence(db, "owner-1@example.com");
    await call(db, "POST", "/api/licence/verify", { key, device_id: "dev-A" });
    const hash = await sha256Hex(JSON.stringify({ steps: STEPS }));
    const payload = { template_hash: hash, steps: STEPS, licence_key: key, device_id: "dev-A" };

    let r = await call(db, "POST", "/api/patterns", { template_hash: hash, steps: STEPS });
    expect(r.status).toBe(401);
    r = await call(db, "POST", "/api/patterns", { ...payload, device_id: "dev-B" });
    expect(r.status).toBe(401);
    r = await call(db, "POST", "/api/patterns", { ...payload, template_hash: "deadbeef" });
    expect(r.status).toBe(400);
    expect(r.body!.error).toBe("invalid_pattern");
    r = await call(db, "POST", "/api/patterns", { ...payload, steps: [{ action: "HACK", target_kind: "APP" }] });
    expect(r.status).toBe(400);
    const wrongHash = await sha256Hex(JSON.stringify({ steps: [{ action: "WAIT", target_kind: "APP" }] }));
    r = await call(db, "POST", "/api/patterns", { ...payload, template_hash: wrongHash });
    expect(r.status).toBe(400);
    expect(String(r.body!.detail)).toContain("template_hash_mismatch");

    r = await call(db, "POST", "/api/patterns", payload);
    expect(r.status).toBe(200);
    expect(r.body!.use_count).toBe(1);
    expect(r.body!.approved).toBe(false);
    r = await call(db, "POST", "/api/patterns", payload);
    expect(r.body!.use_count).toBe(2);

    r = await call(db, "GET", "/api/patterns");
    expect(r.status).toBe(200);
    expect(r.body!.templates).toEqual([]);
    // Approve directly (owner action in D1) and re-check GET + cursor.
    await db.prepare("UPDATE learned_patterns SET approved = ? WHERE template_hash = ?").bind(1, hash).run();
    r = await call(db, "GET", "/api/patterns");
    expect(r.body!.templates.length).toBe(1);
    expect(r.body!.templates[0].template.steps.length).toBe(2);
    expect(typeof r.body!.templates[0].last_seen).toBe("string");
    r = await call(db, "GET", "/api/patterns?cursor=bad");
    expect(r.status).toBe(400);
    expect(r.body!.error).toBe("invalid_cursor");

    r = await call(db, "DELETE", "/api/patterns", { template_hash: hash });
    expect(r.status).toBe(403);
    expect(r.body!.error).toBe("admin_forbidden");
    r = await call(db, "DELETE", "/api/patterns", { template_hash: "0".repeat(64) }, { "x-patterns-admin-token": PAT_ADMIN });
    expect(r.status).toBe(404);
    r = await call(db, "DELETE", "/api/patterns", { template_hash: hash }, { "x-patterns-admin-token": PAT_ADMIN });
    expect(r.status).toBe(200);
    expect(r.body!.deleted_count).toBe(1);
  });

  it("unknown route -> 404", async () => {
    const db = new FakeD1();
    const r = await call(db, "GET", "/nope");
    expect(r.status).toBe(404);
    expect(r.body!.error).toBe("not_found");
  });
});
