/**
 * jarvis-licence-worker — Cloudflare Worker for the Jarvis licence API.
 *
 * v2 (2026-11-21, Supabase -> D1 migration): the store is Cloudflare D1
 * database `omnijarvis-db` (binding DB). Supabase is GONE — no REST calls,
 * no service key, no Auth. Access control lives in this Worker (the D1
 * binding is private by default; there is no key to leak).
 *
 * v1 history: Phase 0 (2026-11-21) ported the Next.js licence server here
 * after a Vercel Hobby team fair-use block (402 DEPLOYMENT_DISABLED).
 *
 * Auth model (v2 — Supabase Auth does not exist anymore):
 *   - verify / patterns upload: licence-key + device_id proof (as v1).
 *   - generate: admin token header `x-licence-admin-token` == LICENCE_ADMIN_TOKEN.
 *     Body { user_id } (opaque owner identifier, e.g. email). No sessions.
 *   - release: admin token + key, OR key + device_id proof.
 *   - status: admin token + key, OR key + device_id proof.
 *   - patterns DELETE: PATTERNS_ADMIN_TOKEN (optional; unset = always 403).
 *
 * Env (Worker secrets, never in code):
 *   DB (D1 binding — omnijarvis-db), LICENCE_ADMIN_TOKEN, PATTERNS_ADMIN_TOKEN
 *
 * Rate limiting: in-memory per-isolate sliding windows (same documented
 * limitation as v1 — NOT a distributed quota; Phase 2 moves it to Upstash).
 *
 * API contract: same routes, same status codes, same error strings as v1
 * wherever the caller can still use them. created_at / last_seen are
 * returned as ISO strings (D1 stores unix-ms integers).
 */

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const RATE_LIMITS = {
  licenceVerify: { limit: 30, windowMs: 60_000 },
  licenceGenerate: { limit: 20, windowMs: 60_000 },
  licenceRelease: { limit: 30, windowMs: 60_000 },
  licenceRevoke: { limit: 20, windowMs: 60_000 }, // U14
  licenceStatus: { limit: 60, windowMs: 60_000 },
  patternsPost: { limit: 60, windowMs: 60_000 },
  patternsGet: { limit: 120, windowMs: 60_000 },
  patternsDelete: { limit: 20, windowMs: 60_000 },
};

const ALLOWED_ACTIONS = [
  "OPEN_APP", "SEARCH", "TAP_FIRST_RESULT", "TAP_SEND",
  "TYPE_TEXT_GENERIC", "WAIT", "SCROLL", "NAVIGATE",
];
const ALLOWED_TARGET_KINDS = [
  "APP", "SEARCH_BOX", "FIRST_RESULT",
  "SEND_BUTTON", "TEXT_FIELD", "GENERIC_BUTTON",
];

const UNAVAILABLE = { error: "pattern_store_unavailable" };

// ---------------------------------------------------------------- utils
function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function clientIp(request) {
  return (
    request.headers.get("cf-connecting-ip") ||
    (request.headers.get("x-forwarded-for") || "").split(",")[0]?.trim() ||
    request.headers.get("x-real-ip")?.trim() ||
    "unknown-ip"
  );
}

// In-memory per-isolate sliding windows (see header note).
const buckets = new Map();
function checkRateLimit(request, routeKey, limit, windowMs) {
  const key = `${routeKey}:${clientIp(request)}`;
  const now = Date.now();
  const cutoff = now - windowMs;
  let entry = buckets.get(key);
  if (!entry) {
    entry = { timestamps: [] };
    buckets.set(key, entry);
  }
  entry.timestamps = entry.timestamps.filter((t) => t > cutoff);
  if (entry.timestamps.length >= limit) return false;
  entry.timestamps.push(now);
  if (buckets.size > 10000) {
    for (const [k, v] of buckets) {
      if (v.timestamps.length === 0 || v.timestamps[v.timestamps.length - 1] <= cutoff) {
        buckets.delete(k);
      }
    }
  }
  return true;
}

function rateLimited(request, routeKey) {
  const cfg = RATE_LIMITS[routeKey];
  return !checkRateLimit(request, routeKey, cfg.limit, cfg.windowMs);
}

function generateLicenceKey() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const chars = Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]);
  const groups = [];
  for (let i = 0; i < 4; i++) {
    groups.push(chars.slice(i * 4, i * 4 + 4).join(""));
  }
  return `JARVIS-${groups.join("-")}`;
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function timingSafeTokenEqual(supplied, expected) {
  if (typeof supplied !== "string" || typeof expected !== "string") return false;
  const a = await sha256Hex(supplied);
  const b = await sha256Hex(expected);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function b64urlEncode(text) {
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(text) {
  try {
    const padded = text.replace(/-/g, "+").replace(/_/g, "/");
    return atob(padded);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- D1
function d1(env) {
  const db = env.DB;
  if (!db) throw new Error("D1 binding not configured");
  return db;
}

async function d1First(env, sql, ...params) {
  const row = await d1(env).prepare(sql).bind(...params).first();
  return row ?? null;
}

async function d1All(env, sql, ...params) {
  const res = await d1(env).prepare(sql).bind(...params).all();
  return res.results ?? [];
}

// Normalised exec: D1 reports failures as success:false OR a thrown
// error (runtime-dependent) — both collapse to { ok:false, error }.
async function d1Run(env, sql, ...params) {
  try {
    const r = await d1(env).prepare(sql).bind(...params).run();
    if (r && r.success === false) {
      return { ok: false, changes: 0, error: String(r.error ?? "d1_failed") };
    }
    const changes =
      r && r.meta && typeof r.meta.changes === "number" ? r.meta.changes : 0;
    return { ok: true, changes, error: null };
  } catch (e) {
    return { ok: false, changes: 0, error: String(e && e.message ? e.message : e) };
  }
}

function isUniqueError(err) {
  return typeof err === "string" && err.includes("UNIQUE constraint failed");
}

function isMissingTableError(err) {
  return typeof err === "string" && err.includes("no such table");
}

// Admin-token check (header x-licence-admin-token). Unset server token
// fails closed — generate/admin paths can never open by accident.
async function isLicenceAdmin(request, env) {
  const expected = env.LICENCE_ADMIN_TOKEN;
  if (!expected) return false;
  const supplied = request.headers.get("x-licence-admin-token") ?? "";
  return timingSafeTokenEqual(supplied, expected);
}

// Row -> API shape (v1 contract: created_at is an ISO string).
function licenceOut(row) {
  if (!row) return null;
  return {
    key: row.key,
    user_id: row.user_id,
    device_id: row.device_id ?? null,
    status: row.status,
    created_at: new Date(row.created_at).toISOString(),
  };
}

// ---------------------------------------------------------------- patterns lib
function computeTemplateHash(template) {
  const canonical = JSON.stringify({
    steps: template.steps.map((s) => ({
      action: s.action,
      target_kind: s.target_kind,
    })),
  });
  return sha256Hex(canonical);
}

const PHONE_LIKE = /\+?\d[\d\s\-().]{7,}\d/;
const DIGIT_RUN = /\d{3,}/;

function scanString(value) {
  if (value.includes("@")) return "string contains '@'";
  if (value.toLowerCase().includes("http")) return "string contains 'http'";
  if (value.includes("/")) return "string contains '/'";
  if (DIGIT_RUN.test(value)) return "digit sequence longer than 2 chars";
  if (PHONE_LIKE.test(value)) return "phone-like pattern";
  return null;
}

function validatePatternPayload(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "body must be an object";
  }
  const allowedBodyKeys = new Set([
    "template_hash", "steps", "licence_key", "device_id",
  ]);
  for (const key of Object.keys(body)) {
    if (!allowedBodyKeys.has(key)) return `unexpected field: ${key}`;
  }
  const hash = body.template_hash;
  if (typeof hash !== "string" || !/^[a-f0-9]{64}$/i.test(hash)) {
    return "template_hash must be a 64-char sha256 hex string";
  }
  if (!Array.isArray(body.steps) || body.steps.length === 0 || body.steps.length > 50) {
    return "steps must be a non-empty array (max 50)";
  }
  for (const step of body.steps) {
    if (!step || typeof step !== "object" || Array.isArray(step)) {
      return "each step must be an object";
    }
    const keys = Object.keys(step);
    if (keys.length !== 2 || !keys.includes("action") || !keys.includes("target_kind")) {
      return "each step must have exactly {action, target_kind}";
    }
    if (!ALLOWED_ACTIONS.includes(step.action)) {
      return `disallowed action: ${String(step.action)}`;
    }
    if (!ALLOWED_TARGET_KINDS.includes(step.target_kind)) {
      return `disallowed target_kind: ${String(step.target_kind)}`;
    }
    for (const v of [step.action, step.target_kind]) {
      const hit = scanString(v);
      if (hit) return `step field rejected: ${hit}`;
    }
  }
  for (const key of ["licence_key", "device_id"]) {
    const v = body[key];
    if (v !== undefined && typeof v !== "string") return `${key} must be a string`;
    if (typeof v === "string" && v.includes("@")) return `${key} contains '@'`;
  }
  return null;
}

// ---------------------------------------------------------------- licence routes
async function licenceVerify(request, env) {
  if (rateLimited(request, "licenceVerify")) {
    return json({ ok: false, error: "rate_limited" }, 429);
  }
  const body = await request.json().catch(() => ({}));
  const key = typeof body.key === "string" ? body.key.trim().toUpperCase() : "";
  const deviceId = typeof body.device_id === "string" ? body.device_id.trim() : "";
  if (!key || !deviceId) {
    return json({ ok: false, error: "missing_key_or_device" }, 400);
  }
  let licence;
  try {
    licence = await d1First(
      env,
      "SELECT key, user_id, device_id, status FROM licences WHERE key = ?",
      key
    );
  } catch {
    return json({ ok: false, error: "verify_failed" }, 500);
  }
  // U14: a revoked licence gets a distinct 403 — the phone can tell the
  // user the licence was revoked (contact the owner) instead of treating
  // it as a typo'd/invalid key. Unknown keys stay 404 invalid_licence.
  if (!licence) {
    return json({ ok: false, error: "invalid_licence" }, 404);
  }
  if (licence.status === "revoked") {
    return json({ ok: false, error: "licence_revoked" }, 403);
  }
  if (licence.status !== "active") {
    return json({ ok: false, error: "invalid_licence" }, 404);
  }
  if (!licence.device_id) {
    // Race-safe bind: only the row that is still unbound gets claimed.
    const bind = await d1Run(
      env,
      "UPDATE licences SET device_id = ? WHERE key = ? AND device_id IS NULL",
      deviceId, key
    );
    if (!bind.ok) return json({ ok: false, error: "verify_failed" }, 500);
    if (bind.changes === 0) {
      // Lost the race — re-read to see who won.
      const reread = await d1First(
        env,
        "SELECT key, device_id, status FROM licences WHERE key = ?",
        key
      ).catch(() => null);
      if (!reread) return json({ ok: false, error: "verify_failed" }, 500);
      if (reread.device_id && reread.device_id !== deviceId) {
        return json({ ok: false, error: "device_mismatch" }, 409);
      }
      if (reread.device_id === deviceId) return json({ ok: true, bound: true });
      return json({ ok: false, error: "verify_failed" }, 500);
    }
    return json({ ok: true, bound: true });
  }
  if (licence.device_id === deviceId) return json({ ok: true, bound: true });
  return json({ ok: false, error: "device_mismatch" }, 409);
}

async function licenceGenerate(request, env) {
  if (rateLimited(request, "licenceGenerate")) {
    return json({ error: "rate_limited" }, 429);
  }
  if (!(await isLicenceAdmin(request, env))) {
    return json({ error: "admin_forbidden" }, 403);
  }
  const body = await request.json().catch(() => ({}));
  const userId = typeof body.user_id === "string" ? body.user_id.trim() : "";
  if (!userId) return json({ error: "missing_user_id" }, 400);

  let active = null;
  try {
    active = await d1First(
      env,
      "SELECT key, user_id, device_id, status, created_at FROM licences WHERE user_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1",
      userId
    );
  } catch {
    return json({ error: "generate_failed" }, 500);
  }
  if (active) return json({ licence: licenceOut(active), existing: true });

  let revoked = null;
  try {
    revoked = await d1First(
      env,
      "SELECT key FROM licences WHERE user_id = ? AND status = 'revoked' LIMIT 1",
      userId
    );
  } catch {
    return json({ error: "generate_failed" }, 500);
  }
  if (revoked) {
    return json(
      {
        error: "licence_revoked",
        reason: "revoked_licence_exists",
        detail: "This account has a revoked licence, so a new licence cannot be generated. Contact the owner.",
      },
      403
    );
  }

  const now = Date.now();
  for (let attempt = 0; attempt < 2; attempt++) {
    const key = generateLicenceKey();
    const created = await d1Run(
      env,
      "INSERT INTO licences (key, user_id, device_id, status, created_at) VALUES (?, ?, NULL, 'active', ?)",
      key, userId, now
    );
    if (created.ok) {
      return json({
        licence: licenceOut({ key, user_id: userId, device_id: null, status: "active", created_at: now }),
        existing: false,
      });
    }
    if (isUniqueError(created.error)) {
      // Key collision (astronomically unlikely) -> new key, retry once.
      // Partial-unique-index hit (active licence appeared concurrently)
      // -> return the existing one instead of a duplicate.
      const again = await d1First(
        env,
        "SELECT key, user_id, device_id, status, created_at FROM licences WHERE user_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1",
        userId
      ).catch(() => null);
      if (again) return json({ licence: licenceOut(again), existing: true });
      continue;
    }
    return json({ error: "generate_failed" }, 500);
  }
  return json({ error: "generate_failed" }, 500);
}

async function licenceRelease(request, env) {
  if (rateLimited(request, "licenceRelease")) {
    return json({ error: "release_failed" }, 429);
  }
  const body = await request.json().catch(() => ({}));
  const key = typeof body.key === "string" ? body.key.trim().toUpperCase() : "";
  const deviceId = typeof body.device_id === "string" ? body.device_id.trim() : "";
  const admin = await isLicenceAdmin(request, env);

  // Admin + key path (dashboard / owner tooling).
  if (admin && key) {
    let licence;
    try {
      licence = await d1First(
        env,
        "SELECT key, user_id, device_id, status FROM licences WHERE key = ?",
        key
      );
    } catch {
      return json({ error: "release_failed" }, 500);
    }
    if (!licence || licence.status !== "active") {
      return json({ error: "invalid_licence" }, 404);
    }
    if (typeof body.user_id === "string" && body.user_id && licence.user_id !== body.user_id) {
      return json({ error: "licence_owner_mismatch" }, 403);
    }
    if (deviceId && licence.device_id !== deviceId) {
      return json({ error: "device_mismatch" }, 409);
    }
    if (!licence.device_id) return json({ error: "not_bound" }, 409);
    const released = await d1Run(
      env,
      "UPDATE licences SET device_id = NULL WHERE key = ? AND device_id = ?",
      key, licence.device_id
    );
    if (!released.ok) return json({ error: "release_failed" }, 500);
    if (released.changes === 0) return json({ error: "not_bound" }, 409);
    return json({ ok: true, released: true, via: "admin_and_key" });
  }

  // Key + device proof, no admin token.
  if (!key || !deviceId) return json({ error: "unauthorized" }, 401);
  let licence;
  try {
    licence = await d1First(
      env,
      "SELECT key, device_id, status FROM licences WHERE key = ?",
      key
    );
  } catch {
    return json({ error: "release_failed" }, 500);
  }
  if (!licence || licence.status !== "active") {
    return json({ error: "invalid_licence" }, 404);
  }
  if (!licence.device_id) return json({ error: "not_bound" }, 409);
  if (licence.device_id !== deviceId) {
    return json({ error: "device_mismatch" }, 409);
  }
  const released = await d1Run(
    env,
    "UPDATE licences SET device_id = NULL WHERE key = ? AND device_id = ?",
    key, deviceId
  );
  if (!released.ok) return json({ error: "release_failed" }, 500);
  if (released.changes === 0) return json({ error: "not_bound" }, 409);
  return json({ ok: true, released: true, via: "key_device" });
}

// U14 — admin-only revoke (the hub's /api/licence-web/admin/revoke is the
// dashboard path; this is the Worker's own route). Sets status='revoked':
// a revoked licence can never verify again (403 licence_revoked) and a
// new licence cannot be generated for that user (licenceGenerate 403).
// The device binding is left on the row as an audit trail — the row is
// dead either way. Idempotent: revoking an already-revoked licence
// returns ok:true with already:true.
async function licenceRevoke(request, env) {
  if (rateLimited(request, "licenceRevoke")) {
    return json({ error: "revoke_failed" }, 429);
  }
  if (!(await isLicenceAdmin(request, env))) {
    return json({ error: "admin_forbidden" }, 403);
  }
  const body = await request.json().catch(() => ({}));
  const key = typeof body.key === "string" ? body.key.trim().toUpperCase() : "";
  if (!key) return json({ error: "missing_key" }, 400);
  let licence;
  try {
    licence = await d1First(
      env,
      "SELECT key, user_id, device_id, status FROM licences WHERE key = ?",
      key
    );
  } catch {
    return json({ error: "revoke_failed" }, 500);
  }
  if (!licence) return json({ error: "invalid_licence" }, 404);
  if (licence.status === "revoked") return json({ ok: true, revoked: true, already: true });
  if (licence.status !== "active") return json({ error: "invalid_licence" }, 404);
  const revoked = await d1Run(
    env,
    "UPDATE licences SET status = ? WHERE key = ? AND status = 'active'",
    "revoked",
    key
  );
  if (!revoked.ok) return json({ error: "revoke_failed" }, 500);
  if (revoked.changes === 0) return json({ error: "invalid_licence" }, 404);
  return json({ ok: true, revoked: true });
}

async function licenceStatus(request, env) {
  if (rateLimited(request, "licenceStatus")) {
    return json({ error: "status_failed" }, 429);
  }
  const url = new URL(request.url);
  const body = request.method === "POST" ? await request.json().catch(() => ({})) : {};
  const keyRaw = url.searchParams.get("key") ?? (typeof body.key === "string" ? body.key : "");
  const key = keyRaw.trim().toUpperCase();
  const deviceRaw = url.searchParams.get("device_id") ?? (typeof body.device_id === "string" ? body.device_id : "");
  const deviceId = deviceRaw.trim();
  const admin = await isLicenceAdmin(request, env);

  if (admin && key) {
    let licence;
    try {
      licence = await d1First(
        env,
        "SELECT key, user_id, device_id, status, created_at FROM licences WHERE key = ?",
        key
      );
    } catch {
      return json({ error: "status_failed" }, 500);
    }
    if (!licence || licence.status !== "active") return json({ licence: null });
    return json({ licence: licenceOut(licence) });
  }
  if (!key || !deviceId) return json({ error: "unauthorized" }, 401);
  let licence;
  try {
    licence = await d1First(
      env,
      "SELECT key, user_id, device_id, status, created_at FROM licences WHERE key = ?",
      key
    );
  } catch {
    return json({ error: "status_failed" }, 500);
  }
  if (!licence || licence.status !== "active" || licence.device_id !== deviceId) {
    return json({ error: "unauthorized" }, 401);
  }
  return json({ licence: licenceOut(licence) });
}

// ---------------------------------------------------------------- patterns routes
// v2: no sessions (Supabase Auth is gone) — key + device proof only.
async function callerHasActivatedLicence(request, env, body) {
  const key = typeof body.licence_key === "string" ? body.licence_key.trim().toUpperCase() : "";
  const deviceId = typeof body.device_id === "string" ? body.device_id.trim() : "";
  if (!key || !deviceId) return { ok: false, status: 401 };
  let licence;
  try {
    licence = await d1First(
      env,
      "SELECT key, device_id, status FROM licences WHERE key = ?",
      key
    );
  } catch {
    return { ok: false, status: 500 };
  }
  if (!licence || licence.status !== "active") return { ok: false, status: 401 };
  if (licence.device_id !== deviceId) return { ok: false, status: 401 };
  return { ok: true };
}

function canonicalSteps(raw) {
  return raw.map((s) => ({ action: s.action, target_kind: s.target_kind }));
}

async function bumpExisting(env, templateHash, steps) {
  let existing;
  try {
    existing = await d1First(
      env,
      "SELECT template_hash, template, use_count, approved FROM learned_patterns WHERE template_hash = ?",
      templateHash
    );
  } catch (e) {
    if (isMissingTableError(String(e && e.message ? e.message : e))) {
      return json(UNAVAILABLE, 503);
    }
    return json({ error: "pattern_store_failed" }, 500);
  }
  if (!existing) return null;
  let storedJson = null;
  try {
    const t = JSON.parse(existing.template);
    storedJson = t && Array.isArray(t.steps)
      ? JSON.stringify({ steps: t.steps.map((s) => ({ action: s.action, target_kind: s.target_kind })) })
      : null;
  } catch {
    storedJson = null;
  }
  const submittedJson = JSON.stringify({ steps });
  if (storedJson !== submittedJson) {
    return json(
      {
        error: "template_hash_conflict",
        detail: "a different template is already stored under this hash; it was not merged",
      },
      409
    );
  }
  const nextCount = (existing.use_count ?? 1) + 1;
  const bump = await d1Run(
    env,
    "UPDATE learned_patterns SET use_count = ?, last_seen = ? WHERE template_hash = ?",
    nextCount, Date.now(), templateHash
  );
  if (!bump.ok) {
    if (isMissingTableError(bump.error)) return json(UNAVAILABLE, 503);
    return json({ error: "pattern_store_failed" }, 500);
  }
  return json({
    ok: true,
    template_hash: templateHash,
    use_count: nextCount,
    approved: existing.approved === 1,
    note: "stored as suggestion; GET returns approved patterns only",
  });
}

async function patternsPost(request, env) {
  if (rateLimited(request, "patternsPost")) {
    return json({ error: "rate_limited" }, 429);
  }
  const body = await request.json().catch(() => null);
  const rawBody = body !== null && typeof body === "object" && !Array.isArray(body) ? body : {};
  const auth = await callerHasActivatedLicence(request, env, rawBody);
  if (!auth.ok) return json({ error: "unauthorized" }, auth.status);
  const validationError = body === null ? "body must be valid JSON" : validatePatternPayload(body);
  if (validationError) {
    return json({ error: "invalid_pattern", detail: validationError }, 400);
  }
  const steps = canonicalSteps(body.steps);
  const canonicalHash = body.template_hash.toLowerCase();
  const computedHash = await computeTemplateHash({ steps });
  if (computedHash !== canonicalHash) {
    return json(
      { error: "invalid_pattern", detail: "template_hash_mismatch: hash does not match the submitted steps" },
      400
    );
  }
  const template = JSON.stringify({ steps });
  const bumped = await bumpExisting(env, canonicalHash, steps);
  if (bumped) return bumped;
  const now = Date.now();
  const insert = await d1Run(
    env,
    "INSERT INTO learned_patterns (id, template_hash, template, use_count, first_seen, last_seen, approved) VALUES (?, ?, ?, 1, ?, ?, 0)",
    crypto.randomUUID(), canonicalHash, template, now, now
  );
  if (!insert.ok) {
    if (isMissingTableError(insert.error)) return json(UNAVAILABLE, 503);
    if (isUniqueError(insert.error)) {
      const raced = await bumpExisting(env, canonicalHash, steps);
      if (raced) return raced;
      const retry = await d1Run(
        env,
        "INSERT INTO learned_patterns (id, template_hash, template, use_count, first_seen, last_seen, approved) VALUES (?, ?, ?, 1, ?, ?, 0)",
        crypto.randomUUID(), canonicalHash, template, now, now
      );
      if (!retry.ok) {
        if (isMissingTableError(retry.error)) return json(UNAVAILABLE, 503);
        return json({ error: "pattern_store_failed" }, 500);
      }
      return json({
        ok: true, template_hash: canonicalHash, use_count: 1, approved: false,
        note: "stored as unapproved suggestion; GET returns approved patterns only",
      });
    }
    return json({ error: "pattern_store_failed" }, 500);
  }
  return json({
    ok: true, template_hash: canonicalHash, use_count: 1, approved: false,
    note: "stored as unapproved suggestion; GET returns approved patterns only",
  });
}

async function patternsGet(request, env) {
  if (rateLimited(request, "patternsGet")) {
    return json({ error: "rate_limited" }, 429);
  }
  const url = new URL(request.url);
  const rawLimit = Number(url.searchParams.get("limit") ?? "20");
  const limit = Number.isFinite(rawLimit) ? Math.min(50, Math.max(1, Math.floor(rawLimit))) : 20;
  const rawOffset = Number(url.searchParams.get("offset") ?? "0");
  const offset = Number.isFinite(rawOffset) ? Math.max(0, Math.floor(rawOffset)) : 0;
  const cursorParam = url.searchParams.get("cursor");
  let rows;
  try {
    rows = await d1All(
      env,
      "SELECT id, template_hash, template, use_count, last_seen, approved FROM learned_patterns WHERE approved = 1"
    );
  } catch (e) {
    if (isMissingTableError(String(e && e.message ? e.message : e))) {
      return json(UNAVAILABLE, 503);
    }
    return json({ error: "pattern_store_failed" }, 500);
  }
  // Sort in JS (same order as v1): use_count DESC, last_seen DESC, id ASC.
  rows.sort((a, b) => {
    if ((b.use_count ?? 0) !== (a.use_count ?? 0)) return (b.use_count ?? 0) - (a.use_count ?? 0);
    if ((b.last_seen ?? 0) !== (a.last_seen ?? 0)) return (b.last_seen ?? 0) - (a.last_seen ?? 0);
    return String(a.id).localeCompare(String(b.id));
  });
  let start = offset;
  if (cursorParam) {
    let cursorId = null;
    try {
      const decoded = JSON.parse(b64urlDecode(cursorParam) || "");
      if (typeof decoded.id === "string" && decoded.id) cursorId = decoded.id;
    } catch {
      cursorId = null;
    }
    if (!cursorId) return json({ error: "invalid_cursor" }, 400);
    const idx = rows.findIndex((r) => r.id === cursorId);
    if (idx === -1) return json({ error: "invalid_cursor" }, 400);
    start = idx + 1;
  }
  const page = rows.slice(start, start + limit);
  const hasMore = start + page.length < rows.length;
  const nextCursor = hasMore
    ? b64urlEncode(JSON.stringify({ id: page[page.length - 1].id }))
    : null;
  const templates = page.map((r) => ({
    template_hash: r.template_hash,
    template: JSON.parse(r.template),
    use_count: r.use_count,
    last_seen: new Date(r.last_seen).toISOString(),
  }));
  return json({ templates, next_cursor: nextCursor });
}

async function patternsDelete(request, env) {
  if (rateLimited(request, "patternsDelete")) {
    return json({ error: "rate_limited" }, 429);
  }
  const adminToken = env.PATTERNS_ADMIN_TOKEN;
  const supplied = request.headers.get("x-patterns-admin-token") ?? "";
  if (!adminToken || !(await timingSafeTokenEqual(supplied, adminToken))) {
    return json({ error: "admin_forbidden" }, 403);
  }
  const body = await request.json().catch(() => ({}));
  const hash = typeof body.template_hash === "string" ? body.template_hash.trim().toLowerCase() : "";
  if (!hash) return json({ error: "missing_template_hash" }, 400);
  const deleted = await d1Run(
    env,
    "DELETE FROM learned_patterns WHERE template_hash = ?",
    hash
  );
  if (!deleted.ok) {
    if (isMissingTableError(deleted.error)) return json(UNAVAILABLE, 503);
    return json({ error: "pattern_delete_failed" }, 500);
  }
  if (deleted.changes === 0) {
    return json({ error: "pattern_not_found", template_hash: hash }, 404);
  }
  return json({
    ok: true, deleted: true, deleted_count: deleted.changes, template_hash: hash,
  });
}

// ---------------------------------------------------------------- router
function statusPage() {
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Jarvis Licence Server</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px;color:#222}code{background:#f0f0f0;padding:2px 6px;border-radius:4px}</style>
</head><body>
<h1>Jarvis Licence Server</h1>
<p><strong>Status: LIVE</strong> (Cloudflare Worker, D1 store — Supabase removed 2026-11-21; the old Vercel host went down on a team-wide Hobby fair-use block, HTTP 402).</p>
<p>Free licence service for the Jarvis Android app: one licence per user, bound to one device. No payment anywhere.</p>
<h2>API</h2>
<ul>
<li><code>POST /api/licence/verify</code> — { key, device_id }</li>
<li><code>POST /api/licence/generate</code> — admin token required</li>
<li><code>POST /api/licence/release</code> — admin token + key, or { key, device_id }</li>
<li><code>POST /api/licence/revoke</code> — admin token required (U14)</li>
<li><code>GET /api/licence/status</code> — admin token + key, or ?key=…&amp;device_id=…</li>
<li><code>GET / POST / DELETE /api/patterns</code> — approved templates only (GET); uploads need an activated licence</li>
</ul>
<p>Web UI (signup / login / dashboard) is not on this host yet — Phase 2.</p>
</body></html>`;
  return new Response(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    try {
      if (path === "/") return statusPage();
      if (path === "/api/licence/verify" && request.method === "POST") {
        return await licenceVerify(request, env);
      }
      if (path === "/api/licence/generate" && request.method === "POST") {
        return await licenceGenerate(request, env);
      }
      if (path === "/api/licence/release" && request.method === "POST") {
        return await licenceRelease(request, env);
      }
      if (path === "/api/licence/revoke" && request.method === "POST") {
        return await licenceRevoke(request, env);
      }
      if (path === "/api/licence/status" && request.method === "GET") {
        return await licenceStatus(request, env);
      }
      if (path === "/api/patterns") {
        if (request.method === "POST") return await patternsPost(request, env);
        if (request.method === "GET") return await patternsGet(request, env);
        if (request.method === "DELETE") return await patternsDelete(request, env);
      }
      return json({ error: "not_found" }, 404);
    } catch (e) {
      return json({ error: "server_error", detail: String(e && e.message ? e.message : e) }, 500);
    }
  },
};
