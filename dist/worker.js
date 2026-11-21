// src/crypto.ts
function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function canonicalString(deviceId, nonce, ts, payloadRaw) {
  return `${deviceId}
${nonce}
${ts}
${payloadRaw}`;
}
async function importPublicKey(publicKeyB64) {
  const raw = base64ToBytes(publicKeyB64);
  return await crypto.subtle.importKey("raw", raw.buffer, { name: "Ed25519" }, false, [
    "verify"
  ]);
}
async function verifySignature(publicKeyB64, signatureB64, deviceId, nonce, ts, payloadRaw) {
  try {
    const key = await importPublicKey(publicKeyB64);
    const sig = base64ToBytes(signatureB64);
    const data = new TextEncoder().encode(canonicalString(deviceId, nonce, ts, payloadRaw));
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig.buffer, data);
  } catch {
    return false;
  }
}
function isTimestampFresh(ts, nowMs, windowMs = 3e5) {
  return Math.abs(nowMs - ts) <= windowMs;
}
function randomNonceHex(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

// src/db.ts
async function getDevice(db, deviceId) {
  const row = await db.prepare("SELECT device_id, tenant_id, public_key, enabled FROM devices WHERE device_id = ?").bind(deviceId).first();
  return row;
}
async function insertTrace(db, tenantId, deviceId, kind, detail) {
  await db.prepare("INSERT INTO traces (tenant_id, device_id, kind, detail, created_at) VALUES (?, ?, ?, ?, ?)").bind(tenantId, deviceId, kind, JSON.stringify(detail), Date.now()).run();
}
async function touchDeviceSeen(db, deviceId) {
  await db.prepare("UPDATE devices SET last_seen = ? WHERE device_id = ?").bind(Date.now(), deviceId).run();
}

// src/do/JarvisHub.ts
var NONCE_TTL_MS = 3e5;
var HELLO_TIMEOUT_MS = 3e4;
var MAX_PENDING_PER_DEVICE = 50;
var JarvisHub = class {
  state;
  env;
  expectedDeviceId = null;
  authenticatedDeviceId = null;
  publicKey = null;
  sockets = /* @__PURE__ */ new Set();
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }
  sql() {
    return this.state.storage.sql;
  }
  ensureTables() {
    this.sql().exec(
      "CREATE TABLE IF NOT EXISTS sessions (device_id TEXT PRIMARY KEY, connected_at INTEGER, last_seen INTEGER)"
    );
    this.sql().exec(
      "CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expires_at INTEGER)"
    );
    this.sql().exec(
      "CREATE TABLE IF NOT EXISTS pending_steps (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT, created_at INTEGER)"
    );
  }
  async useNonce(nonce, nowMs) {
    this.sql().exec("DELETE FROM nonces WHERE expires_at < ?", nowMs);
    try {
      this.sql().exec("INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)", nonce, nowMs + NONCE_TTL_MS);
      return true;
    } catch {
      return false;
    }
  }
  async verifyDeviceMessage(msg) {
    if (!isTimestampFresh(msg.ts, Date.now())) return false;
    if (this.expectedDeviceId && msg.device_id !== this.expectedDeviceId) return false;
    if (!await this.useNonce(msg.nonce, Date.now())) return false;
    if (!this.publicKey) {
      const device = await getDevice(this.env.DB, msg.device_id);
      if (!device || device.enabled === 0) return false;
      this.publicKey = device.public_key;
    }
    return await verifySignature(
      this.publicKey,
      msg.sig,
      msg.device_id,
      msg.nonce,
      msg.ts,
      msg.payload_raw
    );
  }
  async flushPending(ws) {
    const rows = [...this.sql().exec("SELECT id, payload FROM pending_steps ORDER BY id ASC").toArray()];
    for (const row of rows) {
      try {
        ws.send(JSON.stringify({ type: "EXECUTE_STEP", step: JSON.parse(row.payload) }));
      } catch {
        return;
      }
      this.sql().exec("DELETE FROM pending_steps WHERE id = ?", row.id);
    }
  }
  async queueOrSend(step) {
    const payload = JSON.stringify(step);
    for (const ws of this.sockets) {
      try {
        ws.send(JSON.stringify({ type: "EXECUTE_STEP", step }));
        return true;
      } catch {
      }
    }
    const count = [...this.sql().exec("SELECT COUNT(*) AS n FROM pending_steps").toArray()][0];
    if (count.n >= MAX_PENDING_PER_DEVICE) {
      this.sql().exec("DELETE FROM pending_steps WHERE id = (SELECT MIN(id) FROM pending_steps)");
    }
    this.sql().exec("INSERT INTO pending_steps (payload, created_at) VALUES (?, ?)", payload, Date.now());
    return false;
  }
  async fetch(request) {
    this.ensureTables();
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    if (path === "/dispatch" && request.method === "POST") {
      const secret = this.env.INTERNAL_SECRET;
      if (!secret || request.headers.get("x-internal-secret") !== secret) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const body = await request.json();
      if (!body.device_id || !body.step) {
        return Response.json({ error: "bad_request" }, { status: 400 });
      }
      if (this.expectedDeviceId && body.device_id !== this.expectedDeviceId) {
        return Response.json({ error: "device_mismatch" }, { status: 400 });
      }
      const sent = await this.queueOrSend(body.step);
      return Response.json({ ok: true, sent });
    }
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }
    const expected = request.headers.get("x-expected-device");
    if (!expected) {
      return Response.json({ error: "missing_device" }, { status: 400 });
    }
    this.expectedDeviceId = expected;
    const pair = new WebSocketPair();
    this.state.acceptWebSocket(pair[1]);
    this.sockets.add(pair[1]);
    await this.state.storage.setAlarm(Date.now() + HELLO_TIMEOUT_MS);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }
  async webSocketMessage(ws, message) {
    let msg;
    try {
      msg = JSON.parse(typeof message === "string" ? message : new TextDecoder().decode(message));
    } catch {
      ws.close(4400, "bad_json");
      return;
    }
    if (msg.type === "PING") {
      ws.send(JSON.stringify({ type: "PONG" }));
      return;
    }
    if (msg.type !== "HELLO" && msg.type !== "STEP_RESULT") {
      ws.close(4400, "unknown_type");
      return;
    }
    if (!await this.verifyDeviceMessage(msg)) {
      ws.close(4401, "unauthorized");
      return;
    }
    let payload;
    try {
      payload = JSON.parse(msg.payload_raw);
    } catch {
      ws.close(4400, "bad_payload");
      return;
    }
    if (msg.type === "HELLO") {
      this.authenticatedDeviceId = msg.device_id;
      const now = Date.now();
      this.sql().exec(
        "INSERT INTO sessions (device_id, connected_at, last_seen) VALUES (?, ?, ?) ON CONFLICT(device_id) DO UPDATE SET last_seen = excluded.last_seen",
        msg.device_id,
        now,
        now
      );
      await touchDeviceSeen(this.env.DB, msg.device_id);
      ws.send(JSON.stringify({ type: "HELLO_ACK", device_id: msg.device_id }));
      await this.flushPending(ws);
      return;
    }
    const device = await getDevice(this.env.DB, msg.device_id);
    if (device) {
      await insertTrace(this.env.DB, device.tenant_id, msg.device_id, "step_result", {
        ok: payload.ok ?? null,
        summary: typeof payload.summary === "string" ? payload.summary.slice(0, 200) : null
      });
    }
    ws.send(JSON.stringify({ type: "ACK", id: payload.step_id ?? null }));
  }
  async webSocketClose(ws, _code, _reason, _wasClean) {
    this.sockets.delete(ws);
    if (this.authenticatedDeviceId) {
      try {
        await touchDeviceSeen(this.env.DB, this.authenticatedDeviceId);
      } catch {
      }
      this.sql().exec("DELETE FROM sessions WHERE device_id = ?", this.authenticatedDeviceId);
      this.authenticatedDeviceId = null;
    }
  }
  async webSocketError(ws, _error) {
    this.sockets.delete(ws);
    try {
      ws.close(1011, "error");
    } catch {
    }
  }
  async alarm() {
    if (!this.authenticatedDeviceId) {
      for (const ws of this.sockets) {
        try {
          ws.close(4401, "hello_timeout");
        } catch {
        }
      }
      this.sockets.clear();
    }
  }
};

// src/pairing.ts
var PAIRING_TOKEN_TTL_MS = 3e5;
async function deriveSixDigit(token) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const view = new DataView(digest);
  const num = view.getUint32(0, false) % 1e6;
  return String(num).padStart(6, "0");
}
function newPairingToken() {
  return randomNonceHex(16);
}
async function issuePairingToken(db, deviceId, tenantId) {
  const token = newPairingToken();
  const expiresAt = Date.now() + PAIRING_TOKEN_TTL_MS;
  await db.prepare("INSERT INTO pairing_tokens (token, device_id, tenant_id, expires_at) VALUES (?, ?, ?, ?)").bind(token, deviceId, tenantId, expiresAt).run();
  return { token, code: await deriveSixDigit(token), expiresAt };
}
async function consumePairingToken(db, token) {
  const row = await db.prepare("SELECT token, device_id, tenant_id, expires_at FROM pairing_tokens WHERE token = ?").bind(token).first();
  if (!row) return null;
  await db.prepare("DELETE FROM pairing_tokens WHERE token = ?").bind(token).run();
  if (row.expires_at < Date.now()) return null;
  return row;
}
async function registerDevice(db, deviceId, tenantId, publicKeyB64) {
  const now = Date.now();
  await db.prepare(
    "INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(device_id) DO UPDATE SET public_key = excluded.public_key, last_seen = excluded.last_seen"
  ).bind(deviceId, tenantId, publicKeyB64, now, now, 1).run();
}

// src/sync.ts
async function handleSync(db, req, rawRowsJson) {
  const device = await getDevice(db, req.device_id);
  if (!device || device.enabled === 0) {
    return { ok: false, server_seq: 0, accepted: 0, error: "device_not_paired" };
  }
  if (!isTimestampFresh(req.ts, Date.now())) {
    return { ok: false, server_seq: 0, accepted: 0, error: "stale_timestamp" };
  }
  const valid = await verifySignature(
    device.public_key,
    req.sig,
    req.device_id,
    req.nonce,
    req.ts,
    rawRowsJson
  );
  if (!valid) {
    return { ok: false, server_seq: 0, accepted: 0, error: "bad_signature" };
  }
  let accepted = 0;
  if (req.table === "traces") {
    for (const row of req.rows) {
      const kind = typeof row.kind === "string" ? row.kind : "unknown";
      const detail = row.detail ?? {};
      await insertTrace(db, device.tenant_id, req.device_id, kind, detail);
      accepted++;
    }
  } else {
    const period = (/* @__PURE__ */ new Date()).toISOString().slice(0, 7);
    let replies = 0;
    let e2bRuns = 0;
    for (const row of req.rows) {
      replies += typeof row.replies === "number" ? row.replies : 0;
      e2bRuns += typeof row.e2b_runs === "number" ? row.e2b_runs : 0;
    }
    if (replies !== 0 || e2bRuns !== 0) {
      await db.prepare(
        "INSERT INTO usage_counters (tenant_id, period, replies, e2b_runs) VALUES (?, ?, ?, ?) ON CONFLICT(tenant_id, period) DO UPDATE SET replies = usage_counters.replies + excluded.replies, e2b_runs = usage_counters.e2b_runs + excluded.e2b_runs"
      ).bind(device.tenant_id, period, replies, e2bRuns).run();
      accepted = req.rows.length;
    }
  }
  const seqRow = await db.prepare("SELECT last_seq FROM sync_state WHERE device_id = ? AND table_name = ?").bind(req.device_id, req.table).first();
  const serverSeq = seqRow ? seqRow.last_seq : 0;
  await db.prepare(
    "INSERT INTO sync_state (device_id, table_name, last_seq) VALUES (?, ?, ?) ON CONFLICT(device_id, table_name) DO UPDATE SET last_seq = excluded.last_seq"
  ).bind(req.device_id, req.table, Math.max(serverSeq, req.last_seq)).run();
  return { ok: true, server_seq: Math.max(serverSeq, req.last_seq), accepted };
}

// src/supabase.ts
var SupabaseMissing = class extends Error {
  constructor() {
    super("supabase_not_configured");
  }
};
var SupabaseSchemaPending = class extends Error {
  constructor() {
    super("schema_pending");
  }
};
async function supabaseSelect(env, table, query) {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) throw new SupabaseMissing();
  const url = `${env.SUPABASE_URL}/rest/v1/${table}?${query}`;
  const res = await fetch(url, {
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      Accept: "application/json"
    }
  });
  if (res.status === 404) throw new SupabaseSchemaPending();
  if (!res.ok) {
    const text = await res.text();
    if (text.includes("42P01") || text.includes("does not exist")) {
      throw new SupabaseSchemaPending();
    }
    throw new Error(`supabase_select_failed:${res.status}`);
  }
  return await res.json();
}
async function supabaseUpdate(env, table, match, patch) {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) throw new SupabaseMissing();
  const url = `${env.SUPABASE_URL}/rest/v1/${table}?${match}`;
  const res = await fetch(url, {
    method: "PATCH",
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=minimal"
    },
    body: JSON.stringify(patch)
  });
  if (res.status === 404) throw new SupabaseSchemaPending();
  if (!res.ok) {
    const text = await res.text();
    if (text.includes("42P01") || text.includes("does not exist")) {
      throw new SupabaseSchemaPending();
    }
    throw new Error(`supabase_update_failed:${res.status}`);
  }
}
async function verifyLicenceKey(env, key) {
  const rows = await supabaseSelect(
    env,
    "licences",
    `select=key,status&key=eq.${encodeURIComponent(key)}`
  );
  return rows.length > 0 && rows[0].status === "active";
}

// src/cron.ts
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function cronMinuteKey(jobId, nowMs) {
  const minute = Math.floor(nowMs / 6e4);
  return `${jobId}:${minute}`;
}
async function handleTick(db, env, secret, dispatch, nowMs = Date.now()) {
  if (!env.CRON_SECRET || !secret || !constantTimeEqual(secret, env.CRON_SECRET)) {
    return { ok: false, fired: 0, skipped: 0, error: "unauthorized" };
  }
  let jobs;
  try {
    jobs = await supabaseSelect(
      env,
      "scheduled_jobs",
      `select=id,tenant_id,device_id,cron_expr,command&enabled=eq.true&next_run_at=lte.${new Date(nowMs).toISOString()}`
    );
  } catch (e) {
    if (e instanceof SupabaseMissing) return { ok: false, fired: 0, skipped: 0, error: "config_missing" };
    if (e instanceof SupabaseSchemaPending) return { ok: false, fired: 0, skipped: 0, error: "schema_pending" };
    throw e;
  }
  let fired = 0;
  let skipped = 0;
  for (const job of jobs) {
    const jobId = String(job.id);
    const minuteKey = cronMinuteKey(jobId, nowMs);
    const existing = await db.prepare("SELECT id FROM traces WHERE kind = ? AND detail LIKE ? LIMIT 1").bind("cron_fire", `%"minute":"${minuteKey}"%`).first();
    if (existing) {
      skipped++;
      continue;
    }
    const dispatched = await dispatch(String(job.device_id), {
      kind: "CRON_COMMAND",
      command: String(job.command),
      job_id: jobId
    });
    await insertTrace(db, String(job.tenant_id), String(job.device_id), "cron_fire", {
      job_id: jobId,
      minute: minuteKey,
      dispatched
    });
    const next = nextCronRun(String(job.cron_expr), nowMs);
    await supabaseUpdate(env, "scheduled_jobs", `id=eq.${jobId}`, {
      last_run_at: new Date(nowMs).toISOString(),
      next_run_at: next ? new Date(next).toISOString() : null
    });
    fired++;
  }
  return { ok: true, fired, skipped };
}
function nextCronRun(cronExpr, fromMs) {
  const fields = cronExpr.trim().split(/\s+/);
  if (fields.length !== 5) return null;
  const parse = (field, min, max) => {
    const out = /* @__PURE__ */ new Set();
    for (const part of field.split(",")) {
      const stepSplit = part.split("/");
      const range = stepSplit[0];
      const step = stepSplit.length > 1 ? Number(stepSplit[1]) : 1;
      if (!Number.isInteger(step) || step < 1) return null;
      let lo = min;
      let hi = max;
      if (range !== "*") {
        const dash = range.split("-");
        if (dash.length === 1) {
          lo = hi = Number(dash[0]);
        } else if (dash.length === 2) {
          lo = Number(dash[0]);
          hi = Number(dash[1]);
        } else {
          return null;
        }
        if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < min || hi > max || lo > hi) {
          return null;
        }
      }
      for (let v = lo; v <= hi; v += step) out.add(v);
    }
    return out;
  };
  const minutes = parse(fields[0], 0, 59);
  const hours = parse(fields[1], 0, 23);
  const doms = parse(fields[2], 1, 31);
  const months = parse(fields[3], 1, 12);
  const dowsRaw = parse(fields[4], 0, 7);
  if (!minutes || !hours || !doms || !months || !dowsRaw) return null;
  const dows = /* @__PURE__ */ new Set();
  for (const d of dowsRaw) dows.add(d === 7 ? 0 : d);
  const domStar = fields[2] === "*";
  const dowStar = fields[4] === "*";
  let t = Math.floor(fromMs / 6e4) * 6e4 + 6e4;
  const limit = fromMs + 366 * 24 * 60 * 6e4;
  while (t <= limit) {
    const d = new Date(t);
    const domMatch = doms.has(d.getUTCDate());
    const dowMatch = dows.has(d.getUTCDay());
    const dayMatch = domStar && dowStar ? true : domStar ? dowMatch : dowStar ? domMatch : domMatch || dowMatch;
    if (minutes.has(d.getUTCMinutes()) && hours.has(d.getUTCHours()) && months.has(d.getUTCMonth() + 1) && dayMatch) {
      return t;
    }
    t += 6e4;
  }
  return null;
}

// src/ratelimit.ts
var RATE_LIMITS = {
  licenceVerify: { limit: 30, windowMs: 6e4 },
  licenceGenerate: { limit: 20, windowMs: 6e4 },
  licenceRelease: { limit: 30, windowMs: 6e4 },
  licenceStatus: { limit: 60, windowMs: 6e4 },
  patternsPost: { limit: 60, windowMs: 6e4 },
  patternsGet: { limit: 120, windowMs: 6e4 },
  patternsDelete: { limit: 20, windowMs: 6e4 },
  pairingInit: { limit: 10, windowMs: 6e4 },
  pairingRegister: { limit: 10, windowMs: 6e4 },
  sync: { limit: 120, windowMs: 6e4 }
};
var fallbackStore = /* @__PURE__ */ new Map();
function fallbackCheck(key, limit, windowMs, nowMs) {
  const hits = (fallbackStore.get(key) ?? []).filter((t) => nowMs - t < windowMs);
  if (hits.length >= limit) {
    fallbackStore.set(key, hits);
    return false;
  }
  hits.push(nowMs);
  fallbackStore.set(key, hits);
  return true;
}
async function checkRateLimit(env, route2, identifier) {
  const budget = RATE_LIMITS[route2];
  const key = `rl:${route2}:${identifier}`;
  const url = env.UPSTASH_REDIS_REST_URL;
  const token = env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) {
    return { allowed: fallbackCheck(key, budget.limit, budget.windowMs, Date.now()), fallback: true };
  }
  try {
    const res = await fetch(`${url}/pipeline`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify([
        ["INCR", key],
        ["PEXPIRE", key, String(budget.windowMs), "NX"]
      ])
    });
    if (!res.ok) throw new Error(`upstash:${res.status}`);
    const data = await res.json();
    const count = Number(data?.[0]?.result ?? 0);
    return { allowed: count <= budget.limit, fallback: false };
  } catch {
    return { allowed: fallbackCheck(key, budget.limit, budget.windowMs, Date.now()), fallback: true };
  }
}

// src/hub.ts
var SERVICE = "omnijarvis-hub";
var VERSION = "2a-2";
function route(path) {
  const p = path.replace(/\/+$/, "") || "/";
  if (p === "/health") {
    return Response.json({ ok: true, service: SERVICE, version: VERSION });
  }
  if (p === "/") {
    return Response.json({ ok: true, service: SERVICE, version: VERSION });
  }
  return Response.json({ error: "not_found" }, { status: 404 });
}
function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders }
  });
}
function clientIp(request) {
  return request.headers.get("cf-connecting-ip") ?? "unknown";
}
async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;
  try {
    if (path === "/" || path === "/health") return route(path);
    if (path === "/api/keepalive" && method === "GET") {
      return json({ ok: true, service: SERVICE, version: VERSION, time: Date.now() });
    }
    if (path === "/api/pairing/init" && method === "POST") {
      const rl = await checkRateLimit(env, "pairingInit", clientIp(request));
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
      const body = await readJson(request);
      const deviceId = typeof body.device_id === "string" ? body.device_id : "";
      const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
      const licenceKey = typeof body.licence_key === "string" ? body.licence_key : "";
      if (!deviceId || !tenantId || !licenceKey) return json({ error: "bad_request" }, 400);
      let licensed = false;
      try {
        licensed = await verifyLicenceKey(env, licenceKey);
      } catch (e) {
        if (e instanceof SupabaseMissing) return json({ error: "config_missing" }, 503);
        throw e;
      }
      if (!licensed) return json({ error: "licence_invalid" }, 403);
      const issued = await issuePairingToken(env.DB, deviceId, tenantId);
      return json({ ok: true, token: issued.token, code: issued.code, expires_at: issued.expiresAt });
    }
    if (path === "/api/pairing/code" && method === "GET") {
      const token = url.searchParams.get("token") ?? "";
      if (!token) return json({ error: "bad_request" }, 400);
      return json({ ok: true, code: await deriveSixDigit(token) });
    }
    if (path === "/api/pairing/register" && method === "POST") {
      const rl = await checkRateLimit(env, "pairingRegister", clientIp(request));
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
      const body = await readJson(request);
      const token = typeof body.token === "string" ? body.token : "";
      const deviceId = typeof body.device_id === "string" ? body.device_id : "";
      const publicKey = typeof body.public_key === "string" ? body.public_key : "";
      if (!token || !deviceId || !publicKey) return json({ error: "bad_request" }, 400);
      const consumed = await consumePairingToken(env.DB, token);
      if (!consumed || consumed.device_id !== deviceId) {
        return json({ error: "token_invalid" }, 403);
      }
      await registerDevice(env.DB, deviceId, consumed.tenant_id, publicKey);
      return json({ ok: true, device_id: deviceId });
    }
    if (path === "/api/sync" && method === "POST") {
      const body = await readJson(request);
      const deviceId = typeof body.device_id === "string" ? body.device_id : "";
      const rl = await checkRateLimit(env, "sync", deviceId || clientIp(request));
      if (!rl.allowed) return json({ error: "rate_limited" }, 429, rl.fallback ? { "x-ratelimit-fallback": "1" } : {});
      const syncReq = body;
      if (!deviceId || !syncReq.table || !Array.isArray(syncReq.rows)) {
        return json({ error: "bad_request" }, 400);
      }
      const rawRowsJson = JSON.stringify(syncReq.rows);
      const result = await handleSync(env.DB, syncReq, rawRowsJson);
      return json(result, result.ok ? 200 : 403);
    }
    if (path === "/api/cron/tick" && method === "POST") {
      const dispatch = async (deviceId, step) => {
        const id = env.JARVIS_HUB.idFromName(`device:${deviceId}`);
        const stub = env.JARVIS_HUB.get(id);
        const res = await stub.fetch(
          new Request("https://hub/dispatch", {
            method: "POST",
            headers: {
              "x-internal-secret": env.INTERNAL_SECRET ?? "",
              "Content-Type": "application/json"
            },
            body: JSON.stringify({ device_id: deviceId, step })
          })
        );
        return res.ok;
      };
      const result = await handleTick(env.DB, env, request.headers.get("x-cron-secret"), dispatch);
      if (!result.ok && result.error === "unauthorized") return json({ error: "unauthorized" }, 401);
      if (!result.ok && result.error === "schema_pending") return json({ error: "schema_pending" }, 503);
      if (!result.ok && result.error === "config_missing") return json({ error: "config_missing" }, 503);
      return json(result);
    }
    if (path.startsWith("/ws/") && method === "GET") {
      const deviceId = path.slice(4).split("/")[0] ?? "";
      if (!deviceId) return json({ error: "bad_request" }, 400);
      const device = await getDevice(env.DB, deviceId);
      if (!device || device.enabled === 0) return json({ error: "device_not_paired" }, 403);
      const id = env.JARVIS_HUB.idFromName(`device:${deviceId}`);
      const stub = env.JARVIS_HUB.get(id);
      const headers = new Headers(request.headers);
      headers.set("x-expected-device", deviceId);
      return await stub.fetch(new Request(request.url, { method: request.method, headers }));
    }
    return json({ error: "not_found" }, 404);
  } catch (e) {
    if (e instanceof SupabaseSchemaPending) return json({ error: "schema_pending" }, 503);
    return json({ error: "server_error", detail: String(e?.message ?? e) }, 500);
  }
}
var hub_default = {
  async fetch(request, env) {
    return handleRequest(request, env);
  }
};
export {
  JarvisHub,
  hub_default as default,
  handleRequest,
  route
};
