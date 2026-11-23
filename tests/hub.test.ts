import { describe, expect, it, vi } from "vitest";
import hubWorker, { handleRequest, route, type Env } from "../src/hub";
import { FakeD1 } from "./fake-d1";
import { deriveSixDigit, deriveTenantId } from "../src/pairing";
import { genHubKey } from "./helpers";

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
    ...overrides,
  };
}

// D1 seed (replaces the old Supabase fetch stubs — licences live in D1 now).
async function seedLicence(db: FakeD1, key: string, status = "active") {
  await db
    .prepare("INSERT INTO licences (key, user_id, device_id, status, created_at) VALUES (?, ?, NULL, ?, ?)")
    .bind(key, "owner@example.com", status, Date.now())
    .run();
}

describe("hub routing (2a-1 skeleton, kept)", () => {
  it("GET /health -> 200 ok:true", async () => {
    const res = route("/health");
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(body.service).toBe("omnijarvis-hub");
  });

  it("GET / -> 200", () => {
    expect(route("/").status).toBe(200);
  });

  it("unknown path -> 404 not_found", async () => {
    const res = route("/nope");
    expect(res.status).toBe(404);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("not_found");
  });
});

describe("handleRequest (2a-2 routes, D1 licences)", () => {
  it("pairing init: active licence -> 200 token+code", async () => {
    const db = new FakeD1();
    await seedLicence(db, "L-1");
    const res = await handleRequest(
      new Request("https://hub/api/pairing/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", tenant_id: "t-1", licence_key: "L-1" }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(typeof body.token).toBe("string");
    expect(String(body.code)).toMatch(/^\d{6}$/);
    expect(body.code).toBe(await deriveSixDigit(String(body.token)));
  });

  it("pairing init: no tenant_id -> 200, derived lic- tenant (2b-1)", async () => {
    const db = new FakeD1();
    await seedLicence(db, "L-1");
    const res = await handleRequest(
      new Request("https://hub/api/pairing/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", licence_key: "L-1" }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    const row = await db
      .prepare("SELECT tenant_id FROM pairing_tokens WHERE token = ?")
      .bind(String(body.token))
      .first<{ tenant_id: string }>();
    expect(row?.tenant_id).toBe(await deriveTenantId("L-1"));
    expect(row?.tenant_id.startsWith("lic-")).toBe(true);
  });

  it("pairing init: supplied tenant_id is kept (2b-1)", async () => {
    const db = new FakeD1();
    await seedLicence(db, "L-1");
    const res = await handleRequest(
      new Request("https://hub/api/pairing/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", tenant_id: "t-9", licence_key: "L-1" }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    const row = await db
      .prepare("SELECT tenant_id FROM pairing_tokens WHERE token = ?")
      .bind(String(body.token))
      .first<{ tenant_id: string }>();
    expect(row?.tenant_id).toBe("t-9");
  });

  it("pairing init: revoked licence -> 403 licence_invalid", async () => {
    const db = new FakeD1();
    await seedLicence(db, "L-1", "revoked");
    const res = await handleRequest(
      new Request("https://hub/api/pairing/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", tenant_id: "t-1", licence_key: "L-1" }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("licence_invalid");
  });

  it("pairing init: unknown licence -> 403 licence_invalid", async () => {
    const db = new FakeD1();
    const res = await handleRequest(
      new Request("https://hub/api/pairing/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", tenant_id: "t-1", licence_key: "NOPE" }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("licence_invalid");
  });

  it("pairing register: token one-time (second use 403)", async () => {
    const db = new FakeD1();
    await seedLicence(db, "L-1");
    const env = fakeEnv(db);
    const init = await handleRequest(
      new Request("https://hub/api/pairing/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", tenant_id: "t-1", licence_key: "L-1" }),
      }),
      env,
    );
    const { token } = (await init.json()) as { token: string };
    const regBody = JSON.stringify({ token, device_id: "dev-1", public_key: "aGVsbG8=" });
    const r1 = await handleRequest(
      new Request("https://hub/api/pairing/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: regBody,
      }),
      env,
    );
    expect(r1.status).toBe(200);
    const r2 = await handleRequest(
      new Request("https://hub/api/pairing/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: regBody,
      }),
      env,
    );
    expect(r2.status).toBe(403);
    expect(((await r2.json()) as Record<string, unknown>).error).toBe("token_invalid");
  });

  it("pairing register: returns hub_public_key + key_id (M-4 §4.5)", async () => {
    const db = new FakeD1();
    await seedLicence(db, "L-1");
    const hubKey = await genHubKey();
    const env = fakeEnv(db, { HUB_SIGN_SECRET: hubKey.privateKeyB64 });
    const init = await handleRequest(
      new Request("https://hub/api/pairing/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", tenant_id: "t-1", licence_key: "L-1" }),
      }),
      env,
    );
    const { token } = (await init.json()) as { token: string };
    const res = await handleRequest(
      new Request("https://hub/api/pairing/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, device_id: "dev-1", public_key: "aGVsbG8=" }),
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(body.device_id).toBe("dev-1");
    expect(body.hub_public_key).toBe(hubKey.publicKeyB64);
    expect(body.key_id).toBe("hub-1");
  });

  it("pairing register: no HUB_SIGN_SECRET -> key fields omitted, still 200", async () => {
    const db = new FakeD1();
    await seedLicence(db, "L-1");
    const env = fakeEnv(db);
    const init = await handleRequest(
      new Request("https://hub/api/pairing/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", tenant_id: "t-1", licence_key: "L-1" }),
      }),
      env,
    );
    const { token } = (await init.json()) as { token: string };
    const res = await handleRequest(
      new Request("https://hub/api/pairing/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, device_id: "dev-1", public_key: "aGVsbG8=" }),
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.hub_public_key).toBeUndefined();
    expect(body.key_id).toBeUndefined();
  });

  it("GET / -> version 21 (G-17 observability first-use)", async () => {
    const body = (await route("/").json()) as Record<string, unknown>;
    expect(body.version).toBe("21");
  });

  it("pairing code: derives from token", async () => {
    const db = new FakeD1();
    const res = await handleRequest(
      new Request("https://hub/api/pairing/code?token=deadbeef"),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>).code).toBe(
      await deriveSixDigit("deadbeef"),
    );
  });

  it("pairing init rate limit: 11th call in a minute -> 429", async () => {
    const db = new FakeD1();
    await seedLicence(db, "L-1");
    const env = fakeEnv(db);
    let lastStatus = 0;
    for (let i = 0; i < 11; i++) {
      const res = await handleRequest(
        new Request("https://hub/api/pairing/init", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ device_id: `dev-${i}`, tenant_id: "t-1", licence_key: "L-1" }),
        }),
        env,
      );
      lastStatus = res.status;
    }
    expect(lastStatus).toBe(429);
  });

  it("sync bad_request -> 400", async () => {
    const db = new FakeD1();
    const res = await handleRequest(
      new Request("https://hub/api/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1" }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(400);
  });

  it("cron tick wrong secret -> 401", async () => {
    const db = new FakeD1();
    const res = await handleRequest(
      new Request("https://hub/api/cron/tick", {
        method: "POST",
        headers: { "x-cron-secret": "wrong" },
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(401);
  });

  it("WS upgrade unpaired device -> 403 device_not_paired", async () => {
    const db = new FakeD1();
    const res = await handleRequest(
      new Request("https://hub/ws/dev-ghost", { headers: { Upgrade: "websocket" } }),
      fakeEnv(db),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("device_not_paired");
  });

  it("unknown route -> 404", async () => {
    const db = new FakeD1();
    const res = await handleRequest(new Request("https://hub/nope"), fakeEnv(db));
    expect(res.status).toBe(404);
  });
});

describe("Cloudflare Cron Trigger (B-3: hub self-tick)", () => {
  it("scheduled() runs the tick with the Worker's own secret + writes a cron_trigger trace", async () => {
    const db = new FakeD1();
    const env = fakeEnv(db);
    let pending: Promise<unknown> | undefined;
    const ctx = { waitUntil: (p: Promise<unknown>) => { pending = p; } };
    await hubWorker.scheduled({ cron: "*/5 * * * *", scheduledTime: Date.now() }, env, ctx);
    await pending;
    const traces = (await db.prepare("SELECT * FROM traces").bind().all()).results as Record<string, unknown>[];
    const trigger = traces.find((t) => t.kind === "cron_trigger");
    expect(trigger).toBeDefined();
    expect(JSON.parse(String(trigger!.detail)).source).toBe("cf-cron");
  });

  it("HTTP tick with correct secret -> 200 ok:true (refactor preserved)", async () => {
    const db = new FakeD1();
    const res = await handleRequest(
      new Request("https://hub/api/cron/tick", {
        method: "POST",
        headers: { "x-cron-secret": "test-cron" },
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
  });
});

describe("keepalive probe (2a-4: real checks, D1 licences)", () => {
  it("empty D1 -> ok:true, d1.devices 0, licences ok count 0", async () => {
    const db = new FakeD1();
    const res = await handleRequest(new Request("https://hub/api/keepalive"), fakeEnv(db));
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(body.ok).toBe(true);
    expect(body.checks.d1.ok).toBe(true);
    expect(body.checks.d1.devices).toBe(0);
    expect(body.checks.licences.state).toBe("ok");
    expect(body.checks.licences.count).toBe(0);
    expect(body.checks.supabase).toBeUndefined();
  });

  it("one device + one licence in D1 -> devices 1, licences 1", async () => {
    const db = new FakeD1();
    await db
      .prepare(
        "INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .bind("dev-1", "t-1", "key", Date.now(), Date.now(), 1)
      .run();
    await seedLicence(db, "L-1");
    const res = await handleRequest(new Request("https://hub/api/keepalive"), fakeEnv(db));
    const body = (await res.json()) as Record<string, any>;
    expect(body.checks.d1.devices).toBe(1);
    expect(body.checks.licences.count).toBe(1);
  });
});

describe("POST /api/observability/probe (G-17 first-use)", () => {
  it("admin token -> awaits Sentry + Langfuse and returns the accepted ids", async () => {
    const db = new FakeD1();
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      async (url: string) => {
        seen.push(String(url));
        if (String(url).includes("sentry.example.com")) {
          return new Response(JSON.stringify({ id: "srv-event-1" }), { status: 200 });
        }
        return new Response("", { status: 200 });
      },
    );
    try {
      const res = await handleRequest(
        new Request("https://hub/api/observability/probe", {
          method: "POST",
          headers: { "x-admin-token": "adm-1" },
        }),
        fakeEnv(db, {
          LLM_ADMIN_TOKEN: "adm-1",
          SENTRY_DSN: "https://pubkey123@sentry.example.com/42",
          LANGFUSE_PUBLIC_KEY: "pk_test",
          LANGFUSE_SECRET_KEY: "sk_test",
        }),
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        sentry: { configured: boolean; event_id: string | null };
        langfuse: { configured: boolean; trace_id: string | null };
      };
      expect(body.ok).toBe(true);
      expect(body.sentry.configured).toBe(true);
      expect(body.sentry.event_id).toBe("srv-event-1");
      expect(body.langfuse.configured).toBe(true);
      expect(typeof body.langfuse.trace_id).toBe("string");
      expect(String(body.langfuse.trace_id)).toMatch(/^[0-9a-f]{32}$/);
      expect(seen.some((u) => u.includes("/api/public/otel/v1/traces"))).toBe(true);
      expect(seen.some((u) => u.includes("/api/42/envelope/"))).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("no admin token -> 401, senders never called", async () => {
    const db = new FakeD1();
    const fetchFn = vi.fn(async () => new Response("", { status: 200 }));
    vi.stubGlobal("fetch", fetchFn);
    try {
      const res = await handleRequest(
        new Request("https://hub/api/observability/probe", { method: "POST" }),
        fakeEnv(db, {
          LLM_ADMIN_TOKEN: "adm-1",
          SENTRY_DSN: "https://pubkey123@sentry.example.com/42",
          LANGFUSE_PUBLIC_KEY: "pk_test",
          LANGFUSE_SECRET_KEY: "sk_test",
        }),
      );
      expect(res.status).toBe(401);
      expect(fetchFn).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("sinks unconfigured -> 200 with null ids (probe is honest, never faked)", async () => {
    const db = new FakeD1();
    const fetchFn = vi.fn(async () => new Response("", { status: 200 }));
    vi.stubGlobal("fetch", fetchFn);
    try {
      const res = await handleRequest(
        new Request("https://hub/api/observability/probe", {
          method: "POST",
          headers: { "x-admin-token": "adm-1" },
        }),
        fakeEnv(db, { LLM_ADMIN_TOKEN: "adm-1" }),
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        sentry: { configured: boolean; event_id: string | null };
        langfuse: { configured: boolean; trace_id: string | null };
      };
      expect(body.sentry).toEqual({ configured: false, event_id: null });
      expect(body.langfuse).toEqual({ configured: false, trace_id: null });
      expect(fetchFn).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
