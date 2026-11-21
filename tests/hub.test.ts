import { afterEach, describe, expect, it, vi } from "vitest";
import { handleRequest, route, type Env } from "../src/hub";
import { FakeD1 } from "./fake-d1";
import { deriveSixDigit } from "../src/pairing";

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
    SUPABASE_URL: "https://x.supabase.co",
    SUPABASE_SERVICE_ROLE_KEY: "test-key",
    ...overrides,
  };
}

function stubLicences(rows: Record<string, unknown>[]) {
  vi.stubGlobal(
    "fetch",
    async (url: string) => {
      if (url.includes("/rest/v1/licences")) {
        return new Response(JSON.stringify(rows), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    },
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

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

describe("handleRequest (2a-2 routes)", () => {
  it("pairing init: active licence -> 200 token+code", async () => {
    const db = new FakeD1();
    stubLicences([{ key: "L-1", status: "active" }]);
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

  it("pairing init: revoked licence -> 403 licence_invalid", async () => {
    const db = new FakeD1();
    stubLicences([{ key: "L-1", status: "revoked" }]);
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

  it("pairing init: Supabase env missing -> 503 config_missing", async () => {
    const db = new FakeD1();
    const env = fakeEnv(db, { SUPABASE_URL: undefined, SUPABASE_SERVICE_ROLE_KEY: undefined });
    const res = await handleRequest(
      new Request("https://hub/api/pairing/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: "dev-1", tenant_id: "t-1", licence_key: "L-1" }),
      }),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("pairing register: token one-time (second use 403)", async () => {
    const db = new FakeD1();
    stubLicences([{ key: "L-1", status: "active" }]);
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
    stubLicences([{ key: "L-1", status: "active" }]);
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
