/**
 * Upstash live-wiring tests (completeness #45).
 * Upstream calls are MOCKED fetch — no real Redis, no key.
 * Includes the admin-gated /api/admin/ratelimit-probe hub route:
 * no token -> 401; token + live Upstash -> sequential probe counts.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { handleRequest, type Env } from "../src/hub";
import { checkUpstashLive, probeUpstashCounter, upstashStatus } from "../src/ratelimit";

const ENV = {
  UPSTASH_REDIS_REST_URL: "https://upstash-test.example.com",
  UPSTASH_REDIS_REST_TOKEN: "test-token",
} as unknown as Env;

afterEach(() => {
  vi.unstubAllGlobals();
});

function jsonResp(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("upstashStatus / checkUpstashLive", () => {
  it("unconfigured env -> configured:false, live:false, fetch never called", async () => {
    expect(upstashStatus({} as Env)).toEqual({ configured: false });
    const fetchFn = vi.fn(async () => jsonResp("PONG"));
    expect(await checkUpstashLive({} as Env, { fetchFn: fetchFn as unknown as typeof fetch })).toEqual({
      configured: false,
      live: false,
    });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("ping PONG -> live:true; non-ok / network throw -> live:false", async () => {
    expect(upstashStatus(ENV)).toEqual({ configured: true });
    const pongFetch = (async () => jsonResp("PONG")) as unknown as typeof fetch;
    expect(await checkUpstashLive(ENV, { fetchFn: pongFetch })).toEqual({ configured: true, live: true });
    const errFetch = (async () => new Response("no", { status: 401 })) as unknown as typeof fetch;
    expect(await checkUpstashLive(ENV, { fetchFn: errFetch })).toEqual({ configured: true, live: false });
    const throwFetch = (async () => {
      throw new Error("down");
    }) as unknown as typeof fetch;
    expect(await checkUpstashLive(ENV, { fetchFn: throwFetch })).toEqual({ configured: true, live: false });
  });
});

describe("probeUpstashCounter", () => {
  it("unconfigured -> upstash_not_configured", async () => {
    expect(await probeUpstashCounter({} as Env)).toEqual({ ok: false, error: "upstash_not_configured" });
  });

  it("two sequential INCRs + DEL on a random probe key -> ok with counts", async () => {
    let pipelineBody: unknown = null;
    let pipelineUrl = "";
    const fetchFn = (async (url: string, init?: RequestInit) => {
      pipelineUrl = url;
      pipelineBody = JSON.parse(String(init?.body ?? "null"));
      return jsonResp([{ result: "5" }, { result: "6" }, { result: 1 }]);
    }) as unknown as typeof fetch;
    const res = await probeUpstashCounter(ENV, { fetchFn });
    expect(res.ok).toBe(true);
    expect(res.counts).toEqual([5, 6]);
    expect(pipelineUrl).toBe("https://upstash-test.example.com/pipeline");
    const cmds = pipelineBody as Array<[string, string]>;
    expect(cmds[0][0]).toBe("INCR");
    expect(cmds[1][0]).toBe("INCR");
    expect(cmds[2][0]).toBe("DEL");
    expect(cmds[0][1]).toBe(cmds[1][1]);
    expect(cmds[0][1]).toMatch(/^rl:probe:[0-9a-f]{16}$/);
    expect(cmds[2][1]).toBe(cmds[0][1]);
  });

  it("non-sequential counts -> counter_not_sequential; HTTP 500 -> upstash_error", async () => {
    const flatFetch = (async () => jsonResp([{ result: "5" }, { result: "5" }, { result: 1 }])) as unknown as typeof fetch;
    const flat = await probeUpstashCounter(ENV, { fetchFn: flatFetch });
    expect(flat.ok).toBe(false);
    expect(flat.error).toBe("counter_not_sequential");
    const errFetch = (async () => new Response("no", { status: 500 })) as unknown as typeof fetch;
    expect(await probeUpstashCounter(ENV, { fetchFn: errFetch })).toEqual({ ok: false, error: "upstash_error" });
  });
});

describe("POST /api/admin/ratelimit-probe (hub route)", () => {
  function probeEnv(): Env {
    return {
      JARVIS_HUB: {} as unknown as DurableObjectNamespace,
      DB: new FakeD1() as unknown as D1Database,
      LLM_ADMIN_TOKEN: "adm1n",
      ...({ UPSTASH_REDIS_REST_URL: "https://upstash-test.example.com", UPSTASH_REDIS_REST_TOKEN: "test-token" } as Partial<Env>),
    };
  }

  it("no admin token -> 401 (never a public route)", async () => {
    const res = await handleRequest(
      new Request("https://hub/api/admin/ratelimit-probe", { method: "POST" }),
      probeEnv(),
    );
    expect(res.status).toBe(401);
  });

  it("admin token + live Upstash -> 200 with sequential probe counts", async () => {
    vi.stubGlobal(
      "fetch",
      async (url: string) => {
        if (String(url).endsWith("/ping")) return jsonResp("PONG");
        return jsonResp([{ result: "11" }, { result: "12" }, { result: 1 }]);
      },
    );
    const res = await handleRequest(
      new Request("https://hub/api/admin/ratelimit-probe", {
        method: "POST",
        headers: { "x-admin-token": "adm1n" },
      }),
      probeEnv(),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      upstash: { configured: boolean; live: boolean };
      probe: { counts: number[]; sequential: boolean };
    };
    expect(body.ok).toBe(true);
    expect(body.upstash).toEqual({ configured: true, live: true });
    expect(body.probe).toEqual({ counts: [11, 12], sequential: true });
  });

  it("admin token + Upstash down -> 200 with ok:false (honest, no fake live)", async () => {
    vi.stubGlobal("fetch", async () => new Response("no", { status: 500 }));
    const res = await handleRequest(
      new Request("https://hub/api/admin/ratelimit-probe", {
        method: "POST",
        headers: { "x-admin-token": "adm1n" },
      }),
      probeEnv(),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; probe: { error: string } };
    expect(body.ok).toBe(false);
    expect(body.probe.error).toBe("upstash_not_live");
  });
});
