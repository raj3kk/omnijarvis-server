/**
 * Qdrant real-client tests (completeness #30).
 * All Qdrant calls are MOCKED fetch — no real cluster, no key.
 * The client must never fake success: every failure path returns
 * qdrant_not_configured / qdrant_error with ok:false.
 */
import { describe, expect, it } from "vitest";
import {
  QDRANT_COLLECTION,
  qdrantEnsureCollection,
  qdrantQuery,
  qdrantStatus,
  qdrantUpsert,
} from "../src/memory";

const ENV = { QDRANT_URL: "https://qdrant-test.example.com", QDRANT_API_KEY: "test-key" };

type FetchFn = typeof fetch;

function jsonResp(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("qdrantStatus", () => {
  it("configured only when BOTH url and key are set", () => {
    expect(qdrantStatus({})).toEqual({ configured: false });
    expect(qdrantStatus({ QDRANT_URL: "https://x.example.com" })).toEqual({ configured: false });
    expect(qdrantStatus(ENV)).toEqual({ configured: true });
  });
});

describe("qdrantEnsureCollection", () => {
  it("GET 200 -> exists, no create call", async () => {
    const urls: string[] = [];
    const fetchFn = (async (url: string) => {
      urls.push(url);
      return jsonResp({ result: { name: QDRANT_COLLECTION } });
    }) as unknown as FetchFn;
    expect(await qdrantEnsureCollection(ENV, 3, { fetchFn })).toBe(true);
    expect(urls).toEqual([`https://qdrant-test.example.com/collections/${QDRANT_COLLECTION}`]);
  });

  it("GET 404 -> PUT create with size + Cosine; PUT 500 -> false", async () => {
    const calls: { url: string; method?: string; body?: string }[] = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      calls.push({ url, method: init?.method, body: init?.body ? String(init.body) : undefined });
      if (!init?.method || init.method === "GET") return new Response("not found", { status: 404 });
      return jsonResp({ result: true });
    }) as unknown as FetchFn;
    expect(await qdrantEnsureCollection(ENV, 3, { fetchFn })).toBe(true);
    expect(calls).toHaveLength(2);
    expect(calls[1].method).toBe("PUT");
    expect(JSON.parse(calls[1].body ?? "{}")).toEqual({ vectors: { size: 3, distance: "Cosine" } });

    const failFetch = (async (url: string, init?: RequestInit) => {
      if (!init?.method || init.method === "GET") return new Response("not found", { status: 404 });
      return new Response("err", { status: 500 });
    }) as unknown as FetchFn;
    expect(await qdrantEnsureCollection(ENV, 3, { fetchFn: failFetch })).toBe(false);
  });
});

describe("qdrantUpsert", () => {
  it("creates the collection when missing, then upserts the point with tenant payload", async () => {
    const calls: { url: string; method?: string; body?: string; headers?: Record<string, string> }[] = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      calls.push({ url, method: init?.method, body: init?.body ? String(init.body) : undefined, headers: init?.headers as Record<string, string> });
      if (url.endsWith(`/collections/${QDRANT_COLLECTION}`) && !init?.method) {
        return new Response("not found", { status: 404 });
      }
      return jsonResp({ result: { operation_id: 1, status: "completed" }, status: "ok" });
    }) as unknown as FetchFn;
    const res = await qdrantUpsert(
      ENV,
      "t-1",
      7,
      [0.1, 0.2, 0.3],
      { content: "cats are cute", kind: "fact", created_at: 123 },
      { fetchFn },
    );
    expect(res).toEqual({ ok: true });
    expect(calls).toHaveLength(3);
    expect(calls[0].headers?.["api-key"]).toBe("test-key");
    const points = JSON.parse(calls[2].body ?? "{}") as {
      points: Array<{ id: string; vector: number[]; payload: Record<string, unknown> }>;
    };
    expect(points.points[0].id).toBe("t-1:7");
    expect(points.points[0].vector).toEqual([0.1, 0.2, 0.3]);
    expect(points.points[0].payload).toEqual({
      tenant_id: "t-1",
      memory_id: 7,
      kind: "fact",
      content: "cats are cute",
      created_at: 123,
    });
  });

  it("empty embedding -> qdrant_error (never sends a bad vector)", async () => {
    const fetchFn = (async () => jsonResp({})) as unknown as FetchFn;
    expect(await qdrantUpsert(ENV, "t-1", 1, [], {}, { fetchFn })).toEqual({ ok: false, error: "qdrant_error" });
  });
});

describe("qdrantQuery", () => {
  it("posts a tenant-filtered search and maps payload hits", async () => {
    let searchBody: Record<string, unknown> = {};
    const fetchFn = (async (url: string, init?: RequestInit) => {
      searchBody = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
      return jsonResp({
        result: [
          { id: "t-1:7", score: 0.92, payload: { tenant_id: "t-1", memory_id: 7, kind: "fact", content: "cats", created_at: 5 } },
          { id: "t-1:9", score: 0.31, payload: { tenant_id: "t-1", memory_id: 9, kind: "note", content: "dogs", created_at: 6 } },
        ],
      });
    }) as unknown as FetchFn;
    const res = await qdrantQuery(ENV, "t-1", [1, 0, 0], 5, { fetchFn });
    expect(res.ok).toBe(true);
    expect(searchBody).toMatchObject({
      vector: [1, 0, 0],
      filter: { must: [{ key: "tenant_id", match: { value: "t-1" } }] },
      limit: 5,
      with_payload: true,
    });
    expect(res.hits).toEqual([
      { id: 7, content: "cats", kind: "fact", score: 0.92, created_at: 5 },
      { id: 9, content: "dogs", kind: "note", score: 0.31, created_at: 6 },
    ]);
  });

  it("missing collection (404) -> qdrant_error, no auto-create on read", async () => {
    const fetchFn = (async () => new Response("not found", { status: 404 })) as unknown as FetchFn;
    expect(await qdrantQuery(ENV, "t-1", [1, 0], 5, { fetchFn })).toEqual({ ok: false, error: "qdrant_error" });
  });
});
