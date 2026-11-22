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
  it("GET 200 with tenant_id in payload_schema -> exists, no further call", async () => {
    const urls: string[] = [];
    const fetchFn = (async (url: string) => {
      urls.push(url);
      return jsonResp({ result: { name: QDRANT_COLLECTION, payload_schema: { tenant_id: { data_type: "keyword" } } } });
    }) as unknown as FetchFn;
    expect(await qdrantEnsureCollection(ENV, 3, { fetchFn })).toBe(true);
    expect(urls).toEqual([`https://qdrant-test.example.com/collections/${QDRANT_COLLECTION}`]);
  });

  it("GET 200 WITHOUT tenant_id in payload_schema -> PUTs the keyword index (R-15 Q2)", async () => {
    const calls: { url: string; method?: string; body?: string }[] = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      calls.push({ url, method: init?.method, body: init?.body ? String(init.body) : undefined });
      if (!init?.method || init.method === "GET") {
        return jsonResp({ result: { name: QDRANT_COLLECTION, payload_schema: {} } });
      }
      return jsonResp({ result: true });
    }) as unknown as FetchFn;
    expect(await qdrantEnsureCollection(ENV, 3, { fetchFn })).toBe(true);
    expect(calls).toHaveLength(2);
    expect(calls[1].url).toBe(`https://qdrant-test.example.com/collections/${QDRANT_COLLECTION}/index`);
    expect(calls[1].method).toBe("PUT");
    expect(JSON.parse(calls[1].body ?? "{}")).toEqual({ field_name: "tenant_id", field_schema: "keyword" });
  });

  it("GET 200 without tenant_id + index PUT 500 -> false (fail closed, never a fake success)", async () => {
    const fetchFn = (async (url: string, init?: RequestInit) => {
      if (!init?.method || init.method === "GET") {
        return jsonResp({ result: { name: QDRANT_COLLECTION, payload_schema: {} } });
      }
      return new Response("err", { status: 500 });
    }) as unknown as FetchFn;
    expect(await qdrantEnsureCollection(ENV, 3, { fetchFn })).toBe(false);
  });

  it("GET 404 -> PUT create with size + Cosine, then PUT tenant_id index; PUT 500 -> false", async () => {
    const calls: { url: string; method?: string; body?: string }[] = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      calls.push({ url, method: init?.method, body: init?.body ? String(init.body) : undefined });
      if (!init?.method || init.method === "GET") return new Response("not found", { status: 404 });
      return jsonResp({ result: true });
    }) as unknown as FetchFn;
    expect(await qdrantEnsureCollection(ENV, 3, { fetchFn })).toBe(true);
    expect(calls).toHaveLength(3);
    expect(calls[1].method).toBe("PUT");
    expect(JSON.parse(calls[1].body ?? "{}")).toEqual({ vectors: { size: 3, distance: "Cosine" } });
    expect(calls[2].url).toBe(`https://qdrant-test.example.com/collections/${QDRANT_COLLECTION}/index`);
    expect(JSON.parse(calls[2].body ?? "{}")).toEqual({ field_name: "tenant_id", field_schema: "keyword" });

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
    expect(calls).toHaveLength(4); // GET 404, PUT create, PUT tenant_id index, PUT points
    expect(calls[0].headers?.["api-key"]).toBe("test-key");
    expect(calls[2].url).toBe(`https://qdrant-test.example.com/collections/${QDRANT_COLLECTION}/index`);
    const points = JSON.parse(calls[3].body ?? "{}") as {
      points: Array<{ id: number; vector: number[]; payload: Record<string, unknown> }>;
    };
    // R-15 Q1: point id is the D1 memory id as an UNSIGNED INTEGER —
    // the old "t-1:7" string id 400s live ("not a valid point ID").
    expect(points.points[0].id).toBe(7);
    expect(typeof points.points[0].id).toBe("number");
    expect(points.points[0].vector).toEqual([0.1, 0.2, 0.3]);
    expect(points.points[0].payload).toEqual({
      tenant_id: "t-1",
      memory_id: 7,
      kind: "fact",
      content: "cats are cute",
      created_at: 123,
    });
  });

  it("existing indexed collection -> upsert is GET + points only, integer id", async () => {
    const calls: { url: string; method?: string; body?: string }[] = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      calls.push({ url, method: init?.method, body: init?.body ? String(init.body) : undefined });
      if (url.endsWith(`/collections/${QDRANT_COLLECTION}`) && !init?.method) {
        return jsonResp({ result: { name: QDRANT_COLLECTION, payload_schema: { tenant_id: { data_type: "keyword" } } } });
      }
      return jsonResp({ result: { operation_id: 1, status: "completed" }, status: "ok" });
    }) as unknown as FetchFn;
    const res = await qdrantUpsert(ENV, "t-1", 42, [0.1, 0.2, 0.3], { content: "x" }, { fetchFn });
    expect(res).toEqual({ ok: true });
    expect(calls).toHaveLength(2);
    const points = JSON.parse(calls[1].body ?? "{}") as { points: Array<{ id: unknown }> };
    expect(points.points[0].id).toBe(42);
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
