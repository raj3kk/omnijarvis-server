/**
 * Observability tests (completeness #55 Langfuse + #56 Sentry).
 * All upstream calls are MOCKED fetch — no real key, no network.
 * Failure posture: senders never throw and never block.
 */
import { describe, expect, it, vi } from "vitest";
import {
  captureError,
  describeError,
  isLangfuseConfigured,
  isSentryConfigured,
  langfuseHost,
  parseSentryDsn,
  trace,
} from "../src/observability";

const LANGFUSE_ENV = {
  LANGFUSE_PUBLIC_KEY: "pk_test",
  LANGFUSE_SECRET_KEY: "sk_test",
  LANGFUSE_HOST: "https://cloud.langfuse.com",
};
const DSN = "https://pubkey123@sentry.example.com/42";
const SENTRY_ENV = { SENTRY_DSN: DSN };

function okJson(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("langfuseHost / isLangfuseConfigured", () => {
  it("defaults to cloud.langfuse.com; LANGFUSE_BASE_URL is accepted; trailing slash stripped", () => {
    expect(langfuseHost({})).toBe("https://cloud.langfuse.com");
    expect(langfuseHost({ LANGFUSE_BASE_URL: "https://self-host.example.com/" })).toBe(
      "https://self-host.example.com",
    );
    expect(langfuseHost({ LANGFUSE_HOST: "https://h.example.com", LANGFUSE_BASE_URL: "https://b.example.com" })).toBe(
      "https://h.example.com",
    );
    expect(isLangfuseConfigured(LANGFUSE_ENV)).toBe(true);
    expect(isLangfuseConfigured({ LANGFUSE_PUBLIC_KEY: "pk_test" })).toBe(false);
    expect(isLangfuseConfigured({})).toBe(false);
  });
});

describe("trace() — Langfuse ingestion", () => {
  it("env unset -> fetch never called (silent no-op)", async () => {
    const fetchFn = vi.fn(async () => okJson({}));
    await trace({}, "x", {}, { fetchFn: fetchFn as unknown as typeof fetch });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("posts a trace-create batch with Basic auth to /api/public/ingestion", async () => {
    const seen: { url: string; init: RequestInit }[] = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      seen.push({ url, init: init ?? {} });
      return okJson({ success: true });
    }) as unknown as typeof fetch;
    await trace(LANGFUSE_ENV, "memory_store", { tenant_id: "t-1", kind: "fact" }, { fetchFn });
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe("https://cloud.langfuse.com/api/public/ingestion");
    expect(seen[0].init.method).toBe("POST");
    const headers = seen[0].init.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Basic ${btoa("pk_test:sk_test")}`);
    const body = JSON.parse(String(seen[0].init.body)) as {
      batch: Array<{ type: string; body: { name: string; metadata: Record<string, unknown> } }>;
    };
    expect(body.batch).toHaveLength(1);
    expect(body.batch[0].type).toBe("trace-create");
    expect(body.batch[0].body.name).toBe("memory_store");
    expect(body.batch[0].body.metadata).toEqual({ tenant_id: "t-1", kind: "fact" });
  });

  it("non-ok status and network throw both resolve (never block the request path)", async () => {
    const errFetch = (async () => new Response("no", { status: 500 })) as unknown as typeof fetch;
    await expect(trace(LANGFUSE_ENV, "x", {}, { fetchFn: errFetch })).resolves.toBeUndefined();
    const throwFetch = (async () => {
      throw new Error("down");
    }) as unknown as typeof fetch;
    await expect(trace(LANGFUSE_ENV, "x", {}, { fetchFn: throwFetch })).resolves.toBeUndefined();
  });
});

describe("parseSentryDsn / isSentryConfigured", () => {
  it("parses host + project + public key; rejects malformed DSNs", () => {
    expect(parseSentryDsn(DSN)).toEqual({ publicKey: "pubkey123", host: "sentry.example.com", projectId: "42" });
    expect(parseSentryDsn("not-a-url")).toBeNull();
    expect(parseSentryDsn("https://sentry.example.com/42")).toBeNull(); // no public key
    expect(parseSentryDsn("https://key@sentry.example.com/")).toBeNull(); // no project
    expect(parseSentryDsn("https://key@sentry.example.com/a/b")).toBeNull(); // nested path
    expect(isSentryConfigured(SENTRY_ENV)).toBe(true);
    expect(isSentryConfigured({ SENTRY_DSN: "garbage" })).toBe(false);
    expect(isSentryConfigured({})).toBe(false);
  });

  it("describeError extracts type + value only", () => {
    expect(describeError(new TypeError("bad thing"))).toEqual({ type: "TypeError", value: "bad thing" });
    expect(describeError("plain string")).toEqual({ type: "Error", value: "plain string" });
    expect(describeError(42)).toEqual({ type: "Error", value: "unknown error" });
  });
});

describe("captureError() — Sentry envelope", () => {
  it("env unset / bad DSN -> fetch never called", async () => {
    const fetchFn = vi.fn(async () => okJson({}));
    await captureError({}, new Error("x"), {}, { fetchFn: fetchFn as unknown as typeof fetch });
    await captureError({ SENTRY_DSN: "garbage" }, new Error("x"), {}, { fetchFn: fetchFn as unknown as typeof fetch });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("posts a newline-delimited envelope with X-Sentry-Auth and the exception", async () => {
    const seen: { url: string; init: RequestInit }[] = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      seen.push({ url, init: init ?? {} });
      return okJson({ id: "abc" });
    }) as unknown as typeof fetch;
    await captureError(SENTRY_ENV, new TypeError("kaboom"), { tenant_id: "t-1", route: "memory_store" }, { fetchFn });
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe("https://sentry.example.com/api/42/envelope/");
    expect(seen[0].init.method).toBe("POST");
    const headers = seen[0].init.headers as Record<string, string>;
    expect(headers["X-Sentry-Auth"]).toContain("sentry_key=pubkey123");
    expect(headers["X-Sentry-Auth"]).toContain("sentry_version=7");
    const lines = String(seen[0].init.body).split("\n");
    expect(lines).toHaveLength(3);
    const event = JSON.parse(lines[2]) as {
      level: string;
      exception: { values: Array<{ type: string; value: string }> };
      tags: Record<string, string>;
    };
    expect(event.level).toBe("error");
    expect(event.exception.values[0]).toEqual({ type: "TypeError", value: "kaboom" });
    expect(event.tags).toEqual({ tenant_id: "t-1", route: "memory_store" });
  });

  it("non-ok status and network throw both resolve", async () => {
    const errFetch = (async () => new Response("no", { status: 500 })) as unknown as typeof fetch;
    await expect(captureError(SENTRY_ENV, new Error("x"), {}, { fetchFn: errFetch })).resolves.toBeUndefined();
    const throwFetch = (async () => {
      throw new Error("down");
    }) as unknown as typeof fetch;
    await expect(captureError(SENTRY_ENV, new Error("x"), {}, { fetchFn: throwFetch })).resolves.toBeUndefined();
  });
});
