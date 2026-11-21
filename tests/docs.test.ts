/**
 * Docs tests (Phase 3, stage 3b) — D-T1–D-T8 + signed-device auth (D-T9)
 * + docs rate-limit budget unit test.
 *
 * D-T1 ingest caps (5MB) + happy path (mocked Render) · D-T2 OCR accuracy
 * synthetic (manifest structure + no Aadhaar/PAN in fixtures; the numeric
 * gate >= 0.85 runs in CI via render/worker/accuracy_check.py) ·
 * D-T3 structured extraction JSON schema + confidence · D-T4 confirm flow
 * (missing fields ek card me) · D-T5 certificate PDF + QR hash verify ·
 * D-T6 Free tier block · D-T7 PII redaction (consent off) + wipe-shape ·
 * D-T8 Render URL unset -> honest render_not_configured.
 * Render + Gemini upstreams are MOCKED (no real key in CI). Live happy-path
 * proof needs the Render deploy (parent-side, U-2) + test BYOK key (U-1).
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FakeD1 } from "./fake-d1";
import { genDeviceKey } from "./helpers";
import { handleRequest, type Env } from "../src/hub";
import { canonicalString } from "../src/crypto";
import { bytesToBase64 } from "../src/crypto";
import { canonicalPayload, isPiiField, redactPiiText, sha256Hex, sortedJson, REDACTED } from "../src/docs";
import { RATE_LIMITS } from "../src/ratelimit";
import { encryptTenantKey, importMasterKey } from "../src/keyvault";

const FIXED_NOW = Date.UTC(2026, 10, 21, 12, 0, 0);
const RENDER_URL = "https://render-test.example.com";

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
    RENDER_WORKER_URL: RENDER_URL,
    ...overrides,
  };
}

async function makeMasterKeyB64(): Promise<string> {
  const k = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
  return bytesToBase64(raw);
}

async function seedTenant(
  db: FakeD1,
  opts: { id: string; plan?: string; keyEnc?: string | null; piiConsent?: number },
): Promise<void> {
  await db
    .prepare("INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(opts.id, `${opts.id}@example.com`, opts.plan ?? "pro", "byok", opts.keyEnc ?? null, opts.piiConsent ?? 0, FIXED_NOW)
    .run();
}

async function seedTenantWithKey(db: FakeD1, id: string, masterB64: string, plan = "pro", piiConsent = 0): Promise<void> {
  const master = await importMasterKey(masterB64);
  const enc = await encryptTenantKey(master, "TEST-GEMINI-KEY-1");
  await seedTenant(db, { id, plan, keyEnc: enc, piiConsent });
}

async function seedDevice(db: FakeD1, deviceId: string, tenantId: string, publicKeyB64: string): Promise<void> {
  await db
    .prepare("INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(deviceId, tenantId, publicKeyB64, FIXED_NOW, FIXED_NOW, 1)
    .run();
}

async function seedDocJob(db: FakeD1, tenantId: string, status = "ingested"): Promise<number> {
  await db
    .prepare("INSERT INTO doc_jobs (tenant_id, device_id, kind, status, source_name, result_json, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(tenantId, "dev-1", "extract", status, "test.pdf", JSON.stringify({ text: "Invoice No: INV-2026-0142" }), 95, FIXED_NOW)
    .run();
  const row = await db
    .prepare("SELECT id FROM doc_jobs WHERE tenant_id = ? AND created_at = ?")
    .bind(tenantId, FIXED_NOW)
    .first<{ id: number }>();
  return row!.id;
}

/** Mock fetch dispatcher: Render worker URLs + Gemini upstream. */
function stubUpstreams(): void {
  vi.stubGlobal(
    "fetch",
    async (url: unknown, init?: { body?: unknown }) => {
      const u = String(url);
      if (u.startsWith(RENDER_URL)) {
        if (u.endsWith("/doc/extract")) {
          return new Response(JSON.stringify({ ok: true, pages: 1, text: "Invoice No: INV-2026-0142\nName: Arjun Mehta", tables: [{ page: 1, tables: [] }] }), { status: 200 });
        }
        if (u.endsWith("/doc/ocr")) {
          return new Response(JSON.stringify({ ok: true, pages: 1, text: "INVOICE Total 1250", confidence: 92.5, per_page: [{ page: 1, confidence: 92.5, source: "tesseract" }] }), { status: 200 });
        }
        if (u.endsWith("/doc/certificate")) {
          const params = new URLSearchParams(String(init?.body ?? ""));
          const payload = params.get("payload") ?? "{}";
          const hash = createHash("sha256").update(payload).digest("hex");
          return new Response(JSON.stringify({ ok: true, hash, pdf_base64: Buffer.from("%PDF-1.4 fake").toString("base64"), pages: 1, bytes: 13 }), { status: 200 });
        }
        return new Response(JSON.stringify({ ok: false, error: "not_found" }), { status: 404 });
      }
      if (u.includes("generativelanguage.googleapis.com")) {
        return new Response(
          JSON.stringify({
            candidates: [{ content: { parts: [{ text: JSON.stringify({ fields: { name: "Arjun Mehta", amount: "1250", pan_number: "ABCDE1234F" }, confidence: 0.9 }) }] }, finishReason: "STOP" }],
            usageMetadata: { promptTokenCount: 100, candidatesTokenCount: 20 },
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({ error: "unexpected fetch " + u }), { status: 500 });
    },
  );
}

function samplePdfBytes(): Uint8Array {
  return new TextEncoder().encode("%PDF-1.4\n%fake pdf for tests\n");
}

async function ingestPdf(env: Env, tenantId = "t-1"): Promise<Response> {
  const form = new FormData();
  form.append("tenant_id", tenantId);
  form.append("file", new File([samplePdfBytes()], "invoice.pdf", { type: "application/pdf" }));
  return handleRequest(
    new Request("https://hub/api/docs/ingest", {
      method: "POST",
      headers: { "x-internal-secret": "test-internal" },
      body: form,
    }),
    env,
  );
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("docs rate-limit budget", () => {
  it("docs budget is 30/min/tenant (3b §2b)", () => {
    expect(RATE_LIMITS.docs).toEqual({ limit: 30, windowMs: 60_000 });
  });
});

describe("D-T1 ingest caps + happy path", () => {
  it("oversize file (>5MB) -> 413 file_too_large, Render never called", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    stubUpstreams();
    const form = new FormData();
    form.append("tenant_id", "t-1");
    form.append("file", new File([new Uint8Array(5 * 1024 * 1024 + 1)], "big.pdf", { type: "application/pdf" }));
    const res = await handleRequest(
      new Request("https://hub/api/docs/ingest", {
        method: "POST",
        headers: { "x-internal-secret": "test-internal" },
        body: form,
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(413);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("file_too_large");
  });

  it("PDF ingest -> mocked Render extract -> 200 + doc_jobs row", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    stubUpstreams();
    const res = await ingestPdf(fakeEnv(db));
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(body.kind).toBe("extract");
    expect(typeof body.doc_job_id).toBe("number");
    expect(String(body.text)).toContain("INV-2026-0142");
    const row = await db
      .prepare("SELECT status, result_json FROM doc_jobs WHERE id = ?")
      .bind(body.doc_job_id as number)
      .first<{ status: string; result_json: string }>();
    expect(row?.status).toBe("ingested");
    expect(row?.result_json).toContain("INV-2026-0142");
  });

  it("ingest without auth -> 401", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const form = new FormData();
    form.append("tenant_id", "t-1");
    form.append("file", new File([samplePdfBytes()], "invoice.pdf", { type: "application/pdf" }));
    const res = await handleRequest(
      new Request("https://hub/api/docs/ingest", { method: "POST", body: form }),
      fakeEnv(db),
    );
    expect(res.status).toBe(401);
  });
});

describe("D-T9 signed device auth (sync-style Ed25519)", () => {
  it("paired device + valid signature over file sha256 -> 200", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    stubUpstreams();
    const bytes = samplePdfBytes();
    const fileHash = createHash("sha256").update(bytes).digest("hex");
    const nonce = "aabbccddeeff00112233445566778899";
    const ts = Date.now();
    const sig = await key.sign(canonicalString("dev-1", nonce, ts, fileHash));
    const form = new FormData();
    form.append("device_id", "dev-1");
    form.append("file", new File([bytes], "invoice.pdf", { type: "application/pdf" }));
    const res = await handleRequest(
      new Request("https://hub/api/docs/ingest", {
        method: "POST",
        headers: { "x-device-id": "dev-1", "x-nonce": nonce, "x-ts": String(ts), "x-signature": sig },
        body: form,
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>).ok).toBe(true);
  });

  it("bad signature -> 401, unpaired device -> 403", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const key = await genDeviceKey();
    await seedDevice(db, "dev-1", "t-1", key.publicKeyB64);
    const bytes = samplePdfBytes();
    const fileHash = createHash("sha256").update(bytes).digest("hex");
    const nonce = "aabbccddeeff00112233445566778899";
    const ts = Date.now();
    const badSig = await key.sign(canonicalString("dev-1", nonce, ts, "deadbeef"));
    const form = new FormData();
    form.append("device_id", "dev-1");
    form.append("file", new File([bytes], "invoice.pdf", { type: "application/pdf" }));
    const bad = await handleRequest(
      new Request("https://hub/api/docs/ingest", {
        method: "POST",
        headers: { "x-device-id": "dev-1", "x-nonce": nonce, "x-ts": String(ts), "x-signature": badSig },
        body: form,
      }),
      fakeEnv(db),
    );
    expect(bad.status).toBe(401);
    const ghost = await handleRequest(
      new Request("https://hub/api/docs/ingest", {
        method: "POST",
        headers: { "x-device-id": "dev-ghost", "x-nonce": nonce, "x-ts": String(ts), "x-signature": badSig },
        body: form,
      }),
      fakeEnv(db),
    );
    expect(ghost.status).toBe(403);
    expect(((await ghost.json()) as Record<string, unknown>).error).toBe("device_not_paired");
  });
});

describe("D-T2 OCR accuracy fixtures (structure; number gate is CI accuracy_check.py)", () => {
  it("manifest: 10 docs, >=3 fields each, no Aadhaar/PAN-shaped values", () => {
    const manifest = JSON.parse(
      readFileSync(new URL("../render/worker/fixtures/manifest.json", import.meta.url), "utf8"),
    ) as { docs: { id: string; kind: string; png: string; pdf: string; fields: { key: string; value: string }[] }[] };
    expect(manifest.docs).toHaveLength(10);
    for (const doc of manifest.docs) {
      expect(doc.fields.length).toBeGreaterThanOrEqual(3);
      for (const f of doc.fields) {
        expect(f.value).not.toMatch(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/);
        expect(f.value).not.toMatch(/\b[A-Z]{5}[0-9]{4}[A-Z]\b/);
      }
      expect(() => readFileSync(new URL(`../render/worker/fixtures/${doc.png}`, import.meta.url))).not.toThrow();
      expect(() => readFileSync(new URL(`../render/worker/fixtures/${doc.pdf}`, import.meta.url))).not.toThrow();
    }
  });

  it("accuracy gate threshold is 0.85 in accuracy_check.py", () => {
    const src = readFileSync(new URL("../render/worker/accuracy_check.py", import.meta.url), "utf8");
    expect(src).toContain("THRESHOLD = 0.85");
  });
});

describe("D-T3 structured extraction (router doc_extraction kind)", () => {
  it("text + schema -> fields + missing[] + confidence", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master);
    stubUpstreams();
    const body = {
      tenant_id: "t-1",
      turn_id: "turn-doc-1",
      text: "Invoice No: INV-2026-0142 Name: Arjun Mehta Amount: 1250",
      schema: { properties: { name: { type: "string" }, amount: { type: "string" }, gstin: { type: "string" } } },
    };
    const res = await handleRequest(
      new Request("https://hub/api/docs/extract", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify(body),
      }),
      fakeEnv(db, { KEY_ENC_SECRET: master }),
    );
    expect(res.status).toBe(200);
    const out = (await res.json()) as Record<string, unknown>;
    expect(out.ok).toBe(true);
    expect((out.fields as Record<string, unknown>).name).toBe("Arjun Mehta");
    expect(out.missing).toContain("gstin");
    expect(typeof out.confidence).toBe("number");
  });

  it("no text and no doc_job -> 400 text_required", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const res = await handleRequest(
      new Request("https://hub/api/docs/extract", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", turn_id: "turn-doc-2", schema: { properties: {} } }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("text_required");
  });
});

describe("D-T4 confirm flow (one-shot, missing fields ek card me)", () => {
  it("missing required field -> missing_fields + merged fields (no piecemeal)", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const jobId = await seedDocJob(db, "t-1");
    const res = await handleRequest(
      new Request("https://hub/api/docs/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", doc_job_id: jobId, fields: { name: "Arjun Mehta" }, required: ["name", "amount"] }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const out = (await res.json()) as Record<string, unknown>;
    expect(out.ok).toBe(false);
    expect(out.error).toBe("missing_fields");
    expect(out.missing).toEqual(["amount"]);
    expect((out.fields as Record<string, unknown>).name).toBe("Arjun Mehta");
    const row = await db.prepare("SELECT status FROM doc_jobs WHERE id = ?").bind(jobId).first<{ status: string }>();
    expect(row?.status).toBe("ingested"); // not confirmed yet
  });

  it("complete fields + corrections -> confirmed in D1", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const jobId = await seedDocJob(db, "t-1");
    const res = await handleRequest(
      new Request("https://hub/api/docs/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", doc_job_id: jobId, fields: { name: "Arjun Mehta", amount: "1250" }, corrections: { amount: "1251" } }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const out = (await res.json()) as Record<string, unknown>;
    expect(out.ok).toBe(true);
    expect(out.status).toBe("confirmed");
    expect((out.fields as Record<string, unknown>).amount).toBe("1251");
    const row = await db.prepare("SELECT status FROM doc_jobs WHERE id = ?").bind(jobId).first<{ status: string }>();
    expect(row?.status).toBe("confirmed");
  });

  it("unknown doc_job -> 404", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const res = await handleRequest(
      new Request("https://hub/api/docs/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", doc_job_id: 999, fields: { name: "x" } }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(404);
  });
});

describe("D-T5 certificate PDF + QR hash verify", () => {
  it("confirmed job -> certificate row + verify/:hash valid, unknown hash 404", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const jobId = await seedDocJob(db, "t-1", "confirmed");
    stubUpstreams();
    const html = "<html><body><h1>Certificate</h1>{{QR}}</body></html>";
    const payload = { name: "Arjun Mehta", course: "Python Basics" };
    const res = await handleRequest(
      new Request("https://hub/api/docs/certificate", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", doc_job_id: jobId, html, payload }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(200);
    const out = (await res.json()) as Record<string, unknown>;
    expect(out.ok).toBe(true);
    const expectHash = await sha256Hex(canonicalPayload(payload));
    expect(out.hash).toBe(expectHash);
    expect(typeof out.pdf_base64).toBe("string");
    expect(String(out.verify_url)).toContain(expectHash);
    const cert = await db
      .prepare("SELECT payload_hash FROM certificates WHERE payload_hash = ?")
      .bind(expectHash)
      .first<{ payload_hash: string }>();
    expect(cert?.payload_hash).toBe(expectHash);
    const verify = await handleRequest(new Request(`https://hub/api/docs/verify/${expectHash}`), fakeEnv(db));
    expect(verify.status).toBe(200);
    const vBody = (await verify.json()) as Record<string, unknown>;
    expect(vBody.valid).toBe(true);
    expect(vBody).not.toHaveProperty("tenant_id"); // no PII in verify response
    const missing = await handleRequest(
      new Request(`https://hub/api/docs/verify/${"0".repeat(64)}`),
      fakeEnv(db),
    );
    expect(missing.status).toBe(404);
    expect(((await missing.json()) as Record<string, unknown>).valid).toBe(false);
  });

  it("unconfirmed job -> 409 doc_not_confirmed", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const jobId = await seedDocJob(db, "t-1", "ingested");
    const res = await handleRequest(
      new Request("https://hub/api/docs/certificate", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", doc_job_id: jobId, html: "<p>x</p>", payload: { a: 1 } }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(409);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("doc_not_confirmed");
  });
});

describe("D-T6 Free tier block", () => {
  it("free tenant ingest -> 403 plan_docs_not_allowed", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-free", plan: "free" });
    stubUpstreams();
    const res = await ingestPdf(fakeEnv(db), "t-free");
    expect(res.status).toBe(403);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("plan_docs_not_allowed");
  });

  it("free tenant extract -> 403 plan_docs_not_allowed (double-check)", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-free", plan: "free" });
    const res = await handleRequest(
      new Request("https://hub/api/docs/extract", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-free", turn_id: "t", text: "hello", schema: { properties: {} } }),
      }),
      fakeEnv(db),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("plan_docs_not_allowed");
  });
});

describe("D-T7 PII redaction (consent off) + wipe shape", () => {
  it("consent off: PAN field redacted in response AND stored result_json", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master, "pro", 0);
    stubUpstreams();
    const jobId = await seedDocJob(db, "t-1");
    const res = await handleRequest(
      new Request("https://hub/api/docs/extract", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", turn_id: "turn-pii", doc_job_id: jobId, schema: { properties: { name: {}, amount: {}, pan_number: {} } } }),
      }),
      fakeEnv(db, { KEY_ENC_SECRET: master }),
    );
    expect(res.status).toBe(200);
    const out = (await res.json()) as Record<string, unknown>;
    expect((out.fields as Record<string, unknown>).pan_number).toBe(REDACTED);
    expect((out.fields as Record<string, unknown>).name).toBe("Arjun Mehta");
    const row = await db.prepare("SELECT result_json FROM doc_jobs WHERE id = ?").bind(jobId).first<{ result_json: string }>();
    expect(row?.result_json).toContain(REDACTED);
    expect(row?.result_json).not.toContain("ABCDE1234F");
  });

  it("consent on: PAN field preserved", async () => {
    const db = new FakeD1();
    const master = await makeMasterKeyB64();
    await seedTenantWithKey(db, "t-1", master, "pro", 1);
    stubUpstreams();
    const res = await handleRequest(
      new Request("https://hub/api/docs/extract", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", turn_id: "turn-pii2", text: "Name: Arjun Mehta", schema: { properties: { name: {}, pan_number: {} } } }),
      }),
      fakeEnv(db, { KEY_ENC_SECRET: master }),
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>).fields).toMatchObject({ pan_number: "ABCDE1234F" });
  });

  it("redactPiiText: Aadhaar/PAN patterns in free text -> [REDACTED]; 'company' is NOT PII", () => {
    expect(redactPiiText("Aadhaar 1234 5678 9012 and PAN ABCDE1234F here", false)).toBe(
      "Aadhaar [REDACTED] and PAN [REDACTED] here",
    );
    expect(redactPiiText("Aadhaar 1234 5678 9012", true)).toContain("1234");
    expect(isPiiField("company")).toBe(false); // substring trap: 'pan' inside 'company'
    expect(isPiiField("pan_number")).toBe(true);
    expect(isPiiField("aadhaar_number")).toBe(true);
    expect(sortedJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });
});

describe("D-T8 Render URL unset -> honest render_not_configured", () => {
  it("ingest with no RENDER_WORKER_URL -> 503 render_not_configured", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const res = await ingestPdf(fakeEnv(db, { RENDER_WORKER_URL: undefined }));
    expect(res.status).toBe(503);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("render_not_configured");
  });

  it("certificate with no RENDER_WORKER_URL -> 503 render_not_configured", async () => {
    const db = new FakeD1();
    await seedTenant(db, { id: "t-1" });
    const jobId = await seedDocJob(db, "t-1", "confirmed");
    const res = await handleRequest(
      new Request("https://hub/api/docs/certificate", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-secret": "test-internal" },
        body: JSON.stringify({ tenant_id: "t-1", doc_job_id: jobId, html: "<p>x</p>", payload: { a: 1 } }),
      }),
      fakeEnv(db, { RENDER_WORKER_URL: undefined }),
    );
    expect(res.status).toBe(503);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("render_not_configured");
  });
});
