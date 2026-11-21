import { describe, expect, it } from "vitest";
import { handleRequest, type Env } from "../src/hub";
import { FakeD1 } from "./fake-d1";
import { registerDevice } from "../src/pairing";
import { genDeviceKey } from "./helpers";
import {
  BANNED_AUTO_SOLVE_TYPES,
  CAPTCHA_ASSIST_TIMEOUT_MS,
  DEFAULT_BROWSER_PROVIDER,
  MAX_CAPTCHA_ASSISTS_PER_TASK,
  MAX_SCREENSHOT_B64_LENGTH,
  TURNSTILE_ALLOWLIST,
  buildCaptchaAssistEvent,
  captchaAssistTrace,
  createBrowserTask,
  detectCaptcha,
  ensureBrowserTask,
  executeBrowserTask,
  getBrowserTask,
  isAutoSolveBanned,
  isScreenshotSizeOk,
  isTurnstileAutoSolveAllowed,
  requestCaptchaAssist,
  resolveCaptcha,
  resolveCaptchaAssist,
  resolveBrowserProvider,
} from "../src/browser";

function fakeEnv(db: FakeD1, overrides: Partial<Env> = {}): Env {
  return {
    JARVIS_HUB: {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        fetch: async () => new Response(JSON.stringify({ ok: true, sent: true }), { status: 200 }),
      }),
    } as unknown as DurableObjectNamespace,
    DB: db as unknown as D1Database,
    INTERNAL_SECRET: "test-internal",
    CRON_SECRET: "test-cron",
    ...overrides,
  };
}

async function seedDevice(db: FakeD1, deviceId = "dev-1", tenantId = "t-1") {
  const key = await genDeviceKey();
  await registerDevice(db, deviceId, tenantId, key.publicKeyB64);
}

async function browserPost(
  env: Env,
  path: string,
  body: Record<string, unknown>,
  secret = "test-internal",
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await handleRequest(
    new Request(`https://hub${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-internal-secret": secret },
      body: JSON.stringify(body),
    }),
    env,
  );
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe("browser provider resolution (hosting proof FAIL — Render NOT viable)", () => {
  it("default provider is PhoneWebView", () => {
    expect(DEFAULT_BROWSER_PROVIDER).toBe("phone_webview");
    expect(resolveBrowserProvider()).toEqual({ ok: true, provider: "phone_webview" });
    expect(resolveBrowserProvider("phone_webview")).toEqual({ ok: true, provider: "phone_webview" });
    expect(resolveBrowserProvider(null)).toEqual({ ok: true, provider: "phone_webview" });
  });

  it("Render refuses (409.4 MB probe > 350 MB threshold)", () => {
    const res = resolveBrowserProvider("render");
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe("render_browser_unavailable");
      expect(res.reason).toContain("409.4");
    }
  });

  it("E2B refuses until an account exists (U-4)", () => {
    const res = resolveBrowserProvider("e2b");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("e2b_not_configured");
  });

  it("unknown provider is an honest error, never a silent fallback", () => {
    const res = resolveBrowserProvider("playwright-cloud");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("unknown_provider");
  });
});

describe("captcha detection (recognise only — never solve)", () => {
  it("detects Turnstile / reCAPTCHA / hCaptcha iframes", () => {
    expect(detectCaptcha('<iframe src="https://challenges.cloudflare.com/turnstile/v0/api.js">')).toEqual({
      detected: true,
      type: "turnstile",
    });
    expect(detectCaptcha('<div class="g-recaptcha" data-sitekey="x">')).toEqual({
      detected: true,
      type: "recaptcha",
    });
    expect(detectCaptcha('<iframe src="https://hcaptcha.com/1/api.js">')).toEqual({
      detected: true,
      type: "hcaptcha",
    });
  });

  it("data-sitekey alone -> detected, type unknown (never guessed)", () => {
    expect(detectCaptcha('<div data-sitekey="abc">')).toEqual({ detected: true, type: "unknown" });
  });

  it("clean page -> not detected", () => {
    expect(detectCaptcha("<html><body><h1>Hello</h1></body></html>")).toEqual({
      detected: false,
      type: "unknown",
    });
  });

  it("every challenge type resolves to human-assist (C-T7: no auto-solve path)", () => {
    for (const type of ["turnstile", "recaptcha", "hcaptcha", "unknown"] as const) {
      expect(resolveCaptcha(type, "example.com").action).toBe("human_assist");
    }
    // Turnstile on an allowlisted-looking site still human-assists:
    // the allowlist is empty and no solver is installed (D3 gated).
    expect(resolveCaptcha("turnstile", "flow99.in").action).toBe("human_assist");
  });

  it("Turnstile allowlist is empty — auto-solve is impossible (C-T6)", () => {
    expect(TURNSTILE_ALLOWLIST.length).toBe(0);
    expect(isTurnstileAutoSolveAllowed("flow99.in")).toBe(false);
    expect(isTurnstileAutoSolveAllowed(null)).toBe(false);
  });

  it("banned types are banned (D3 §5 hard ban)", () => {
    expect(BANNED_AUTO_SOLVE_TYPES).toEqual(
      expect.arrayContaining(["recaptcha_v2", "recaptcha_v3", "hcaptcha", "image_grid", "audio", "distorted_text"]),
    );
    for (const t of BANNED_AUTO_SOLVE_TYPES) expect(isAutoSolveBanned(t)).toBe(true);
  });

  it("countdown is 60s — timeout is a pause window, not a fail", () => {
    expect(CAPTCHA_ASSIST_TIMEOUT_MS).toBe(60_000);
  });
});

describe("browser task lifecycle (D1 browser_tasks, migration 0005)", () => {
  it("executeBrowserTask creates a running PhoneWebView task", async () => {
    const db = new FakeD1();
    const res = await executeBrowserTask(db, {
      tenant_id: "t-1",
      device_id: "dev-1",
      task_name: "Open example",
      url: "https://example.com",
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.provider).toBe("phone_webview");
    expect(res.status).toBe("running");
    expect(res.execution).toBe("device");
    const row = await getBrowserTask(db, res.task_id);
    expect(row?.status).toBe("running");
    expect(row?.assist_count).toBe(0);
  });

  it("executeBrowserTask with provider=render refuses (no row created)", async () => {
    const db = new FakeD1();
    const res = await executeBrowserTask(db, {
      tenant_id: "t-1",
      device_id: "dev-1",
      task_name: "Open example",
      provider: "render",
    });
    expect(res.ok).toBe(false);
    const rows = await db.prepare("SELECT * FROM browser_tasks").bind().all();
    expect(rows.results.length).toBe(0);
  });

  it("ensureBrowserTask: device-reported id creates once, returns existing on repeat", async () => {
    const db = new FakeD1();
    const first = await ensureBrowserTask(db, {
      id: "bt-device-1",
      tenant_id: "t-1",
      device_id: "dev-1",
      task_name: "Device task",
      site: "example.com",
    });
    const second = await ensureBrowserTask(db, {
      id: "bt-device-1",
      tenant_id: "t-1",
      device_id: "dev-1",
      task_name: "Device task",
      site: "example.com",
    });
    expect(first.id).toBe("bt-device-1");
    expect(second.id).toBe("bt-device-1");
    const rows = await db.prepare("SELECT * FROM browser_tasks").bind().all();
    expect(rows.results.length).toBe(1);
  });

  it("requestCaptchaAssist x3 -> awaiting_user; 4th -> assist_cap_reached + paused (C-T5)", async () => {
    const db = new FakeD1();
    const task = await createBrowserTask(db, { tenant_id: "t-1", device_id: "dev-1", task_name: "T" });
    for (const n of [1, 2, 3]) {
      const res = await requestCaptchaAssist(db, task.id);
      expect(res).toEqual({ ok: true, assist_count: n, status: "awaiting_user" });
      expect((await getBrowserTask(db, task.id))?.status).toBe("awaiting_user");
    }
    const fourth = await requestCaptchaAssist(db, task.id);
    expect(fourth).toEqual({ ok: false, error: "assist_cap_reached", assist_count: 3, status: "paused" });
    const row = await getBrowserTask(db, task.id);
    expect(row?.status).toBe("paused");
    expect(row?.assist_count).toBe(3);
  });

  it("requestCaptchaAssist on unknown task -> task_not_found; on aborted task -> task_closed", async () => {
    const db = new FakeD1();
    expect(await requestCaptchaAssist(db, "bt-nope")).toEqual({ ok: false, error: "task_not_found" });
    const task = await createBrowserTask(db, { tenant_id: "t-1", device_id: "dev-1", task_name: "T" });
    await resolveCaptchaAssist(db, task.id, "aborted");
    expect(await requestCaptchaAssist(db, task.id)).toEqual({ ok: false, error: "task_closed", status: "aborted" });
  });

  it("resolve: solved -> running, timeout -> paused (C-T2: pause not fail), aborted -> aborted", async () => {
    const db = new FakeD1();
    const t1 = await createBrowserTask(db, { tenant_id: "t-1", device_id: "dev-1", task_name: "T1" });
    await requestCaptchaAssist(db, t1.id);
    expect(await resolveCaptchaAssist(db, t1.id, "solved")).toEqual({ ok: true, status: "running" });
    const t2 = await createBrowserTask(db, { tenant_id: "t-1", device_id: "dev-1", task_name: "T2" });
    await requestCaptchaAssist(db, t2.id);
    expect(await resolveCaptchaAssist(db, t2.id, "timeout")).toEqual({ ok: true, status: "paused" });
    const t3 = await createBrowserTask(db, { tenant_id: "t-1", device_id: "dev-1", task_name: "T3" });
    await requestCaptchaAssist(db, t3.id);
    expect(await resolveCaptchaAssist(db, t3.id, "aborted")).toEqual({ ok: true, status: "aborted" });
    expect(await resolveCaptchaAssist(db, "bt-nope", "solved")).toEqual({ ok: false, error: "task_not_found" });
  });

  it("assist cap constant is 3 (D3 §3.2)", () => {
    expect(MAX_CAPTCHA_ASSISTS_PER_TASK).toBe(3);
  });
});

describe("CAPTCHA_ASSIST event + screenshot cap", () => {
  it("event carries type/task_id/site/task_name (+ small screenshot)", async () => {
    const db = new FakeD1();
    const task = await createBrowserTask(db, {
      tenant_id: "t-1",
      device_id: "dev-1",
      task_name: "Fill form",
      site: "example.com",
    });
    const { event, screenshotDropped } = buildCaptchaAssistEvent(task, "aGVsbG8=");
    expect(event).toEqual({
      type: "CAPTCHA_ASSIST",
      task_id: task.id,
      site: "example.com",
      task_name: "Fill form",
      screenshot_b64: "aGVsbG8=",
    });
    expect(screenshotDropped).toBe(false);
  });

  it("oversized screenshot is DROPPED, never sent raw (GAP-4)", async () => {
    const db = new FakeD1();
    const task = await createBrowserTask(db, { tenant_id: "t-1", device_id: "dev-1", task_name: "T" });
    expect(isScreenshotSizeOk("x".repeat(MAX_SCREENSHOT_B64_LENGTH))).toBe(true);
    expect(isScreenshotSizeOk("x".repeat(MAX_SCREENSHOT_B64_LENGTH + 1))).toBe(false);
    const { event, screenshotDropped } = buildCaptchaAssistEvent(task, "x".repeat(300_000));
    expect(event.screenshot_b64).toBeUndefined();
    expect(screenshotDropped).toBe(true);
    expect(isScreenshotSizeOk(null)).toBe(true);
  });

  it("trace detail never carries a solution/token/screenshot (C-T3/C-T8)", () => {
    const detail = captchaAssistTrace("bt-1", "example.com", { solved: true, duration_s: 42 });
    expect(detail).toEqual({ task_id: "bt-1", site: "example.com", solved: true, duration_s: 42 });
    const text = JSON.stringify(detail);
    expect(text).not.toContain("solution");
    expect(text).not.toContain("token");
    expect(text).not.toContain("screenshot");
    const requested = captchaAssistTrace("bt-1", null, { outcome: "requested", assist_count: 1 });
    expect(requested).toEqual({ task_id: "bt-1", site: null, outcome: "requested", assist_count: 1 });
  });
});

describe("hub routes /api/browser/* (internal-secret gated)", () => {
  it("task: no secret -> 401", async () => {
    const db = new FakeD1();
    const { status, body } = await browserPost(fakeEnv(db), "/api/browser/task", {
      tenant_id: "t-b1",
      device_id: "dev-1",
      task_name: "T",
    }, "wrong");
    expect(status).toBe(401);
    expect(body.error).toBe("unauthorized");
  });

  it("task: unpaired device -> 403 device_not_paired", async () => {
    const db = new FakeD1();
    const { status, body } = await browserPost(fakeEnv(db), "/api/browser/task", {
      tenant_id: "t-b2",
      device_id: "dev-1",
      task_name: "T",
    });
    expect(status).toBe(403);
    expect(body.error).toBe("device_not_paired");
  });

  it("task: provider render/e2b -> 503 honest error", async () => {
    const db = new FakeD1();
    await seedDevice(db, "dev-1", "t-b3");
    for (const provider of ["render", "e2b"]) {
      const { status, body } = await browserPost(fakeEnv(db), "/api/browser/task", {
        tenant_id: "t-b3",
        device_id: "dev-1",
        task_name: "T",
        provider,
      });
      expect(status).toBe(503);
      expect(body.error).toBe(provider === "render" ? "render_browser_unavailable" : "e2b_not_configured");
    }
  });

  it("task: default -> 200 running PhoneWebView task", async () => {
    const db = new FakeD1();
    await seedDevice(db, "dev-1", "t-b4");
    const { status, body } = await browserPost(fakeEnv(db), "/api/browser/task", {
      tenant_id: "t-b4",
      device_id: "dev-1",
      task_name: "Open example",
      site: "example.com",
      url: "https://example.com",
    });
    expect(status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.provider).toBe("phone_webview");
    expect(body.status).toBe("running");
    expect(typeof body.task_id).toBe("string");
    const row = await getBrowserTask(db, String(body.task_id));
    expect(row?.task_name).toBe("Open example");
  });

  it("assist: unknown task -> 404; happy path -> awaiting_user + delivered", async () => {
    const db = new FakeD1();
    await seedDevice(db, "dev-1", "t-b5");
    const env = fakeEnv(db);
    const missing = await browserPost(env, "/api/browser/assist", { task_id: "bt-nope" });
    expect(missing.status).toBe(404);
    expect(missing.body.error).toBe("task_not_found");
    const created = await browserPost(env, "/api/browser/task", {
      tenant_id: "t-b5",
      device_id: "dev-1",
      task_name: "Fill form",
      site: "example.com",
    });
    const taskId = String(created.body.task_id);
    const first = await browserPost(env, "/api/browser/assist", { task_id: taskId });
    expect(first.status).toBe(200);
    expect(first.body).toMatchObject({ ok: true, assist_count: 1, status: "awaiting_user", delivered: true });
    const traces = await db.prepare("SELECT * FROM traces").bind().all();
    const assist = traces.results.filter((t) => (t as Record<string, unknown>).kind === "captcha_assist");
    expect(assist.length).toBe(1);
    expect(JSON.parse(String((assist[0] as Record<string, unknown>).detail))).toMatchObject({
      task_id: taskId,
      outcome: "requested",
      assist_count: 1,
    });
  });

  it("assist: 4th request -> assist_cap_reached + paused, no event (C-T5)", async () => {
    const db = new FakeD1();
    await seedDevice(db, "dev-1", "t-b6");
    const env = fakeEnv(db);
    const created = await browserPost(env, "/api/browser/task", {
      tenant_id: "t-b6",
      device_id: "dev-1",
      task_name: "T",
    });
    const taskId = String(created.body.task_id);
    for (let i = 0; i < 3; i++) {
      const r = await browserPost(env, "/api/browser/assist", { task_id: taskId });
      expect(r.body.ok).toBe(true);
    }
    const fourth = await browserPost(env, "/api/browser/assist", { task_id: taskId });
    expect(fourth.body).toMatchObject({ ok: false, error: "assist_cap_reached", status: "paused" });
    expect((await getBrowserTask(db, taskId))?.status).toBe("paused");
  });

  it("resolve: solved -> running; timeout -> paused; no secret -> 401", async () => {
    const db = new FakeD1();
    await seedDevice(db, "dev-1", "t-b7");
    const env = fakeEnv(db);
    const created = await browserPost(env, "/api/browser/task", {
      tenant_id: "t-b7",
      device_id: "dev-1",
      task_name: "T",
    });
    const taskId = String(created.body.task_id);
    await browserPost(env, "/api/browser/assist", { task_id: taskId });
    const solved = await browserPost(env, "/api/browser/resolve", { task_id: taskId, solved: true, duration_s: 30 });
    expect(solved.body).toMatchObject({ ok: true, status: "running" });
    await browserPost(env, "/api/browser/assist", { task_id: taskId });
    const timedOut = await browserPost(env, "/api/browser/resolve", { task_id: taskId, solved: false, duration_s: 60 });
    expect(timedOut.body).toMatchObject({ ok: true, status: "paused" });
    const noAuth = await browserPost(env, "/api/browser/resolve", { task_id: taskId, solved: true }, "wrong");
    expect(noAuth.status).toBe(401);
  });
});
