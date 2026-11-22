/**
 * browser.ts — Browser agent, provider-gated (Phase 3, stage 3c).
 *
 * Hosting proof (frozen, phase-3/3c/browser_probe_result.json,
 * measured 2026-11-21 ~23:40 IST): Chromium Headless Shell 159,
 * single light page, peak RSS **409.4 MB** vs the frozen 350 MB
 * threshold -> **Render browser agent NOT viable**. Executor default
 * is therefore **PhoneWebView** (1.4.20 browser tab +
 * AccessibilityService — HAVE), and the E2B provider is a
 * gated stub only until an E2B account exists (U-4, parent-side).
 * **No stage may claim "server browser works" until E2B is live.**
 *
 * Captcha scope (D3 brief, human-assist-first ONLY — until the D3 LOCKED
 * auto-solver, 2026-11-22):
 * - Detection only recognises a challenge (known selectors + iframes);
 *   it NEVER solves one. There is no solver import, no solver call in
 *   this module — `resolveCaptcha` returns `human_assist` for every
 *   challenge type EXCEPT the single gated `auto_solve` branch
 *   (flag on + type in scope + caps ok, D3 locked 2026-11-22).
 * - Turnstile auto-solve is GATED (explicit D3 decision + user-owned
 *   sites only). The allowlist is EMPTY by design; `isTurnstileAllowed`
 *   therefore always returns false until a decision changes it.
 * - Banned forever: image-grid / reCAPTCHA v2/v3 / hCaptcha / audio /
 *   distorted-text auto-solve (ToS ban + no solver support).
 * - Timeout (60s) = PAUSE, never fail, never auto-solve, never
 *   auto-resume. Max 3 assist requests per task; the 4th auto-pauses
 *   the task. A captcha solution/token value is NEVER stored, logged,
 *   or traced — traces carry only {task_id, site, solved, duration_s}.
 *
 * D3 LOCKED auto-solve (2026-11-22, captcha-solver DESIGN §5/§6) —
 * the ban list below is NARROWED, not deleted, and remains the
 * enforcement point:
 * - `audio` and `recaptcha_v3` stay banned, always human-only.
 * - `recaptcha_v2` / `hcaptcha` / `image_grid` / `distorted_text` move
 *   to auto-solve allowed ONLY when the device asserts the §1
 *   one-time flag AND the §3 caps allow AND the type is in scope.
 *   The single gated branch lives in `resolveCaptcha()` (flag + caps
 *   passed in by the caller); everything else routes human_assist
 *   exactly as before. The solver itself lives in src/captcha.ts
 *   (Gemini/Groq vision only — no third-party solver service, no
 *   audio solving, no fingerprint spoofing, no proxy rotation).
 *
 * Task state lives in D1 `browser_tasks` (migration 0005). Status
 * `awaiting_user` is the server-side AWAITING_USER state (app-side
 * mirror: PlanState.AWAITING_USER in agent_plan.json).
 */
import type { D1Like } from "./db";

/** Browser execution providers. */
export type BrowserProvider = "phone_webview" | "e2b" | "render";

/** Frozen default: PhoneWebView (hosting proof FAIL, §2a). */
export const DEFAULT_BROWSER_PROVIDER: BrowserProvider = "phone_webview";

/** Render browser agent verdict (probe 409.4 MB > 350 MB threshold). */
export const RENDER_BROWSER_UNAVAILABLE_REASON =
  "render_browser_unavailable: Chromium single-page peak RSS 409.4 MB exceeds the 350 MB Render-free budget (probe 2026-11-21)";

/** E2B is gated: no account exists (U-4). */
export const E2B_NOT_CONFIGURED_REASON =
  "e2b_not_configured: no E2B account yet (U-4) — server browser execution is gated";

/** Turnstile auto-solve allowlist — EMPTY by design (D3 gated, no decision yet). */
export const TURNSTILE_ALLOWLIST: readonly string[] = [];

/** Captcha countdown: the canvas active-wait window only (D3 §3.2). */
export const CAPTCHA_ASSIST_TIMEOUT_MS = 60_000;

/** Rate guard (D3 §3.2): max assist requests per task. */
export const MAX_CAPTCHA_ASSISTS_PER_TASK = 3;

/** Screenshot cap (D3 §3.4 / 3c §2b): PNG <200KB over WS. Base64 of
 *  200KB is ~273,067 chars; anything larger is dropped, never sent raw. */
export const MAX_SCREENSHOT_B64_LENGTH = 273_000;

/** AWAITING_USER + the rest of the browser-task lifecycle. */
export type BrowserTaskStatus = "running" | "awaiting_user" | "paused" | "aborted" | "done";

export const BROWSER_TASK_STATUSES: readonly BrowserTaskStatus[] = [
  "running",
  "awaiting_user",
  "paused",
  "aborted",
  "done",
];

export interface BrowserTaskRow {
  id: string;
  tenant_id: string;
  device_id: string;
  task_name: string;
  site: string | null;
  url: string | null;
  provider: string;
  status: BrowserTaskStatus;
  assist_count: number;
  created_at: number;
  updated_at: number;
}

/** New task id (device- or server-generated; `bt-` + 16 hex chars). */
export function newBrowserTaskId(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return "bt-" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// --- Provider resolution (frozen: PhoneWebView default, others refuse) ---

export type ProviderResolution =
  | { ok: true; provider: BrowserProvider }
  | { ok: false; error: "render_browser_unavailable" | "e2b_not_configured" | "unknown_provider"; reason: string };

/**
 * Resolve the executor for a browser task. Render refuses (hosting
 * proof FAIL) and E2B refuses (no account) — both are honest errors,
 * never a silent fallback to a different provider.
 */
export function resolveBrowserProvider(requested?: string | null): ProviderResolution {
  const want = (requested ?? DEFAULT_BROWSER_PROVIDER).toLowerCase();
  if (want === "phone_webview" || want === "phonewebview" || want === "") {
    return { ok: true, provider: "phone_webview" };
  }
  if (want === "render") {
    return { ok: false, error: "render_browser_unavailable", reason: RENDER_BROWSER_UNAVAILABLE_REASON };
  }
  if (want === "e2b") {
    return { ok: false, error: "e2b_not_configured", reason: E2B_NOT_CONFIGURED_REASON };
  }
  return { ok: false, error: "unknown_provider", reason: `unknown browser provider: ${requested}` };
}

// --- Captcha detection (recognise only — never solve) ---

export type CaptchaChallengeType = "turnstile" | "recaptcha" | "hcaptcha" | "unknown";

export interface CaptchaDetection {
  detected: boolean;
  type: CaptchaChallengeType;
}

/**
 * Detect a captcha challenge in page HTML (D3 §3.4): known selectors +
 * challenge iframes. Detection is a heuristic — a false positive only
 * ever routes to human-assist, never to a solver.
 */
export function detectCaptcha(html: string): CaptchaDetection {
  const lower = html.toLowerCase();
  if (
    lower.includes("cf-turnstile") ||
    lower.includes("challenges.cloudflare.com") ||
    lower.includes("turnstile")
  ) {
    return { detected: true, type: "turnstile" };
  }
  if (
    lower.includes("g-recaptcha") ||
    lower.includes("recaptcha/api") ||
    lower.includes("google.com/recaptcha")
  ) {
    return { detected: true, type: "recaptcha" };
  }
  if (lower.includes("h-captcha") || lower.includes("hcaptcha.com")) {
    return { detected: true, type: "hcaptcha" };
  }
  if (lower.includes("data-sitekey")) {
    return { detected: true, type: "unknown" };
  }
  if (lower.includes("captcha")) {
    return { detected: true, type: "unknown" };
  }
  return { detected: false, type: "unknown" };
}

/** Types that may NEVER be auto-solved (D3 §5 hard ban, narrowed by the
 * D3 LOCKED auto-solver 2026-11-22 — DESIGN §6: only `audio` and
 * `recaptcha_v3` stay banned. recaptcha_v2 / hcaptcha / image_grid /
 * distorted_text moved to the gated auto_solve branch in resolveCaptcha
 * below; the ban list remains the enforcement point. */
export const BANNED_AUTO_SOLVE_TYPES: readonly string[] = ["audio", "recaptcha_v3"];

export function isAutoSolveBanned(challengeType: string): boolean {
  return (BANNED_AUTO_SOLVE_TYPES as readonly string[]).includes(challengeType);
}

/**
 * Turnstile auto-solve is allowed ONLY for allowlisted user-owned
 * sites, and ONLY after the explicit D3 decision. The allowlist is
 * empty, so this is always false today.
 */
export function isTurnstileAutoSolveAllowed(site: string | null): boolean {
  if (!site) return false;
  return TURNSTILE_ALLOWLIST.includes(site.toLowerCase());
}

export type CaptchaResolution = { action: "human_assist" | "auto_solve"; reason: string };

/**
 * The resolution for a detected challenge (D3 LOCKED auto-solver,
 * DESIGN §6). The single gated branch: a grid challenge (reCAPTCHA v2
 * / hCaptcha — the detection types `recaptcha` / `hcaptcha`) routes to
 * `auto_solve` ONLY when the caller passes the device flag
 * (autoSolveAllowed — the §1 one-time "always allow", re-read per
 * challenge) AND capsOk (the §3 per-task/per-day caps, counted from
 * captcha_solves). Everything else — flag off, caps hit, audio,
 * Turnstile, v3, unknown — routes to `human_assist` exactly as before.
 * The flag + cap state are caller inputs: this function decides the
 * routing, it never reads D1 or the flag store itself.
 */
export function resolveCaptcha(
  type: CaptchaChallengeType,
  site: string | null,
  opts: { autoSolveAllowed?: boolean; capsOk?: boolean } = {},
): CaptchaResolution {
  if (type === "turnstile" && isTurnstileAutoSolveAllowed(site)) {
    // Unreachable while TURNSTILE_ALLOWLIST is empty; kept as the
    // single gated branch so a future decision changes ONE list,
    // not the control flow. (No solver code lives behind it today.)
    return { action: "human_assist", reason: "turnstile allowlist hit but no solver is installed (D3 gated)" };
  }
  if (
    (type === "recaptcha" || type === "hcaptcha") &&
    opts.autoSolveAllowed === true &&
    opts.capsOk === true
  ) {
    return {
      action: "auto_solve",
      reason: `${type} auto-solve allowed (D3 locked, flag on, caps ok) — Gemini/Groq vision`,
    };
  }
  if (type === "recaptcha" || type === "hcaptcha") {
    return {
      action: "human_assist",
      reason: `${type} auto-solve needs the device flag + caps (D3 locked) — human-assist`,
    };
  }
  return {
    action: "human_assist",
    reason:
      type === "turnstile"
        ? "turnstile not allowlisted (D3 gated) — human-assist"
        : `${type} auto-solve is banned (D3 §5) — human-assist`,
  };
}

/** Screenshot size gate: <200KB PNG over WS (3c §2b, GAP-4). */
export function isScreenshotSizeOk(screenshotB64: string | null | undefined): boolean {
  if (!screenshotB64) return true; // absent is fine — the card degrades gracefully
  return screenshotB64.length <= MAX_SCREENSHOT_B64_LENGTH;
}

// --- D1 browser_tasks (migration 0005) ---

export async function createBrowserTask(
  db: D1Like,
  task: {
    id?: string;
    tenant_id: string;
    device_id: string;
    task_name: string;
    site?: string | null;
    url?: string | null;
    provider?: BrowserProvider;
  },
  nowMs = Date.now(),
): Promise<BrowserTaskRow> {
  const id = task.id ?? newBrowserTaskId();
  const provider = task.provider ?? DEFAULT_BROWSER_PROVIDER;
  await db
    .prepare(
      "INSERT INTO browser_tasks (id, tenant_id, device_id, task_name, site, url, provider, status, assist_count, created_at, updated_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(
      id,
      task.tenant_id,
      task.device_id,
      task.task_name,
      task.site ?? null,
      task.url ?? null,
      provider,
      "running",
      0,
      nowMs,
      nowMs,
    )
    .run();
  const row = await getBrowserTask(db, id);
  if (!row) throw new Error("browser task insert failed");
  return row;
}

/** Device-reported task (PhoneWebView executor): create if missing, else return existing. */
export async function ensureBrowserTask(
  db: D1Like,
  task: {
    id: string;
    tenant_id: string;
    device_id: string;
    task_name: string;
    site?: string | null;
    url?: string | null;
    provider?: BrowserProvider;
  },
  nowMs = Date.now(),
): Promise<BrowserTaskRow> {
  const existing = await getBrowserTask(db, task.id);
  if (existing) return existing;
  return await createBrowserTask(db, task, nowMs);
}

export async function getBrowserTask(db: D1Like, taskId: string): Promise<BrowserTaskRow | null> {
  return await db
    .prepare(
      "SELECT id, tenant_id, device_id, task_name, site, url, provider, status, assist_count, created_at, updated_at " +
        "FROM browser_tasks WHERE id = ?",
    )
    .bind(taskId)
    .first<BrowserTaskRow>();
}

async function setBrowserTaskStatus(
  db: D1Like,
  taskId: string,
  status: BrowserTaskStatus,
  assistCount: number | null,
  nowMs: number,
): Promise<void> {
  if (assistCount === null) {
    await db
      .prepare("UPDATE browser_tasks SET status = ?, updated_at = ? WHERE id = ?")
      .bind(status, nowMs, taskId)
      .run();
  } else {
    await db
      .prepare("UPDATE browser_tasks SET status = ?, assist_count = ?, updated_at = ? WHERE id = ?")
      .bind(status, assistCount, nowMs, taskId)
      .run();
  }
}

export type AssistRequestResult =
  | { ok: true; assist_count: number; status: "awaiting_user" }
  | { ok: false; error: "task_not_found" }
  | { ok: false; error: "task_closed"; status: BrowserTaskStatus }
  | { ok: false; error: "assist_cap_reached"; assist_count: number; status: "paused" };

/**
 * Request one captcha assist for a task (D3 §3.2 rate guard).
 * Success -> status `awaiting_user`, assist_count + 1.
 * 4th request (count already 3) -> task auto-pauses, NO event is
 * sent — the caller must check `ok` before dispatching CAPTCHA_ASSIST.
 */
export async function requestCaptchaAssist(
  db: D1Like,
  taskId: string,
  nowMs = Date.now(),
): Promise<AssistRequestResult> {
  const task = await getBrowserTask(db, taskId);
  if (!task) return { ok: false, error: "task_not_found" };
  if (task.status === "aborted" || task.status === "done") {
    return { ok: false, error: "task_closed", status: task.status };
  }
  if (task.assist_count >= MAX_CAPTCHA_ASSISTS_PER_TASK) {
    await setBrowserTaskStatus(db, taskId, "paused", task.assist_count, nowMs);
    return { ok: false, error: "assist_cap_reached", assist_count: task.assist_count, status: "paused" };
  }
  const next = task.assist_count + 1;
  await setBrowserTaskStatus(db, taskId, "awaiting_user", next, nowMs);
  return { ok: true, assist_count: next, status: "awaiting_user" };
}

export type AssistOutcome = "solved" | "aborted" | "timeout";

export type AssistResolveResult =
  | { ok: true; status: BrowserTaskStatus }
  | { ok: false; error: "task_not_found" };

/**
 * Resolve a pending assist. solved -> task runs on; timeout -> PAUSED
 * (never failed, never auto-resumed); aborted -> ABORTED (decline-abort
 * rule: the whole plan aborts, partial state is cleared by the caller).
 */
export async function resolveCaptchaAssist(
  db: D1Like,
  taskId: string,
  outcome: AssistOutcome,
  nowMs = Date.now(),
): Promise<AssistResolveResult> {
  const task = await getBrowserTask(db, taskId);
  if (!task) return { ok: false, error: "task_not_found" };
  const status: BrowserTaskStatus =
    outcome === "solved" ? "running" : outcome === "aborted" ? "aborted" : "paused";
  await setBrowserTaskStatus(db, taskId, status, null, nowMs);
  return { ok: true, status };
}

/** Trace detail for captcha_assist — solution/token values NEVER appear here. */
export function captchaAssistTrace(
  taskId: string,
  site: string | null,
  opts: { solved?: boolean; duration_s?: number; outcome?: string; assist_count?: number },
): Record<string, unknown> {
  const detail: Record<string, unknown> = { task_id: taskId, site: site ?? null };
  if (opts.outcome !== undefined) detail.outcome = opts.outcome;
  if (opts.solved !== undefined) detail.solved = opts.solved;
  if (opts.duration_s !== undefined) detail.duration_s = opts.duration_s;
  if (opts.assist_count !== undefined) detail.assist_count = opts.assist_count;
  return detail;
}

// --- CAPTCHA_ASSIST WS event (hub -> paired device) ---

export interface CaptchaAssistEvent {
  type: "CAPTCHA_ASSIST";
  task_id: string;
  site: string;
  task_name: string;
  screenshot_b64?: string;
}

/**
 * Build the WS event (3c §2b). An oversized screenshot is DROPPED
 * (never sent raw) — the card then shows site + task + countdown
 * without an image. `screenshotDropped` tells the caller.
 */
export function buildCaptchaAssistEvent(
  task: BrowserTaskRow,
  screenshotB64?: string | null,
): { event: CaptchaAssistEvent; screenshotDropped: boolean } {
  const event: CaptchaAssistEvent = {
    type: "CAPTCHA_ASSIST",
    task_id: task.id,
    site: task.site ?? "",
    task_name: task.task_name,
  };
  if (screenshotB64 && isScreenshotSizeOk(screenshotB64)) {
    event.screenshot_b64 = screenshotB64;
    return { event, screenshotDropped: false };
  }
  return { event, screenshotDropped: Boolean(screenshotB64) };
}

// --- Task execution entry (planning + provider dispatch decision) ---

export type ExecuteBrowserTaskResult =
  | { ok: true; task_id: string; provider: BrowserProvider; status: BrowserTaskStatus; execution: "device" }
  | { ok: false; error: "render_browser_unavailable" | "e2b_not_configured" | "unknown_provider"; reason: string };

/**
 * Plan + start a browser task. PhoneWebView is the only live executor:
 * the task row is created (status running) and the DEVICE executes it
 * via its 1.4.20 browser tab — the server plans, tracks, and assists,
 * it does not drive the WebView step-by-step (that path is E2B-gated).
 * Render/E2B refuse honestly instead of silently falling back.
 */
export async function executeBrowserTask(
  db: D1Like,
  input: {
    tenant_id: string;
    device_id: string;
    task_name: string;
    site?: string | null;
    url?: string | null;
    provider?: string | null;
  },
  nowMs = Date.now(),
): Promise<ExecuteBrowserTaskResult> {
  const resolved = resolveBrowserProvider(input.provider);
  if (!resolved.ok) return resolved;
  const task = await createBrowserTask(
    db,
    {
      tenant_id: input.tenant_id,
      device_id: input.device_id,
      task_name: input.task_name,
      site: input.site ?? null,
      url: input.url ?? null,
      provider: resolved.provider,
    },
    nowMs,
  );
  return { ok: true, task_id: task.id, provider: resolved.provider, status: task.status, execution: "device" };
}
