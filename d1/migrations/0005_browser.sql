-- OmniJarvis D1 migration 0005 — browser tasks (Phase 3, stage 3c).
-- Pehle-Jaanch phase-3/3c §2b: browser_tasks + AWAITING_USER state.
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: CREATE TABLE IF NOT EXISTS + indexes only.
-- Hosting proof FAIL (phase-3/3c/browser_probe_result.json: Chromium
-- peak RSS 409.4 MB > 350 MB threshold) — the Render browser agent
-- does NOT exist; provider is 'phone_webview' by default, 'e2b' is
-- gated (no account), 'render' refuses. This table tracks tasks the
-- DEVICE executes (PhoneWebView) plus server-side assist state.
-- Captcha rule (D3): traces carry {task_id, site, solved, duration_s}
-- ONLY — a captcha solution/token value is NEVER stored here or in
-- traces. assist_count caps at 3 per task (D3 §3.2 rate guard).

-- browser_tasks: one row per browser task.
-- status: running -> awaiting_user -> running (solved) | paused
-- (timeout / assist cap) | aborted (user said stop) | done.
CREATE TABLE IF NOT EXISTS browser_tasks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  task_name TEXT NOT NULL,
  site TEXT,
  url TEXT,
  provider TEXT NOT NULL DEFAULT 'phone_webview',
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'awaiting_user', 'paused', 'aborted', 'done')),
  assist_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_browser_tasks_device ON browser_tasks(device_id, created_at);
CREATE INDEX IF NOT EXISTS idx_browser_tasks_status ON browser_tasks(status);
