/**
 * Playwright smoke spec — live public pages only (R1).
 *
 * Read-only GETs against the PRODUCTION hub + licence Worker: no auth,
 * no writes, no keys. The version is asserted only as "a number-like
 * string" — this workflow runs on PRs BEFORE the deploy lands, so it
 * must not hard-code the version it expects to see live.
 *
 * Installed by the workflow with `npm i --no-save @playwright/test`
 * (package.json is never touched).
 */
import { expect, test } from "@playwright/test";

const HUB = "https://omnijarvis-hub.rajraj3kk.workers.dev";
const LICENCE = "https://jarvis-licence.rajraj3kk.workers.dev";

test("hub /health returns ok + a version string", async ({ request }) => {
  const res = await request.get(`${HUB}/health`);
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.ok).toBe(true);
  expect(typeof body.version).toBe("string");
  expect(body.version).toMatch(/^\d+$/);
});

test("hub / renders the version JSON in a real browser", async ({ page }) => {
  const res = await page.goto(HUB);
  expect(res?.status()).toBe(200);
  const text = (await page.content()) ?? "";
  expect(text).toContain("omnijarvis-hub");
});

test("hub unknown path is 404, not 500", async ({ request }) => {
  const res = await request.get(`${HUB}/definitely-not-a-route`);
  expect(res.status()).toBe(404);
});

test("licence Worker status page is live", async ({ page }) => {
  const res = await page.goto(LICENCE);
  expect(res?.status()).toBe(200);
  await expect(page.locator("h1")).toContainText("Jarvis Licence Server");
  await expect(page.locator("body")).toContainText("Status: LIVE");
});
