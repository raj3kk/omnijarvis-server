import { defineConfig } from "vitest/config";

const stubPath = new URL("./tests/cloudflare-workers-stub.ts", import.meta.url).pathname;

export default defineConfig({
  test: {
    setupFiles: ["./tests/setup.ts"],
    // Playwright specs live under tests/playwright/ but are NOT vitest
    // tests (they import @playwright/test, which is installed ad-hoc by
    // the playwright-smoke workflow, never in package.json). Exclude them
    // here so `npm test` never tries to collect them.
    exclude: ["**/node_modules/**", "**/dist/**", "tests/playwright/**"],
  },
  resolve: {
    // "cloudflare:workers" is a Workers-runtime module — in tests it
    // resolves to a stub exporting a fake DurableObject base class.
    alias: {
      "cloudflare:workers": stubPath,
    },
  },
});
