import { defineConfig } from "vitest/config";

const stubPath = new URL("./tests/cloudflare-workers-stub.ts", import.meta.url).pathname;

export default defineConfig({
  test: {
    setupFiles: ["./tests/setup.ts"],
  },
  resolve: {
    // "cloudflare:workers" is a Workers-runtime module — in tests it
    // resolves to a stub exporting a fake DurableObject base class.
    alias: {
      "cloudflare:workers": stubPath,
    },
  },
});
