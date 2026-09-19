import { defineConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  server: {
    fs: {
      // Allow access to the WASM package output (one level above js/)
      allow: [".."],
    },
  },
  test: {
    // *.bench.ts files form their own benchmark project (benchmark.include
    // defaults to **/*.bench.ts); the old benchmark.outputJson config is gone
    // in vitest 5 — results print via the default reporter
    include: ["bench/**/*.bench.ts"],
    testTimeout: 30_000,
    browser: {
      enabled: true,
      provider: playwright(),
      instances: [{ browser: "chromium" }],
      headless: true,
    },
  },
});
