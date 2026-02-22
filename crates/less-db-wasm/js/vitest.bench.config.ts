import { defineConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";
import path from "path";

// Path to the JS reference library source. Adjust to match your local checkout.
const LESS_DB_JS_PATH =
  process.env.LESS_DB_JS_PATH ??
  "/Users/nchapman/Code/lessisbetter/less-platform/less-db-js/src/index.ts";

export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  resolve: {
    alias: {
      "@less-platform/db": path.resolve(LESS_DB_JS_PATH),
    },
  },
  worker: {
    format: "es",
    plugins: () => [wasm(), topLevelAwait()],
  },
  test: {
    include: ["bench/**/*.bench.ts"],
    benchmark: {
      include: ["bench/**/*.bench.ts"],
      outputJson: "bench/results.json",
    },
    testTimeout: 30_000,
    browser: {
      enabled: true,
      provider: playwright(),
      instances: [{ browser: "chromium" }],
      headless: true,
    },
  },
});
