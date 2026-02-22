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
