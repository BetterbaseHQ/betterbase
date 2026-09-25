import { playwright } from "@vitest/browser-playwright";
import topLevelAwait from "vite-plugin-top-level-await";
import wasm from "vite-plugin-wasm";
import { defineConfig } from "vitest/config";

/**
 * SDK↔server integration suite.
 *
 * Runs real SDK clients (full wasm/crypto/OPFS fidelity, headless chromium)
 * against the dockerized e2e stack (accounts :25377 / sync :25379). Boots
 * via `just sdk-integration` at the workspace root; self-skips when the
 * stack is down so `just check-js` is unaffected.
 *
 * The Node-side globalSetup probes the stack, registers the harness OAuth
 * client, and serves email verification codes (polled from docker logs)
 * over a localhost sidecar — browser tests cannot exec docker.
 */
export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  server: {
    fs: {
      allow: [".."],
    },
  },
  test: {
    include: ["integration-tests/**/*.test.ts"],
    globalSetup: ["integration-tests/global-setup.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // Scenarios share one stack and one sync DB — serial keeps load and
    // cross-scenario interference predictable.
    fileParallelism: false,
    browser: {
      enabled: true,
      provider: playwright(),
      instances: [{ browser: "chromium" }],
      headless: true,
    },
  },
});
