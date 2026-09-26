/**
 * Testing utilities for betterbase apps.
 *
 * Import from "betterbase/testing" (test files only — requires `vitest`).
 *
 * - `mock-sync.tsx` — alias-in test double for `betterbase/sync/react`
 * - `mock-auth.tsx` — `MockAuthProvider` + `makeFakeSession()` for the
 *   auth context
 *
 * Typical vitest setup (component tests that exercise the local db but not
 * the network):
 *
 * ```ts
 * // vitest.browser.config.ts
 * resolve: {
 *   alias: {
 *     "betterbase/sync/react": "betterbase/testing/mock-sync",
 *   },
 * },
 * ```
 *
 * (A specifier, not a raw path — the exports map resolves it to the same
 * module instance `betterbase/testing` imports, so the double and the
 * harness share state without coupling app configs to SDK file layout.)
 *
 * Then drive the stub with `setSyncState`, `setSyncDb`, `spaceOp`,
 * `setPendingInvitations`, `setFileUrl` and reset between tests with
 * `resetSyncMocks()`.
 */

export * from "./mock-sync.js";
export * from "./mock-auth.js";
