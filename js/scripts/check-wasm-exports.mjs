#!/usr/bin/env node
/**
 * CI guard: every function exported by the WASM surface must have a live
 * TypeScript call site, or be suppressed in one of the two tables below with
 * a reason.
 *
 * The surface is parsed from the generated pkg/*.d.ts files (the actual JS
 * API wasm-bindgen produces), so `pnpm build:wasm` must have run first.
 * Call sites are searched in src/ and browser-tests/ (the two wasm-init
 * declaration files are excluded — they name every export without calling
 * any of them).
 *
 * Liveness is a WORD-BOUNDARY TEXTUAL check over a corpus with comments and
 * string literals stripped. Consequences:
 *   - A non-wasm TS identifier with the same name (e.g. the `WSClient.rewrapDEKs`
 *     RPC method vs the wasm `rewrapDEKs` batch fn) counts as "live". Such
 *     collisions are recorded in NAME_COLLISIONS below.
 *   - A semantic check (resolving identifiers via the TS compiler) is a
 *     follow-up; the tables are the source of truth in the meantime.
 *
 * The check fails in two directions:
 *   - a dead export that is not suppressed (new dead surface), and
 *   - a DEAD_WITH_PLAN entry whose export has gained a call site (stale —
 *     the list must shrink as the surface is wired up).
 * NAME_COLLISIONS entries are exempt from the stale check by definition.
 *
 * Scope: function exports only. The db-wasm class surface (WasmDb, etc.) is
 * covered by typecheck and direct usage.
 *
 * Run: pnpm check:wasm-exports   (also part of `pnpm check`)
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL("..", import.meta.url)), "");

const DTS_FILES = [
  join(root, "../crates/betterbase-wasm/pkg/betterbase_wasm.d.ts"),
  join(root, "../crates/betterbase-db-wasm/pkg/betterbase_db_wasm.d.ts"),
];

// Declaration files that enumerate the wasm API without calling it.
const DECL_FILES = new Set([
  join(root, "src/wasm-init.ts"),
  join(root, "src/db/wasm-init.ts"),
]);

/**
 * Intentionally dead exports, each with the change that will consume it.
 * Adding an entry here must come with the plan that removes it. These are
 * stale-checked: once an export gains a real call site, the entry is
 * flagged — the list must shrink as the surface is wired up.
 */
const DEAD_WITH_PLAN = {
  CURRENT_VERSION:
    "version constants: TS hardcodes 4 in sync/types.ts instead of reading the wasm constant (audit: drift risk)",
  filesBlobDir:
    "G8: file-storage.ts recomputes the blob dir name; should call the wasm constant",
  filesPoolDir:
    "G8: file-storage.ts recomputes the pool dir name; should call the wasm constant",
  parseWebfingerResponse:
    "discovery: discovery.ts parses .well-known/webfinger itself; wire to wasm or delete",
  validateServerMetadata:
    "discovery: discovery.ts validates well-known metadata itself; wire to wasm or delete",
};

/**
 * Wasm exports whose names collide with live non-wasm TS identifiers. The
 * textual liveness check cannot distinguish a wasm call site from an
 * unrelated same-named identifier, so these are suppressed from both dead
 * and stale detection. Each entry documents the collision and the plan for
 * the wasm export.
 */
const NAME_COLLISIONS = {
  rewrapDEKs:
    "live hits are the WSClient.rewrapDEKs RPC method; wasm batch-rewrap twin is pre-AUD-024/026 — task 12 ports rewrap orchestration to Rust",
  SUPPORTED_VERSIONS:
    "live hits are the TS-hardcoded Set([4]) in crypto/types.ts; same version-constant drift risk as CURRENT_VERSION",
};

function walkTs(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (entry === "node_modules" || entry === "dist") continue;
      out.push(...walkTs(p));
    } else if (/\.[mt]s(x?)$/.test(p)) {
      out.push(p);
    }
  }
  return out;
}

/**
 * Strip comments and string literals so that mentions in prose/strings don't
 * count as call sites. Conservative: block comments, then '...', "...", then
 * `...` templates, then // line comments. Edge cases fail safe — missed text
 * only makes a name look MORE live (a visible failure), never less.
 */
function stripCommentsAndStrings(src) {
  let out = src.replace(/\/\*[\s\S]*?\*\//g, " ");
  out = out.replace(/'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"/g, '""');
  out = out.replace(/`(?:[^`\\]|\\.)*`/g, '""');
  out = out.replace(/\/\/[^\n]*/g, " ");
  return out;
}

function main() {
  // 1. Enumerate the wasm function surface from the generated d.ts files.
  const exports = new Set();
  for (const dts of DTS_FILES) {
    let content;
    try {
      content = readFileSync(dts, "utf8");
    } catch {
      console.error(`✗ Cannot read ${dts} — run \`pnpm build:wasm\` first.`);
      process.exit(2);
    }
    for (const m of content.matchAll(/export function ([A-Za-z0-9_$]+)/g)) {
      exports.add(m[1]);
    }
  }

  // 2. Collect call-site candidates (src + browser-tests, minus declarations).
  const files = [
    ...walkTs(join(root, "src")),
    ...walkTs(join(root, "browser-tests")),
  ].filter((f) => !DECL_FILES.has(f));
  const haystack = files
    .map((f) => stripCommentsAndStrings(readFileSync(f, "utf8")))
    .join("\n");

  // 3. Liveness: word-boundary reference in the stripped corpus.
  const isLive = (name) =>
    new RegExp(`(?<![A-Za-z0-9_$])${name}(?![A-Za-z0-9_$])`).test(haystack);

  const dead = [...exports].filter((n) => !isLive(n));
  const unexpectedDead = dead
    .filter((n) => !DEAD_WITH_PLAN[n] && !NAME_COLLISIONS[n])
    .sort();
  const stale = Object.keys(DEAD_WITH_PLAN)
    .filter((n) => isLive(n))
    .sort();

  let ok = true;
  if (unexpectedDead.length > 0) {
    ok = false;
    console.error(
      "✗ Dead wasm exports (no TS call site, not suppressed in the script):",
    );
    for (const n of unexpectedDead) console.error(`  - ${n}`);
    console.error(
      "  Wire them up, or add them to DEAD_WITH_PLAN / NAME_COLLISIONS in scripts/check-wasm-exports.mjs with a reason.",
    );
  }
  if (stale.length > 0) {
    ok = false;
    console.error(
      "✗ Stale DEAD_WITH_PLAN entries (export now has a call site — remove them):",
    );
    for (const n of stale) console.error(`  - ${n}`);
  }

  console.log(
    `wasm-export guard: ${exports.size} exports, ${exports.size - dead.length} live, ` +
      `${Object.keys(DEAD_WITH_PLAN).length} dead-with-plan, ` +
      `${Object.keys(NAME_COLLISIONS).length} name-collisions, ` +
      `${unexpectedDead.length} unexpected-dead, ${stale.length} stale`,
  );
  if (!ok) process.exit(1);
}

main();
