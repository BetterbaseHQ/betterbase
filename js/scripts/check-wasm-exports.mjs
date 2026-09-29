#!/usr/bin/env node
/** Check actual production WASM calls and prohibit production test doubles.
 * Requires `pnpm build:wasm`. Tests cannot make a production export live.
 * The explicit exceptions below are stale-checked in both directions.
 */
import ts from "typescript";
import { readFileSync } from "node:fs";
import { resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const declarations = [
  resolve(root, "../crates/betterbase-wasm/pkg/betterbase_wasm.d.ts"),
  resolve(root, "../crates/betterbase-db-wasm/pkg/betterbase_db_wasm.d.ts"),
];
const boundaries = new Set([
  ...declarations,
  resolve(root, "src/wasm-init.ts"),
  resolve(root, "src/db/wasm-init.ts"),
]);
const deferred = {
  classifyPushRejectionCode:
    "Conformance oracle: TS push policy uses the shared rejection table without requiring initialized WASM.",
  defaultEpochAdvanceIntervalMs:
    "Conformance oracle for the TS public constant; rotation policy reads its default inside Rust.",
  generateP256Keypair:
    "Conformance/interop helper; browser auth receives the app keypair from accounts.",
  spacesSchema:
    "Conformance oracle for the TS collection builder; production validates through parseSpacesRecord.",
  verifyMembershipEntry:
    "Conformance helper; production verifies inside the Rust membership fold.",
  CURRENT_VERSION:
    "Version constants still mirrored in TS; consolidate with synchronous package initialization.",
  SUPPORTED_VERSIONS:
    "Version constants still mirrored in TS; consolidate with synchronous package initialization.",
  filesBlobDir: "File storage directory naming remains in the TS host.",
  filesPoolDir: "File storage directory naming remains in the TS host.",
};

const surface = new Set();
for (const file of declarations) {
  for (const match of readFileSync(file, "utf8").matchAll(
    /export function ([\w$]+)/g,
  ))
    surface.add(match[1]);
}
const configPath = resolve(root, "tsconfig.json");
const config = ts.readConfigFile(configPath, ts.sys.readFile);
const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
const program = ts.createProgram(parsed.fileNames, parsed.options);
const checker = program.getTypeChecker();
const live = new Set();
const violations = [];
const isTest = (path) =>
  /(?:\.test\.[cm]?tsx?$|-mock\.[cm]?tsx?$|\/testing\/)/.test(path);
for (const file of program.getSourceFiles()) {
  if (
    !file.fileName.startsWith(resolve(root, "src") + "/") ||
    file.isDeclarationFile ||
    isTest(file.fileName)
  )
    continue;
  function visit(node) {
    // Resolve the called function's declaration, not its spelling: a
    // WSClient.rewrapDEKs call must never count as a WASM rewrapDEKs call.
    if (ts.isCallExpression(node)) {
      const signature = checker.getResolvedSignature(node);
      const declaration = signature?.declaration;
      if (
        declaration &&
        boundaries.has(resolve(declaration.getSourceFile().fileName))
      ) {
        const name = declaration.name?.getText();
        if (surface.has(name)) live.add(name);
      }
    }
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      !node.isTypeOnly &&
      !node.importClause?.isTypeOnly
    ) {
      const specifier = node.moduleSpecifier.text;
      const resolved = ts.resolveModuleName(
        specifier,
        file.fileName,
        parsed.options,
        ts.sys,
      ).resolvedModule;
      if (resolved && isTest(resolved.resolvedFileName)) {
        violations.push(
          `${relative(root, file.fileName)} imports test code ${specifier}`,
        );
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(file);
}
for (const name of surface) {
  if (!live.has(name) && !deferred[name])
    violations.push(`No production WASM call: ${name}`);
}
for (const name of Object.keys(deferred)) {
  if (live.has(name) || !surface.has(name))
    violations.push(`Stale deferred export: ${name}`);
}
console.log(
  `WASM guard: ${surface.size} exports, ${live.size} production calls, ${Object.keys(deferred).length} explicitly deferred.`,
);
for (const violation of violations) console.error(violation);
if (violations.length) process.exit(1);
