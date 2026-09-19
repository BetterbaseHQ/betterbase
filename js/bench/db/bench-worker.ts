/**
 * Worker entry point for WASM/OPFS benchmarks.
 */
import { initWorker } from "../../src/db/opfs/init.js";
import { buildBenchCollection } from "./shared.js";

const users = buildBenchCollection();

initWorker([users]);
