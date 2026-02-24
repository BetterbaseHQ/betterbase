/**
 * Worker entry point for WASM/OPFS benchmarks.
 */
import { initWorker } from "../src/opfs/init.js";
import { buildBenchCollection } from "./shared.js";

const users = buildBenchCollection();

initWorker([users]);
