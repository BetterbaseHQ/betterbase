/**
 * Worker entry point for WASM/OPFS benchmarks.
 */
import { initOpfsWorker } from "../src/opfs/init.js";
import { buildBenchCollection } from "./shared.js";

const users = buildBenchCollection();

initOpfsWorker([users]);
