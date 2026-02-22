/**
 * Test worker entry point for OPFS browser tests.
 *
 * Imports the same collection definitions used by the test files and
 * initializes the OPFS worker infrastructure.
 */
import { initOpfsWorker } from "../src/opfs/init.js";
import { buildUsersCollection } from "./opfs-helpers.js";

const users = buildUsersCollection();

initOpfsWorker([users]);
