/**
 * Test worker entry point for OPFS browser tests.
 *
 * Imports the same collection definitions used by the test files and
 * initializes the OPFS worker infrastructure.
 */
import { initWorker } from "../../src/db/opfs/init.js";
import {
  buildUsersCollection,
  buildDocsCollection,
  buildNotesCollection,
} from "./opfs-helpers.js";

const users = buildUsersCollection();
const docs = buildDocsCollection();
const notes = buildNotesCollection();

initWorker([users, docs, notes]);
