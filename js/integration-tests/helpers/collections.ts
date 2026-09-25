/**
 * Shared collection set for integration scenarios. Kept in one module so
 * the test files and the db worker register identical definitions.
 */
import { collection, t } from "../../src/db/index.js";

export const notes = collection("notes")
  .v(1, {
    title: t.string(),
    body: t.text(),
  })
  .build();

export const documents = collection("documents")
  .v(1, {
    name: t.string(),
    kind: t.string(),
  })
  .build();
