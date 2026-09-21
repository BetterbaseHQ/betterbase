import { t } from "../../src/db/schema.js";
import { collection } from "../../src/db/collection.js";

export const def = collection("probe")
  .v(1, { name: t.string(), n: t.number() })
  .build();
