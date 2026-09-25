import { initWorker } from "../../src/db/opfs/init.js";
import { documents, notes } from "./collections.js";

initWorker([notes, documents]);
