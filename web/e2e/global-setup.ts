import { mkdirSync, rmSync } from "node:fs";
import { dirname } from "node:path";

import { E2E_DB_PATH } from "../playwright.config";

/** Start every run from an empty database so setup + login are exercised for real. */
export default function globalSetup() {
  mkdirSync(dirname(E2E_DB_PATH), { recursive: true });
  for (const suffix of ["", "-wal", "-shm"]) {
    try {
      rmSync(`${E2E_DB_PATH}${suffix}`, { force: true });
    } catch {
      // A reused dev server (reuseExistingServer) may still hold the file open; CI always
      // starts fresh, so this only matters locally.
    }
  }
}
