import { readdirSync, rmSync } from "node:fs";
import { resolve } from "node:path";

const TMP_DIR = resolve(__dirname, "..", ".playwright-tmp");

/**
 * Clear the throwaway SQLite files. All servers are stopped by the time this
 * runs, so it also sweeps up files left by a previous run that crashed before
 * teardown (playwright.config picks a fresh `e2e-<ts>-<pid>.db` name each run).
 */
export default function globalTeardown() {
  let entries: string[];
  try {
    entries = readdirSync(TMP_DIR);
  } catch {
    return;
  }
  for (const name of entries) {
    if (!name.startsWith("e2e-")) continue;
    try {
      rmSync(resolve(TMP_DIR, name), { force: true });
    } catch {
      // Windows may hold a file open briefly after the server exits; harmless,
      // the next run uses a different name and this sweep will catch it later.
    }
  }
}
