import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

import { defineConfig, devices } from "@playwright/test";

const UI_PORT = 3100;
const API_PORT = 8100;
const FIXTURE_PORT = 9100;

const REPO_ROOT = resolve(__dirname, "..");
const TMP_DIR = resolve(REPO_ROOT, "web/.playwright-tmp");

// Every run gets its own SQLite file. A unique name is what makes the suite
// correct: the old code deleted one shared `e2e.db` to "start empty", but
// Playwright starts the `webServer` processes before globalSetup *and* re-loads
// this config in every worker, so that delete kept racing the API server — which
// migrates on startup and holds the file open — and wiped the schema out from
// under it on Linux ("no such table: user"). It only ever passed on Windows,
// where the open handle makes the delete fail. A fresh path per run needs no
// delete at all; the API migrates it from scratch, so setup + login are still
// exercised for real. `global-teardown.ts` sweeps the files afterwards.
const E2E_DB_RELATIVE = `web/.playwright-tmp/e2e-${Date.now()}-${process.pid}.db`;

mkdirSync(TMP_DIR, { recursive: true });

/**
 * One real-browser flow against the real API + engine, fully offline (RNF-04, ADR-9):
 * the spec-001 Starlette fixture as the scan target, `webvigil-web serve` on a throwaway
 * SQLite file, and the built dashboard proxying `/api/*` to it.
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 90_000,
  reporter: process.env.CI ? [["github"], ["list"]] : "list",
  globalTeardown: "./e2e/global-teardown.ts",
  use: {
    baseURL: `http://127.0.0.1:${UI_PORT}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `uv run python scripts/serve-fixture-app.py --port ${FIXTURE_PORT}`,
      cwd: REPO_ROOT,
      url: `http://127.0.0.1:${FIXTURE_PORT}/`,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
    {
      // `migrate` explicitly first — `serve` also auto-migrates on startup, but running
      // it as its own step makes the schema creation visible in the log and independent
      // of lifespan timing.
      command:
        `uv run webvigil-web migrate && ` +
        `uv run webvigil-web serve --host 127.0.0.1 --port ${API_PORT}`,
      cwd: REPO_ROOT,
      env: {
        // Relative to REPO_ROOT (the API server's cwd); forward slashes keep the SQLite URL sane.
        WEBVIGIL_DATABASE_PATH: E2E_DB_RELATIVE,
        WEBVIGIL_SESSION_SECRET: "e2e-only-secret-not-for-real-deployments-0123456789",
      },
      url: `http://127.0.0.1:${API_PORT}/api/health`,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
    {
      // `next.config` rewrites are baked at build time (RNF-06), so the UI is rebuilt here
      // with the e2e API port before `next start`.
      command: `pnpm exec next build && pnpm exec next start --port ${UI_PORT}`,
      cwd: __dirname,
      env: { API_PROXY_TARGET: `http://127.0.0.1:${API_PORT}` },
      url: `http://127.0.0.1:${UI_PORT}`,
      reuseExistingServer: !process.env.CI,
      timeout: 240_000,
    },
  ],
});

export const TARGETS = {
  ui: `http://127.0.0.1:${UI_PORT}`,
  fixture: `http://127.0.0.1:${FIXTURE_PORT}/`,
};
