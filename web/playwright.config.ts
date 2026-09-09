import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { defineConfig, devices } from "@playwright/test";

const UI_PORT = 3100;
const API_PORT = 8100;
const FIXTURE_PORT = 9100;

const REPO_ROOT = resolve(__dirname, "..");
// Relative to REPO_ROOT (the API server's cwd); forward slashes keep the SQLite URL sane.
const E2E_DB_RELATIVE = "web/.playwright-tmp/e2e.db";
export const E2E_DB_PATH = resolve(REPO_ROOT, E2E_DB_RELATIVE);

// Create the throwaway-DB directory at config load, before Playwright starts the
// `webServer` processes: the API server runs Alembic on startup and SQLite cannot
// create the file if the parent is missing. globalSetup also does this, but it
// runs after the web servers on a fresh checkout, so CI never had the directory.
mkdirSync(dirname(E2E_DB_PATH), { recursive: true });

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
  globalSetup: "./e2e/global-setup.ts",
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
      command: `uv run webvigil-web serve --host 127.0.0.1 --port ${API_PORT}`,
      cwd: REPO_ROOT,
      env: {
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
