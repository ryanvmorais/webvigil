/**
 * Vitest config for the component/unit suite: jsdom environment, the same `@/` alias as
 * tsconfig, and `vitest.setup.ts` for the global test hooks. The Playwright e2e suite is
 * separate (`playwright.config.ts`).
 */
import { resolve } from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": resolve(__dirname, "./src") },
  },
  test: {
    environment: "jsdom",
    environmentOptions: { jsdom: { url: "http://localhost:3000/" } },
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    css: false,
    restoreMocks: true,
    testTimeout: 15_000,
  },
});
