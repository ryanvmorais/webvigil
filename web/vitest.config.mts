/**
 * Vitest config for the component/unit suite: jsdom environment, the same `@/` alias as
 * tsconfig, and `vitest.setup.ts` for the global test hooks. The Playwright e2e suite is
 * separate (`playwright.config.ts`).
 */
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  test: {
    environment: "jsdom",
    environmentOptions: { jsdom: { url: "http://localhost:3000/" } },
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    css: false,
    // clearMocks wipes call history before each test; restoreMocks puts spied
    // originals back. Both are needed since vitest 4: restoreMocks alone no
    // longer clears the call history of a standalone `vi.fn()` (the hoisted
    // router / handler mocks the auth and form tests share).
    clearMocks: true,
    restoreMocks: true,
    testTimeout: 15_000,
  },
});
