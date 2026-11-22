import type { RequestHandler } from "msw";

/**
 * Per-suite handlers are added with `server.use(...)`; this base list stays empty so an
 * unmocked request fails the test that sent it (`vitest.setup.ts`).
 */
export const handlers: RequestHandler[] = [];
