import type { RequestHandler } from "msw";

/**
 * Per-suite handlers are added with `server.use(...)`; this base list stays empty so an
 * unmocked request fails loudly (`onUnhandledFrame: "error"`).
 */
export const handlers: RequestHandler[] = [];
