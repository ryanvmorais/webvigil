/**
 * Global test setup: jest-dom + jest-axe matchers, MSW lifecycle (unmocked requests
 * error), DOM cleanup after each test, and the jsdom shims (`matchMedia`,
 * `ResizeObserver`, …) that Radix and sonner expect.
 */
import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { toHaveNoViolations } from "jest-axe";
import { afterAll, afterEach, beforeAll, expect } from "vitest";

import { server } from "@/test/msw/server";

expect.extend(toHaveNoViolations);

// jsdom gaps that Radix / sonner rely on. A file that opts into the `node` environment (the proxy
// test, `@vitest-environment node`) has no DOM to patch.
if (typeof window !== "undefined") {
  if (!window.matchMedia) {
    window.matchMedia = (query: string) =>
      ({
        matches: false,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }) as MediaQueryList;
  }
  if (!globalThis.ResizeObserver) {
    globalThis.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  }
  if (!Element.prototype.scrollIntoView) {
    Element.prototype.scrollIntoView = () => {};
  }
  if (!Element.prototype.hasPointerCapture) {
    Element.prototype.hasPointerCapture = () => false;
    Element.prototype.setPointerCapture = () => {};
    Element.prototype.releasePointerCapture = () => {};
  }
  // jsdom 26 (pulled in with vitest 4) ships a real `URL.createObjectURL` that
  // returns a random `blob:` URL. Override it unconditionally so the report
  // preview test can assert an exact `src`.
  URL.createObjectURL = () => "blob:mock";
  URL.revokeObjectURL = () => {};
}

// `"error"` only logs and makes the `fetch` reject, so a test that never looks at the outcome
// would still pass: "blocks the form before calling the API" held even when the form called it.
// Each unmocked request is collected and fails the test that sent it.
const unhandled: string[] = [];
server.events.on("request:unhandled", ({ request }) => {
  unhandled.push(`${request.method} ${request.url}`);
});

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));

afterEach(() => {
  cleanup();
  server.resetHandlers();
  const sent = unhandled.splice(0);
  if (sent.length > 0) {
    throw new Error(`Request(s) with no MSW handler: ${sent.join(", ")}`);
  }
});

afterAll(() => server.close());
