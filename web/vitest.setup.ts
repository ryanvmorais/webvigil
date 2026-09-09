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

// jsdom gaps that Radix / sonner rely on.
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

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));

afterEach(() => {
  cleanup();
  server.resetHandlers();
});

afterAll(() => server.close());
