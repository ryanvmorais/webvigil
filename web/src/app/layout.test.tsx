/**
 * The root layout's rendering mode — spec 022 RF-07, ADR-3.
 *
 * Only the exported route option is read; the layout is not rendered. Dropping `force-dynamic`
 * would prerender nine pages that then ship scripts without a nonce, a failure that otherwise
 * shows up only in the browser, so a unit test pins it.
 */
import { expect, test } from "vitest";

import { dynamic } from "./layout";

test("the whole tree renders per request, so every page can carry a nonce", () => {
  expect(dynamic).toBe("force-dynamic");
});
