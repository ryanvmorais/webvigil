/**
 * The security headers on the real, built dashboard (issue #138, step 1).
 *
 * Read-only requests against `next build` + `next start`, the one thing the unit suite cannot
 * prove: that the headers reach the browser. Files run in order with one worker, so this runs
 * before `smoke.spec.ts`; it creates no account, so it leaves the first-run flow alone.
 */
import { expect, test } from "@playwright/test";

import { securityHeaders } from "../src/lib/security-headers";

test("a page and a static file both carry the security headers", async ({ request }) => {
  const page = await request.get("/login");
  expect(page.ok()).toBe(true);

  for (const { key, value } of securityHeaders) {
    expect(page.headers()[key.toLowerCase()], `${key} on /login`).toBe(value);
  }

  // A file Next serves itself, found the way a browser finds it: in the page's own markup.
  const script = (await page.text()).match(/src="(\/_next\/static\/[^"]+\.js)"/)?.[1];
  expect(script, "a /_next/static script in /login").toBeTruthy();
  const asset = await request.get(script as string);
  expect(asset.ok()).toBe(true);
  for (const { key, value } of securityHeaders) {
    expect(asset.headers()[key.toLowerCase()], `${key} on ${script}`).toBe(value);
  }
});

// `/api/*` is deliberately not asserted: Next only proxies it, and the answer carries the API's own
// headers, not these. Securing the API's responses is the API's job (FastAPI), not the dashboard's.
