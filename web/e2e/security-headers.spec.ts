/**
 * The security headers and the Content-Security-Policy on the real, built dashboard (issue #138,
 * steps 1 and 2; spec 022 RF-01, RF-06, RF-09).
 *
 * Read-only requests against `next build` + `next start`, the one thing the unit suite cannot
 * prove: that the headers reach the browser, once, with a nonce that matches the page. Files run in
 * order with one worker, so this runs before `smoke.spec.ts`; it creates no account, so it leaves
 * the first-run flow alone.
 */
import { expect, test, type APIResponse } from "@playwright/test";

import { securityHeaders } from "../src/lib/security-headers";

/**
 * Every `Content-Security-Policy` header of a response.
 *
 * @param response - Any response.
 * @returns The values, one per header line (`headers()` would join them with a comma).
 */
function policies(response: APIResponse): string[] {
  return response
    .headersArray()
    .filter((header) => header.name.toLowerCase() === "content-security-policy")
    .map((header) => header.value);
}

test("a page has exactly one policy, and its nonce is the one on the page's scripts", async ({
  request,
}) => {
  const page = await request.get("/login");
  expect(page.ok()).toBe(true);

  const found = policies(page);
  expect(found, "one Content-Security-Policy header").toHaveLength(1);
  const nonce = found[0].match(/script-src [^;]*'nonce-([^']+)'/)?.[1];
  expect(nonce, "a nonce in script-src").toBeTruthy();
  expect(found[0]).not.toContain("upgrade-insecure-requests");

  const scripts = (await page.text()).match(/<script\b[^>]*>/g) ?? [];
  expect(scripts.length, "scripts in /login").toBeGreaterThan(0);
  for (const tag of scripts) {
    expect(tag, "every script carries the nonce").toContain(`nonce="${nonce}"`);
  }
});

test("each request gets its own nonce", async ({ request }) => {
  const nonces = new Set<string>();
  for (let i = 0; i < 3; i += 1) {
    const [policy] = policies(await request.get("/login"));
    nonces.add(policy.match(/'nonce-([^']+)'/)?.[1] ?? "");
  }
  expect(nonces.size).toBe(3);
  expect(nonces.has("")).toBe(false);
});

test("a page and a static file both carry the other security headers", async ({ request }) => {
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
  // The proxy does not run on static files, and a policy on a script file would do nothing (RF-06).
  expect(policies(asset), `no policy on ${script}`).toEqual([]);
});

// `/api/*` is deliberately not asserted: Next only proxies it, and the answer carries the API's own
// headers, not these. Securing the API's responses is the API's job (FastAPI), not the dashboard's.
