/**
 * Response headers every dashboard route sends, pages and static files alike (issue #138, step 1).
 *
 * The Content-Security-Policy is not in this list: it carries a per-request nonce, so it is built
 * by the proxy (`src/proxy.ts`, `lib/csp.ts`, spec 022) and runs on pages only. Keeping it out of
 * here leaves a page with exactly one policy header (two would be intersected silently, ADR-5).
 *
 * Lives here, not inside `next.config.ts`, so the unit suite can read it; `next.config.ts`
 * imports it by relative path (the config is loaded before the `@/` alias exists).
 *
 * - **Clickjacking:** `X-Frame-Options: DENY`; the policy's `frame-ancestors 'none'` is its modern
 *   twin on pages. The report preview is not affected: it frames a `blob:` document the page
 *   builds itself, which does not carry these headers.
 * - **`nosniff`:** the browser trusts the declared `Content-Type`.
 * - **`Referrer-Policy`:** cross-origin requests get the origin, never the path (scan ids).
 * - **`Permissions-Policy`:** the dashboard uses none of these features, so none is granted.
 *
 * `Strict-Transport-Security` is deliberately absent: it only means something over HTTPS, and
 * whoever terminates TLS in front of the dashboard is the one who knows the site is HTTPS-only.
 */
export const securityHeaders: { key: string; value: string }[] = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  },
];
