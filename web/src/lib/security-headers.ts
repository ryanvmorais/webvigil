/**
 * Response headers every dashboard route sends (issue #138, step 1; the Content-Security-Policy
 * for scripts and styles is step 2, because Next needs a per-request nonce for its inline scripts).
 *
 * Lives here, not inside `next.config.ts`, so the unit suite can read it; `next.config.ts`
 * imports it by relative path (the config is loaded before the `@/` alias exists).
 *
 * - **Clickjacking:** `frame-ancestors 'none'` and its legacy twin `X-Frame-Options: DENY`. The
 *   report preview is not affected: it frames a `blob:` document the page builds itself, which does
 *   not carry these headers.
 * - **`nosniff`:** the browser trusts the declared `Content-Type`.
 * - **`Referrer-Policy`:** cross-origin requests get the origin, never the path (scan ids).
 * - **`Permissions-Policy`:** the dashboard uses none of these features, so none is granted.
 *
 * `Strict-Transport-Security` is deliberately absent: it only means something over HTTPS, and
 * whoever terminates TLS in front of the dashboard is the one who knows the site is HTTPS-only.
 */
export const securityHeaders: { key: string; value: string }[] = [
  { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  },
];
