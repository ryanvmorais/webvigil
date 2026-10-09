/**
 * The dashboard's Content-Security-Policy (spec 022, issue #138 step 2): a per-request nonce for
 * scripts, and the other directives, as pure functions the proxy calls and the unit suite reads.
 *
 * The dashboard renders text that came from the sites a user scanned. React escapes it; this
 * policy is the second layer, so that if a rendering mistake ever let markup through, the browser
 * would still refuse to run it (no `'unsafe-inline'` for scripts, RF-02).
 *
 * - **Scripts:** `'self' 'nonce-…' 'strict-dynamic'`, no host list (ADR-2). Next stamps the nonce
 *   it reads from the request's policy on its own scripts.
 * - **Styles keep `'unsafe-inline'`** (RF-04, ADR-4): `sonner` injects a `<style>` at runtime with
 *   no nonce hook and React emits `style` attributes, which a nonce cannot cover. An inline style
 *   can restyle a page but cannot run code. The report preview, a `blob:` document that inherits
 *   this policy, also depends on it (ADR-9): lifting it means moving the report off inline styles.
 * - **No `upgrade-insecure-requests`** (RF-03): the dashboard is served over plain
 *   `http://127.0.0.1` by default and the directive would rewrite its own requests to `https`.
 */

/** Bytes of randomness in a nonce: 128 bits (ADR-6). */
const NONCE_BYTES = 16;

/**
 * Draw a fresh nonce.
 *
 * @returns 16 random bytes from `crypto.getRandomValues`, base64 encoded (`btoa` exists on every
 *   runtime, where `Buffer` is Node's).
 */
export function generateNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Build the policy for one response.
 *
 * Written one directive per line and joined, so a reviewer reads it as a table with no
 * template-literal whitespace to collapse (RNF-04).
 *
 * @param nonce - The nonce of this request, from {@link generateNonce}.
 * @param options - `isDev` adds what `next dev` needs and a production build must never carry:
 *   `'unsafe-eval'` (React's debugging uses `eval`) and the HMR websocket (`ws:` / `wss:`).
 * @returns The `Content-Security-Policy` header value.
 */
export function buildContentSecurityPolicy(nonce: string, options: { isDev: boolean }): string {
  const { isDev } = options;
  const directives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    // The API is the same-origin `/api` rewrite, so nothing else is ever fetched.
    `connect-src 'self'${isDev ? " ws: wss:" : ""}`,
    // The report preview is a sandboxed `blob:` iframe (RF-05, ADR-9).
    "frame-src blob:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ];
  return directives.join("; ");
}
