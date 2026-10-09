---
feature: Dashboard Content-Security-Policy — a per-request nonce policy for the Next.js dashboard (issue #138, step 2)
status: approved
date: 2026-10-09
related:
  - 022-dashboard-csp/requirements.md
  - 003-web-ui/design.md
  - 015-web-toolchain-modernization/design.md
origin: conception
---

# 022 — Dashboard Content-Security-Policy — design

## Overview

One new file turns the policy on, and two small edits make it hold. `web/src/proxy.ts` (Next 16's name for
the middleware) runs before every page, draws a fresh nonce, builds the policy from it with a pure function,
and puts the policy in two places: the **request** headers it forwards (where Next reads the nonce back and
stamps it on the scripts it renders) and the **response** the browser receives. A nonce can only be stamped
on a page that is rendered for a request, so the root layout opts the whole tree into dynamic rendering
(ADR-3). The step-1 header list loses its `frame-ancestors 'none'` policy, which the full policy now carries
(ADR-5).

```
browser ──► next start ──► proxy.ts ──► route render ──► HTML + Content-Security-Policy
                            │   nonce = 16 random bytes, base64            ▲
                            │   policy = buildContentSecurityPolicy(nonce)  │
                            └─► request header  ──► Next reads 'nonce-…', stamps it on its scripts
                            └─► response header ─────────────────────────────┘
/api/*, /_next/static/*, /_next/image/*, /icon.svg, prefetches: the proxy does not run (matcher)
```

Nothing else moves: no component changes, no new dependency, no API or engine change (RNF-01, RNF-05).

## Module layout

```
web/src/
├── proxy.ts                NEW  proxy(request), config.matcher
├── proxy.test.ts           NEW  forwarded and response headers, a fresh nonce each time, the matcher
├── lib/
│   ├── csp.ts              NEW  buildContentSecurityPolicy(nonce, {isDev}), generateNonce()
│   ├── csp.test.ts         NEW  every directive, the dev difference, the nonce
│   ├── security-headers.ts      the Content-Security-Policy entry removed; comment updated
│   └── security-headers.test.ts the CSP assertions move to csp.test.ts
└── app/layout.tsx          export const dynamic = "force-dynamic" (+ a test that it stays)
web/e2e/
├── security-headers.spec.ts     the policy on a page, one header, a fresh nonce, no CSP on an asset
└── smoke.spec.ts                no CSP violation along the whole flow; the report preview is opened
docs/web-ui.md, CHANGELOG.md, CLAUDE.md          the "Security headers" section and the step-1 line
```

`next.config.ts` keeps `headers()` for the four headers that are the same on every route; it is not
touched.

## Components

### `lib/csp.ts`

```ts
export function generateNonce(): string;
export function buildContentSecurityPolicy(nonce: string, options: { isDev: boolean }): string;
```

`generateNonce` fills 16 bytes with `crypto.getRandomValues` and returns them base64 encoded (`btoa`), so the
nonce has 128 bits and exists on every runtime (ADR-6).

`buildContentSecurityPolicy` joins the directives with `"; "`, from a list written one directive per line
so a reviewer reads the policy as a table, with no template-literal whitespace to collapse (RNF-04):

| Directive | Value | Why |
|---|---|---|
| `default-src` | `'self'` | everything not listed below |
| `script-src` | `'self' 'nonce-<n>' 'strict-dynamic'` (+ `'unsafe-eval'` when `isDev`) | RF-02; `strict-dynamic` lets the nonced bootstrap load the chunks it needs, so no host list (ADR-2) |
| `style-src` | `'self' 'unsafe-inline'` | RF-04, resolved decision 1: sonner injects a `<style>`, React emits `style` attributes |
| `img-src` | `'self' data: blob:` | the icon, inline SVG data URIs of the UI kit |
| `font-src` | `'self'` | no web font ships |
| `connect-src` | `'self'` (+ `ws: wss:` when `isDev`) | the API is the same-origin `/api` rewrite; the dev server's HMR socket |
| `frame-src` | `blob:` | the report preview (RF-05) |
| `object-src` | `'none'` | no plugins |
| `base-uri` | `'self'` | an injected `<base>` cannot redirect relative URLs |
| `form-action` | `'self'` | the forms are React handlers; a hijacked form cannot post elsewhere |
| `frame-ancestors` | `'none'` | clickjacking, replacing step 1's own header |

No `upgrade-insecure-requests` (resolved decision 4, RF-03).

### `proxy.ts`

```ts
export function proxy(request: NextRequest): NextResponse {
  const policy = buildContentSecurityPolicy(generateNonce(), { isDev: process.env.NODE_ENV === "development" });
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("Content-Security-Policy", policy);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", policy);
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico|icon.svg).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
```

Next parses the forwarded request header for `'nonce-…'` while it renders and attaches the nonce to its
framework scripts, page bundles and inline scripts. The proxy runs on the Node runtime by default in Next 16,
so `crypto` and `btoa` are the standard globals. The nonce is never written anywhere else: no `x-nonce`
header, no log line (RNF-03).

### The root layout

`export const dynamic = "force-dynamic"` in `app/layout.tsx`, with a comment that says why: a nonce exists
only for a rendered request, so a prerendered page would ship scripts the policy refuses. The route table
of `next build` turns every `○` into `ƒ`; the build is read in the first stage's tasks to confirm it
(RF-07). `cacheComponents` is not enabled, so the segment option is still honoured in Next 16.3.

### The step-1 header list

`securityHeaders` keeps `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` and
`Permissions-Policy`, applied to every route by `headers()` as now. Its `Content-Security-Policy:
frame-ancestors 'none'` entry is removed: the policy lives in the proxy, which runs on pages only, so a
page has exactly one `Content-Security-Policy` header and a script file has none (RF-06; two policies would
intersect and the stricter would win silently).

## Interfaces

- **Response header on every HTML page** (the proxy's matcher): `Content-Security-Policy: default-src
  'self'; script-src 'self' 'nonce-<base64>' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src
  'self' data: blob:; font-src 'self'; connect-src 'self'; frame-src blob:; object-src 'none'; base-uri
  'self'; form-action 'self'; frame-ancestors 'none'`.
- **Unchanged:** `/api/*` (the API's own headers), `/_next/static/*` and `/_next/image/*` (the four
  step-1 headers, no policy), `/icon.svg`.
- **Library:** `generateNonce()`, `buildContentSecurityPolicy(nonce, { isDev })`; the dashboard has no
  other consumer.

## ADRs

### ADR-1 — A nonce from the proxy, not a static policy with `'unsafe-inline'`, not hashes

**Decision.** The policy is built per request in `proxy.ts`, with a nonce.
**Alternatives.** (a) A static policy in `headers()` with `script-src 'self' 'unsafe-inline'`, which keeps
the pages static. (b) Next's experimental SRI hash policy (`experimental.sri`), which keeps static pages
and avoids nonces.
**Why.** (a) allows any inline script, which is the one thing a CSP for text from hostile sites exists to
refuse; the dashboard would send a header that scores well and protects nothing. (b) is experimental, ties
the policy to a feature that can change in a minor release, and is what Next's own guide calls an
alternative for when static generation matters; here it does not (RNF-02).
**Trade-off.** Dynamic rendering of every page and no CDN caching of the HTML (ADR-3).

### ADR-2 — `'nonce-…' 'strict-dynamic'` with `'self'` and no host list

**Decision.** `script-src 'self' 'nonce-<n>' 'strict-dynamic'`.
**Alternatives.** A host allow-list; the nonce alone without `strict-dynamic`.
**Why.** Next's bootstrap script loads its chunks dynamically; with `strict-dynamic` a script the nonced
bootstrap loads is trusted without listing it, so there is no allow-list to maintain or to bypass. `'self'`
stays for browsers that do not understand `strict-dynamic`, which ignores it where it is supported.
**Trade-off.** A script a future dependency injects with `document.createElement("script")` from a nonced
script is trusted; that is the contract of `strict-dynamic`, and the e2e run still sees a violation for any
inline script without a nonce.

### ADR-3 — Dynamic rendering from the root layout

**Decision.** `export const dynamic = "force-dynamic"` in `app/layout.tsx` (resolved decision 2).
**Alternatives.** `await connection()` in each page; marking only some routes.
**Why.** The guide's own rule is that every page that carries a nonce must be rendered per request. A single
declaration in the one layout all routes share makes the rule hold for pages not written yet; per-page marking
fails silently the day someone forgets it, and the symptom (a blocked script) appears only in the browser.
**Trade-off.** Nine pages that were prerendered are rendered per request; the dashboard is a local-first
admin UI that already renders `/scans/[id]` dynamically, and `docs/web-ui.md` says so (RNF-02).

### ADR-4 — `'unsafe-inline'` for styles, scripts stay strict

**Decision.** `style-src 'self' 'unsafe-inline'` (resolved decision 1).
**Alternatives.** A nonce for styles; patching or replacing `sonner`.
**Why.** `sonner` injects a `<style>` element at runtime with no nonce option, and React renders `style`
attributes, which a nonce cannot cover. Both would be silently blocked. An inline style can restyle a page
but cannot run code, so the risk the policy exists for is untouched.
**Trade-off.** Style injection is not blocked. The comment in `csp.ts` and `docs/web-ui.md` say why, and the
next step is a toast library that accepts a nonce.

### ADR-5 — The policy lives in the proxy only; `headers()` keeps the other four

**Decision.** `securityHeaders` loses its Content-Security-Policy entry; the proxy sets the only one.
**Alternatives.** Keep step 1's `frame-ancestors 'none'` header and add the proxy's beside it.
**Why.** Two `Content-Security-Policy` headers are intersected by the browser, and a rule written in one
place is read in one place. `frame-ancestors 'none'` is in the new policy, and `X-Frame-Options: DENY`
stays on every route, so framing stays forbidden everywhere.
**Trade-off.** A static file no longer carries `frame-ancestors`; it has no effect on a script or a
stylesheet, and `X-Frame-Options` still covers it.

### ADR-6 — 128 random bits from `getRandomValues`; no `x-nonce` header

**Decision.** `generateNonce` encodes 16 bytes from `crypto.getRandomValues`.
**Alternatives.** `Buffer.from(crypto.randomUUID()).toString("base64")` as in the guide.
**Why.** A UUID v4 has 122 random bits and is a string of hex digits and hyphens, so the nonce would be an
encoding of a known format; 16 random bytes are 128 bits and unpredictable. `btoa` works on every runtime,
where `Buffer` is Node's. No `x-nonce` header is added because no component reads it; fewer places hold the
secret (RNF-03).
**Trade-off.** None worth naming.

### ADR-7 — Enforce at once, with the e2e flow as the guard

**Decision.** `Content-Security-Policy`, not `-Report-Only` (resolved decision 3).
**Alternatives.** Report-only for a release, then enforce.
**Why.** Without a reporting endpoint report-only only prints console messages, which the e2e flow and the
Lighthouse run already fail on. The dashboard has ten routes and one dialog that loads a frame; the flow
visits all of them.
**Trade-off.** A page the e2e flow does not reach could break unseen. The Lighthouse run audits the five
logged-in pages and `/login`, and the unit tests pin the policy; a page added later must add itself to
those, as the project already requires for the Lighthouse configuration.

### ADR-8 — The matcher leaves out the API, static files, images, the icon and prefetches

**Decision.** `/((?!api|_next/static|_next/image|favicon.ico|icon.svg).*)`, skipping prefetch requests.
**Alternatives.** Run the proxy on everything.
**Why.** `/api/*` is Next proxying the FastAPI service: the answers are the API's, and giving them the
dashboard's policy would be wrong (RF-09). Static files must stay static. A prefetch request is not a
document and would only cost a nonce.
**Trade-off.** The proxy is not a general place to add headers; the four static ones stay in
`headers()`.

### ADR-9 — `frame-src blob:` and nothing else for frames

**Decision.** The report preview's `blob:` frame is allowed explicitly (RF-05).
**Alternatives.** `child-src`; no `frame-src` and `default-src 'self'`.
**Why.** `default-src 'self'` alone would refuse the `blob:` frame and blank the preview. `frame-src` is the
directive for that load. The frame stays `sandbox=""`, so the report cannot run a script or reach the
dashboard whatever the policy says.
**Trade-off.** A `blob:` document inherits the creator's policy: the report's inline `<style>` is allowed
only because of ADR-4. A future stricter `style-src` must move the report to a nonce or another
mechanism.

## Impact on existing code

- `web/src/lib/security-headers.ts` and its unit test: the CSP entry and its assertion go; the e2e test
  that read the whole list for pages now reads the four headers for pages and assets and asserts the
  policy separately.
- `app/layout.tsx`: one export. Every page becomes dynamic; `next build`'s route table changes (read in the
  tasks).
- The Docker image (`output: "standalone"`) and `next start` serve the proxy as they serve any other
  server code; the standalone trace includes it.
- `.github/lighthouse/` thresholds are unchanged and still the guard of RF-08; the performance score is a
  warning there already.
- `docs/web-ui.md` "Security headers" is rewritten around the policy; `CHANGELOG.md` extends the
  step-1 line; `CLAUDE.md` replaces its "o passo 2 do #138" sentence.
- No change to `web/openapi.json`, the API types, the engine or the PyPI package.

## Risks

- **A Next or dependency upgrade adds an inline script without a nonce.** Next stamps its own; a library's
  would be blocked. The e2e flow reports any CSP violation message and fails (RF-08), so the upgrade PR is
  red instead of the dashboard broken.
- **Development mode.** `next dev` needs `'unsafe-eval'` and an HMR websocket (`ws:`), both added only
  when `NODE_ENV` is `development`; checked by hand once and by the unit test of the builder. A
  production build never carries them.
- **`blob:` inheritance differs between browsers.** The e2e runs Chromium only. If another browser were to
  block the report's styles, the preview would render unstyled; the sandbox keeps it harmless.
- **No static HTML.** Each page costs a render. Accepted (ADR-3, RNF-02); Lighthouse's performance score
  would show a large regression as a warning.
- **A reverse proxy that caches HTML.** A nonce makes a cached page's scripts fail. The dashboard sends no
  cache headers for dynamic pages; `docs/web-ui.md` says not to cache them.

## Test strategy

Follows the web suite's habits: logic in Vitest with nothing mocked that is not the unit under test, and the
one thing unit tests cannot prove (the browser's view) in Playwright on the built dashboard.

- **Vitest — `csp.test.ts`:** each directive of the table appears exactly once with its value; the nonce is
  embedded once, in `script-src` only; no `'unsafe-inline'` in `script-src`; `'unsafe-eval'`, `ws:` and
  `wss:` only when `isDev`; no `upgrade-insecure-requests`; the same inputs give the same string;
  `generateNonce` returns 100 distinct values that decode to 16 bytes.
- **Vitest — `proxy.test.ts`** (`@vitest-environment node`, for `NextRequest`): the response carries the
  policy; the forwarded request headers carry the same one (Next's `x-middleware-request-*` entry); two
  calls give two nonces; no `x-nonce` anywhere; the matcher source matches `/login`, `/scans/12`,
  `/settings` and does not match `/api/scans`, `/_next/static/a.js`, `/_next/image`, `/icon.svg`.
- **Vitest — `security-headers.test.ts`:** the four headers, each once; none is a
  `Content-Security-Policy`; `next.config` applies them to every route. A layout test asserts
  `dynamic === "force-dynamic"`.
- **Playwright — `security-headers.spec.ts`:** `/login` has exactly one `Content-Security-Policy` header
  (read with `headersArray`), its nonce is the one on the page's inline scripts, two requests have two
  nonces, the four headers are on the page and on a `/_next/static` asset, and the asset has no policy.
- **Playwright — `smoke.spec.ts`:** a console and `pageerror` listener runs from setup to logout and the
  test fails on a CSP violation message or an uncaught page error; the flow also opens "Preview report" and
  asserts the frame renders and is styled (`font-size` of the report body, the existing 15 px check, read
  inside the `blob:` frame). Plain network-failure lines of the console (a 401 after logout) are not
  violations and are left to Lighthouse's console-error assertion on its pages.
- **Lighthouse CI:** unchanged, the guard for the thresholds of RF-08.
- **Manual, once:** `next dev` loads a page and hot-reloads; `next build` route table is all `ƒ`; the
  standalone image serves `/login` with the header.
- **Gate:** `pnpm lint`, `pnpm format:check`, `pnpm typecheck`, `pnpm test`, `pnpm build`,
  `pnpm test:e2e` at the end of each stage.
