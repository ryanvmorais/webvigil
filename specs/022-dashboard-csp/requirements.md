---
feature: Dashboard Content-Security-Policy — a per-request nonce policy for the Next.js dashboard (issue #138, step 2)
status: approved
date: 2026-10-09
related:
  - 003-web-ui/requirements.md
  - 003-web-ui/design.md
  - 015-web-toolchain-modernization/requirements.md
origin: conception
---

# 022 — Dashboard Content-Security-Policy

## Context and problem

The dashboard (`web/`, Next.js 16 App Router) is a thin client of the Web API (spec 003). Issue #138
asked it to send the security headers it recommends to others, in two steps. **Step 1 is shipped**
(PR #159): `X-Frame-Options`, `frame-ancestors 'none'`, `X-Content-Type-Options`, `Referrer-Policy` and
`Permissions-Policy` on every route, from `headers()` in `next.config.ts`
(`web/src/lib/security-headers.ts`). **Step 2, this spec,** is the rest of the Content-Security-Policy:
the directives that say where scripts, styles, images and connections may come from.

Why it matters here more than for most apps. The dashboard renders text that came from the **sites a user
scanned**: finding titles, evidence, URLs, technology names. React escapes it, and the 1.0.x advisories
and the hardening batch of 1.1.0 (#161 URL schemes, #172 Markdown, #163 the report's own CSP) all treat
that text as hostile. A policy that forbids inline script execution is the second layer: if a rendering
mistake ever let markup through, the browser would still refuse to run it. The Web API already does the
same for the HTML report it serves (`sandbox; default-src 'none'`, #163); the dashboard page that frames it
does not.

### What the code and the framework say (checked on 2026-10-09)

- **Next 16.3.8 uses `proxy.ts`** (the renamed `middleware.ts`) as the place to generate a nonce, put it
  in the request's `Content-Security-Policy` header, and let Next read it back: Next then stamps the nonce
  on its framework scripts, the page bundles and its inline scripts by itself. The guide is shipped in
  `node_modules/next/dist/docs/01-app/02-guides/content-security-policy.md`.
- **A nonce needs dynamic rendering.** A static page is built before any request exists, so it has no
  nonce to carry. Today nine of the ten routes of the production build are static (`○ /`, `/login`,
  `/scans`, `/scans/new`, `/checks`, `/settings`, `/setup`, …); only `/scans/[id]` is dynamic (`ƒ`). The
  policy therefore changes how the dashboard is rendered, not only what it sends (RF-07).
- **The dashboard has no inline script of its own** (no `<script>`, `dangerouslySetInnerHTML` or
  `next/script` in `web/src`); the inline scripts are Next's. That is what makes a strict `script-src`
  possible.
- **Styles cannot be as strict.** `sonner` (the toast library) injects a `<style>` element at runtime with
  no nonce hook, and React `style={}` props become inline `style` attributes. A `style-src` without
  `'unsafe-inline'` would silently unstyle the toasts (resolved decision 1 accepts that).
- **The report preview is a `blob:` iframe** (`report-preview.tsx`, `sandbox=""`). A `blob:` document
  inherits the policy of the page that created it, and the HTML report is one self-contained file with an
  inline `<style>`. A policy that blocks inline styles, or does not allow the frame, would turn the preview
  blank or unstyled.
- **`upgrade-insecure-requests`**, which the Next guide's example carries, would rewrite the dashboard's
  own `http://127.0.0.1` subresource requests to `https`: it is wrong for a local-first tool served over
  plain HTTP.

**This spec covers a nonce-based Content-Security-Policy for every HTML response of the dashboard, the
dynamic rendering it needs, and the tests that keep it from silently breaking the app.** It changes no
engine, no API and no visible behaviour.

### Where it sits

```
web/src/proxy.ts (new)               builds the policy per request, sets the nonce, runs on pages only
web/src/lib/csp.ts (new)             buildContentSecurityPolicy(nonce, { isDev }) -> string (a pure function)
web/src/lib/security-headers.ts      step-1 headers; its Content-Security-Policy entry moves to csp.ts
web/src/app/layout.tsx               opts the tree into dynamic rendering so Next can stamp the nonce
web/e2e/security-headers.spec.ts     asserts the policy and that no page of the smoke flow violates it
```

## Goals

- Every HTML response of the dashboard carries a `Content-Security-Policy` with a fresh, unpredictable
  nonce, and **scripts run only if they carry that nonce** (no `'unsafe-inline'` for scripts).
- `default-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`,
  `frame-ancestors 'none'` and an explicit `frame-src` for the report preview.
- The app behaves as before: every page, the toasts, the report preview and the e2e flow work, and
  nothing in the browser console reports a violation.
- The policy is a tested pure function, and the end-to-end test fails if a page ever violates it.

## Non-goals

- **A strict `style-src`.** Needs a toast library that accepts a nonce, or a patch; a later step
  (resolved decision 1).
- **Trusted Types, `require-trusted-types-for`**, a `report-to` / `report-uri` endpoint, and the
  experimental SRI hash policy of Next. Each is its own change.
- **The Web API's headers.** `/api/*` is proxied by Next and carries the API's own headers; securing them
  is FastAPI's job (#163 did it for the report). `Strict-Transport-Security` stays out for the reason
  step 1 gave.
- **Changing what the dashboard renders or how it looks.**

## Personas

- **As a user of the dashboard**, I want the page that shows text from scanned sites to refuse to run any
  script it did not ship, so that a rendering mistake cannot become code execution in my browser.
- **As the maintainer**, I want the policy tested, so that a Next or dependency upgrade that adds an inline
  script, or a new component that needs a style, fails CI instead of breaking the dashboard in production.
- **As a reviewer of the project's own hygiene**, I want the scanner's dashboard to send the policy a
  scan of it would ask for.

## Functional requirements

### RF-01 — A policy with a fresh nonce on every page

- **Given** a request for any page of the dashboard (`/`, `/login`, `/setup`, `/scans`, `/scans/new`,
  `/scans/[id]`, `/checks`, `/settings`, the not-found page)
  **When** it is answered
  **Then** the response carries one `Content-Security-Policy` header whose `script-src` holds
  `'nonce-<value>'`, the value is at least 128 bits of randomness encoded as base64, and two requests never
  share one.
- **Given** the HTML of that response
  **When** it is read
  **Then** every inline `<script>` carries the same nonce as the header.

### RF-02 — Scripts: the nonce and nothing else

- **Given** the policy
  **When** its `script-src` is read
  **Then** it is `'self' 'nonce-<value>' 'strict-dynamic'`, with no `'unsafe-inline'`, no `'unsafe-eval'`
  and no host allow-list. In **development only** (`next dev`), `'unsafe-eval'` is added, because React's
  debugging uses `eval` there.

### RF-03 — The other directives

- **Given** the policy
  **When** its directives are read
  **Then** they are: `default-src 'self'`; `connect-src 'self'` (the API is reached through the same-origin
  `/api` rewrite); `img-src 'self' data: blob:`; `font-src 'self'` (the UI ships no web font);
  `object-src 'none'`; `base-uri 'self'`; `form-action 'self'`; `frame-ancestors 'none'`;
  `frame-src blob:` (the report preview); and **no** `upgrade-insecure-requests`.

### RF-04 — Styles

- **Given** the policy
  **When** its `style-src` is read
  **Then** it is `'self' 'unsafe-inline'`, and the reason (toast styles injected at runtime, `style`
  attributes of React) is written next to it in the code and in `docs/web-ui.md` (resolved decision 1).

### RF-05 — The report preview still works

- **Given** a completed scan
  **When** the user opens "Preview report"
  **Then** the `blob:` frame loads and the report is styled, the frame is still `sandbox=""` (no script, no
  same-origin access), and no violation is reported.

### RF-06 — One policy, the other step-1 headers unchanged

- **Given** any page response
  **When** its headers are read
  **Then** there is exactly **one** `Content-Security-Policy` header (the step-1 `frame-ancestors 'none'`
  value is replaced by the full policy, not added beside it, because two policies intersect), and
  `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy` are as step 1
  sent them.
- **Given** a file Next serves itself under `/_next/static`
  **When** it is requested
  **Then** it still carries `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` and
  `Permissions-Policy`, and no `Content-Security-Policy`: a policy on a script file has no effect, and the
  proxy does not run on it (RF-09).

### RF-07 — Dynamic rendering, no regression

- **Given** the production build (`next build` + `next start`)
  **When** each page is requested
  **Then** it is rendered per request (the route table shows no static page that serves a page without a
  nonce), hydrates without error, and behaves as before.
- **Given** the Docker image (`output: "standalone"`)
  **When** it serves a page
  **Then** the same holds.

### RF-08 — Nothing in the console

- **Given** the end-to-end flow (setup, login, new scan, scan detail, report preview and download, check
  catalogue, settings, logout)
  **When** it runs in a real browser
  **Then** no `securitypolicyviolation` event and no console error is recorded, and the test fails if one
  is.
- **Given** the Lighthouse CI run
  **When** it audits the dashboard pages
  **Then** the thresholds of `.github/lighthouse/` still hold (accessibility and best practices ≥ 95, zero
  console errors, CLS ≤ 0.1, weight ≤ 500 KB).

### RF-09 — Where the proxy runs

- **Given** a request for `/api/*`, `/_next/static/*`, `/_next/image/*` or the icon
  **When** it is routed
  **Then** the proxy does not run on it: the API's answers are not given the dashboard's policy, and static
  files are not made dynamic. A prefetch request (`next-router-prefetch`) is also skipped, as the Next guide
  recommends.

### RF-10 — Tests

See the test strategy in the design. The suite must cover: the policy builder as a unit (every directive
of RF-02 to RF-04, the development difference, the nonce embedded once, no `upgrade-insecure-requests`);
the proxy's request and response headers and its matcher; the step-1 header list without its old CSP entry;
and, end to end, RF-01, RF-06, RF-07 and RF-08 on the built dashboard.

## Non-functional requirements

### RNF-01 — No new dependency

The policy uses what Next 16 ships (`proxy.ts`, `NextResponse`, `crypto.randomUUID`). `web/package.json` is
unchanged.

### RNF-02 — Cost is stated, not hidden

Rendering every page per request replaces static prerendering for pages that were static, and a nonce makes
them uncacheable by a CDN. The dashboard is a local-first admin UI behind a login, served by a Node process
that already answers `/scans/[id]` dynamically; the cost is accepted, written in `docs/web-ui.md`, and
measured by the Lighthouse run (the performance score is a warning, not an error).

### RNF-03 — The nonce never leaves the response

It is not logged, not written to a file and not exposed to client code. It travels in the request's
`Content-Security-Policy` header, which is where Next reads it; no `x-nonce` header is added, because
nothing in the dashboard reads one.

### RNF-04 — Deterministic and testable

`buildContentSecurityPolicy` is a pure function of the nonce and the environment flag; the same inputs give
the same string, with no whitespace artefact of a template literal.

### RNF-05 — Dashboard-only

No engine, API, database, OpenAPI or report change; `web/openapi.json` and the generated API types are
untouched. The dashboard is not part of the PyPI package, so the CHANGELOG entry extends the existing
dashboard-headers line.

## Resolved decisions

Settled at the requirements gate (2026-10-09), each as recommended in the draft. The design builds on them;
they are cited by number.

1. **`'unsafe-inline'` for styles is accepted (was OQ-1).** The toast library injects a `<style>` at runtime
   and React emits `style` attributes, so a strict `style-src` would need a different toast library or a
   patch. Scripts are where the risk is; the trade-off is recorded and revisited if the toast library gains a
   nonce option.
2. **Every page renders dynamically, set once in the root layout (was OQ-2).** One line makes the rule hold
   for any future page.
3. **The policy is enforced at once (was OQ-3).** No `Content-Security-Policy-Report-Only` phase: the end to
   end flow and the Lighthouse run visit every page, and the e2e violation check (RF-08) is the guard.
4. **No `upgrade-insecure-requests` (was OQ-4).** The dashboard is served over `http://127.0.0.1` by default.
5. **It lands before 1.1.0 (was OQ-5).** The dashboard is not in the PyPI package, so no release depends on
   it; the CHANGELOG line of step 1 is extended.
