---
feature: Dashboard Content-Security-Policy — a per-request nonce policy for the Next.js dashboard (issue #138, step 2)
status: draft
date: 2026-10-09
related:
  - 022-dashboard-csp/requirements.md
  - 022-dashboard-csp/design.md
origin: conception
---

# 022 — Dashboard Content-Security-Policy — Tasks

Ordered, small, each tagged with the requirement / ADR it satisfies. The last task of every stage is the
quality gate of the web suite, run in `web/`: `pnpm lint` → `pnpm format:check` → `pnpm typecheck` →
`pnpm test` → `pnpm build`, plus `pnpm test:e2e` from the stage that touches the built dashboard on
(the e2e run builds nothing itself: `pnpm build` comes first). Dashboard only: no engine, API, `openapi.json`
or Python change, so the Python gate does not run (RNF-05). Tests follow the habits in the design's test
strategy: logic in Vitest with nothing mocked that is not the unit under test, the browser's view in
Playwright.

Work happens on a branch cut from `main` **after** the spec PR (#187) is merged: `feat/dashboard-csp`,
one PR, `Closes #138` (step 1 shipped in #159; this is the last step), CHANGELOG `[Unreleased]` in the same
PR.

Baseline: record the Vitest count (`pnpm test`) and the `next build` route table on `main` before the first
edit, and the counts again at close.

## Stage 0 — The policy as a tested pure function, and the step-1 list without its CSP

- [ ] Record the baseline: Vitest test count, and the `next build` route table (nine `○`, one `ƒ`).
  — RF-07
- [ ] `web/src/lib/csp.ts`: a file header (what the policy protects, why styles keep `'unsafe-inline'`,
  ADR-4, why no `upgrade-insecure-requests`), `generateNonce()` (16 bytes from `crypto.getRandomValues`,
  base64 through `btoa`) and `buildContentSecurityPolicy(nonce, { isDev })` with the directives of the
  design's table, one per line of a list joined by `"; "`; `'unsafe-eval'`, `ws:` and `wss:` only when
  `isDev`. — RF-01, RF-02, RF-03, RF-04, RNF-01, RNF-04, ADR-2, ADR-4, ADR-6, ADR-9
- [ ] `web/src/lib/csp.test.ts` (header: what is tested, nothing isolated since the module is pure):
  each directive of the table appears exactly once with its value; the nonce is embedded once, in
  `script-src` only; `script-src` has no `'unsafe-inline'`; `'unsafe-eval'`, `ws:` and `wss:` appear only
  with `isDev`; no `upgrade-insecure-requests`; the same inputs give the same string; `generateNonce`
  returns 100 distinct values that each decode to 16 bytes. — RF-01, RF-02, RF-03, RF-04, RNF-04, RF-10
- [ ] `web/src/lib/security-headers.ts`: remove the `Content-Security-Policy: frame-ancestors 'none'`
  entry; rewrite the file header (the policy now lives in `csp.ts` and the proxy, not here; the four headers
  that stay, and why `frame-ancestors` is still covered: `X-Frame-Options` here, `frame-ancestors` in the
  policy). — RF-06, ADR-5
- [ ] `web/src/lib/security-headers.test.ts`: the four headers, each once, none a
  `Content-Security-Policy`; `next.config` still applies them to every route. — RF-06, RF-10, ADR-5
- [ ] Quality gate (`pnpm lint`, `format:check`, `typecheck`, `test`, `build`). — RF-10

## Stage 1 — The proxy and dynamic rendering

- [ ] `web/src/proxy.ts`: `proxy(request)` builds the policy with `isDev: process.env.NODE_ENV ===
  "development"`, sets it on the forwarded request headers and on the response, and `config.matcher` as in
  the design (excludes `api`, `_next/static`, `_next/image`, `favicon.ico`, `icon.svg`, skips prefetch
  through `missing`); a file header says why the policy is built here and nowhere else, and that the nonce
  is never logged or exposed (no `x-nonce`). — RF-01, RF-03, RF-06, RF-09, RNF-03, ADR-1, ADR-5, ADR-6,
  ADR-8
- [ ] `web/src/app/layout.tsx`: `export const dynamic = "force-dynamic"` with a comment saying why (a nonce
  exists only for a rendered request, so a prerendered page would ship scripts the policy refuses); the
  file header names it. — RF-07, ADR-3
- [ ] `web/src/proxy.test.ts` (`@vitest-environment node`, for `NextRequest`; the module under test is
  the only unit, nothing mocked): the response carries the policy; the forwarded request headers carry the
  same policy (Next's `x-middleware-request-*` entry); two calls give two nonces; no `x-nonce` anywhere; the
  matcher source matches `/login`, `/scans/12`, `/settings` and does not match `/api/scans`,
  `/_next/static/a.js`, `/_next/image`, `/icon.svg`. — RF-01, RF-09, RNF-03, RF-10, ADR-8
- [ ] `web/src/app/layout.test.tsx`: `dynamic === "force-dynamic"`, so that dropping the line fails a unit
  test and not the browser. — RF-07, RF-10, ADR-3
- [ ] Run `pnpm build` and read the route table: every route is `ƒ` (the not-found page and the icon
  excepted as Next lists them); fix nothing by hand, record the table in the design's implementation notes.
  — RF-07
- [ ] Manual, once: `pnpm dev` loads `/login`, hot-reloads an edit and shows no console message (the dev
  policy with `'unsafe-eval'` and `ws:`); `pnpm build && pnpm start` serves `/login` with the header and the
  page hydrates. — RF-02, RF-07
- [ ] Quality gate (`pnpm lint`, `format:check`, `typecheck`, `test`, `build`, `pnpm test:e2e`): the
  existing e2e run must still pass as it is (`security-headers.spec.ts` loops over the shortened list, so it
  checks the four headers and says nothing yet about the policy; Stage 2 adds that). — RF-07, RF-10

## Stage 2 — End to end: the browser's view

- [ ] `web/e2e/security-headers.spec.ts`: rewrite around the four headers plus the policy: `/login` has
  exactly one `Content-Security-Policy` header (read with `headersArray`); its `script-src` nonce is the one
  on the page's inline scripts; two requests have two different nonces; the four headers are on the page
  and on a `/_next/static` asset; the asset has no `Content-Security-Policy`; the file header names the
  spec. — RF-01, RF-06, RF-09, RF-10, RNF-04
- [ ] `web/e2e/smoke.spec.ts`: a `console` and `pageerror` listener on the page from the first
  `goto` to logout, failing the test on a message that matches `/content security policy/i` or on an
  uncaught page error (a network-failure line, such as the 401 after logout, is not a violation and is left
  to Lighthouse's console-error assertion). — RF-08, ADR-7
- [ ] `web/e2e/smoke.spec.ts`: open "Preview report" on the scan detail, wait for the `blob:` frame and
  assert the report heading is visible inside it and `getComputedStyle(body).fontSize` is `15px` (styled, so
  the inline `<style>` survived the inherited policy), and that the frame is still `sandbox=""`. — RF-05,
  RF-08, ADR-9
- [ ] Mutation check, not committed: temporarily drop `frame-src blob:`, then `'unsafe-inline'` from
  `style-src`, then the nonce from the request headers, run the e2e once each and see it fail for the right
  reason; restore. — RF-08, ADR-7
- [ ] Quality gate (`pnpm lint`, `format:check`, `typecheck`, `test`, `build`, `pnpm test:e2e`). The
  e2e is fully green. — RF-08, RF-10

## Stage 3 — Documentation, Lighthouse, image, close-out

- [ ] `docs/web-ui.md`: rewrite "Security headers" around the policy: the table of directives, the nonce
  and why every page renders per request, the cost (RNF-02: no static HTML, uncacheable, a reverse proxy must
  not cache pages), why styles keep `'unsafe-inline'` and what would lift it, why the report preview needs
  `frame-src blob:`, where the proxy does not run, and what stays out (Trusted Types, report endpoint,
  HSTS). — RF-03, RF-04, RF-05, RF-07, RF-09, RNF-02
- [ ] `CHANGELOG.md` `[Unreleased]`: extend the dashboard-headers line (the step-1 entry) with the
  policy, the dynamic rendering and the e2e guard. `CLAUDE.md`: replace the "a política de scripts com nonce
  é o passo 2 do #138" sentence with the shipped policy, and mark 022 in the state list. — RNF-05, Release
  notes
- [ ] `specs/README.md` row 022 → `done`; this file's checkboxes and status; the design's status
  `done` with Deviations and Implementation notes, including the before/after route table. — Close-out
- [ ] Lighthouse: run the CI config locally if the toolchain allows it, otherwise read the workflow run
  on the PR; record accessibility, best practices, console errors, CLS and weight against the thresholds,
  and the Performance score before and after (a warning, not an error). — RF-08, RNF-02
- [ ] Docker image: build `web/Dockerfile` (`output: "standalone"`), start it and confirm `/login` carries
  the header and hydrates; if Docker is not available locally, say so on the PR and rely on the CI image
  build. — RF-07
- [ ] Final gate: the full web gate plus `pnpm test:e2e`, then the Python suite's cheap part
  (`uv run ruff check .`, `uv run pytest tests/unit/test_lighthouse_config.py`) to prove nothing outside
  `web/` moved. Record the Vitest count against the baseline. — RF-10, RNF-05
