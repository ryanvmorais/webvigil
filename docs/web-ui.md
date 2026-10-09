# Web UI

`web/` is a Next.js (App Router) dashboard for the Web API (spec 002). TypeScript strict,
Tailwind + shadcn/ui, TanStack Query, managed by `pnpm`. It is a **thin client of the
API** — it never talks to the engine, holds no scan state of its own, and adds no scanning
capability. The visual language (design tokens, severity scale, badge rules) is in
[web-ui-design.md](web-ui-design.md).

## What it covers

First-run setup and login · a paginated, status-filterable scan history that polls while a
scan runs · a new-scan form (mode / scope / politeness / `disabled_checks`, with the
Active-Mode `authorized_by` gate) · scan detail with live status, a per-severity summary,
and a findings table filterable by severity and check id · report preview (HTML, in a
sandboxed iframe) and download (json / sarif / html / md) · the check catalogue · a
settings screen (change password, API version, log out).

## Requirements

- Node 24 (see `engines` in `web/package.json`), `pnpm` (pinned by `packageManager`).
- The Web API reachable somewhere (`webvigil-web serve`, default `http://127.0.0.1:8000`).

## Development

```bash
# 1. the API, in one shell
uv sync --all-extras
uv run webvigil-web serve            # http://127.0.0.1:8000

# 2. the dashboard, in another
cd web
pnpm install
pnpm dev                             # http://localhost:3000
```

`pnpm dev` reads `API_PROXY_TARGET` (default `http://127.0.0.1:8000`) and proxies every
`/api/*` request to it **server-side**. The browser only ever makes same-origin requests,
so the `SameSite=Lax` session cookie works and **no CORS configuration is needed** —
`web.cors_origins` stays empty.

## The proxy model

```
browser ──/api/*──► Next server ──proxy──► webvigil.api (FastAPI) ──► engine
        one origin              API_PROXY_TARGET
```

Next evaluates `next.config.ts` `rewrites()` **at build time**, so:

- `pnpm dev` — reads `API_PROXY_TARGET` live from the environment.
- `pnpm build` / `next start` / the Docker image — the value is baked in at build. Set it
  before building; `docker compose` passes it as a build arg (`http://api:8000`).

`API_PROXY_TARGET` is read only in `next.config.ts` (server side). It never reaches the
browser bundle, and the bundle contains no credentials or session secret.

## Security headers

The dashboard renders text that came from the sites a user scanned: finding titles, evidence, URLs,
technology names. React escapes it; the headers below are the second layer (issue
[#138](https://github.com/ryanvmorais/webvigil/issues/138), spec 022 and the step before it).

**Every page and static file** carries `X-Frame-Options: DENY` (it cannot be framed),
`X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin` (a cross-origin
request gets the origin, never the path) and a `Permissions-Policy` that grants camera, microphone,
geolocation, payment and USB to nobody. The list is
[`web/src/lib/security-headers.ts`](../web/src/lib/security-headers.ts), applied by `headers()` in
`next.config.ts`.

**Every page** also carries one `Content-Security-Policy` with a fresh nonce, built per request by
[`web/src/proxy.ts`](../web/src/proxy.ts) (Next 16's name for the middleware) from the pure function in
[`web/src/lib/csp.ts`](../web/src/lib/csp.ts):

| Directive | Value | Why |
|---|---|---|
| `default-src` | `'self'` | everything not listed below |
| `script-src` | `'self' 'nonce-<random>' 'strict-dynamic'` | a script runs only if it carries this request's nonce; no `'unsafe-inline'`, no host list |
| `style-src` | `'self' 'unsafe-inline'` | see "Why styles stay open" below |
| `img-src` | `'self' data: blob:` | the icon and the UI kit's inline SVGs |
| `font-src` | `'self'` | no web font ships |
| `connect-src` | `'self'` | the API is the same-origin `/api` rewrite |
| `frame-src` | `blob:` | the report preview |
| `object-src` | `'none'` | no plugins |
| `base-uri` | `'self'` | an injected `<base>` cannot redirect relative URLs |
| `form-action` | `'self'` | a hijacked form cannot post elsewhere |
| `frame-ancestors` | `'none'` | clickjacking; the modern twin of `X-Frame-Options` |

`next dev` adds `'unsafe-eval'` to `script-src` (React's debugging uses `eval`) and `ws: wss:` to
`connect-src` (the hot-reload socket); a production build never carries them. There is no
`upgrade-insecure-requests`: the dashboard is served over plain `http://127.0.0.1` by default and the
directive would rewrite its own requests to `https`.

- **How the nonce reaches the scripts.** The proxy draws 16 random bytes per request and puts the policy
  on the request it forwards, where Next reads the `'nonce-…'` and stamps it on its own scripts, and on
  the response. The nonce is not logged and no header carries it separately.
- **Every page renders per request.** A nonce exists only for a rendered request, so the root layout
  declares `export const dynamic = "force-dynamic"` and no page is prerendered any more (nine of the ten
  routes were). The cost is that the HTML is never cached: a reverse proxy in front of the dashboard must
  not cache pages, because a cached page's scripts would carry a stale nonce and be refused. The
  dashboard is a local-first admin UI behind a login, so this is accepted; Lighthouse's performance
  score would show a large regression as a warning.
- **Why styles stay open.** The toast library (`sonner`) injects a `<style>` element at runtime with no
  way to give it a nonce, and React renders `style` attributes, which a nonce cannot cover. An inline
  style can restyle a page but cannot run code, so scripts, where the risk is, stay strict. The report
  preview depends on it too. Lifting it needs a toast library that accepts a nonce and a report that does
  not use inline styles.
- **The report preview still works.** It frames a `blob:` document the page builds, in an iframe with
  `sandbox=""` (no script, no same-origin access). A `blob:` document inherits the page's policy, hence
  `frame-src blob:` and the inline styles above.
- **Where the proxy does not run.** `/api/*` (Next only proxies it; the answer carries the API's own
  headers, and the report responses send `nosniff` and a sandbox policy: see [web-api.md](web-api.md)),
  `/_next/static`, `/_next/image`, the icon, and prefetch requests. A static file therefore has the four
  headers above and no policy, which would do nothing on a script file.
- **No `Strict-Transport-Security`.** It only means something over HTTPS, so whoever terminates TLS
  in front of the dashboard sets it.
- **Left for later.** Trusted Types, a `report-to` endpoint and Next's experimental SRI hash policy.
- **Tests.** `csp.test.ts` and `proxy.test.ts` pin the policy and the matcher; the e2e suite reads one
  header with a matching nonce off the built dashboard, and the end-to-end flow (including opening the
  report preview) fails on any CSP violation or uncaught page error.

## Scripts

| Command (in `web/`) | What it does |
|---|---|
| `pnpm dev` | Dev server on `:3000` |
| `pnpm build` / `pnpm start` | Production build + serve |
| `pnpm lint` / `pnpm format:check` / `pnpm typecheck` | ESLint / Prettier / `tsc --noEmit` |
| `pnpm test` | Vitest (Testing Library + MSW + jest-axe) |
| `pnpm test:e2e` | Playwright: one real-browser flow against the real API on a temp DB, offline |
| `pnpm gen:api` | Regenerate `src/lib/api-types.ts` from `openapi.json` |

## Typed API layer

`scripts/dump-openapi.py` (repo root) writes `web/openapi.json` from the FastAPI app;
`pnpm gen:api` turns that into `web/src/lib/api-types.ts` via `openapi-typescript`. Both
files are committed and drift-checked in CI — after any API change, run:

```bash
uv run python scripts/dump-openapi.py
pnpm --dir web gen:api
```

All requests go through one typed wrapper (`web/src/lib/api.ts`) that sets
`credentials: "include"`, parses the `{ detail }` error shape, and throws a typed
`ApiError`.

## Containers

`docker compose up --build` starts `api` and `web`; the dashboard is on
`http://localhost:3000` and reaches the API through the in-network proxy
(`API_PROXY_TARGET=http://api:8000`). The `web` image runs the Next standalone output as a
non-root user. The SQLite volume (`webvigil-data`) is the only state to back up — unchanged
from the API alone.

## CI

The `web` job in `.github/workflows/ci.yml` runs the drift check, lint, format, typecheck,
unit tests, `pnpm build`, the Playwright flow, and a `docker build` of the web image. The
`compose` job runs `docker compose up --build` and walks the first-run flow through the
dashboard's own port (3000, so the `/api` proxy is exercised): health, setup, login with a
cookie jar, `me`, and the `authenticated` flag. The Python `quality` and `docker` jobs are
unchanged.
