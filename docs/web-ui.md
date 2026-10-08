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

Every page and static file the dashboard serves carries `Content-Security-Policy:
frame-ancestors 'none'` and `X-Frame-Options: DENY` (it cannot be framed), `X-Content-Type-Options:
nosniff`, `Referrer-Policy: strict-origin-when-cross-origin` (a cross-origin request gets the origin,
never the path) and a `Permissions-Policy` that grants camera, microphone, geolocation, payment and
USB to nobody. The list is [`web/src/lib/security-headers.ts`](../web/src/lib/security-headers.ts),
applied by `headers()` in `next.config.ts`; a unit test reads it and an e2e test checks it on the
built dashboard.

- **The report preview still works.** It frames a `blob:` document the page builds, which does not
  carry these headers.
- **`/api/*` is not covered.** Next only proxies it; the answer carries the API's own headers.
- **No `Strict-Transport-Security`.** It only means something over HTTPS, so whoever terminates TLS
  in front of the dashboard sets it.
- **No script and style policy yet.** That needs a per-request nonce for Next's inline scripts and
  is the second step of [#138](https://github.com/ryanvmorais/webvigil/issues/138).

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
