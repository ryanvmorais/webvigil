---
feature: Web UI — Next.js dashboard for the Web API
status: done
date: 2026-09-06
related: [002-web-api/requirements.md, 002-web-api/design.md]
origin: conception
---

# 003 — Web UI

## Context and problem

Spec 002 shipped `webvigil.api`: a single-user FastAPI service that persists scans and
findings in SQLite, runs them one at a time through the engine, and exposes a documented
REST contract (auth, scans, findings, reports, check catalogue, health). Today the only way
to drive it is `curl` or the `/docs` Swagger page.

This spec builds the **browser dashboard** that consumes that API: a Next.js (App Router)
application under `web/`, TypeScript + Tailwind + shadcn/ui + TanStack Query, managed by
`pnpm`. It covers first-run setup, login, a browsable scan history, a new-scan form, a scan
detail view with filterable findings, report preview and download, a check catalogue, and a
settings screen for changing the password.

The UI is a **thin client of the Web API** — it never talks to the engine, never holds
scan state of its own, and adds no scanning capability. Every behaviour it shows is already
a documented endpoint from spec 002.

### Where it sits

```
browser ──► web/  (Next.js, `next start`, output: standalone)
                │  rewrites /api/* ──► webvigil.api  (FastAPI, spec 002)
                │                            │
                │                     webvigil.core.Orchestrator (unchanged)
                └── same browser origin in production; CORS only for the dev server
```

In production the Next.js server proxies `/api/*` to the FastAPI service (a second
`docker-compose` service), so the browser sees one origin and the `SameSite=Lax` session
cookie works without CORS. In development, `next dev` on `:3000` reaches `webvigil-web
serve` on `:8000` via a rewrite plus `web.cors_origins`.

## Goals

- A Next.js App Router app in `web/`, TypeScript strict, Tailwind + shadcn/ui, TanStack
  Query for server state, `pnpm` for dependencies.
- **First-run setup** and **login** screens driven by `/api/setup` and `/api/auth/*`; an
  auth guard that redirects unauthenticated users to login (or to setup when
  `needs_setup`).
- **Scan history**: a paginated list (opaque cursor), filterable by status, that polls for
  updates while any scan is non-terminal.
- **New scan form**: target + mode + scope + politeness options + `disabled_checks`,
  pre-filled from `/api/config/defaults`, with the Active-Mode `authorized_by` gate
  enforced client-side (and still by the API).
- **Scan detail**: live status, metadata, per-severity counts, a findings table filterable
  by severity and check id, and cancel / delete actions with the API's state rules.
- **Reports**: inline HTML preview and download in all four formats (json / sarif / html /
  md) via `/api/scans/{id}/report`.
- **Check catalogue**: a browsable view of `/api/checks`, reused as the source for the
  form's `disabled_checks` control.
- **Settings**: change password, show the API version, log out.
- **Typed API layer**: TypeScript types generated from the FastAPI `openapi.json`, with a
  CI check that they are current, wrapped by a small typed `fetch` client.
- **Quality gate**: ESLint + Prettier + `tsc --noEmit` + Vitest (Testing Library + MSW) +
  `next build`, plus a Playwright end-to-end flow against the real API on a temp database.
- **Container**: a `web` service in `docker-compose.yml` alongside `api`; `docker compose
  up` serves the dashboard on a documented port.

## Non-goals

- Any change to `webvigil.api`, `webvigil.core`, or the engine. If the UI needs something
  the API does not expose, that is a new spec-002 revision, tracked separately — not done
  here. (One exception is allowed: see Open questions / RF-31.)
- Multi-user, roles, org switching, or per-user views — the API is single-user.
- Real-time streaming (WebSocket / SSE). The UI **polls**, matching spec 002's decision.
- Scan scheduling, recurring scans, notifications, email, webhooks.
- Diffing or trend charts across scans over time.
- Server-side rendering of authenticated data / a Next.js BFF with its own session — the
  browser calls the API directly (through the rewrite) and the API owns the cookie.
- Internationalisation. Copy is English; a future i18n pass is out of scope (the API
  already returns English messages).
- Publishing the UI to npm or a public CDN; it ships only with the repo / compose stack.
- Editing findings, adding notes, marking false positives, or any finding-level state — the
  API has no such fields.
- Authentication mechanisms other than the API's cookie (no API tokens, no SSO).

## Personas

| Persona | Needs from 003 |
|---|---|
| **Solo dev / small-team lead** | Trigger a scan from the browser, watch it run, read the findings with severity context, and pull a report — without the CLI or `curl`. Keep a visible history. |
| **Frontend contributor** | A conventional Next.js app: typed API access, component tests, a fast `pnpm dev`, and a clear folder layout. No bespoke build tooling. |
| **Operator running the compose stack** | `docker compose up` brings up API + UI; one documented port; the SQLite volume is the only state to back up (unchanged from 002). |

## Functional requirements

### Application shell and tooling

**RF-01 — Project scaffold**
- **Given** a fresh checkout, **when** `pnpm install && pnpm dev` is run in `web/`, **then**
  the Next.js App Router app starts, TypeScript is in `strict` mode, and Tailwind +
  shadcn/ui are configured.
- **Given** `pnpm build`, **then** it produces a standalone output (`output: "standalone"`)
  that `pnpm start` serves.
- The app has no hard-coded API base URL: it calls same-origin `/api/*` and relies on a
  rewrite (dev and prod) to reach the FastAPI service.

**RF-02 — App layout**
- **Given** an authenticated session, **when** any page loads, **then** a persistent shell
  is shown: a header with the product name, a link to the scan list, the check catalogue,
  settings, and a logout control.
- **Given** the viewport is narrow (mobile), **then** the layout remains usable (no
  horizontal scroll of the page body; the nav collapses).
- A light/dark theme follows the OS preference; no manual toggle is required in 003.

**RF-03 — Typed API client**
- **Given** the FastAPI app is importable, **when** `pnpm gen:api` is run, **then**
  `web/src/lib/api-types.ts` is regenerated from `openapi.json` via `openapi-typescript`.
- **Given** CI runs, **when** the committed `api-types.ts` differs from a fresh generation,
  **then** the job fails with a message to run `pnpm gen:api`.
- All API calls go through one typed wrapper (`web/src/lib/api.ts`) that sets
  `credentials: "include"`, parses the `{ detail }` error shape, and throws a typed
  `ApiError { status, detail }`.

**RF-04 — Server-state management**
- **Given** any list or detail view, **when** it fetches from the API, **then** it uses
  TanStack Query (query keys namespaced per resource; mutations invalidate the affected
  keys).
- **Given** a query returns 401, **then** the client clears the cached session and redirects
  to `/login` (or `/setup` when `needs_setup`).

### First-run setup and authentication

**RF-05 — Setup gate**
- **Given** the app loads and `GET /api/setup` returns `{ needs_setup: true }`, **when** the
  user is anywhere except `/setup`, **then** they are redirected to `/setup`.
- **Given** `needs_setup` is false, **when** the user opens `/setup`, **then** they are
  redirected to `/login` (or the app if already authenticated).

**RF-06 — Setup form**
- **Given** `/setup`, **when** the user submits a username (1–64 chars) and a password
  (≥ 8 chars, confirmed twice), **then** `POST /api/setup` is called; on 201 the user is
  sent to `/login` with a success notice.
- **Given** the API returns 409 (setup already done), **then** the form shows that and links
  to `/login`.
- **Given** a 422, **then** field-level errors from the API body are shown.

**RF-07 — Login form**
- **Given** `/login`, **when** the user submits valid credentials, **then** `POST
  /api/auth/login` is called; on 204 the browser stores the cookie and the user lands on
  the scan list.
- **Given** invalid credentials (401), **then** a single generic error ("invalid username
  or password") is shown; the password field is cleared; the username is kept.
- The form does not reveal whether the username exists.

**RF-08 — Auth guard**
- **Given** any route other than `/login` and `/setup`, **when** the session is missing or
  expired (`GET /api/auth/me` → 401), **then** the user is redirected to `/login` and, after
  a successful login, returned to the originally requested path.
- **Given** a valid session, **when** `/login` or `/setup` is opened, **then** the user is
  redirected to the scan list.

**RF-09 — Logout**
- **Given** an authenticated user, **when** they activate logout, **then** `POST
  /api/auth/logout` is called, the TanStack Query cache is cleared, and they land on
  `/login`.

**RF-10 — Session expiry during use**
- **Given** the user is idle past the cookie TTL, **when** their next API call returns 401,
  **then** the app redirects to `/login` with a "your session expired" notice rather than
  showing a raw error.

### Scan list

**RF-11 — List view**
- **Given** `/scans` (the app's home), **when** it loads, **then** it calls `GET
  /api/scans?limit=20` and shows a table: target, mode badge, scope, status badge,
  per-severity counts, created time (relative + absolute on hover), and a link to the
  detail view.
- **Given** the response has a `next_cursor`, **then** a "load more" / pagination control
  requests the next page and appends (or replaces) rows.
- **Given** the list is empty, **then** an empty state with a "new scan" call to action is
  shown.

**RF-12 — Status filter**
- **Given** the list, **when** the user picks a status (`queued`, `running`, `completed`,
  `failed`, `cancelled`, `interrupted`, or "all"), **then** `GET /api/scans?status=…` is
  refetched and the cursor resets. The active filter is reflected in the URL query string.

**RF-13 — Live refresh**
- **Given** the visible list contains at least one scan in `queued` or `running`, **when**
  the view is mounted and focused, **then** it re-polls `GET /api/scans` on an interval
  (default 3 s); polling stops when no scan on the page is non-terminal or the tab is
  hidden.

**RF-14 — New-scan entry point**
- **Given** the list view, **when** the user activates "new scan", **then** they go to
  `/scans/new`.

### New scan

**RF-15 — Form fields and defaults**
- **Given** `/scans/new`, **when** it loads, **then** it fetches `GET /api/config/defaults`
  and pre-fills: mode (`passive`), scope (`host`), `max_pages`, `delay_ms`,
  `follow_robots`, and shows `fail_on` as informational only (the API has no exit code).
- Fields: `target` (required, text), `mode` (passive / active), `scope` (host /
  subdomains), `max_pages` (int > 0), `delay_ms` (int ≥ 0), `follow_robots` (toggle),
  `disabled_checks` (multi-select, from RF-19), `authorized_by` (text, shown only for
  active).

**RF-16 — Client-side validation mirrors the API**
- **Given** `mode = active` and an empty `authorized_by`, **when** the user submits, **then**
  the form blocks submission and explains that active scans require an authorization
  attestation — the same rule the API enforces (RF-08 of spec 002).
- **Given** an obviously malformed target, **then** the field shows an inline error; the
  authoritative check is still the API's 422, which is surfaced on the field if it slips
  through.

**RF-17 — Active-Mode warning**
- **Given** `mode = active` is selected, **then** a visible warning states that active scans
  send potentially intrusive traffic and must only target systems the user is authorized to
  test, linking to `SECURITY.md` guidance.

**RF-18 — Submit**
- **Given** a valid form, **when** the user submits, **then** `POST /api/scans` is called;
  on 201 the user is redirected to `/scans/{id}` for the new scan, which will show `queued`
  then `running`.
- **Given** a 422, **then** the API's field errors are mapped back onto the form controls.

**RF-19 — Disabled-checks control**
- **Given** the form, **when** the `disabled_checks` control opens, **then** it lists checks
  from `GET /api/checks` (id, name, category, default severity) and lets the user select any
  to disable for this scan; the selection is sent as `disabled_checks`.

### Scan detail and findings

**RF-20 — Detail header**
- **Given** `/scans/{id}`, **when** it loads, **then** it calls `GET /api/scans/{id}` and
  shows: target, status badge, mode, scope, `authorized_by` (if active), `tool_version`,
  `pages_scanned`, created / started / finished times, the options that were applied, and,
  for `failed`, the `error` string.
- **Given** the id does not exist (404), **then** a not-found state with a link back to the
  list.

**RF-21 — Live status**
- **Given** the scan is `queued` or `running`, **when** the view is open and focused,
  **then** it polls `GET /api/scans/{id}` (default 2 s) until the status is terminal, then
  stops and refetches the findings once.

**RF-22 — Findings table**
- **Given** a scan with results, **when** the detail view loads, **then** it calls `GET
  /api/scans/{id}/findings` and renders a table ordered as the API returns it (severity
  desc, then check id, url, key): severity badge, title, check id, location (url + param /
  header / cookie), confidence.
- **Given** a row is expanded, **then** it shows description, remediation, evidence blobs
  (rendered as preformatted text, each labelled), CWE ids (linked to MITRE), and references
  (linked).

**RF-23 — Findings filters**
- **Given** the findings table, **when** the user sets a minimum severity and/or a check
  id, **then** `GET /api/scans/{id}/findings?severity=&check_id=` is refetched; filters are
  reflected in the URL.
- **Given** a filter yields nothing, **then** an empty state distinguishes "no findings
  match this filter" from "this scan produced no findings".

**RF-24 — Severity summary**
- **Given** the detail view, **then** the per-severity `counts` from the scan record are
  shown as a compact summary (e.g. chips: `2 high · 3 medium · 1 low`), matching the totals
  in the findings table when no filter is applied.

**RF-25 — Cancel**
- **Given** a `queued` or `running` scan, **when** the user activates "cancel" and
  confirms, **then** `POST /api/scans/{id}/cancel` is called; on 204 the view refetches and
  shows `cancelled`.
- **Given** the scan is already terminal (409), **then** the control is hidden or disabled;
  a race that returns 409 is surfaced as a toast and the view refetches.

**RF-26 — Delete**
- **Given** a terminal scan, **when** the user activates "delete" and confirms, **then**
  `DELETE /api/scans/{id}` is called; on 204 the user returns to the list and the deleted
  scan is gone.
- **Given** a non-terminal scan, **then** the delete control is disabled with a hint to
  cancel first (the API returns 409).

### Reports

**RF-27 — Download**
- **Given** a scan in `completed` or `interrupted`, **when** the user picks a format (json /
  sarif / html / md) from the report menu, **then** the browser downloads
  `/api/scans/{id}/report?format=…&download=true` and the file saves as
  `webvigil-{id}.{ext}`.
- **Given** a scan with no results, **then** the report menu is disabled with a hint.

**RF-28 — HTML preview**
- **Given** a `completed` / `interrupted` scan, **when** the user opens "preview report",
  **then** the HTML report is fetched from
  `/api/scans/{id}/report?format=html&download=false` and shown inline (in a sandboxed
  `iframe` via a blob URL, or a dedicated preview route) without triggering a download.

### Check catalogue

**RF-29 — Catalogue view**
- **Given** `/checks`, **when** it loads, **then** it calls `GET /api/checks` and shows a
  table: id, name, category, mode, default severity, CWE ids, references — filterable by
  category and mode, sortable by severity.
- The same query powers RF-19; it is fetched once and cached.

### Settings

**RF-30 — Change password**
- **Given** `/settings`, **when** the user submits current password + a new password
  (≥ 8 chars, confirmed), **then** `POST /api/auth/password` is called; on 204 a success
  notice is shown and the form clears.
- **Given** a wrong current password (403), **then** an inline error on the current-password
  field; the API's generic message is used.
- The settings page also shows the API version (`GET /api/health`) and a logout control.

### API contract touch-up (conditional)

**RF-31 — Only-if-needed API change**
- **Given** the UI needs a field the spec-002 API does not return **and** displaying it is
  in scope for these screens, **when** the gap is found during design, **then** it is
  recorded as an explicit, minimal amendment to `webvigil.api` (new response field or query
  param only — no behaviour change), listed in `003-web-ui/design.md` under "API
  amendments", and traced back to the spec-002 requirement it extends.
- No such change may alter scan execution, auth, or persistence semantics. If a larger
  change is needed, it stops and becomes its own spec revision.

## Non-functional requirements

**RNF-01 — Thin client, API is the source of truth**
The UI holds no scan/finding state beyond the TanStack Query cache. It never computes
findings, ordering, counts, or report bytes — it renders what the API returns. Deterministic
finding order comes from the API (spec 002 RF-13); the UI must not re-sort.

**RNF-02 — Quality gate**
`pnpm lint` (ESLint, `next/core-web-vitals` + TypeScript rules), `pnpm format:check`
(Prettier), `pnpm typecheck` (`tsc --noEmit`, strict), `pnpm test` (Vitest), and `pnpm
build` all pass. A new CI job `web` runs them on the same Node LTS used locally. The Python
jobs (`quality` matrix, `docker`) are unchanged.

**RNF-03 — Component / hook tests without a browser or a live API**
Vitest + Testing Library + MSW. MSW intercepts `fetch` and replays fixtures shaped by
`api-types.ts`. Covered: setup/login forms (success, 401, 409, 422), the auth guard,
`ScanForm` (active requires `authorized_by`; defaults pre-fill), cursor pagination,
status-filter refetch, findings filters, cancel/delete state rules, the 401 → redirect
path.

**RNF-04 — One end-to-end flow in a real browser**
A Playwright test starts `webvigil-web serve` against a temp SQLite DB and the built UI
(`next start`), then drives: setup → login → create a passive scan of the spec-001
Starlette fixture target (or `example.com` offline fixture) → watch it reach `completed` →
open findings → download the JSON report → change password → logout. Runs in the `web` CI
job. No external network.

**RNF-05 — Accessibility baseline**
Semantic landmarks, labelled form controls, visible focus states, keyboard-operable menus
and dialogs, `aria-live` for toasts and for scan-status changes. Colour is never the only
signal for severity or status (icon or text label too). Target: no serious/critical axe
violations on the main screens (checked in a Vitest + `jest-axe` assertion).

**RNF-06 — No secrets in the frontend**
The bundle contains no credentials, no session secret, no API keys. The session cookie is
`HttpOnly` and never read by JS. The only build-time config is the API rewrite target
(`API_PROXY_TARGET`, default `http://127.0.0.1:8000`), used by `next.config` server-side
only.

**RNF-07 — Consistent error presentation**
Every API error is surfaced through one mechanism: field-level messages for 422/403 on
forms, a toast for transient/action errors, a full-page state for 404 and for a failed
initial load. Raw stack traces or `[object Object]` never reach the user.

**RNF-08 — Deterministic, cache-friendly builds**
`pnpm-lock.yaml` is committed; CI uses `--frozen-lockfile`. `pnpm gen:api` output is
committed and drift-checked (RF-03). No network calls during `pnpm build`.

**RNF-09 — Container parity**
`docker compose up --build` starts `api` and `web`; the dashboard is reachable on one
documented port and can complete the RNF-04 flow against the composed API. The `web` image
uses the Next standalone output and runs as a non-root user.

**RNF-10 — Docs**
`README.md` gains a "Web UI" section (dev + compose). `docs/web-api.md` (or a new
`docs/web-ui.md`) documents the rewrite/proxy model, `API_PROXY_TARGET`, and the dev CORS
requirement. `CLAUDE.md` and `specs/README.md` move 003 to done.

**RNF-11 — Node / package manager**
Node 20 LTS or newer; `pnpm` only (a `packageManager` field pins the version). The Python
toolchain and `uv` usage are untouched.

## Resolved decisions

Settled with Ryan on 2026-09-06:

1. **Repo layout (Open q. 1):** a plain `web/` subdirectory — no pnpm/turbo workspace
   tooling. The two stacks share nothing but the OpenAPI schema. Two lockfiles
   (`uv.lock`, `web/pnpm-lock.yaml`), one repo.
2. **`gen:api` source (Open q. 2 / RF-03):** a `scripts/dump-openapi.py` imports the
   FastAPI app and writes `web/openapi.json` (committed). `pnpm gen:api` regenerates
   `api-types.ts` from that file. CI regenerates both and fails on any diff.
3. **Playwright target in CI (Open q. 3 / RNF-04):** reuse the spec-001 Starlette fixture
   app as the scan target; the `web` CI job makes it reachable from the composed network.
4. **HTML report preview (Open q. 4 / RF-28):** sandboxed `iframe` + blob URL fetched from
   `?format=html&download=false`. No new API route.
5. **API changes (Open q. 5 / RF-31):** the default is **no change to `webvigil.api`**.
   RF-31 stays as a guarded escape hatch, exercised only if design surfaces a concrete,
   display-only gap.
6. **shadcn/ui component set (Open q. 6 / RF-01):** vendor in `button`, `input`, `select`,
   `dialog`, `table`, `badge`, `toast` (sonner), `dropdown-menu`, `tabs`, `form`. The
   scaffold task lists exactly these.

## Open questions

None. Ready for `/spec design`.
