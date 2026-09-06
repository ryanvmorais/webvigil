---
feature: Web UI — Next.js dashboard for the Web API
status: done
date: 2026-09-06
related: [003-web-ui/requirements.md, 003-web-ui/design.md]
origin: conception
---

# 003 — Web UI — Tasks

Ordered, small tasks grouped by stage. Each references the requirement(s) it satisfies.
The last task of every stage is the **web quality gate**:

```
pnpm -C web lint && pnpm -C web format:check && pnpm -C web typecheck \
  && pnpm -C web test && pnpm -C web build
```

Work top to bottom; mark `[x]` after each. Write component/hook tests in the same stage as
the code they cover (RNF-03). All new app code lives in `web/**`; the only files outside
`web/` are `scripts/dump-openapi.py`, `scripts/serve-fixture-app.py`, and edits to
`.github/workflows/ci.yml`, `docker-compose.yml`, `.gitignore`, and the docs. **No change to
`src/webvigil/**` or `pyproject.toml`** (RF-31 unused).

---

## Stage 0 — Scaffold and tooling

- [x] `create-next-app` into `web/` (App Router, TypeScript, Tailwind, ESLint, `src/`
  dir, `@/*` alias). `tsconfig` `"strict": true` (default). — RF-01
- [x] `next.config.ts`: `rewrites()` mapping `/api/:path*` → `${process.env.API_PROXY_TARGET
  ?? "http://127.0.0.1:8000"}/api/:path*` (server-side only). `output: "standalone"` is
  opt-in via `NEXT_OUTPUT_STANDALONE` (the trace step symlinks `node_modules` — needs
  Developer Mode on Windows; CI/Linux and the Dockerfile set the flag). — RF-01, ADR-3, RNF-09
- [x] `package.json`: pin `"packageManager": "pnpm@9.15.4"`; scripts `dev`, `build`,
  `start`, `lint`, `format`, `format:check` (Prettier), `typecheck` (`tsc --noEmit`),
  `test` (Vitest), `test:e2e` (Playwright), `gen:api` (`openapi-typescript openapi.json -o
  src/lib/api-types.ts`). Commit `pnpm-lock.yaml`. — RF-01, RNF-02, RNF-08, RNF-11
- [x] Prettier config (`.prettierrc` + `.prettierignore`) + `pnpm format` the tree; ESLint
  on `next/core-web-vitals` + `next/typescript` + `prettier`. — RNF-02
- [x] `components.json` + `pnpm dlx shadcn add`; vendored: `button`, `input`, `select`,
  `dialog`, `table`, `badge`, `sonner`, `dropdown-menu`, `tabs`, `form`, `label`. `sonner`
  rewritten to drop `next-themes` (ADR-8). — RF-01, decision 6
- [x] `tailwind.config.ts`: `darkMode: "media"` + full shadcn token map + `severity.*`
  scale + `tailwindcss-animate`; `globals.css` defines the CSS variables for light and
  `@media (prefers-color-scheme: dark)`; system font stack (no `next/font` — offline
  builds, RNF-08). — RF-02, ADR-8
- [x] Vitest config (`jsdom`, `@testing-library/*`, `jest-axe`, `@` alias) + `vitest.setup.ts`
  (jest-dom matchers, `toHaveNoViolations`, MSW `server` lifecycle). `web/.gitignore` gains
  `playwright-report`, `test-results`, `.playwright-tmp`. — RNF-03
- [x] One smoke test (`app/page.tsx` redirects to `/scans`) so `pnpm test` is non-empty.
- [x] Web quality gate. — lint / format:check / typecheck / test / build all green.

## Stage 1 — Typed API layer

- [x] `scripts/dump-openapi.py`: import `create_app(WebConfig(database_path=":memory:"))`,
  write `app.openapi()` as sorted, pretty JSON to `web/openapi.json`. Passes `ruff` + `black`. — ADR-4
- [x] Run the dump + `pnpm gen:api`; committed `web/openapi.json` and
  `web/src/lib/api-types.ts` (generated header; eslint + prettier ignore it). — RF-03
- [x] `src/lib/api.ts`: `ApiError` class; `request<T>()` / `requestBlob()` (both
  `credentials: "include"`, JSON headers only with a body, 204 → `undefined`, `!res.ok` →
  `throw new ApiError(status, detail ?? statusText)`); `fieldErrors(err)` (422 `loc[-1]` →
  msg, drops `body`); `errorMessage(err)`. Types from `api-types.ts` `components`. — RF-03,
  RNF-06, RNF-07
- [x] `src/lib/api.ts`: the `api` object — one method per consumed endpoint; `api.reportUrl`
  returns the URL string, `api.reportBlob` fetches the HTML; `TERMINAL_STATUSES` /
  `REPORTABLE_STATUSES` / `SCAN_STATUSES` / `REPORT_FORMATS` constants. — RF-03
- [x] `src/lib/query-keys.ts`: the namespaced key factory. — RF-04
- [x] `src/lib/format.ts`: `relativeTime` / `absoluteTime` (forced `en` locale — copy is
  English), `cweUrl(n)`, `reportFilename(id, ext)`.
- [x] Tests: `request` 204/JSON/error paths; `ApiError.detail` string vs `ValidationItem[]`;
  `fieldErrors` maps a FastAPI 422 body; `reportUrl` query string; `listScans` limit/filter;
  `format` helpers. — RF-03, RNF-07
- [x] Web quality gate. — all green.

## Stage 2 — Providers, shell, error states

- [x] `src/components/providers.tsx`: `QueryClient` with `QueryCache`/`MutationCache`
  `onError` → pure `unauthorizedRedirect({error, hadSession, queryKey})` (clears the cache,
  `router.replace("/login")`, `?reason=expired` when `keys.auth.me()` was cached, skips the
  guard's own probes). `<QueryClientProvider>` + `<Toaster/>` in `app/layout.tsx`. System
  font, no `next/font`. — RF-04, RF-10
- [x] `src/lib/polling.ts`: `listInterval(statuses)` / `detailInterval(status)` — a number
  only when the tab is visible and something is non-terminal, else `false`. — RF-13, RF-21,
  ADR-5
- [x] `src/components/error-states.tsx`: `<FullPageSpinner>` (`role=status`), `<NotFound>`,
  `<LoadFailed onRetry>`, `<Empty>` (optional CTA). — RNF-07
- [x] `src/components/app-shell.tsx`: `<header>` (product name → `/scans`), `nav[aria-label=Primary]`
  (Scans / Checks / Settings, `aria-current`), `<LogoutButton>`; nav collapses to a
  `dropdown-menu` under `sm`; `<main class="container overflow-x-auto">`. — RF-02
- [x] `src/components/{severity,status,confidence}-badge.tsx` + `severity-summary.tsx` +
  `src/lib/severity.ts`: every badge carries an icon **and** a text label (never colour
  alone). — RF-24, RNF-05
- [x] `src/hooks/use-auth.ts` landed here (needed by `<LogoutButton>`): `useSetupStatus`,
  `useMe`, `useHealth`, `useSetup`, `useLogin`, `useLogout`, `useChangePassword`. — RF-04..10, RF-30
- [x] Tests: `unauthorizedRedirect` (fresh / expired / guard-owned / non-401); Providers
  wiring redirects on a live 401; polling helpers honour `visibilityState` + terminal
  status; `app-shell` nav + `aria-current` + mobile trigger; badges expose a non-colour
  signal; `severity-summary` chip order. — RF-04, RF-10, RF-13, RNF-05
- [x] Web quality gate. — all green.

## Stage 3 — Setup, login, auth guard, logout

- [x] `src/hooks/use-auth.ts` (landed in Stage 2): `useSetupStatus`, `useMe({enabled})`
  (both `retry: false`), `useSetup`, `useLogin`, `useLogout`, `useChangePassword`,
  `useHealth` — invalidations per design §"Mutations". — RF-04..09
- [x] `src/components/auth-guard.tsx`: setup → spinner / `<LoadFailed>` → `/setup` → `me`
  (enabled only once setup resolves and is not needed) → spinner → `/login?next=…` →
  children. — RF-05, RF-08
- [x] `app/(app)/layout.tsx`: `<AuthGuard><AppShell>{children}</AppShell></AuthGuard>`.
  `app/(auth)/layout.tsx`: centered card; authed → `/scans`; `needs_setup` and not on
  `/setup` → `/setup`; setup done and on `/setup` → `/login`. — RF-05, RF-08
- [x] `app/(auth)/setup/page.tsx`: username (1–64) + password (≥ 8, confirmed) → `POST
  /api/setup`; 201 → `/login?setup=done`; 409 → message + link; 422 → field errors. — RF-06
- [x] `app/(auth)/login/page.tsx` (`<Suspense>` around the form for `useSearchParams`):
  → `POST /api/auth/login`; 204 → `router.replace(next ?? "/scans")`; 401 → one generic
  error, password cleared, username kept; renders `setup=done` / `reason=expired` notices.
  No username-existence disclosure. — RF-07, RF-08, RF-10
- [x] `app/page.tsx`: `redirect("/scans")` (Stage 0).
- [x] Tests (MSW): setup success/mismatch/409/422; login 401 behaviour + `next` round-trip
  + expired notice; guard redirects for `needs_setup`, missing session, valid session, hard
  setup failure; `useLogout` clears the cache and returns to `/login`. — RF-05..10
- [x] Web quality gate. — all green (43 tests).

## Stage 4 — Scan list

- [x] `src/hooks/use-scans.ts`: `useScanList({ status })` — `useInfiniteQuery` over `GET
  /api/scans?limit=20&status=&cursor=`, `getNextPageParam: p => p.next_cursor ?? undefined`,
  `refetchInterval` derived from the loaded rows' statuses via `listInterval`. Plus
  `useCreateScan` (used in Stage 5). — RF-11, RF-13, ADR-6
- [x] `src/hooks/use-query-param.ts` + `src/components/field-select.tsx` (shared Select
  wrapper — Radix Select is swapped for a native `<select>` in tests).
- [x] `src/components/status-filter.tsx`: `FieldSelect` (all + the six statuses), value from
  and written to `?status=`; a new filter is a new query key so paging resets. — RF-12
- [x] `src/components/scan-list-table.tsx` + `mode-badge.tsx`: `table` with target link,
  mode badge, scope, status badge, `SeveritySummary`, created time (relative + absolute in
  `title`). — RF-11
- [x] `app/(app)/scans/page.tsx` (`<Suspense>`): header + "New scan" button, `StatusFilter`,
  the table, "Load more" when `hasNextPage`, `<Empty>` (CTA only when unfiltered),
  `<LoadFailed>` on error. — RF-11, RF-14
- [x] Tests: `useQueryParams.setParams` add/replace/remove; `StatusFilter` writes/clears
  `?status=`; cursor pagination appends; empty state CTA; load failure + retry. Polling
  start/stop is covered by `polling.test.ts`. — RF-11, RF-12, RF-13
- [x] Web quality gate. — all green.

## Stage 5 — Check catalogue and new-scan form

- [x] `src/hooks/use-checks.ts` (`useChecks`, `staleTime: 5min`) + `src/hooks/use-defaults.ts`
  (`useScanDefaults`). — RF-19, RF-29
- [x] `app/(app)/checks/page.tsx` + `src/components/checks-table.tsx`: `table` (id, name,
  category, mode, default severity badge, CWE links, references), category + mode filters
  (`FieldSelect`), a toggle-sort on the severity header. — RF-29
- [x] `src/hooks/use-scans.ts`: `useCreateScan` → `POST /api/scans` → invalidate
  `["scans"]`, `router.push("/scans/{id}")` (landed in Stage 4). — RF-18
- [x] `src/components/scan-form.tsx` (shadcn `Form` = react-hook-form + zod) +
  `src/components/disabled-checks-field.tsx` + `src/lib/links.ts`: fields per design; zod
  mirrors the API (`target` required + URL-ish; `active` ⇒ non-empty `authorized_by`);
  defaults pre-filled from `useScanDefaults` via `form.reset`; `fail_on` shown read-only;
  `disabled_checks` = expandable native-checkbox list from `useChecks`; `authorized_by` +
  `role="alert"` warning (links `SECURITY.md` on GitHub) only for `active`; server 422 →
  `form.setError` via `fieldErrors`. — RF-15, RF-16, RF-17, RF-19, ADR-11
- [x] `app/(app)/scans/new/page.tsx`: renders `<ScanForm>`. — RF-18
- [x] Tests: catalogue filter + severity sort + retry; form defaults pre-fill; `active`
  without `authorized_by` blocks submit with the attestation message + warning shown;
  `disabled_checks` lists `/api/checks`; server 422 → target field; valid passive submit →
  `router.push("/scans/42")` with no `authorized_by` in the body. — RF-15..19
- [x] Web quality gate. — all green (56 tests).

## Stage 6 — Scan detail and findings

- [x] `src/hooks/use-scan.ts`: `useScan(id)` (`refetchInterval: detailInterval`, on first
  terminal read invalidate findings once); `useCancelScan`, `useDeleteScan` with the design's
  invalidations. `src/hooks/use-findings.ts`: `useFindings(id, { severity, checkId })`. — RF-20,
  RF-21, RF-23, RF-25, RF-26
- [x] `src/components/findings-table.tsx`: renders rows **in API order** (no client re-sort);
  columns severity badge, title, check id, location, confidence; expandable row → description,
  remediation, labelled evidence `<pre>` blocks, CWE links, reference links. — RF-22, RNF-01
- [x] `src/components/findings-filters` (min severity + check id `select`s, URL-synced) with
  the two distinct empty states ("no match" vs "no findings"). — RF-23
- [x] `app/(app)/scans/[id]/page.tsx`: header (target, status, mode, scope, `authorized_by`
  if active, `tool_version`, `pages_scanned`, timestamps, applied options, `error` when
  `failed`); `<NotFound>` on 404; `severity-summary` from `counts`; the findings table +
  filters; Cancel (non-terminal only, confirm `dialog`, 409 → toast + refetch); Delete
  (terminal only, confirm `dialog` → back to list; disabled otherwise). — RF-20, RF-21,
  RF-24, RF-25, RF-26
- [x] Tests: polls while `running`, stops + refetches findings on `completed`; 404 state;
  findings render in API order and filters sync to the URL + refetch; cancel visibility +
  409 toast; delete gating + 204 navigates back. — RF-20..26
- [x] Web quality gate.

## Stage 7 — Reports

- [x] `src/components/report-menu.tsx` (`dropdown-menu`): enabled only for
  `completed`/`interrupted`; items are `<a href={api.report(id, fmt, true)} download>` for
  json/sarif/html/md; disabled state shows a hint. — RF-27
- [x] `src/components/report-preview.tsx`: `dialog` + `<iframe sandbox="">` fed by
  `URL.createObjectURL(await api.reportBlob(id))`; revoke on close. Wire both into the
  detail page. — RF-28, ADR-7
- [x] Tests: menu disabled unless reportable; item hrefs carry `format` + `download=true`;
  preview mounts a sandboxed iframe from a blob and revokes the URL on unmount. — RF-27, RF-28
- [x] Web quality gate.

## Stage 8 — Settings

- [x] `src/hooks/use-auth.ts`: `useHealth` (`GET /api/health`).
- [x] `app/(app)/settings/page.tsx`: change-password form (current + new ≥ 8, confirmed) →
  `POST /api/auth/password`; 204 → success notice + form clears; 403 → inline error on the
  current-password field. Show the API version and a Log out control. — RF-30
- [x] Tests: 403 → current-password field error; success clears the form; version rendered;
  logout clears the cache. — RF-30
- [x] Web quality gate.

## Stage 9 — Accessibility and error-presentation pass

- [x] `jest-axe` assertions: no serious/critical violations on `/login`, `/setup`, `/scans`,
  `/scans/new`, `/scans/[id]`, `/checks`, `/settings`. — RNF-05
- [x] Audit against RNF-05: semantic landmarks, labelled controls, visible focus, keyboard
  operation of every `dropdown-menu` / `dialog`, `aria-live` on toasts and on scan-status
  changes; severity/status never colour-only. Fix gaps. — RNF-05
- [x] Audit against RNF-07: every error path resolves to exactly one of field / toast /
  full-page; no raw stack trace or `[object Object]` reachable. Fix gaps. — RNF-07
- [x] Web quality gate.

## Stage 10 — End-to-end (Playwright)

- [x] `scripts/serve-fixture-app.py`: `uvicorn.run(make_app("insecure"), host, port)` with
  `--port` (default 9100); repo-root `sys.path` shim so `tests.fixtures.app` imports. Passes
  `ruff` + `black`. — ADR-9
- [x] `web/playwright.config.ts` + `web/e2e/global-setup.ts`: one chromium project, 1
  worker; three `webServer` entries — fixture app (`:9100`), `uv run webvigil-web serve`
  (`:8100`, `WEBVIGIL_DATABASE_PATH=web/.playwright-tmp/e2e.db` wiped by global-setup),
  `next build && next start` (`:3100`, `API_PROXY_TARGET=http://127.0.0.1:8100`). The
  rewrite is baked at build time (RNF-06), hence the rebuild. — ADR-9, RNF-04
- [x] `web/e2e/smoke.spec.ts`: setup → login → new **passive** scan of
  `http://127.0.0.1:9100` → wait for `completed` → findings visible → download the JSON
  report and `JSON.parse` the saved file → change password → logout → back at `/login`.
  No external network. — RNF-04
- [x] `pnpm test:e2e` green locally (rebuilds internally); `useSetup` now invalidates the
  `["setup"]` query so the post-setup redirect sticks.
- [x] Web quality gate.

## Stage 11 — Container and CI

- [x] `web/Dockerfile`: multi-stage (deps → build with `API_PROXY_TARGET` +
  `NEXT_OUTPUT_STANDALONE` → `node:20-alpine` runner, copy `.next/standalone` +
  `.next/static` + `public` as `nextjs:nodejs`, `USER nextjs`, `CMD ["node", "server.js"]`).
  `web/.dockerignore` (excludes `.next`, `node_modules`, tests). `web/public/.gitkeep`. — RNF-09
- [x] `docker-compose.yml`: `web` service (build `./web` with `API_PROXY_TARGET` build arg
  = `http://api:8000`, `depends_on: [api]`, `3000:3000`); header comment points at the
  dashboard; dropped the dev-CORS hint (ADR-3). — RNF-09
- [x] `.github/workflows/ci.yml`: new `web` job — `setup-uv` + `uv sync --all-extras`;
  `pnpm/action-setup@v4` (v9) + Node 20 (pnpm cache); `pnpm --dir web install
  --frozen-lockfile`; regenerate `openapi.json` + `api-types.ts` then `git diff
  --exit-code`; `lint` / `format:check` / `typecheck` / `test` / `build`; `playwright
  install --with-deps chromium` + `test:e2e`; `docker build ./web`. `quality` and `docker`
  jobs untouched. — RF-03, RNF-02, RNF-04, RNF-08
- [ ] `docker compose up --build` smoke — **deferred to the Stage 12 manual checklist**
  (no Docker on this machine); the CI `web` job builds the image. — RNF-09
- [x] Web quality gate + `test:e2e` green.

## Stage 12 — Docs and spec closeout

- [x] `docs/web-ui.md`: what it covers, dev quick start, the build-time rewrite/proxy model,
  `API_PROXY_TARGET`, scripts, the typed API layer, containers, CI. No dev-CORS (ADR-3). — RNF-10
- [x] `README.md`: a "Web UI" section (dev + `docker compose up`, port 3000) + web commands
  under Development. — RNF-10
- [x] `CLAUDE.md`: 003 → concluída; `pnpm` commands + a Web UI architecture layer.
  `docs/architecture.md`: Web UI row + rules + specs list. `SECURITY.md`: the dashboard can
  start Active-Mode scans (still `authorized_by`-gated). — RNF-10
- [x] `specs/README.md`: `003-web-ui` marked **done** in the roadmap. — RNF-10
- [~] Manual verification: the Playwright flow covers setup → login → passive scan of the
  fixture → `completed` → findings → JSON report download → change password → logout; the
  HTML preview + all four report formats are covered by unit tests (`report-preview`,
  `report-menu`). `docker compose up --build` is **not run here** (no Docker on this
  machine) — the CI `web` job builds the image; a full compose smoke stays for the next
  environment that has Docker.
- [x] Final web quality gate + `pnpm test:e2e` green; Python gate green (`ruff` / `black` /
  `lint-imports` / `pytest` 178 passed — only `scripts/` added). Frontmatter set to
  `status: done`.
