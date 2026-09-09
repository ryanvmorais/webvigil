---
feature: Web toolchain modernization — Node 24, Tailwind CSS v4, Next.js 16
status: done
date: 2026-09-09
related:
  - 015-web-toolchain-modernization/requirements.md
  - 015-web-toolchain-modernization/design.md
origin: conception
---

# 015 — Web toolchain modernization — Tasks

One branch (`spec/015-web-toolchain-modernization`), one PR. Stages 1–3 are
applied and gated in order; Stage 4 integrates, updates docs, and retires the
Dependabot backlog.

**The `web/` quality gate**, referenced below, is (run from `web/`):

```
pnpm install --frozen-lockfile=false   # only when deps changed
pnpm lint && pnpm format:check && pnpm typecheck && pnpm test && pnpm build && pnpm test:e2e
docker build --build-arg API_PROXY_TARGET=http://api:8000 -t webvigil-web:local ./web   # from repo root
```

The Python gate (`ruff → black → mypy → lint-imports → pytest`) is unaffected by
this spec; CI runs it on the PR.

## Stage 0 — Baseline

- [x] Capture the current `pnpm build` route/size table and `pnpm test` count into a
      note at the bottom of this file (the RNF-03 / RF-11 comparison point). — RNF-03
- [x] Commit the three spec docs (`requirements.md`, `design.md`, `tasks.md`). — —

> Baseline is captured against `spec/015` at its base — i.e. on top of the CI
> repair (PR #12: lockfile re-resolved, vitest 4 test fallout fixed, OpenAPI
> types regenerated), with `next` 15.5.24 / `tailwindcss` 3.4.19 / Node 20.

## Stage 1 — Node 24

- [x] `.github/workflows/ci.yml`: in the `web` job, `node-version: 20` → `24`. The
      PR #6 review's worry about the `version: 9` input was unfounded (there is no
      root `package.json` for it to conflict with) — instead pointed
      `pnpm/action-setup@v6` at `web/package.json` via `package_json_file` so the
      pnpm version has one source (`packageManager`). — RF-01
- [x] `web/Dockerfile`: `node:20-alpine` → `node:24-alpine` in the `deps`, `build`
      and `runner` stages; `corepack enable`, the non-root user and the standalone
      `CMD` left untouched. — RF-01, RNF-05
- [x] `web/package.json`: added `"engines": { "node": ">=24" }`; `@types/node` →
      `^24` (resolves to `24.13.3`). `pnpm install` refreshed the lockfile. — RF-01, RF-02
- [x] Quality gate (Stage 1). — RF-11
      <!-- result: lint / format:check / typecheck (@types/node 24, clean) / test
      (86 passed) / build (bundle identical to baseline) / test:e2e (1 passed) all
      green locally. `docker build ./web` runs in CI only — no local Docker. -->
      <!-- Node local: v24.15.0 -->


## Stage 2 — Tailwind CSS v4

- [x] `web/package.json`: removed `tailwindcss@^3` and `tailwindcss-animate`; added
      `tailwindcss@^4.3.3`, `@tailwindcss/postcss@^4.3.3`, `tw-animate-css@^1.4.0`
      (dev); `tailwind-merge` → `^3.6.0`; bumped `prettier-plugin-tailwindcss` to
      `^0.8.1` (v4-aware sorter). `pnpm install`. — RF-03, RF-05
- [x] `web/postcss.config.mjs`: plugin → `@tailwindcss/postcss`; docstring refreshed. — RF-03
- [x] `web/src/app/globals.css`: rewritten to v4 — `@import "tailwindcss"`,
      `@import "tw-animate-css"`, unchanged `:root` + dark `@media` token blocks,
      `@theme inline` token map, `@keyframes accordion-*`, base layer. Every
      `--token` value byte-identical. **Deviation from design:** no `@utility
      container` — in v4 `@utility container` *extends* the built-in (keeps its
      stepped `max-width`s) rather than replacing it, which would letterbox content
      between 640–1200px. Instead `app-shell.tsx`'s three `container` usages became
      explicit `mx-auto w-full max-w-[1200px] px-6` (the exact old behaviour:
      full-width minus a 1.5rem gutter, capped at 1200px, centred). — RF-03, RF-04
- [x] Deleted `web/tailwind.config.ts`; `components.json` `tailwind.config` → `""`. — RF-03
- [x] `web/src/components/ui/{dropdown-menu,select}.tsx`: `origin-[--radix-*]` and
      `max-h-[--radix-*]` → `(--radix-*)` (the bare-`[--x]` form is invalid in v4;
      `[var(--x)]` and `data-[x]:` forms still resolve and were left alone).
      Verified the compiled CSS emits `transform-origin:var(--radix-…)` /
      `max-height:var(--radix-…)`. — RF-05
- [x] Cross-check: `shadcn diff` reports "No updates found" (the command is a
      near-noop in the current CLI). Relied instead on `pnpm build` failing on any
      unresolved utility + the compiled-CSS inspection above. — RF-05, ADR-6
- [x] `pnpm format` re-sorted classes: `prettier-plugin-tailwindcss` 0.6→0.8 + v4
      changed the canonical order, so ~24 component files got a class-order-only
      diff (2–8 lines each, spot-checked — pure reordering, no semantic change). — RF-06
- [x] Visual check: built app + `next start`, screenshotted `/login` and `/setup`
      in light and OS-dark via Playwright. Both render correctly; dark mode inverts
      the primary button (light bg / dark text) exactly as the token design
      intends — `prefers-color-scheme` still drives the theme (RF-04 / ADR-8). The
      full walk of every route is folded into Stage 4's manual pass. — RNF-01, RF-04
- [x] Quality gate (Stage 2). — RF-11
      <!-- result: format:check / lint / typecheck / test (86) / build (Compiled
      successfully; per-route First Load JS +1–2 kB vs baseline, within RNF-03) /
      test:e2e with CI=1 from clean (1 passed) all green. docker build ./web is
      CI-only. -->

## Stage 3 — Next.js 16

- [x] `pnpm dlx @next/codemod@latest upgrade latest`. Bumped `next` 15.5.24 → 16.3.4,
      `react`/`react-dom` → 19.2.8 (pinned, like `next`), `@types/react*` pinned +
      a `pnpm.overrides` to dedupe them. It also added `export const instant = false`
      to 11 files for Cache Components — reverted, that feature is opt-in
      (`cacheComponents`) and unused here, and the app is all-client anyway (ADR-5).
      `next.config.ts`: removed the `eslint` key (Next 16 dropped it with
      `next lint`). `tsconfig.json`: Next 16 now owns it (rewrites `jsx` →
      `react-jsx`, `include`, re-indents on every build) — added to
      `.prettierignore`. — RF-07, ADR-5
- [x] `web/package.json`: `lint` script `next lint` → `eslint`. — RF-08
- [x] `web/eslint.config.mjs`: `eslint-config-next` 16 ships native flat config, so
      `FlatCompat` + `@eslint/eslintrc` are gone; `core-web-vitals` already bundles
      the TS rules; `prettier` (`eslint-config-prettier/flat`) stays last; `ignores`
      kept. `eslint` pinned to `^9.39.5` (a transitive bump had pulled ESLint 10,
      which `eslint-config-next` 16 does not support). Docstring refreshed. — RF-08
- [x] `pnpm lint` — the new `eslint-plugin-react-hooks` v6 (React Compiler rules)
      flagged three pre-existing patterns:
      - `report-preview.tsx` `set-state-in-effect`: moved the reset out of the
        effect into `onOpenChange` (fix).
      - `providers.tsx` `refs`: `useState(() => new QueryClient(…))` for the lazy
        init, handler rebind moved into a `useEffect`; the cache `onError` closures
        still read `handlerRef.current` (only ever on an async error, never during
        render) so `react-hooks/refs` is disabled for that block with a reason.
      - `scan-form.tsx` `incompatible-library`: `form.watch()` is RHF's supported
        API and has no compiler-friendly form — line-disabled with a reason.
      Also removed seven now-unused `eslint-disable` directives from test files.
      Ends at zero warnings and zero errors. — RF-08
- [x] `pnpm build`: **Turbopack** (Next 16 default), compiled successfully, all nine
      routes emit. `NEXT_OUTPUT_STANDALONE=1` build produces `.next/standalone/server.js`
      which boots and serves `/login` (200); the Dockerfile layout is unchanged.
      No fallback to `--webpack` needed. — RF-07, RF-09, ADR-4
      <!-- build engine used: Turbopack -->
- [x] `pnpm test:e2e` with `CI=1` from clean — 1 passed (Next 16 standalone rebuild
      + `next start` + real scan + report + logout, offline). — RF-09, RNF-02
- [x] Quality gate (Stage 3). — RF-11
      <!-- result: format:check / lint (eslint, 0/0) / typecheck / test (86) /
      build (Turbopack) / test:e2e (CI=1, clean, 1 passed) all green. Note: Next 16
      dropped the per-route First Load JS table from `next build` output, so RNF-03's
      exact size comparison is not reproducible; total `.next/static` JS is ~1.0 MB
      uncompressed, no new heavy deps were added, and the build is faster. -->

## Stage 4 — Rollout, docs, backlog

- [x] RNF-03: Next 16 removed the per-route First Load JS table from `next build`
      (both Turbopack and `--webpack`), so the Stage 0 comparison cannot be
      reproduced. Proxy check: total `.next/static` JS ~1.0 MB uncompressed;
      no new runtime deps; Tailwind v4's engine is lighter than v3's JIT and the
      build is faster. If a hard number is needed later, add `@next/bundle-analyzer`. — RNF-03
- [x] `docs/web-ui.md`: Node 20 → 24. (No `tailwind.config.ts` reference existed.) — RF-13
- [x] `CLAUDE.md`: stack line now names Next.js 16 / React 19 / Tailwind CSS v4 /
      Node 24; spec-status paragraph gained a 015 sentence. — RF-13
- [x] `specs/README.md`: added the `015-web-toolchain-modernization` roadmap row. — RF-13
- [x] `README.md`: the dashboard blurb names no toolchain version — no change. — RF-13
- [x] `web/pnpm-lock.yaml` holds the final versions. Dependabot PRs #7, #8, #10,
      #11 closed as superseded, each with a comment pointing to the merge (`86af1c4`). — RF-12
- [x] Full `web/` quality gate on the integrated branch. — RF-11
      <!-- result: on PR #13 (merged as 86af1c4) — web CI job green: lint, format,
      typecheck, test (86), build (Turbopack), test:e2e (offline), docker build
      ./web. quality (3.12) green; quality (3.13) flaked once on
      test_openapi_scan_is_deterministic (a pre-existing two-active-scan engine
      flake, unrelated to this spec) and passed on re-run. -->
- [x] Set this spec's three docs to `status: done`; run `/preparar-commits`. — —

## Baseline (Stage 0)

`pnpm test` — **86 passed** (24 files), vitest 4.1.11.

`pnpm build` — next 15.5.24, webpack:

```
Route (app)                                 Size  First Load JS
┌ ○ /                                      123 B         102 kB
├ ○ /_not-found                            989 B         103 kB
├ ○ /checks                              2.39 kB         159 kB
├ ○ /login                               6.51 kB         128 kB
├ ○ /scans                               5.34 kB         162 kB
├ ƒ /scans/[id]                          9.01 kB         184 kB
├ ○ /scans/new                           34.9 kB         184 kB
├ ○ /settings                             6.2 kB         125 kB
└ ○ /setup                               5.62 kB         128 kB
+ First Load JS shared by all             102 kB
```

RNF-03 budget: shared and per-route First Load JS within ~10% of these numbers.

