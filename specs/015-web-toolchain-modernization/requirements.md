---
feature: Web toolchain modernization — Node 24, Tailwind CSS v4, Next.js 16
status: in progress
date: 2026-09-09
related:
  - 003-web-ui/requirements.md
origin: conception
---

# 015 — Web toolchain modernization

## Context and problem

Dependabot version updates were enabled for the repository (`6513d77`). The CI
actions bumps (`checkout`, `setup-node`, `pnpm/action-setup`), `next` 15.5.24,
`vitest` 4 and `@testing-library/jest-dom` 7 have already landed on `main`. Four
open Dependabot PRs cannot be merged as plain bumps because each one is the
visible tip of a migration:

- **#8 `@types/node` 20 → 26.** Node 20 reached end of life on 2026-04-30. The
  types are only a symptom: `.github/workflows/ci.yml`, `Dockerfile`,
  `web/Dockerfile` and `docs/web-ui.md` all pin Node 20, and `web/package.json`
  has no `engines` floor at all.
- **#11 `tailwindcss` 3.4 → 4.3.** Tailwind v4 is a new engine with a different
  build pipeline (`@tailwindcss/postcss`), CSS-first configuration (`@theme`
  instead of `tailwind.config.ts`), a changed arbitrary-value syntax that the
  shadcn/ui components use, and no bundled `tailwindcss-animate`.
- **#10 `tailwind-merge` 2 → 3.** v3 is built for Tailwind v4's theme scale;
  running it against v3 merges classes incorrectly. It can only move with #11.
- **#7 `eslint-config-next` 15.1.6 → 16.3.4.** The Next ESLint preset tracks the
  framework major. Adopting it means upgrading Next.js 15 → 16, where the
  `next lint` command is removed and the ESLint integration changes.

The `web/` dashboard is therefore one major behind on both of its framework
pillars (Next 15.5, Tailwind 3.4) and running on an unsupported Node. This spec
brings the whole `web/` toolchain current in one coordinated pass, keeping every
existing quality gate green and the dashboard visually unchanged.

The Python side of the project (engine, CLI, Web API, Alembic, `uv` graph) is
**not** touched — its Dependabot PRs are handled independently under
`/revisar-dependabot`.

## Objectives

- Move the entire `web/` toolchain off end-of-life Node 20 to Node 24 (Active
  LTS): CI, both Docker images, and an explicit `engines` floor.
- Upgrade Tailwind CSS 3 → 4, including `tailwind-merge` 3 and a replacement for
  `tailwindcss-animate`, with the design tokens and OS-only dark mode of spec
  003 preserved exactly.
- Upgrade Next.js 15 → 16, including `eslint-config-next` 16 and the migration
  off the removed `next lint` command.
- Keep every gate that guards `web/` green with no regression: `pnpm lint`,
  `format:check`, `typecheck`, `test` (86 unit tests), `build`, `test:e2e`
  (offline Playwright), and `docker build ./web`.
- Retire Dependabot PRs #7, #8, #10 and #11 (merged, superseded, or closed with
  the lockfile updated by this spec).
- Update the documentation that references the old versions.

## Non-objectives

- No changes to the engine, CLI, Web API, database, or the `uv` dependency graph.
- No visual redesign. The dashboard renders the same before and after; this is a
  toolchain migration, not a UI change.
- No new features, routes, components, or dependencies beyond what the three
  upgrades require.
- Not adopting Tailwind v4 capabilities beyond the migration (no palette rework,
  no container-query features, no new tokens).
- Not changing the package manager (`pnpm`), the test runner (`vitest`), the
  component library (shadcn/ui), or the data layer (TanStack Query).
- Not forcing a React upgrade. React stays on the `^19` range; whatever minor
  Next 16 requires within that range is acceptable, nothing more.
- No hosted deployment or infrastructure change (the project stays repo-only).

## Personas

- **As the maintainer,** I want the `web/` toolchain on a supported Node and on
  current framework majors, so that Dependabot stays quiet, security patches
  keep applying cleanly, and the build does not drift further behind.
- **As a contributor,** I want `pnpm install && pnpm dev` to work on a current
  Node LTS without engine warnings or peer-dependency conflicts.

## Functional requirements

### Node runtime

#### RF-01 — Node 24 across every environment that runs the dashboard

- **Given** the CI `web` job
  **When** it sets up Node
  **Then** it uses Node 24 (`node-version: 24`), and the `quality`/`docker` jobs
  are unaffected.
- **Given** `web/Dockerfile` (the only Node image; the root `Dockerfile` and
  `docker/target.Dockerfile` are Python 3.12 and out of scope)
  **When** it selects a base image
  **Then** every stage uses a `node:24-alpine` (or the pinned equivalent) base,
  and the image still builds in CI.
- **Given** `web/package.json`
  **When** a contributor runs `pnpm install` on Node older than the floor
  **Then** `engines.node` declares `>=24` (or the agreed range) and pnpm warns.

#### RF-02 — `@types/node` aligned to the runtime major

- **Given** the dev dependencies
  **When** `@types/node` is pinned
  **Then** its major matches the Node the project targets (24), and `tsc
  --noEmit` passes.
- **Given** Dependabot PR #8 (which proposes `26.x`)
  **When** this spec lands
  **Then** the PR is closed as superseded, or retargeted, so the installed
  version matches the runtime rather than running ahead of it.

### Tailwind CSS v4

#### RF-03 — Tailwind v4 build pipeline

- **Given** `web/postcss.config.mjs`
  **When** the build runs
  **Then** it uses `@tailwindcss/postcss`, `tailwindcss` 4.x is installed, and
  `pnpm build` emits the same set of utilities the components use.
- **Given** `web/src/app/globals.css`
  **When** Tailwind processes it
  **Then** the v3 `@tailwind base/components/utilities` directives are replaced
  by the v4 entry (`@import "tailwindcss"`), and no utility class in the app or
  in `components/ui/*` fails to resolve.

#### RF-04 — Design tokens and dark mode preserved

- **Given** the shadcn "slate" token set and the `--severity-*` scale in
  `globals.css`
  **When** they are migrated to the v4 convention
  **Then** every token keeps its current value in light and dark, and the
  utilities that consume them (`bg-background`, `text-severity-high`, `border`,
  the `border-severity-*` classes in `src/lib/severity.ts`, …) resolve to the
  same computed colors.
- **Given** spec 003 RF-02 / ADR-8 (theme follows the OS; no `.dark` class, no
  toggle)
  **When** dark mode is configured in v4
  **Then** it still keys off `prefers-color-scheme` only, with no class-based
  dark variant introduced.

#### RF-05 — shadcn/ui components and the class merger on v4

- **Given** the 11 files in `web/src/components/ui/`
  **When** Tailwind v4 processes their class lists
  **Then** the arbitrary-value / CSS-variable syntax is updated to what v4
  accepts, the animation utilities (`animate-in`, `fade-out-0`, `zoom-out-95`,
  `slide-in-from-top-2`, `animate-spin`, the `accordion-*` keyframes) still
  work, and every component renders as before.
- **Given** `src/lib/utils.ts` (`cn` = `twMerge(clsx(...))`)
  **When** `tailwind-merge` is upgraded to 3.x
  **Then** `cn` still de-duplicates conflicting classes correctly for the v4
  scale, verified by the existing component tests.

#### RF-06 — class sorting still enforced

- **Given** `prettier-plugin-tailwindcss`
  **When** `pnpm format:check` runs
  **Then** it sorts v4 classes without error and the tree is already formatted.

### Next.js 16

#### RF-07 — Next 16 upgrade

- **Given** `next` 16.x installed
  **When** `pnpm build` runs
  **Then** all nine routes build (`/`, `/login`, `/setup`, `/checks`, `/scans`,
  `/scans/new`, `/scans/[id]`, `/settings`, `/_not-found`), with no use of an
  API removed in 16.
- **Given** `pnpm dev`
  **When** the dashboard is opened
  **Then** it boots and every route renders against a running Web API.

#### RF-08 — `next lint` replaced

- **Given** Next 16 removes the `next lint` command
  **When** the lint gate runs
  **Then** `pnpm lint` calls the ESLint CLI directly, `eslint-config-next` 16 is
  wired via its flat config, the current rule coverage (`next/core-web-vitals`,
  `next/typescript`, `jsx-a11y`, `prettier` last) is preserved, and the
  `ignores` list still covers generated paths.
- **Given** the existing code
  **When** the new lint runs
  **Then** it reports no warnings or errors (any new rule violations are fixed
  or explicitly disabled with a reason).

#### RF-09 — standalone output and the API proxy still work

- **Given** spec 003 RNF-06 (the `/api/*` proxy is baked at build time; no
  cross-origin calls) and the standalone Docker output
  **When** Next 16 builds with `output: "standalone"` and `rewrites()`
  **Then** `web/Dockerfile` produces a working image and the Playwright e2e flow
  (rebuild with the e2e API port → `next start` → real scan → report → logout,
  fully offline) passes.

#### RF-10 — build engine decision recorded

- **Given** Next 16 defaults `next build` to Turbopack
  **When** this spec's design is written
  **Then** it records whether the project adopts Turbopack or opts out to
  webpack, with the reason, as an ADR.

### Verification and rollout

#### RF-11 — the full web gate is green

- **Given** all three upgrades applied
  **When** CI runs
  **Then** `pnpm lint`, `pnpm format:check`, `pnpm typecheck`, `pnpm test`
  (86 passing), `pnpm build`, `pnpm test:e2e`, `docker build ./web` and the
  root `docker` job all pass.

#### RF-12 — Dependabot backlog retired

- **Given** PRs #7, #8, #10, #11
  **When** this spec lands on `main`
  **Then** each is merged, closed as superseded, or rebased to a no-op, and
  `web/pnpm-lock.yaml` reflects the final versions.

#### RF-13 — documentation updated

- **Given** `docs/web-ui.md`, `README.md`, `CLAUDE.md`, `specs/README.md`
  **When** the versions change
  **Then** every reference to Node 20, Tailwind 3 / the `tailwind.config.ts`
  workflow, and Next 15 is corrected, and the spec 015 roadmap row is added.

## Non-functional requirements

### RNF-01 — no visual regression

- **Given** the dashboard before and after the migration
  **When** each route is viewed at the same breakpoints
  **Then** layout, spacing, colors, and typography are unchanged; the e2e run is
  the automated backstop and any remaining check is manual per route.

### RNF-02 — offline build and test

- **Given** spec 003 RNF-04 (the e2e suite runs fully offline)
  **When** the toolchain changes
  **Then** no build step or runtime path adds a network dependency, and
  `pnpm test:e2e` still runs with no outbound traffic.

### RNF-03 — bundle size does not regress

- **Given** the current First Load JS (~105 kB shared, routes 106–188 kB)
  **When** the upgraded build is measured
  **Then** the shared and per-route sizes are within roughly 10% of current, or
  the increase is explained in the design.

### RNF-04 — engine isolation intact

- **Given** the `import-linter` contract (the engine never imports UI code)
  **When** the migration completes
  **Then** nothing in `web/` is imported by the Python packages and the contract
  check is unaffected (the boundary is one-directional and stays that way).

### RNF-05 — Docker image posture unchanged

- **Given** `web/Dockerfile` ships the Next standalone output as a non-root user
  **When** the base image moves to Node 24
  **Then** the image still runs as `nextjs:nodejs`, exposes 3000, and its size
  stays in the same range.

## Open questions

1. **Turbopack for `next build`.** Next 16 makes Turbopack the default build
   engine. Adopt the default, or pass `--webpack` to keep the current behavior
   for the standalone + proxy build? Leaning: adopt the default and fall back
   only if the standalone output or the baked `rewrites()` misbehave.
2. **Tailwind v4 configuration form.** Keep a JS `tailwind.config.ts` bridged
   via `@config`, or go fully CSS-first with `@theme` in `globals.css`? Leaning:
   CSS-first, to match the shadcn v4 convention and avoid a config file that
   Dependabot will keep bumping.
3. **`tailwindcss-animate` replacement.** Adopt `tw-animate-css` (the community
   successor shadcn moved to), or drop the dependency and inline the handful of
   keyframes actually used (`accordion-*`, and the `animate-in` family from the
   dialog/dropdown/select components)? Leaning: `tw-animate-css`, to keep the
   `components/ui/*` files regenerable from the shadcn CLI.
4. **shadcn `components/ui/*` migration method.** Regenerate the 11 files from
   the shadcn CLI at v4, or hand-migrate them? Leaning: hand-migrate (the set is
   small and the files carry local docstring/style conventions), using a CLI
   diff as a cross-check.
5. **`engines.node` strictness.** Declare `>=24` only, or a bounded
   `>=24 <25`? And set `engine-strict` in `.npmrc`, or leave it a warning?
   Leaning: `>=24`, warning only.

## Tests

### RF group — the CI `web` job is the contract

The migration is complete only when the `web` job passes end to end. That job
runs, in order: generated OpenAPI types current → `pnpm lint` → `pnpm
format:check` → `pnpm typecheck` → `pnpm test` (vitest, 86 tests) → `pnpm build`
→ `pnpm test:e2e` (Playwright, offline) → `docker build ./web`. The root
`docker` job (CLI image) must also stay green.

### RNF group — regression backstops

- **Visual:** the Playwright flow exercises setup, login, a real scan, the
  report menu, and logout; it is the automated no-visual-regression check.
  Anything it does not cover (the checks catalogue, settings, empty/error
  states) is verified manually once.
- **Bundle:** capture `pnpm build`'s route table before and after; compare.
- **Offline:** run `pnpm test:e2e` with no network and confirm it passes (it
  already asserts unmocked requests error out).
