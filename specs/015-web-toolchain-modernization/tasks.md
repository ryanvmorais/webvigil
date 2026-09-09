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

- [ ] `web/package.json`: remove `tailwindcss@^3` and `tailwindcss-animate`; add
      `tailwindcss@^4`, `@tailwindcss/postcss@^4`, `tw-animate-css` (all dev); set
      `tailwind-merge` to `^3`. `pnpm install`. — RF-03, RF-05
- [ ] `web/postcss.config.mjs`: plugin → `@tailwindcss/postcss`; refresh the file
      docstring. — RF-03
- [ ] `web/src/app/globals.css`: rewrite to the v4 form per design §Components/Stage 2 —
      `@import "tailwindcss"`, `@import "tw-animate-css"`, unchanged `:root` + dark
      `@media` token blocks, `@theme inline` token map, `@utility container`,
      `@keyframes accordion-*`, base layer. Every `--token` value byte-identical to
      today. Refresh the file docstring. — RF-03, RF-04
- [ ] Delete `web/tailwind.config.ts`; set `components.json` → `"tailwind": { "config": "" , … }`. — RF-03
- [ ] `web/src/components/ui/*.tsx`: change the CSS-variable arbitrary-value syntax
      `[--radix-*]` → `(--radix-*)` (dropdown-menu, select, and any other hit); leave
      literal arbitrary values like `min-w-[8rem]` as they are. — RF-05
- [ ] Cross-check the `ui/*` diff against a fresh shadcn CLI generation
      (`pnpm dlx shadcn@latest diff`, or generate into a temp dir and diff);
      reconcile anything beyond the syntax edit, note why the files diverge from a
      bare CLI output (local docstrings). — RF-05, ADR-6
- [ ] `pnpm format` so `prettier-plugin-tailwindcss` re-sorts v4 classes; review the
      diff. — RF-06
- [ ] Visual check: `pnpm dev`, walk every route and open the dialog / dropdown /
      select primitives; toggle the OS dark mode; confirm colors, spacing, radius and
      typography are unchanged. — RNF-01, RF-04
- [ ] Quality gate (Stage 2). — RF-11
      <!-- result: -->

## Stage 3 — Next.js 16

- [ ] `pnpm dlx @next/codemod@canary upgrade latest`; review the diff hunk by hunk —
      expect `package.json` bumps (`next` 16, `eslint-config-next` 16, `react` /
      `react-dom` / `@types/react*` within `^19`) and no `src/` route changes. — RF-07, ADR-5
- [ ] `web/package.json`: `lint` script `next lint` → `eslint`. — RF-08
- [ ] `web/eslint.config.mjs`: reconcile for `eslint-config-next` 16 — keep the
      `ignores` block, keep the rule order with `"prettier"` last; drop `FlatCompat` /
      `@eslint/eslintrc` only if v16 exports a flat config directly, otherwise keep
      the compat shim. Refresh the file docstring. — RF-08
- [ ] `pnpm lint`: resolve every new violation (fix, or disable with a reason);
      end at zero warnings. — RF-08
- [ ] `pnpm build`: confirm the Turbopack build succeeds, all nine routes emit, and
      `output: "standalone"` produces `server.js`. If standalone or the baked
      `rewrites()` break, set the build script to `next build --webpack` and record
      it here. — RF-07, RF-09, ADR-4
      <!-- build engine used: -->
- [ ] `pnpm test:e2e`: the offline Playwright flow passes end to end. — RF-09, RNF-02
- [ ] Quality gate (Stage 3). — RF-11
      <!-- result: -->

## Stage 4 — Rollout, docs, backlog

- [ ] Compare the `pnpm build` route/size table with the Stage 0 baseline; confirm
      within ~10% or explain the delta in a note here. — RNF-03
      <!-- delta: -->
- [ ] `docs/web-ui.md`: Node 20 → 24; drop or adjust the `tailwind.config.ts`
      reference. — RF-13
- [ ] `CLAUDE.md`: stack line (name Tailwind v4 / Next 16 only if a version is
      given); the spec-status paragraph — add 015, update "Nenhuma spec em
      andamento". — RF-13
- [ ] `specs/README.md`: add the `015-web-toolchain-modernization` roadmap row with
      its scope and status. — RF-13
- [ ] `README.md`: check the stack blurb; change only if it names a toolchain
      version. — RF-13
- [ ] Confirm `web/pnpm-lock.yaml` holds the final versions; close Dependabot PRs
      #7, #8, #10, #11 with a comment pointing to this spec and the merge. — RF-12
- [ ] Full `web/` quality gate on the integrated branch; record the result. — RF-11
      <!-- result: -->
- [ ] Set this spec's three docs to `status: done`; run `/preparar-commits` and
      `/atualizar-docs`. — —

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

