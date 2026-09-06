---
feature: Dependency fingerprinting — passive client-side library detection + known-vulnerability matching
status: done
date: 2026-09-06
related: [004-deps-fingerprint/requirements.md, 004-deps-fingerprint/design.md]
origin: conception
---

# 004 — Dependency fingerprinting — Tasks

Ordered, small tasks grouped by stage. Each references the requirement(s) / ADR(s) it
satisfies. The last task of every stage is a quality gate:

- Python stages → `/qualidade-python` + `uv run lint-imports`.
- The web stage → `pnpm lint && pnpm format:check && pnpm typecheck && pnpm test && pnpm build`
  (+ `pnpm gen:api` drift check, + `pnpm test:e2e`).

Work top to bottom; mark `[x]` after each. Write failing tests first where it pays (`rules`,
`advisories`, `fingerprint`, the checks, `mapping`). New engine code lives in
`src/webvigil/checks/deps/**` and a few files under `src/webvigil/core/**`; the API and web
changes are additive and traced.

---

## Stage 0 — Vendored database, provenance, refresh script, packaging

- [x] `scripts/update-retirejs-db.py`: `--source URL` (default the community
  `jsrepository-master.json`), `--dry-run`. GET via `urllib.request` (stdlib only), validate
  it parses, normalise (keep `extractors` + `vulnerabilities` per component, drop what
  WebVigil never reads), write `src/webvigil/checks/deps/data/retirejs.json` and refresh
  `data/PROVENANCE.json` (`source_url`, `upstream_commit`, `upstream_etag`, `retrieved`,
  `license`, `attribution`). Print a `N components, +X/-Y vulnerabilities` summary. — RF-21, RNF-06
- [x] Run the script for real; commit `data/retirejs.json` + `data/PROVENANCE.json`. — RF-06
- [x] `NOTICE` (repo root): record the bundled Retire.js data, Apache-2.0, with attribution. — RNF-06
- [x] `pyproject.toml`: add `webvigil/checks/deps/data/*.json` to package data / `include` so
  it ships in the wheel; decide `packaging` in `[project.dependencies]` vs. a vendored
  comparator (ADR-7 — leaning `packaging`). — design §Impact, ADR-7, Risks
- [x] Test: `webvigil.checks.deps` imports and loads the DB from its installed location
  (not a repo-relative path). — Risks
- [x] Quality gate.

## Stage 1 — Core model changes

- [x] `webvigil/core/findings.py`: un-comment `DEPS = "DEPS"` in `Category`. — RF-09
- [x] `webvigil/core/technology.py` (new): `DetectionMethod` (StrEnum: hash/sri/filename/
  filecontent/uri) and `Technology` (frozen pydantic: `name`, `version: str | None`,
  `detection`, `source_url`, `vulnerable: bool = False`, `advisories: tuple[str, ...] = ()`). — RF-12, ADR-8
- [x] `webvigil/core/result.py`: `ScanResult` gains `technologies: tuple[Technology, ...] = ()`. — RF-12
- [x] `webvigil/core/context.py`: add `Detection` (frozen dataclass) and `Observations`
  (mutable: `detections` tuple, `add_technology`/`add_warning`, `technologies` sorted+deduped
  property, `warnings` list); `ScanContext` gains
  `observations: Observations = field(default_factory=Observations)`. — RF-12, ADR-2
- [x] Tests: `Observations` dedupes on `(name, version)`, prefers concrete version + higher
  confidence, sorts by `(name, version or "")`; `ScanResult` with `technologies` round-trips
  through `model_dump_json` / `load_result`. — RF-12, RF-14, RNF-04
- [x] Quality gate.

## Stage 2 — Retire.js rule engine

- [x] `webvigil/checks/deps/rules.py`: `RetireJsRules.load(path=_VENDORED)` (`lru_cache`);
  compile `extractors.filename` / `filecontent` / `uri` templates, substituting `§§version§§`
  with a capturing version group; index `extractors.hashes` (sha1 → version); parse
  `vulnerabilities` ranges (`atOrAbove` / `below` / `.x` shorthand). `ConfigError` on a shape
  it can't compile. — RF-05, RF-06
- [x] `RetireJsRules.identify(url, body, sri_hash)` → `list[Detection]` (no advisory
  knowledge); `RetireJsRules.provenance` exposes the parsed `PROVENANCE.json`. — RF-01, RF-05
- [x] Tests: load the **real** vendored file and assert every extractor compiles and every
  range parses; with `tests/data/retirejs-mini.json`, `identify` returns the expected
  `Detection` for a filename, a banner, a hash, and a bare URL. — RF-05, Risks
- [x] Quality gate.

## Stage 3 — Advisory provider

- [x] `webvigil/checks/deps/advisories.py`: `Advisory` (frozen: `identifiers`, `summary`,
  `severity: Severity`, `severity_from_upstream: bool`, `first_safe_version: str | None`,
  `info_urls`, `cwe`), `AdvisoryProvider` Protocol (`match(name, version) -> list[Advisory]`),
  `RetireJsProvider(rules)`. — RF-07, RF-08, RF-11
- [x] Range evaluation with the version comparator (ADR-7); severity mapping
  (`low/medium/high/critical` → `Severity`, absent → `MEDIUM` + `severity_from_upstream=False`);
  `first_safe_version` = smallest fixed boundary above the detected version. — RF-07, RF-08
- [x] Tests: `match("jquery", "1.12.4")` → the CVE-2020-11022/11023 advisory;
  `match("jquery", "3.6.0")` → `[]`; `atOrAbove`-only, `below`-only, both, `.x` shorthand,
  pre-release versions; missing-severity entry; `first_safe_version`. — RF-07, RF-08, Risks
- [x] Quality gate.

## Stage 4 — Fingerprinter

- [x] `webvigil/checks/deps/fingerprint.py`: `Fingerprinter(http, rules, *, max_fetches=50)`;
  `async scan(pages)` — parse each HTML `Page` with `selectolax`, collect `<script src>`,
  `<link href>`, `integrity` values, and inline `<script>` text; resolve URLs against
  `page.url`. — RF-01, RF-03, RNF-01
- [x] Classify each referenced URL with `http`'s scope guard: in-scope + not already crawled
  → bounded GET queue; out-of-scope (CDN) → URL + SRI only, never fetched. Fetch the queue
  through `http.get`, swallow failures, stop at `max_fetches` and record the warning via a
  returned marker (the orchestrator adds it to `warnings`). — RF-03, RNF-07, ADR-5
- [x] Apply `rules.identify` per source (URL, SRI hash, body, inline script text); dedupe to
  one `Detection` per `(name, version)` preferring higher confidence + concrete version. — RF-02, RF-04, RF-05
- [x] Tests (hand-built `Page`s, `http` with a `MockTransport`): filename detection; inline
  banner detection; SRI hash → exact version; CDN script detected from URL and **not fetched**
  (`http.stats.requests` unchanged); `> max_fetches` in-scope resources → queue truncated +
  warning. — RF-01..04, RNF-07
- [x] Quality gate.

## Stage 5 — The DEPS checks

- [x] `webvigil/checks/deps/check.py`: module-level `_provider()` (lru-cached
  `RetireJsProvider(RetireJsRules.load())`). — RF-11
- [x] `VulnerableLibraryCheck` (`id="deps.js.vulnerable-library"`, `Category.DEPS`,
  `PASSIVE`, `default_severity=MEDIUM`): for each `ctx.observations.detections` with a
  version, `match`; on a hit emit a finding (severity = highest matched, per-finding
  `cwe`/`references` from the advisories, `dedup_key=f"{name}@{version}"`, evidence =
  detection + advisory ids, remediation = "Upgrade … to <first safe version> or later") and
  `add_technology(vulnerable=True, advisories=…)`; on a miss `add_technology(vulnerable=False)`. — RF-09, RF-12
- [x] `LibraryDetectedCheck` (`id="deps.js.library-detected"`, `Category.DEPS`, `PASSIVE`,
  `default_severity=INFO`): for each detection with `version is None`, emit one INFO finding
  and `add_technology(vulnerable=False)`. — RF-10, RF-12
- [x] `webvigil/checks/deps/__init__.py`: import both checks so `@register` runs; ensure the
  package is imported by the default check discovery path. — RF-15
- [x] Tests (seed `ctx.observations.detections` directly, no HTTP): vulnerable finding shape
  + inventory entry; INFO only for `version is None`; both checks run concurrently → exactly
  one inventory entry per library; disabling an id removes its findings. — RF-09, RF-10, RF-15, Risks
- [x] Quality gate.

## Stage 6 — Orchestrator wiring and staleness

- [x] `webvigil/checks/deps/staleness.py`: `STALE_AFTER_DAYS = 90`,
  `staleness_warning(rules) -> list[str]` from `rules.provenance.retrieved`. — RF-22
- [x] `webvigil/core/orchestrator.py`: after `_select_checks`, if any selected check is
  `Category.DEPS`, load the rules, run `Fingerprinter(http, rules).scan(pages)`, seed
  `Observations(detections=…)`, and `warnings.extend(staleness_warning(rules))`; after
  `_run_checks`, `warnings.extend(context.observations.warnings)` and pass
  `technologies=context.observations.technologies` to `ScanResult`. — RF-12, RF-22, ADR-1, ADR-3
- [x] Tests: DEPS checks disabled → Fingerprinter not run (`http.stats.requests` = crawl
  only), `result.technologies == ()`; enabled → inventory populated, `vulnerable` flags
  correct; a stale provenance date → warning present in `result.warnings`. — RF-12, RF-22, ADR-3
- [x] Quality gate.

## Stage 7 — Reporters and CLI

- [x] `webvigil/reporting/html.py` + `markdown.py`: a "Detected technologies" section
  (name, version or "unknown", detection method, a text "vulnerable" marker) rendered when
  `result.technologies` is non-empty; HTML reuses the existing severity-token CSS. JSON and
  SARIF unchanged. — RF-13, RNF-05
- [x] `webvigil/cli/_render.py`: add the summary line
  `"Detected N client-side libraries (M with known vulnerabilities)"` when
  `result.technologies`. — RF-16
- [x] `webvigil/cli` `version` command: print `staleness_warning` to stderr when stale. — RF-22
- [x] Tests: HTML + Markdown contain the section with the vulnerable row marked; JSON
  round-trips `technologies`; SARIF has the `deps.js.vulnerable-library` rule; the CLI
  summary line; `version` prints the staleness note for a stale fixture DB and nothing for a
  fresh one. — RF-13, RF-14, RF-16, RF-22
- [x] Quality gate.

## Stage 8 — Fixture app and integration tests

- [x] `tests/fixtures/app.py`: the **insecure** profile serves a page referencing a
  self-hosted `jquery-1.12.4.min.js` (with the `/*! jQuery v1.12.4 */` banner) and serves
  that file; the **hardened** profile references a current version or none. — RF-19
- [x] Integration test: scan the insecure profile → `deps.js.vulnerable-library` present
  with the expected identifiers and a `technologies` entry `vulnerable=true`; scan the
  hardened profile → **zero** `DEPS` findings. — RF-19, RNF-05
- [x] Quality gate.

## Stage 9 — Web API amendment (additive, traces to spec 002)

- [x] `webvigil/api/db.py`: `Scan` gains
  `technologies: list[dict] = Field(default_factory=list, sa_column=Column(JSON))`. — RF-17
- [x] `webvigil/api/migrations/versions/0002_scan_technologies.py`: `add_column` /
  `drop_column` inside `batch_alter_table`; extend the metadata-diff test. — RF-17, ADR-8
- [x] `webvigil/api/mapping.py`: `store_result` writes
  `[t.model_dump() for t in result.technologies]`; `rows_to_result` rebuilds
  `tuple(Technology(**t) …)` (treat `None`/missing as `[]`). — RF-17, RF-14
- [x] `webvigil/api/schemas.py`: `ScanOut` gains `technologies: list[TechnologyOut]` (detail
  payload only, not `ScanSummary`). — RF-17
- [x] `uv run python scripts/dump-openapi.py` → commit the updated `web/openapi.json`. — RF-17
- [x] Tests: `store_result` → `rows_to_result` round-trips `technologies`;
  `GET /api/scans/{id}` returns them; migration `0002` `upgrade`/`downgrade` on a tmp DB; a
  scan row created before the column reads back as `[]`. — RF-17, RF-19
- [x] Quality gate.

## Stage 10 — Web UI amendment (additive, traces to spec 003)

- [x] `web/`: `pnpm gen:api` → regenerate `src/lib/api-types.ts` from the updated
  `openapi.json`. — RF-18, spec 003 RF-03
- [x] `web/src/components/technologies-table.tsx`: `TechnologiesTable({ items })` — a
  `<section>` + `<h2>Detected technologies</h2>` + table (library, version or "unknown",
  detection method, a "Vulnerable" tag linking to
  `?check_id=deps.js.vulnerable-library`); hidden when `items` is empty. — RF-18
- [x] `web/src/app/(app)/scans/[id]/page.tsx`: render
  `<TechnologiesTable items={s.technologies} />` between the metadata `<dl>` and the
  "Findings" section. — RF-18
- [x] `web/`: component test (`renderWithClient`, a `ScanOut` fixture with a vulnerable and a
  clean entry, empty-state hidden) + include the screen in the existing `jest-axe`
  assertion. — RF-18, spec 003 RNF-03, RNF-05
- [x] `web/e2e/smoke.spec.ts`: after the fixture scan reaches `completed`, assert the
  "Detected technologies" section lists the seeded vulnerable library. — RF-18, spec 003 RNF-04
- [x] Web quality gate (`pnpm lint && pnpm format:check && pnpm typecheck && pnpm test &&
  pnpm build`, `api-types.ts` drift check, `pnpm test:e2e`).

## Stage 11 — Docs, roadmap, verification, close

- [x] `docs/dependency-fingerprinting.md` (new): how detection works (sources, confidence
  tiers), the vendored DB + `PROVENANCE.json`, running `update-retirejs-db.py`, the
  limitations (no version → no match; CDN scripts URL/SRI only; no reachability; `max_fetches`
  cap), and that disabling both `deps.*` ids disables the pass. — RNF-09, ADR-3
- [x] `docs/architecture.md`: a DEPS/fingerprint note in the engine layer. `README.md`: the
  check list gains the two ids + a link to the new doc. `CLAUDE.md`: architecture summary +
  the `scripts/update-retirejs-db.py` command. — RNF-09
- [x] `specs/README.md`: mark `004-deps-fingerprint` **done**; set `requirements.md`,
  `design.md`, `tasks.md` `status: done`. — RNF-09
- [x] Manual verification: `webvigil scan` against the insecure fixture shows the summary
  line + the finding; `webvigil report --format html/md` shows the section; `webvigil-web`
  migrate + serve, run a scan through the dashboard, confirm "Detected technologies" renders;
  `webvigil version` with a back-dated `PROVENANCE.json` shows the staleness note.
- [x] Final full quality gate (`/qualidade-python` + `uv run lint-imports` + the web gate).
