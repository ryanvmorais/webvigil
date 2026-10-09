---
feature: HAR import — seed the crawl and the injection points of a single-page application from recorded browser traffic
status: draft
date: 2026-10-09
related:
  - 021-har-import/requirements.md
  - 021-har-import/design.md
origin: conception
---

# 021 — HAR import — Tasks

Ordered, small, each tagged with the requirement / ADR it satisfies. The last task of every stage is
the quality gate (`ruff check .` → `black --check .` → `mypy src` → `lint-imports` → `pytest`; the
suite's config hides the summary line, so the result recorded is the exit code and the count from
`--co -q`). Engine and CLI only: no `web/` gate, no API migration, no `web/openapi.json` change
(RNF-06). Tests follow `specs/README.md`, "Testes de uma spec": logic in unit, integration attached to the
shared full scan, no determinism test of its own, about one test line per `src/` line.

Work happens on a branch cut from `main` **after** the spec PR (#185) is merged: `feat/har-import`, one
PR, `Closes #146`, CHANGELOG `[Unreleased]` in the same PR.

Baseline: _(record the passing count on `main` before Stage 0)_.

## Stage 0 — Plumbing: error, config, `ApiOperation`, injection source

- [ ] `webvigil/core/errors.py`: `class HarError(WebVigilError)` with a docstring (a missing, oversized
  or unreadable file, invalid JSON, a document without `log.entries`; a bad entry is not this error).
  — RF-01, RF-02, ADR-6
- [ ] `webvigil/core/config.py`: `ScanSection.har: str | None = None` and `har_max_operations: int =
  Field(default=150, gt=0)` with their `Attributes:` lines; the `with_overrides` docstring names
  `[scan] har`. — RF-12, ADR-7
- [ ] `webvigil.example.toml`: commented `[scan] har` and `har_max_operations`, with the CLI flag, next
  to the `openapi` keys. — RF-12
- [ ] `webvigil/crawler/openapi.py`: `ApiOperation.source: str = "openapi"` and the `seed_url` property
  (`url` for `"openapi"`, `url?urlencode(query)` for `"har"` when the query is not empty); the `Attributes:`
  docstring lines. — ADR-1, ADR-2
- [ ] `webvigil/checks/injection/points.py`: `_operation_points` uses `source=operation.source` in its
  GET and POST branches (the path-parameter branch keeps `"openapi-path"`); the `enumerate_points`
  docstring says "imported operation". `checks/injection/models.py`: the `InjectionPoint.source`
  docstring lists `"har"`. — RF-06, ADR-1
- [ ] Grep `src/webvigil/api/` and `web/src/` for a hardcoded list of point sources or scan options;
  confirm neither needs a change (the stored `Scan.options` and the OpenAPI schema stay as they are).
  — RF-12
- [ ] Tests: `test_crawler_openapi.py` (an OpenAPI operation has `source == "openapi"` and
  `seed_url == url`; a `"har"` operation's `seed_url` carries the query, none when the query is empty);
  `test_injection_points.py` (a `source="har"` GET and POST operation give `"har"` points; a parameter the
  crawl and a HAR operation share is one point); `test_config.py` (the defaults, the TOML keys,
  `har_max_operations = 0` is a `ConfigError`). — RF-06, RF-12, ADR-1, ADR-2
- [ ] Quality gate. — _(record the result)_

## Stage 1 — The importer: `webvigil/crawler/har.py`

- [ ] Module docstring (what it imports, what it never reads, the layering: no `webvigil.checks`) and the
  constants with their comments: `_MAX_FILE_BYTES` (64 MiB), `_MAX_ENTRIES` (20,000), `_MAX_VALUE` (256),
  `_MAX_URL` (2048), `_MAX_NAME` (128), `_PLACEHOLDER` (`"wv"`), `_STATIC_TYPES`, `_DYNAMIC_TYPES`,
  `_STATIC_MIME`, `_STATIC_EXT`, `_SECRET_WORDS`. — RNF-01, RNF-02, ADR-7
- [ ] `HarTally`, `HarImport` and `HarImport.summary()` (zero categories left out; the RF-11 wording, with
  "out of scope" for a foreign host or scheme). — RF-11
- [ ] `load_har(path, *, target, max_operations)`: the `://` check, the missing-path check, the size
  check before reading, `utf-8-sig` decode, `json.loads` with `ValueError` and `RecursionError` →
  `HarError("not a HAR file")`, the `log.entries` list check, the entry cap with its warning. — RF-01,
  RF-02, RF-11, RNF-02, ADR-6
- [ ] `_classify(entry, target)`: well-formed → URL → scope (`target.in_scope` and the target's scheme) →
  method → static → unsafe (`looks_unsafe_operation`), returning an operation or a tally field name; the
  scope step before the method step. — RF-02, RF-03, RF-04, RF-09, ADR-5
- [ ] `_is_static(entry)`: `_resourceType`, then `response.content.mimeType`, then the URL extension; only
  those fields are indexed. — RF-04, ADR-3
- [ ] `_operation(entry, target, ...)`: the URL rebuilt without userinfo and fragment; the query from
  `queryString` with the `parse_qsl` fallback; the body from `postData` (urlencoded, multipart text parts
  from `params` or the raw text, JSON, other); the operation has `source="har"`, `operation_id=""`,
  `path_params=()`, `url_template == url`. — RF-05, RF-06, ADR-1, ADR-8
- [ ] `_SECRET_NAME_RE` / `_is_secret_name(name)` (camelCase split, `_` and `-` as breaks, whole words,
  optional plural) and `_scrub(name, value)`; applied to every query value and form field value. — RF-07,
  ADR-4
- [ ] `_json_shape(text)`: typed placeholders, one element per array, depth 4, 24 keys, the
  `openapi._MAX_BODY_UNITS` bound; invalid JSON or a bare scalar → `None`. — RF-06, ADR-4
- [ ] Dedup by `_key`, the stable sort, the `max_operations` cap with its warning, the empty-result
  warning, and `authenticated` (header **names** and the cookie-list length only). — RF-05, RF-08, RF-11,
  RNF-03, ADR-3, ADR-7
- [ ] `merge_operations(primary, secondary)`. — RF-01
- [ ] Tests `tests/unit/test_crawler_har.py` (strategy in the design): the per-tool documents as a
  parametrized table; each filter and its tally; the build cases; the secret-name tables (positive and
  negative) and the 256-character bound; `authenticated`; the adversarial file (no recognisable secret in
  the serialised `HarImport`); the caps (an oversized sparse file is refused without being read, the entry
  cap, `max_operations`, `RecursionError`); the fatal errors; a BOM; the same file twice gives the same
  result; `merge_operations`. — RF-01 … RF-11, RNF-02, RNF-03, RNF-05, RF-14
- [ ] Quality gate (`lint-imports` proves `crawler.har` imports nothing from `checks`). — _(record the
  result)_

## Stage 2 — Wiring: orchestrator, CLI, JavaScript-app warning

- [ ] `webvigil/core/orchestrator.py`: `_load_har(target, warnings)` after `_load_openapi` (a no-op when
  `[scan] har` is unset; appends `har.warnings` and `har.summary()`; appends the "looks authenticated"
  warning when `har.authenticated` and the scan has no `[auth] cookies`, `[auth] headers` or
  `[auth.login]`); `operations = merge_operations(openapi_ops, har_ops)`; `extra_seeds` uses
  `op.seed_url`; the `run` and `_load_har` docstrings name `HarError`. — RF-01, RF-08, RF-10, RF-11,
  ADR-1, ADR-2
- [ ] `webvigil/crawler/jsapp.py`: `script_app_warning(pages, *, har=False)` with the new sentence; the
  orchestrator passes `har=bool(self._config.scan.har)`. — RF-13
- [ ] `webvigil/cli/app.py`: `--har PATH` option (help text: a local `.har` file recorded in a browser or
  a proxy), `_build_config(har=...)` and `scan_overrides["har"]`, the docstrings. — RF-01, RF-12
- [ ] Confirm the result's metadata does not carry the `[scan]` table or the HAR path (read
  `ScanResult` construction in the orchestrator); add a one-line test if it could. — RF-07, RNF-05
- [ ] Tests: `test_orchestrator.py` (HAR operations reach the `Crawler` as seeds with their query and as
  `post_operations`; the merge with OpenAPI; the two warnings and their absence; a `HarError` is fatal
  before any request); `test_crawler_jsapp.py` (the new sentence, with and without `har=True`);
  `test_cli.py` (`--har` overrides `[scan] har`; a bad file exits 4); `tests/api/test_mapping.py` (a
  stored `har` option never reaches the config) and `tests/api/test_scans.py` (a `har` field in the
  request body is ignored and the scan's config has none). — RF-01, RF-08, RF-12, RF-13, RF-14
- [ ] Quality gate. — _(record the result)_

## Stage 3 — Fixture app and integration

- [ ] `tests/fixtures/app.py`: `GET /spa/items?name=`, linked from no page, both profiles (insecure
  reflects `name` unescaped, hardened escapes it); fixture tests only for what guards a security
  invariant, none for the plain answer. — RF-06, RF-14
- [ ] `tests/integration/test_scan_fixture_app.py`: a `har` option on `_run` / `_execute` (the path goes
  to `raw["scan"]["har"]`); a session fixture that writes the HAR under `tmp_path_factory` (the
  `/spa/items?name=widget` entry; a foreign-host entry; a static asset; a `DELETE`; a login `POST`; an
  entry with `Cookie` / `Authorization` headers and a `?token=` URL; a JSON `POST` to an `/api/` route);
  `_full` passes its path. — RF-14
- [ ] Scenarios on the existing full scans (no new scan except one small unauthenticated scan for the
  warning): the unlinked route is in `pages_scanned`; the insecure scan hits it with a point whose
  `source` is `har`, the hardened scan reaches it and reports nothing; no request reaches the foreign host,
  the login route or the `DELETE`; no secret string of the file appears in the JSON, SARIF, Markdown or HTML
  report; the POST operation is posted once with the recorded shape in the Active scan and never in a
  Passive one; the summary warning has the right tallies; the "looks authenticated" warning appears in the
  small scan that has no auth. — RF-03 … RF-10, RNF-04, RNF-05
- [ ] Re-measure the integration config's budgets (`request_budget`, envelope sample) now that the
  fixture has a point and a page more; bump only what the measurement shows is starving, test-only, as 018
  did. — Test strategy
- [ ] Quality gate: the full suite with `--cov`; record the time against the ~10 minute budget and the
  test-line / source-line ratio. — RNF-07, _(record the result)_

## Stage 4 — Documentation, manual check, close-out

- [ ] `docs/api-scanning.md`: a "HAR import" section (how to record in Chrome, Edge, Firefox, Burp, ZAP
  and mitmproxy; what is imported and what is skipped and why; secrets; the caps; the multipart and
  GraphQL limits; record a read-only walk). `docs/web-api.md`: the field is not exposed.
  `docs/authenticated-scanning.md`: the recording shows routes, the scan authenticates by itself. — RF-08,
  RF-12
- [ ] `CHANGELOG.md` `[Unreleased]` **Added**: `--har` / `[scan] har` / `har_max_operations`, in one
  user-facing paragraph. `CLAUDE.md`: a spec 021 paragraph in the architecture section and the state line
  (the test count is bumped by the release PR). `specs/README.md`: the 021 row to **done**; the
  "Crawl de SPA" note in the non-goals now points to `--har`. The README "Scope and limitations" line about
  single-page applications names `--har`. — RNF-06
- [ ] `docs/stack.md`: no entry (no new technology); confirm. — RNF-01
- [ ] Manual check on the CLI against the fixture served by uvicorn: a hand-made HAR with
  `--mode passive` (GET seeds fetched, no POST) and `--mode active --authorized-by … --submit-post-forms`
  (the POST operation posted once); record the summary line. Optionally, on a throw-away Juice Shop
  container, a HAR built from the browser's own export of a short walk: compare the page count and the
  findings with the 1.0 benchmark row (the full repeat is issue #148). — RF-10, RF-11
- [ ] Mark the three spec files `status: done`; record the as-built deviations and measurements in a
  "Deviations" / "Implementation notes" section of `design.md`, as 018 did. — process
- [ ] Final quality gate: ruff / black / mypy / lint-imports / the full suite; open the PR with
  `Closes #146`. — _(record the result)_
