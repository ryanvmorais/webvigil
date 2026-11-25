---
feature: Safe output — redaction, size bounds and control-character neutralization applied in one place for every output
status: done
date: 2026-11-25
related:
  - 024-secret-values/requirements.md
  - 019-automated-login/design.md
  - 002-web-api/design.md
  - 003-web-ui/design.md
origin: conception
---

# 025 — Safe output — Tasks

The tasks are small and ordered, and each one cites the requirement or ADR it satisfies. Each stage is one
pull request, cut from an up-to-date `main` after the previous one is merged (RNF-05). The spec itself lands
first, in its own pull request.

The last task of every stage is the quality gate:

```bash
uv run ruff check .
uv run black --check .
uv run mypy src
uv run lint-imports
uv run pytest --cov
uv build && uv run --no-project python scripts/check-package.py dist
```

Stage 3 also runs the dashboard's gate, from `web/`:

```bash
pnpm lint && pnpm format:check && pnpm typecheck && pnpm test && pnpm build
```

Every new or changed test is seen failing once, by breaking the line it guards, and the pull request says what
was broken (`specs/README.md`, "Testing a spec", rule 9). The design's test strategy lists the sabotage of each
guard.

Each stage also runs mutation testing in batch over the guards it adds or changes:

- every changed function has a killed mutant;
- every surviving mutant is triaged as equivalent or outside the change;
- the score goes in the pull request (RNF-06).

Every user-visible change goes into `[Unreleased]` of `CHANGELOG.md` in the pull request of the stage that
makes it.

## Stage 0 — The safe-output module and the shared cases

- [x] Record the baseline on `main`, on one Python version:
  - the test count and the suite time;
  - `uv run pytest --cov` per file;
  - three JSON reports of the fixture application (anonymous, with `[auth]` cookies and headers, and with the
    automated login), from `tests.fixtures.serve:app` served by `uv run uvicorn`, with the requests the
    fixture received and the duration of each scan, kept outside the repository for Stage 4.

  — RF-10, RNF-04, RNF-06
- [x] `src/webvigil/core/bounded.py`: `store_text(value, limit)` (`replace_surrogates`, then `truncate`); the
  `bounded()` validator calls it. — RF-01, ADR-1
- [x] `src/webvigil/core/text.py`: `escape_json_controls(document)`, the expression of `json_report.py` as a
  function. — RF-05
- [x] `src/webvigil/core/output.py`: `Sink`, the profile table of the design's data model, and
  `safe_text(value, sink, *, one_line, limit, redactor)` with the order redaction, bound, neutralization.
  — RF-01, ADR-1, ADR-2
- [x] `src/webvigil/core/output.py`: `Redactor`, built from `_Scrubber` and `_spellings` (moved from
  `auth/scrub.py`, behaviour unchanged for whole spellings), with `CUT_MARKERS`, the prefix and suffix sets and
  the cut rule of the design, `cut_edges` included. `auth/scrub.py` imports it and keeps `_texts`,
  `looks_like_session_value` and the walk. — RF-02, ADR-3
- [x] `src/webvigil/core/output.py`: `safe_traceback(exc)` over the cause and context chain and exception
  groups, frames as Python formats them, each exception's type, message and notes on one line each, bounded to
  `URL_MAX_CHARS`. — RF-04, ADR-4
- [x] `src/webvigil/core/output.py`: `SafeLogFilter` (message through `Sink.LOG`, `args` emptied, `exc_text`
  from `safe_traceback`, a record whose message cannot be rendered left alone) and `get_logger(name)`, which
  attaches it once. — RF-04, ADR-4
- [x] `tests/data/text-controls-cases.json`: the cases of the design's interfaces, written with JSON escapes
  only. `tests/unit/test_text_cases.py`: `show_controls` over every case. — RF-07, ADR-7
- [x] `tests/unit/test_output.py`: the profile table, idempotence, the order, the traceback and the log filter
  of the design's test strategy, each with its positive control. — RF-01, RF-04, RF-11
- [x] `tests/unit/test_output.py`: the cut rule at every offset of a known secret, under every spelling, for
  the marker cuts and the evidence edges, with the three positive controls of the design (whole secret away
  from a cut, a title with no marker, a 3-character fragment). — RF-02, RF-11
- [x] Apply the sabotage of the design for each guard of this stage and watch each test fail: the cut rule
  removed, a match anywhere, the bound after the neutralization, a range dropped from `INVISIBLE_CHARS`, the
  traceback joined with `show_controls` over the whole text. — RF-11
- [x] Mutation testing in batch over `core/output.py`, `store_text` and `escape_json_controls`. — RNF-06
- [x] Quality gate. —

## Stage 1 — Engine, CLI and reports

- [x] `src/webvigil/auth/scrub.py`: the walk calls the `Redactor` with `cut_edges=True` for evidence content and
  at markers only for every other field; the redaction warning counts fields changed by either rule.
  — RF-02, ADR-3
- [x] `tests/unit/test_scrub.py` (or the existing scrub tests): a result whose evidence comes from the snippet
  helpers of `checks/injection/detect/xss.py`, `cmdi.py`, `ssrf.py`, `checks/upload/scanner.py` and
  `checks/envelope/scanner.py`, and from `EvidenceItem.of`, each called with a body that holds the secret
  across the cut, with no fragment of 4 or more characters left. — RF-02, RF-11
- [x] `src/webvigil/cli/_render.py`: `_printable` becomes `safe_text(value, Sink.TERMINAL, one_line=...)`;
  a `cell(value)` helper returns a one-line `Text`. — RF-03, ADR-2
- [x] `src/webvigil/cli/app.py`: `list-checks` builds its rows from `_render.cell`, so no cell is read as
  markup. — RF-03
- [x] `src/webvigil/reporting/html.py`, `markdown.py`: `safe_text(page, Sink.DOCUMENT)` in place of
  `show_controls`. `json_report.py`, `sarif.py`: `safe_text(document, Sink.JSON)`. The existing reporter tests
  keep their expected output. — RF-05
- [x] `src/webvigil/reporting/__init__.py`: `MAX_REPORT_BYTES = 64 * 1024 * 1024`; `load_result` reads 1 MiB
  chunks into a `bytearray` until the end of the file or one byte past the limit. — RF-08, ADR-6
- [x] `src/webvigil/cli/app.py`: after writing a JSON report, the `scan` command warns through
  `_render.status` when its UTF-8 size is over `MAX_REPORT_BYTES`; the file is written whole and the exit code
  is unchanged. — RF-08, ADR-6
- [x] `tests/unit/`: the read-size spy (no read above 1 MiB), the limit at 64 MiB and one byte more, the scan
  warning with its one-byte-smaller control, and the memory ratios in a subprocess (POSIX only). — RF-08, RF-11
- [x] `tests/unit/`: a terminal test of `list-checks` with a plugin whose id looks like Rich markup and holds a
  control character, shown as written. — RF-03, RF-11
- [x] `docs/architecture.md`, `CLAUDE.md`, the help text of `webvigil report`: the 64 MiB limit.
  `CHANGELOG.md` `[Unreleased]`: the partial-secret redaction under **Security**, the report limit and the
  scan warning under **Changed**. — RF-02, RF-08, ADR-9
- [x] Apply the sabotage of the design for each guard of this stage and watch each test fail: evidence scrubbed
  without `cut_edges`, `read(MAX_REPORT_BYTES + 1)` restored, the warning removed, `list-checks` printing
  plain strings. — RF-11
- [x] Mutation testing in batch over the changed parts of `auth/scrub.py`, `reporting/__init__.py` and the
  write step of `cli/app.py`. — RNF-06
- [x] Quality gate. —

## Stage 2 — Web API and the sink inventory

- [x] `src/webvigil/api/runner.py`, `security.py`: loggers from `get_logger`. — RF-04, ADR-4
- [x] `src/webvigil/api/app.py`: the lifespan attaches `SafeLogFilter` to `uvicorn.error` and `httpx2`, once.
  — RF-04, ADR-4
- [x] `src/webvigil/api/db.py`, `api/migrations/env.py`: `hide_parameters=True`. — RF-04, ADR-5
- [x] `src/webvigil/api/runner.py`: `_terminate` writes `safe_text(error, Sink.STORE)`. — RF-06
- [x] `src/webvigil/api/app.py`: `_validation_failed` passes each string part of `loc` and each `msg` through
  `safe_text(..., Sink.MESSAGE)`, and still drops `input`, `ctx` and `url`. — RF-06
- [x] `tests/api/test_log_canary.py`: the two failures of the design (a scan that raises with the canary,
  controls and an oversized message; a store into a dropped findings table), logging captured at `DEBUG`, with
  the positive controls (both failures logged; an engine without `hide_parameters` shows the canary).
  — RF-04, RF-06, RF-11
- [x] `tests/api/`: the `422` with an oversized key and a message holding a control character. — RF-06, RF-11
- [x] `tests/unit/test_output_inventory.py`: the syntax-tree walk of ADR-8 over `src/webvigil`, `OUTPUT_SINKS`
  with a reason per site, `logging.getLogger` allowed only in `core/output.py`, and the positive controls over a
  throwaway source. Every output of the CLI, the reporters and the Web API is listed. — RF-09, ADR-8
- [x] `docs/web-api.md`: the log treatment and the `422` message bound. `CHANGELOG.md` `[Unreleased]`: the log
  treatment under **Security**, the `422` message bound under **Changed**. — RF-04, RF-06
- [x] Apply the sabotage of the design for each guard of this stage and watch each test fail: the filter not
  attached, `hide_parameters` removed, `Scan.error` written raw, `msg` not bounded, an unlisted
  `typer.echo(value)` in a scratch copy of a module. — RF-11
- [x] Mutation testing in batch over `SafeLogFilter`, the lifespan's attach step, `_terminate` and
  `_validation_failed`. — RNF-06; 23 of 23 killed after two new tests
- [x] Quality gate. — 3609 passed, 4 skipped, 98 %; ruff, black, mypy, lint-imports and the package check green

## Stage 3 — Dashboard

- [x] `web/src/lib/text.ts`: `display(value, { multiLine })`. — RF-07
- [x] `web/src/lib/text.test.ts`: run every case of `../tests/data/text-controls-cases.json` through
  `showControls`; a missing file fails with a message that names it. — RF-07, ADR-7
- [x] `web/src/components/scan-list-table.tsx`, `web/src/app/(app)/scans/[id]/page.tsx`: target (heading and
  page title), tool version, `authorized_by`, the error message through `display`. — RF-07
- [x] `web/src/components/findings-table.tsx`, `findings-filters.tsx`: the check id and the filter labels
  through `display`; the existing `showControls` calls become `display`. — RF-07
- [x] `web/src/components/technologies-table.tsx`, `checks-table.tsx`: name, version, the advisories tooltip,
  the source URL, the check's name, id and category through `display`. — RF-07
- [x] `web/src/lib/api.ts`: `errorMessage` and `fieldErrors` through `display`; `report-preview.tsx`: its
  error text. — RF-07
- [x] `web/src/lib/hostile-render.test.tsx`: the payload helper that fills every string at any depth, and a
  render of each page with no raw control, bidirectional or zero-width character in the text, the attributes
  or `document.title`. — RF-07, RF-09, ADR-8
- [x] `docs/web-ui.md`: `display()` for every API value. `CHANGELOG.md` `[Unreleased]`: the dashboard fields
  under **Changed**. — RF-07
- [x] Apply the sabotage of the design and watch each test fail: `display()` removed from the scan list's
  target, a range dropped from `HIDDEN_RANGES`. — RF-11; 27 sabotages, one per `display` call and both of these,
  all red
- [x] Quality gate, the Python one and the dashboard's. — Python: 3609 passed, 4 skipped, 98 %; ruff, black,
  mypy, lint-imports and the package check green. Dashboard: 576 passed; lint, format, typecheck and build green

## Stage 4 — Cross-check and documentation

- [x] RF-10: repeat the three scans of Stage 0 from the new `main`. Compare the requests the fixture received
  and the JSON reports, leaving out timestamps and durations: the requests are byte for byte the same, and
  findings, severities, check ids, fingerprints and `schema_version` are identical, except a redacted fragment
  next to a cut. Compare the scan durations with the baseline. — RF-10, RNF-04; identical once the per-run
  random values are masked, as between two runs of the baseline; 5.1 s, 4.5 s and 28.7 s against 5.3 s, 4.9 s
  and 29.6 s
- [x] `.github/workflows/`: confirm the whole CI matrix on the last merge commit: `quality` on Linux and Windows
  for every Python version, `package`, `docker`, `web` and `compose`. — RNF-05; all green on `46e2bf7`
- [x] `docs/writing-checks.md`: cut a snippet with a marker from `CUT_MARKERS`, log through `get_logger`, and a
  new output needs an `OUTPUT_SINKS` line with its reason. — RF-09, ADR-3, ADR-8
- [x] `CLAUDE.md`: one line in the architecture section saying that every output goes through
  `core/output.py::safe_text` with its `Sink`, and that a logger comes from `get_logger`. — RF-01, RF-09
- [x] `design.md`: fill in `## Implementation notes` with the measurements: tests before and after, coverage
  per file, suite time, scan durations, the memory ratios, the mutation scores. Set `status: done` in the three
  files and on the roadmap of `specs/README.md`. — RF-11
- [x] Quality gate. — 3613 collected, 4 skipped on Windows, 98 %; ruff, black, mypy, lint-imports and the
  package check green
