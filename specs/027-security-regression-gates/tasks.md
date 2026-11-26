---
feature: Security regression gates — failure injection with markers at every stage, every sensitive point inventoried by a test, and the hardening left from the 1.6.0 review
status: in progress
date: 2026-11-25
related:
  - 001-foundation/design.md
  - 002-web-api/design.md
  - 020-session-security/design.md
  - 024-secret-values/requirements.md
  - 025-safe-output/requirements.md
  - 026-destination-policy/requirements.md
origin: conception
---

# 027 — Security regression gates — Tasks

The tasks are small and ordered, and each one cites the requirement or ADR it satisfies. Each stage is one pull
request, cut from an up-to-date `main` after the previous one is merged (RNF-05). The spec itself lands first, in its
own pull request.

The last task of every stage is the quality gate:

```bash
uv run ruff check .
uv run black --check .
uv run mypy src
uv run lint-imports
uv run pytest --cov
uv build && uv run --no-project python scripts/check-package.py dist
```

A stage that changes `web/` also runs, from `web/`:

```bash
pnpm lint && pnpm format:check && pnpm typecheck && pnpm test && pnpm build
```

Every new or changed test is seen failing once, by breaking the line it guards, and the pull request says what was
broken (`specs/README.md`, "Testing a spec", rule 9). The design's test strategy lists the sabotage of each guard.

Each stage that changes `src/` also runs mutation testing in batch over the guards it adds or changes:

- every changed function has a killed mutant;
- every surviving mutant is triaged as equivalent or outside the change;
- the score goes in the pull request (RNF-06).

Every user-visible change goes into `[Unreleased]` of `CHANGELOG.md` in the pull request of the stage that makes it.

A failure the suite finds that exposes a credential in a released version stops the stage and follows
[`SECURITY.md`](../../SECURITY.md) (design, "The fixes the suite forces").

## Stage 0 — Baseline and the Web API hardening

- [x] Record the baseline on `main`, on one Python version:
  - the test count and the suite time;
  - `uv run pytest --cov` per file;
  - four JSON reports of the fixture application, from `tests.fixtures.serve:app` served by `uv run uvicorn`:
    anonymous, with `[auth]` cookies and headers, with the automated login and the session tests, and with
    `--scope subdomains` against `localhost`;
  - the requests the fixture received in each scan and the duration of each scan.

  The baseline is kept outside the repository for Stage 6. — RF-14, RNF-04, RNF-06
- [x] `src/webvigil/api/routes/setup.py`: `create_first_user` hashes inside `throttle.check_slot()`; without a slot,
  `429` with `Retry-After: BUSY_RETRY_S` and `too many password checks in progress: try again shortly`. The `409`
  before the hash stays first. — RF-08
- [x] `src/webvigil/api/client_address.py`: `_name_addresses` refreshes under a `threading.Lock` with the expiry
  checked again inside it; the comment about a second lookup goes. — RF-09
- [x] `web/src/server/forwarded-for.mjs`: the patched `emit` rewrites the header on `"upgrade"` as on `"request"`;
  the file's comment says both. — RF-10, ADR-7
- [x] Tests, from the design's test strategy:
  - `tests/api/`: setup with no free slot (`429`, `Retry-After`, no `user` row), with a free slot (the account), and
    a second setup (`409` without a slot);
  - `tests/unit/` (client address): eight threads past the expiry with a blocking, counting resolver stub; a failing
    stub; no call before the expiry;
  - `web/src/server/forwarded-for.test.ts`: `"upgrade"` rewritten, `"request"` still rewritten, `"connection"` left
    alone.

  — RF-08, RF-09, RF-10, RF-15
- [x] Apply the design's sabotage and watch each test fail: the hash outside the slot, the lock removed, the
  `upgrade` branch dropped. — RF-15
- [x] Mutation testing in batch over `create_first_user` and `_name_addresses`. — RNF-06
- [x] `CHANGELOG.md` `[Unreleased]`, **Changed:** the setup `429` and the dashboard's forwarding of an upgrade. —
  RNF-02
- [x] Quality gate, Python and `web/`. — 3771 passed, 4 skipped (Windows), 113 s with coverage, 98 %;
  ruff/black/mypy/import-linter green; package check ok; `web/` 579 passed, build ok.

## Stage 1 — `robots.txt` and the logout test

- [x] `src/webvigil/http/client.py`: `decode_text(content, content_type)`, the decoding `Response.text` uses; the
  response's `text` calls it. — RF-12
- [x] `src/webvigil/crawler/robots.py`:
  - `Robots.disallow_all(reason)` and `Robots.unreadable`; `can_fetch` refuses every URL when it is set;
  - `load` returns it on a `5xx` and on `RequestFailed`; `OutOfScopeError`, a `4xx`, a missing and an empty file stay
    allow-all;
  - `load` decodes the part within the limit with `decode_text`, cut at its last line feed;
  - `_request_target` keeps a `?` that ends the path with an empty query.

  — RF-11, RF-12, ADR-6
- [x] `src/webvigil/crawler/crawler.py`: `robots_unreadable`, from the loaded `Robots`. — RF-11
- [x] `src/webvigil/core/orchestrator.py`: the warning `robots.txt could not be read (<reason>): only the target URL
  was crawled; set follow_robots = false under [scan] to crawl without it`, in place of the count warning when
  `robots_unreadable` is set. — RF-11, ADR-6
- [x] `src/webvigil/checks/session/scanner.py`: `_find_logout` keeps a link or form only when
  `may_carry_credentials` allows it and keeps looking; a configured `logout_url` it refuses gives the warning
  `session logout test skipped: [auth.login] logout_url may not receive the scan's credentials`. — RF-13
- [x] Tests, from the design's test strategy:
  - the robots tests: `503`, a refused connection, `404`, an empty `200`, a missing file, a `200` file with no rule
    (positive control), `Disallow: /a?` against `/a?`, `/a?x` and `/a`, and the 600 KiB `latin-1` file;
  - `test_crawler.py`: only the target URL fetched after a `503`, and the warning;
  - `test_session_scanner.py`: the sibling logout link alone, the sibling before the origin's, and a configured
    sibling `logout_url`, each first run on `main` (the false positive).

  — RF-11, RF-12, RF-13, RF-15
- [x] Apply the design's sabotage and watch each test fail: each `robots.py` change reverted in turn, and
  `_find_logout` back to `may_request`. — RF-15
- [x] Mutation testing in batch over `load`, `_request_target`, `can_fetch` and `_find_logout`. — RNF-06.
  114 mutants, 103 killed; the 11 survivors are triaged in the design's implementation notes.
- [x] `CHANGELOG.md` `[Unreleased]`: **Changed**, the `robots.txt` rules and warning; **Fixed**, the logout choice
  under `--scope subdomains`. — RNF-02
- [x] [`docs/architecture.md`](../../docs/architecture.md), the crawler's paragraph on `robots.txt`: a server or
  network error keeps only the target URL, with the warning. The README's line ("honoured unless you turn it off")
  still holds and does not change. — RF-11
- [x] Quality gate. — 3808 passed, 4 skipped (Windows), 121 s with coverage, 98 %;
  ruff/black/mypy/import-linter green; package check ok. No change in `web/`.

## Stage 2 — The sensitive-point inventory

- [ ] `tests/sensitive_points.py`: the walker of the design's Components, ported in English: the Python families by
  syntax tree (`error` with text followed through variables, wrapping exceptions and fields across files; `message`;
  the twelve operations), the dashboard families by pattern, the files `git ls-files` lists under `src/webvigil` and
  `web/src` without tests, vendored data and generated files, and the keys `<module>:<function> <family>
  <callee>[#n]` and `<path> <family> <match>[#n]`. — RF-07, ADR-5
- [ ] `tests/unit/test_sensitive_point_inventory.py`: `SENSITIVE_POINTS` with one reason per point, each written
  after reading the point's code; the four tests of the design (unlisted and stale points, empty reasons, the
  throwaway source with one point per family, the count of calls read). — RF-07
- [ ] A point whose reading shows no guard is fixed in this stage, with its test seen failing first, or stops the
  stage if it exposes a credential in a released version. — RF-07, ADR-4
- [ ] Apply the design's sabotage and watch each test fail: a family removed from the walker, and a second `open()`
  added to a listed function. — RF-15
- [ ] Quality gate.

## Stage 3 — The failure table and the CLI harness

- [ ] `tests/support.py`: `spellings(value)`, the seven forms of the design; the integration and CLI canaries of
  spec `024` use it in place of their own copies, and still pass. — RF-03
- [ ] `tests/failure/table.py`: `Kind`, `Stage`, `STAGES` (every pass of `Orchestrator.run`, `crawl`, `target`,
  `osv`, the CLI stages and the API stages), `DEPENDENCIES`, the markers and `HOSTILE`, and `fault_for`. — RF-01,
  RF-02, ADR-1
- [ ] `tests/failure/faults.py`: `failing_resolver`, `failing_read`, `failing_write`, `failing_render`; each records
  what it raised. — RF-02, RF-05
- [ ] `tests/failure/outputs.py`: `Outputs` for a CLI run (standard output and error, the report, the three other
  formats through `webvigil report`, the log records), `credential_hits` and `failure_hits` with the allowed outputs
  per kind. — RF-03, RF-04
- [ ] `tests/failure/test_table.py`: every pass of `Orchestrator.run` and `discover` is a seam, with the throwaway
  class as the positive control; every `CONNECTIONS` entry and every `file` and `sql` point of the inventory is a key
  of `DEPENDENCIES`, and every key has one; `fault_for` is fixed and covers every pair of stage and kind. — RF-02,
  RF-06
- [ ] `tests/failure/test_cli.py`: the runs `resolver`, `openapi-read`, `har-read`, `config-read`, `openapi-parse`,
  `report-write`, `report-render` and `report-read`, each with the design's assertions and the positive controls. —
  RF-02, RF-03, RF-04, RF-05, ADR-3
- [ ] The fixes the CLI harness forces, each with its run seen failing on `main` first:
  - `src/webvigil/cli/app.py`: a report that cannot be written or rendered prints one error line in the project's
    words and exits with `4`; `webvigil report` says `could not read <path> (<type>)`;
  - `src/webvigil/crawler/openapi.py`: `not valid JSON (line <n>, column <m>)`;
  - anything else the runs find.

  — RF-02, RF-04, ADR-4
- [ ] Apply the design's sabotage and watch each test fail: `safe_text` stops redacting one credential, the CLI's
  error line prints `str(exc)`, the seams stop raising (the controls go red), a pass renamed in the throwaway class,
  and `fault_for` on the run number alone. — RF-15
- [ ] Mutation testing in batch over the changed functions of `cli/app.py` and `crawler/openapi.py`. — RNF-06
- [ ] `CHANGELOG.md` `[Unreleased]`: **Changed**, the new error lines; **Fixed**, a report that cannot be written
  ends with exit code `4` instead of a traceback. — RNF-02
- [ ] Quality gate.

## Stage 4 — The scan harness

- [ ] `tests/failure/faults.py`: `FaultTransport`, `attributed` and `failing_osv`, as in the design. — RF-02, ADR-2
- [ ] `tests/failure/test_scan.py`: six runs of the full configuration with the credential markers, each with the
  design's assertions and the positive controls of RF-05; the results kept for Stage 5. — RF-01, RF-02, RF-03,
  RF-04, RF-05, ADR-1
- [ ] The fixes the scan harness forces, each with its run seen failing on `main` first:
  - `src/webvigil/core/orchestrator.py`: the Retire.js rules, the staleness warning and the disclosure catalogue load
    inside their pass's `try`;
  - anything else the runs find.

  — RF-02, ADR-4
- [ ] Measure the failure-injection suite with coverage on CI and write it in the pull request; past 20 s, two kinds
  share a run on alternating stages before the merge. — RNF-06
- [ ] Apply the design's sabotage and watch each test fail: the fault transport stops applying faults, and one
  stage's seam name changed. — RF-15
- [ ] Mutation testing in batch over the changed functions of `core/orchestrator.py`. — RNF-06
- [ ] `CHANGELOG.md` `[Unreleased]`, **Fixed:** what the runs found. — RNF-02
- [ ] Quality gate.

## Stage 5 — The API harness

- [ ] `tests/failure/faults.py`: `failing_store`, `failing_claim` and `raising_orchestrator`. — RF-02
- [ ] `tests/failure/outputs.py`: `Outputs` for the API (every response of the scan, findings, report and list
  routes, every table row as text, the server log). — RF-03, RF-04
- [ ] `tests/failure/test_api.py`: the results of Stage 4 through a stand-in orchestrator and the real `ScanRunner`,
  with credential markers in the scan's options; the orchestrator raising a `RuntimeError` and a `WebVigilError`, the
  store and the claim raising `OperationalError`; each with the design's assertions and the positive controls. —
  RF-02, RF-03, RF-04, RF-05, ADR-3
- [ ] The fixes the API harness forces, each with its run seen failing on `main` first:
  - `src/webvigil/core/output.py`: the portable traceback, moved from `core/orchestrator.py`;
  - `src/webvigil/api/runner.py`: `scan <id> failed (<type>)` with the portable traceback in place of
    `logger.exception`;
  - anything else the runs find.

  — RF-04, ADR-4
- [ ] Apply the design's sabotage and watch each test fail: the runner back to `logger.exception`, and the stand-in
  orchestrator returning a result without the markers (the controls go red). — RF-15
- [ ] Mutation testing in batch over the changed functions of `api/runner.py`. — RNF-06
- [ ] `CHANGELOG.md` `[Unreleased]`, **Changed:** the server log line of an engine error. — RNF-02
- [ ] Quality gate.

## Stage 6 — Cross-check and documentation

- [ ] Run the baseline's four scans again and compare: the requests byte for byte, and findings, severities, check
  ids, fingerprints, warnings and `schema_version`; the test count, the suite time and per-file coverage against
  Stage 0. Then delete the baseline. — RF-14, RNF-04, RNF-06
- [ ] [`docs/writing-checks.md`](../../docs/writing-checks.md): a new pass needs a row in the failure table and lines
  in the inventory. — RF-06, RF-07
- [ ] The project's agent notes: one line each for the failure table and the inventory. — RF-06, RF-07
- [ ] `specs/README.md`: the roadmap row `done`; the three files `status: done`; `## Deviations` and
  `## Implementation notes` in the design. — RNF-05
- [ ] Quality gate.
