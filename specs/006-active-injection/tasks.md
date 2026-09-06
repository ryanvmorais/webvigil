---
feature: Active injection — reflected XSS, SQL injection, path traversal, open redirect (Active Mode)
status: done
date: 2026-09-06
related:
  - 006-active-injection/requirements.md
  - 006-active-injection/design.md
origin: conception
---

# 006 — Active injection — Tasks

Ordered, small, each tagged with the requirement it satisfies. The last task of every stage
is the quality gate (`ruff → black → mypy src → lint-imports → pytest`). No `web` gate
(RF-19 / RNF-02). Tasks are `[ ]` until done; `/spec implementar` marks them `[x]` one by
one and records the pytest count on each gate line.

## Stage 0 — Category, `[injection]` config, HTTP verbs

- [x] `webvigil/core/findings.py`: replace `# Reserved for later specs: INJECTION.` with
  `INJECTION = "INJECTION"` on `Category`. — RF-08
- [x] `webvigil/core/config.py`: add `class InjectionSection(_Section)` (`request_budget: int
  = 500`, `max_injection_points: int = 200`, `time_based_sqli: bool = True`,
  `time_based_delay_s: int = 5`); `ScanConfig` gains `injection: InjectionSection =
  InjectionSection()`; add `injection` to the `with_overrides` docstring's section list. —
  ADR-4, RF-16
- [x] `webvigil.example.toml`: add a documented `[injection]` block (all four keys, "only
  consulted on an Active scan", `time_based_delay_s` must stay below `[http] timeout_s`). —
  ADR-4
- [x] `webvigil/http/client.py`: extract `request(method, url, *, params, data, headers,
  allow_out_of_scope)` from `get()`; `get()` becomes a pass-through. `_request_with_retry`
  takes `method`: non-idempotent retries only on pre-send `ConnectError` / `ConnectTimeout`,
  never on `5xx` / `ReadTimeout`; `301/302/303` drop the body, `307/308` keep it. Add
  `HttpStats.crafted_requests` and bump it for non-`GET`. — ADR-9, RF-15
- [x] Tests: `test_config.py` — `[injection]` round-trips, unknown key rejected, override
  beats file. `test_http_client.py` — `request("POST", …)` honours scope guard + rate
  limiter; `POST` not retried on `5xx` or `ReadTimeout`, retried on `ConnectError`; `GET`
  unchanged; `303` vs `307` body handling. — RF-15, RF-16
- [x] Quality gate. — 370 passed; ruff/black/mypy/lint-imports green.

## Stage 1 — Form discovery

- [x] `webvigil/crawler/forms.py` (no new fetches — parses `page.text`): `FormField`
  (frozen), `Form` (frozen: `method`, absolute normalized `action`, `enctype`, `fields`,
  `source_url`), `extract_forms(pages, target) -> tuple[Form, ...]` — selectolax; resolve
  `action` against the page URL; drop out-of-scope actions; `method` = `POST` iff
  `form@method` upcases to `POST`; fields from named `input`/`textarea`/`select`; dedup on
  `(method, action, sorted field names)`. — ADR-3, RF-05
- [x] Tests (`test_crawler_forms.py`): relative / empty / absolute / out-of-scope action;
  method normalisation; `input` + `textarea` + `select` field extraction; hidden field kept;
  dedup; a page with no form → `()`. — RF-05, RF-22
- [x] Quality gate. — 378 passed; ruff/black/mypy/lint-imports green.

## Stage 2 — Injection-point model, payloads, enumeration

- [x] `webvigil/checks/injection/__init__.py` + `data/`? (no — payloads are a `.py`
  module). Create the package with `models.py`: `InjectionPoint` (frozen, `key` property),
  `Baseline` (frozen), `InjectionHit` (frozen, `evidence` = `(label, content)` pairs),
  `ActiveBudget` (`take` / `take_time_based` / `start_point`). — RF-06, RF-07, RF-12, ADR-6
- [x] `webvigil/checks/injection/payloads.py`: the documented constants — `XSS_PROBE` /
  `XSS_BREAKERS`, `SQLI_ERROR` / `SQL_ERROR_SIGNATURES` (5 DBMS) / `SQLI_BOOLEAN_PAIRS` /
  `SQLI_TIME`, `TRAVERSAL` / `TRAVERSAL_SIGNATURES`, `REDIRECT_SENTINEL` /
  `REDIRECT_PAYLOADS`. Comment each block. — RNF-07
- [x] `webvigil/checks/injection/points.py`: `_FUZZ_TYPES`, `_SKIP_TYPES`,
  `_EXCLUDE_FORM_RE`, `_PREFERRED_REDIRECT`, `_PATHLIKE_NAMES`; `enumerate_points(pages,
  forms, *, max_points) -> (list[InjectionPoint], list[str])` — query-param points + form
  points, exclusion heuristic, dedup on `key`, stable sort, truncate + warning; priority
  tags for traversal / redirect. — RF-04, RF-06, Resolved-req-8
- [x] Tests (`test_injection_points.py`): query points; form points; `_FUZZ_TYPES` /
  `_SKIP_TYPES`; every exclusion keyword + an innocuous-form negative; cross-URL dedup;
  `max_points` truncation + warning; priority tagging. — RF-06, RF-22
- [x] Quality gate. — 385 passed; ruff/black/mypy/lint-imports green.

## Stage 3 — Reflected-XSS detector

- [x] `webvigil/checks/injection/detect/__init__.py` + `detect/xss.py`: `async detect(point,
  baseline, http, budget, cfg) -> list[InjectionHit]` — send `XSS_PROBE`, short-circuit if
  not reflected; send breakers; hit iff the breaker payload is present **verbatim** in an
  HTML response; classify context (text / attribute / `<script>` / `href:javascript:`);
  confidence HIGH / MEDIUM. — RF-08, RF-13
- [x] Tests (`test_injection_xss.py`): body / attribute-break / `<script>` /
  `href:javascript:` positives; entity-encoded, percent-encoded, `text/plain`, comment-only
  negatives; token-not-reflected short-circuit. Uses `pytest-httpx`. — RF-08, RF-22
- [x] Quality gate. — 392 passed; ruff/black/mypy/lint-imports green.

## Stage 4 — SQL-injection detectors

- [x] `webvigil/checks/injection/detect/sqli.py`: `detect_error` (signature absent from
  `baseline.raw_body`, names the DBMS), `detect_boolean` (TRUE≈baseline & FALSE≠baseline via
  `difflib.quick_ratio` on normalised bodies; stability re-fetch; second-pair confirm),
  `detect_time` (`D=0` control vs `D=delay`; `_TIME_DELTA_S`; halving confirm;
  `budget.take_time_based`). — RF-09, RF-13
- [x] Tests (`test_injection_sqli.py`): five DBMS error signatures; signature-already-in-
  baseline → no hit; boolean clean positive; unstable-baseline negative; always-different
  negative; time-based delay positive; uniformly-slow negative; scaling confirm. — RF-09,
  RF-22
- [x] Quality gate. — 400 passed; ruff/black/mypy/lint-imports green.

## Stage 5 — Traversal and open-redirect detectors

- [x] `webvigil/checks/injection/detect/traversal.py`: send `TRAVERSAL` (path-like points
  first); hit iff a `TRAVERSAL_SIGNATURES` match absent from `baseline.raw_body`; evidence
  quotes the leaked line (trimmed). — RF-10, RF-13
- [x] `webvigil/checks/injection/detect/redirect.py`: send `REDIRECT_PAYLOADS` (preferred-
  name points first); hit iff `final_location` host == `REDIRECT_SENTINEL`, or a `3xx`
  `Location` to the sentinel, or meta-refresh / `location.href|replace` to the sentinel in
  the body; confidence HIGH (header) / MEDIUM (body). — RF-11, RF-13
- [x] Tests (`test_injection_traversal.py`, `test_injection_redirect.py`): passwd + win.ini
  positives, signature-in-baseline + echoed-payload negatives; `Location` sentinel
  (absolute / protocol-relative / backslash / `@`-confusion), `final_location` path,
  meta/JS body path, same-host negative. — RF-10, RF-11, RF-22
- [x] Quality gate. — 409 passed; ruff/black/mypy/lint-imports green.

## Stage 6 — `InjectionScanner` engine

- [x] `webvigil/checks/injection/engine.py`: `_DETECTORS` / `_KIND_BY_CHECK_ID` maps,
  `_PER_POINT_REQUEST_CAP` / `_TIME_BASED_SLEEP_CAP` / similarity + delta constants,
  `InjectionReport`, `InjectionScanner(http, target, config, pages, forms, selected_kinds)`
  with `run()`: `enumerate_points` → per point `_baseline` (one shared `request()`,
  normalised + raw body + timing) → ordered detectors drawing on one `ActiveBudget` →
  collect hits + cap warnings; swallow `RequestFailed` / `OutOfScopeError`. — RF-07, RF-12,
  RF-03
- [x] Tests (`test_injection_engine.py`): budget exhaustion → warning + stop; per-point cap;
  `time_based_sqli = False` drops `sqli-time`; `selected_kinds` gating; baseline fetched
  once per point and shared. — RF-12, RF-13, RF-22
- [x] Quality gate. — 415 passed; ruff/black/mypy/lint-imports green.

## Stage 7 — The six checks, `Observations`, orchestrator wiring

- [x] `webvigil/core/context.py`: `if TYPE_CHECKING` import of `InjectionHit`; `Observations`
  gains `injection_hits: tuple[InjectionHit, ...] = ()` (after `probe_hits`). — ADR-6
- [x] `webvigil/checks/injection/checks.py`: `_InjectionCheck` base (`kind` ClassVar,
  `category = INJECTION`, `mode = ACTIVE`, `run` filters `ctx.observations.injection_hits`
  by `kind` → `finding(...)` with `Location(url, method, param)`), `_DESCRIPTION` /
  `_REMEDIATION` per kind, and the six `@register` classes with ids / severities / cwe from
  the design table. Register in `injection/__init__.py`. — RF-08..RF-11, RF-16
- [x] `webvigil/checks/__init__.py`: add `injection` to `_load_builtin_checks`. — RF-16
- [x] `webvigil/core/orchestrator.py`: import `InjectionScanner` + the kind map +
  `extract_forms`; `forms = extract_forms(pages, target)` after the crawl; `_inject(
  check_types, http, target, pages, forms, warnings)` (returns `()` on passive or when no
  injection kind is selected; else runs the scanner, extends warnings); pass
  `injection_hits` into `Observations(...)`. — ADR-1, ADR-2, RF-01, RF-12
- [x] Tests: `test_checks_injection.py` (each check emits only its kind, `Location` fields
  set, evidence mapped); `test_injection_orchestrator.py` (`_inject` `()` on passive; `()`
  when all six disabled; wires `injection_hits`; a raising `InjectionScanner` → scan warning
  not crash — monkeypatch `orch_mod.InjectionScanner`). — RF-08..RF-11, RF-13
- [x] Quality gate. — 422 passed; ruff/black/mypy/lint-imports green.

## Stage 8 — CLI and SARIF

- [x] `webvigil/cli/app.py`: `scan` gains `--time-based-sqli/--no-time-based-sqli`
  (`bool | None = None`); `_build_config` gains `time_based_sqli`, builds
  `injection_overrides` when not `None`, passes `injection=` to `with_overrides`. — RF-16
- [x] `webvigil/cli/_render.py`: after the disclosure block, when `metadata.mode is ACTIVE`
  and any `injection.*` finding, print `"Active injection: N finding(s)"`. — RF-16, ADR-7
- [x] `webvigil/reporting/sarif.py`: `_result` adds `logicalLocations` when
  `finding.location.key` is set (`kind` = `parameter` if `location.param` else `member`).
  Additive; `_unique_rules` unchanged. — ADR-8, RF-18
- [x] Tests: `test_cli.py` — `list-checks` shows the six; `--no-time-based-sqli` sets
  `config.injection.time_based_sqli = False`; the active-scan summary line. `test_reporters.py`
  — SARIF `logicalLocations` present iff `location.param`; JSON/MD/HTML render `method` +
  `param`. — RF-16, RF-18
- [x] Quality gate. — 426 passed; ruff/black/mypy/lint-imports green.

## Stage 9 — Fixture app, Docker target, integration tests

- [x] `tests/fixtures/app.py` — insecure profile adds: `/search?q=` (reflects `q`
  unescaped + a GET form), `/item?id=` (sync handler, module-level `sqlite3` `:memory:`,
  string-concat query, `OperationalError` → 500, `1=1`/`1=2` row-set change, `SLEEP(n)`
  honoured — ADR-10), `/download?file=` (`open(root/file)`, fixture `etc/passwd` under
  root), `/go?next=` (unchecked 302), `POST /comment` (hidden `csrf` + reflects `body`
  unescaped), `POST /login` (must be skipped). Add `app.state.requests` request log. Link
  `/search` and `/comment` from the insecure index so the crawl reaches them. — RF-20
- [x] `tests/fixtures/app.py` — hardened profile: `/search` escapes, `/item` uses `WHERE id
  = ?` + 404 on non-int, `/download` jails + 404s traversal, `/go` allow-lists, `/comment`
  escapes. — RF-20
- [x] `tests/fixtures/serve.py` (3 lines: `app = make_app("insecure")`); `docker/target.Dockerfile`
  (`python:3.12-slim`, `pip install starlette uvicorn`, copy `tests/fixtures`, `CMD uvicorn
  fixtures.serve:app --host 0.0.0.0 --port 8080`); `docker-compose.yml` gains a
  `profiles: ["targets"]` `target` service on `8080`. — RF-24
- [x] `tests/integration/test_scan_fixture_app.py` — `scan` fixture `_run` gains an Active
  path (`scan.mode = active`, `active.authorized_by = "test"`, `injection.time_based_delay_s
  = 2`). Tests: insecure + active finds all six (XSS ×2), with expected `param`/`method`/
  severity; insecure + passive finds none + no crafted request; hardened + active → zero
  `INJECTION`; `/login` never receives a payload (assert on the request log); two Active
  runs deterministic + within budget. — RF-21
- [x] Quality gate. — 431 passed; ruff/black/mypy/lint-imports green.

## Stage 10 — Docs, roadmap, verification, close

- [x] `docs/active-injection.md` (new): what Active Mode does now; the four classes, how
  each is detected and its limits (no headless JS; three SQLi techniques; traversal needs a
  readable known file; redirect inspects `Location`, does not follow); the injection-point
  model (query params + forms from crawled bodies); the request budget + per-point caps; the
  non-destructive posture + the exclusion heuristic **and its limits**; the Docker target
  (`docker compose --profile targets up target`); why stored XSS / SSRF / command injection
  are deferred. — RF-23
- [x] `docs/architecture.md` (checks + crawler + http bullets, specs list), `docs/writing-checks.md`
  (a worked `ACTIVE` check: reading injection points, the shared baseline, the budget, the
  confirmation pattern; note the post-scan re-fetch phase as the stored-XSS extension point
  — Resolved-req-11). — RF-23
- [x] `README.md` (coverage table `v0.6` → shipped with a link; an `--mode active`
  quick-start line), `CLAUDE.md` (layer-3 `webvigil.checks.injection` paragraph; `Estado`
  line → 006 concluída, next = `007-auth-flows`), `specs/README.md` (`006` row → **done**;
  note that stored XSS + SSRF slipped to a later spec and why). — RF-23
- [x] Set all three `006` spec files to `status: done`; fill the design's "Implementation
  notes" (final budget numbers vs. the fixture's request count, any detector tuning, the
  pytest delta). — RF-23
- [x] Manual verification: `docker compose --profile targets up -d target`, then
  `webvigil scan http://localhost:8080 --mode active --authorized-by me --format md` — the
  six findings appear with correct params; `--no-time-based-sqli` drops `sqli.time-based`;
  a passive scan of the same target shows none; `webvigil list-checks` shows the six.
  Record the output in the notes. — RNF-05
- [x] Final full quality gate: ruff / black / mypy (91 files) / lint-imports (2 contracts
  kept) / pytest — **431 passed**. — RNF-02
