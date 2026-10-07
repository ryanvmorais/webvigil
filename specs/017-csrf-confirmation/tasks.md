---
feature: Active CSRF confirmation — replay a state-changing form without a valid token (Active Mode)
status: done
date: 2026-10-06
related:
  - 017-csrf-confirmation/requirements.md
  - 017-csrf-confirmation/design.md
origin: conception
---

# 017 — Active CSRF confirmation — Tasks

Ordered, small, each tagged with the requirement / ADR it satisfies. The last task of
every stage is the quality gate (`ruff → black → mypy src → lint-imports → pytest`).
Engine and CLI only — no `web` gate, no API migration (RNF-01, RNF-02).

A full `pytest` run takes about an hour, so a stage gate runs lint, types, import contracts
and the **test files that stage touched**; the **full** suite runs at Stage 3 (the first
stage that changes the integration fixture) and at Stage 4 (close). The baseline count is
recorded when Stage 0 starts and the delta when the spec closes.

Baseline before 017 (clean `main` after spec 016): **921 passed** (the spec 016 close run).
At 017 close: **995 passed**.

## Stage 0 — Behaviour-neutral prep: shared helpers, predicates, the switch

- [x] `webvigil/checks/csrf/tokens.py` (new): move `_TOKEN_NAME_RE`, `_is_token_field` and
  `_is_candidate` out of `checks.py` as the public `is_token_field(field)` and
  `is_candidate(form)`, with their docstrings; `checks.py` imports them. No logic change; the
  passive check's tests pass untouched. — ADR-1 (shared by the check and the pass, no cycle)
- [x] `webvigil/crawler/safety.py`: add `is_login_url(url)` (the `_AUTH_FORM_RE` on the URL
  path) and `is_destructive_form(form)` — flatten action path + query, field names and the
  value of named `submit` / `button` inputs, turn `_` and `-` into spaces, then match
  `_DESTRUCTIVE_RE` or `_LOGOUT_RE`. Comment the `<button>`-text gap. — RF-04, ADR-2
- [x] `webvigil/core/config.py`: `InjectionSection.csrf_confirm: bool = False`, documented in
  `Attributes:` next to `file_upload` (writes to the target, like `stored_xss`). — RF-11
- [x] Tests: `test_safety.py` — `is_destructive_form` true for `delete_account`, `/items/remove`,
  a named submit with `value="Delete"`, `/logout`; false for a benign form; `is_login_url`
  true for `/login` and `/signin`, false for `/panel`. `test_config.py` — `csrf_confirm`
  defaults to `False`, loads from `[injection] csrf_confirm = true`. — RF-04, RF-11, RF-14
- [x] Quality gate: ruff / black / mypy / lint-imports green; `pytest` for `test_checks_csrf.py`
  (untouched, proves the move changed nothing), `test_safety.py`, `test_config.py`. — RNF-02

## Stage 1 — The pass

- [x] `webvigil/checks/csrf/scanner.py`: module docstring (the experiment, what it writes to
  the target, the sentinel); `CsrfHit` and `_Shape` dataclasses with `Attributes:`; the
  `Verdict` alias; constants with a `#` rationale each — `_MAX_FORMS = 20`,
  `_PER_FORM_CAP = 5`, `_FOREIGN_ORIGIN = "https://webvigil.invalid"`, `_REJECTION_RE`,
  `_SIMILARITY = 0.95`, `_LENGTH_GUARD = 0.10`, `_TOKEN_CAP = 6000`. — RF-02, RF-05..RF-07,
  RNF-04, ADR-8
- [x] `scanner.py`: `CsrfScanner.__init__` / `warnings` and `_candidates` — in-order,
  de-duplicated on `(method, action, field names)`, skipping non-`POST`, non-urlencoded, file
  inputs, auth / search (`is_candidate`), destructive (`is_destructive_form`), counted by
  reason; forms past the cap counted as "not tested (cap)". — RF-01, RF-02, RF-04
- [x] `scanner.py`: `_build_body(form, *, suffix, mode)` — the field table of the design
  (defaults unchanged, sentinel `wvcsrf<tok><suffix>`, typed fallbacks, first named submit,
  unchecked boxes omitted), plus `_alter(value)` and token-field removal / alteration, nothing
  else mutated. — RF-03, RF-06
- [x] `scanner.py`: `_fetch_form` (GET `source_url`, wrap the response in a `Page`,
  `parse_forms`, match on `(method, action, field names)`; `None` → inconclusive), `_submit`
  (one `POST` through `http.request(..., data=, headers=, crafted=True)`, same-origin
  headers for the control, `webvigil.invalid` for replays, a failed request returns `None`).
  — RF-05, RF-06, RNF-06, ADR-3
- [x] `scanner.py`: `_shape(response, tokens)` and the body normaliser (sentinel, seen token
  values, hex runs, ISO timestamps, long digit runs, whitespace), `_equivalent(a, b)`
  (status class, final path, word-token `SequenceMatcher` ratio, length guard) and
  `_judge(control, replays)`. — RF-07, ADR-2, ADR-8
- [x] `scanner.py`: `_experiment(form)` — fetch → control → replay A (token removed) → replay B
  (token altered), one replay for a token-less form, stop at the first confirmation, at a
  rejected control, or a failed fetch; build the `CsrfHit` with the two shape summaries
  (`POST /x -> 302 -> /y (200)`); `run()` loops the candidates and writes the one tally line
  (RF-08) only when at least one `POST` form existed. — RF-05..RF-08
- [x] Tests: `tests/unit/test_csrf_scanner.py` (a `_FakeHttp` that records every call, in the
  style of `test_upload_scanner.py`) — every item of the "Unit — `test_csrf_scanner.py`"
  bullet of the design's test strategy. — RF-14
- [x] Quality gate: ruff / black / mypy (the new module included) / lint-imports green;
  `pytest tests/unit/test_csrf_scanner.py tests/unit/test_checks_csrf.py`. — RNF-02
  29 passed in `test_csrf_scanner.py` (the stage's own tests); `test_checks_csrf.py` still green. Two
  fixes from the first run: the sentinel contains "csrf" so it is stripped before the rejection
  words are searched, and `_judge` became `_compare` (one replay) plus the loop in `_experiment`.

## Stage 2 — Check, wiring, CLI

- [x] `webvigil/core/context.py`: `Observations.csrf_hits: tuple[CsrfHit, ...] = ()` with the
  `Attributes:` entry and the `TYPE_CHECKING` import. — RF-09
- [x] `webvigil/checks/csrf/checks.py`: `TokenNotEnforcedCheck` (`id`, `name`, `category`,
  `mode = ACTIVE`, `default_severity = MEDIUM`, `cwe = (352,)`, references), `_DESCRIPTION`
  and `_REMEDIATION` for it, the title, evidence (`form` / `replay` / `control` / `attack` /
  `credentials`), confidence from `_CONFIDENCE[_session_samesite(ctx.pages)]` capped at
  `MEDIUM` unless `ctx.config.auth.cookies`; `NoCsrfTokenCheck.run` skips actions present in
  `observations.csrf_hits`. Update the module docstring and `csrf/__init__.py`. — RF-09,
  RF-10, ADR-4, ADR-5
- [x] `webvigil/core/orchestrator.py`: `_CSRF_CHECK_ID`, `_scan_csrf` (the `_scan_upload`
  shape: Active + switch + selected check, exception → warning), called **after** the upload
  pass, `csrf_hits=` into `Observations`, and the "CSRF confirmation requires --mode active"
  warning in `run()`; the pass's tally warning is appended. — RF-08, RF-11, ADR-6, ADR-7
- [x] `webvigil/cli/app.py`: `--confirm-csrf/--no-confirm-csrf` (help says it writes to the
  target), `_build_config` / `_run_scan` plumbing like `file_upload`. `cli/_render.py`: the
  dim "enabled — test data marked wvcsrf was left on the target" note and the red
  "CSRF confirmed: N form(s)…" line; the passive line keeps counting `csrf.form.no-token`
  only. — RF-11, RNF-03
- [x] Tests: `test_checks_csrf.py` (finding shape, `SameSite` × cookies / no cookies, no hits →
  nothing, passive skips a confirmed action and is unchanged with no hits);
  `test_orchestrator*.py` (pass skipped Passive / switch off / check disabled, exception →
  warning, hits reach the context, runs after the upload pass, the Active-only warning);
  `test_cli.py` (`--confirm-csrf`, the summary notes, `list-checks` shows
  `csrf.form.token-not-enforced | CSRF | active | MEDIUM`); fix any test that counts
  registered checks. — RF-09..RF-11, RF-14
- [x] Quality gate: ruff / black / mypy / lint-imports green; `pytest` for the touched unit
  files. — RNF-02
  Whole unit suite: green (45 s). `test_checks_csrf.py` +9, `test_injection_orchestrator.py` +6,
  `test_cli.py` +3. No test counted the registered checks, so none needed a new number.

## Stage 3 — Fixture app and integration

- [x] `tests/fixtures/app.py`: the `/panel` page and `_csrf_route(...)` building the four
  routes (`/newsletter`, `/settings`, `/transfer`, `/prefs`) per the design's table; one
  constant token; escaped echoes; `app.state.csrf_log` reset per app; `/panel` linked from the
  shared link block and registered in both profiles; the redirect of `/newsletter` to
  `/panel?saved=newsletter`. Docstring comment explaining each route's role. — RF-12
- [x] Tests: `tests/unit/test_fixture_csrf.py` — each route accepts / rejects as the table says
  (no token, ignored token, enforced token with the right / altered / missing value, the
  `Origin` check, escaped echo, `csrf_log` entries), both profiles. — RF-12, RF-14
- [x] `tests/integration/test_scan_fixture_app.py`: the five scenarios of the design's
  "Integration" bullet (insecure + switch; insecure without it; passive; hardened + switch;
  determinism and caps). Update the crawl-count assertion for `/panel`. — RF-13
- [x] Re-measure the injection pass against the fixture: `/newsletter`, `/settings` and
  `/prefs` are new `POST` points. Confirm every existing `injection.*` integration test still
  passes at the current `_PER_POINT_REQUEST_CAP` and `request_budget` (the integration test's
  1200 / `max_pages = 90`); if one starves, raise the number by measurement and record the
  before / after here, as 011, 014 and 016 did. — RNF-04
- [x] Quality gate: ruff / black / mypy / lint-imports green, then the **full** `pytest`.
  **995 collected.** The full run had two failures, both the spec-012 envelope tests
  (`host_header_injection_found`, `trace_and_dangerous_methods`): the envelope pass samples the entry,
  then every form action, then the other pages, so the four `/panel` form actions pushed `/reset` and
  `/resource` out of the fixture's sample of 20. The integration config now uses
  `envelope_url_sample` 24 / `envelope_budget` 150 (test-only; the engine defaults are untouched);
  the whole `tests/integration` folder was rerun green (68 passed). — RNF-02
  **Injection budget:** no `injection.*` integration test starved with the three new POST points
  (`/newsletter`, `/settings`, `/prefs`; `/transfer` is excluded by `_EXCLUDE_FORM_RE`), so
  `_PER_POINT_REQUEST_CAP` (42) and `request_budget` (650 / 1200 in the integration config) are unchanged.
  Other fixture changes: the hardened profile's older POST routes (`/comment`, `/guestbook`, `/profile`,
  `/api/xml`) are wrapped in `_token_enforced` so every token the hardened profile serves is enforced,
  and the passive `/profile` assertion also expects the tokenless `/newsletter` form.

## Stage 4 — Docs and close

- [x] `docs/authenticated-scanning.md`: remove the "Active CSRF confirmation" bullet from
  "What is deferred"; add the "Active CSRF confirmation" section — the experiment, the
  switch, what is written to the target, the three verdicts, and the RF-17 blind spots (one
  place, each resolving toward *inconclusive* / *no finding*). — RF-16, RF-17
- [x] `docs/active-injection.md` (the checks table and the flag / config list),
  `docs/architecture.md` (the csrf bullet now covers the pass; spec list through 017),
  `README.md` (`v0.17` row; "Scope and limitations"), `CLAUDE.md` (layer-3 paragraph, the
  `Estado` line, the pending list loses "active CSRF confirmation"), `specs/README.md`
  (roadmap row, the `007` pending note), and `docs/stack.md` only if it names the passes.
  — RF-16
- [x] Manual verification: serve the fixture, run `uv run webvigil scan … --mode active
  --authorized-by … --confirm-csrf`, check the three outcomes by eye (two confirmed forms, two
  refuted, one tally warning, the passive `/newsletter` finding replaced) and that the same
  scan without the switch writes nothing to `/newsletter` or `/settings`. Record it in
  `design.md` under "Implementation notes", together with any deviation from the design. — RF-13
- [x] Set `status: done` on the three spec files and the roadmap row; quality gate: ruff /
  black / mypy / lint-imports green and the **full** `pytest`; record the final count and the
  delta against the baseline above. — RNF-02
  **995 passed** (921 before: +74 — `test_csrf_scanner` 29, `test_fixture_csrf` 10, and 35 added to
  existing files: the CSRF checks, the orchestrator, the CLI, the safety predicates and the integration scans). The
  count is the sum of the full run (everything but the two envelope tests) and the green rerun of
  `tests/integration`; a full run takes about an hour on this machine.
