---
feature: Session-security checks — weak session ids, session fixation, logout that does not invalidate the session
status: done
date: 2026-10-07
related:
  - 020-session-security/requirements.md
  - 020-session-security/design.md
origin: conception
---

# 020 — Session-security checks — Tasks

Ordered, small, each tagged with the requirement / ADR it satisfies. The last task of every
stage is the quality gate (`ruff → black --check → mypy src → lint-imports → pytest`, the full
suite: it runs in about 10 minutes since the test audit, issue #101). Engine and CLI only — no
`web` gate, no API migration (RNF-01, RNF-02).

Tests follow [`specs/README.md`, "Testes de uma spec"](../README.md#testes-de-uma-spec): logic in
unit, integration attached to the shared scans, about 1.0 test line per source line.

Baseline before 020 (clean `main` after #109): **967 passed**. At 020 close: **1090 passed** (+123) in about 10.5 minutes.

## Stage 0 — Behaviour-neutral prep: the shared cookie module, the category, the config

- [x] `webvigil/checks/session/__init__.py` (docstring only) and `session/cookies.py`:
  `SESSION_NAME_RE` (the CSRF check's pattern widened by `connect.sid`, `phpsessid`,
  `jsessionid`), `is_session_cookie`, `is_jwt`, `session_cookies(headers)` (session-looking
  `(name, value)` pairs of a response's `Set-Cookie` lines, JWT-shaped values dropped, a
  malformed line skipped). `checks/csrf/checks.py` imports the shared pattern; no behaviour
  change — `test_checks_csrf.py` passes untouched. — RF-02, design "cookies.py"
- [x] `webvigil/core/findings.py`: `Category.SESSION`, documented in `Attributes:`. — RF-10
- [x] `webvigil/core/config.py`: `SessionSection` (`sample_ids`, `sample_count` 3..20,
  `test_logout`), `ScanConfig.session`, `LoginSection.logout_url`; the `with_overrides` docstring
  names the new section. — RF-01, RF-04, RF-07
- [x] `webvigil/core/context.py`: `Observations.session_hits: tuple[SessionHit, ...] = ()`
  (the hit type lives in `checks/session/scanner.py`; import under `TYPE_CHECKING` if it would
  cycle). — design "Hits and observations"
- [x] Tests: `test_session_cookies.py` (name pattern table of hits and misses, JWT skipping,
  several `Set-Cookie` lines, a malformed header) and rows in the `test_config.py` tables
  (`[session]` defaults and ranges, a bad `sample_count`, `logout_url`, the round trip). Unit
  suite green.
- [x] **Stage 0 gate:** the full gate.

## Stage 1 — HTTP and login plumbing

- [x] `webvigil/http/client.py`: `_ANON` `ContextVar` and `HttpClient.anonymous()` (sets `_ANON`
  and `_QUIET`, resets both in `finally`); in `_request_with_retry` an anonymous request carries
  no static `[auth]` cookie, no static `[auth]` header, no session pairs and absorbs nothing,
  while the caller's own `headers` (an explicit `Cookie`) go out untouched. Without the context
  every byte is as before. — ADR-2
- [x] `webvigil/http/session.py`: `Session.closed` and `close()`; `recover` returns `False` once
  closed. — RF-09
- [x] `webvigil/auth/login.py`: `CookieTransition(pre, post)`; the handshake records
  `pre` from the pending jar after the page `GET` and `post` after the `POST` chain, before the
  commit, kept as `Authenticator.transition` only for a committed login; `reference_url`
  (`check_url`, else the landing page). — ADR-3, RF-05
- [x] Tests: in `test_http_session.py` `anonymous()` (no static cookie, no static header, no
  jar, an explicit `Cookie` kept, a concurrent task unaffected, `close()` stops a re-login) and
  in `test_auth_login.py` the transition (pre/post values, a failed login records nothing, a
  re-login replaces it) and `reference_url`. Every existing client / auth test passes untouched.
- [x] **Stage 1 gate:** the full gate.

## Stage 2 — The analysers, the scanner and the checks

- [x] `webvigil/checks/session/ids.py`: `estimated_bits` (alphabet capacity), `Rule`,
  `judge_value` (short, low-entropy, numeric, repeating, timestamp, counter) and `judge_samples`
  (duplicates, sequence with a near-constant step, timestamp series, low variance); severity is
  the maximum over the fired rules. Pure functions. — RF-03, RF-04, ADR-6
- [x] `webvigil/checks/session/scanner.py`: `SessionHit` (value-free `facts`) and
  `SessionScanner` with the four steps — seen ids, anonymous samples
  (`async with http.anonymous()`, sequential, one hit per cookie name merged from both sources,
  a warning when nothing was issued), fixation (candidates from `transition`, cap 3, the
  confirming `GET` with an explicit `Cookie` minus the candidate, `MEDIUM` and `verified: no`
  without a reference or with an unconfirmed login) and logout (`logout_url` → crawled `<a>` →
  crawled `POST` form with `form_body`; the anonymous oracle; the pre-logout snapshot; one
  logout request; `session.close()`; the anonymous replay with the snapshot); each step in its
  own try/except, warnings on every skip. — RF-03..RF-09, ADR-1, ADR-3..5, ADR-8
- [x] `webvigil/checks/session/checks.py`: `WeakSessionIdCheck` (PASSIVE), `SessionFixationCheck`
  and `LogoutNotInvalidatedCheck` (ACTIVE), registered; location carries the URL and the cookie
  name, the dedup key is `"weak"` / `"fixation"` / `"logout"`, evidence straight from `facts`,
  OWASP WSTG and CWE references; `registry.load_plugins` imports the package. — RF-10, ADR-7
- [x] Tests: `test_session_ids.py` (tables: value → rules, capacity per alphabet, series →
  rules, a random series that fires nothing), `test_session_scanner.py` (each step against a
  `HandlerTransport` site, the cases listed in the design, and **no value in any hit** by
  planting a recognisable secret in every cookie), `test_session_checks.py` (hit → finding:
  location, name, dedup key independent of the value, severity, evidence) and the three rows in
  `test_check_metadata.py` (47 → 50 checks). — RF-03..RF-10
- [x] **Stage 2 gate:** the full gate. `lint-imports` confirms `checks.session` imports no UI or
  DB framework.

## Stage 3 — Orchestrator, CLI, summary

- [x] `webvigil/core/orchestrator.py`: `_log_in` returns the `Authenticator`; `_scan_session`
  (selected iff a `session.*` check is, last pass after `_scan_csrf`, hits into
  `Observations.session_hits`, scanner warnings appended, any exception downgraded to
  `session checks failed: …`); the `--test-logout` gate warning outside Active Mode or without a
  login. — RF-01, RF-09, RF-11, ADR-1
- [x] `webvigil/cli/app.py`: `--sample-sessions/--no-sample-sessions`,
  `--test-logout/--no-test-logout`, `--logout-url` (deep-merged into `[auth.login]` like the 019
  flags), help text saying what each sends and that the logout test ends the session;
  `webvigil/cli/_render.py`: the `Session checks: …` summary line. — RF-01, RF-07, RF-11
- [x] Tests: rows in the `test_cli.py` tables (the three flags override the file, the summary
  line, the gate warning) and `test_orchestrator.py` (the pass runs last and only when a
  `session.*` check is selected, a step failure becomes a warning, a Passive scan without
  `--sample-sessions` sends nothing new). — RF-01, RF-11
- [x] **Stage 3 gate:** the full gate.

## Stage 4 — Fixture app and integration

- [x] `tests/fixtures/app.py`: the insecure profile gets counter ids on `GET /signin`, a login
  that keeps the anonymous id, and a `GET /logout` that clears the cookie but keeps the session
  valid; the hardened profile gets a long random-looking index cookie (`__Host-session` changes
  from `abc123`), a login that issues a new id, and a `/logout` that deletes the session
  server-side; `app.state.logout_log`. The legacy any-cookie `/account*` gate stays. — RF-12
- [x] `tests/unit/test_fixture_session.py`: only the guarantees the integration leans on (the
  insecure login keeps the anonymous id and the hardened rotates it; `/logout` invalidates only in
  the hardened profile; the counter ids increase). — RF-12
- [x] `tests/integration/test_scan_fixture_app.py`: the `scan` fixture takes `sample_sessions`
  and `test_logout`; `_full` turns both on (no `logout_url`, so the discovery from the crawl runs);
  the insecure full scan reports `session.id.weak`, `session.fixation` and
  `session.logout.not-invalidated` carrying the cookie name and no value, the logout request is
  the last the app logs before the replay, the samples carried no `Cookie`; the hardened twin
  still reports nothing; the existing determinism and "no secret in any report" tests keep
  passing with the new findings. If the logout test cannot share the `_full` scan, one dedicated
  scan configuration, noted in the design. — RF-13
- [x] **Stage 4 gate:** the full gate; record the suite time (it should stay near 10 minutes).

## Stage 5 — Docs and close

- [x] `docs/authenticated-scanning.md`: a "Session-security checks" section (the three checks,
  the switches, what each proves and cannot prove, the secrets rule, the rules table) and the
  deferred bullet leaves; `docs/active-injection.md` coverage row; the check catalogue wherever
  the checks are listed. — RF-14
- [x] `README.md` (roadmap row `v0.20`, flags, the "Authentication" limitation), `CLAUDE.md`
  (architecture paragraph, state line, the 020 entry), `specs/README.md` (roadmap row to
  **done**), `docs/stack.md` only if a dependency appeared (none expected), the CLI help. —
  RF-14
- [ ] `/atualizar-docs`, then the full gate one last time; record the test-count delta against
  the 967 baseline and the suite time. Mark the three spec files `status: done`.
- [ ] Open the PR with `Closes #53`.
