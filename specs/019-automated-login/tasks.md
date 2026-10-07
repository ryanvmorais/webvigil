---
feature: Automated login — find the login form, submit credentials, capture the session, re-authenticate when it drops (Active Mode, opt-in)
status: done
date: 2026-10-07
related:
  - 019-automated-login/requirements.md
  - 019-automated-login/design.md
origin: conception
---

# 019 — Automated login — Tasks

Ordered, small, each tagged with the requirement / ADR it satisfies. The last task of every
stage is the quality gate (`ruff → black → mypy src → lint-imports → pytest`). Engine and CLI
only — no `web` gate, no API migration (RNF-01, RNF-02).

Since the test audit (#101) the whole suite runs in about 10 minutes, so every stage gate runs
the **full** `pytest`; the unit suite alone (`pytest tests/unit tests/api`) is the quick check
inside a stage. Tests follow [`specs/README.md`, "Testes de uma spec"](../README.md#testes-de-uma-spec):
logic in unit, integration attached to the shared scans, about 1.0 test line per source line.

Baseline before 019 (clean `main` after #108): **878 passed**. At 019 close: **967 passed** (+89) in 10 min 33 s, with 6 new unit files, rows in four existing ones and one extra integration scan.

## Stage 0 — Behaviour-neutral prep: config, errors, result, shared helpers

- [x] `webvigil/crawler/forms.py`: extract `parse_forms_html(text, url, target)` from
  `parse_forms` (which becomes a call to it); no logic change, `test_crawler*` pass untouched.
  — design "Module layout"
- [x] `webvigil/core/errors.py`: `LoginFailedError(WebVigilError)`, documented. — RF-06
- [x] `webvigil/core/config.py`: `LoginSection` (fields, validators: `extra_fields` as
  `name=value`, the two markers compiled, `form_index >= 0`, `max_relogins` in 0..10, a
  `before` validator that rejects a `password` key with the explanatory message) and
  `AuthSection.login: LoginSection | None = None`; properties `AuthSection.configured`
  (`cookies or headers or login`) and `has_session` (`cookies or login`). — RF-02, RF-03
- [x] Replace `bool(config.auth.cookies or config.auth.headers)` in `core/orchestrator.py`
  (`authenticated=`) and `crawler/crawler.py` (`_authenticated`) by `auth.configured`, and
  `bool(ctx.config.auth.cookies)` in `checks/csrf/checks.py` by `auth.has_session`. No change
  without a login. — design "Impact"
- [x] `webvigil/core/result.py`: `LoginSummary(relogins: int, session_lost: bool)` and
  `ScanMetadata.login: LoginSummary | None = None`, documented in `Attributes:`; export from
  `webvigil.core`. — RF-11
- [x] Tests: add rows to the existing tables in `test_config.py` (login defaults, each bad
  value, the `password` key, a bad regex, range of `max_relogins`, TOML round trip) and to
  `test_reporters.py` (`metadata.login` is `null` without a login). Unit suite green.
- [x] **Stage 0 gate:** `ruff → black --check → mypy src → lint-imports → pytest` (full).

## Stage 1 — The session: jar, `Session`, `HttpClient`

- [x] `webvigil/http/session.py`: `SessionJar` over `httpx.Cookies` — `begin` / `commit` /
  `rollback`, `absorb(raw, handshake=)` (handshake accepts every cookie and honours a
  clearing `Set-Cookie`; live accepts only names already held), `pairs_for(url)` (target host
  only), `values`. — RF-07, ADR-2
- [x] Same file: `Session` — `generation`, `relogins`, `max_relogins`, `lost`, the login-URL
  predicate and `logged_out_marker` it is built with, `known_login_redirects`,
  `looks_dropped(response)` (401; login redirect from a non-login URL not yet learned; marker;
  never 403 / 5xx / out-of-scope redirect), `recover(seen)` under an `asyncio.Lock` with the
  generation test, the cap, the `check_url` confirmation and the failed-attempts-count rule,
  `summary()`, `warnings()`, `secrets`. — RF-08, RF-09, ADR-4, ADR-6
- [x] `webvigil/http/client.py`: `use_session()`; `handshake()` async context manager over a
  module `ContextVar`, set / reset in `try/finally`, calling `jar.begin()`; split `request`
  into `_send_with_redirects` (today's body) and the drop-retry wrapper; in
  `_request_with_retry` replace the cookie block (static pairs minus the session's names, then
  the session pairs, target host only) and absorb each raw response; keep
  `self._active_client.cookies.clear()`. Without a session every byte is as before. — RF-07,
  RF-09, ADR-1, ADR-3
- [x] Tests: `test_session_jar.py` (handshake hops, rotation-only live mode, Secure on http,
  Path, host-only, expiry and `Max-Age=0`, non-target host, `localhost` and an IP, `values`)
  and `test_http_session.py` (no session = same request bytes; attach merges static + jar and
  the login wins a name clash; drop → one re-login → one retry and the retry's verdict is
  returned; `403` / `5xx` never re-login; N concurrent `401`s → one login; cap and `lost`;
  `check_url` confirms or vetoes; ADR-6 learning; two concurrent tasks and the `ContextVar`).
  Every existing `test_http_client.py` test passes untouched. — RF-07..RF-09
- [x] **Stage 1 gate:** the full gate.

## Stage 2 — The `Authenticator` and the scrub

- [x] `webvigil/auth/__init__.py`, `auth/login.py`: `Credentials` (frozen dataclass, `__repr__`
  hides the password, `from_environment(name)`), `LoginResult(confirmed: bool)` and
  `Authenticator.login()` — gate checks (scope, https), `GET` the login page, pick the form
  (`form_index`, password-typed field, listing what was found on zero / several), pick the
  fields and apply the overrides (a missing named field fails naming it), build the body with
  `form_body(..., replace=...)`, submit **once** with `Origin` / `Referer` (urlencoded or
  multipart), verify in the order markers → `check_url` → heuristic, commit or roll back, and
  fail with a message that carries no body, cookie or password; an SSO / out-of-scope redirect
  fails with the "delegated login is not supported" message. — RF-04, RF-05, RF-06, ADR-5
- [x] `webvigil/auth/scrub.py`: `scrub_result(result, secrets)` — JSON round trip, four
  spellings per secret (raw, JSON-escaped, `quote`, `quote_plus`), secrets under 4 characters
  skipped, `[redacted]` placeholder. — RF-11, ADR-9
- [x] Tests: `test_auth_login.py` (table over small HTML pages: one / none / several forms,
  `form_index`, field picking and each override, hidden fields and extras in the body,
  multipart, scope and scheme gates, SSO redirect, verification order incl. *inconclusive*,
  exactly one `POST`, a wrong password never retried, error messages free of secrets) and
  `test_auth_scrub.py` (four spellings, short secrets, nesting in evidence / warnings /
  metadata, fingerprints unchanged). — RF-04..RF-06, RF-11
- [x] **Stage 2 gate:** the full gate. `lint-imports` confirms `webvigil.auth` imports no UI
  framework.

## Stage 3 — Orchestrator, CLI, summary

- [x] `webvigil/core/orchestrator.py`: `credentials=` constructor argument (falls back to
  `os.environ[password_env]`, else `LoginFailedError`); after `HttpClient` opens and **before**
  `_load_openapi`: in Active Mode build the `Session` / `Authenticator`, `login()`,
  `http.use_session()`; Passive with a login configured appends the RF-01 warning and sends
  nothing; an unconfirmed login adds its warning; after the checks `warnings.extend(
  session.warnings())`, `metadata.login = session.summary()` and
  `scrub_result(result, session.secrets)`. — RF-01, RF-06, RF-09, RF-11, ADR-7, ADR-8
- [x] `webvigil/cli/app.py`: `--login-url`, `--username`, `--password-env`; `_build_config`
  deep-merges them into the file's `[auth.login]`; resolve the password (env → no-echo
  `typer.prompt` on a TTY → usage error, exit 2) and pass `Credentials` to the
  `Orchestrator`; `LoginFailedError` already exits 4. Help text says it makes a real login. —
  RF-02, RF-01
- [x] `webvigil/cli/_render.py`: the summary line (`auth: logged in (N re-logins)` /
  `session lost after N re-logins` / `login not confirmed`) from `result.metadata.login`, the
  username from the CLI's own config. — RF-11
- [x] Tests: rows in the `test_cli.py` tables (flags merge deep into the file, password from
  env / prompt / usage error, exit 4 on a failed login, the summary line, Passive warning)
  and `test_orchestrator.py` (login before the OpenAPI load, Passive sends nothing, metadata
  and scrub applied) — logic at unit level with `MockTransport`. — RF-01, RF-02, RF-11
- [x] **Stage 3 gate:** the full gate.

## Stage 4 — Fixture app and integration

- [x] `tests/fixtures/app.py`: the `/signin` area in both profiles — `GET /signin` (form with
  `email`, `password`, hidden `csrf`, sets `pre=<token>`), `POST /signin` (token check, wrong
  password → `200` + form + error, right → `session=<opaque>` and `302 /signin/done`),
  `/signin/done` (`welcome=1`, `302 /account`), `/portal/ping` and `/portal/api` (live until
  `session_ttl` authenticated requests, then `302 /signin` / `401`), `/blocked` (`403`),
  `/sso` (`302` to `https://idp.webvigil.invalid/…`); `app.state.login_log`, `sessions`, a
  lockout counter (hardened: `429` after 3 failures); `make_app(profile, *, session_ttl=None)`.
  `/login` and the any-cookie `/account*` gate stay. — RF-12
- [x] `tests/unit/test_fixture_signin.py`: only the safety-relevant guarantees (the CSRF token
  is enforced, the lockout counter counts, the session expires exactly at `session_ttl`);
  no test that restates a route's page content. — RF-12
- [x] `tests/integration/test_scan_fixture_app.py`: the `_full` scan swaps its static `session`
  cookie for `[auth.login]` + `credentials` (the bearer header stays) and the existing
  assertions must still pass; add `login_log` has one entry, `metadata.login.relogins == 0`,
  and extend the "no secret in any report" test to the password and the session value; **one**
  new scan configuration (Active, small `session_ttl`) asserting expiry → re-login → crawl
  continues, `relogins >= 1` and `len(login_log) == 1 + relogins`; a Passive scan with a
  login configured sends no `/signin` request and warns. — RF-13
- [x] **Stage 4 gate:** the full gate; record the suite time (it should stay near 10 minutes).

## Stage 5 — Docs and close

- [x] `docs/authenticated-scanning.md`: an "Automated login" section (flags, `[auth.login]`,
  the handshake, the verdict, re-login, the single attempt, what it will never do, the
  short-secret note, credentials advice) and the bullet leaves "What is deferred". — RF-14
- [x] `README.md` (feature list / flags), `CLAUDE.md` (architecture paragraph, state line,
  the 019 entry), `specs/README.md` (roadmap row to **done**), `docs/stack.md` only if a
  dependency appeared (none expected), the CLI help. — RF-14
- [ ] `/atualizar-docs`, then the full gate one last time; record the test count delta against
  the 878 baseline and the suite time. Mark the three spec files `status: done`.
- [ ] Open the PR with `Closes #52`; leave #53 for spec 020.
