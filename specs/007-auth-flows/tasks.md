---
feature: Authenticated scanning (static cookies), CSRF detection, and form-driven crawling
status: done
date: 2026-09-06
related:
  - 007-auth-flows/requirements.md
  - 007-auth-flows/design.md
origin: conception
---

# 007 — Authenticated scanning, CSRF detection, form-driven crawling — Tasks

Ordered, small, each tagged with the requirement it satisfies. The last task of every stage
is the quality gate (`ruff → black → mypy src → lint-imports → pytest`). No `web` gate
(RF-12 / RNF-02). Tasks are `[ ]` until done; `/spec implementar` marks them `[x]` one by
one and records the pytest count on each gate line. Baseline at spec 006 close: **431
passed**.

## Stage 0 — Category, `[auth]` config, `submit_forms`, metadata flag

- [x] `webvigil/core/findings.py`: add `CSRF = "CSRF"` to `Category` (after `INJECTION`). —
  RF-08, ADR-9
- [x] `webvigil/core/config.py`: add `class AuthSection(_Section)` — `cookies: list[str] =
  []`, a `field_validator("cookies")` that rejects an entry with no `=` or an empty name
  (`ValueError` → `ConfigError`), and an `as_header` property (`"; ".join(strip)`). Add
  `submit_forms: bool = True` to `ScanSection`. `ScanConfig` gains `auth: AuthSection =
  AuthSection()`; add `auth` to the `with_overrides` docstring's section list. — RF-01,
  RF-06, ADR-4
- [x] `webvigil/core/result.py`: `ScanMetadata` gains `authenticated: bool = False` (after
  `authorized_by`), with a comment that it records only *that* cookies were supplied. —
  RF-02, ADR-7
- [x] `webvigil.example.toml`: add a documented `[auth]` block (`cookies = []`, "sent only
  to the target host, never written to a report, CLI: --cookie") and a `submit_forms = true`
  line + comment under `[scan]`. — ADR-4
- [x] Tests (`test_config.py`): `[auth] cookies` round-trips; an entry with no `=` and one
  with an empty name each raise `ConfigError`; `as_header` joins; `[scan] submit_forms`
  default `True` and an override; an unknown `[auth]` key is rejected. — RF-01, RF-15
- [x] Quality gate. — 438 passed; ruff/black/mypy/lint-imports green.

## Stage 1 — Cookie attachment in the HTTP layer

- [x] `webvigil/http/client.py`: `HttpClient.__init__` computes `self._cookie_header =
  config.auth.as_header`. In `_request_with_retry`, build `req_headers = dict(headers or {})`
  and, when `self._cookie_header` and `_host_of(url) == self._target.host`, set/append the
  `cookie` header (append after a caller-supplied one with `"; "`); pass `req_headers` to the
  httpx call. Never log or store it. — RF-01, RF-02, ADR-1
- [x] Tests (`test_http_client.py`): a configured cookie is present on a target-host request;
  **absent** on an `allow_out_of_scope=True` request and on a different-host request; a
  caller `Cookie` header is preserved and the configured value appended; no `[auth] cookies`
  → no `cookie` header. — RF-02, RF-15, RNF-06
- [x] Quality gate. — 442 passed; ruff/black/mypy/lint-imports green.

## Stage 2 — `safety.py`, form parsing helpers

- [x] `webvigil/crawler/safety.py` (new): `is_logout(url)`, `is_destructive(url)` (word-
  boundary regex; **no** `reset`), `is_auth_form(form)` (login/signin/signup/register/auth/
  password), `looks_like_search(form)` (name/action contains `search`/`query`/`q`). Keyword
  lists per the design's "Heuristic keyword sets" table, commented. — RF-03, ADR-5, ADR-8
- [x] `webvigil/crawler/forms.py`: `FormField` gains `checked: bool = False` (from
  `"checked" in node.attributes` for checkbox/radio). Split the `extract_forms` loop body
  into `parse_forms(page: Page, target: Target) -> list[Form]` (single page, no dedup);
  `extract_forms` becomes the dedup wrapper over `parse_forms`. Add `submission_url(form) ->
  str | None` — `None` unless `method == "GET"`; else `action` with the query replaced by
  `urlencode` of `(name, value)` for value-carrying types + checked checkbox/radio
  (`_SUBMIT_VALUE_TYPES`), stable parser order. — RF-05, ADR-2, ADR-3
- [x] Tests: `test_crawler_safety.py` (new) — each `is_logout` / `is_destructive` keyword,
  word-boundary negatives (`/blogout`, `/undeletable`, `/reset-password` not destructive),
  `is_auth_form` / `looks_like_search` positives + negatives. `test_crawler_forms.py`
  (additions) — `FormField.checked` parsed; `submission_url` for a GET form with
  text/hidden/select/checkbox-checked/checkbox-unchecked/submit fields; `None` for a POST
  form; existing `extract_forms` tests still pass through `parse_forms`. — RF-03, RF-05,
  RF-15
- [x] Quality gate. — 466 passed; ruff/black/mypy/lint-imports green.

## Stage 3 — Crawler: form collection + GET-form submission + skip logic

- [x] `webvigil/crawler/crawler.py`: `__init__` derives `self._authenticated =
  bool(config.auth.cookies)`, `self._submit_forms = config.scan.submit_forms`,
  `self._forms: dict[...] = {}`, `self._skipped_destructive = 0`. Add `forms` and
  `skipped_destructive` properties. `_maybe_enqueue` skips a URL when `is_logout(url)` or
  (`self._authenticated and is_destructive(url)`), bumping `_skipped_destructive` for the
  destructive case. New `_collect_and_enqueue_forms(page, seen, queue)` — called per fetched
  HTML page: `parse_forms` → `self._forms.setdefault(key, form)`; for each `GET` form, if
  `self._submit_forms` and not `is_auth_form` / `is_logout(action)` / (`authenticated` and
  `is_destructive(action)`), enqueue `submission_url(form)`. — RF-03, RF-05, RF-06
- [x] Tests (`test_crawler.py` additions): GET search form → submission URL enqueued and
  fetched; POST form → not submitted but in `crawler.forms`; `/logout` link → never
  enqueued (anon and auth); authenticated + `/items/5/delete` link → skipped and
  `skipped_destructive == 1`; anonymous + same link → followed; `submit_forms = False` → no
  submission; submitted-form URLs count against `max_pages`; deterministic order. — RF-03,
  RF-05, RF-06, RNF-04
- [x] Quality gate. — 472 passed; ruff/black/mypy/lint-imports green.

## Stage 4 — `ScanContext.forms`, orchestrator wiring

- [x] `webvigil/core/context.py`: `if TYPE_CHECKING` import of `Form` from
  `webvigil.crawler.forms`; `ScanContext` gains `forms: tuple[Form, ...] = ()` (before
  `observations`). Update the docstring. — RF-07
- [x] `tests/support.py`: `make_context` gains `forms: Sequence[Form] | None = None` →
  `forms=tuple(forms or ())`. — RF-07
- [x] `webvigil/core/orchestrator.py`: build `crawler = Crawler(...)`; `pages =
  tuple(await crawler.discover())`; `forms = crawler.forms` (drop the
  `from webvigil.crawler.forms import extract_forms` import + call — keep `Form` for the
  `_inject` type); when `crawler.skipped_destructive`, append the "declined N link(s)"
  warning; pass `forms=forms` into `ScanContext`; set `authenticated=bool(self._config.auth.cookies)`
  on `ScanMetadata`. `_inject` unchanged (still receives `forms`). — ADR-2, ADR-7, RF-03,
  RF-07
- [x] Tests: `test_orchestrator.py` (additions) — `metadata.authenticated` is `True`
  with `[auth] cookies`, `False` without; `ctx.forms` reaches a check; the destructive-skip
  warning appears. (Also updated the three `_StubCrawler`s in the deps/disclosure/injection
  orchestrator tests to expose `forms` / `skipped_destructive`.) — RF-02, RF-03, RF-07
- [x] Quality gate. — 475 passed; ruff/black/mypy/lint-imports green.

## Stage 5 — `csrf.form.no-token`

- [x] `webvigil/checks/csrf/__init__.py` — `from webvigil.checks.csrf import checks  #
  noqa: F401`. `webvigil/checks/csrf/checks.py` — `_TOKEN_NAME_RE`, `_SESSION_NAME_RE`,
  `_weaker` / `_session_samesite(pages)` (stdlib `http.cookies.SimpleCookie`), `_is_token_field`,
  `_DESCRIPTION` / `_REMEDIATION` (naming the JS-token / header-token / double-submit blind
  spots), `OWASP_CSRF`; `NoCsrfTokenCheck(Check)` — `id = "csrf.form.no-token"`, `category =
  CSRF`, `mode = PASSIVE` (base default), `default_severity = MEDIUM`, `cwe = (352,)`; `run`
  iterates `ctx.forms`, skips non-`POST` / `is_auth_form` / `looks_like_search` / has-token,
  emits a finding with SameSite-weighted `confidence`, `Location(url=action, method="POST")`,
  `dedup_key="no-token"`, three evidence items. — RF-08, RF-09, ADR-6
- [x] `webvigil/checks/__init__.py`: add `csrf` to the `_load_builtin_checks` import tuple. —
  RF-10
- [x] Tests (`test_checks_csrf.py`, new): token present (each recognised name) → nothing;
  token absent → one finding; `GET` form → nothing; login form → nothing; `SameSite=Lax`
  session cookie → `LOW`; no `SameSite` → `HIGH`; no session cookie → `MEDIUM`; same action
  seen twice → one fingerprint; `location.method == "POST"`; evidence carries the field
  list. Uses `make_context(..., forms=[...], pages=[...])`. — RF-08, RF-09, RF-15
- [x] Quality gate. — 487 passed; ruff/black/mypy/lint-imports green.

## Stage 6 — CLI and reporters

- [x] `webvigil/cli/app.py`: `scan` gains `cookie: Annotated[list[str] | None,
  typer.Option("--cookie", ...)] = None`. `_build_config` gains `cookie: list[str] | None`,
  builds `auth_overrides = {"cookies": cookie}` when not `None`, passes `auth=auth_overrides`
  to `with_overrides`. A `ConfigError` from a bad pair is already caught. `_emit` passes
  `cookie_count=len(cfg.auth.cookies)` to `_render.summary`. — RF-10
- [x] `webvigil/cli/_render.py`: `summary(result, *, cookie_count: int = 0)`. After the
  injection block: when `cookie_count`, print `"Authenticated scan: N cookie(s) supplied"`
  (dim); when any `csrf.form.no-token` finding, print `"CSRF: F form(s) without an anti-CSRF
  token"` (yellow). — RF-10
- [x] Tests: `test_cli.py` (additions) — `--cookie a=1 --cookie b=2` → `config.auth.cookies
  == ["a=1", "b=2"]`; `--cookie` replaces a config-file list; a `--cookie` with no `=` →
  non-zero exit + one-line error, no traceback; `list-checks` shows `csrf.form.no-token`;
  the summary cookie-count and CSRF-count lines. `test_reporters.py` (additions) —
  `metadata.authenticated` is in the JSON and `true` when set; round-trips; SARIF/HTML/MD
  unchanged. — RF-10, RF-12, RF-15
- [x] Quality gate. — 493 passed; ruff/black/mypy/lint-imports green.

## Stage 7 — Fixture app, integration tests

- [x] `tests/fixtures/app.py` — **insecure** profile adds: `GET /account` (sync;
  `request.cookies.get("session") == "abc123"` → `200` linking `/account/settings` +
  `/logout` and rendering `<form method="post" action="/profile"><input name="nickname">
  </form>` with **no token**; else `RedirectResponse("/login", 302)`); `GET
  /account/settings` (same gate → `200`); `POST /profile` (`200`, `methods=["POST"]`); `GET
  /logout` (`RedirectResponse("/", 302)`). `_LINKS` gains `<a href="/account">account</a>`
  (both profiles). Route wiring via `_INJECTION_ROUTES`. — RF-13
- [x] `tests/fixtures/app.py` — **hardened** profile: `/account` + `/account/settings` gated
  on the `__Host-session` cookie; `POST /profile` form carries `<input type="hidden"
  name="csrf_token" value="tok123">`. (`_hardened` already sets `SameSite=Lax`.) — RF-13
- [x] `tests/integration/test_scan_fixture_app.py` — `scan` fixture `_run` gains `cookies:
  list[str] | None = None`. Tests: `test_authenticated_scan_reaches_the_account_area`;
  `test_anonymous_scan_stops_at_the_login_redirect`; `test_crawler_submits_the_get_search_form`;
  `test_crawler_never_submits_post_forms_or_logout`; `test_csrf_check_flags_the_tokenless_profile_form`;
  `test_hardened_authenticated_scan_reports_no_csrf`; `test_cookie_value_never_appears_in_any_report`;
  `test_authenticated_scan_is_deterministic`. Recomputed `test_crawler_reaches_the_linked_pages`
  (8 → 9: search-form submission + `/account`→`/login`) and loosened
  `test_the_login_form_is_never_fuzzed` (the crawler may now GET `/login` as a redirect
  target; the form is still never submitted with a payload). Also: `HttpClient` now clears
  the httpx cookie jar before each request so a scan sends only the configured `[auth]`
  cookies (determinism + config-driven auth). — RF-14
- [x] Quality gate. — 501 passed; ruff/black/mypy/lint-imports green.

## Stage 8 — Docs, roadmap, verification, close

- [x] `docs/authenticated-scanning.md` (new): supplying cookies (`--cookie`, `[auth]
  cookies`, CLI-replaces-config, where to get a cookie); the privacy guarantee (target-host
  only, never in a report); the jar-clearing determinism note; the logout / destructive link
  heuristic **and its limits**; form-driven crawling (GET only, default values,
  `submit_forms`); `csrf.form.no-token` (what it proves, the SameSite weighting, the
  false-positive blind spots); why the login flow, auth headers, and session-security tests
  are deferred. — RF-16
- [x] `docs/architecture.md` (the http / crawler / checks bullets + the specs list gains
  `007-auth-flows`), `docs/writing-checks.md` (`ctx.forms`; a note on a form-reasoning
  check; `webvigil/crawler/safety.py` as the shared "safe to touch" helper). — RF-16
- [x] `README.md` (coverage table `v0.7` row → shipped with the `docs/authenticated-scanning.md`
  link + the deferral note; an authenticated `--cookie` quick-start line), `CLAUDE.md`
  (layer-3 paragraph for authenticated crawl + `webvigil.checks.csrf`; `Estado` line → 007
  concluída, next = the three tech-debt specs; deferral note), `specs/README.md` (`007` row
  → **done**; a note that the login flow / auth headers / session tests slipped to a later
  spec and why). — RF-16
- [x] Set all three `007` spec files to `status: done`; add an "Implementation notes"
  section to `design.md` (jar clearing, field order, API mapping confirmed zero-change,
  crawl-count deltas, the pytest delta). — RF-16
- [x] Manual verification: `uvicorn tests.fixtures.serve:app` on `:9317` — authenticated
  scan reaches `/account` + `/account/settings` (14 pages), `csrf.form.no-token` on
  `POST /profile` at HIGH confidence, `metadata.authenticated: true`; anonymous scan reaches
  neither account page and reports no `csrf.*`; `--cookie "session=UNIQUESECRET42"` → the
  value appears 0 times in the JSON report; summary prints the cookie count + CSRF count;
  `webvigil list-checks` shows `csrf.form.no-token | CSRF | passive | MEDIUM`. — RNF-05, RNF-06
- [x] Final full quality gate: ruff / black / mypy (94 files) / lint-imports (2 contracts
  kept, 0 broken) / pytest — **501 passed**. — RNF-02
