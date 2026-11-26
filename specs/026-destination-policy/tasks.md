---
feature: Destination policy — one place decides what each URL may receive, and a public name that resolves only to internal addresses is reported
status: in progress
date: 2026-11-25
related:
  - 001-foundation/design.md
  - 019-automated-login/design.md
  - 020-session-security/design.md
  - 023-httpx2-migration/design.md
  - 024-secret-values/requirements.md
origin: conception
---

# 026 — Destination policy — Tasks

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

Every new or changed test is seen failing once, by breaking the line it guards, and the pull request says what
was broken (`specs/README.md`, "Testing a spec", rule 9). The design's test strategy lists the sabotage of each
guard.

Each stage also runs mutation testing in batch over the guards it adds or changes:

- every changed function has a killed mutant;
- every surviving mutant is triaged as equivalent or outside the change;
- the score goes in the pull request (RNF-06).

Every user-visible change goes into `[Unreleased]` of `CHANGELOG.md` in the pull request of the stage that
makes it.

## Stage 0 — The policy module and the table of cases

- [x] Record the baseline on `main`, on one Python version:
  - the test count and the suite time;
  - `uv run pytest --cov` per file;
  - four JSON reports of the fixture application, from `tests.fixtures.serve:app` served by `uv run uvicorn`:
    anonymous, with `[auth]` cookies and headers, with the automated login and the session tests, and with
    `--scope subdomains` against `localhost`;
  - the requests the fixture received in each scan and the duration of each scan.

  The baseline is kept outside the repository for Stage 4. — RF-08, RNF-04, RNF-06
- [x] `src/webvigil/core/destination.py`: `CREDENTIAL_HEADERS`, `SPECIAL_USE_LABELS`, `may_request`,
  `may_carry_credentials`, `keeps_data`, `without_credentials`, `is_target_host` and `is_public_name`, as in the
  design's Components. `Target` only under `TYPE_CHECKING`; the list from `core/suffixes.py`. — RF-01, RF-02,
  RF-06, ADR-1, ADR-5
- [x] `src/webvigil/core/target.py`: the docstrings of `in_scope` and `carries_credentials` say that the package
  asks them through `core/destination.py`. No change in the rules. — ADR-1
- [x] `tests/unit/test_destination.py`, from the design's test strategy:
  - the table of `(target, scope, url)` rows, asserted against the module and against `Target`;
  - `keeps_data` over the four combinations of URLs, with `credentialed` true and false;
  - `without_credentials` dropping `Cookie`, `Authorization` and an `[auth]` name in mixed case, with the
    origin as the positive control, and `None` and `{}` passing through;
  - `is_public_name` with its true and false rows.

  — RF-02, RF-06, RF-10, ADR-5
- [x] Apply the design's sabotage and watch each test fail:
  - `may_carry_credentials` returning `may_request`;
  - `keeps_data` without its `credentialed` test;
  - `is_public_name` without `SPECIAL_USE_LABELS`;
  - `is_public_name` through `registrable_domain`.

  — RF-10
- [x] Mutation testing in batch over `core/destination.py`. — RNF-06; 51 mutants, 49 killed, 2 equivalent.
- [x] Quality gate. — 3727 passed, 4 skipped (Windows); 98 % line and branch coverage, `core/destination.py` 100 %;
  ruff, black, mypy, import-linter and the package check green.

## Stage 1 — The HTTP client and the session jar

- [ ] `src/webvigil/http/client.py`:
  - the scope check asks `may_request` and raises `OutOfScopeError` itself;
  - the credential attachment, the re-login check and the `Set-Cookie` intake ask `may_carry_credentials`;
  - `_withholds_data` becomes `not keeps_data(..., credentialed=self._credentialed())`;
  - `_hop_headers` becomes `without_credentials`, applied before the first `_request_with_retry` and on every
    hop;
  - `_CREDENTIAL_HEADERS` comes from `core/destination.py`.

  — RF-01, RF-03, ADR-2
- [ ] `src/webvigil/http/client.py`: remove `allow_out_of_scope` from `get`, `request` and
  `_send_with_redirects`. Delete `src/webvigil/http/scope_guard.py` and the `ScopeGuard` export of
  `src/webvigil/http/__init__.py`. — ADR-3
- [ ] `tests/unit/test_http_client.py`: rewrite the two tests that used `allow_out_of_scope`, so that they prove
  the out-of-scope refusal and an in-scope URL instead. Drop the keyword from the fake clients of
  `test_envelope_scanner.py`, `test_injection_engine.py` and `test_upload_scanner.py`. — ADR-3
- [ ] `src/webvigil/http/session.py`: `SessionJar(target)`. `pairs_for` asks `may_carry_credentials` in place of
  the host match, and the `repr` shows the target's origin. `src/webvigil/auth/login.py` builds
  `SessionJar(target)`. Tests that build a jar pass a `Target`. — RF-04, ADR-4
- [ ] `tests/unit/test_http_redirect_credentials.py`: a request with an explicit `Cookie` and `Authorization`,
  under `--scope subdomains`, to a sibling subdomain, both on the first request and after a redirect, leaves
  them off the wire. The positive control is the same request to the origin, which carries them. Seen failing
  on `main`. — RF-03, RF-10
- [ ] `tests/unit/test_session_jar.py`: `pairs_for` returns nothing for another port, for plain `http` from an
  `https` target and for a sibling subdomain. It returns the cookies for the origin and for the `https` upgrade
  of an `http` target. Seen failing with the host match restored. — RF-04, RF-10
- [ ] `CHANGELOG.md` `[Unreleased]`:
  - **Security:** a credential header that a pass sends itself follows the client's rule on the first request
    too.
  - **Changed:** `webvigil.http.ScopeGuard` and the `allow_out_of_scope` keyword of `HttpClient` are removed
    from the provisional Python API, and `SessionJar` takes a `Target`.

  — RNF-02, ADR-3, ADR-8
- [ ] Mutation testing in batch over the changed functions of `http/client.py` and `SessionJar.pairs_for`.
  — RNF-06
- [ ] Quality gate. —

## Stage 2 — The passes and the inventory gate

- [ ] `src/webvigil/auth/login.py`:
  - `_check_gate` asks `may_request` and `may_carry_credentials`;
  - the landing page check asks `may_request`;
  - `_check_delegated` picks its message with `is_target_host(...) or may_request(...)`.

  — RF-01
- [ ] `src/webvigil/checks/session/scanner.py`: `_may_get_cookies` asks `may_carry_credentials` and keeps its
  warning. The logout finder asks `may_request`. — RF-01, ADR-2
- [ ] `src/webvigil/crawler/crawler.py`, `forms.py` and `har.py`: links, form actions and HAR entries ask
  `may_request`. — RF-01
- [ ] `src/webvigil/crawler/openapi.py`: the document URL asks `may_request`, and the `servers` warning asks
  `is_target_host`. — RF-01
- [ ] `src/webvigil/checks/deps/fingerprint.py`, `checks/disclosure/probe.py` and `checks/upload/scanner.py`:
  `may_request`. — RF-01
- [ ] `tests/unit/test_destination_inventory.py`: the walk over `src/webvigil` with the three kinds of site
  (rule calls, destination comparisons, network openings). Rule calls are allowed only in
  `webvigil.core.destination`. `COMPARISONS` and `CONNECTIONS` hold each remaining site with its reason. The
  positive controls run over a throwaway source string:
  - an unlisted `in_scope` call fails;
  - an unlisted `parts.hostname == x` fails;
  - an unlisted `httpx2.AsyncClient(...)` fails;
  - a stale entry fails.

  — RF-05, RF-09, ADR-7
- [ ] `tests/integration/test_scan_fixture_app.py`: the `_osv_up` stub records the requests it gets. A test over
  the cached full scan asserts that no OSV request carries a `Cookie`, an `Authorization`, a configured
  `[auth]` header name, the session cookie's value or the target's host. The positive controls are that the
  fixture received the `[auth]` header in the same scan and that the stub was called. — RF-05, RF-10
- [ ] Apply the design's sabotage and watch each test fail:
  - a `target.in_scope(url)` added to a scratch copy of a pass (the inventory);
  - the scan's headers forwarded to the OSV client in a scratch change.

  — RF-10
- [ ] `docs/writing-checks.md`: a pass asks `webvigil.core.destination`, not `Target`, and a new destination
  comparison or network opening needs its inventory line with the reason. `docs/checks-internals.md`: the
  `Target.in_scope` mention becomes `may_request`. — RF-09
- [ ] Mutation testing in batch over `_check_gate`, `_check_delegated` and `_may_get_cookies`. — RNF-06
- [ ] Quality gate. —

## Stage 3 — The address notices

- [ ] `src/webvigil/http/addresses.py`:
  - `AddressNotices` and `MAX_LEFT_OUT_LINES`;
  - `AddressGuard.addresses` records `internal_target` and `left_out` under its lock, the first time it sees
    each host;
  - `AddressGuard.notices()` returns the snapshot;
  - `address_warnings(notices)` builds the lines of the design.

  — RF-06, RF-07, ADR-5, ADR-6
- [ ] `src/webvigil/core/orchestrator.py`: after `blocked_address_warning`, extend `warnings` with
  `address_warnings(http.addresses.notices())`. — RF-06, RF-07
- [ ] `tests/unit/test_http_addresses.py`, with the resolver stubbed:
  - an internal target under a public name records its notice and warning, and `addresses()` returns the
    internal addresses (positive control);
  - each non-public name of the `is_public_name` table records nothing;
  - a host with two public and one internal address records `(host, 1)` and allows the two public ones;
  - twelve such hosts give ten lines and the summary line;
  - a host with only internal addresses still raises `BlockedAddressError` and records nothing new.

  — RF-06, RF-07, RF-10
- [ ] An orchestrator unit test over a stub client whose guard returns both notices finds both warnings in
  `result.warnings`. — RF-06, RF-07, RF-10
- [ ] Apply the design's sabotage and watch each test fail: each record removed in turn, and the `extend` in
  the orchestrator removed. — RF-10
- [ ] `docs/architecture.md`: the destination policy in place of the scope guard paragraph, and the two
  warnings and the proxy note in the address guard paragraph. `CHANGELOG.md` `[Unreleased]`, **Changed**: the
  two warnings. — RF-06, RF-07, RNF-02
- [ ] Mutation testing in batch over `AddressGuard.addresses`, `AddressGuard.notices` and `address_warnings`.
  — RNF-06
- [ ] Quality gate. —

## Stage 4 — Cross-check and documentation

- [ ] RF-08: repeat the four scans of Stage 0 from the new `main`. Compare the requests the fixture received
  and the JSON reports, leaving out timestamps, durations and per-run random values: the requests are byte for
  byte the same, and findings, severities, check ids, fingerprints, warnings and `schema_version` are
  identical. Compare the scan durations with the baseline. — RF-08, RNF-04
- [ ] `.github/workflows/`: confirm the whole CI matrix on the last merge commit: `quality` on Linux and Windows
  for every Python version, `package`, `docker`, `web` and `compose`. — RNF-05
- [ ] `CLAUDE.md`: one line in the architecture section saying that every destination decision goes through
  `core/destination.py`, and that a new comparison or connection needs its line in
  `tests/unit/test_destination_inventory.py`. — RF-01, RF-09
- [ ] `design.md`: fill in `## Implementation notes` with the measurements: tests before and after, coverage
  per file, suite time, scan durations, the mutation scores. Set `status: done` in the three files and on the
  roadmap of `specs/README.md`. — RF-10
- [ ] Quality gate. —
