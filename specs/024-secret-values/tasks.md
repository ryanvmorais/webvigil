---
feature: Secret values — one type for every credential and session value, which cannot be printed, logged or serialized by accident
status: in progress
date: 2026-11-24
related:
  - 007-auth-flows/requirements.md
  - 013-auth-and-api-surface/requirements.md
  - 019-automated-login/design.md
  - 020-session-security/design.md
  - 002-web-api/design.md
origin: conception
---

# 024 — Secret values — Tasks

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

Stage 4 also runs the dashboard's gate, from `web/`:

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

## Stage 0 — The type and its gates

- [x] Record the baseline on `main`, on one Python version:
  - the test count;
  - `uv run pytest --cov` per file;
  - three JSON reports of the fixture application (anonymous, with `[auth]` cookies and headers, and with the
    automated login), from `tests.fixtures.serve:app` served by `uv run uvicorn`, kept outside the repository
    for Stage 5.

  — RF-10, RNF-06
- [x] `src/webvigil/core/secrets.py`: `REDACTED`, `SecretKind`, `Secret` with every operation of the design's
  table, and `secret_field()` with the wrap validator, the two serialization modes and the JSON schema.
  — RF-01, RF-02, RF-03, ADR-1, ADR-5
- [x] `src/webvigil/core/secrets.py`: `collect_secrets(*roots)` over pydantic models, dataclasses, mappings and
  sequences, with the depth cap. — RF-07
- [x] `tests/unit/test_core_secrets.py`: the contract table of the design, one row per way out, each with its
  positive control on the revealed string. Add equality, hash, immutability, subclassing, `len`/`bool`,
  `secret_field` errors and schema, and `collect_secrets`, including a model with one more secret field.
  — RF-01, RF-02, RF-03, RF-07, RF-11
- [x] `tests/unit/test_secret_inventory.py`: the reveal inventory over the syntax tree of `src/webvigil`, with
  `ALLOWED_REVEALS` empty. It refuses `getattr(…, "reveal")` and `_value` outside `core/secrets.py`. Its
  positive control is a throwaway source with an unlisted call. — RF-03, ADR-3
- [x] `tests/unit/test_secret_inventory.py`: the credential-field gate of ADR-4, with its exemption table,
  its declared list and its two positive controls.
  - **Today's fields.** The ten credential fields still typed `str` go in a `PENDING_CONVERSION` set: the
    seven of the design's dry run, plus the declared `AuthSection.headers` and `CookieTransition.pre`/`post`.
    Each stage removes its own.
  - **Stale entries.** An entry that already holds a `Secret` fails.

  — RF-11, ADR-4
- [x] Apply the sabotage of the design for `core/secrets.py` and the two gates, and watch each test fail. — RF-11
  — 17 breaks, each red: `__str__`, `__format__` and `__repr__` showing the value, `__reduce_ex__` and
  `__getstate__` dropped, `__eq__` taking a `str`, the JSON serializer returning the value, assignment and
  subclassing allowed, the length check skipped, `collect_secrets` skipping dataclasses or off by one at the cap,
  an unlisted `reveal()` in `src`, a stale inventory line, and a pending, exempt or declared entry removed.
- [x] Mutation in batch over `core/secrets.py`. — RNF-06
  — `core/secrets.py`: 117 of 118 mutants killed, 1 equivalent (a constant `__hash__` keeps the contract). The
  gates' own logic, in the test file: 87 of 90 killed; 1 equivalent (the module filter only keeps third-party
  classes out), and 2 are the final assertions over today's clean source, proven by the sabotage above. Every
  new test is failed by some mutant except the `json.dumps` refusal, which has no project code to mutate.
- [x] Quality gate. — 3336 passed, 2 skipped (3222 and 2 before) in 104 s with coverage; ruff, black, mypy,
  `lint-imports` and the package check green; no file of `src/webvigil` loses a line or a branch, and
  `core/secrets.py` is fully covered.

## Stage 1 — The scan's configured credentials

- [x] `src/webvigil/core/config.py`:
  - **`AuthSection`.** `cookies` and `headers` become `list[Secret]`, parsed in the `mode="before"` validators
    into named secrets. The position-only messages and the reserved-header rule stay as they are.
    `header_pairs` returns `(name, Secret)`. `as_header` and `secret_values` are removed.

  — RF-04, ADR-2
- [x] `src/webvigil/core/config.py`: `ScanConfig.web` keeps no values (`{}` for any table). — RF-06
- [x] `src/webvigil/auth/login.py`: `Credentials.password: Secret`, with `__post_init__` wrapping a `str`.
  `from_environment` builds the secret, and `_build_body` reveals it. Add the site to `ALLOWED_REVEALS`.
  — RF-04, RF-03
- [x] `src/webvigil/cli/app.py`: the password prompt and the environment value become a `Secret` at once.
  — RF-04
- [x] `src/webvigil/http/client.py`:
  - `_cookie_header: Secret | None`, built by `_static_cookie_header`;
  - `_send` reveals the cookie header and each `[auth]` header value per request;
  - `_hop_headers` filters by name;
  - both sites are added to `ALLOWED_REVEALS`.

  — RF-04, RF-10
- [x] `src/webvigil/auth/scrub.py`:
  - `scrub_result(result, secrets: Iterable[Secret])` with the kind split and the `HEADER` scheme rule;
  - `REDACTED` comes from `core/secrets.py` and is re-exported;
  - `_spellings` is added to `ALLOWED_REVEALS`.

  — RF-07
- [x] `src/webvigil/core/orchestrator.py`: the scrub list comes from `collect_secrets(self._config,
  self._credentials) | session.secrets`. For now, `Session` keeps its jar values as strings, wrapped here as
  `SESSION` secrets until Stage 2. — RF-07
- [x] `tests/unit/`: adapt the tests listed below, with no assertion about the bytes sent changing.
  - `test_config.py`, `test_auth_scrub.py` and `test_auth_login.py`;
  - `test_http_client.py` and `test_http_redirect_credentials.py`;
  - `test_cli.py`.

  Remove `AuthSection.cookies`, `AuthSection.headers` and `Credentials.password` from `PENDING_CONVERSION`.
  — RF-04, RF-07, RF-10
- [x] Apply the stage's sabotage (the `HEADER` scheme rule, `collect_secrets` skipping dataclasses) and watch
  each test fail. — RF-11
  — 21 breaks, each red but one: the scheme rule, `collect_secrets` skipping dataclasses, the orchestrator
  collecting `self._credentials` or dropping the jar values, the cookie value unstripped in the scrub, the
  short count missing the credential without its scheme, the cookie stripped or the header unstripped in the
  config, a secret entry not passed through, a bare string parsed as a list, a non-string entry left to the type
  error, the `[web]` table kept, `Credentials` keeping a string or re-wrapping a secret, the wrong kind from the
  environment, the CLI or the prompt, the client holding header values as text, and the login's credentials
  replaced. The one green break, counting issued values as short, is equivalent: an issued value is a text only
  from 8 characters, so the code was simplified to one count.
- [x] Mutation in batch over the `AuthSection` validators, the scrub's kind split and `collect_secrets` as
  used by the orchestrator. — RNF-06
  — 120 mutants over every changed function (the validators, `header_pairs`, the `[web]` drop, `_texts`,
  `scrub_result`, `_static_cookie_header`, the client's credential checks, `Credentials`, the CLI's password and
  the orchestrator's scrub list), run against the whole unit suite: 119 killed. The survivor, `on_target` dropped
  from the session-cookie branch of `_request_with_retry`, is equivalent and on a line this stage did not change:
  the jar gives pairs for the target only, and the header is added only on the target. The first run, against
  the stage's own test files, also showed the `if scheme and credential.strip()` condition redundant (an empty
  credential is dropped by the caller), so it was removed, and it asked for three tests: the 4-character floor,
  spaces after the scheme, and a common-word session value left in the result. Its survivors on anonymous
  requests are killed by `test_http_session.py`. Every new or changed test is failed by a mutant or by the
  sabotage above.
- [x] `CHANGELOG.md`, `[Unreleased]`, **Changed**: `AuthSection.cookies` and `headers` and
  `Credentials.password` hold `Secret` in the Python API. — RNF-02, ADR-10
- [x] Quality gate. — 3348 passed, 2 skipped (3336 and 2 before); ruff, black, mypy, `lint-imports` and the
  package check green; no file of `src/webvigil` loses a line or a branch against the Stage 0 baseline.

## Stage 2 — Session values and the scanner's canary

- [x] `src/webvigil/http/session.py`:
  - `SessionJar._remember` stores `Secret(…, kind=SESSION, name=…)`;
  - `values` and `pending_items()` return secrets;
  - `SessionJar` and `Session` get names-only `repr`s;
  - `Session` loses `secrets=` and `given_secrets`;
  - `pairs_for` is listed in `ALLOWED_REVEALS` as the library-storage reading site, with its reason.

  — RF-05, ADR-6 — `pairs_for` calls no reveal, so it is in a `LIBRARY_READS` list of its own (design, deviation 13).
- [x] `src/webvigil/core/orchestrator.py`: drop the Stage 1 wrapping; `session.secrets` are secrets. — RF-07
- [x] `src/webvigil/auth/login.py`: `CookieTransition.pre` and `post` map to `Secret`. — RF-05
- [x] `src/webvigil/checks/session/`:
  - `session_cookies()` returns `(name, Secret)`;
  - `is_jwt`, `judge_value` and `judge_samples` take `Secret`;
  - `ids.py` and `is_jwt` reveal, added to `ALLOWED_REVEALS`;
  - the fixation check compares secrets with `==`.

  — RF-05, RF-03 — the weak-id facts moved to `ids.py` as `id_facts` (design, deviation 14).
- [x] `tests/unit/`: adapt `test_http_session.py`, `test_auth_login.py` and the session check tests. Remove
  `CookieTransition.pre` and `post` from `PENDING_CONVERSION`. — RF-05
- [x] `tests/fixtures/app.py`: `app.state.auth_log` records the `Authorization` header and the canary cookie of
  each request. — RF-11
- [x] `tests/integration/test_scan_fixture_app.py`: the `scan` fixture captures logging at `DEBUG` with the
  cached result. `_full` gains one static cookie with a canary value; check that the expected findings of the
  full scan do not change. — RF-11 — with the cookie, the full scans of both profiles give the same findings
  (71 and 0), severities, confidences, fingerprints and warnings as before it.
- [x] `tests/integration/test_scan_fixture_app.py`: the canary test.
  - **What it proves.** No spelling of the cookie, the bearer token, the password or the issued session id
    appears in the logs, the warnings, or the JSON, SARIF, HTML and Markdown renderings. The spellings are
    built in the test.
  - **Positive control.** The `auth_log` holds each value, and the session was confirmed.

  — RF-04, RF-05, RF-07, RF-11
- [x] `tests/unit/test_cli.py`: the CLI canary through `httpx_mock`, over stdout, stderr and the report
  files. — RF-08, RF-11
- [x] Apply the stage's sabotage (a jar value stored as a plain string in the scrub list, a reveal removed from
  the inventory) and watch each test fail. — RF-11
  — 15 breaks, each red: the orchestrator dropping the jar's values, the jar dropping the Latin-1 form, the jar's
  values or its pending cookies of the wrong kind, a value in the `repr` of the jar or of the session, a reveal
  out of the inventory, a stale library read, the session cookies of the wrong kind, the fixation compared by
  identity, a wrong length in the id facts, the fixture recording no credential, no log capture, the configured
  credentials left out of the scrub, and the canary cookie not sent. The engine canary alone does not see the
  scrub removed, because the fixture app echoes neither the configured values nor the session id; the
  orchestrator's unit tests and the CLI canary, whose site echoes both, do.
- [x] Mutation in batch over the jar's `_remember`, `pending_items` and the session checks' reading sites.
  — RNF-06
  — 115 mutants (97 on the guards of the changed functions, 18 on their values), run against the stage's test
  files and the canary: 93 killed. Two survivors were in this stage's code and asked for a test each: an empty
  cookie value adds nothing to the scrub list, and a decreasing series is read in the order issued. Against the
  whole unit suite, 96 are killed. The 19 left are guards of the session analysers and of the fixation step's
  entry that this stage did not change (specs 020 and before). Every changed function has a killed mutant, and
  every new test is failed by a mutant or by the sabotage above (the library-read test by the stale entry).
- [x] Quality gate. — 3355 passed, 2 skipped (3348 and 2 before) in 99 s with coverage; ruff, black, mypy,
  `lint-imports` and the package check green; no file of `src/webvigil` loses a line or a branch against the
  Stage 0 baseline.

## Stage 3 — A credential in a URL is refused

- [ ] `src/webvigil/core/urls.py`: `has_userinfo(url)`. — RF-09, ADR-7
- [ ] `src/webvigil/core/target.py`: `Target.parse` refuses userinfo before reading the host, with the
  design's message. — RF-09, ADR-7
- [ ] `src/webvigil/core/config.py`: the userinfo validator on `[auth.login]` `url`, `check_url` and
  `logout_url`, `[scan] openapi` and `[deps] osv_base_url`. — RF-09
- [ ] `tests/unit/test_core_urls.py` and the target tests: the design's table of refused and accepted forms.
  `tests/unit/test_config.py`: each URL setting refused by name, a file path and a relative URL accepted.
  `tests/unit/test_cli.py`: exit `4`, with neither part of the credential in stdout or stderr.
  — RF-09, RF-08, RF-11
- [ ] Apply the stage's sabotage (the check removed from `Target.parse`, and from one URL validator) and
  watch each test fail. — RF-11
- [ ] Mutation in batch over `has_userinfo`, the `Target.parse` refusal and the URL validators. — RNF-06
- [ ] `docs/authenticated-scanning.md`: the refusal and `--header "Authorization: Basic …"`, the username and
  `extra_fields` not being scrubbed, and command-line values staying visible to the shell history (the
  `[auth]` table avoids that). — RF-09, resolved decisions 1, 3 and 5
- [ ] `CHANGELOG.md`, `[Unreleased]`, **Security**: a target or a URL setting with a credential in it is
  refused, where the credential used to be dropped without a word. — RNF-02
- [ ] Quality gate.

## Stage 4 — Web API

- [ ] `src/webvigil/api/config.py`: `WebConfig.session_secret` as `secret_field(SIGNING_KEY)`, with the length
  check on the wrapped value, and the environment override through the same validation. — RF-06
- [ ] `src/webvigil/api/security.py`:
  - `create_token`, `decode_token`, `hash_password` and `verify_password` take `Secret` and reveal it, all
    four added to `ALLOWED_REVEALS`;
  - `resolve_session_secret` returns `Secret`;
  - `dummy_password_hash` wraps its value.

  — RF-06, RF-03
- [ ] `src/webvigil/api/schemas.py`: the four password fields as `secret_field(PASSWORD, …)` with today's
  limits. `src/webvigil/api/routes/` passes them through. `src/webvigil/api/cli.py`: `reset-password` wraps
  the prompt. Remove the five Web API fields (`session_secret` and the four passwords) from
  `PENDING_CONVERSION`; the set is now empty and is deleted.
  — RF-06, ADR-4
- [ ] `src/webvigil/api/app.py`: the `RequestValidationError` handler that keeps `type`, `loc` and `msg`, and
  `app.state.session_secret: Secret`. — RF-08, ADR-8
- [ ] `src/webvigil/api/migrations/versions/0003_strip_target_userinfo.py`: rewrite `scan.target` without
  userinfo; `downgrade` is a no-op, and the docstring says so. — RF-09, ADR-9
- [ ] `tests/unit/` (Web API):
  - **Canary.** A pinned canary `session_secret`, then setup, login, a password change and a too-long
    password, with logging at `DEBUG`. No canary appears in the logs or in the responses, and `loc` and `msg`
    stay in the `422`.
  - **Refused target.** `POST /api/scans` with userinfo answers `422`, without the target, and stores no row.
  - **Migration.** A `0002` database is upgraded to `0003`: the userinfo row is stripped, and the other row
    and the findings are unchanged.

  — RF-06, RF-08, RF-09, RF-11
- [ ] `uv run python scripts/dump-openapi.py`, then `pnpm gen:api` in `web/`. The password fields gain `format`
  and `writeOnly`, and the TypeScript types stay `string`. — RF-06
- [ ] Apply the stage's sabotage (`LoginIn.password` retyped to `str`, the `422` handler keeping `input`, the
  migration skipping a row) and watch each test fail. — RF-11
- [ ] Mutation in batch over the `422` handler, the migration and `resolve_session_secret`. — RNF-06
- [ ] `docs/web-api.md`: the `422` body has `type`, `loc` and `msg` only, and the migration strips stored
  userinfo. `CHANGELOG.md`, `[Unreleased]`:
  - **Security**: the Web API keeps no credential from a target URL, including in scans already stored;
  - **Changed**: the `422` body.

  — RNF-02, ADR-8, ADR-9
- [ ] Quality gate, the Python one and the dashboard's.

## Stage 5 — Cross-check and documentation

- [ ] RF-10: repeat the three scans of Stage 0 from the new `main`. Compare the JSON reports, leaving out
  timestamps and durations: findings, severities, check ids, fingerprints and `schema_version` are identical.
  — RF-10
- [ ] `.github/workflows/`: confirm the whole CI matrix on the last merge commit: `quality` on Linux and Windows
  for every Python version, `package`, `docker`, `web` and `compose`. — RNF-05
- [ ] `docs/writing-checks.md`: a check that handles a credential receives a `Secret`, and a new reveal needs
  an `ALLOWED_REVEALS` line with its reason. `docs/checks-internals.md`: the scrub list comes from
  `collect_secrets`. — RF-03, RF-07
- [ ] `CLAUDE.md`: one line in the architecture section saying that every new credential is a `Secret` and
  that a `reveal()` goes only at an inventoried site. — RF-03
- [ ] `design.md`: fill in `## Implementation notes` with the measurements: tests before and after, coverage
  per file, suite time, the mutation scores. Set `status: done` in the three files and on the roadmap of
  `specs/README.md`. — RF-11
- [ ] Quality gate.
