---
feature: POST form submission by the crawler — urlencoded, multipart and OpenAPI JSON bodies (Active Mode, opt-in)
status: done
date: 2026-10-07
related:
  - 018-post-form-crawl/requirements.md
  - 018-post-form-crawl/design.md
origin: conception
---

# 018 — POST form submission by the crawler — Tasks

Ordered, small, each tagged with the requirement / ADR it satisfies. The last task of every
stage is the quality gate (`ruff → black → mypy src → lint-imports → pytest`). Engine and CLI
only — no `web` gate, no API migration (RNF-01, RNF-02).

The unit suite runs in under a minute; a full `pytest` takes about an hour because of the
integration scans, so a stage gate runs lint, types, import contracts and the **unit suite**;
the **integration file** runs at Stage 3 (the first stage that changes the fixture) and the
**full** suite at Stage 4 (close). The baseline count is recorded when Stage 0 starts and the
delta when the spec closes.

Baseline before 018 (clean `main` after spec 017): **995 passed** (the spec 017 close).
At 018 close: **1062 passed**.

## Stage 0 — Behaviour-neutral prep: shared helpers, the page method, the keys

- [x] `webvigil/crawler/safety.py`: move `is_candidate(form)` here from
  `checks/csrf/tokens.py` (it only calls `is_auth_form` / `looks_like_search`); `tokens.py`
  imports it and keeps `is_token_field`. Add `looks_unsafe_operation(op)` — flatten
  `url_template` and `operation_id`, turn `_` and `-` into spaces, match `_DESTRUCTIVE_RE`,
  `_LOGOUT_RE` or `_AUTH_FORM_RE`. — ADR-4, RF-03
- [x] `webvigil/crawler/forms.py`: add `form_body(form, *, sentinel, skip, replace)` (the field
  table of spec 017's `_build_body`: defaults unchanged, the sentinel for a text-like control
  with no default, typed fallbacks, unchecked boxes omitted, first named submit) and its
  `_fallback` helper; `checks/csrf/scanner._build_body` becomes a thin wrapper
  (`skip` = token field names for the removed replay, `replace = {name: _alter(value)}` for
  the altered one). No logic change: `test_csrf_scanner.py` passes untouched. — ADR-4, RF-05
- [x] `webvigil/core/context.py`: `Page.method: str = "GET"`, the `fetched_by_get` property,
  and a `method` argument on `from_response` / `failed`, documented in `Attributes:`. — ADR-2
- [x] `webvigil/http/client.py`: widen the `_Files` alias to also admit a list of
  `(name, (filename | None, content, content type | None))` pairs; docstring says why. No
  logic change. — ADR-5
- [x] `webvigil/core/config.py`: `ScanSection.submit_post_forms: bool = False` and
  `max_post_submissions: int = 25` (positive), documented — the first says it writes to the
  target. — RF-01, RF-04, ADR-6
- [x] Tests: `test_crawler_forms.py` — `form_body` per field type (the table), `skip`,
  `replace`; `test_crawler_safety.py` — `is_candidate` still excludes auth / search / GET,
  `looks_unsafe_operation` (login, `delete_account`, `/orders/remove`, a benign operation);
  `test_config.py` — the two keys, defaults and TOML; a `Page` test file or an addition to
  `test_crawler.py` — `Page.method` defaults to `GET`, `fetched_by_get`, `from_response` /
  `failed` pass the method through. — RF-14
- [x] Quality gate: ruff / black / mypy / lint-imports green; the **unit suite**, with
  `test_csrf_scanner.py` and `test_checks_csrf.py` untouched (the proof the move changed
  nothing). — RNF-02
  Whole unit suite green. The 017 scanner and check tests passed untouched through the `form_body` extraction and the `is_candidate` move.

## Stage 1 — The POST phase

- [x] `webvigil/crawler/crawler.py`: factor the GET loop of `discover()` into
  `_drain(queue, pages, robots, max_pages)` (the same behaviour) and call it from the phase-1
  BFS; module docstring updated (the POST phase, what it writes). The existing crawler tests
  pass untouched. — ADR-3
- [x] `crawler.py`: `PostSummary`, the `post_operations=` constructor argument, the
  `_post_enabled` gate (`submit_post_forms` **and** `mode is ACTIVE`), `post_summary`
  property, and `_next_candidate()` — forms in inventory order (`POST`, urlencoded or
  multipart, no file input, `is_candidate`, not `is_destructive_form`, not `is_logout`,
  `robots.txt` allows), then API operations (`POST`, not `looks_unsafe_operation`); each skip
  tallied once per distinct form / operation. — RF-02, RF-03, RF-07
- [x] `crawler.py`: `_submit_form` (urlencoded `content=urlencode(pairs)` + `Content-Type`;
  multipart as `files=[(name, (None, value))]`; the marker `wvcrawl<token>`) and
  `_submit_operation` (`op.url`, `params=op.query`, `body_json` / `body_fields` / none with
  the matching `Content-Type`); both through `HttpClient.request("POST", …)`, no `Origin` /
  `Referer`, a failed request returns a failed `Page`. — RF-05, RF-06, RF-07, ADR-5, ADR-6
- [x] `crawler.py`: `_post_phase` — the loop of the design (submit, append the `Page` with
  `method="POST"`, enqueue its links and forms, `_drain`, next), stopping at
  `max_post_submissions` or `max_pages`, counting `over_cap`; called from `discover()` only
  when `_post_enabled`. — RF-04, RF-06, ADR-1, ADR-3
- [x] Tests: `tests/unit/test_crawler_post.py` (a `_FakeHttp` recording every `GET` / `POST`
  with headers and body, and a small site) — every item of the "Unit — `test_crawler_post.py`"
  bullet of the design's test strategy, plus the gate (nothing sent when the switch is off or
  the mode is Passive). — RF-14
- [x] Quality gate: ruff / black / mypy (the touched modules included) / lint-imports green;
  the **unit suite**. — RNF-02
  21 passed in `test_crawler_post.py`; the whole unit suite is green. mypy flagged two things on the first pass (a loop variable reused across two key types, and list invariance for the multipart parts); both fixed.

## Stage 2 — What the other passes learn, wiring, CLI

- [x] The four re-request / enumerate sites skip a page that is not `fetched_by_get`:
  `injection/stored.py` (`frontier` and `pre`), `injection/points.py` (`enumerate_points`
  GET points), `envelope/scanner.py` (`_sample_urls`), `disclosure/probe.py`
  (`_discovered_dirs`; `_referenced_scripts` unchanged). — RF-09, ADR-2
- [x] `webvigil/core/orchestrator.py`: pass `post_operations=` to the `Crawler`; append the
  `POST crawl: …` warning from `crawler.post_summary` (none when the phase did not run or had
  nothing to submit); the "POST crawling requires --mode active" warning in `run()`. — RF-01,
  RF-08, ADR-7
- [x] `webvigil/cli/app.py`: `--submit-post-forms/--no-submit-post-forms` (help says it writes
  to the target), `_build_config` / `_run_scan` / `_emit` plumbing like `--confirm-csrf`;
  `cli/_render.py`: the dim "POST crawl: enabled …" note. — RF-01, RNF-03
- [x] Tests: one test per pass proving a `POST` page is skipped and a `GET` page is not;
  orchestrator tests (operations reach the crawler, the summary warning and its absence, the
  Active-only warning, a Passive scan with the switch sends nothing); `test_cli.py`
  (`--submit-post-forms`, the config override both ways, the summary note). — RF-09, RF-14
- [x] Quality gate: ruff / black / mypy / lint-imports green; the **unit suite**. — RNF-02
  Whole unit suite green. New: `test_post_pages.py` 4 (one per pass), 4 orchestrator tests, 2 CLI tests. The four stub crawlers of the orchestrator tests gained a `post_summary = None` attribute — the real crawler's interface grew.

## Stage 3 — Fixture app and integration

- [x] `tests/fixtures/app.py`: the `/support` page and the routes of the design's table
  (`/support/ticket`, `/support/callback`, `/support/feedback`, `/api/notes`, plus the GET
  pages `/support/status` and `/support/received`), `app.state.post_log` reset per app,
  escaped echoes, the insecure stack trace / SRI-less script / unflagged cookie on the
  `/support/feedback` answer, the hardened plain `400`; `/support` linked from the shared
  link block and registered in both profiles; a comment above each route naming its role.
  — RF-12
- [x] Tests: `tests/unit/test_fixture_post.py` — each route's answer, the multipart parse, the
  JSON body, `post_log` entries, both profiles. — RF-12, RF-14
- [x] `tests/integration/test_scan_fixture_app.py`: a `post_forms` option on the `scan`
  fixture and a helper that writes the one-operation OpenAPI document to `tmp_path`; the
  scenarios of the design's "Integration" bullet (insecure + switch; without it and Passive
  with it; hardened + switch; the JSON operation; no re-request with `GET`; determinism).
  Update the crawl-count assertion for `/support`. — RF-13
- [x] Re-measure against the fixture: `/support/ticket`, `/support/callback` and
  `/support/feedback` are new `POST` injection points and `/support` adds form actions to the
  spec-012 envelope sample. Confirm every existing `injection.*` and envelope integration test
  still passes at the current caps; if one starves, raise the number by measurement and record
  before / after here, as 011, 014, 016 and 017 did. — RNF-04
- [x] Quality gate: ruff / black / mypy / lint-imports green; the **unit suite** and
  `tests/integration`. — RNF-02
  The whole unit suite and the whole `tests/integration` folder (72 tests) are green.
  **Re-measure:** the three new `/support` forms did not starve any `injection.*` test (the
  injection budget and `_PER_POINT_REQUEST_CAP` are unchanged); the spec-012 envelope tests did
  starve — the sample takes the entry, then every form action, then the other pages, so the
  seven form actions of specs 017 and 018 pushed `/reset` and `/resource` out. The integration
  config's `envelope_url_sample` / `envelope_budget` went 20 / 130 → 24 / 150 (017) → **30 / 180**
  (018), test-only; the engine defaults are untouched. The 017 hardened CSRF test also needed the
  hardened `/support` routes to enforce the token they serve (`_support_guarded`).

## Stage 4 — Docs and close

- [x] `docs/authenticated-scanning.md`: "Form-driven crawling" covers the `POST` phase (what
  it submits, the three body kinds, the filter, the cap, that it **writes to the target** and
  what it never does); the "`POST` form submission by the crawler" bullet leaves "What is
  deferred" (multipart / JSON bodies and parameter mining are addressed or restated);
  `docs/api-scanning.md` (the `POST` operations are submitted under the switch);
  `docs/architecture.md`, `README.md` (`v0.18` row, the opt-in switches sentence, a quick-start
  line), `CLAUDE.md` (layer-2/3 paragraph, `Estado`, the pending list) and `specs/README.md`
  (roadmap row). — RF-16
- [x] Manual verification: serve the fixture, run `uv run webvigil scan … --mode active
  --authorized-by … --submit-post-forms [--openapi <doc>]`, check by eye the `POST crawl:`
  warning, the pages behind the `POST`s in `pages_scanned`, the findings on the
  `/support/feedback` answer, and that the same scan without the switch posts nothing to
  `/support/*`. Record it in `design.md` under "Implementation notes", with any deviation from
  the design. — RF-13
- [x] Set `status: done` on the three spec files and the roadmap row; quality gate: ruff /
  black / mypy / lint-imports green and the **full** `pytest`; record the final count and the
  delta against the baseline above. — RNF-02
  **1062 collected**, all passing (995 before: +67 — `test_crawler_post` 21, `test_fixture_post` 17,
  `test_post_pages` 4, and 25 added to existing files: forms, safety, config, crawler, the
  orchestrator and CLI tests, the integration scans). The count is the sum of the whole unit suite
  and the whole `tests/integration` folder (72), each run green after the last code change; only docs
  and spec files changed after them, and a single full run takes about an hour on this machine.
