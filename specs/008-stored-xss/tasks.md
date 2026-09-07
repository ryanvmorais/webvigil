---
feature: Stored / persistent XSS — two-phase inject-then-recrawl detection (Active Mode)
status: done
date: 2026-09-07
related:
  - 008-stored-xss/requirements.md
  - 008-stored-xss/design.md
origin: conception
---

# 008 — Stored / persistent XSS — Tasks

Ordered, small, each tagged with the requirement it satisfies. The last task of every stage
is the quality gate (`ruff → black → mypy src → lint-imports → pytest`). No `web` gate
(RF-12 / RNF-02). Tasks are `[ ]` until done; `/spec implementar` marks them `[x]` one by
one and records the pytest count on each gate line. Baseline at spec 007 close: **501
passed**.

## Stage 0 — Config, markers, models, `build_request` extraction

- [x] `webvigil/core/config.py`: add `stored_xss: bool = False` to `InjectionSection` (after
  `time_based_delay_s`), with the "opt-in; markers are persisted by design" comment. Update
  the `InjectionSection` docstring to mention spec 008. — RF-01, ADR-4
- [x] `webvigil.example.toml`: add a commented `stored_xss = false` line to the `[injection]`
  block — "two-phase stored-XSS pass; writes marker rows the target keeps; CLI: --stored-xss".
  — ADR-4
- [x] `webvigil/checks/injection/payloads.py`: add the stored-XSS section — `STORED_TOKEN_BYTES
  = 6` and `STORED_MARKERS = ("<wvstored{token}>", '"><wvstored{token}>')`, with the design's
  comments (inert tag, verbatim-in-executable-context, per-point token). — RF-04, ADR-5, RNF-06
- [x] `webvigil/checks/injection/points.py`: move `_build_request` here from `engine.py` as
  the public `build_request(point, value) -> tuple[str, str, list[tuple[str, str]],
  dict[str, str] | None]` (body unchanged). `webvigil/checks/injection/engine.py`: drop the
  local `_build_request`, `from webvigil.checks.injection.points import ... build_request`,
  call it in `_send`. — ADR-3
- [x] `webvigil/checks/injection/models.py`: add `StoredMarker` (frozen, slots — `token: str`,
  `point: InjectionPoint`, `payloads: tuple[str, ...]`) and `StoredXssReport` (`hits`,
  `warnings`, `markers_submitted: int = 0`, `pages_recrawled: int = 0`). Add
  `ActiveBudget.take_recrawl(n: int = 1) -> bool` — checks/increments `spent` against
  `request_limit` only (ignores `per_point_limit`). — ADR-5, ADR-6
- [x] Tests: `test_config.py` — `[injection] stored_xss` round-trips, defaults `False`, an
  override applies, an unknown `[injection]` key still rejected. `test_injection_points.py` —
  the moved `build_request` still builds a GET pair-list and a POST `dict` body + kept query
  (relocate the existing `_build_request` assertions). `test_injection_models.py` (new or
  additions) — `take_recrawl` decrements `spent`, does not consult `point_spent`, refuses
  past `request_limit`. — RF-15
- [x] Quality gate. — 507 passed; ruff/black/mypy/lint-imports green.

## Stage 1 — `Crawler.recrawl`

- [x] `webvigil/crawler/crawler.py`: add `async def recrawl(self, frontier: Sequence[str], *,
  should_fetch: Callable[[], bool], max_fetches: int) -> list[Page]`. Re-fetch every
  `frontier` URL (seed `seen` with their normalized forms so they are not re-queued as
  links), then follow **one hop** of new in-scope links and safe GET forms discovered on
  those frontier pages — reusing `_fetch`, `_enqueue_links`, `_collect_and_enqueue_forms`,
  and the `is_logout` / `is_destructive` / `is_auth_form` skips. Stop at `max_fetches` pages
  or when `should_fetch()` returns `False`. Do **not** re-consult robots/sitemap. Keep the
  one-hop bound simple (drain the frontier first, then a single pass of the link queue — no
  depth tuple needed). `discover()` unchanged. — RF-05, ADR-2
- [x] Tests (`test_crawler.py` additions): `recrawl` re-fetches every frontier URL; a new
  link on a frontier page is followed once; a link found on a one-hop page is **not**
  followed (no second hop); `should_fetch` returning `False` stops it; `max_fetches` caps
  the page count; a new `/logout` or destructive link is skipped; `submit_forms=False`
  suppresses form submission in the re-crawl. — RF-05, RNF-04
- [x] Quality gate. — 511 passed; ruff/black/mypy/lint-imports green.

## Stage 2 — `StoredXssScanner`

- [x] `webvigil/checks/injection/stored.py` (new): `_STORED_REFETCH_CAP = 60`, `_CHECK_ID =
  "injection.xss.stored"`, `_stored_order(points)` (form points before query points, stable
  order within each). `StoredXssScanner(http, target, config: ScanConfig, pages, forms)`:
  - `run()` — enumerate points (`enumerate_points`, `max_points=config.injection.max_injection_points`);
    build one `ActiveBudget(request_limit=config.injection.request_budget,
    per_point_limit=_PER_POINT_REQUEST_CAP, time_based_limit=0)`.
  - **Phase A** — per point (in `_stored_order`), `budget.start_point()`, mint `token = "wv"
    + secrets.token_hex(STORED_TOKEN_BYTES)`, submit each `STORED_MARKERS` template
    (`build_request` + `http.request(..., crafted=True)`, `budget.take()`-gated, swallow
    `RequestFailed` / `OutOfScopeError`); record `StoredMarker` when ≥1 payload was sent.
    Stop when `budget.exhausted()`.
  - **Phase B** — `frontier = tuple(p.url for p in pages if p.ok)`; `pre = {normalize_url(p.url):
    p.text for p in pages if p.ok}`; `recrawled = await Crawler(http, target, config).recrawl(
    frontier, should_fetch=budget.take_recrawl, max_fetches=min(_STORED_REFETCH_CAP,
    max(1, config.scan.max_pages)))`. Budget-exhausted → the 006 budget warning; `len(recrawled)
    >= _STORED_REFETCH_CAP` → the re-crawl-cap warning.
  - **Detect** — `_detect(markers, recrawled, pre)`: per marker, per re-crawled ok HTML page,
    per concrete payload string: `payload in page.text` and not in `pre[url]` (when the URL
    was known); render location must differ from `marker.point.base_url` unless the point was
    `POST`; classify context via `xss._context`; collect render locations. One `InjectionHit(
    kind="xss-stored", url=marker.point.base_url, method=..., param=...)` per marker with a
    hit — first executable render location + `(+N more page(s))` in evidence; `confidence`
    HIGH for a body/attribute break on a page ≠ the injection point, else MEDIUM;
    `title` names both ends. Snippet via `xss._snippet`. — RF-04, RF-05, RF-08, RF-09, ADR-1, ADR-5, ADR-6, ADR-9
- [x] Tests (`test_injection_stored.py`, new): Phase A — form points before query points;
  `_EXCLUDE_FORM_RE` form → no marker; hidden/CSRF field values preserved in the body;
  budget + per-point gating. Detection — `<wvstored…>` verbatim in body / attribute context
  → hit; entity-encoded / `text/plain` / HTML-comment → no hit; marker only in the Phase A
  POST response → no hit; marker already in a known page's pre-injection body → no hit;
  marker on a new URL → hit; multi-page render → one hit + `(+N more)` evidence; hit `url`
  == injection point (not the render page); confidence HIGH vs MEDIUM; `_STORED_REFETCH_CAP`
  truncation → warning. Uses `pytest-httpx` with a small router. — RF-15
- [x] Quality gate. — 522 passed; ruff/black/mypy/lint-imports green.

## Stage 3 — `injection.xss.stored` check

- [x] `webvigil/checks/injection/checks.py`: add `_DESCRIPTION["xss-stored"]` (the design's
  text), `_REMEDIATION["xss-stored"] = _REMEDIATION["xss"]`, `_REFERENCES["xss-stored"] =
  _REFERENCES["xss"]`; `@register class StoredXssCheck(_InjectionCheck)` — `id =
  "injection.xss.stored"`, `name = "Stored cross-site scripting"`, `kind = "xss-stored"`,
  `default_severity = Severity.HIGH`, `cwe = (79, 20)`, `references = _REFERENCES["xss-stored"]`.
  `_InjectionCheck.run` is reused unchanged. — RF-07
- [x] Tests (`test_checks_injection.py` additions): an `xss-stored` hit → one `HIGH` finding
  with `location = Location(url=<injection point>, method=..., param=...)` and evidence
  carrying the "Rendered on" line; `[]` when no `xss-stored` hit; `list-checks` metadata
  (`INJECTION` / `active` / `HIGH`). — RF-07, RF-15
- [x] Quality gate. — 523 passed; ruff/black/mypy/lint-imports green.

## Stage 4 — Orchestrator wiring

- [x] `webvigil/core/orchestrator.py`: `from webvigil.checks.injection.stored import
  StoredXssScanner`; `_STORED_CHECK_ID = "injection.xss.stored"`. Add `async def
  _inject_stored(self, check_types, http, target, pages, forms, warnings) ->
  tuple[InjectionHit, ...]` — returns `()` unless `scan.mode is ACTIVE` **and**
  `config.injection.stored_xss` **and** the check is selected; wraps `StoredXssScanner(...).run()`
  in `try/except` → a `"stored-XSS pass failed: …"` warning on error. In `run()`, call it
  after `_inject` and pass `injection_hits + stored_hits` into `Observations`. In
  `_select_checks` (or `run`), when `config.injection.stored_xss and scan.mode is not ACTIVE`,
  append `"stored-XSS testing requires --mode active — the stored pass did not run"`. — RF-01, ADR-1
- [x] Tests (`test_injection_orchestrator.py` additions): `_inject_stored` returns `()` on
  passive / `stored_xss=False` / check disabled; `stored_hits` reach the context merged with
  `injection_hits`; a raising `StoredXssScanner` → a scan warning, not a crash (monkeypatch
  `orch_mod.StoredXssScanner`); `stored_xss=True` + passive → the "requires --mode active"
  warning. Update any `_StubCrawler` that needs a `recrawl`. — RF-01, RF-15
- [x] Quality gate. — 528 passed; ruff/black/mypy/lint-imports green.

## Stage 5 — CLI

- [x] `webvigil/cli/app.py`: `scan` gains `stored_xss: Annotated[bool | None,
  typer.Option("--stored-xss/--no-stored-xss", help=...)] = None`. `_build_config` gains
  `stored_xss: bool | None` and folds `{"stored_xss": stored_xss}` into `injection_overrides`
  when not `None` (beside `time_based_sqli`). `_render` unchanged. — RF-10
- [x] Tests (`test_cli.py` additions): `--stored-xss` → `config.injection.stored_xss is True`;
  `--no-stored-xss` → `False`; default → file value (`False`); `list-checks` shows
  `injection.xss.stored | INJECTION | active | HIGH`. — RF-10, RF-15
- [x] Quality gate. — 529 passed; ruff/black/mypy/lint-imports green.

## Stage 6 — Fixture app, integration tests

- [x] `tests/fixtures/app.py` — **insecure** profile: `_FORMS` / `_INSECURE_PAGE` gain
  `<form method="post" action="/guestbook"><textarea name="body"></textarea></form>`;
  `_LINKS` gains `<a href="/guestbook">guestbook</a>`. Handlers: `POST /guestbook`
  (`request.app.state.guestbook.append(body)`, `RedirectResponse("/guestbook", 302)`);
  `GET /guestbook` (render every entry **unescaped**, each linking `/guestbook/e/<i>`);
  `GET /guestbook/e/{i}` (render entry `i` **unescaped**; `404` on a bad index). Wire via
  `_INJECTION_ROUTES` for both profiles; `make_app` sets `app.state.guestbook = []`. — RF-13, ADR-8
- [x] `tests/fixtures/app.py` — **hardened** profile: `/guestbook` and `/guestbook/e/<i>`
  wrap the entry in `html.escape(...)`. — RF-13
- [x] `tests/integration/test_scan_fixture_app.py`: `scan` fixture `_run` gains `stored_xss:
  bool = False` (threaded into the `injection` config section). Tests:
  `test_stored_xss_found_on_the_insecure_guestbook`;
  `test_stored_xss_render_location_is_the_per_entry_page`;
  `test_stored_xss_not_run_without_the_opt_in` (no `POST /guestbook` with a `wvstored` body
  in the request log); `test_stored_xss_passive_scan_does_nothing`;
  `test_hardened_profile_reports_no_stored_xss` (extend the hardened loop with
  `stored_xss=True`); `test_authenticated_stored_xss_and_cookie_privacy`;
  `test_stored_xss_scan_is_deterministic`. Recompute any page-count assertion the new
  `/guestbook` link shifts. — RF-14
- [x] Quality gate. — 536 passed; ruff/black/mypy/lint-imports green.

## Stage 7 — Docs, roadmap, verification, close

- [x] `docs/active-injection.md`: add a **Stored XSS** section — the two-phase
  inject-then-recrawl model; the dedicated `--stored-xss` opt-in and **why** (markers are
  persisted by design, amends the 006 payload-hygiene rule); the plain statement that marker
  strings remain in the target and are not cleaned up; the shared budget + `_STORED_REFETCH_CAP`;
  what a hit proves; the blind-spot / >1-hop / moderation-delay limits; the authenticated-scan
  synergy. Update the "No stored / DOM XSS" bullet to "stored XSS shipped in v0.8 (opt-in);
  DOM XSS still needs a JS engine". — RF-16
- [x] `docs/writing-checks.md`: replace the "If a later spec adds **stored** XSS…" note with
  the shipped two-phase pass as the reference for a stateful Active technique (inject via
  Phase A, re-observe via a depth-1 re-crawl, correlate by token). `docs/architecture.md`:
  the `webvigil.checks.injection` bullet + the specs list gains `008-stored-xss`. — RF-16
- [x] `README.md`: coverage table `v0.8` row (stored XSS, opt-in, link to the docs); update
  the "Stored XSS and SSRF were on the original `v0.6` line" note to "stored XSS shipped in
  v0.8; SSRF is still pending its out-of-band collaborator"; a `--stored-xss` quick-start
  line. `CLAUDE.md`: layer-3 `webvigil.checks.injection` paragraph gains the stored pass;
  `Estado` line → `008` concluída, next = `009-ssrf` / `010-osv-online`. `specs/README.md`:
  roadmap row `008-stored-xss` → **done** (`v0.8`). — RF-16
- [x] Set all three `008` spec files to `status: done`; add an "Implementation notes" section
  to `design.md` (the `_STORED_REFETCH_CAP` value validated against the fixture, the
  one-hop-queue implementation choice, the API/UI zero-change confirmation, crawl-count
  deltas, the pytest delta, anything that shifted from the design). — RF-16
- [x] Manual verification: `uvicorn tests.fixtures.serve:app` — Active scan with
  `--mode active --authorized-by me --stored-xss` finds `injection.xss.stored` on
  `POST /guestbook` (`body`), evidence "Rendered on" a `/guestbook/e/<id>` page; the same
  scan **without** `--stored-xss` reports no stored finding and issues no `wvstored` POST;
  an authenticated `--cookie` run finds a stored marker in the account area with the cookie
  value absent from the JSON; `webvigil list-checks` shows `injection.xss.stored`. Record
  the marker rows left in the fixture store. — RNF-05, RNF-06
- [x] Final full quality gate: ruff / black / mypy / lint-imports (2 contracts kept, 0
  broken) / pytest — 536 passed. — RNF-02
