---
feature: POST form submission by the crawler — urlencoded, multipart and OpenAPI JSON bodies (Active Mode, opt-in)
status: done
date: 2026-10-07
related:
  - 018-post-form-crawl/requirements.md
  - 007-auth-flows/design.md
  - 013-auth-and-api-surface/design.md
  - 017-csrf-confirmation/design.md
origin: conception
---

# 018 — POST form submission by the crawler — design

## Overview

018 adds a **`POST` phase to the `Crawler`**, not a new orchestrator pass. The reason is the
whole point of the issue: the answer to a submission has to become a `Page` in the crawl's
list, so every later pass and every check that reads `ctx.pages` sees it, and its links and
forms re-enter the BFS. A pass that ran after the crawl could submit forms, but it could not
extend the crawl (ADR-1).

```
Crawler.discover()
  1. GET BFS                      unchanged: links, safe GET forms, sitemaps, --openapi GETs
  2. POST phase (opt-in)          only when submit_post_forms AND mode is ACTIVE
       loop until the cap or max_pages:
         candidate = next unsubmitted form (inventory order), then API operation
         page = submit(candidate)  → Page(method="POST"), appended to pages
         enqueue its links / forms
         drain the GET queue again  (the same BFS loop, within max_pages)
  3. pages returned; crawler.post_summary → one scan warning (orchestrator)
```

Everything else follows from reusing the `Page`: a header-less cross-origin script on the
thank-you page is a `content.sri.missing` finding, a stack trace after a bad submission is a
`disclosure.stack-trace`, a session cookie set by the response reaches `cookie.*` — with no
change to those checks. The four places that *re-request or enumerate from* a page's URL with
`GET` learn to skip a `POST` page (ADR-2).

## Module layout

```
src/webvigil/crawler/
├── crawler.py     + POST phase (_post_phase, _next_candidate, _submit_form, _submit_operation),
│                    the GET loop factored into _drain(), post_summary
├── forms.py       + form_body(form, *, sentinel, skip, replace)   (shared with spec 017)
├── safety.py      + looks_unsafe_operation(op)
└── openapi.py     (unchanged: ApiOperation already carries body_fields / body_json)

src/webvigil/core/context.py       Page.method, Page.fetched_by_get, from_response(method=)
src/webvigil/core/config.py        ScanSection.submit_post_forms, max_post_submissions
src/webvigil/core/orchestrator.py  hands the POST operations to the Crawler, appends the
                                   summary warning, warns when the switch is on outside Active
src/webvigil/http/client.py        widen the `files` type (a list of pairs); no logic change
src/webvigil/cli/app.py, _render.py  --submit-post-forms; one summary note
src/webvigil/checks/csrf/scanner.py  _build_body becomes a thin wrapper over form_body
src/webvigil/checks/{injection/stored.py, injection/points.py, envelope/scanner.py,
                     disclosure/probe.py}   skip a POST page where they re-request / enumerate
tests/fixtures/app.py              /support page and four POST routes (both profiles)
```

`webvigil.api` and `web/` are untouched: `submit_post_forms` defaults to `False` and the API
never sets it.

## Data model

```python
@dataclass(frozen=True, slots=True)
class Page:
    ...                      # existing fields
    method: str = "GET"      # the verb that produced this response

    @property
    def fetched_by_get(self) -> bool:
        return self.method == "GET"
```

`Page.from_response(response, method="GET")` and `Page.failed(url, error, method="GET")` take
the method; every existing caller keeps the default. `ScanSection` gains:

```python
submit_post_forms: bool = False     # opt-in: the crawler POSTs candidate forms (Active only)
max_post_submissions: int = 25      # cap on submissions per scan
```

The crawler keeps a small result for the orchestrator:

```python
@dataclass(slots=True)
class PostSummary:
    forms: int = 0          # forms submitted
    operations: int = 0     # API operations submitted
    skipped: int = 0        # POST candidates left out for a safety / shape / robots reason
    over_cap: int = 0       # candidates left unsubmitted by the cap or max_pages
```

## Components

### Candidate selection

A **form** is a candidate when all of: `method == "POST"` (the inventory already holds only
in-scope forms), `enctype` is urlencoded or multipart, no field of `type == "file"`,
`is_candidate(form)` (not auth, not search — spec 017's predicate, moved to
`crawler/safety.py` because the crawler must not import from `checks`; see Impact), not
`is_destructive_form`, not
`is_logout(form.action)`, and allowed by `robots.txt`. The inventory is keyed on
`(method, action, field names)`, so one form is one candidate however many pages carry it.

An **API operation** is a candidate when `op.method == "POST"` and
`looks_unsafe_operation(op)` is false — a new predicate in `crawler/safety.py` that flattens
`url_template` and `operation_id` (`_` and `-` as word breaks) and matches
`_DESTRUCTIVE_RE`, `_LOGOUT_RE` or `_AUTH_FORM_RE`, the same vocabulary 013's injection filter
uses (that regex lives in `checks/injection/points.py`, which the crawler cannot import). An
operation whose body is neither form-urlencoded, `application/json` nor absent is skipped:
`ApiOperation` records only those kinds, so nothing else reaches the crawler.

`_next_candidate()` returns the first not-yet-submitted candidate: forms in inventory order
(re-read each time, so a form first seen on a response page joins), then operations in
document order. Skips are tallied once per distinct form or operation.

### Building the submission (`forms.form_body`)

The body logic 017 wrote in `checks/csrf/scanner._build_body` is generic — defaults travel,
a text-like control with no default gets the sentinel, typed fallbacks, unchecked boxes
omitted, the first named submit button — except for the token handling. It moves to
`crawler/forms.py`:

```python
def form_body(form, *, sentinel, skip=frozenset(), replace=None) -> list[tuple[str, str]]
```

`skip` is a set of field names to leave out, `replace` a `name -> value` mapping. The 017
scanner calls it with `skip = token field names` (removed replay) or `replace = {name:
_alter(value)}` (altered replay) and passes the same results as before; its tests pass
untouched, which is the proof the move changed nothing. The crawler calls it with defaults
and the sentinel `wvcrawl<token>` (one `secrets.token_hex(4)` per scan).

### Sending it

- **urlencoded form** — `content=urlencode(pairs)` plus `Content-Type:
  application/x-www-form-urlencoded` (httpx accepts only a mapping for `data=`; spec 017
  recorded the failure).
- **multipart form (no file input)** — every field as a text part: `files=[(name, (None,
  value))]`, a list so a repeated name survives. httpx omits the `filename` for a `None`
  first element, so the request is `multipart/form-data` with no file part. The
  `HttpClient._Files` alias widens to admit the list form; the value is forwarded untouched.
- **API operation** — `op.url`, `params=op.query`, and one of `content=op.body_json` with
  `Content-Type: application/json`; `content=urlencode(op.body_fields)` with the urlencoded
  type; or no body.

Every request is `HttpClient.request("POST", …)`: scope guard, rate limiter, `[auth]` cookies
and headers, no retry of a non-idempotent request. `Origin` / `Referer` are **not** set: the
crawler is not a browser and this is not a cross-site test (that is 017).

### The phase (`_post_phase`, `_drain`)

The GET loop in `discover()` becomes `_drain(queue, pages, robots, max_pages)`, called by the
phase-1 BFS and again inside the phase. The phase:

```python
submitted = 0
while submitted < cap and len(pages) < max_pages:
    candidate = self._next_candidate()
    if candidate is None: break
    page = await self._submit(candidate)           # Page(method="POST"), or a failed Page
    pages.append(page); submitted += 1
    self._enqueue_links(page, seen, queue)
    self._collect_and_enqueue_forms(page, seen, queue)
    await self._drain(queue, pages, robots, max_pages)
self._summary.over_cap = number of candidates still unsubmitted
```

A submission counts as one page against `max_pages` and as one against
`max_post_submissions`, whether it succeeded or failed (a failed `Page` is appended, as the GET
crawl appends one). A `4xx` / `5xx` answer is kept: the disclosure checks want error pages.
The phase never runs when the switch is off or the mode is not Active; `discover()` is then
byte-for-byte what it is today.

### Orchestrator, CLI and the summary

`Orchestrator.run` passes `post_operations=[op for op in operations if op.method == "POST"]`
to the `Crawler`; after `discover()` it appends one warning built from
`crawler.post_summary`: `POST crawl: 6 submitted — 4 forms, 2 API operations, 5 skipped, 0
not submitted (cap)`. No line when the phase did not run or had nothing to submit. When
`submit_post_forms` is on outside Active Mode, `run()` warns `POST crawling requires --mode
active — the POST phase did not run`, the 008 / 014 / 017 pattern.

CLI: `--submit-post-forms/--no-submit-post-forms`, wired through `_build_config` and `_emit`
like `--confirm-csrf`; `_render.summary` prints, in Active Mode with the phase on, a dim note
(`POST crawl: enabled — candidate forms were submitted with benign values; test data marked
"wvcrawl" was left on the target`). `max_post_submissions` is a `[scan]` TOML key only.

### What the other passes learn

| Site | Today | With a `POST` page |
|---|---|---|
| `stored.py` Phase B | `frontier` and `pre` from every OK page; re-fetches with `GET` | built from `page.fetched_by_get` pages only |
| `points.py` `enumerate_points` | a `GET` injection point per query parameter of `page.requested_url` | a `POST` page contributes none (the form is already a `POST` point) |
| `envelope/scanner.py` `_sample_urls` | `page.requested_url` of every OK page | `fetched_by_get` pages only |
| `disclosure/probe.py` `_discovered_dirs` | directory prefixes of every OK page's path | `fetched_by_get` pages only |

`_referenced_scripts` keeps reading a `POST` page's HTML: it only reads, and a script a
thank-you page references is part of the surface. Passive checks read `ctx.pages` unchanged.

## Interfaces

- **CLI:** `webvigil scan <url> --mode active --authorized-by "<who>" --submit-post-forms
  [--cookie "name=value"] [--openapi <doc>]`.
- **Config:** `[scan] submit_post_forms = true`, `max_post_submissions = 25`.
- **Library:** `Crawler(http, target, config, extra_seeds=…, post_operations=…)`;
  `Crawler.post_summary -> PostSummary | None`; `Page.method`, `Page.fetched_by_get`.
- **Web API / OpenAPI:** unchanged.

## ADRs

### ADR-1 — The phase lives in the crawler, not in a separate pass

- **Decision:** `Crawler.discover()` runs the `POST` phase and resumes its own BFS.
- **Alternatives:** an orchestrator pass like `UploadScanner` / `CsrfScanner` that submits the
  inventory after the crawl and returns hits.
- **Why:** the issue is about *reach*: the response of a submission must be a `Page`, and its
  links and forms must be followed. A pass that runs after the crawl would have to grow the
  `pages` tuple and re-run the BFS from outside, duplicating the crawler's queue, scope and
  robots logic. Inside the crawler the queue, `seen`, the scope guard and `max_pages` are
  already there.
- **Trade-off:** the crawler now owns a state-changing step, which it never had; the opt-in,
  the Active gate and the safety filter are what make that acceptable, and `discover()` is
  unchanged with the switch off.

### ADR-2 — Record the method on the `Page` and filter at the four re-request sites

- **Decision:** `Page.method` (default `"GET"`) and a `fetched_by_get` property; the four
  sites that re-request or enumerate from a page's URL with `GET` use it.
- **Alternatives:** a second list of "submission pages" next to `pages`; a flag on the
  `Crawler` result only.
- **Why:** one list keeps every `ctx.pages` check working with no change, which is the
  feature. The only code that must tell the two apart is the code that *acts on the URL*, and
  there are four such places (table above).
- **Trade-off:** a new field on a widely used dataclass; the default makes every existing
  construction site valid, and `ScanContext._by_url` keeps the first page per URL, which is
  the `GET` one because the phase runs after the BFS.

### ADR-3 — The phase waits for the GET queue and the BFS resumes

- **Decision:** the resolved decision of the requirements, as a loop: submit one, enqueue what
  it links, drain the GET queue, take the next candidate.
- **Alternatives:** submit every candidate first and drain once at the end; submit a form the
  moment it is parsed.
- **Why:** draining after each submission keeps a multi-step flow (form → confirmation page →
  next form) inside one phase and lets the second form be found; submitting at discovery time
  would let a write change a page the crawl is still reading.
- **Trade-off:** pages read after a submission may differ from the same page read before it.
  That is inherent to writing; the phase runs only after the pre-write surface was read.

### ADR-4 — One body builder for every pass that submits a form

- **Decision:** `crawler/forms.form_body` with `skip` / `replace`; spec 017's scanner calls it.
- **Alternatives:** copy 017's builder into the crawler; let the crawler import it from
  `checks.csrf`.
- **Why:** two copies would drift (the field table is the subtle part), and the crawler may not
  import from `checks` (layering: checks import the crawler, not the reverse). `skip` /
  `replace` express the only thing 017 changes — the token fields — without a callback.
- **Trade-off:** a small refactor of merged 017 code; its 29 scanner tests are the guard.

### ADR-5 — Multipart as a list of text parts

- **Decision:** send a no-file multipart form as `files=[(name, (None, value))]`.
- **Alternatives:** send it urlencoded; add a dedicated multipart encoder.
- **Why:** a server that declared `multipart/form-data` may parse nothing else, and httpx
  already encodes a text-only multipart body when the filename is `None`. A list keeps repeated
  names. The cost is widening one type alias.
- **Trade-off:** relies on httpx's documented `(None, value)` text-part form; a unit test
  against the fake and the fixture's multipart route pin it.

### ADR-6 — The defaults: marker `wvcrawl`, 25 submissions, no new budget

- **Decision:** the marker is `wvcrawl<token>` (a different prefix from 017's `wvcsrf` so an
  operator can tell which pass wrote a record); `max_post_submissions = 25`, a `[scan]` key;
  no other budget — a submission is a page under `max_pages`.
- **Why:** 25 is half the default `max_pages` (50): enough for the forms of a typical small
  application, small enough that a runaway inventory cannot turn into hundreds of writes. A
  config key because crawl breadth is exactly what `[scan]` tunes; the injection and upload
  budgets are separate because they are not pages.
- **Trade-off:** a site with more forms needs the key raised, and `max_pages` as well.

### ADR-7 — Opt-in outside Active Mode is a warning

- **Decision:** `--submit-post-forms` without `--mode active` warns and does not run.
- **Why:** the same as 008 / 014 / 017 (ADR-7 of spec 017): three flags should not disagree,
  and nothing is sent without the gate.

## Fixture app

A new page `/support`, linked from the shared link block (both profiles crawl it), carries
three `POST` forms; a fourth is a JSON API operation. Every route records what it received in
`app.state.post_log` as `(route, content type, field names)`, so a test can count the writes,
and escapes what it echoes.

| Route | Body | Answer |
|---|---|---|
| `POST /support/ticket` (`subject`, `message`) | urlencoded | `200` page with a link to `/support/status` — a GET page linked from nowhere else |
| `POST /support/callback` (`name`, `phone`) | multipart, no file | `302` → `/support/received` — a GET page reachable only through this redirect |
| `POST /support/feedback` (`format=xml` hidden, `rating`) | urlencoded | insecure: `500` with a Python stack trace and a cross-origin `<script>` with no `integrity`, and a `Set-Cookie: ticket=…` with no flags; hardened: `400` with a plain message |
| `POST /api/notes` | JSON `{"text": "..."}` | `200` JSON; described by a one-operation OpenAPI document the integration test writes to `tmp_path` (the shared `/openapi.json` of spec 013 is left alone, so its operation-count tests do not move) |

`/support/status` and `/support/received` exist in both profiles. The skip cases are the
fixture's existing forms: the login form, the search form, the file-input upload form and the
`/transfer`-style routes of spec 017.

## Request budget

No new budget: a submission is one request (plus the client's in-scope redirect hops) and one
page. At most `max_post_submissions` (25) submissions, and `max_pages` pages in all. The
phase draws on neither the injection nor the upload budget. The fixture's new forms add
`POST` injection points; the integration config's injection budget and the spec-012 envelope
sample are re-measured in the task list, as 011, 014, 016 and 017 did.

## Impact on existing code

- `crawler/safety.py` gains `is_candidate`, **moved** out of `checks/csrf/tokens.py` (it only
  calls `is_auth_form` and `looks_like_search`, both already in `safety.py`); `tokens.py`
  re-exports it, so spec 017's imports keep working and `webvigil.crawler` stays free of
  `webvigil.checks`. `is_token_field` stays in `tokens.py`: only the 017 scanner needs it.
- `core/context.py`: `Page.method` with a default; `ScanContext` and every `Page(...)`
  construction stay valid.
- `http/client.py`: a wider `files` type, no logic change.
- Existing tests: the fixture crawl count rises by one page (`/support`) plus the two
  GET-only pages the phase reaches only in a `--submit-post-forms` scan; the spec-012
  envelope sample may need the same test-only bump 017 needed.
- `webvigil.api`, the dashboard, the reporters and `openapi.json`: untouched.

## Risks

- **It writes to the target.** One submission per distinct form, up to 25, with benign data
  marked `wvcrawl<token>`. Mitigated by the opt-in, the Active gate, the auth / search /
  destructive / file filter, the cap and the docs. Not mitigated: a benign-looking form with a
  real side effect (an email send).
- **A form that depends on state the crawl does not have** (a CSRF token bound to a session
  the scan lacks, a required field only a human knows) answers an error page. The page is
  kept — an error page is informative — and nothing else follows from it.
- **Pages read after a write can differ from those read before it.** ADR-3: the read-only
  surface is complete before the first write.
- **Multipart relies on httpx's text-part form.** Pinned by tests.
- **`max_pages` pressure.** Submission pages consume the same page budget; on a small
  `max_pages` the phase submits fewer forms and reports the rest as "not submitted (cap)".

## Test strategy

- **Unit — `test_crawler_post.py`** (a `_FakeHttp` recording `GET` and `POST` calls with
  headers and bodies, and a tiny site): each skip reason (non-`POST`, file input, `text/plain`,
  auth, search, logout, destructive, `robots.txt`, over the cap), de-duplication and order;
  nothing sent before the GET queue drains; the BFS resumes on new URLs; the cap and
  `max_pages` both stop it; a failed submission is a failed `Page` and counts; the urlencoded,
  multipart and API bodies (defaults unchanged, the `wvcrawl` marker, typed fallbacks, first
  submit, no file part; `body_json` / `body_fields` / none) and their `Content-Type`; the
  summary line and its absence.
- **Unit — `test_forms.py` (additions):** `form_body` field table; `skip` and `replace`.
- **Unit — `test_csrf_scanner.py`:** untouched (the guard for ADR-4).
- **Unit — `test_context.py` / pass tests:** `Page.method` default and `fetched_by_get`;
  `stored`, `points`, `envelope` and `probe` each skip a `POST` page.
- **Unit — `test_crawler_safety.py`:** `looks_unsafe_operation`.
- **Unit — `test_config.py` / `test_cli.py` / orchestrator:** the defaults, the TOML keys,
  `--submit-post-forms`, the warning outside Active Mode, the summary note, the summary line,
  the operations reach the crawler.
- **Unit — `test_fixture_post.py`:** each route's answer and `post_log`.
- **Integration — `test_scan_fixture_app.py`:**
  - insecure, Active, `--submit-post-forms` → `/support/status` and `/support/received` are in
    `pages_scanned`; a `disclosure.stack-trace`, a `content.sri.missing` and a cookie-flag
    finding whose page is the `/support/feedback` answer; the summary warning has the right
    tallies; login, search and file-input forms were not posted; no posted value is a payload;
  - the same scan **without** the switch, and a Passive scan with it → no `POST` reaches
    `/support/*` and none of those findings exists;
  - hardened, Active, switch on → the pages are reached, nothing is reported;
  - with an `--openapi` document in `tmp_path` → `POST /api/notes` is posted with
    `application/json`;
  - the request log shows no later pass re-requests `/support/ticket` or `/support/callback`
    with `GET`;
  - determinism across two runs.
- **Gate:** `ruff → black → mypy → lint-imports → pytest` at the end of each stage.

## Deviations from the approved requirements

Recorded here so the requirements text stays as approved; the as-built behaviour is below.

1. **RF-10, "evidence says the page is the answer to a POST".** Not added per check: about
   twenty passive checks build findings from `page.url` with no shared hook, and a hook would
   be its own refactor. For a submission with no redirect the location *is* the form's action
   URL; the crawl summary names what was submitted; `Page.method` is there for a later check or
   reporter. A non-redirected `POST` page's finding therefore reads like any page's.
2. **RF-12, "the insecure POST-only pages lack the security headers".** The header checks read
   only the entry page (`ctx.entry`), so a header-less thank-you page produces no finding. The
   fixture gives the insecure answer a stack trace, a cross-origin script with no `integrity`
   and an unflagged cookie instead — three checks that do read every page.
3. **RF-09, the disclosure probe.** Only `_discovered_dirs` skips a `POST` page;
   `_referenced_scripts` still reads its HTML (it re-requests nothing of the page).
4. **RF-02 / RF-03, the operation filter.** `looks_unsafe_operation` in `crawler/safety.py`
   reuses the 013 vocabulary rather than the injection-pass regex, which the crawler cannot
   import.

## Implementation notes

What changed between this design and the code, and what was measured.

- **Deviations 1-4 above stand as built.** Two further ones:
  - **RF-13, "no later pass re-requests a POST-only URL with `GET`".** It cannot be asserted for
    a form action: the spec-012 envelope pass samples every form action with `GET` on purpose (reset
    links live there), and all three `/support` POST routes are form actions. RF-09 is covered by
    `tests/unit/test_post_pages.py` (one test per pass); the integration test asserts it only for the
    `--openapi` operation URL `/api/notes`, which is not a form action.
  - **`PostSummary.warning()`** lives on the dataclass, so the orchestrator only appends it.
- **Fixture.** `/support` and its routes are as designed. Two additions: every form carries a constant
  `csrf_token` (so the passive CSRF check stays quiet) and `/support/feedback` has a text field, so the
  crawler's `wvcrawl` marker identifies its post in `post_log`. The hardened profile wraps the three
  form routes in `_support_guarded` (a `403` unless the served token comes back) — the 017 hardened test
  asserts the CSRF confirmation finds nothing to confirm, and an unchecked token would be confirmed.
- **Integration config.** `envelope_url_sample` / `envelope_budget` 20 / 130 → 24 / 150 → 30 / 180
  (test-only): the envelope sample is the entry, every form action, then the other pages, and specs 017
  and 018 added seven form actions. No injection budget moved; the stub crawlers of four orchestrator
  test files gained `post_summary = None` because the real crawler's interface grew.
- **A `Page` the POST phase appends is also in `ScanContext._by_url`** after the `GET` pages, so
  `page_for(url)` still returns the `GET` page for a URL both reached.
- **Manual verification** (CLI, fixture served by uvicorn, `--mode active --submit-post-forms
  --openapi` with a one-operation document): the warning read `POST crawl: 11 submitted — 10 forms,
  1 API operation, 2 skipped, 0 not submitted (cap)`; `/support/feedback`'s answer drew
  `disclosure.debug.error-page`, `content.sri.missing` and `http.cookies.flags`; the same scan without
  the switch added no `POST crawl:` warning and no finding on that URL. (The page counts of the two
  runs are not comparable: both ran against the same live server, whose guestbook had grown by the
  injection payloads of the first.)
