---
feature: Stored / persistent XSS — two-phase inject-then-recrawl detection (Active Mode)
status: done
date: 2026-09-07
related:
  - 001-foundation/requirements.md
  - 002-web-api/requirements.md
  - 003-web-ui/requirements.md
  - 006-active-injection/requirements.md
  - 007-auth-flows/requirements.md
origin: conception
---

# 008 — Stored / persistent XSS

## Context and problem

Spec 006 shipped the first `ACTIVE` checks: the `InjectionScanner` enumerates injection
points (query params + form fields parsed from crawled bodies), baselines each, fans a
bounded set of payloads, and confirms every signal in-band. Its `injection.xss.reflected`
detector catches XSS **only when the payload bounces straight back in the same response**.

The other half of the XSS problem is **stored XSS**: the payload is *saved* by the
application on one request and then *rendered*, unescaped, on a **later, separate** request
— on a comment thread, a profile page, an activity feed, an admin dashboard. It is usually
more severe than reflected XSS (it fires for every visitor, no phishing link needed) and
006 cannot see it, because there is no single response that both receives and reflects the
payload.

Detecting it needs machinery 006 deliberately left out: a **stateful two-phase flow** —
submit a unique marker through each injection point, then **re-crawl the whole site** and
hunt for that marker rendered as live HTML on a page other than the one it was submitted
to. This was called out as the natural extension point in `docs/writing-checks.md` and
tracked as roadmap row `008-stored-xss` since the 006/007 close.

008 adds one check — `injection.xss.stored` — plus the two-phase pass behind it. Like every
earlier spec it stays inside the engine's rules: a pure library, no new runtime dependency
(detection is `re` + the existing `selectolax` + stdlib), the scope guard unchanged, the
good-neighbor policy on every crafted request and every re-crawl fetch, the 006
non-destructive posture unchanged, and the Active-Mode attestation strictly enforced.

### The one rule 008 changes: markers are persisted on purpose

006 RNF-07 says "no payload is designed to write persistent data". **008 amends that for
its own pass only.** A stored-XSS marker is stored by the target by design — that is the
entire point of the test. This is why 008 gets a **dedicated opt-in** (`--stored-xss` /
`[injection] stored_xss`, default **off**) *on top of* `--mode active --authorized-by`, and
why the docs state plainly that the marker strings remain in the target's data store after
the scan and WebVigil does not remove them.

### Deferred, on purpose

- **DOM-based XSS** — needs a JavaScript engine / headless browser. Out since spec 001,
  unchanged.
- **Stored XSS through non-form vectors** — a poisoned `User-Agent` / `Referer` rendered in
  an admin log, filename or EXIF content from a file upload, an imported CSV, a webhook
  body. 008 submits markers through the same injection points as 006 (query params + form
  fields); other vectors are later specs.
- **Blind stored XSS** — the marker is stored but rendered only somewhere the scan can
  never reach (an internal admin panel, a staff email, a moderation queue). This is the
  stored-XSS analogue of the SSRF blind spot; a real answer needs an out-of-band
  collaborator (roadmap `009-ssrf` adds one). 008's re-crawl covers what an
  authenticated crawl of the target itself can see.
- **Marker cleanup** — deleting the rows 008 wrote. WebVigil does not know the target's
  data model; attempting deletion would itself be a destructive action. Documented, not
  automated.
- **Automated exploitation, WAF evasion, payload polymorphism** — as 006.

### Where it sits

```
webvigil.checks.injection
    points.py          enumerate_points() — unchanged; POST-form points are tried first
                       by the stored pass (query params second)                        — RF-04
    payloads.py        + STORED_MARKERS — a small, documented, benign, WebVigil-attributable
                       marker set (no alert(); a distinctive tag + one attribute-breaker) — RF-04, RNF-06
    engine.py          + a stored phase (its own module, e.g. stored.py) that runs after the
                       006 per-point detector loop: one unique marker per point, then a
                       full re-crawl from the seed, then token-match with context analysis  — RF-04, RF-05
        └── injection.xss.stored   (kind = "xss-stored")  — a ~10-line hit-filter check     — RF-07

webvigil.core.config          [injection] stored_xss: bool = False   (opt-in)               — RF-01, RF-10
webvigil.core.orchestrator    the stored pass runs only when mode is ACTIVE, the check is
                              selected, AND stored_xss is on                                — RF-01
webvigil.core.context         Observations.injection_hits already carries the new kind      — RF-07
CLI                           --stored-xss / --no-stored-xss  ·  summary re-crawl note      — RF-10

fixture   tests/fixtures/app.py:  POST /guestbook stores `body`; GET /guestbook lists every
          entry and links a per-entry GET /guestbook/e/<id> — both render unescaped
          (insecure) / html.escape'd (hardened). Store lives on app.state, reset per app.   — RF-13
```

The engine still imports nothing from `webvigil.cli`, `webvigil.api`, or `web/`. The
`import-linter` contract is unchanged (`webvigil.checks`, `webvigil.crawler`,
`webvigil.http` are already source modules). `injection.xss.stored` is an ordinary
`Finding` with `location.method` / `location.param` populated and rides spec 001's four
reporters and spec 002/003's persistence and dashboard with **no migration, no
`openapi.json` regen, no component change** (as 006 RF-19 established for `INJECTION`). This
is an **engine + CLI** spec.

## Goals

- One new `ACTIVE` check — `injection.xss.stored` (`category = INJECTION`, `mode = ACTIVE`,
  `cwe = 79`, default `HIGH`) — gated by the existing `--mode active --authorized-by`
  **and** the new dedicated `--stored-xss` / `[injection] stored_xss` opt-in.
- **A two-phase pass**:
  - **Phase A — inject**: for each in-scope non-excluded injection point (006's
    `enumerate_points`, POST-form points first, query params second), submit **one unique
    marker payload** and remember `token → (point, payload)`.
  - **Phase B — re-crawl**: after every Phase A submission, run a **full fresh crawl from
    the seed** (bounded by `max_pages` and a dedicated re-fetch cap), and for every
    re-crawled page body look for any recorded token rendered with its HTML-significant
    characters **verbatim** in an **executable context**.
- **Budget**: Phase A and Phase B both draw on 006's shared `[injection] request_budget`;
  Phase B is additionally bounded by a documented `_STORED_REFETCH_CAP`. Hitting either cap
  is a scan **warning**, not an error.
- **False-positive discipline**: a hit needs the marker's context-breaking payload back
  **verbatim** (`<`, `>`, `"` unencoded) in an HTML response, on a page fetched by a
  **Phase B GET** (never the Phase A POST response), and **absent from that URL's
  pre-injection body** when the URL was already known. The hardened fixture profile yields
  **zero** `INJECTION` findings with the stored pass on.
- **Distinct from reflected XSS**: `injection.xss.reflected` (006) fires on same-response
  reflection; `injection.xss.stored` fires only from the Phase B re-crawl. When an app both
  reflects and stores, both findings are legitimate.
- **Authenticated by inheritance**: Phase A submissions and the Phase B re-crawl both go
  through `ctx.http`, so a spec 007 `--cookie` scan tests (and re-crawls) the authenticated
  area — the highest-value stored-XSS surface — with no extra work. The 007 logout /
  destructive-link heuristics guard the re-crawl exactly as the first crawl.
- **Vulnerable target**: the `tests/fixtures` insecure profile gains a guestbook (`POST`
  to store, a list page and a per-entry page that render unescaped); the hardened profile
  escapes them.
- Docs: a new stored-XSS section (the two-phase model, the dedicated opt-in and *why*, the
  persisted-marker warning, the re-crawl budget, the blind-spot limits) plus the usual
  architecture / writing-checks / README / CLAUDE / roadmap updates.

## Non-goals

- **DOM XSS** (needs a JS engine — spec 001 non-goal, unchanged).
- **Stored XSS via non-form vectors** — request headers, uploaded-file content/metadata,
  imported data, API bodies that are not `application/x-www-form-urlencoded` or a query
  string. 008 uses 006's injection-point model.
- **Blind stored XSS** — a marker rendered only where the scan cannot reach. Needs the
  out-of-band collaborator from `009-ssrf`. Documented as a limit.
- **Marker cleanup / rollback.** 008 does not delete what it wrote.
- **A second injection-point model.** 008 reuses `enumerate_points`; it does not mine
  parameters or guess hidden fields.
- **New verbs.** `GET` / `POST` only, as 006. No `PUT` / `PATCH` / `DELETE`.
- **Automated exploitation** — a confirmed stored XSS is proved with one bounded marker and
  stopped. No cookie theft PoC, no payload chaining.
- **WAF detection / evasion / payload mutation.** The marker set is small, static,
  documented, in-repo (006 RNF-07).
- **A headless re-render.** Phase B matches the marker in served HTML **text**; it does not
  execute scripts or resolve client-side templating.
- **Any database migration, `openapi.json` regeneration, or new API / UI component.**
  `injection.xss.stored` is an ordinary `Finding` (RF-12). `--stored-xss` is a CLI +
  config-file input; `POST /api/scans` gains **no** `stored_xss` field in v0.8 (consistent
  with 006 keeping `--time-based-sqli` CLI-only).
- **A new consent banner.** The spec 001 Active-Mode banner is unchanged; the `--stored-xss`
  opt-in is a plain flag / config key, not an attestation prompt.

## Personas

| Persona | Needs from 008 |
|---|---|
| **Security-conscious developer** | "If I paste `<svg onload=…>` into a comment, does it run for the next visitor?" — a HIGH finding naming the form field the marker went in through **and** the page it rendered on, with the payload and the unescaped snippet, and an output-encoding fix. Run against a dev instance with `--mode active --authorized-by me --stored-xss`. |
| **CI pipeline author** | An authenticated Active scan of a staging deploy with `--stored-xss` on, bounded by the request budget and the re-fetch cap, producing SARIF so `--fail-on high` blocks a release on a confirmed stored XSS — and knowing markers land in the staging DB, which is acceptable there and never in production. |
| **Pentester / consultant** | First-pass stored-XSS coverage across every comment / profile / message form the authenticated crawl reached, with the two-phase re-crawl catching the payload wherever the app chose to render it, and a clean mapping from *input field* to *render location*. |
| **Check author / contributor** | The stored pass as the reference for a **two-phase** Active technique — inject, re-observe, correlate by token — the counterpart to 006's single-request-plus-baseline detectors. |

## Functional requirements

### Active Mode, the stored-XSS opt-in, and safety

**RF-01 — Gated by the Active-Mode attestation AND the dedicated stored-XSS opt-in**
- **Given** `--mode active` **and** `--authorized-by "<text>"` (or `[active].authorized_by`)
  **and** `--stored-xss` (or `[injection] stored_xss = true`), **when** a scan runs, **then**
  the `injection.xss.stored` check is eligible and the two-phase stored pass runs.
- **Given** `--mode active --authorized-by …` but **no** stored-XSS opt-in, **then**
  `injection.xss.stored` does **not** run, **no marker is ever written**, and no re-crawl
  happens — the 006 injection pass is byte-for-byte unchanged.
- **Given** `--stored-xss` **without** `--mode active`, **then** the stored pass does not run
  (the check is `mode = ACTIVE` and is not selected); the scan records a **warning**
  ("stored-XSS testing requires --mode active"), not an error.
- **Given** the default (`--mode passive`), **then** nothing here runs and no crafted
  request is issued.
- **Given** `[checks] disabled = ["injection.xss.stored"]`, **then** the stored pass is
  skipped entirely even with `--stored-xss` — no marker, no re-crawl (parallel to 006
  ADR-2).

**RF-02 — Scope guard and good-neighbor policy on every request**
- **Given** any Phase A marker submission or any Phase B re-crawl fetch, **then** it goes
  through `ctx.http`, the scope guard blocks any out-of-scope host before network I/O
  (spec 001 RF-04), and the concurrency cap, per-host delay, `timeout_s`, and retry policy
  apply exactly as to a first-crawl fetch (spec 001 RF-03).
- **Given** a marker whose *value* contains markup, **then** that is data in a request to an
  **in-scope** URL; WebVigil issues no request anywhere off-scope.
- **Given** an authenticated scan (spec 007 `--cookie`), **then** the `[auth]` cookies ride
  every Phase A submission and every Phase B re-crawl fetch (in-scope only, never in a
  report — 007 RF-02, unchanged), and the 007 logout / destructive-link avoidance
  heuristics apply to the re-crawl.

**RF-03 — Non-destructive posture and persistent-marker discipline**
- **Given** Phase A, **then** it uses **`GET` and `POST` only**; forms matching 006's
  authentication / destruction exclusion heuristic (`points.py` `_EXCLUDE_FORM_RE`) yield
  **no** marker; hidden and anti-CSRF fields are submitted **with their discovered values**
  (never fuzzed, never dropped); `file` / `password` inputs are not marker-fuzzed. This is
  006 RF-04, reused unchanged.
- **Given** the stored pass runs, **then** every marker is **deliberately persistent** —
  008 amends 006 RNF-07 for this pass. Each marker is: distinctive and unambiguously
  attributable to WebVigil (contains `webvigil` / a `wv…` token), benign (no `alert(`, no
  `document.cookie`, no network call), and bounded in length. The evidence snippet is
  trimmed (spec 001).
- **Given** a completed stored scan, **then** WebVigil does **not** attempt to delete the
  markers it wrote; the docs state they remain in the target's data store.

### The two-phase pass

**RF-04 — Phase A: marker injection across injection points**
- **Given** the injection points from `enumerate_points(pages, forms)` (006 RF-06 — query
  params on discovered in-scope URLs + fuzzable fields of discovered in-scope non-excluded
  forms), **when** Phase A runs, **then** it visits them **POST-form points first, query
  params second** (stored XSS is overwhelmingly a form problem), stable order within each
  group.
- **Given** one injection point, **then** Phase A sends a **small set** (documented,
  in-repo — a bare distinctive tag and one attribute-breaker are enough) of marker payloads,
  each carrying a **token unique to that point**, and records `token → (point, payload)`.
- **Given** the shared `ActiveBudget` (006), **then** every Phase A submission is
  `take()`-gated against `request_budget` and the per-point cap; a submission that fails
  (`RequestFailed` / `OutOfScopeError`) is swallowed and the point skipped, as in 006.
- **Given** the 006 reflected-injection pass also runs in the same scan, **then** Phase A
  reuses the **same** enumerated points (no second enumeration) and runs **after** the 006
  per-point detector loop.

**RF-05 — Phase B: full re-crawl from the seed**
- **Given** every Phase A submission is done, **when** Phase B runs, **then** it performs a
  **fresh full crawl starting from the seed URL** — a second discovery pass — bounded by
  `[scan] max_pages` and by `_STORED_REFETCH_CAP` (RF-06), following the same link and
  form rules as the first crawl (including the 007 safety heuristics; `submit_forms`
  honoured).
- **Given** each page the re-crawl fetches, **then** its body is searched for every
  recorded token.
- **Given** a token found in a re-crawled page, **then** it is a **stored-XSS hit** iff
  **all** hold:
  - the token's **context-breaking payload** is present with `<`, `>`, `"` **verbatim**
    (not `&lt;` / `%3C` / stripped) **and** the response `is_html`;
  - the page was fetched by a **Phase B GET** (a hit is never taken from the Phase A POST
    response — that is reflected XSS, 006's job);
  - **if** that page URL was already in the first-crawl page set, the payload is **absent
    from its pre-injection body**; **if** the URL is new (created by the injection and
    discovered only by the re-crawl), that condition is vacuously satisfied.
- **Given** a hit, **then** an `InjectionHit(kind="xss-stored")` records the **injection
  point** (method + base URL + param), the payload, the **render location** (the page URL
  where the marker surfaced — distinct from the injection point, and the core stored-XSS
  signal), the reflection context, and a trimmed snippet.
- **Given** the same marker renders on several re-crawled pages, **then** one hit per
  injection point is emitted (the first / most-executable render location; dedup is on the
  injection point, not the render page — RF-09).

**RF-06 — Budget: shared request budget plus a dedicated re-fetch cap**
- **Given** the stored pass, **then** Phase A submissions and Phase B re-crawl fetches
  **both** count against 006's `[injection] request_budget`; hitting it stops the pass with
  the existing budget warning.
- **Given** Phase B, **then** the number of re-crawl fetches is **additionally** capped at a
  documented `_STORED_REFETCH_CAP` (a constant, sized against the fixture's real page
  count; design picks the number); hitting it truncates the re-crawl and records a warning
  ("stored-XSS re-crawl stopped at the N-page cap"), not an error.
- **Given** `_STORED_REFETCH_CAP` and `max_pages` disagree, **then** the re-crawl stops at
  whichever is smaller.

### Detection

**RF-07 — `injection.xss.stored`** (`category = INJECTION`, `mode = ACTIVE`, `cwe = 79`,
default `HIGH`)
- **Given** the stored pass produced `InjectionHit(kind="xss-stored")` entries on
  `ctx.observations.injection_hits`, **when** the check runs, **then** it is a ~10-line
  filter (the 006 `_InjectionCheck` base) that turns each into a `Finding` with
  `location = Location(url=<render location>, method=<injection method>, param=<injection
  param>)` and evidence carrying the injection point, the payload, the render location, the
  context, and the snippet.
- **Given** no stored hit, **then** the check returns `[]`.
- `title` names both ends, e.g. `"Stored XSS: the 'body' field of POST /guestbook renders
  unescaped on /guestbook/e/7"`.

**RF-08 — False-positive discipline**
- A hit requires the HTML-significant characters **verbatim** in an **executable context**
  (element content, an attribute break, a `<script>` block, a `javascript:` / `data:` URL)
  on an HTML response — the same bar as 006's reflected detector.
- **Given** the marker comes back **encoded** (`&lt;`, `%3C`) or only in a non-executing
  position (an HTML comment, a `text/plain` body, a safely-quoted attribute), **then**
  **nothing** is reported.
- **Given** a page that merely **echoes** the request (a "your search: …" line) on a Phase B
  GET whose query the re-crawl itself supplied, **then** that is reflected, not stored —
  the pre-injection-baseline / new-URL condition (RF-05) and the "render location ≠
  injection point" check keep it out.
- **Given** the hardened fixture profile, **then** **zero** `INJECTION` findings with
  `--stored-xss` on.
- `confidence`: `HIGH` for a clean tag/attribute break on a render location different from
  the Phase A submission target; `MEDIUM` for a `<script>`-string context or when the only
  render location is the form's own action page.
- Known limits, documented (RF-16): a marker stored but rendered only behind an unreached
  view (blind); a marker the app renders after moderation / a delay the scan does not wait
  for; a marker mangled by length truncation so the break sequence is broken; a second
  injection point that overwrites the first point's stored value before the re-crawl.

**RF-09 — Determinism**
- **Given** the same target behaviour, **then** the stored pass produces the same findings
  and the same fingerprints across runs, with stable report ordering (spec 001 RNF-04).
- **Given** the per-run random token, **then** it guarantees marker uniqueness but does
  **not** enter the fingerprint.
- **Given** `fingerprint` / dedup, **then** it is keyed on `check_id` + injection point
  (method + base URL + param) — **not** the render-location URL and **not** the token — so a
  per-entry render page (`/guestbook/e/7` vs `…/8` across runs) and a multi-page render do
  not churn the finding identity.
- **Given** the scan is re-run, **then** the target accumulates additional marker rows
  (RF-03); this changes neither the finding set nor the fingerprints. Documented.

### CLI

**RF-10 — Surface**
- **Given** `webvigil scan <url> --mode active --authorized-by "…" --stored-xss`, **then**
  the stored pass runs; **given** `--no-stored-xss` or the default, **then** it does not.
  The flag is `--stored-xss / --no-stored-xss`, overriding `[injection] stored_xss`
  (default `false`) — the same pattern as 006's `--time-based-sqli`.
- **Given** `webvigil list-checks`, **then** `injection.xss.stored` appears with category
  `INJECTION`, mode `active`, severity `HIGH`.
- **Given** the human-readable summary of a stored scan, **then** the existing
  `"Active injection: N finding(s)"` line already counts `injection.xss.*` (it matches
  `injection.`), and a short note reports the re-crawl (e.g. `"Stored XSS: re-crawled P
  page(s)"`). A scan without `--stored-xss` is unchanged.
- **Given** the config, **then** `[injection] stored_xss` toggles the pass; no other new
  config key (the re-fetch cap is an internal constant, like 006's `_PER_POINT_REQUEST_CAP`).

**RF-11 — Exit codes**
- `--fail-on <severity>` treats an `injection.xss.stored` finding by severity exactly as
  today. No new exit code; a budget or re-crawl-cap hit is a warning, not an operational
  error; `--stored-xss` without `--mode active` is a warning (RF-01), exit unchanged.

### Reporting

**RF-12 — Reporters and the Web API unchanged in shape**
- **Given** a completed scan, **then** `injection.xss.stored` findings render through the
  four existing reporters with **no new section and no new top-level array**: JSON lists
  them among `findings` with `location.method` / `location.param` populated; SARIF emits one
  `rule` for the id with the render location + parameter in the location and
  `logicalLocations` (006 ADR-8); HTML and Markdown group them by severity like any other
  finding.
- **Given** a finding, **then** its `evidence` carries: the injection point (method + URL +
  param), the marker payload (trimmed), the **render location** URL, the reflection
  context, and the response snippet.
- **Given** a scan run through the Web API in Active Mode, **then** `injection.xss.stored`
  findings persist and are returned by `GET /api/scans/{id}` through spec 002's lossless
  persistence with **no** migration and **no** schema change; `GET /api/checks` lists the
  new check with `category: "INJECTION"` and the dashboard picks it up with **no** component
  change and **no** `openapi.json` / `api-types.ts` regeneration (006 RF-19 established
  this for the category; 008 adds only an id).
- **Given** the Web API's scan-request schema, **then** it is **unchanged** — v0.8 adds
  **no** `stored_xss` field to `POST /api/scans`. An authenticated stored scan is a CLI +
  config-file capability in v0.8 (as 006 did for `--time-based-sqli`).
- **This is stated here so the design phase does not reopen it.** The expectation, to
  confirm in design: 008 touches the **engine + CLI only**. If a hardcoded check-id or
  category list is found in `webvigil.api` or `web/`, 008 updates that one spot; none is
  expected.

### Fixture app and tests

**RF-13 — Stored-XSS surface in the fixture** (mirrors 001 RF-27, 004 RF-19, 005 RF-13,
006 RF-20, 007 RF-13)
- **Given** the `tests/fixtures` app's **insecure** profile, **then** it serves, in addition
  to its current surface:
  - a `<form method="post" action="/guestbook"><textarea name="body"></textarea></form>`
    on a page the crawler reaches (the home page or a linked `/guestbook`).
  - `POST /guestbook` — appends `body` to an in-memory store held on `app.state` (reset per
    `make_app()` call, like `app.state.requests`) and responds (200 or a 302 to
    `/guestbook`).
  - `GET /guestbook` — renders **every** stored entry **unescaped** into the HTML body, and
    links each to a per-entry page.
  - `GET /guestbook/e/<id>` — renders one stored entry **unescaped**; reachable **only**
    from the `/guestbook` list, i.e. only discoverable by the Phase B re-crawl after an
    entry exists. This is the case that forces the full re-crawl (RF-05) rather than a
    re-fetch of the first-crawl page set.
- **Given** the **hardened** profile, **then** the guestbook `POST` is accepted but
  `/guestbook` and `/guestbook/e/<id>` render entries with `html.escape` — yielding **zero**
  `INJECTION` findings with `--stored-xss` on.

**RF-14 — Integration tests**
- **Given** an Active scan of the insecure profile **with** `--stored-xss`, **then**
  `injection.xss.stored` is reported with `location.param == "body"`,
  `location.method == "POST"`, and a render-location URL that is a `/guestbook…` page
  distinct from the injection point; the finding's evidence names both ends.
- **Given** an Active scan of the insecure profile **without** `--stored-xss`, **then**
  **no** `injection.xss.stored` finding and **no** request to `POST /guestbook` with a
  marker and **no** second crawl (assert via the fixture request log).
- **Given** a **passive** scan, **then** none of the above and no crafted request.
- **Given** an Active `--stored-xss` scan of the **hardened** profile, **then** **zero**
  `INJECTION` findings.
- **Given** the marker rendered on `/guestbook/e/<id>`, **then** the test asserts the
  finding's render location is the **per-entry** page — proving the full re-crawl found a
  page absent from the first crawl.
- **Given** an authenticated (`--cookie`) `--stored-xss` scan, **then** a marker submitted
  to a form in the `/account` area is found on re-crawl, and the cookie value appears
  **nowhere** in any report (007 RF-14, extended to the re-crawl).
- **Given** two identical Active `--stored-xss` runs, **then** identical findings and
  fingerprints (the target having more marker rows the second time notwithstanding).

**RF-15 — Unit tests**
- Phase A: POST-form points visited before query points; excluded forms (`/login`) get no
  marker; hidden/CSRF fields preserved; `token → (point, payload)` map built; budget
  gating.
- Phase B: token found verbatim in an executable context → hit; encoded / `text/plain` /
  comment-only → no hit; token only in the Phase A POST response → no hit (that is
  reflected); token present in the pre-injection body of a known page → no hit; token on a
  new URL → hit; `_STORED_REFETCH_CAP` truncation → warning; `max_pages` still caps.
- Dedup / fingerprint: one hit per injection point across multiple render pages; render-page
  id varying across runs does not change the fingerprint.
- Check: `injection.xss.stored` turns hits into findings with the right location and
  evidence; empty when no hit.
- Config / CLI: `[injection] stored_xss` round-trips and defaults `false`; `--stored-xss`
  beats the file; `--stored-xss` without `--mode active` → warning, no pass; `list-checks`
  shows the id; the summary re-crawl note.
- Orchestrator: the stored pass runs only when `mode is ACTIVE` and `stored_xss` and the
  check is selected; a raising stored pass surfaces as a scan warning, not a crash (as 006's
  `_inject`).

### Documentation

**RF-16 — Docs**
- `docs/active-injection.md` gains a **Stored XSS** section (or a new
  `docs/stored-xss.md` linked from it): the two-phase inject-then-recrawl model; the
  dedicated `--stored-xss` opt-in and **why** it exists (markers are persisted by design —
  amends 006 RNF-07); the plain statement that marker strings remain in the target and are
  not cleaned up; the shared budget + `_STORED_REFETCH_CAP`; what a hit proves; the
  blind-spot and truncation limits; the authenticated-scan synergy.
- `docs/architecture.md` (the checks bullet), `docs/writing-checks.md` (replace the
  "if a later spec adds stored XSS…" note with the shipped two-phase pass as the reference
  for a stateful Active technique), `README.md` (coverage table `v0.8` row + a `--stored-xss`
  quick-start line; update the "Stored XSS … moved to a later spec" note to "shipped in
  v0.8"), `CLAUDE.md` (layer-3 paragraph + `Estado` line → `008` concluída, next = `009` /
  `010`), and `specs/README.md` (roadmap row `008-stored-xss` → **done**). 008 moves
  `draft → approved → in progress → done`.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.checks.injection` (a stored-phase module + the marker constants
+ the check) with, at most, a small additive change to `webvigil.core.config`
(`stored_xss`) and `webvigil.core.orchestrator` (the pass wiring). It imports nothing from
`webvigil.cli`, `webvigil.api`, or `web/`. Phase B reuses `webvigil.crawler.Crawler`.
Detection uses `re`, `selectolax`, and `urllib.parse` — **no runtime dependency is added**.
The `import-linter` contract is unchanged.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy` covering the new
modules. **No** API migration test and **no** `web` gate expected (pending the RF-12
confirmation). The Docker jobs are unchanged (the fixture target image already packages the
insecure profile).

**RNF-03 — Safe by default**
A passive scan and a plain `--mode active` scan (no `--stored-xss`) are byte-for-byte
unchanged and write **no** marker. The stored pass runs only past
`--mode active --authorized-by` **and** the `--stored-xss` opt-in. Every Phase A and Phase B
request is in-scope, `GET`/`POST` only, rate-limited, and bounded by the shared budget and
the re-fetch cap.

**RNF-04 — Determinism**
Per RF-09. Given the same target behaviour, findings and fingerprints are identical across
runs; the fingerprint is keyed on the injection point, not the render location or the
token; report ordering is stable.

**RNF-05 — False-positive discipline**
Per RF-08. A hit needs the marker verbatim in an executable context on a Phase B GET,
absent from the known page's pre-injection body; the hardened fixture yields zero
`INJECTION` findings with the pass on.

**RNF-06 — Persistent-marker hygiene**
Per RF-03. Markers are a small, static, documented, in-repo set; each is benign (no
`alert(`, no data exfiltration), distinctive, WebVigil-attributable, and bounded. The
evidence snippet is trimmed. 008 amends 006 RNF-07 **only** for this pass and **only**
behind the dedicated opt-in; the docs state markers are not removed.

**RNF-07 — Bounded work and runtime**
The shared `request_budget`, the per-point cap, `_STORED_REFETCH_CAP`, and `max_pages`
together keep a stored scan's added request count and wall-clock time predictable for a
given site size. Hitting any cap is a scan warning, not an error.

**RNF-08 — Python support**
Runs on CPython 3.12 and 3.13 (the existing CI matrix).

**RNF-09 — Docs**
Per RF-16. The persisted-marker behaviour, the dedicated opt-in, and the exact scope (no
DOM, no blind, no non-form vectors, no cleanup) are stated plainly so a user is never
surprised.

## Resolved decisions

Settled with Ryan on 2026-09-07:

1. **Re-fetch surface:** a **full fresh re-crawl from the seed** after Phase A, bounded by
   `max_pages` and a dedicated re-fetch cap. The stateful two-phase crawl is the core of
   the spec. (Rejected: re-fetching only the first-crawl page set — it would miss a marker
   that surfaces on a URL created by the injection.)
2. **Consent model:** a **dedicated opt-in** — `--stored-xss` / `[injection] stored_xss`,
   **default off** — *on top of* `--mode active --authorized-by`. Stored-XSS testing writes
   persistent data to the target (it amends 006 RNF-07), which is more invasive than
   reflected fuzzing and warrants an explicit extra choice — the same reasoning that gave
   spec 005's GET-only probe its own `--probe` opt-in.
3. **Injection vectors:** the **006 injection-point model** — fuzzable fields of `POST`
   forms **and** `GET` query params (`enumerate_points`, `_FUZZ_TYPES`, `_EXCLUDE_FORM_RE`
   unchanged) — with **POST-form points tried first** and query params second. (Rejected:
   POST-only, which drops the rare GET-persisted case; and all-fields-incl-hidden, which
   adds noise and submission-breakage risk.)
4. **Budget:** Phase A and Phase B draw on the **shared `[injection] request_budget`**, with
   Phase B additionally bounded by an internal `_STORED_REFETCH_CAP` constant. `stored_xss`
   is the on/off knob (like `time_based_sqli`) but **defaults off** per decision 2. No
   separate `stored_xss_budget` config key.

## Resolved during requirements

Settled with Ryan on 2026-09-07 ("aprovado"). The design phase elaborates the mechanics;
these answers are fixed.

5. **Pass structure (Open question 1):** a **separate `StoredXssScanner`**, invoked by the
   orchestrator **after `_inject`**. Phase B needs a `Crawler`, which `InjectionScanner`
   does not hold — a dedicated pass keeps that dependency out of the reflected engine.
6. **Re-crawl construction (Open question 2):** a **lighter re-crawl** that reuses the first
   crawl's discovered-URL frontier as **seeds**, then follows **one hop** of new links from
   the pages it re-fetches — not a verbatim second `discover()`. Faithful to decision 1
   (full coverage from the seed) at lower request cost.
7. **`_STORED_REFETCH_CAP` value (Open question 3):** an internal constant, **sized against
   the fixture's real page count**; design sets the number and validates it in
   implementation (as 006 did for its budget defaults).
8. **Marker set (Open question 4):** plain **`<wvstored…>`-tag** payload strings — a bare
   distinctive tag carrying the token, plus one attribute-breaker of the same shape. No
   `alert(`, no comment/attribution wrapper.
9. **Multi-render reporting (Open question 5):** report the **first executable render
   location only** (RF-05 as written) **plus a count** of the other pages the marker
   rendered on, in the evidence.

## Open questions

None. Ready for `/spec design`.
