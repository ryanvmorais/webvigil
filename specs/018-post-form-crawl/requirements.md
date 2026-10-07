---
feature: POST form submission by the crawler — urlencoded, multipart and OpenAPI JSON bodies (Active Mode, opt-in)
status: done
date: 2026-10-07
related:
  - 007-auth-flows/requirements.md
  - 013-auth-and-api-surface/requirements.md
  - 014-file-upload/requirements.md
  - 017-csrf-confirmation/requirements.md
origin: conception
---

# 018 — POST form submission by the crawler

## Context and problem

Issue #55 points at a hole in what the checks can see. The crawler follows `<a href>` links
and, since spec 007, submits safe **`GET`** forms (search, filters) with their default values.
It reads `POST` forms into the inventory and never sends them
([`docs/authenticated-scanning.md`](../../docs/authenticated-scanning.md), "What is
deferred"). Whatever sits *behind* a `POST` is therefore never reached by the passive checks:
the "thank you" page after a contact form, the confirmation step of a multi-page flow, the
error page a malformed submission draws, the record listing a "create" form redirects to, the
JSON a `POST` API operation answers with.

**What exists, and what does not.**

- The **injection pass** (006, 013) already `POST`s to the forms and form-urlencoded
  operations it enumerates, but it sends *payloads* into one field at a time and judges the
  response against a baseline. It does not feed the response back into the crawl: a page
  reached only by a `POST` is not a `Page`, so no passive check (headers, cookies, content,
  disclosure) ever looks at it and none of its links or forms are followed.
- The **CSRF confirmation pass** (017) `POST`s forms to prove a token is not enforced, and
  also discards what it reads.
- `--openapi` (013) seeds the crawl with `GET` operations only. A `POST` operation's body is
  synthesised (`ApiOperation.body_json`, `body_fields`) but used only as the injection
  baseline.

**What the issue asks.** Let the crawler submit `POST` forms with safe, benign values, and
support `multipart` and JSON bodies. Respect the good-neighbour policy and the passive /
active split: *submitting forms changes server state, so it must be opt-in.*

**What "support multipart and JSON" can honestly mean here.** An HTML form can only be
`application/x-www-form-urlencoded`, `multipart/form-data` or `text/plain`; it can never
carry a JSON body. A JSON body comes from an API description or from JavaScript, and WebVigil
runs no JavaScript. So the JSON half has exactly one source: the **`POST` operations of an
`--openapi` import**, whose body the importer already synthesises. See **Open question 2**.

**It is a different kind of crawl step.** Every crawl request so far is a read. This one
**writes** — a record, a message, a subscription, an email — with benign values, once per
distinct form. That is the `--stored-xss` (008), `--file-upload` (014) and `--confirm-csrf`
(017) situation and it gets the same discipline: Active Mode plus its own switch
(**Open question 1**).

### Where it sits

```
webvigil.crawler
       ├── Crawler.discover()        GET BFS: links, safe GET forms, sitemaps, --openapi GETs  [001/007/013]
       └── Crawler POST phase        NEW, after the GET queue drains, opt-in:
                                      urlencoded + multipart forms, OpenAPI POST operations
                                      → each response becomes a Page, its links / forms are
                                        enqueued and the GET BFS resumes (bounded by max_pages)

webvigil.crawler.forms     + body builder shared with the 017 pass (defaults, benign sentinel)
webvigil.core.context      Page learns the method that produced it
config / CLI               + [scan] submit_post_forms / --submit-post-forms, max_post_submissions
```

Reuses what 006–017 built, unchanged: the `Form` inventory and `parse_forms`, the candidate
and safety predicates (`is_candidate`, `is_destructive_form`, `is_auth_form`, `is_logout`),
`ApiOperation` and its synthesised bodies, `HttpClient.request` (scope guard, rate limiter,
`[auth]` cookies and headers, no retry of a non-idempotent request) and the Active-Mode gate.
**No new consent mechanism beyond the opt-in.** **No change to `webvigil.api` or the
dashboard** — the switch defaults off and the API never sets it. The engine imports nothing
from `webvigil.cli` / `webvigil.api` / `web/`; no new runtime dependency.

## Goals

- An **opt-in `POST` phase in the crawler**, off by default, usable only in Active Mode
  (`--mode active --authorized-by` **and** `--submit-post-forms`), that submits each distinct
  candidate form once with its **default values** (and a benign marker for a field that has
  none), never a payload.
- **Three body kinds**: `application/x-www-form-urlencoded` forms, `multipart/form-data` forms
  **without** a file input, and the **JSON body** of an `--openapi` `POST` operation.
- The **response becomes a `Page`**: every check that reads `ctx.pages` sees it, and the links
  and forms on it are enqueued, so a multi-step flow is followed by the existing BFS, bounded
  by `max_pages`.
- **Reads stay stable**: the `POST` phase starts only after the `GET` queue has drained, so a
  write cannot change a page the crawl is still reading.
- **Safe by construction**: the 017 candidate filter (login / registration / search /
  destructive forms are skipped), the 013 operation filter for API operations, `robots.txt`
  honoured, a hard cap on submissions, one submission per distinct form.
- **No cross-pass damage**: a page that only exists as the answer to a `POST` is never
  re-requested with `GET` by another pass.
- **Fixture-app coverage** for both profiles — a `POST`-only page, a redirect-after-post, a
  multipart form, a `POST`-only JSON operation — deterministic and offline.
- **Docs** corrected: the "What is deferred" bullet leaves `docs/authenticated-scanning.md`;
  the README / CLAUDE / specs-roadmap entries.

## Non-goals

- **File uploads.** A form with a file input is skipped here; `--file-upload` (014) owns it.
  The crawler never invents a file.
- **Parameter mining and guessing** — the issue's "Problem" lists it, its "Proposal" does not.
  WebVigil tests the parameters a target exposes, not guessed ones (README, "Not a fuzzer").
- **Payloads.** The crawl sends defaults only. Fuzzing the values is the injection pass's job
  and it already does.
- **JavaScript-built requests.** A form assembled by script, an `XHR` / `fetch` body, a JSON
  shape the page's JS knows: out since spec 001 (no headless browser). JSON comes only from
  an OpenAPI document.
- **Login.** Login / registration / password forms are never submitted; automated login is
  issue #52.
- **Other verbs and encodings.** No `PUT` / `PATCH` / `DELETE`, no `text/plain` forms, no
  `XML` bodies, no `GraphQL`.
- **Multi-step state tracking.** The crawl follows the *links and forms of each response*; it
  does not model a wizard's hidden state across steps or re-submit a form with a value chosen
  from an earlier response.
- **Web API / dashboard changes.** Engine and CLI only, following 006–017.

## Personas

| Persona | Needs from 018 |
|---|---|
| **Security-conscious developer** | Passive checks (headers, cookies, disclosure, SRI) that also read the pages a form leads to — the post-submit page, the error page — on a staging copy, without writing a script. |
| **Pentester / consultant** | A wider authenticated surface in one run: the pages behind the `POST`s of a logged-in session, reached the way a user would reach them, with the writes bounded and listed. |
| **API owner** | `POST`-only operations of an OpenAPI description reached, so their responses are inspected, not only the `GET`s. |
| **CI pipeline author** | An off-by-default switch whose effect is deterministic and capped, safe to enable against a disposable environment. |
| **Check author / contributor** | A `Page` that says which method produced it, so a check can tell a fetched page from a submission's answer. |

## Functional requirements

### Gate and selection

#### RF-01 — Opt-in, Active Mode only

- **Given** `[scan] submit_post_forms = true` (CLI `--submit-post-forms`) and `--mode active
  --authorized-by`
  **When** the crawl runs
  **Then** the `POST` phase of RF-04 runs after the `GET` queue drains.
- **Given** a Passive scan, or an Active scan without the switch
  **Then** no `POST` is sent by the crawler and the crawl is byte-for-byte what it is today.
- **Given** the switch on outside Active Mode
  **Then** a scan warning says it requires `--mode active` and the phase does not run — the
  008 / 014 / 017 behaviour for an opt-in used in the wrong mode.
- **Given** `[scan] submit_forms = false`
  **Then** it still governs only the `GET` forms; the two switches are independent.

#### RF-02 — Which forms are submitted

- **Given** the crawler's form inventory
  **Then** a form is a candidate only when it is an in-scope `POST`, its enctype is
  `application/x-www-form-urlencoded` or `multipart/form-data`, it has **no file input**, and
  it is **not** an auth form, a search form, a logout form or destructive-looking
  (`is_candidate`, `is_destructive_form`, `is_logout` — the 017 filter).
- **Given** a skipped form
  **Then** it is counted by reason in the crawl summary (RF-08), never silently dropped.
- **Given** the same `(method, action, field names)` on several pages
  **Then** it is submitted once.

#### RF-03 — Which API operations are submitted

- **Given** an `--openapi` import
  **Then** each `POST` operation is a candidate, and a `GET` operation keeps its 013 role as a
  crawl seed.
- **Given** an operation whose path or `operationId` looks like authentication or a
  state-changing action (`login`, `logout`, `delete`, `password`, `checkout`, …)
  **Then** it is skipped, as 013 already skips it for fuzzing.
- **Given** an operation with a form-urlencoded body, with an `application/json` body, or
  with no body
  **Then** it is sent with the synthesised body of the matching kind
  (`ApiOperation.body_fields`, `body_json`, nothing) and its `Content-Type`; any other body
  type is skipped and counted.

### Submission

#### RF-04 — Phase order and cap

- **Given** the opt-in is on
  **When** the `GET` BFS queue is empty (or `max_pages` is reached)
  **Then** the crawler submits the candidates in a stable order — forms in inventory order,
  then API operations — up to `max_post_submissions` (default 25).
- **Given** the cap is reached
  **Then** the remaining candidates are counted as "not submitted (cap)" in the summary.
- **Given** a submission's response (RF-06) adds new `GET` URLs to the queue
  **Then** the `GET` BFS resumes for them, within `max_pages`, and the phase then continues
  with the next candidate; a form that first appears on such a page joins the candidates
  until the cap is reached.

#### RF-05 — Benign values only

- **Given** a form field with a default value
  **Then** the crawler sends it unchanged (hidden fields and anti-CSRF tokens travel as
  served; an unchecked box is omitted; the first named submit button is sent).
- **Given** a text-like field with no default
  **Then** it gets `wvcrawl<token>` (one random token per scan, findable on the target);
  email / url / number / tel / date fields get a browser-acceptable fallback; `password` and
  `file` fields are never invented.
- **Given** an urlencoded form
  **Then** the body is sent urlencoded; a multipart form is sent as `multipart/form-data` with
  its fields as parts and no file part.
- **Given** the crawler
  **Then** it sends no injection payload and changes no field it did not fill.

#### RF-06 — The response becomes a page

- **Given** a submission that returns a response (after the client's in-scope redirects)
  **Then** it is recorded as a `Page` carrying the method that produced it, counted in
  `pages_scanned` and against `max_pages`, and read by every check that reads `ctx.pages`.
- **Given** the response is HTML
  **Then** its links and forms are enqueued / inventoried like any page's (RF-02 filters
  apply, a destructive link is skipped on an authenticated scan).
- **Given** the submission fails (transport error, out of scope)
  **Then** it is a failed page, not an exception out of the crawl, and counts toward the cap.
- **Given** the `POST` answers `4xx` or `5xx`
  **Then** the page is kept: an error page is what the disclosure checks want to read.

#### RF-07 — Politeness, secrets, retries

- **Given** any submission
  **Then** it goes through the shared `HttpClient`: scope guard, concurrency cap, per-host
  delay, timeout, and `robots.txt` (a form or operation whose URL `robots.txt` disallows is
  not submitted, counted as skipped).
- **Given** configured `[auth]` cookies and headers
  **Then** they are attached by the client as for every request and never copied into a
  page, a log line, a warning or the metadata.
- **Given** a `POST`
  **Then** it is never retried on a `5xx` or a read timeout (the client's non-idempotent
  rule).

#### RF-08 — Crawl summary, not noise

- **Given** the phase ran
  **Then** one scan warning gives the tallies — `POST crawl: N submitted — A forms, B API
  operations, C skipped, D not submitted (cap)` — and no line appears when it did not run or
  there was nothing to submit.

### Effect on the rest of the scan

#### RF-09 — A submission's page is not re-requested

- **Given** a `Page` produced by a `POST`
  **Then** no other pass re-requests its URL with `GET`: the stored-XSS re-crawl frontier, the
  request-envelope URL sample and the disclosure probe's path derivation ignore it. The passes
  keep using the pages that *were* fetched with `GET`.
- **Given** the same URL reached by a `GET` and by a `POST`
  **Then** both pages are kept (they are different responses) and a finding's fingerprint is
  unaffected (it keys on the check, location and evidence, as today).

#### RF-10 — Findings and the passive checks

- **Given** a passive check run over a submission's page
  **Then** its finding location is the form's action URL and its evidence says the page is
  the answer to a `POST`, so a reader can tell it from a fetched page.
- **Given** the scan produced no `POST` page
  **Then** every existing finding is byte-identical to before 018.

#### RF-11 — Relationship with the 006 / 008 / 014 / 017 passes

- **Given** the crawler's phase and the other write passes in one scan
  **Then** the crawler's phase runs inside the crawl, before every pass, and the 017 CSRF
  pass still runs last; each pass keeps its own switch and cap and none reuses another's.

### Fixture app and tests

#### RF-12 — Vulnerable and hardened endpoints

- **Given** the fixture app, **both** profiles
  **Then** it serves: a `POST` contact form whose answer is a `POST`-only page with a new
  link; a form that redirects after posting (`302`) to a page that only exists after a post;
  a multipart form (no file input); an OpenAPI `POST` operation answering JSON; and a form
  that answers an error page on a missing field.
- **Given** the insecure profile
  **Then** the `POST`-only pages lack the security headers and one answers a stack trace, so
  the passive checks have something to find that no `GET` reaches.
- **Given** the fixture
  **Then** each route records what it received (`app.state`), so a test can assert how many
  writes the crawl made and that none carried a payload.

#### RF-13 — Integration tests

- Active scan of the insecure profile with the switch → the `POST`-only pages are in
  `pages_scanned`; a header / disclosure finding exists whose location is a `POST`-only
  action; the summary warning has the right tallies.
- The same scan **without** the switch, and a Passive scan with it → no `POST` reaches those
  routes and no such finding exists.
- Active scan of the hardened profile with the switch → the pages are reached and nothing is
  reported.
- Login, search, destructive and file-input forms are not submitted; no submitted value is a
  payload; every submission respects the cap.
- No later pass re-requests a `POST`-only URL with `GET` (the fixture's request log).
- Deterministic across repeated runs.

#### RF-14 — Unit tests

- Candidate filter: each skip reason (non-`POST`, file input, `text/plain`, auth, search,
  logout, destructive, robots-disallowed, over the cap), the de-duplication and the order.
- Body building: urlencoded and multipart, defaults unchanged, the marker, typed fallbacks,
  first submit button, no file part; API operations for form / JSON / no body.
- Phase order: nothing sent before the `GET` queue drains; the BFS resumes on new URLs; the cap
  and `max_pages` both stop it.
- `Page` method: a `POST` page carries it, a `GET` page does not; the other passes' filters
  skip a `POST` page.
- Config and CLI: the defaults, the TOML keys, `--submit-post-forms`, the warning outside
  Active Mode, the summary line.

### Reporting and docs

#### RF-15 — Reporters unchanged

- No reporter gains a field or a section; a saved canonical JSON re-renders offline exactly
  as before.

#### RF-16 — Docs

- `docs/authenticated-scanning.md` ("Form-driven crawling" now covers the `POST` phase; the
  bullet leaves "What is deferred"), `docs/api-scanning.md` (`POST` operations are submitted
  under the switch), `README.md` (`v0.18` row, the opt-in switches sentence, quick start),
  `CLAUDE.md`, `docs/architecture.md` and the `specs/README.md` roadmap row. The docs state
  plainly that the phase **writes to the target** and what it never does.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.crawler` and the orchestrator / config / CLI wiring; no new
runtime dependency. The engine imports nothing from `webvigil.cli` / `webvigil.api` /
`web/`; `import-linter` unchanged.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green. No `web` gate work.

**RNF-03 — Safe by default**
A Passive scan, and an Active scan without the switch, is unchanged and sends no `POST` from
the crawler. The phase runs only past `--mode active --authorized-by` **and** the switch. It
writes to the target; the CLI help, the docs and the summary say so.

**RNF-04 — Bounded work**
At most `max_post_submissions` submissions (default 25) and `max_pages` pages in all; one
submission per distinct form or operation; no retry. The default is a constant justified in
the design.

**RNF-05 — Determinism**
Order is inventory order, then operations; the marker is random per scan but findings and
fingerprints are stable across runs.

**RNF-06 — Scope guard intact**
Every request goes to an in-scope URL through the `HttpClient`; no new host.

**RNF-07 — Secrets**
Configured cookies and headers never reach a page, log, warning or metadata.

**RNF-08 — Python support**
No syntax or API newer than the project's Python floor.

## Resolved decisions

1. **Active Mode only, plus its own switch.** The Passive contract is "safe to point at
   production"; a `POST` changes state. The Active gate alone would turn every Active scan
   into a form-submitting one, which is the 017 argument again.
2. **Defaults and a marker, never a payload.** The crawl is for reach, not for finding; the
   injection pass already sends payloads and keeps its own budget.
3. **The `POST` phase waits for the `GET` queue.** A write cannot change a page the crawl is
   still reading, and the `GET` surface the passive checks see is the same with or without
   the switch up to that point.
4. **One submission per distinct form.** The same discipline as the GET-form de-duplication;
   a form is not re-posted per page it appears on.
5. **A file input is out.** A fake file is an upload test, and 014 already owns it, with its
   own opt-in and its own proof.
6. **The 017 filter is the safety filter.** One definition of "candidate" and "destructive"
   for every pass that submits a form.

## Open questions

1. **Gate.** Active Mode **and** a switch. **Proposed:** `--submit-post-forms` /
   `[scan] submit_post_forms`, default off, with `max_post_submissions` (default 25)
   beside it in `[scan]`. The alternative — the switch alone, usable in a Passive scan — is
   rejected: it would let the safe-for-production mode write to the target.
2. **Where the JSON body comes from.** **Proposed:** only the `POST` operations of an
   `--openapi` import (body already synthesised by 013). HTML cannot send JSON and WebVigil
   runs no JavaScript, so there is no other honest source. The alternative — guessing a JSON
   shape for a form-less endpoint — is parameter guessing, a non-goal.
3. **Phase order.** **Proposed:** the `POST` phase starts after the `GET` queue drains and
   the `GET` BFS resumes for what it finds (RF-04). The alternative — submitting each form as
   it is discovered — finds more pages in one pass but lets a write change a page the crawl
   is still reading and makes the `GET` surface depend on the switch.
