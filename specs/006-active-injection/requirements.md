---
feature: Active injection — reflected XSS, SQL injection, path traversal, open redirect (Active Mode)
status: done
date: 2026-09-06
related:
  - 001-foundation/requirements.md
  - 002-web-api/requirements.md
  - 003-web-ui/requirements.md
  - 004-deps-fingerprint/requirements.md
  - 005-info-disclosure/requirements.md
origin: conception
---

# 006 — Active injection

## Context and problem

Specs 001–005 shipped the engine + CLI, the Web API, the dashboard, passive dependency
fingerprinting, and opt-in information-disclosure probing. **Every check so far is
`PASSIVE`.** It reads what the target returns to ordinary requests — headers, cookies, TLS,
CORS, crawled HTML, referenced scripts — or, with `--probe`, fetches a curated list of
well-known paths with plain `GET`s. WebVigil has never sent the target a crafted input and
watched how the application *handles* it.

Active Mode itself already exists end to end: `--mode active` plus `--authorized-by`
raises a legal-warning banner, records the attestation in the metadata and every report,
and makes `mode == ACTIVE` checks eligible (spec 001 RF-15). But **no active check ships
today** — an Active run currently executes the same passive checks. This spec fills that
gap with the first ones.

006 adds **active injection testing** for the four vulnerability classes that can be
detected reliably from the responses themselves, with no headless browser and no
out-of-band collaborator:

- **Reflected XSS** — a parameter's value comes back in the page unescaped, in a context
  where it would execute.
- **SQL injection** — a parameter reaches a SQL query unsanitised, provable through a DBMS
  error, a boolean-differential response, or an injected time delay.
- **Path traversal / LFI** — a parameter reaches a filesystem path, provable by reading a
  known file (`/etc/passwd`, `win.ini`).
- **Open redirect** — a parameter controls a redirect target and an off-site value is
  honoured.

To do this the engine needs machinery it has never had: HTTP verbs beyond `GET`, discovery
of the target's `<form>`s and query parameters as **injection points**, a **bounded
crafted-request pass** with baselines and a shared request budget, and per-class detectors
with confirmation logic to keep false positives out.

Like every earlier spec it stays inside the engine's rules: a pure library, no new runtime
dependency (detection is `re` + `difflib` + stdlib), the scope guard unchanged, the
good-neighbor policy applied to every crafted request, and — this being Active Mode — the
authorization gate strictly enforced.

### Deferred, on purpose

Three items from the original roadmap line for `006` move to a later spec, for concrete
technical reasons rather than scope-trimming:

- **Stored XSS** needs a stateful two-phase flow (inject via one request, then re-fetch
  every discovered page hunting for the marker rendered unescaped). That is a new crawl
  mechanic; it rides on top of the injection-point model 006 builds. Deferred to a
  follow-up.
- **SSRF** is only meaningfully detectable with an **out-of-band collaborator** — a server
  the scanner controls that the target calls back to. WebVigil's design principle since
  spec 004 is that the engine talks only to the target, never to a third party (the
  Retire.js DB is vendored, spec 005's probe is target-only, no telemetry). An in-band-only
  SSRF check (`169.254.169.254`, `file://`, response/timing diff) misses every blind case
  and produces mostly false negatives. Deferred until a spec adds an **opt-in** collaborator
  (parallels the deferred OSV.dev provider already tracked for spec 004).
- **OS command injection, XXE, SSTI** were never in the `006` line and stay out.

### Where it sits

```
webvigil.checks.injection          new check package  (Category.INJECTION, mode = ACTIVE)
       │
       ├── injection.xss.reflected          reflection + context analysis, no JS execution
       ├── injection.sqli.error-based        DBMS error signatures absent from the baseline
       ├── injection.sqli.boolean-based      true/false differential, confirmed
       ├── injection.sqli.time-based         injected sleep reproduces, control returns fast
       ├── injection.traversal.path          /etc/passwd · win.ini signature
       └── injection.redirect.open           off-site Location honoured

webvigil.http        + request(method, url, ...)   POST/other verbs, in-scope, rate-limited
form parsing         <form> read out of already-crawled page bodies — no new crawl fetches
injection engine     one bounded pass: enumerate points → baseline → fan payloads → detect
                     shared request budget, shared baselines, confirmation rounds

payload sets:  src/webvigil/checks/injection/data/…   (versioned in-repo, documented)
vulnerable target:  tests/fixtures/app.py insecure profile + a compose service (RF-24)
```

The engine still imports nothing from `webvigil.cli`, `webvigil.api`, or `web/`. The
`import-linter` "engine stays independent" contract is unchanged (`webvigil.checks`,
`webvigil.http`, `webvigil.crawler` are already source modules). Findings flow through spec
001's four reporters; `Location` has carried `method` and `param` since spec 001, so the
reporters already render them. With **no change to `webvigil.api` or the dashboard**,
`injection.*` findings persist and render through spec 002/003's existing plumbing, and the
new `INJECTION` category surfaces automatically (the API returns `category` as a string;
the dashboard derives its category filter from the data). This is an **engine + CLI** spec.

## Goals

- The first `ACTIVE` checks: `injection.xss.reflected`, `injection.sqli.error-based`,
  `injection.sqli.boolean-based`, `injection.sqli.time-based`, `injection.traversal.path`,
  `injection.redirect.open` — all `category = INJECTION`, `mode = ACTIVE`, gated by the
  existing `--mode active --authorized-by` (no new consent mechanism).
- **Injection-point enumeration**: query-string parameters on discovered in-scope URLs
  plus fuzzable fields of discovered in-scope `<form>`s (GET and POST), parsed from
  already-crawled page bodies — no extra crawl fetches. De-duplicated and capped.
- A **bounded crafted-request pass** with a per-scan request budget and per-point payload
  caps, shared baselines, and confirmation rounds for the differential detectors; every
  request through `ctx.http`, every policy (scope, concurrency, delay, timeout) applied.
- **Non-destructive posture**: `GET`/`POST` only (never `PUT`/`PATCH`/`DELETE`); forms that
  look like authentication or destruction (login, logout, delete, password, register,
  checkout…) excluded from fuzzing by a documented heuristic; hidden and anti-CSRF fields
  preserved as-is; `file`/`password` inputs submitted but not payload-fuzzed.
- **HTTP layer**: a general in-scope `request(method, …)` for non-`GET` verbs, with a
  retry policy that never re-sends a non-idempotent request on a `5xx`.
- **False-positive discipline**: reflected XSS needs the HTML-significant characters
  unescaped in an executable context; error-based SQLi needs a real DBMS signature;
  boolean/time-based need a confirmed differential; the hardened fixture profile yields
  **zero** `INJECTION` findings.
- **Vulnerable target**: the `tests/fixtures` insecure profile gains injectable endpoints
  for all four classes (plus a login form the fuzzer must skip); a profile-gated
  `docker-compose` service runs it for manual `--mode active` scans and demos.
- Docs: a new active-injection section (what each class detects and its limits, the
  injection-point model, the budget, the non-destructive heuristics, why stored XSS / SSRF
  / command injection are deferred) plus the usual architecture / writing-checks / README /
  CLAUDE / roadmap updates.

## Non-goals

- **Stored / persistent XSS, DOM XSS.** Stored XSS needs a stateful re-fetch phase (see
  "Deferred"); DOM XSS needs JavaScript execution (a headless browser), explicitly out
  since spec 001. 006 detects reflected XSS by response inspection only.
- **SSRF.** In-band-only detection is low-value; a real check waits for an opt-in
  out-of-band collaborator (see "Deferred").
- **OS command injection, XXE, SSTI, LDAP/NoSQL/XPath injection, CRLF/header injection,
  host-header attacks, HTTP request smuggling, deserialisation, mass assignment, race
  conditions.** Not in the `006` line; each is a candidate for its own later spec.
- **A JavaScript engine / headless browser.** The crawler and the XSS detector work on
  served HTML text only (spec 001 Non-goal, unchanged). No client-side rendering, no
  event-handler simulation.
- **An out-of-band / OAST collaborator server**, DNS callback infrastructure, or any
  scanner-hosted third-party service. The engine talks only to the target (spec 004/005
  principle).
- **Authenticated / session-aware injection testing** — reaching parameters that only
  exist behind a login, maintaining a session, CSRF-token refresh across a login flow.
  Spec 007. 006 fuzzes what an unauthenticated crawl can reach, and preserves anti-CSRF
  tokens it *finds* in a form but does not solve login.
- **Parameter mining / brute-forcing hidden parameters** (Arjun/param-miner style). 006
  fuzzes parameters the target actually exposes in a URL or a form, not guessed ones.
- **Automated exploitation** — dumping a database via a confirmed SQLi, reading arbitrary
  files past the proof, chaining an open redirect into a full attack. 006 proves the
  vulnerability with a single bounded marker and stops.
- **Brute-forcing credentials or fuzzing login forms.** Auth/destructive forms are
  excluded from fuzzing by heuristic (Resolved decision 3).
- **WAF detection / evasion / payload polymorphism.** Payloads are a small, static,
  well-known set shipped in-repo (RNF-07). No encoding-mutation engine, no bypass tuning.
- **A new consent gate.** Injection checks are `mode = ACTIVE` and reuse spec 001's
  `--mode active --authorized-by` gate and banner unchanged (Resolved decision — the
  attestation gate is exactly what this is for).
- **Any database migration, `openapi.json` regeneration, or new API/UI component.**
  `injection.*` findings are ordinary `Finding`s (RF-20). Contrast spec 004, which needed a
  new inventory surface.
- **Fuzzing bodies that are not `application/x-www-form-urlencoded` or query strings** —
  JSON request bodies, `multipart/form-data` file parts, GraphQL, XML. A JSON-body
  injection point is a reasonable later addition; 006 covers URL and urlencoded-form
  parameters.

## Personas

| Persona | Needs from 006 |
|---|---|
| **Security-conscious developer** | "Is my `/search?q=` reflecting unescaped? Is `/item?id=` concatenating into SQL?" — a HIGH finding that names the exact parameter, method, and URL, shows the payload and the proof (reflected string / DB error), and gives a parameterise-and-encode fix. Run locally against a dev instance with `--mode active --authorized-by me`. |
| **CI pipeline author** | An Active scan of a staging deploy that finishes in bounded time (request budget), produces SARIF so `--fail-on high` blocks the release on a confirmed injection, and never runs by accident (the gate). |
| **Pentester / consultant** | Fast, reliable first-pass coverage of reflected XSS, SQLi (three techniques), traversal, and open redirect across every query parameter and form the crawl reached — with confirmation rounds so the report is not full of maybes, and a documented budget so a large app does not explode the request count. |
| **Check author / contributor** | `Category.INJECTION`, the injection-point model, the shared baseline/budget pass, and the confirmation pattern as the reference for writing an `ACTIVE` check — the counterpart to spec 001's passive `Check` example. |

## Functional requirements

### Active Mode, scope, and safety

**RF-01 — Gated by the existing Active-Mode attestation**
- **Given** `--mode active` **and** `--authorized-by "<text>"` (or `[active].authorized_by`
  in the config), **when** a scan runs, **then** the six `injection.*` checks are eligible,
  the spec 001 banner is shown, and the attestation is recorded in the metadata and every
  report — all unchanged from spec 001 RF-15.
- **Given** the default (`--mode passive`), **when** a scan runs, **then** no
  `injection.*` check runs and **no crafted request is issued**; the injection pass is
  skipped entirely.
- **Given** `--mode active` without an attestation, **then** the scan refuses to start
  (non-interactive) or prompts (interactive) — spec 001 RF-15, unchanged. 006 adds **no**
  new flag or prompt for consent.

**RF-02 — Scope guard binds every crafted request**
- **Given** any crafted request (a mutated query, a form submission, a baseline), **when**
  it is issued, **then** it goes through `ctx.http` and the scope guard blocks it before
  network I/O if its host is out of scope (spec 001 RF-04).
- **Given** a payload whose *value* names an off-scope host (an open-redirect target, a
  `file://` URL), **then** that is data in a request to an **in-scope** URL; WebVigil never
  issues a request to the off-scope host. **Given** the response is a 3xx whose `Location`
  points off scope, **then** the HTTP layer records it as evidence and does **not** follow
  it (spec 001 RF-04, unchanged).

**RF-03 — Good-neighbor policy and the active-request budget**
- **Given** the injection pass runs, **then** the concurrency cap, per-host delay, retry
  policy, and `timeout_s` apply to every crafted request exactly as to a crawl fetch
  (spec 001 RF-03).
- **Given** the number of crafted requests (baselines + payloads + confirmations) would
  exceed a **documented per-scan budget**, **when** the pass runs, **then** it stops at the
  budget and the scan records a warning ("active injection stopped at the N-request
  budget"), not an error (parallel to spec 004 RNF-07 / spec 005 RF-09).
- **Given** a single injection point, **then** the payloads sent against it are capped
  (documented per-point cap) so one heavily-parameterised URL cannot consume the whole
  budget.
- **Given** time-based SQLi is enabled, **then** the number of sleep-inducing requests per
  scan is separately capped and each sleep is bounded (default 5 s, below `timeout_s`), so
  the added wall-clock time is predictable.

**RF-04 — Non-destructive posture**
- **Given** the injection engine issues requests, **then** it uses **`GET` and `POST`
  only** — never `PUT`, `PATCH`, `DELETE`, or any other verb.
- **Given** a discovered form whose `method`, `action`, submit-button text, or field names
  match a documented **exclusion heuristic** (login, log in, signin, logout, sign out,
  register, sign up, delete, remove, destroy, drop, password, passwd, change-password,
  reset, checkout, pay, purchase, order, transfer, unsubscribe, deactivate), **when**
  injection points are enumerated, **then** that form is **not fuzzed** (its fields yield
  no injection points). The heuristic and its limits are documented.
- **Given** a form is fuzzed, **then** hidden fields and anti-CSRF-looking tokens are
  submitted **with their discovered values** (never fuzzed, never dropped); `file` inputs
  are omitted or sent empty; `password` inputs are sent empty or with a benign fixed value
  and are **not** payload-fuzzed.
- Active Mode can still cause a state change (submitting a non-excluded form, e.g. posting
  a comment). This is inherent to Active Mode and the spec 001 banner already says so; 006
  does not claim Active Mode is side-effect-free.

### Injection points

**RF-05 — Form discovery (from crawled bodies, no new fetches)**
- **Given** the pages the crawler already fetched, **when** the injection pass starts,
  **then** it parses `<form>` elements out of each in-scope HTML `page.text` and builds a
  `Form` per form: the **absolute** action URL (resolved against the page URL; an empty or
  missing `action` means the page URL), the method (`GET` or `POST`; anything else → `GET`
  per the HTML spec), the enctype, and the fields (name, type, current value; `select`
  first `option`, `textarea` body, `checkbox`/`radio` as present).
- **Given** a form whose resolved action is **out of scope**, **then** it is dropped.
- **Given** the crawler itself, **then** it is **unchanged** — form parsing reads
  `ctx.pages` (spec 005's passive tier established reading crawled bodies without new
  requests). Whether the parser lives in `webvigil.crawler` or the injection package is a
  design decision.

**RF-06 — Injection-point enumeration and dedup**
- **Given** the discovered in-scope URLs and forms, **when** the pass enumerates injection
  points, **then** it produces one point per:
  - each distinct **query-string parameter name** on each in-scope discovered URL
    (`/p?id=1` and `/p?id=2&x=3` on the same path → points `id` and `x` once each), and
  - each **fuzzable field** of each in-scope non-excluded form (RF-04).
- **Given** an injection point, **then** it carries the **base request** needed to replay
  it: method, URL, the full parameter/field set, which single parameter is under test, and
  that parameter's original value (so a payload can *append to* or *replace* it).
- **Given** the same (method, path, parameter) appears on many crawled URLs, **then** it
  collapses to one injection point (fingerprint-style dedup — RNF-04).
- **Given** the number of injection points exceeds a documented cap, **then** the pass
  tests the cap's worth (stable ordering — path, then parameter) and records a warning.

**RF-07 — Baseline**
- **Given** an injection point, **when** the pass starts on it, **then** it sends **one
  baseline request** (the original value, or a benign non-marker value) and keeps the
  baseline response (status, length, a normalised body, timing).
- **Given** the four detectors run against one injection point, **then** they **share** the
  one baseline (it is fetched once, not once per check). The baseline counts against the
  RF-03 budget.

### Detection — the four classes

**RF-08 — Reflected XSS** (`injection.xss.reflected`, `category = INJECTION`)
- **Given** an injection point, **when** the XSS detector runs, **then** it sends a unique
  per-run probe token and a small set of context-breaking payloads combining the
  HTML-significant characters `< > " ' /` and markers like `</script>`,
  `onwv<token>=`, `javascript:` — from a documented in-repo payload set.
- **Given** a response that reflects a payload **with the HTML-significant characters
  intact** (not HTML-entity-encoded, not percent-encoded, not stripped) in an **executable
  context** — raw HTML text (element content), inside a tag as a new attribute or breaking
  the quoting of an existing one, inside a `<script>` block, or as a `javascript:` /
  `data:` URL in `href`/`src` — **then** a `HIGH` finding reports the parameter, the
  payload, the detected context, and the reflected snippet (trimmed).
- **Given** the token is reflected but **encoded** (`&lt;`, `%3C`), or only in a
  non-executing context (an HTML comment, a `text/plain` response, an attribute that is
  safely quoted and the quote is encoded), **then** **nothing** is reported.
- **Given** the same token reflects on several pages, **then** the finding dedups on
  check id + URL + method + parameter (not the payload).
- Detection is **reflection + context analysis only** — no browser, no JS execution.
  `confidence` is `HIGH` for a clean break out of context, `MEDIUM` for a reflection whose
  exploitability depends on context the detector cannot fully resolve.

**RF-09 — SQL injection** (`injection.sqli.*`, `category = INJECTION`, `cwe = 89`)
Three checks, each independently listable and disable-able:

- **`injection.sqli.error-based`** (`HIGH`)
  - **Given** a payload that breaks SQL syntax (`'`, `"`, `')`, `';`, a trailing `--`),
    **when** the response contains a **DBMS error signature** (MySQL/MariaDB
    `You have an error in your SQL syntax`, PostgreSQL `PSQLException` /
    `unterminated quoted string`, MSSQL `Unclosed quotation mark` /
    `Incorrect syntax near`, Oracle `ORA-01756` / `ORA-00933`, SQLite
    `SQLITE_ERROR` / `unrecognized token` / `near "…": syntax error`) **that is absent
    from the baseline response**, **then** a `HIGH` finding names the DBMS, the parameter,
    and quotes the error (trimmed).

- **`injection.sqli.boolean-based`** (`HIGH`)
  - **Given** a parameter, **when** the detector sends a **TRUE** variant
    (`… AND 1=1 -- `, `…' OR '1'='1`, and a numeric `1 AND 1=1`) and a **FALSE** variant
    (`… AND 1=2 -- `, `…' AND '1'='2`), **then** it compares each response to the
    baseline using a normalised similarity measure.
  - **Given** the TRUE response is **materially similar** to the baseline **and** the FALSE
    response is **materially different** (a documented similarity threshold), **and** a
    **second confirmation round** with a different true/false pair reproduces the same
    split, **then** a `HIGH` finding reports the parameter and both response deltas.
  - **Given** the baseline is itself unstable between two identical requests (dynamic
    content, CSRF token, timestamp), **then** the detector accounts for that noise floor
    and does **not** fire on it.

- **`injection.sqli.time-based`** (`HIGH`, on by default, individually disable-able and
  separately budgeted — RF-03)
  - **Given** a parameter, **when** the detector sends a DBMS-specific sleep payload
    (`… AND SLEEP(D) -- `, `…' || pg_sleep(D) -- `, `…; WAITFOR DELAY '0:0:D' -- `,
    Oracle `dbms_pipe.receive_message`) with `D` = the configured delay (default 5 s),
    **then** it measures the response time.
  - **Given** the injected request takes **≥ ~D seconds longer** than both the baseline and
    a **`D = 0` control**, **and** a **repeat** with a different `D` scales proportionally,
    **then** a `HIGH` finding reports the parameter and the timings.
  - **Given** the target is simply slow (baseline and control also take ~D), **then**
    **nothing** is reported.

**RF-10 — Path traversal / LFI** (`injection.traversal.path`, `category = INJECTION`,
`cwe = 22`, `HIGH`)
- **Given** an injection point, **when** the traversal detector runs, **then** it sends
  `../`-sequence payloads targeting `etc/passwd` and `Windows/win.ini` — raw
  (`../../../../etc/passwd`), URL-encoded (`%2e%2e%2f`), double-encoded, the `....//`
  filter-bypass form, an absolute path (`/etc/passwd`), and (legacy) a trailing null byte —
  from a documented in-repo set, prioritising parameters whose baseline value looks
  path-like (contains `/`, `\`, `.`, a file extension, or a name in `file|path|page|doc|
  template|include|dir|folder|download|attachment`) but, within budget, trying all string
  parameters.
- **Given** a response containing a **file signature absent from the baseline** —
  `root:.*:0:0:` (a `/etc/passwd` line), `\[fonts\]` / `\[extensions\]` /
  `; for 16-bit app support` (`win.ini`) — **then** a `HIGH` finding reports the parameter,
  the payload, and the leaked line (trimmed; a `/etc/passwd` body is not a secret but the
  snippet is still bounded).
- **Given** the payload is reflected back unmodified but the file is **not** disclosed
  (an error page, a 404, the literal `../../etc/passwd` echoed with no file content),
  **then** **nothing** is reported.

**RF-11 — Open redirect** (`injection.redirect.open`, `category = INJECTION`,
`cwe = 601`, `MEDIUM`)
- **Given** an injection point, **when** the open-redirect detector runs, **then** it
  injects an **off-site absolute URL** with a sentinel host (`https://webvigil.example/`
  and variants: protocol-relative `//webvigil.example`, backslash `https:\/\/…`,
  whitespace/control-char prefixes, `@`-confusion `https://target@webvigil.example`) into
  parameters — prioritising a preferred-name list
  (`next|url|redirect|redirect_uri|redir|return|returnUrl|return_to|dest|destination|
  continue|to|goto|target|out|link`) but, within budget, trying all string parameters.
- **Given** the response is a **3xx whose `Location` resolves to the injected sentinel
  host**, **or** the body contains a `<meta http-equiv="refresh" … url=<sentinel>>` or a
  `location.href = "<sentinel>"` / `location.replace("<sentinel>")` pointing at the
  sentinel, **then** a `MEDIUM` finding reports the parameter, the payload, and the
  redirect mechanism.
- **Given** the redirect target stays on the target host (the parameter is ignored,
  sanitised, or only a path is honoured), **then** **nothing** is reported.
- WebVigil inspects the `Location` header / body; it does **not** follow the redirect to
  the sentinel host (RF-02).

### Injection engine

**RF-12 — One bounded, coordinated pass**
- **Given** an Active scan with ≥1 `injection.*` check selected, **when** it runs, **then**
  the crafted-request work is **coordinated**: injection points are enumerated once,
  baselines are fetched once per point and shared, and a **single request budget** (RF-03)
  spans all four detectors — the checks do **not** each independently re-fuzz every point.
- **Given** every `injection.*` check is disabled (`[checks] disabled`), **then** the pass
  is skipped entirely — no enumeration, no baseline, no crafted request (parallel to spec
  004 ADR-3 / spec 005 RF-10).
- Whether the coordinator is an orchestrator-owned pass that exposes injection points and
  a budget handle on `ScanContext` (like spec 004's `Fingerprinter` / spec 005's
  `DisclosureProbe`), with the four checks as thin detectors, **or** a shared helper the
  checks call, is an **Open question** for the design phase.
- Every crafted request goes through `ctx.http` (RF-02, RF-03).

**RF-13 — False-positive discipline**
- Reflected XSS requires the HTML-significant characters **verbatim** in an executable
  context (RF-08). Error-based SQLi requires a **real DBMS signature** not in the baseline
  (RF-09). Boolean-based and time-based require a **confirmed** differential across a
  second round (RF-09). Traversal requires a **file signature** not in the baseline
  (RF-10). Open redirect requires the **sentinel host** in the redirect target (RF-11).
- **Given** a target that reflects every parameter, errors verbosely on every input, or is
  slow on every request, **then** the detectors' baseline comparison and confirmation
  rounds keep them from firing.
- **Given** the hardened fixture profile, **then** **zero** `INJECTION` findings are
  reported, with Active Mode on (RF-22).
- `confidence` reflects the evidence strength per finding.

**RF-14 — Determinism**
- **Given** the same target responses and the same payload sets, **then** a scan produces
  the same findings and the same fingerprints across runs, with stable ordering in every
  report (spec 001 RNF-04).
- The per-run random probe **token** guarantees reflection uniqueness but does not change
  *which* findings are produced.
- `fingerprint` is keyed on `check_id` + URL + method + parameter — **not** the payload or
  the page a form was found on — so re-runs and multi-page sites are stable (RNF-04).

### HTTP layer

**RF-15 — Verbs beyond `GET`**
- **Given** the injection engine (or form submission) needs a non-`GET` request, **when**
  it issues one, **then** it uses a new general `HttpClient` method (e.g.
  `request(method, url, *, params, data, json, headers)`), and the **scope guard, rate
  limiter, `timeout_s`, and manual redirect handling** apply exactly as for `get`.
- **Given** a `POST` (or any non-idempotent request), **when** it gets a `5xx` or a
  transient failure, **then** it is **not automatically retried on the `5xx`** (no
  double-submit); a connection error / timeout **before** the request is sent may be
  retried. `GET` retry behaviour is unchanged (spec 001 RF-05).
- **Given** a completed scan, **then** `HttpStats` counts crafted requests (surfaced in
  reports/tests like the existing counters).

### CLI

**RF-16 — Surface**
- **Given** `webvigil list-checks`, **then** every `injection.*` check appears with
  category `INJECTION`, mode `active`, and its default severity.
- **Given** `webvigil scan <url> --mode active --authorized-by "<text>"`, **then** the
  injection pass runs; **given** no `--mode active`, **then** it does not.
- **Given** `[checks] disabled = ["injection.sqli.time-based"]` (or any id), **then** that
  check does not run — same mechanism as every other check. **Given** every `injection.*`
  check is disabled, **then** the pass is skipped (RF-12).
- **Given** the config, **then** a small `[active]` surface tunes the pass (the exact keys
  are an Open question; candidates: `request_budget`, `time_based_sqli`,
  `max_injection_points`). `[active]` currently holds only `authorized_by`. New **CLI
  flags** are kept minimal — at most `--no-time-based-sqli`; the rest config-only (Open
  question).
- **Given** the human-readable summary (no `--format`) of an Active scan, **then** it
  includes a line such as `"Active scan: F injection finding(s) across P injection points,
  R crafted requests"`. A passive scan's summary is unchanged.

**RF-17 — Exit codes**
- `--fail-on <severity>` compares the new findings by severity exactly as today (spec 001
  RF-25). No new exit code; the injection pass hitting its budget is a warning, not an
  operational error.

### Reporting

**RF-18 — Reporters unchanged in shape**
- **Given** a completed scan, **then** `injection.*` findings render through the four
  existing reporters with **no new section and no new top-level array** (contrast spec
  004's `technologies`): JSON lists them among `findings` with `location.method` and
  `location.param` populated; SARIF emits one `rule` per `injection.*` id used, each
  finding a `result` with the URL + parameter in the location and the fingerprint in
  `partialFingerprints`; HTML and Markdown group them by severity like any other finding.
- **Given** an `injection.*` finding, **then** its `evidence` carries: the injection point
  (method + URL + parameter), the payload sent (trimmed), and the proof — the reflected
  snippet, the DBMS error, the `/etc/passwd` line, the timing delta, or the `Location`
  header — plus the baseline delta where the detector used one.
- **Given** a saved canonical JSON, **when** `webvigil report scan.json --format …` runs,
  **then** every format re-renders with no network request (spec 001 RF-24).

### Web API / Web UI

**RF-19 — Minimal amendment**
- **Given** a scan run through the Web API in Active Mode, **then** `injection.*` findings
  persist and are returned by `GET /api/scans/{id}` through spec 002's lossless finding
  persistence (RF-19) and schema (RF-25) — **no** migration, **no** schema change, **no**
  new field. `Location.method` / `Location.param` already round-trip.
- **Given** `GET /api/checks`, **then** the new checks appear with `category: "INJECTION"`
  (the field is already a string) and the dashboard's check catalogue lists them; the
  dashboard's category filter, derived from the returned data, gains `INJECTION`
  automatically with **no** component change and **no** `openapi.json` / `api-types.ts`
  regeneration.
- **Given** the dashboard's "new scan" form and scan-detail screen, **then** Active Mode
  and `authorized_by` are already supported (spec 002/003) — no change.
- **This is stated here so the design phase does not reopen it.** The expectation, to be
  confirmed in design, is that 006 touches the **engine + CLI only**. If a hardcoded
  category list or a category enum is found anywhere in `webvigil.api` or `web/`, 006
  updates that one spot; none is expected (verified: `api/routes/meta.py` returns
  `category` as `str`; `web/src/app/(app)/checks/page.tsx` derives the filter from data).

### Fixture app and tests

**RF-20 — Injectable surface in the fixture** (mirrors spec 001 RF-27, spec 004 RF-19,
spec 005 RF-13)
- **Given** the `tests/fixtures` app's **insecure** profile, **then** it serves, in
  addition to its current surface:
  - `GET /search?q=…` — echoes `q` **unescaped** into the HTML body (reflected XSS,
    executable context) and also renders a `<form method="get" action="/search">`.
  - `GET /item?id=…` — backed by a tiny in-memory **SQLite** table, with `id`
    **string-concatenated** into the query: a broken quote raises an `OperationalError`
    whose text reaches the response (error-based), `1=1` vs `1=2` change the row set
    (boolean-based), and a `SLEEP(n)` / `pg_sleep(n)` token is recognised and mapped to
    `await asyncio.sleep(n)` (time-based, simulated).
  - `GET /download?file=…` — opens `web_root / file` and returns its bytes, with a fixture
    `etc/passwd` reachable via `../` (path traversal).
  - `GET /go?next=…` — `302` to `next` with **no validation** (open redirect).
  - `POST /comment` — a `<form method="post">` that reflects its `body` field **unescaped**
    in the response (reflected XSS via POST) and carries a hidden token the fuzzer must
    preserve.
  - `POST /login` — a `<form method="post" action="/login">` with `username` / `password`
    that the fuzzer **must skip** (RF-04 heuristic).
- **Given** the **hardened** profile, **then** the equivalent endpoints parameterise the
  SQL, HTML-escape reflected values, validate the redirect target against an allow-list,
  and resolve `file` inside a jail (or simply return `404`) — yielding **nothing**.

**RF-21 — Integration tests**
- **Given** an Active scan (`--mode active`) of the insecure profile, **then**
  `injection.xss.reflected` (twice: `q` via GET and `body` via POST),
  `injection.sqli.error-based`, `injection.sqli.boolean-based`,
  `injection.sqli.time-based`, `injection.traversal.path`, and `injection.redirect.open`
  are all reported with the expected ids, severities, and `location.param` / `method`.
- **Given** a **passive** scan of the insecure profile, **then** **none** of the
  `injection.*` findings appear and no crafted request is issued.
- **Given** an Active scan of the **hardened** profile, **then** **zero** `INJECTION`
  findings (false-positive guard).
- **Given** any Active scan, **then** the `POST /login` form is **never submitted with a
  payload** — asserted via a request spy / the fixture's request log.
- **Given** an Active scan, **then** it is deterministic across repeated runs (same
  findings, same fingerprints) and stays within the request budget.

**RF-22 — Unit tests**
- Form parsing: action resolution (relative, empty, absolute, out-of-scope drop), method
  normalisation, hidden/token field preservation, `file`/`password` handling, the
  destructive-form exclusion heuristic (each keyword, plus a false-positive guard for an
  innocuous form).
- Injection-point enumeration: query-param extraction, form-field points, cross-URL dedup,
  the point cap + warning.
- Each detector against crafted responses: XSS contexts (body / attribute-break /
  `<script>` / `href` `javascript:` positive; entity-encoded / percent-encoded /
  `text/plain` / comment-only negative); DB error signatures for each of the five DBMS;
  boolean differential (clean positive; unstable-baseline negative; always-different
  negative); time-based (injected-delay positive; uniformly-slow negative; control scales);
  traversal signatures (`passwd` / `win.ini` positive; echoed-payload-only negative); open
  redirect (`Location` sentinel positive incl. protocol-relative and backslash; same-host
  negative).
- HTTP layer: `request("POST", …)` honours the scope guard and rate limiter; a `5xx` on a
  `POST` is **not** retried; a `GET` still is.
- The budget-cap warning and the point-cap warning.

### Documentation

**RF-23 — Docs**
- A new `docs/active-injection.md`: what Active Mode does now; the four classes, how each
  is detected, and each one's limits (no headless JS for XSS; three SQLi techniques and
  when each applies; traversal needs a readable known file; open redirect inspects
  `Location`, does not follow it); the injection-point model (query params + forms from
  crawled bodies); the request budget and per-point caps; the non-destructive posture and
  the exclusion heuristic **and its limits** (a login form named `/session` is not caught);
  why stored XSS, SSRF, and command injection are deferred.
- `docs/architecture.md` (the checks / crawler / http bullets), `docs/writing-checks.md`
  (a worked `ACTIVE` check: reading injection points, taking a baseline, drawing from the
  budget, the confirmation pattern — the counterpart to the existing passive example),
  `README.md`'s coverage table + an `--mode active` quick-start line, `CLAUDE.md`'s
  architecture summary + `Estado` line, and `specs/README.md`'s roadmap are updated; 006
  moves `draft → approved → in progress → done`. The roadmap note records that stored XSS
  and SSRF slipped from the `006` line to a later spec and why.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.checks.injection` (plus helper modules) with additions to
`webvigil.http` (verbs) and `webvigil.crawler` or the injection package (form parsing). It
imports nothing from `webvigil.cli`, `webvigil.api`, or `web/`. Detection uses the standard
library (`re`, `difflib`, `time`, `urllib.parse`); **no runtime dependency is added**. The
fixture app's SQLite endpoint uses stdlib `sqlite3` and lives under `tests/`. The
`import-linter` contract is unchanged (`webvigil.checks`, `webvigil.http`,
`webvigil.crawler` are already `source_modules`).

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy` covering the new
modules. **No** API migration test and — pending the RF-19 confirmation — **no** `web`
gate is expected. The Python `quality` matrix and the `docker` job are otherwise
unchanged, except the new profile-gated compose target (RF-24) which is not part of the
default `docker compose up`.

**RNF-03 — Safe by default**
A passive scan is byte-for-byte unchanged and issues no crafted request. The injection
pass runs only past the `--mode active --authorized-by` gate. Every crafted request is
in-scope, `GET`/`POST` only, bounded by the request budget and per-point caps, and
rate-limited. Time-based payloads are bounded and separately capped.

**RNF-04 — Determinism**
Per RF-14. Given the same target responses and payload sets, findings and fingerprints are
identical across runs; report ordering is stable.

**RNF-05 — False-positive discipline**
Per RF-13. Every detector confirms its signal (verbatim characters / real DBMS error /
confirmed differential / file signature / sentinel host) against a baseline; the hardened
fixture profile yields zero `INJECTION` findings.

**RNF-06 — Bounded work and runtime**
The active-request budget, the per-point payload cap, the injection-point cap, and the
time-based sleep bound together keep an Active scan's added request count and wall-clock
time predictable for a given site size. Hitting any cap is a scan warning, not an error.

**RNF-07 — Payload hygiene**
Payloads are a **small, static, well-known, documented set** shipped as versioned in-repo
data (no mutation/encoding engine, no WAF-evasion tuning). No payload is designed to write
persistent data. A `Finding`'s evidence snippet is bounded (spec 001's evidence trimming)
and carries only the proof marker, not an exploitation chain.

**RNF-08 — Python support**
Runs on CPython 3.12 and 3.13 (the existing CI matrix).

**RNF-09 — Docs**
Per RF-23. The state-changing nature of Active Mode and the exact scope of what 006 does
and does not test are stated explicitly, so a user is never surprised.

## Resolved decisions

Settled with Ryan on 2026-09-06:

1. **v0.6 vulnerability-class scope:** **four classes** — reflected XSS, SQL injection
   (error-based, boolean-based, time-based), path traversal / LFI, and open redirect. All
   detectable **in-band**, from the target's own responses, with no headless browser and no
   out-of-band collaborator. **Stored XSS** (needs a stateful re-fetch phase) and **SSRF**
   (needs an opt-in OAST collaborator, which conflicts with the "engine talks only to the
   target" principle) are **deferred to a later spec**. OS command injection / XXE / SSTI
   were never in the `006` line and stay out.
2. **Vulnerable target app:** **extend `tests/fixtures/app.py`** — the insecure profile
   gains injectable endpoints for all four classes plus a login form the fuzzer must skip;
   the hardened profile serves safe equivalents. A **profile-gated `docker-compose`
   service** runs the insecure app on a port for manual `--mode active` scans and demos,
   separate from the default `docker compose up`. Follows the spec 001 / 004 / 005 pattern
   of growing the one fixture app.
3. **Form / POST fuzzing posture:** fuzz **query parameters + `GET` forms + `POST`
   forms**. Exclude forms that look like authentication or destruction (login, logout,
   delete, password, register, checkout, …) by a documented keyword heuristic. Preserve
   hidden and anti-CSRF fields with their discovered values; submit but do not fuzz
   `file` / `password` inputs. Active Mode remains free to cause a benign state change
   (the spec 001 banner already warns); 006 does not claim otherwise.
4. **Consent model:** **no new gate.** Injection checks are `mode = ACTIVE` and reuse spec
   001's `--mode active --authorized-by` attestation and banner unchanged — the legal
   attestation gate is exactly what payload-bearing checks are for. (Contrast spec 005,
   whose GET-only probe got its own Safe-Mode opt-in flag.)
5. **Web API / Web UI:** **no amendment expected.** `injection.*` findings are ordinary
   `Finding`s and ride spec 002's lossless persistence and spec 003's existing findings
   view; the new `INJECTION` category flows through as a string and the dashboard's
   data-derived category filter picks it up. No migration, no `openapi.json` regen, no
   component change. Design confirms; if a single hardcoded category spot exists, 006
   updates it. 006 is an engine + CLI spec.

## Resolved during requirements (open questions, settled as proposed)

Approved with Ryan on 2026-09-06 ("aprovado com as propostas"). The design phase elaborates
the mechanics; these answers are fixed.

6. **Injection-engine shape (RF-12):** the **orchestrator-owned pass** model — an
   `InjectionScanner` (or equivalent) that enumerates points, takes baselines, owns the
   request budget, and exposes points + budget on `ScanContext`, consistent with spec 004's
   `Fingerprinter` and spec 005's `DisclosureProbe`. The six checks are thin detectors.
7. **`[active]` config + CLI surface (RF-16):** config keys `request_budget` (default
   ~500), `time_based_sqli` (default `true`), `max_injection_points` (default ~200),
   `time_based_delay_s` (default `5`). The only new CLI flag is
   `--time-based-sqli / --no-time-based-sqli`; everything else is config-only.
8. **Payload routing (RF-08–RF-11):** every in-scope injection point gets reflected-XSS +
   error-based SQLi + boolean SQLi payloads. Traversal, time-based SQLi, and open-redirect
   run **heuristic-prioritised** (preferred parameter names / value shape first) and then
   fill remaining budget breadth-first.
9. **Budget defaults (RF-03):** 500 crafted requests / scan, 30 payloads / injection point,
   200 injection points, 8 time-based sleeps / scan. Design validates the numbers against
   the fixture app's actual request count and may adjust with rationale.
10. **Form-parsing location (RF-05):** a `webvigil.crawler` `Form` model, populated from the
    already-fetched page bodies during `discover()` — **no new fetches**. The crawler owns
    "what the site exposes"; the injection package owns "what to do with it".
11. **Stored-XSS seam:** nothing structural now. The post-scan re-fetch phase is documented
    as the natural extension point in `docs/writing-checks.md`.

## Open questions

None. Ready for `/spec design`.
