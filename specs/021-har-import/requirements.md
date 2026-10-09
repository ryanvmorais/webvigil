---
feature: HAR import — seed the crawl and the injection points of a single-page application from recorded browser traffic
status: done
date: 2026-10-09
related:
  - 006-active-injection/requirements.md
  - 013-auth-and-api-surface/requirements.md
  - 018-post-form-crawl/requirements.md
origin: conception
---

# 021 — HAR import

## Context and problem

WebVigil's crawler reads HTML and runs no JavaScript. A single-page application (SPA) is, to it, a
near-empty shell: the entry document carries a `<script>` and an empty `<div id="root">`, and every
route, every API call and every form is built in the browser. The 1.0 benchmark measured what that
costs (`docs/benchmark.md`): OWASP Juice Shop scanned unaided gave **1 page and no application
finding**, while the same scan seeded with five routes through `--openapi` gave **22 pages and a SQL
injection**. The gap is *surface discovery*, not detection. 1.0.0 only **warns** when the entry page
looks like a JavaScript app (`script_app_warning`); it gives the user nothing to do about it unless the
application publishes an OpenAPI document, and most SPAs do not.

A browser already knows the surface. A person who opens the application, logs in and clicks through it
produces exactly the list of requests the scanner is missing, and every browser and intercepting proxy
can save that list as a **HAR file** (HTTP Archive, JSON). Importing it is the same move spec 013 made
for OpenAPI: turn a description of the surface into seeds for the crawl and points for the injection
pass.

Why HAR and not something heavier. A headless browser (`webvigil[browser]`) would discover routes by
itself, but it is a large dependency with its own security surface and its own spec; mining routes out
of the JavaScript bundles is heuristic and lossy. Both are parked (issue #146). HAR import adds **no
dependency** (the format is JSON), covers **authenticated flows** (the person logged in while
recording), and keeps the property the project is built on: **the engine talks only to the target**.
It sends no request of its own while importing, because the file is local.

**This spec covers a `--har` seed source for the crawl and the injection pass, reusing the mechanism of
`--openapi`.** It is a minor feature (1.1); it changes no check, no report field and no default.

### Where it sits

```
webvigil.core.config           [scan] har                 (str: a local .har / .json path)
                               [scan] har_max_operations  (int, default 150)
webvigil.cli                   --har PATH
webvigil.crawler.har (new)     load_har(path, target, max_operations) -> (list[ApiOperation], warnings)
                               HarError (webvigil.core.errors)
webvigil.core.orchestrator     _load_har(...) next to _load_openapi(...): both lists are merged
                               before the crawl; GET operations -> Crawler(extra_seeds=...),
                               POST operations -> Crawler(post_operations=...) (spec 018),
                               all operations -> enumerate_points(operations=...) (spec 013)
webvigil.checks.injection      InjectionPoint(source="har")   (a source, like "openapi")
```

The importer returns the same `ApiOperation` records the OpenAPI importer returns, so the crawler, the
`POST` phase and the injection enumerator need no new code path for a HAR beyond the new `source`.

## Goals

- `--har traffic.har` (and `[scan] har`) seeds the crawl and the injection points from the traffic a
  browser recorded.
- A HAR written by Chrome, Edge, Firefox, Safari, Burp Suite, OWASP ZAP or mitmproxy loads, without
  the user converting it.
- It **never sends anything on its own**: the import reads a local file. What reaches the target is
  what the crawler and the injection pass already send, under the gates they already have.
- **What the file holds in secret stays out of every output.** Cookies, `Authorization` and every other
  header, and the value of any parameter that looks like a secret, are never copied into a finding, a
  report, the metadata, a warning or a log line.
- A scan with a HAR and one without behave the same everywhere else.

## Non-goals

- **Running JavaScript or driving a browser.** No headless browser, no `webvigil[browser]`; that is
  its own spec, later.
- **Recording.** WebVigil does not proxy traffic or write HAR files; the user records with the tool they
  already have.
- **Mining the recorded responses.** The importer reads the *requests*. It does not parse recorded HTML
  or JSON bodies for further links or routes.
- **WebSocket frames, Server-Sent Events, GraphQL schema or operation fuzzing.** A recorded GraphQL
  `POST` is a `POST` with a JSON body like any other (RF-06); nothing is fuzzed inside the query.
- **Methods other than `GET` and `POST`.** `PUT`, `PATCH`, `DELETE`, `OPTIONS` and `HEAD` entries are
  not acted on (the injection pass fuzzes `GET` and `POST` only, spec 006), exactly as for `--openapi`.
- **Templating path segments.** `/rest/products/42/reviews` is one literal URL; WebVigil does not guess
  that `42` is a parameter (resolved decision 4).
- **A URL as the source, an upload, or the Web API / dashboard.** The source is a path on the machine
  that runs the scan. The Web API does not accept it (RF-12).
- **Fuzzing the leaves of a JSON body.** A limit of spec 013 that stays.

## Personas

- **As a developer of a single-page application**, I want to browse my app once, export the traffic and
  run WebVigil on it, so that the scan reaches the API behind the JavaScript and not just the empty
  shell.
- **As a security engineer with an intercepting proxy**, I want to hand WebVigil the history I already
  captured while testing by hand, so that the automated pass covers the routes I walked.
- **As a reviewer of a scan report**, I want to be sure that importing a recording cannot put the
  session or the credentials of whoever recorded it into a report that gets shared.

## Functional requirements

### RF-01 — The source: `--har` and `[scan] har`

- **Given** `--har traffic.har` (or `[scan] har = "traffic.har"`) naming a readable file
  **When** the scan starts
  **Then** the file is parsed into operations **before the crawl**, in the same step as an `--openapi`
  document.
- **Given** both `--har` and `--openapi`
  **When** the scan starts
  **Then** both are loaded and their operations are merged (de-duplicated by method, URL template and
  parameter names, the OpenAPI one winning on a tie); neither replaces the other.
- **Given** a value that is not a local path (it contains `://`)
  **When** the scan starts
  **Then** it fails with a `HarError` that says the source must be a local file.
- **Given** a path that does not exist, or a directory
  **When** the scan starts
  **Then** it fails with a `HarError` naming the path, before any request is sent.

### RF-02 — The format

- **Given** a JSON document with `log.entries` as in HAR 1.1 / 1.2 (UTF-8, a byte-order mark tolerated),
  as exported by Chrome / Edge / Firefox / Safari DevTools, Burp Suite, OWASP ZAP or mitmproxy
  **When** it is loaded
  **Then** each entry's `request` (`method`, `url`, `queryString`, `postData`) is read. The `response`
  is consulted only for its `content.mimeType`, to recognise a static asset (RF-04); `timings`, the
  response bodies and `cookies` are never read. An entry with a missing or malformed `request` is
  skipped and counted, not fatal.
- **Given** a file that is not valid JSON, or JSON without `log.entries`
  **When** it is loaded
  **Then** it fails with a `HarError` ("not a HAR file") — fatal, because the user asked for it
  explicitly, like an unreadable `--openapi` document (exit code `4`, operational).
- **Given** a valid HAR with no usable entry after filtering
  **When** it is loaded
  **Then** the scan continues with a warning, as it does for an OpenAPI document with no operations.

### RF-03 — Scope: only the target is ever a seed

- **Given** an entry whose URL is outside the target's scope (`Target.in_scope`: the exact host, or the registrable
  domain and its subdomains under `--scope subdomains`)
  **When** the file is imported
  **Then** the entry is ignored, no request is ever made to that URL, and the count is reported once in
  the summary line (RF-11). Analytics, fonts, CDNs and third-party APIs are the usual case.
- **Given** an entry whose URL is not `http` or `https` (`ws:`, `wss:`, `data:`, `chrome-extension:`,
  `blob:`)
  **When** the file is imported
  **Then** it is ignored and counted.

### RF-04 — What becomes a seed

- **Given** an in-scope `GET` or `POST` entry for a document or an API call (an `xhr` / `fetch` / document
  request)
  **When** the file is imported
  **Then** it becomes an operation.
- **Given** an in-scope entry for a **static asset** — an image, a font, audio or video, a stylesheet, a
  script or a source map (judged by the browser's `_resourceType` when the file has it, else by the
  response `mimeType`, else by the URL extension)
  **When** the file is imported
  **Then** it is not an operation (the crawler already finds the scripts a page references, and the
  fingerprint pass reads them) and it is counted as static.
- **Given** an in-scope entry with any other method
  **When** the file is imported
  **Then** it is ignored and counted by method.

### RF-05 — The shape of an operation, and de-duplication

- **Given** `GET /rest/products/search?q=apple&limit=10`
  **When** it is imported
  **Then** the operation is `GET` on that path with the query parameters `q` and `limit` in order of
  appearance, and the crawl later requests that URL (path **and** query), because an SPA endpoint often
  answers nothing without its parameters.
- **Given** the same method, path and set of parameter *names* recorded many times with different
  values
  **When** it is imported
  **Then** it is one operation, and the first recorded values are the ones kept.
- **Given** the same file and the same configuration
  **When** it is imported twice
  **Then** the operations come out in the same, stable order (RNF-03).

### RF-06 — Injection points

- **Given** an operation with query parameters
  **When** the injection pass enumerates its points
  **Then** each parameter is an `InjectionPoint` with `source="har"`, de-duplicated by the point's key
  with the points the crawl found by itself (a parameter both the crawl and the HAR know is one point).
- **Given** a recorded `POST` whose body is `application/x-www-form-urlencoded` or `multipart/form-data`
  (text parts only)
  **When** the injection pass enumerates its points
  **Then** each text field is a point; a file part is not.
- **Given** a recorded `POST` whose body is JSON
  **When** it is imported
  **Then** the operation carries the body's **shape** (keys and value types) for the `POST` crawl phase
  to submit (RF-08, resolved decision 2), and no leaf of it is fuzzed.

### RF-07 — Secrets never leave the file

- **Given** any request header in an entry — `Cookie`, `Authorization`, `Set-Cookie`, `X-API-Key`,
  `X-CSRF-Token`, any other
  **When** the file is imported
  **Then** none of them is read into an operation, sent to the target, logged, or written into a
  finding, evidence item, report, scan metadata or warning. `request.cookies` and
  `response.cookies` are not read either.
- **Given** a query or body parameter whose name looks like a secret (`token`, `access_token`, `key`,
  `api_key`, `secret`, `password`, `passwd`, `auth`, `session`, `sid`, `jwt`, `signature`, `otp`, in
  any case and with `_` / `-` as breaks)
  **When** the file is imported
  **Then** the parameter name is kept (it is still an injection point) and its **value** is replaced
  by a placeholder, so the recorded secret never appears in a finding's location or evidence.
- **Given** a value longer than 256 characters
  **When** the file is imported
  **Then** it is replaced by a placeholder as well (a blob is not a parameter value worth replaying).

### RF-08 — Authenticated flows

- **Given** a recording made while logged in
  **When** it is imported
  **Then** the routes and parameters of the logged-in application are seeds, because the importer reads
  every request regardless of the session that made it.
- **Given** the same scan
  **When** the crawl requests those seeds
  **Then** it does so with the credentials the scan was **configured** with (`--cookie`, `--header`,
  `--login-url`), never with the ones in the file (resolved decision 1).
- **Given** a recording whose entries carried a `Cookie` or an `Authorization` header and a scan
  configured with none of `--cookie`, `--header` or `--login-url`
  **When** the file is imported
  **Then** one warning says that the recording looks authenticated and the scan is not, and names the
  three options. The warning carries no value, no cookie name and no header name.

### RF-09 — Unsafe operations are skipped

- **Given** a recorded request whose path looks like authentication or a state-changing action
  (`login`, `logout`, `register`, `password`, `delete`, `remove`, `checkout`, `pay`, `unsubscribe` ...
  the vocabulary `--openapi` already uses)
  **When** the file is imported
  **Then** it is not an operation and it is counted as skipped. A person who recorded a purchase does
  not make WebVigil place another one.

### RF-10 — Mode gates are unchanged

- **Given** a scan in any mode with `--har`
  **When** the file is imported
  **Then** no request is sent by the import; the `GET` operations are requested by the crawl exactly as
  `--openapi` ones are, in Passive Mode too.
- **Given** a Passive scan whose HAR contains `POST` operations
  **When** the scan runs
  **Then** no `POST` leaves the scanner. The `POST` operations are submitted only by the `POST` crawl
  phase (`--mode active --authorized-by` **and** `--submit-post-forms`, spec 018), with its caps and its
  `robots.txt` rule, and fuzzed only by the injection pass in Active Mode (spec 006).

### RF-11 — Caps and the summary line

- **Given** a HAR that yields more operations than `[scan] har_max_operations` (default 150)
  **When** it is imported
  **Then** the first operations in stable order are kept and a warning says how many were dropped.
- **Given** a HAR larger than the size cap, or with more entries than the entry cap
  **When** it is loaded
  **Then** a file over the size cap fails with a `HarError`, and entries past the entry cap are ignored
  with a warning (RNF-02).
- **Given** any scan with `--har`
  **When** the import finishes
  **Then** one summary warning reads like `HAR import: 212 entries read, 41 operations seeded (30 GET,
  11 POST); ignored: 118 other host, 31 static, 14 other method, 6 unsafe, 2 malformed`, so "no
  finding" can be told apart from "never imported".

### RF-12 — Configuration, CLI and the Web API

- **Given** `[scan] har` and `[scan] har_max_operations` in the TOML file
  **When** the configuration is loaded
  **Then** they are validated like the `openapi` keys, `--har` overrides `[scan] har`, and
  `webvigil.example.toml` documents both.
- **Given** the Web API's scan request
  **When** a client sends a `har` field (or any path to be read)
  **Then** it is not accepted: the path would be read from the server's disk by a remote caller. The
  scan request schema does not expose `har`, as it does not expose `openapi`.

### RF-13 — The JavaScript-app warning points to it

- **Given** an entry page that looks like a JavaScript application (the existing `script_app_warning`)
  and no `--har` and no `--openapi`
  **When** the scan finishes
  **Then** the warning, which today only suggests `--openapi <file>`, also names `--har <file>` and says
  in a few words how to get one (browse the app with the browser's network panel open and save the
  traffic as HAR).

### RF-14 — Tests

See the test strategy in the design. The suite must cover: the parser on HAR files from each of the
tools in RF-02 (trimmed, real-shaped); every filter of RF-03 / RF-04 / RF-09; the secret rules of RF-07
on an adversarial file (a session cookie, a bearer token, a `?token=` in a URL, a password in a body);
the gates of RF-10 (Passive sends no `POST`; a foreign host is never requested); the merge with
`--openapi`; the caps; and the Web API refusal of RF-12. Integration attaches to the shared scan of
`tests/integration/test_scan_fixture_app.py` (`specs/README.md`, "Testes de uma spec").

## Non-functional requirements

### RNF-01 — No new dependency

HAR is JSON; the importer uses the standard library. `pyproject.toml` is unchanged, and the engine
layering holds: `webvigil.crawler.har` imports nothing from `webvigil.checks` (import-linter).

### RNF-02 — Bounded on a hostile file

A HAR can come from a third party (a colleague, a bug report). Reading it must not take unbounded
memory or time: a size cap on the file (a `HarError` over it), a cap on the entries read, a cap on the
length of every string kept, a cap on the depth of a JSON body shape, and a `HarError` (not a crash) on
JSON that is too deeply nested to parse. The caps are tuned defaults in the sense of
`docs/stability.md`.

### RNF-03 — Deterministic

The same file and configuration give the same operations in the same order and the same warnings. No
randomness; placeholders are fixed per type, as for `--openapi`.

### RNF-04 — The engine talks only to the target

No request is made to a host the scope guard does not allow, and the importer makes none at all. The
file's contents never choose a destination other than through the target's own scope rule.

### RNF-05 — Secrets stay out

RF-07 holds for every output channel: findings, evidence, the four report formats, scan metadata, the
warnings, the log, and the Web API's stored rows. A test feeds a file full of recognisable secrets and
asserts that none appears in any output.

### RNF-06 — Backward compatible

New optional keys and one new option; defaults and the JSON `schema_version` are unchanged; a scan
without `--har` is byte-for-byte what it was. This is a minor release (`docs/stability.md`).

### RNF-07 — Test budget

About one line of test per line of `src/` added, and the whole suite stays within the ~10 minute budget
of `specs/README.md`.

## Resolved decisions

Settled at the requirements gate (2026-10-09), each as recommended in the draft. The design builds on
them; they are cited by number.

1. **Routes, not the session (was OQ-1).** The importer reads the routes and parameters a logged-in
   recording shows. It never lifts a `Cookie` or `Authorization` from the file; the scan authenticates
   with `--cookie`, `--header` or `--login-url`, and warns when the recording looks authenticated and
   the scan is not (RF-08).
2. **Recorded values (was OQ-2).** The recorded value of a query or form-encoded parameter is kept as
   the baseline, except for a secret-named parameter or a blob (RF-07). A JSON body is imported as its
   shape only, with typed placeholders (RF-06).
3. **One file (was OQ-3).** A single `--har` in 1.1; `[scan] har` stays a string so it can accept a
   list later without breaking a string value.
4. **No path templating (was OQ-4).** `/rest/products/42/reviews` is one literal URL in 1.1. Revisit
   with the benchmark repeat (issue #148).
5. **Caps (was OQ-5).** File 64 MiB, 20,000 entries read, 150 operations (`[scan] har_max_operations`),
   256 characters per kept string.
