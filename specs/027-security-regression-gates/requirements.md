---
feature: Security regression gates — failure injection with markers at every stage, every sensitive point inventoried by a test, and the hardening left from the 1.6.0 review
status: in progress
date: 2026-11-25
related:
  - 001-foundation/design.md
  - 002-web-api/design.md
  - 020-session-security/design.md
  - 024-secret-values/requirements.md
  - 025-safe-output/requirements.md
  - 026-destination-policy/requirements.md
origin: conception
---

# 027 — Security regression gates

## Context and problem

Specs `024` to `026` moved three classes of defect into one place each: credentials and session values are
a `Secret` (`024`), every output goes through `core/output.py` (`025`) and every destination decision goes
through `core/destination.py` (`026`). Each spec added a test that lists its own call sites and fails on a new
one outside the table (`ALLOWED_REVEALS`, `OUTPUT_SINKS`, `COMPARISONS` and `CONNECTIONS`).

Two kinds of regression are still not caught by the suite:

- **A failure nobody exercised.** The tests that plant a credential and look for it in every output (the
  canaries of spec `024`) run a scan that succeeds. The 1.6.0 defects
  ([GHSA-38gf-jvgw-g2pq](https://github.com/ryanvmorais/webvigil/security/advisories/GHSA-38gf-jvgw-g2pq) and
  [GHSA-jh8f-87gj-2mw7](https://github.com/ryanvmorais/webvigil/security/advisories/GHSA-jh8f-87gj-2mw7)) sat
  on error paths: a connection that failed, a body that could not be decoded, a database write that raised.
  A scan of the fixture application reaches none of them. A new pass or a new dependency adds error paths
  that no test reaches.
- **A sensitive point outside the three classes.** Text of an exception that becomes output, a project
  exception that carries a value from the site, and calls to dangerous operations (SQL, a command, code
  loading, deserialization, a file path, XML, a dynamic regular expression, HTML, a redirect, a network
  connection, cryptography) are not listed by any test. A new one is reviewed only if someone thinks of it.

Five behaviours left from the review of 1.6.0 are also fixed here:

- **The initial setup hashes a password outside the Argon2 ceiling.** Login allows four password checks at a
  time and answers `429` past that; the setup route, before the first account exists, does not count.
- **A trusted proxy's name is resolved by every request that finds the cache expired**, at the same time.
- **A request the dashboard forwards with a protocol upgrade keeps the client's `X-Forwarded-For` as it came.**
  The dashboard appends the connection's address to every ordinary request, not to an upgrade. The Web API has
  no WebSocket route and refuses such a request before any handler runs, so nothing reads the address today;
  a route added later would.
- **The crawler's `robots.txt` reading differs from RFC 9309 in three places:** a server error reads as "allow
  everything" (the RFC says to assume a complete disallow), a rule that ends in `?` never matches a URL that
  ends in `?`, and a file over the size limit is decoded as UTF-8 whatever its declared charset, unlike a
  smaller one.
- **The logout test (`--test-logout`) can pick a logout endpoint the scan's credentials do not reach.** Under
  `--scope subdomains`, a logout on a sibling subdomain is in scope, but the destination policy of spec `026`
  keeps the session cookies off it, so the logout cannot end the session and the test may report a session
  that was never asked to end.

**This spec adds a failure-injection suite that plants markers in every credential and every failure text and
fails each stage of a scan in turn, adds a test that inventories every sensitive point of the source, and fixes
the behaviours above.** It closes the hardening work after 1.6.0; what a scan reports does not change, except
where a requirement below says so.

### Where it sits

```
tests/                    the failure-injection suite, its table of stages, the sensitive-point inventory
src/webvigil/api/         the setup route under the Argon2 ceiling, the trusted-proxy lookup shared
web/src/server/           every forwarded request carries the connection's address
src/webvigil/crawler/     robots.txt as RFC 9309 reads it
src/webvigil/checks/      the logout test picks a logout the credentials reach
```

## Goals

- Every credential and every failure text carries a marker, every stage of a scan is failed in turn, and every
  output is searched for the markers, with a positive control for each search.
- A stage or an external dependency added without a row in the failure table fails a test.
- Every sensitive point of the source is listed by a test with the reason it is safe, and a new one fails the
  test.
- The setup route, the trusted-proxy lookup, the dashboard's forwarding, `robots.txt` and the logout test behave as
  the requirements below say.
- A scan of the same target sends the same requests and reports the same findings, apart from the changes
  above.

## Non-goals

- **Changing the rules of specs `024` to `026`.** What may be revealed, how an output is made safe and what each
  URL may receive stay as they are.
- **A fuzzer or random fault injection.** Each failure is chosen by a fixed rule, so a run can be repeated.
- **Mutation testing in CI.** It stays a step of each implementation, run in batch.
- **The dashboard's own failure paths.** The dashboard renders what the Web API returns; the suite searches the
  Web API's responses, and the dashboard's text functions keep the shared cases of spec `025`.
- **`robots.txt` caching and the RFC's 30-day rule.** A scan reads `robots.txt` once; there is no later request
  for the rule to apply to.
- **A new flag, configuration key or check.**

## Personas

- **As a maintainer**, I want a test to fail when a change lets a credential or a third-party error text reach
  an output on a path nobody exercised, so that a review does not depend on someone thinking of it.
- **As a contributor adding a pass or a dependency**, I want a table that tells me which failures to cover, and a
  test that tells me when I forgot.
- **As someone scanning a site I do not run**, I want the crawler to stop when the site's `robots.txt` answers
  with a server error, as a well-behaved crawler does.
- **As someone running the logout test under `--scope subdomains`**, I want no finding about a session the scan
  never asked to end.

## Functional requirements

### Failure injection

### RF-01 — Every credential and every failure text carries a marker

- **Given** the failure-injection suite
  **When** it configures a scan
  **Then** each credential holds a value of its own that appears nowhere else: each `[auth]` cookie, each
  `[auth]` header, a bearer token, the login password, the session cookies the target issues, and, for the Web
  API, the account password and the signing secret.
- **Given** a failure the suite injects
  **When** it is raised
  **Then** its text holds a marker of its own, control, bidirectional and zero-width characters, and more text
  than the bound of spec `025`.

### RF-02 — Every stage is failed in turn

- **Given** a table of the stages of a scan (the automated login, the OpenAPI and HAR imports, the crawl with
  `robots.txt` and the sitemaps, the address guard, the dependency fingerprint, the OSV lookup, the disclosure
  probe, the injection, stored XSS, envelope, upload, CSRF and session passes, the passive checks, the report
  writers) and of the Web API (the scan runner and the database)
  **When** the suite injects, at each stage, each kind of failure the table gives it (a refused or reset
  connection, a timeout, a server error, an undecodable body, an exception raised by a dependency, a file that
  cannot be read or written, a database statement that raises)
  **Then** the scan ends as the documentation says: the CLI writes a result with a warning or an error line and
  exits with a documented code, with no traceback on the terminal; the Web API marks the scan `failed` or
  `completed` with its error bounded.
- **Given** the same configuration run twice
  **When** the suite chooses which request or call fails
  **Then** it chooses the same one both times.

### RF-03 — No credential reaches an output, in any form

- **Given** each run of RF-02
  **When** the suite searches every output: the standard output and error, every log record of the engine and
  the Web API at every level, the JSON, SARIF, HTML and Markdown reports, every Web API response body and
  header, and every database row
  **Then** no credential marker is found, written as it is, percent-encoded (both forms), escaped for JSON or
  HTML, as Python `repr`, or in base64.

### RF-04 — Failure text reaches only the outputs that may carry it

- **Given** a failure marker from RF-01
  **When** it is found in an output
  **Then** that output is one the inventory of RF-07 declares may carry the text of that failure, and there the
  text is cut at its bound and its control, bidirectional and zero-width characters are shown as escapes.
- **Given** a failure raised by a third-party library on a path that holds a credential
  **When** the scan reports it
  **Then** the output names the kind of failure in the project's own words, and no part of the library's
  message appears.

### RF-05 — Every search has a positive control

- **Given** each search of RF-03 and RF-04
  **When** the run ends
  **Then** the same search finds each credential marker in the requests the fixture received (the credential
  did reach the target), and finds each failure marker in the failure as it was raised, so a search that could
  never find anything fails.
- **Given** a stage of the table
  **When** its failure is injected
  **Then** the suite checks that the failure was raised (the stub was called), so a stage the scan skipped does
  not pass.

### RF-06 — A new stage joins the table

- **Given** the passes the orchestrator runs and the external dependencies the engine and the Web API use
  (network clients, files read and written, the database)
  **When** one is added without a row in the failure table
  **Then** a test fails and names it.

### The inventory

### RF-07 — Every sensitive point is inventoried

- **Given** the source of `webvigil` (`src/webvigil`, read as Python syntax trees) and of the dashboard
  (`web/src`, read by text patterns)
  **When** a test lists every place where an exception's text becomes output, every project exception whose
  message carries a dynamic value, and every call to a dangerous operation (SQL, a command, code evaluation or
  loading, deserialization, a file path, XML, a dynamic regular expression, HTML, a redirect, a network
  connection, cryptography)
  **Then** each one is in a declared table, keyed by module and function, with the reason it is safe; a point
  with no line fails the test, a line with no point left fails it, and a line with an empty reason fails it.
- **Given** a throwaway source with one point of each family
  **When** the same walk runs over it
  **Then** it finds every one, so a walk that stopped seeing a family cannot pass.

### Hardening

### RF-08 — The initial setup counts toward the Argon2 ceiling

- **Given** no account yet
  **When** setup requests arrive while the Argon2 checks allowed at the same time are all taken
  **Then** the extra requests get `429` with `Retry-After`, as a login does, and no account is created by them.
- **Given** a free slot
  **When** a setup request arrives
  **Then** it creates the account as today, and only one account is ever created.

### RF-09 — A trusted proxy's name is resolved once at a time

- **Given** a name in `web.trusted_proxies` whose cached addresses have expired
  **When** several requests need them at the same time
  **Then** one lookup runs, and the other requests use its answer.
- **Given** a lookup that fails
  **When** the requests that waited for it go on
  **Then** they treat the connection as not coming from a trusted proxy, as today.

### RF-10 — Every request the dashboard forwards carries the connection's address

- **Given** the dashboard's server in front of the Web API
  **When** it forwards a request to `/api/*` that asks for a protocol upgrade, such as a WebSocket handshake
  **Then** the `X-Forwarded-For` the API receives ends with the address of the connection, as for an ordinary
  request, or the dashboard refuses the request without forwarding it.
- **Given** an ordinary request
  **When** the dashboard forwards it
  **Then** the header is built as today.

### RF-11 — A `robots.txt` server error stops the crawl

- **Given** `follow_robots` on (the default)
  **When** `robots.txt` answers with a `5xx` status after the client's retries, or cannot be fetched because of
  a network error
  **Then** the crawler fetches the target URL and no other URL from its queue, and the result carries a warning
  that says `robots.txt` could not be read and how to turn `follow_robots` off.
- **Given** a `robots.txt` that answers `4xx`, is missing or is empty
  **When** the crawl runs
  **Then** every URL is allowed, as today.

### RF-12 — `robots.txt` rules match as RFC 9309 says

- **Given** a rule whose path ends in `?`
  **When** the crawler asks about a URL with the same path followed by `?` and an empty or non-empty query
  **Then** the rule matches; it does not match the same path with no `?`.
- **Given** a `robots.txt` larger than the size limit with a declared charset
  **When** it is read
  **Then** the part within the limit is decoded as a smaller file with the same charset is, cut at its last
  complete line.

### RF-13 — The logout test uses only a logout the credentials reach

- **Given** `--test-logout` and a logout endpoint (configured, linked or a form) at a URL that may not carry the
  scan's credentials, such as a sibling subdomain under `--scope subdomains`
  **When** the session pass chooses the logout
  **Then** that endpoint is not used; with no other, the test is skipped with its warning, and no
  `session.logout.not-invalidated` finding is reported.
- **Given** a logout endpoint at a URL that may carry the credentials
  **When** the test runs
  **Then** it behaves as today.

### RF-14 — Same scan, same requests

- **Given** the fixture application scanned with the same configuration (anonymous, with `[auth]` cookies and
  headers, with the automated login and the session tests, and with `--scope subdomains`), before and after
  this spec
  **When** the requests the fixture received and the JSON reports are compared, leaving out timestamps and
  durations
  **Then** the requests are byte for byte the same, and findings, severities, check ids, fingerprints, warnings
  and `schema_version` are identical.

### RF-15 — Tests

See the test strategy in the design. The suite must cover:

- the failure-injection runs of RF-02 to RF-05 over the whole table, with their positive controls;
- the table check of RF-06, with a positive control that an unlisted stage fails it;
- the inventory of RF-07 over the source and over the throwaway source;
- the setup ceiling (RF-08) with the slots held, with a positive control that a setup with a free slot creates
  the account;
- concurrent lookups of one expired proxy name (RF-09), with the resolver stubbed and its calls counted;
- an upgrade request through the dashboard's server (RF-10), with a positive control that an ordinary request
  gets the connection's address;
- each `robots.txt` case of RF-11 and RF-12, with a positive control that a `200` file with no rule lets the
  queue through;
- the logout choice of RF-13, with a positive control that a logout on the target's origin is still used.

## Non-functional requirements

### RNF-01 — No new dependency

The suite, the inventory and the fixes are written on the standard library and the dependencies the project
already has.

### RNF-02 — A minor release

The change fits a minor release under [`docs/stability.md`](../../docs/stability.md): commands, options,
configuration keys, check ids, exit codes, the report schema and fingerprints do not change. The `robots.txt`
rules, the setup `429` and the dashboard's forwarding of an upgrade are listed under **Changed** in the
CHANGELOG, and the logout choice under **Fixed**.

### RNF-03 — The engine boundary

The fixes in the engine import nothing from the CLI or the Web API; the `import-linter` contract keeps passing.

### RNF-04 — No measurable cost on a scan

A full scan of the fixture application takes no measurably longer.

### RNF-05 — Every step leaves `main` working

The work lands in independent pull requests, each with the full CI green.

### RNF-06 — The suite stays fast and offline, and its guards are proven

No test talks to the real network or the real resolver, and no injected failure waits out a real timeout or
backoff. The whole suite keeps running in under 2 minutes with coverage; the failure-injection suite runs
within a budget the design sets. Per-file line and branch coverage of `src/webvigil` does not drop. Every new
test is seen failing once. Every changed guard goes through mutation testing in batch: every changed function
has a killed mutant, every surviving mutant is triaged, and the score goes in the pull request.

## Resolved decisions

1. **The inventory is a test in the style of the three that exist (decision of 2026-11-25).** A table keyed by
   module and function, with a reason per line, reads well in a review and fails the same way as
   `OUTPUT_SINKS`; it needs no tool outside the repository.
2. **A `robots.txt` server error stops the crawl (decision of 2026-11-25).** RFC 9309, section 2.3.1.4, tells a
   crawler to assume a complete disallow when the file is unreachable because of a server or network error. The
   target URL the user gave is still fetched, as it is today with a disallow-all file, and the warning says how
   to scan without `robots.txt`.
3. **Failures are chosen by a fixed rule, not at random.** A failure that shows up only on some runs cannot be
   bisected or proved fixed.
