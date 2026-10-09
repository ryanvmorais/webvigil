# Changelog

All notable changes to WebVigil are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/); what that promises is in
[docs/stability.md](docs/stability.md).

The `v0.1` to `v0.20` milestones in the README are the steps the project was built in, each
designed as a spec under [`specs/`](specs/). None of them was released: `1.0.0` is the first
release and contains all of them.

## [Unreleased]

### Added

- `csrf.form.state-change-over-get` (`MEDIUM`, CWE-352 and CWE-650), a passive check for a `GET` form that
  changes state ([#144](https://github.com/ryanvmorais/webvigil/issues/144)). `csrf.form.no-token` reads
  `POST` forms only, so the CSRF module of OWASP DVWA, which changes the password with a `GET` form, went
  unreported. The check flags a `GET` form with no anti-CSRF token field that has two password inputs (or
  one named like the new, confirmed or old password), or a destructive verb in its action, its field names
  or its submit label. Search, login, registration and logout forms are left out, and nothing is submitted.
  Confidence is `MEDIUM` at most and `SameSite=Lax` does not lower it, because a `Lax` cookie is sent when
  a cross-site link is followed. A scan that finds such a form now reports it, so `--fail-on` can see it.

### Fixed

- The Web API serves every report with `X-Content-Type-Options: nosniff`, and the HTML report also with
  `Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'`
  ([#163](https://github.com/ryanvmorais/webvigil/issues/163)). `GET /api/scans/{id}/report?format=html&download=false`
  shows the report inline from the API's own origin, built from what the scanned site sent. The template
  escapes it, so nothing was known to be wrong, but no header would have contained a mistake. The report
  keeps rendering (it is one self-contained file with an inline `<style>`), and the dashboard's preview,
  which frames a `blob:` in a sandboxed iframe, is not affected.
- The Web API refuses a state-changing request from another origin
  ([#162](https://github.com/ryanvmorais/webvigil/issues/162)). `POST /api/auth/logout` and
  `POST /api/scans/{id}/cancel` change state with no body, so a page on another port of the same host
  (the same site, so the `SameSite=Lax` cookie goes with it) could send them without a preflight, and the
  API never looked at `Origin`. A `POST`, `PUT`, `PATCH` or `DELETE` whose `Origin` is present and is
  neither the server's own (its `Host`, or the dashboard proxy's `X-Forwarded-Host`) nor listed in
  `web.cors_origins` now gets a `403`. A request with no `Origin` (curl, the CLI) is unaffected, and so
  is the bundled dashboard.
- A reference is a link only when it is an `http(s)` URL
  ([#161](https://github.com/ryanvmorais/webvigil/issues/161)). The references of a finding became
  `<a href>` in the HTML report and in the dashboard as they were, and the ones from the opt-in OSV
  lookup (`--osv-online`) are copied from an advisory record, so a `javascript:` or `data:` URL in one
  would have been a link. The OSV provider now keeps only absolute `http(s)` URLs (so the JSON, SARIF and
  Markdown reports no longer carry anything else), and the HTML report and the dashboard check the scheme
  again and show any other value as plain text.
- The Markdown report no longer writes what the scanned site sent as Markdown or HTML
  ([#172](https://github.com/ryanvmorais/webvigil/issues/172)). A title with a path or a parameter name,
  the label and content of an evidence item, a description, a library name or a check error went into the
  file as they were, so a fence in the evidence closed the block early and markup in a title or a label
  reached the renderer. Those values are now plain text: the Markdown and HTML metacharacters are escaped,
  a line break cannot start a new block, and the evidence is fenced (and an inline code span delimited)
  with a run of backticks longer than any run inside it. Code spans that a check writes itself
  (`` `integrity` ``) are kept, so an ordinary report reads as before; the one visible change is a bare
  `<tag>` in a remediation, which a renderer used to swallow as HTML and is now shown. The JSON, SARIF and
  HTML reports are unchanged.
- A `POST` form that is only a button is now part of the form inventory
  ([#145](https://github.com/ryanvmorais/webvigil/issues/145)). The parser dropped every form with no
  named field, so the "Generate" button of OWASP DVWA's weak-session-ID module never reached the `POST`
  crawl and `session.id.weak` found nothing there. Such a form is now kept, with the label of its
  buttons, and `--submit-post-forms` submits it (an empty body, as a browser sends an unnamed button).
  The label of a button, including the text of a `<button>`, now also feeds the destructive-form filter,
  which closes the documented gap of a "Delete" that lived only in a `<button>`. Side effect: the passive
  `csrf.form.no-token` check now also sees a `POST` form made only of a button, and reports it when it
  has no token.
- `injection.cmdi.os` no longer reports command injection on an endpoint that only echoes its input
  ([#177](https://github.com/ryanvmorais/webvigil/issues/177)). The Windows `set /a` proof looked for the
  product of the two random operands in the text that starts at the random marker, so the digits of the
  product could appear inside the marker by chance (about one scan parameter in a thousand). The product
  now has to be printed after the marker, as a whole number, and not be on the baseline page already.
- `injection.sqli.boolean-based` no longer misses a blind SQL injection on a form whose field ships empty,
  or whose "no such row" page is the site's own layout with a different status
  ([#143](https://github.com/ryanvmorais/webvigil/issues/143)). The OWASP DVWA module was the case: an
  empty `id` matches no row, so the `TRUE` and `FALSE` payloads answered the same page, and with a real
  `id` the two pages differed by a few bytes (a `200` and a `404`). The detector now repeats the pairs on a
  seeded value when the field is empty and the seed changes the page, and counts a status-class split as
  the difference when the body is otherwise the same. Both are confirmed against the baseline as before; a
  split that rests on the status alone is reported with `MEDIUM` confidence instead of `HIGH`.

## [1.0.4] - 2026-10-08

A patch release with one fix, in how much of what the scanned site declares the crawl keeps.
Nothing in the CLI, the exit codes, the configuration keys, the check ids or the JSON report changes.

### Security

- A `robots.txt`, a sitemap or a page served by the scanned site can no longer keep a scan busy for a
  long time or make it use a lot of memory (GHSA-63j8-4f3v-r77j). The crawl read every sitemap that `robots.txt`
  declared and kept every distinct link and form a page carried; it now reads at most 20 sitemaps and
  10,000 sitemap URLs, 20,000 links per page, 500 forms per page and 1,000 controls per form, and keeps
  at most 2,000 forms and a bounded set of URLs seen. The pages fetched do not change while `max_pages`
  is within those limits, and a scan warning says when one was reached.

## [1.0.3] - 2026-10-08

A patch release with one fix, in the patterns and the size limits that read what the scanned site sends.
Nothing in the CLI, the exit codes, the configuration keys, the check ids or the JSON report changes.

### Security

- A page, a script or an API description served by the scanned site can no longer keep a scan busy for a
  long time or make it use a lot of memory (GHSA-7cmg-mh2g-8rwv). The patterns of the library fingerprint
  (which run in the default Safe Mode), of the Active Mode signatures and body comparison, and of the
  host-header, `TRACE` and CSRF-confirmation passes are bounded, and they read the first 256 KiB of a body
  or script. The OpenAPI import caps the size of the request bodies it builds from a schema. A library
  marker or a framework message that appears only after the first 256 KiB of a body is no longer
  recognised, and a request body for a very large schema is cut short.

## [1.0.2] - 2026-10-08

A patch release with one fix, in the error-page signatures of the information-disclosure check.
Nothing in the CLI, the exit codes, the configuration keys, the check ids or the JSON report changes.

### Security

- A response from the scanned site can no longer keep a scan busy for a long time in the error-page
  signatures (GHSA-wxvq-cw49-p7f6): the patterns for the Java, Node.js and Python stack traces and for the
  Django and Rails debug pages are bounded, and the signatures read the first 256 KiB of a body. A
  framework error that appears only past that point is no longer recognised.

## [1.0.1] - 2026-10-08

A patch release: it fixes the Web API and lifts the `selectolax` cap. Nothing in the CLI, the
exit codes, the configuration keys, the check ids or the JSON report changes.

### Changed

- The engine parses HTML with the Lexbor backend of `selectolax` (`selectolax.lexbor`) instead of the Modest
  one that `selectolax` 1.0 removed, so the `selectolax<1` cap is gone (`selectolax>=1.0.0,<2`) and
  Dependabot can keep it current. Lexbor follows the HTML5 parsing rules and returns a form's fields in
  document order, as a browser sends them, so the parameters of a crawled form can be listed in a different
  order. On the bundled test app a full Active scan gives the same findings; a page with malformed HTML can
  be read differently.
- The container image is built from a base image pinned by digest, so rebuilding a tag starts from the
  same base until the pin is bumped.

### Fixed

- On Windows, a report redirected from stdout (`webvigil scan … --format json > scan.json`) was written in
  the system code page instead of UTF-8, so `webvigil report` could not read it back. It is UTF-8 now,
  as `--output` always was.
- The Web API answers `422` instead of `500` for a scan id outside the range a row can have (zero, negative,
  or larger than a SQLite integer) and for a list cursor that carries one.

### Security

- The Web API refuses, at start, a pinned `session_secret` shorter than 32 characters and a `*` in
  `cors_origins` (the API sends the session cookie), with a one-line error and exit code 4 instead of a
  traceback. **If you pinned a shorter secret, generate a longer one**
  (`python -c 'import secrets; print(secrets.token_urlsafe(48))'`) or unset it so one is generated; changing
  it signs every session out.
- `webvigil-web serve` warns when it listens beyond this machine with `cookie_secure` off.
- Login takes the same time for a username that does not exist as for a wrong password (it checked no hash
  before), so the response time no longer tells a real username from a made-up one.
- The Web API no longer lets an unauthenticated client make it hold memory in proportion to what it sends
  (GHSA-vw64-75mj-x37q): a request body over 1 MiB is refused with `413`, the login username and password are
  capped at 64 and 256 characters like the setup ones (a longer one is `422`), and the table of failed
  logins keeps at most 10,000 short keys. 1.0.0 kept every failed username for 15 minutes, whatever its size.
- The dashboard sends security headers on every page: it cannot be framed (`frame-ancestors 'none'`,
  `X-Frame-Options: DENY`), the browser may not sniff content types, a cross-origin request gets the
  origin and never the path of a scan, and camera, microphone, geolocation, payment and USB are
  granted to nobody. A script and style policy is not part of this change.

## [1.0.0] - 2026-10-08

The first release.

### Added

**Scanner and CLI**
- `webvigil scan` in **Safe Mode** by default (passive: it reads and sends no crafted request),
  `list-checks`, `report` (re-render a saved scan offline) and `version`.
- Reports in JSON (canonical, with a `schema_version`), SARIF 2.1.0, HTML and Markdown;
  `--fail-on` and documented exit codes for CI.
- A `webvigil.toml` configuration file (every key can be overridden by a flag), a scope guard,
  bounded concurrency, a request delay, a page limit and `robots.txt` handling on every scan (a warning says when it kept URLs out of the crawl, when the target stopped answering, or when the
  entry page looks like a JavaScript application the crawler cannot see into).
  A response body is read up to `[http] max_body_bytes` (10 MiB, after decompression) and the rest is
  dropped with a warning, so a hostile or oversized response cannot exhaust the scanner's memory.

**Passive checks**
- Security headers and technology-disclosure headers, cookie flags, TLS and HTTPS configuration,
  CORS misconfiguration.
- Client-side dependency fingerprinting with known-vulnerability matching against a vendored
  Retire.js database, and an opt-in OSV.dev lookup (`--osv-online`).
- Information disclosure: stack traces and directory listings, plus opt-in probing for exposed
  `.git`, `.env`, backups and debug endpoints (`--probe`).
- Subresource Integrity, mixed content, a session identifier in a URL, a private IP in a body.
- CSRF: forms that carry no anti-CSRF token.
- Session security: weak or predictable session ids (`session.id.weak`), with opt-in anonymous
  sampling (`--sample-sessions`).

**Active Mode** (`--mode active --authorized-by "<name / engagement>"`, in-band, every finding
confirmed against a per-request baseline)
- Reflected XSS; SQL injection (error, boolean and time based); path traversal; open redirect;
  SSRF (cloud metadata, loopback and internal hosts, `file://`); OS command injection; server-side
  template injection; expression-language injection (SpEL, OGNL, JEXL, MVEL, Unified EL); CRLF
  injection; host-header injection; LDAP, XPath and SSI injection; dangerous HTTP methods.
- Opt-in, each off by default and documented as writing to the target or making a real request:
  stored XSS (`--stored-xss`), file upload (`--file-upload`), XXE (`--xxe`), CSRF confirmation
  (`--confirm-csrf`), POST crawling (`--submit-post-forms`), automated login (`--login-url`) and
  the logout test (`--test-logout`).
- Session fixation (`session.fixation`) and a logout that does not invalidate the session
  (`session.logout.not-invalidated`), which build on the automated login.

**Authenticated and API scanning**
- Static cookies (`--cookie`) and headers (`--header`); an automated form login that keeps the
  session and logs in again when it drops (one attempt, never another credential, the password
  only from the environment or a prompt); OpenAPI / Swagger import (`--openapi`).

**Web API and dashboard** (optional, in the repository)
- A FastAPI service with SQLite persistence and a queued scan runner, and a Next.js dashboard for
  it.
  `docker compose` publishes them on `127.0.0.1` only; see [Who can reach it](docs/web-api.md#who-can-reach-it).
  Login attempts are throttled (a wait that doubles up to 5 minutes), and changing the password signs
  the other sessions out.

**Packaging**
- A package for PyPI: the engine, the CLI and (with the `web` extra) the Web API, published from a
  GitHub Release with PyPI Trusted Publishing (no stored token) after a dry run on TestPyPI. The
  dashboard stays in the repository. See [releasing](docs/releasing.md).
- A container image for the CLI on `ghcr.io/ryanvmorais/webvigil` (`linux/amd64` and `linux/arm64`; tags
  `X.Y.Z`, `X.Y`, `X` and `latest`), built, smoke-tested and vulnerability-scanned before it is pushed,
  with signed build provenance and an SBOM.
- `selectolax` is capped below 1.0: version 1.0 removed the parser the engine imports.

**Quality and security of the project**
- Strict typing, an import contract that keeps the engine independent of the CLI, the API and the
  database, 1138 tests, a CI matrix on Python 3.12 to 3.14, Lighthouse CI for the dashboard, CodeQL
  and Dependabot.
- A security policy with private vulnerability reporting, a code of conduct, and the
  [stability policy](docs/stability.md).

[Unreleased]: https://github.com/ryanvmorais/webvigil/compare/v1.0.4...HEAD
[1.0.4]: https://github.com/ryanvmorais/webvigil/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/ryanvmorais/webvigil/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/ryanvmorais/webvigil/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/ryanvmorais/webvigil/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/ryanvmorais/webvigil/releases/tag/v1.0.0
