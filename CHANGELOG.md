# Changelog

All notable changes to WebVigil are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/2.0.0/) and the project follows
[Semantic Versioning](https://semver.org/); what that promises is in
[docs/stability.md](docs/stability.md).

The `v0.1` to `v0.22` milestones are the steps the project was built in, each
designed as a spec under [`specs/`](specs/). None of them was released on its own: `1.0.0` is the
first release and contains `v0.1` to `v0.20`, and `v0.21` (the HAR import) and `v0.22` (the dashboard's Content-Security-Policy) arrived in `1.1.0`.

## [Unreleased]

## [1.6.0] - 2026-11-24

A minor release of security and reliability fixes (GHSA-hhpx-9q93-mv55, GHSA-38gf-jvgw-g2pq,
GHSA-jh8f-87gj-2mw7 and GHSA-wfp3-jwpm-7j2x), with one new Web API setting. It is backward
compatible with [docs/stability.md](docs/stability.md): no check id, JSON report field or existing
configuration key changes. Exit code `4` now covers the cases the policy already lists, so a CI job
that uses `--fail-on` can fail on a scan left incomplete, and a site's `robots.txt` can lead the
crawl to different pages.

### Changed

- **With `--fail-on`, a scan left incomplete now exits with `4`.** When a scan pass or a check
  fails and no finding reaches the threshold, a build no longer passes on a scan that could not
  look. A finding at the threshold still exits with `3`, and without `--fail-on` the exit code
  stays `0`. An OSV.dev outage does not count, because the offline database still answers.
- The locked dependencies move to their latest releases older than seven days. The container
  image gets `httpx2` and `httpcore2` 2.16.2, and the Web API of the Docker Compose stack also
  gets `python-multipart` 0.0.34. Only the lockfile changed: an install from PyPI resolves the
  same ranges as before.

### Fixed

- **A target that never answers now exits with `4`, as documented.** A closed port or a name that
  does not resolve used to finish as a scan with exit `0` and header findings about a response
  that never came. The scan now stops with an error and writes no report, and the Web UI shows it
  as failed. If the entry page fails but another page answers, the header checks read that page.
- **The terminal now says when a scan is incomplete**, also with `--format` and `--output`, where
  no summary is printed.
- **The dashboard's Docker build no longer takes local `.env*` files.** A build from a working
  copy that had one sent it to the build context and copied it into the build stage.

### Security

- **Credentials stay on the target origin through redirects** (GHSA-hhpx-9q93-mv55). In a scan with
  credentials, a `307` or `308` that would resend a request body or query parameters to a URL that
  may not receive credentials (plain `http` from an `https` target, or another subdomain) is no
  longer followed, and an automated login that ends there fails with an error that says the
  destination may not receive the password. Scans without credentials follow their redirects as
  before.
- **The session tests keep the session's cookies on the target origin** (GHSA-hhpx-9q93-mv55). When
  the reference page is in scope but off that origin, the fixation and logout tests are skipped with
  a warning; set `[auth.login] check_url` to a page on the origin to run them.
- **A cookie the target sets stays out of later requests** (GHSA-hhpx-9q93-mv55). The HTTP client no
  longer keeps a `Set-Cookie` between requests, so a retry, an anonymous request or a request to
  another subdomain in scope carries only the cookies that request may receive.
- **IPv6 forms of internal addresses are recognized** (GHSA-hhpx-9q93-mv55). The address guard now
  reads the IPv4 address inside IPv4-compatible and IPv4-translated IPv6 addresses, and any other
  IPv6 address counts as public only in global unicast (`2000::/3`). A public target can no longer
  send the scan to an internal host through the deprecated site-local range or a reserved one.
- **Error output no longer repeats raw failure text or the secret parts of a URL**
  (GHSA-38gf-jvgw-g2pq). The terminal, CI logs, reports, the database and the Web API now name a
  network failure by its type, with a plain description for an untrusted TLS certificate and for an
  address the scan refuses, and show a URL as `scheme://host[:port]/path`, without userinfo, query,
  fragment or path parameters, or only its scheme when the address cannot be told apart from a
  credential. A failed scan pass reports its exception type. A failed check reports its type, frames
  and chain without exception messages; WebVigil's own errors keep their message.
- **Redaction recognizes a credential quoted as Python bytes** (GHSA-38gf-jvgw-g2pq), the form
  libraries use in their errors, including values with non-ASCII or control characters.
- **A target with an invalid port now exits with `4`** (GHSA-38gf-jvgw-g2pq), as documented, instead
  of `1`, and the message for an invalid target no longer repeats it, since a mistyped one can hold
  a password. The same goes for a value given to `--config`, `--openapi` or `--har` that may be a
  URL typed without its scheme, and a config file that cannot be read now exits with `4` instead of
  a traceback.
- **What a site or a report file holds can no longer stall the CLI, abort a scan or lose its
  result** (GHSA-jh8f-87gj-2mw7). `webvigil report` on a damaged file says it is not a valid report
  and names a few field paths, never a value from the file, and validation stops at the first bad
  item of a list. Error messages, status lines and the terminal summary have a size limit, the
  summary lists up to 100 warnings and counts the rest, and a failed login names a few forms and
  fields. The dashboard shows a failed scan's error with its hidden characters made visible. A
  sitemap or an OpenAPI server URL that cannot be read no longer ends the scan, and a link or
  redirect to a URL that cannot be sent costs that URL alone. A character UTF-8 cannot encode is
  replaced with U+FFFD wherever text enters a result, so every report format, the database and the
  Web API keep working, also for rows stored by an earlier version.
- **`robots.txt` rules now follow RFC 9309 on every supported Python version**
  (GHSA-jh8f-87gj-2mw7). WebVigil reads the file with its own parser, so groups, the most specific
  rule, `*`, `$` and percent-encoding give the same decision whichever Python runs the scan, and no
  content of the file can end the crawl. This can change which pages a scan reaches. A file or a URL
  beyond what the crawl can evaluate is not followed, and the scan warns about it.
- **A single client guessing a password now delays only itself** (GHSA-wfp3-jwpm-7j2x). The login
  wait belongs to each client, so failures from one address do not delay another. A short limit per
  username still contains guesses spread over many addresses, so those can delay that login for as
  long as the guessing lasts. Only a few password checks run at once, with the excess answered `429`
  and `Retry-After`, and a client already waiting does not compete for them. A full table of failed
  logins no longer drops a client that is waiting.
- **The new `trusted_proxies` setting** (`WEBVIGIL_TRUSTED_PROXIES`, empty by default,
  GHSA-wfp3-jwpm-7j2x) says which proxies may name the client through `X-Forwarded-For`; any other
  request is counted by the address of its connection, whatever forwarding headers it carries. The
  Compose file trusts only its dashboard, whose image now reports the real connection. If you run
  your own reverse proxy in front of the API, list it, or all its clients share one wait. A network
  broader than `/8` in IPv4 or `/7` in IPv6 is refused.
- **A Web API redirect keeps the scheme the client used** (GHSA-wfp3-jwpm-7j2x). A path with a stray
  trailing slash is answered with a relative `Location`, so a client behind a TLS proxy is not sent
  to plain `http`.
- **A password change now ends a login that was still being verified** (GHSA-wfp3-jwpm-7j2x), and of
  two changes made at the same time one is stored and the other gets `409` instead of overwriting
  it. A change overtaken by `reset-password` also gets `409` and no new session, and a reset
  overtaken by another change says so and exits with `1`.

## [1.5.0] - 2026-11-23

A minor release that moves the engine's HTTP client to `httpx2`. It is backward compatible with
[docs/stability.md](docs/stability.md): no CLI option, exit code, check id, configuration key or
JSON report field changes. Only the provisional Python API changes, as described below.

### Changed

- **The engine's HTTP client is now `httpx2`, in place of `httpx`** (#304). Commands,
  configuration, check ids, the report schema and fingerprints do not change. Certificate trust
  stays the same: the `certifi` bundle, or `SSL_CERT_FILE` / `SSL_CERT_DIR` when set. An install
  now brings `httpx2` and `httpcore2` instead of `httpx` and `httpcore`, and the provisional
  Python API exposes `httpx2` objects where it exposed `httpx` ones, such as `Response.headers`.
  In the TLS handshake the client now offers HTTP/2 before HTTP/1.1, so a server that follows the
  client's preference answers over HTTP/2.

### Fixed

- The `target` service of the Compose file starts again. Its image was missing `jinja2`, so the
  deliberately vulnerable app stopped at startup.

## [1.4.7] - 2026-11-22

A patch release that keeps a scan running when a session cookie or a `--cookie` value is outside
ASCII, and hides a credential or session value that a page echoes percent-encoded in Latin-1. It is
backward compatible with [docs/stability.md](docs/stability.md): no CLI option, exit code, check id,
configuration key or JSON report field changes.

### Fixed

- A session cookie or a `--cookie` value outside ASCII no longer stops the scan or ends its later
  passes early. The scanner now sends the value back byte for byte, and the report shows and
  redacts it as text.
- The report also hides a credential or session value that a page echoes percent-encoded in
  Latin-1.

## [1.4.6] - 2026-11-22

A patch release that reads a backslash in a link or a redirect the way a browser does, keeps a
redirect the HTTP library cannot parse from failing the request, and refuses a time-based delay too
short to tell a delayed answer from a slow one. It is backward compatible with
[docs/stability.md](docs/stability.md): no CLI option, exit code, check id or JSON report field
changes, and no configuration key is renamed or removed; `[injection] time_based_delay_s` now
refuses a value below 2.

### Changed

- The locked dependencies move to their latest releases older than seven days. The Docker Compose
  stack gets FastAPI 0.163.1 in its Web API and Next.js 16.4.6 in its dashboard. Only the
  lockfiles changed: an install from PyPI resolves the same ranges as before.

### Fixed

- A backslash in a link or a redirect is read the way a browser reads it: in an `http` or
  `https` URL, a `\` before the query is a `/`. A target that answers the open-redirect probe with
  `Location: /\webvigil.invalid/` (or `\\webvigil.invalid/`) is now reported as
  `injection.redirect.open`; before, the scanner took that `Location` for a path on the target,
  followed it as an in-scope redirect and saw no redirect at all. The crawler and the checks
  resolve every link the same way, so `/\other.example/` is a link to `other.example`, out of
  scope, and no longer a page of the target. A backslash in the query or the fragment, or in a
  `mailto:` or `javascript:` link, is kept.
- A redirect whose `Location` the HTTP library could not turn into a request, such as
  `https:\\other.example/` (a browser reads it as `https://other.example/`) or `mailto:x`, no
  longer fails the request. The scanner never let the library follow redirects, but the library
  still parsed the `Location` and raised, so the page was lost and the open-redirect probe stopped
  on that parameter. The scanner now reads the value itself, as it does for every redirect: a
  target that honours the `https:\\webvigil.invalid` probe is reported as
  `injection.redirect.open`.
- `[injection] time_based_delay_s` must be at least 2. A time-based hit needs the delayed answer to
  arrive `delay - 1` seconds after the slower of the control and the baseline; with a delay of 1
  or less that margin was zero or negative, so an Active scan reported a time-based SQL injection
  and a time-based command injection on parameters of a target that never waits. A
  configuration with a smaller value is now a configuration error (exit code 4) that names the
  setting.

## [1.4.5] - 2026-11-21

A patch release that moves the CLI to Typer 0.29.1 and makes a `ScanResult` built with its
constructor recompute its severity counts. It is backward compatible with
[docs/stability.md](docs/stability.md): no CLI option, exit code, configuration key, check id or
JSON report field changes.

### Changed

- The container image (the CLI) moves to Typer 0.29.1, up from 0.28.0, the release an install
  from PyPI already resolves (#302). Typer 0.29 validates option values with Pydantic, so the
  message for an invalid value reads differently: `--max-pages abc` now reports
  `Input should be a valid integer, unable to parse string as an integer`. The exit code stays 2.
  Only the lockfile changed: an install from PyPI resolves the same ranges as before.

### Fixed

- A `ScanResult` built with its constructor (`ScanResult(...)`, as code using the Python API
  may do) now recomputes severity counts that disagree with its findings, as reading a report
  file already did (#313). The recount was dropped there without an error. The scan engine and
  the Web API never pass counts that disagree, so no report they produced changes.

## [1.4.4] - 2026-11-21

A patch release that moves the Web API of the Docker Compose stack to FastAPI 0.163.0. It is
backward compatible with [docs/stability.md](docs/stability.md): no CLI option, exit code,
configuration key, check id or JSON report field changes.

### Changed

- The Web API of the Docker Compose stack moves to FastAPI 0.163.0, up from 0.162.7, the latest
  release older than seven days. The release adds a concurrency limit for dependencies and
  changes nothing the Web API uses. The container image (the CLI) does not include FastAPI. Only
  the lockfile changed: an install from PyPI resolves the same ranges as before.

## [1.4.3] - 2026-11-21

A patch release that refreshes the locked dependencies and type-checks the dashboard with
TypeScript 7. It is backward compatible with [docs/stability.md](docs/stability.md): no CLI
option, exit code, configuration key, check id or JSON report field changes.

### Changed

- The dashboard is type-checked with TypeScript 7 (7.0.2, the native compiler), up from 5.9
  (#235). TypeScript 7.0 has no JavaScript API yet, so the tools that need one (the ESLint
  config and `openapi-typescript`) keep TypeScript 6 through the `@typescript/typescript6`
  compatibility package, as the Next.js docs describe. Nothing changes for the engine, the CLI or
  the Web API.
- The locked dependencies move to their latest releases older than seven days. The container
  image gets `markdown-it-py` 4.3.0 and `annotated-doc` 0.0.6, and the Web API of the Docker
  Compose stack also gets FastAPI 0.162.7, SQLModel 0.0.50 and `argon2-cffi-bindings` 26.2.0.
  Only the lockfile changed: an install from PyPI resolves the same ranges as before.

## [1.4.2] - 2026-11-14

A patch release with a round of hardening of the crawler and of the cookie and sitemap parsers.
It is backward compatible with [docs/stability.md](docs/stability.md): no CLI option, exit code,
configuration key, check id or JSON report field changes.

### Fixed

- The stored-XSS re-crawl counts the page text it keeps against the same 256 MiB allowance as the
  first crawl, instead of an allowance of its own, and the scan warns when the re-crawl reached
  one of the crawl's limits, page text included.
- `session.id.weak` and the session-cookie weighting of `csrf.form.no-token` read a `Set-Cookie`
  line as a browser does (RFC 6265bis): a cookie whose name and value pass 4096 octets is ignored,
  an attribute whose value passes 1024 octets is ignored, and only the `name=value` pair reaches
  the standard library's cookie parser, whatever the length of the attributes.
- A sitemap that carries a document type declaration is no longer parsed. The sitemap protocol
  has no use for one, and without one there is no entity to expand, whatever version of `expat`
  the Python runtime links (the Python documentation says versions before 2.7.2 may be
  vulnerable to entity expansion).

## [1.4.1] - 2026-11-14

A patch release with a security fix for what a scanned site can make the checks cost
(GHSA-gf8g-gcvm-28m9) and a round of hardening of the checks. It is backward compatible with
[docs/stability.md](docs/stability.md): no CLI option, exit code, configuration key, check id or
JSON report field changes. As part of the security fix, `http.cookies.flags` reports at most 20
findings per page, `session.id.weak` judges at most 50 session cookie names in a scan, and a
check keeps at most 5,000 distinct findings in a scan.

### Fixed

- A malformed value from the scanned site no longer costs more than the result it belongs to.
  An injection detector that fails on one point now loses only that point's result, with one
  warning per detector, instead of every injection finding of the scan. An HSTS `max-age` or a
  session id with thousands of digits, a JSON body nested past the parser, and a TLS certificate
  that loads but has an unknown signature algorithm or a bad extension no longer stop their
  check: the certificate is reported as `cert-unparseable`.
- The `--osv-online` lookup reads at most 16 MiB per response, gives each request a total
  deadline of three times `[deps] osv_timeout_s`, keeps at most 200 records per package, and
  skips a malformed record with a warning. Any failure falls back to the offline database with a
  warning instead of aborting the scan.
- The `--file-upload` pass reports server-side execution only when the uploaded file's own output
  (its marker followed by the computed product) comes back. A not-found page that echoed the file
  name and happened to hold the same number was reported as a critical finding. The pass also
  follows at most 4 of the links an upload answer gives, and its fetches count against the
  per-form request cap.
- The SQL injection error probes no longer include an `OR` condition. A form field can feed an
  `UPDATE` or a `DELETE`, and a condition true for every row could widen what it changes. The
  quote-breaking probes that remain draw the same database errors.
- The expression-language, CSRF confirmation, and stored XSS passes no longer slow down with the
  size of a response. They cut the text before splitting it, stop tokenizing at their cap, skip
  the full page comparison when a quick bound already rules it out, and read each re-crawled
  page once instead of once per marker. The findings are the same.

### Security

- A scanned site that sets many cookies can no longer fill the scan's memory with findings
  (GHSA-gf8g-gcvm-28m9). `http.cookies.flags` reports at most 20 findings per page, the last one
  noting that the page sets more, and `session.id.weak` judges at most 50 session cookie names in
  a scan, with a warning past that. No check keeps more than 5,000 distinct findings in a scan;
  the rest are dropped with a warning.
- A script the scanned site serves can no longer stall the dependency fingerprinting
  (GHSA-gf8g-gcvm-28m9). A Retire.js pattern that repeats a group of one-character alternatives
  (a line break or any character) cost time exponential in the run it read; the group is now
  compiled as the character class it matches, which finds the same libraries in linear time.
- The value of a cookie the scanned site sets no longer appears in the report. The response
  headers shown by the header checks, the `http.cookies.flags` evidence and the CRLF injection
  proof keep the cookie's name and attributes and show `***` for its value (`sid=***; Path=/`),
  so a session token the target issues during an authenticated scan stays out of the report. The
  CRLF proof shows only the injected `Set-Cookie` line.
- `disclosure.session-id-in-url` redacts every session parameter of a URL, also when the value
  appears earlier in the URL or the URL carries more than one, and redacts the page's own URL in
  the finding's location and evidence.

## [1.4.0] - 2026-11-13

A minor release with two security fixes for what a scanned site can make the checks do
(GHSA-xwxv-whh4-h422 and GHSA-9w7j-qp5j-mw26), a round of hardening of the reports, and paged,
searchable findings in the Web API and the dashboard. It is backward compatible with
[docs/stability.md](docs/stability.md): no CLI option, exit code, configuration key, check id or
JSON report field changes. The Web API's findings route now returns pages, a change to a
provisional interface listed under Changed, and the SRI, mixed-content and
session-identifier-in-URL checks report at most 20 findings per page, as part of a security fix.

### Added

- The dashboard's findings table has a text search (title, URL, parameter, header or cookie
  name), and its Check filter lists only the checks that found something in the scan, each with
  its number of findings. Both run on the server, across every page. In the Web API they are the
  `q` parameter of `GET /api/scans/{id}/findings` and the new `GET /api/scans/{id}/findings/checks`.

### Changed

- **The findings of a scan come in pages.** `GET /api/scans/{id}/findings` returns
  `{items, next_cursor, total}` instead of a bare list: 50 findings by default, up to 200 with
  `limit`, and the next page with `cursor`. The dashboard shows 50 at a time with "Load more", as
  in the scan list, so a scan with thousands of findings no longer arrives, or renders, at once.
  The order is unchanged. The full set is in every report format.

- The SARIF rule's `shortDescription` is `WebVigil check <check id>`, no longer the title of the
  first finding of that check. Each result's message still carries its own title.
- In the Markdown report, only a reference that is an `http(s)` URL is a link (`<url>`), as in the
  HTML report. Mentions (`@name`), issue references (`#12`) and bare URLs in the rest of the text
  are broken with a zero-width space, so a report pasted into GitHub notifies nobody and links
  nowhere; it reads the same.
- Every free-text field of a scan result has a size bound, applied when a check builds a finding
  and when a report is read back: 1,024 characters for a check id, a title, a parameter, header
  or cookie name, a label or a library name, version or advisory id; 16,384 for a description, a
  remediation, an error message or a warning; 65,536 for a URL or a traceback; 4,096 for a piece
  of evidence, as before. A longer value is cut and ends in `...[truncated]`; a report whose
  values were already cut reads back unchanged.

### Security

- What a scanned site serves can no longer keep the checks busy for hours or fill memory with
  findings (GHSA-xwxv-whh4-h422). Dependency fingerprinting matches the library patterns made of
  pieces joined by "anything in between" piece by piece, reads each distinct inline script once
  and up to 4 MiB of them in a scan, and examines up to 1,000 distinct script and stylesheet URLs,
  with a warning past either limit. The `--probe` validators read the first 256 KiB of a body with
  bounded patterns, and the redaction of a JSON body scans only the strings its evidence keeps.
  The ASP.NET error-page signature and the open-redirect detector bound their repetitions.
- The SRI, mixed-content and session-identifier-in-URL checks report at most 20 findings per
  page; the last one notes that the page lists more.
- A `Cookie`, an `Authorization` or a configured `[auth]` header that a check passes itself no
  longer follows a redirect to another subdomain (`--scope subdomains`) or down to plain `http`
  (GHSA-9w7j-qp5j-mw26). The session tests of the automated login sent the session cookie this
  way; on such a hop it is now dropped, like the credentials the client adds itself.
- Bidirectional controls and zero-width characters from the scanned site (the "Trojan Source"
  characters) are shown as visible `\uNNNN` escapes in the terminal summary, the Markdown, HTML
  and JSON reports and the dashboard, so a title, a URL or a piece of evidence reads as what it
  holds. A reference with one of them, or with a C1 control, is never a link.
- A `|` inside backticks in a library name, version or advisory id no longer splits its row of
  the Markdown technologies table.
- The SARIF report escapes brackets and backslashes in result messages (so text from the site
  is never rendered as a link), uses only an `http(s)` reference as `helpUri`, and percent-encodes
  the location into a valid URI.
- The HTML report carries its own `Content-Security-Policy` (`<meta>`), so a report opened from a
  file runs no script and loads nothing, as when the Web API serves it.
- The dashboard links a reference only when `//` follows the scheme: `http:example.org` was
  accepted and resolved against the dashboard's own page.
- `webvigil report` reads a JSON file of at most 256 MiB and exits with code 4 on a larger one,
  so a file someone sent cannot exhaust the machine's memory.
- `webvigil report` refuses a report whose `schema_version` is not an integer (a string or a
  float could pass the newer-schema check and be read anyway), and recomputes the severity counts
  from the findings instead of showing the counts written in the file.

## [1.3.1] - 2026-11-13

A patch release with one security fix for how the terminal output shows what a scanned site
sent (GHSA-98xg-gg8r-r93h) and a round of hardening of the scan engine and the reports. It is
backward compatible with [docs/stability.md](docs/stability.md): no CLI option, exit code,
configuration key, check id or JSON report field changes. Two behaviours change on purpose, as
part of the security fixes, and are listed under Changed: the HAR import hides more of what a
recording holds, and the crawler skips state-changing links on every scan.

### Changed

- The HAR import hides more of what a recording holds. A value that looks like a credential (a
  JWT, a long random token, a long hex digest) becomes `wv` under any parameter name, and so do
  the values of `pass`, `pin`, `sig`, `nonce`, `ticket`, `assertion` and of a parameter named
  exactly `code` or `state`. An entry whose path carries a token-like segment is left out and
  counted as `token in path` in the import summary.
- The crawler skips links and `GET` forms that look state-changing (`delete`, `remove`,
  `unsubscribe`, `cancel` and the rest of the list in
  [docs/authenticated-scanning.md](docs/authenticated-scanning.md)) on every scan, not only on
  an authenticated one: an anonymous `GET /items/5/delete` can change state too. The warning
  that counts them no longer says "(authenticated crawl)".

### Security

- `--cookie` and `--header` values (a bearer token also on its own) are now scrubbed from the
  report when the target echoes them, with or without `--login-url`. Before, only the login's
  password and session were.
- The report scrubbing also catches HTML-escaped and lower-case percent-encoded echoes, covers
  finding references and technology names, versions and advisories, and adds a warning that
  counts the fields it changed. A session value the target set is scrubbed only when it looks
  like a session id, so a target cannot blank out findings by setting a cookie to a common word.
  A configured credential under four characters, which cannot be scrubbed, gets a warning.
- The traceback of a check that fails no longer carries the machine's paths (the install
  directory, the OS user name): each frame keeps only its path inside the install.
- A configuration error names the setting and its position, never the value given, so a
  malformed cookie or header, a `password` in `[auth.login]` or a short `session_secret` no longer
  reach the terminal or a CI log.
- `--scope subdomains` finds the registrable domain with the full
  [Public Suffix List](https://publicsuffix.org/), vendored in the package (both its ICANN and
  private sections), instead of a list of eleven suffixes. A target on a shared host such as
  `alice.herokuapp.com` no longer takes `bob.herokuapp.com` into scope, and a target that is a
  public suffix itself is scanned as that host only. The list is refreshed by
  `scripts/update-public-suffix-list.py`; nothing is downloaded during a scan.
- The automated login searches `logged_in_marker` and `logged_out_marker` in the first 200,000
  characters of the answer, as the re-login already did, so a huge login answer no longer costs
  a regular expression over up to 10 MiB.
- What the scanned site writes can no longer end a scan with an error. A link, a form action, a
  sitemap entry or a `Location` header with a malformed host or port is skipped; a `charset=`
  that names a codec that is not a text encoding reads the body as UTF-8; a body that does not
  decode as its `Content-Encoding` claims, or a URL longer than 64 KiB, fails that one request.
  An unexpected error in the dependency fingerprint or the disclosure probe becomes a warning,
  as in the other passes.
- Text from the scanned site is no longer read as terminal markup or control sequences
  (GHSA-98xg-gg8r-r93h). The terminal summary printed a finding's title and location (which
  quote cookie names, header values and form fields) and the scan warnings as Rich markup, so a
  bracket the site wrote could restyle or hide that line, or make the summary fail before any
  finding was shown; it now prints them as text. Control characters (an escape sequence, the C1
  range, a lone carriage return) are written as a visible `\xNN` escape in the summary, in error
  lines and in the Markdown and HTML reports, and as `\u00XX` in the JSON report, so a report
  printed to a terminal shows them instead of acting on them. A CRLF in the evidence of the
  Markdown and HTML reports reads as LF.

## [1.3.0] - 2026-11-12

A minor release with two security fixes for what a scanned site can make a scan do
(GHSA-2qw3-xm7x-r7cg and GHSA-73j5-mxxc-x7x5) and a round of hardening of the Web API. It is
backward compatible with [docs/stability.md](docs/stability.md): no exit code, check id or JSON
report field changes. One setting is new, `[scan] max_duration_s` (`--max-duration`), and three
behaviours change on purpose, listed under Changed: the scope also checks the port, response
bodies are decoded by WebVigil (`gzip` and `deflate` only), and a request that uses up its total
deadline is not retried.

### Added

- `[scan] max_duration_s` (`--max-duration` on the CLI): the most a whole scan may take, 4 hours by
  default (`0` for no limit). Past it no request is sent, every pass ends with what it has, and the
  report carries a warning that names the setting. The Web API's scans use the default.

### Changed

- A request that uses up `[http] total_timeout_s` is no longer retried, so a slow target costs one
  deadline per request instead of three.
- The scanner decodes response bodies itself and asks only for `gzip` and `deflate`
  (`Accept-Encoding: gzip, deflate`). A body in another coding (`br`, `zstd`) is kept as it came,
  whatever else is installed next to WebVigil, and a response that lists more than three codings is
  not decoded.
- The scope also checks the port: a URL is in scope on the target's own port and, when the
  target uses its scheme's default port, on the `http`/`https` pair on ports 80 and 443. A link
  to another port of the target host, or to a scheme other than `http`/`https`, is out of scope
  and counted as such.

### Fixed

- The Web API's scan runner keeps going after an unexpected error (a database failure while
  claiming, loading or storing a scan): the scan is `failed` and the next one runs, instead of
  every later scan staying `queued` until a restart.
- Cancelling a scan while its result is being written no longer races the write: the cancel gets
  `409` and the scan ends `completed`, never `cancelled` with findings.

### Security

- `POST /api/auth/password` is throttled like the login: after 5 wrong current passwords the
  user waits, with `429` and `Retry-After`, so a stolen session cannot guess the password without
  limit.
- The container image installs exactly the locked dependency graph (`uv sync --locked`, which
  fails if `uv.lock` is stale), and a new release of a dependency is locked only after it has been
  public for a week.
- Behind the dashboard's proxy, a failed login counts against the username only, so one
  stranger's failures no longer make every user of the dashboard wait.
- A password change now signs out sessions issued earlier in the same second: the session token's
  issue time keeps its fraction of a second.
- A session token without an expiry, an issue time or a subject is refused.
- `webvigil-web reset-password` enforces the same password policy as the Web API (8 to 256
  characters).
- The Web API's SQLite database, which holds the password hash and the session signing secret, is
  created readable by its owner only (`0600`), and an existing one, with its `-wal` and `-shm`
  files, is set to `0600` when the server starts.
- Every option of `POST /api/scans` has a ceiling (`max_pages` 10 000, `delay_ms` 60 000, the
  target 2 048 characters, `authorized_by` 256, `disabled_checks` 200 ids of 128 characters), and
  the queue holds at most 100 scans (`429` beyond that).
- A scan that crashes records `internal error` instead of the exception text, which stays in the
  server log.
- What a scanned site sends is bounded in memory and time beyond one response
  (GHSA-2qw3-xm7x-r7cg): `[http] max_body_bytes` holds at every decoding stage of a compressed body,
  `robots.txt` is read up to 500 KiB (RFC 9309), the text the scan keeps of its pages shares a
  256 MiB allowance (a page past it keeps its first 256 KiB), the automated login's cookie jar is
  bounded (past 1 024 distinct values the session is given up, with a warning), and the OpenAPI
  import builds only the operations it keeps, bounds a local document to 64 MiB and reports a
  malformed one, or one whose arrays and objects nest past 256 levels, as an import error.
- A scanned site can no longer steer the scan's requests or credentials outside the target
  (GHSA-73j5-mxxc-x7x5). Every host name is resolved once per scan and the scanner connects to
  the address it checked; when the target resolves to a public address, no host of the scan may
  resolve to a loopback, private, link-local or other non-public address, and a scan warning
  counts the requests not sent. The scope checks the port. Configured `[auth]` cookies and
  headers, the automated login's session and its password go only to the target origin or its
  `https` upgrade, never from an `https` target to plain `http`. Through an HTTP proxy set in the
  environment (`HTTP_PROXY`, `HTTPS_PROXY`) the proxy resolves the names and the address check
  does not apply.

## [1.2.1] - 2026-11-12

A patch release with one fix, in which host names the Web API answers for. Nothing in the CLI, the
exit codes, the check ids or the JSON report changes; the Web API has one new setting,
`allowed_hosts`.

### Security

- A web page open in the browser can no longer reach a locally running `webvigil-web` dashboard or
  API as if it were the same site (GHSA-q373-8m5q-qwww). The Web API now answers only requests
  addressed to a host it knows: an IP address, `localhost`, the bind `host` when it is a name, or a
  name in the new `allowed_hosts` setting (`WEBVIGIL_ALLOWED_HOSTS`), checking both `Host` and the
  `X-Forwarded-Host` the dashboard's proxy adds; any other name gets `400`. Parallel login attempts
  are now counted as they arrive, so a burst of them waits like a sequence would, and two first-run
  setup requests at once create exactly one account. **If you reach the API or the dashboard by a
  host name other than `localhost`** (a reverse proxy, a LAN name), add that name to `allowed_hosts`;
  the Compose file already lists `api`, the name the dashboard uses.

### Changed

- The container image applies Debian's security updates when it is built, so it carries a fix
  Debian has published before the official Python base image is rebuilt with it, and it starts from
  a newer base image.
- The README (and `README.pt-BR.md`) lists what WebVigil checks by area instead of by build
  milestone: a table with what each area finds, whether it is passive or active, and the switch
  that turns it on. The ten switches that are off by default are a table under "Safe by default".
- The README (and `README.pt-BR.md`) opens with the terminal recording, whose severity table is now
  drawn on the character grid, shows the dashboard in the "Web UI"
  section and has a new "The HTML report" section with the report in the light and the dark palette.

## [1.2.0] - 2026-10-30

A minor release: the logo, the README in Brazilian Portuguese, a more accessible dashboard,
Python 3.15 and the Windows CI, all backward compatible with [docs/stability.md](docs/stability.md):
no exit code, check id or JSON report field changes. 1541 Python tests and 271 for the dashboard.

### Added

- CI runs the quality gate on Windows (`windows-2025`) as well as Linux, on every Python in the
  classifiers, so `Operating System :: OS Independent` is tested and not only declared.
- Python 3.15 is supported: the `3.15` classifier, a `3.15` run in the CI matrix, and the Docker
  image is built on `python:3.15-slim`. The minimum stays Python 3.12.
- A logo: a browser window with an open eye,
  `assets/webvigil-web-vulnerability-scanner-logo.svg`, shown at the top of the README.
- The README in Brazilian Portuguese, `README.pt-BR.md`: the same sections as `README.md`, with
  the commands unchanged. A test keeps the two in step.

### Changed

- The dashboard's toolchain moves from Node 24 to Node 26 (Active LTS since 2026-10-28): the CI and
  Lighthouse jobs, the `web/Dockerfile` images, `engines.node` and `@types/node`. The Node 26 image has
  no `corepack`, so the Dockerfile installs the pnpm version that `packageManager` pins. Nothing
  changes for the engine, the CLI or the Web API.
- The dashboard's package manager moves from pnpm 9.15.4 to 12.15.0 (`packageManager` in
  `web/package.json`). pnpm 12 blocks dependency install scripts until they are approved, so
  `web/pnpm-workspace.yaml` approves the three that run one today (`esbuild`, `msw`, `unrs-resolver`),
  and the lockfile gains a block that pins pnpm itself. pnpm 12 no longer reads the `pnpm` field of
  `package.json`, so the dependency overrides (the patched releases of four transitive packages)
  live in `web/pnpm-workspace.yaml` as well. Nothing changes for the engine, the CLI or the Web API.
- The logo is also in the dashboard (the header and the sign-in pages, where the shield was), in
  the app icon of the tab and in the header of the HTML report. In the report it is an inline SVG,
  so the page still loads nothing.

- The dashboard is easier to use from the keyboard, a phone and a screen reader, after an
  accessibility and layout audit of every page in both themes. The item highlighted in a menu or a
  list now has a visible ring (its fill alone was 1.10:1 against the menu in the light theme), and the
  focus ring of buttons, fields and selects is 2 px. Each expand button in the findings table is named
  after its finding, and the full location of a finding is in its detail. Each page has its own tab
  title ("Scans | WebVigil", and the target's address on a scan). The sign-in, setup and 404 pages have
  a main landmark. A wrong password no longer sends the keyboard focus to the top of the page, and the
  `?next=` address survives it. A table wider than the screen is a named region that the keyboard can
  scroll.
- A scan that is still queued or running no longer reads "No findings" or "This scan produced no
  findings": it says "Scan in progress" until it finishes. On a phone the scan list hides the Mode,
  Scope and Created columns (the scan page still shows them), so the Findings column fits. A page that
  matches no route shows a "Page not found" page with a link back to the scans instead of Next's bare
  404, and the "Vulnerable" badge reads "Vulnerable · 11 advisories" (the ids are in its tooltip and in
  the finding it opens). The dialogs and menus stop animating when the system asks for reduced motion.
  Small copy changes: the scan options read "max pages: 12" instead of raw JSON, and the report button
  says why it is disabled.
- The container image no longer ships `pip`. The runtime never uses it, and the copy in the base image
  vendors its own `certifi`, which image scanners flagged (GHSA-6q48-6c7w-9gw2) until the base image
  was rebuilt.
- The PyPI keywords add `vulnerability-scanner`, `devsecops`, `sarif` and `xss`, the terms people
  search for when they look for a tool like this one. PyPI reads them at upload, so they take effect
  with the next release.

### Security

- The locked `certifi` moves to 2026.10.19, which closes an advisory rated CRITICAL. Only the
  lockfile changed: the container image gets the new release, and an install from PyPI resolves its
  own.

## [1.1.0] - 2026-10-09

A minor release: new options, detector improvements and hardening, all backward compatible with
[docs/stability.md](docs/stability.md): no exit code, existing check id or JSON report field changes.
1528 Python tests and 202 for the dashboard.

### Added

- `--har` / `[scan] har`: seed the scan from a HAR file recorded in a browser or an intercepting proxy
  ([#146](https://github.com/ryanvmorais/webvigil/issues/146)). The crawler runs no JavaScript, so a
  single-page application looked like one empty page (the Juice Shop benchmark found one page and no
  finding). Browse the application once with the network panel open, save the traffic as HAR, and the
  target's own `GET` and `POST` requests become crawl seeds (with the query they were recorded with) and
  injection points, the way an `--openapi` description does. Static assets, other hosts, other methods and
  login or state-changing paths are left out, and a summary line says what was read, seeded and ignored.
  The import reads a local file and sends nothing; a `POST` goes out only from `--submit-post-forms` in
  Active Mode. Cookies, headers and response bodies in the file are never read, a secret-named parameter's
  value and any value over 256 characters become a placeholder, a JSON body is kept as its shape only, and
  a recording that looks authenticated draws a warning when the scan carries no `--cookie`, `--header` or
  `--login-url`. `[scan] har_max_operations` (default `150`) caps the operations. The Web API does not
  accept the option. See [docs/har-import.md](docs/har-import.md).
- `[http] total_timeout_s` (default `60`), a deadline for one whole request
  ([#140](https://github.com/ryanvmorais/webvigil/issues/140)). `timeout_s` limits each connect, read and
  write on its own, so a server that sends one byte every few seconds never tripped it and could hold a
  request, and a concurrency slot, open for a very long time. The deadline runs from sending the request
  to the last byte of the body (the wait for a free slot is not counted), and a request that passes it is
  handled like any timeout: retried when idempotent, counted in the "no response" warning, and reported as
  a failed request. A response that honestly takes more than a minute to arrive now fails the same way;
  raise the key for a very slow target.
- `csrf.form.state-change-over-get` (`MEDIUM`, CWE-352 and CWE-650), a passive check for a `GET` form that
  changes state ([#144](https://github.com/ryanvmorais/webvigil/issues/144)). `csrf.form.no-token` reads
  `POST` forms only, so the CSRF module of OWASP DVWA, which changes the password with a `GET` form, went
  unreported. The check flags a `GET` form with no anti-CSRF token field that has two password inputs (or
  one named like the new, confirmed or old password), or a destructive verb in its action, its field names
  or its submit label. Search, login, registration and logout forms are left out, and nothing is submitted.
  Confidence is `MEDIUM` at most and `SameSite=Lax` does not lower it, because a `Lax` cookie is sent when
  a cross-site link is followed. A scan that finds such a form now reports it, so `--fail-on` can see it.
- The dashboard sends a `Content-Security-Policy` on every page, with a fresh nonce per request: a script
  runs only if it carries that nonce (no `'unsafe-inline'`), and the policy also limits where images, fonts,
  connections, frames, forms and `<base>` may point, and forbids framing the dashboard. Styles still allow
  inline rules (the toast library injects one at runtime), and the report preview keeps working. Every page
  is now rendered per request instead of being prerendered, so a reverse proxy in front of the dashboard
  must not cache its HTML. Together with the security headers of 1.0.1 this closes the dashboard part of
  [#138](https://github.com/ryanvmorais/webvigil/issues/138).
- A scan target can now be a one-label host (`http://app:8000/`, a Compose or cluster service name, an
  intranet host) or an IPv6 literal (`http://[::1]:8000/`); both were refused with "could not determine a
  valid host" ([#191](https://github.com/ryanvmorais/webvigil/issues/191)). `--scope subdomains` on such a
  host behaves like `--scope host`, since there is no registrable domain to widen to, and the payloads that
  put the target host in a URL's userinfo are not sent to an IPv6 target. A malformed bracketed host is now
  a plain "invalid target" error instead of a traceback.

- The injection pass now fuzzes the value of a `<select>`
  ([#190](https://github.com/ryanvmorais/webvigil/issues/190)). A browser only sends a listed option, but a
  client can send anything, and a server that builds a query from the option is as exposed as one that
  builds it from a text box; OWASP DVWA at the "medium" level keeps its SQL injection behind a `<select>`,
  and both the error-based and the blind finding were missed there. A select point keeps the listed option
  as its baseline, is tested after every other point (so on a spent budget it is the first thing dropped),
  and is never written to by `--stored-xss`. Radio and hidden fields are still sent as they are.
  A scan of a page with selects spends more of the same request budget.

### Fixed

- `--file-upload` no longer spends its per-form cap on the files a server rejects
  ([#194](https://github.com/ryanvmorais/webvigil/issues/194)). A server that refuses a file with a plain
  `200` page cost about thirteen look-ups per payload, and the cap ended the pass before it reached the
  payloads that claim an image type, so OWASP DVWA at the "medium" level, which filters by the declared
  part type only, was reported clean. A payload whose answer is the benign upload's answer, when the benign
  file never comes back, is now skipped after its one `POST`; and the pass also sends a plain `.php` file
  declared as `image/jpeg`.
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

[Unreleased]: https://github.com/ryanvmorais/webvigil/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/ryanvmorais/webvigil/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/ryanvmorais/webvigil/compare/v1.4.7...v1.5.0
[1.4.7]: https://github.com/ryanvmorais/webvigil/compare/v1.4.6...v1.4.7
[1.4.6]: https://github.com/ryanvmorais/webvigil/compare/v1.4.5...v1.4.6
[1.4.5]: https://github.com/ryanvmorais/webvigil/compare/v1.4.4...v1.4.5
[1.4.4]: https://github.com/ryanvmorais/webvigil/compare/v1.4.3...v1.4.4
[1.4.3]: https://github.com/ryanvmorais/webvigil/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/ryanvmorais/webvigil/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/ryanvmorais/webvigil/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/ryanvmorais/webvigil/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/ryanvmorais/webvigil/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/ryanvmorais/webvigil/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/ryanvmorais/webvigil/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/ryanvmorais/webvigil/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ryanvmorais/webvigil/compare/v1.0.4...v1.1.0
[1.0.4]: https://github.com/ryanvmorais/webvigil/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/ryanvmorais/webvigil/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/ryanvmorais/webvigil/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/ryanvmorais/webvigil/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/ryanvmorais/webvigil/releases/tag/v1.0.0
