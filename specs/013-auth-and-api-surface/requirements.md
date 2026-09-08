---
feature: Auth width and API surface — header/bearer auth, OpenAPI import to seed points, four missing passive checks
status: done
date: 2026-09-08
related:
  - 001-foundation/requirements.md
  - 006-active-injection/requirements.md
  - 007-auth-flows/requirements.md
origin: conception
---

# 013 — Auth width and API surface

## Context and problem

Spec 007 shipped authenticated scanning, but only through a **static cookie**
(`--cookie "name=value"` / `[auth] cookies`). Spec 007's own requirements
deferred header/bearer auth: "**Auth by header/bearer was scheduled for 013**
(does not need stateful login)" (`specs/README.md`). A large share of the
applications WebVigil should be able to scan — REST and GraphQL APIs, SPAs
talking to a JSON backend, anything behind an API gateway — authenticate with a
**bearer token** (`Authorization: Bearer …`) or an **API-key header**
(`X-API-Key`, `X-Auth-Token`). Today WebVigil cannot reach a single
authenticated endpoint on those targets.

The same targets have a second problem: **there is nothing to crawl**. WebVigil
discovers pages by following `<a href>` links and submitting safe `GET` forms
(spec 007). A JSON API serves no HTML and has no links, so the crawler finds the
entry document and stops. The injection pass (spec 006) then has almost no
injection points to work with. Every serious API scanner solves this by
**importing the API description** — an OpenAPI / Swagger document — and using it
to enumerate the operations, their parameters, and their request shapes.

Third, four **passive checks** that a reviewer comparing WebVigil to ZAP /
Wapiti would notice missing are still absent, and each is a small, self-contained
body/HTML inspection with no Active-Mode component:

- **Subresource Integrity (SRI) missing** — a cross-origin `<script>` /
  `<link rel="stylesheet">` loaded with no `integrity` attribute (CWE-353,
  CWE-1104).
- **Mixed content** — an HTTPS page that pulls a subresource over plain `http://`
  (CWE-319).
- **Session identifier in the URL** — a session token or API key carried in a
  query string or path segment, where it leaks into logs, `Referer`, and browser
  history (CWE-598).
- **Private / internal IP address disclosed in a response body** — an RFC-1918,
  loopback, or link-local address leaked in an HTML comment, a JSON payload, or
  an error page (CWE-200).

**This spec covers the minimum "auth and API" width, in-band, with no new
runtime dependency, no headless browser, and no out-of-band collaborator.** It
is the third of the four "real parity" specs (011 → 012 → **013** → optional 014
→ v1.0).

### Where it sits

```
webvigil.core.config           [auth] headers            (list[str], "Name: Value")
                               [scan] openapi            (str: local .json path or in-scope URL)
                               [scan] openapi_max_operations  (int, default 150)

webvigil.http.client           attach [auth] headers to target-host requests only,
                               never to a report / log / metadata / evidence line
                               (mirrors the spec 007 cookie handling exactly)

webvigil.crawler.openapi       NEW — parse an OpenAPI 3.0 / 3.1 / Swagger 2.0 JSON
                               document; resolve local #/components $refs; yield
                               operations (method, URL, query + path params with
                               synthesized values, a synthesized request body)

webvigil.crawler.crawler       + seed the discovered GET operations (like a sitemap
                               seed: scope-guarded, counted, capped by max_pages)

webvigil.checks.injection.points   + InjectionPoint source "openapi" for the query
                               and path parameters of GET / POST operations

webvigil.checks.content        NEW package (Category.CONTENT)
       ├── content.sri.missing        cross-origin subresource without integrity (MEDIUM)
       └── content.mixed              https page loads an http:// subresource (MEDIUM)

webvigil.checks.disclosure     + two passive checks (Category.DISCLOSURE)
       ├── disclosure.session-id-in-url   session token / API key in a URL (MEDIUM)
       └── disclosure.private-ip          RFC-1918 / loopback address in a body (LOW)
```

Reuses the existing machinery: the same `HttpClient` (auth attachment sits next
to the cookie attachment), the same `Crawler` seeding path as sitemaps, the same
`InjectionPoint` / `InjectionScanner` (only a new `source` string), the same
`Check` base and `list-checks` / `meta` plumbing (a new `Category` member is an
opaque string downstream — no API / OpenAPI / dashboard change, exactly like
`Category.HTTP` in spec 012).

The engine still imports nothing from `webvigil.cli` / `webvigil.api` / `web/`;
**no new runtime dependency** (OpenAPI parsing is `json` + hand-rolled `$ref`
resolution; the four checks are `selectolax` + `re`, already in use).
`import-linter` unchanged.

### Deployment note

Nothing here needs new infrastructure or costs anything to run. `--header` adds
request headers. `--openapi` reads a local file, or fetches **one in-scope URL**
(the target's own `/openapi.json`) — the engine still talks only to the target
(RNF-03). The four passive checks add zero requests. An OpenAPI-seeded scan is a
bounded set of extra in-scope GETs plus the operations' parameters folded into
the existing Active-Mode injection budget.

## Goals

- **Header / bearer auth.** A repeatable `--header "Name: Value"` flag and an
  `[auth] headers` list. Any header (`Authorization: Bearer …`, `X-API-Key: …`,
  `X-Auth-Token: …`). Attached only to requests whose host is the target host;
  **never** written to a report, a log line, the scan metadata, a warning, or a
  finding's evidence — the exact discipline spec 007 applied to cookies.
- **OpenAPI / Swagger import.** `--openapi <path|url>` / `[scan] openapi`.
  Accepts a local `.json` file or an **in-scope** URL returning JSON. Parses
  OpenAPI 3.0.x, 3.1.x, and Swagger 2.0. Resolves local `#/components` (3.x) /
  `#/definitions` (2.0) `$ref`s. Extracts every operation: method, resolved URL
  (server / `basePath` reconciled against the target origin), `in: query` and
  `in: path` parameters with a synthesized value (`example` → `default` →
  `enum[0]` → a type-based placeholder), and — for a body operation — a
  synthesized form or JSON request body sent with the baseline request.
- **Seed the crawl and the injection pass from the import.**
  - GET operations become crawler **seeds** — fetched in scope, counted in
    `pages_scanned`, bounded by `max_pages` — so the injection pass and the
    passive checks see endpoints that no HTML links to.
  - The query and path parameters of GET and POST operations become
    `InjectionPoint`s (`source = "openapi"`), de-duplicated against the points
    enumerated from crawled URLs and forms, tested by the spec 006 / 009 / 011 /
    012 detectors under the existing shared budget.
  - An operation whose path / `operationId` looks like authentication or
    destruction (`login`, `logout`, `delete`, `password`, …, the existing
    `_EXCLUDE_FORM_RE`) is **not** fuzzed — mirrors the form-exclusion rule.
- **Four passive checks**, all `PASSIVE`, all issuing no HTTP of their own
  (they read `ctx.pages`):
  - `content.sri.missing` (`Category.CONTENT`, MEDIUM, CWE-353 / CWE-1104).
  - `content.mixed` (`Category.CONTENT`, MEDIUM, CWE-319).
  - `disclosure.session-id-in-url` (`Category.DISCLOSURE`, MEDIUM, CWE-598).
  - `disclosure.private-ip` (`Category.DISCLOSURE`, LOW, CWE-200).
- **`Category.CONTENT`** — one new `StrEnum` member for the two HTML-subresource
  checks. An opaque string in the API / OpenAPI / dashboard, exactly like
  `Category.HTTP` in spec 012 — no downstream change.
- **Fixture-app coverage.** The insecure profile gains: an `/openapi.json`
  describing at least one GET operation with a query parameter and one POST
  operation, both on paths **not linked from any HTML page**; a page with a
  cross-origin script tag missing `integrity`; a link carrying `;jsessionid=`;
  and a body leaking a `10.x` address in an HTML comment. The hardened profile
  gains the safe equivalents. Integration tests assert the findings on one
  profile and **zero** on the other, and that an OpenAPI-seeded endpoint yields
  an injection finding.
- **Docs.** Header auth folded into `docs/authenticated-scanning.md`; a new
  `docs/api-scanning.md` for the OpenAPI import (what it extracts, the
  limitations — JSON only, no leaf-level JSON-body fuzzing, local `$ref`s only);
  the four checks in `docs/`; README coverage row `v0.13`; `CLAUDE.md` and
  `specs/README.md` updated.

## Non-goals

- **YAML OpenAPI documents.** `--openapi` accepts JSON only in 013 — a local
  `.json` file or a URL returning `application/json`. Adding YAML means a new
  runtime dependency (`pyyaml`), which breaks the "no new runtime dependency
  since spec 004" line. YAML support is a documented fast-follow; a user can
  convert with any tool in the meantime (Resolved decision 2).
- **Leaf-level JSON request-body fuzzing.** A body operation's JSON is
  synthesized and sent for the baseline, but its individual string / number
  leaves do **not** become injection points in 013. That needs a new
  `InjectionPoint` source with JSON-path addressing and a raw-body
  `build_request` path — a separate, larger change. 013 seeds query and path
  parameters and form-urlencoded body fields (Resolved decision 1).
- **Stateful / automatic login.** No login form submission, no token refresh, no
  OAuth dance. The token is supplied by the user, static, for the whole scan —
  same posture as the spec 007 cookie. (Session-fixation / logout-invalidation
  tests stay deferred — they need a stateful flow, `specs/README.md`.)
- **External `$ref` resolution.** Only local pointers (`#/components/…`,
  `#/definitions/…`) are followed. A `$ref` to another file or a URL is skipped
  with a warning (Resolved decision 6).
- **GraphQL schema import**, **Postman collections**, **HAR files**, **API
  Blueprint / RAML** — OpenAPI / Swagger only.
- **New HTTP verbs for the injection pass.** The engine still fuzzes only `GET`
  and `POST` (spec 006 ADR). A `PUT` / `PATCH` / `DELETE` operation from the
  import is recorded but not exercised (RNF-07).
- **Response-schema validation** / contract testing / spec-conformance checks.
  The import is a *seed source*, not an oracle.
- **Web API / dashboard changes.** Engine + CLI only, following specs 005 / 006
  / 009 / 011 / 012. New check ids and the new category surface automatically
  through `list-checks` and the existing `meta` route (Resolved decision 7).
- **Client-Side / DOM-based mixed content**, **CSP `upgrade-insecure-requests`
  interplay**, **HSTS-preload cross-checks** — `content.mixed` is a static HTML
  subresource-scheme check only.
- **Parameter mining / brute-forcing endpoints.** Only operations the OpenAPI
  document actually declares are seeded.
- **`content.sri.missing` for same-origin resources.** SRI's value is for
  third-party CDNs; a same-origin script without `integrity` is not flagged
  (RNF-06).

## Personas

| Persona | Needs from 013 |
|---|---|
| **API developer** | "Scan my authenticated REST API." — `--header "Authorization: Bearer $TOKEN" --openapi ./openapi.json --mode active` reaches every declared endpoint and fuzzes its parameters. |
| **Security-conscious developer** | The four passive findings on a normal `webvigil scan` — a CDN script with no SRI, an `http://` image on an HTTPS page, a `jsessionid` in a link, an internal IP in a comment. |
| **Pentester / consultant** | On an authorized engagement, point WebVigil at the client's Swagger doc with the engagement's bearer token and get an injection sweep of the whole surface in one run. |
| **CI pipeline author** | `webvigil scan "$STAGING" --openapi "$STAGING/openapi.json" --header "Authorization: Bearer $CI_TOKEN"` — the token never lands in the archived JSON report or the CI log. |

## Functional requirements

### Header / bearer authentication

**RF-01 — `[auth] headers` config field**
- **Given** a `webvigil.toml` with `[auth] headers = ["Authorization: Bearer abc123", "X-Tenant: acme"]`, **when** the config loads, **then** each entry is validated as a `Name: Value` pair (a non-empty token name before the first `:`, a `:` present; the value may be empty and may itself contain `:`), and an invalid entry is a `ConfigError`.
- **Given** the field is unset, **then** it defaults to an empty list (an unauthenticated scan), exactly like `[auth] cookies`.
- **Given** an entry whose name (case-insensitive) is `Host` or `Content-Length`, **then** it is rejected — these are computed by the transport and a user override would corrupt the request. `Cookie` is allowed but `--cookie` / `[auth] cookies` is the documented path (Resolved decision 8).

**RF-02 — `--header` CLI option**
- **Given** `webvigil scan <url> --header "Authorization: Bearer abc" --header "X-API-Key: k"`, **when** the config is built, **then** the passed values override `[auth] headers` from the file (whole-list replace, like `--cookie`), and each is validated as in RF-01.
- **Given** `--header` is not passed, **then** the file value (or the empty default) stands.

**RF-03 — Host-gated attachment**
- **Given** configured auth headers, **when** `HttpClient` issues a request whose host **equals the target host**, **then** every configured header is added to the request (a header the caller already set for that request is not overwritten by an `[auth]` entry of the same name — the caller's value wins, so a detector that deliberately sets `Authorization` is not clobbered).
- **Given** a request whose host is **not** the target host (an out-of-scope asset the scope allows, a cross-host redirect), **then** **no** configured auth header is attached — identical to the spec 007 cookie rule.

**RF-04 — Secrecy**
- **Given** a completed scan, **then** no configured header **name or value** appears in: the canonical JSON report, any other reporter's output, the scan metadata, a warning string, a `CheckError` message or traceback, or any finding's evidence.
- **Given** the scan summary and metadata, **then** `metadata.authenticated` is `True` when **either** `[auth] cookies` **or** `[auth] headers` is non-empty, and the CLI summary reports the header count the way it already reports the cookie count — a count only, never the content.

### OpenAPI / Swagger import

**RF-05 — `--openapi` / `[scan] openapi`**
- **Given** `--openapi ./openapi.json` (a readable local JSON file) **or** `--openapi https://<target>/openapi.json` (an **in-scope** URL that returns JSON), **when** the scan starts, **then** the document is loaded before the crawl and its operations are used as seeds (RF-09).
- **Given** an `--openapi` URL that is **out of scope**, **then** the scan fails with a clear operational error before any request — the engine talks only to the target (RNF-03).
- **Given** a file that does not exist, is not valid JSON, or is JSON but not a recognizable OpenAPI / Swagger document (no `openapi:` and no `swagger:` key), **then** the scan fails with a clear operational error — the user explicitly asked for it, so a silent skip would be wrong (Resolved decision 5).
- **Given** a document that parses but yields **zero** usable operations (all filtered, all external `$ref`, empty `paths`), **then** the scan **continues** and records a warning.

**RF-06 — Version coverage**
- **Given** an OpenAPI **3.0.x** or **3.1.x** document, **then** components are resolved from `#/components/{schemas,parameters,requestBodies,…}` and the base URL from `servers[0].url`.
- **Given** a **Swagger 2.0** document, **then** components are resolved from `#/definitions` and `#/parameters`, and the base URL from `schemes[0]` + `host` + `basePath`.
- **Given** a `servers[0].url` (or `host`) that names **a different host** than the target, **then** the path is still taken but resolved against the **target origin**, with a warning that the document's server was overridden.
- **Given** a relative `servers[0].url` (e.g. `/api/v2`), **then** it is joined to the target origin.

**RF-07 — Operation extraction**
- **Given** each `(path, method)` in `paths`, **when** the method is one WebVigil acts on, **then** an operation record is produced with: the HTTP method, the resolved absolute URL with `{templated}` path segments filled from their parameter's synthesized value, the `in: query` parameters (name + synthesized value), and — for a body method — a synthesized request body (RF-08).
- **Given** a parameter or schema node that is a **local `$ref`** (`#/components/…` / `#/definitions/…`), **then** it is resolved (one level of nesting is enough for the common case; a cycle is broken and a placeholder used).
- **Given** an **external `$ref`** (anything not starting `#/`), **then** that node is skipped and a warning is recorded (Resolved decision 6).
- **Given** `in: header` or `in: cookie` parameters, **then** they are ignored — authentication is the `--header` path, not the import's job.
- **Given** a parameter with no `example` / `default` / `enum`, **then** its value is a deterministic type-based placeholder (`string` → `"wv"`, `integer` → `1`, `boolean` → `true`, `array` → one element, `object` → `{}`), so the request is well-formed.

**RF-08 — Request-body synthesis**
- **Given** a body operation whose body media type is `application/x-www-form-urlencoded`, **then** the synthesized fields become `InjectionPoint`s (`source = "openapi"`) the same way form fields do (RF-09).
- **Given** a body operation whose body media type is `application/json`, **then** a minimal JSON object is synthesized from the schema (required properties, values per RF-07) and sent with the baseline request, but its **leaves are not enumerated as injection points** in 013 (Resolved decision 1) — a documented limitation.
- **Given** any other media type (`multipart/form-data`, `application/xml`, …), **then** the body is not synthesized; the operation still contributes its query and path parameters.

**RF-09 — Seeding the crawl and the injection pass**
- **Given** the extracted GET operations, **then** their URLs are added to the crawler's queue as seeds — scope-guarded, robots-gated like any crawl URL, counted in `pages_scanned`, and subject to `max_pages`. A URL already discovered by the HTML crawl is not fetched twice.
- **Given** the extracted GET and POST operations, **when** the scan is Active and an injection check is selected, **then** their query and path parameters (and form-urlencoded body fields, RF-08) are enumerated as `InjectionPoint`s, de-duplicated against the crawl-derived points by `InjectionPoint.key`, and tested by the existing detectors under the existing shared `ActiveBudget`.
- **Given** an operation whose `path` or `operationId` matches `_EXCLUDE_FORM_RE` (login / logout / delete / password / checkout / …), **then** it is **not** fuzzed (its parameters are not enumerated) — mirrors the form-exclusion rule (RNF-07).

**RF-10 — Bounded import**
- **Given** `[scan] openapi_max_operations` (default 150), **when** the document declares more acted-on operations than the cap, **then** the first `N` (stably ordered by path then method) are seeded and a warning names the total.
- **Given** the seeded GET operations, **then** they still count against `max_pages` — the import cannot make the crawl unbounded.

### Passive checks

**RF-11 — `content.sri.missing`**
- **Given** an OK HTML page, **when** it has a `<script src>` or `<link rel="stylesheet">` (or `rel="preload"` / `rel="modulepreload"` with `as` script/style) whose resolved URL is **cross-origin** to the page and which has **no `integrity` attribute**, **then** the check emits one MEDIUM finding per distinct resource URL (`Category.CONTENT`, `cwe = (353, 1104)`, `confidence = HIGH`).
- **Given** a cross-origin subresource that **has** `integrity` but **no** `crossorigin` attribute (the integrity check silently cannot run), **then** the check emits a MEDIUM finding noting the missing `crossorigin`.
- **Given** a **same-origin** subresource with no `integrity`, **then** **no** finding (RNF-06).
- **Given** the same resource URL on several pages, **then** it is reported once (dedup by resource URL).

**RF-12 — `content.mixed`**
- **Given** an OK HTML page **served over `https://`**, **when** it references a subresource over plain `http://` — `<script src>`, `<link href>`, `<img src>`, `<iframe src>`, `<form action>`, `<video>/<audio>/<source src>`, `<object data>`, `<embed src>` — **then** the check emits one finding per distinct `http://` URL (`Category.CONTENT`, `cwe = (319,)`): MEDIUM for active content (`script`, `link`, `iframe`, `form`, `object`, `embed`), LOW for passive content (`img`, `video`, `audio`).
- **Given** a page served over `http://`, **then** the check does not run for that page (there is no downgrade to flag).
- **Given** a `//host/path` protocol-relative URL, **then** it is **not** mixed content (it inherits `https`).

**RF-13 — `disclosure.session-id-in-url`**
- **Given** a session-token-shaped key — `jsessionid`, `phpsessid`, `aspsessionid`, `asp.net_sessionid`, `sid`, `sessionid`, `session_id`, `session`, `auth`, `authtoken`, `access_token`, `token`, `apikey`, `api_key`, `cfid`, `cftoken` — appearing as a **query parameter** or a **`;name=value` path parameter** in: a discovered page's own final URL, an `<a href>` target, a `<form action>`, or an out-of-scope redirect `Location` — **then** the check emits one MEDIUM finding per distinct `(key, location)` (`Category.DISCLOSURE`, `cwe = (598,)`), with the **value redacted** in the evidence.
- **Given** the key appears only in a request the scanner itself crafted (e.g. an OpenAPI-synthesized `token` parameter), **then** it is **not** flagged — only URLs the target produced count.

**RF-14 — `disclosure.private-ip`**
- **Given** an OK response body, **when** it contains an IP literal in a private range — RFC-1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), IPv6 loopback (`::1`) or unique-local (`fc00::/7`) — in an HTML comment, a JSON value, an inline script, or an error page, **then** the check emits one LOW finding per distinct address (`Category.DISCLOSURE`, `cwe = (200,)`), with surrounding context redacted per the existing disclosure redaction.
- **Given** the address is the **target's own resolved host** (a scan of `http://10.0.0.5/`), **then** it is **not** flagged.
- **Given** more than a small cap (e.g. 10) of distinct private addresses on one page, **then** the first `N` are reported and the finding notes the total (a config-dump page should not produce 200 findings).

**RF-15 — `Category.CONTENT` and `list-checks`**
- **Given** the `Category` `StrEnum`, **then** it gains a `CONTENT = "CONTENT"` member with a docstring line.
- **Given** `webvigil list-checks`, **then** the four new ids appear with their category (`CONTENT` / `DISCLOSURE`), `passive`, and their default severity.
- **Given** `[checks] disabled = ["content.mixed"]` (etc.), **then** that check does not run — standard suppression.

### Fixture app and tests

**RF-16 — Fixture endpoints**
- **Given** the fixture app's **insecure** profile, **then** it adds: `GET /openapi.json` returning a small valid OpenAPI 3.1 document that declares at least one `GET` operation with a query parameter and one `POST` operation, on paths **not linked from any HTML page**, where the `GET` operation's handler is vulnerable to one existing injection class (so the seeded scan produces a finding); an HTML page with a cross-origin `<script src>` and no `integrity`; an `<a href>` carrying `;jsessionid=…`; and a page whose body has `<!-- backend: 10.1.2.3 -->`.
- **Given** the **hardened** profile, **then** the equivalent endpoints are safe: SRI present with `crossorigin`, all subresources same-origin or `https`, no session id in any URL, no private IP in any body, and the OpenAPI operations' handlers validate input.

**RF-17 — Integration coverage**
- **Given** an Active scan of the insecure profile with `--openapi <fixture>/openapi.json`, **then** an injection finding is present for the seeded operation's parameter (an endpoint no HTML linked), and `pages_scanned` reflects the seeded GET operation.
- **Given** a Passive scan of the insecure profile, **then** `content.sri.missing`, `content.mixed` (using a synthesized https page in unit tests; see Open questions), `disclosure.session-id-in-url`, and `disclosure.private-ip` each fire; **given** the hardened profile, **then** none of the four fire.
- **Given** any scan with `--header "Authorization: Bearer secret-xyz"`, **then** `"secret-xyz"` and `"Authorization"` appear **nowhere** in the JSON report (asserted).

**RF-18 — Unit coverage**
- Header attachment: host-gated on / off, caller value not overwritten, secrecy (a report render with headers set contains neither name nor value).
- OpenAPI parser: 3.0 / 3.1 / 2.0 base-URL resolution; local `$ref` resolution and a broken cycle; external `$ref` skipped with a warning; server-host mismatch → target origin + warning; malformed / non-OpenAPI JSON → error; `openapi_max_operations` cap → warning; auth/destructive `operationId` excluded.
- Each passive check's branches, including the RNF-06 negatives (same-origin SRI, `http` page for mixed content, target's own host for private-ip, scanner-crafted URL for session-id).

### Reporting

**RF-19 — Reporters unchanged**
No reporter gains a field or a section. The four checks flow through the same
`Check.finding` → `Finding` path; `Category.CONTENT` rides the existing
`category` string; CWE ids ride the existing `cwe` field. A saved canonical JSON
re-renders offline exactly as before.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.http.client` (auth attach), `webvigil.crawler`
(`openapi.py` + a seeding hook), `webvigil.checks.injection.points` (a new
`source`), `webvigil.checks.content` (new package), and
`webvigil.checks.disclosure` (two checks). **No new runtime dependency** —
OpenAPI parsing is `json` + hand-rolled local `$ref` resolution; the checks use
`selectolax` + `re`. Nothing imported from `webvigil.cli` / `webvigil.api` /
`web/`. `import-linter` contracts unchanged.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy`
covering every new module. No `web` gate work (engine + CLI only).

**RNF-03 — No new egress, no infrastructure**
The engine still makes outbound requests **only to the target host**. `--openapi`
with a URL fetches exactly one in-scope document; an out-of-scope URL is refused
(RF-05). A local `--openapi` file is read, not fetched. `--header` values go
only to target-host requests (RF-03). No collaborator, no third-party service,
no cost.

**RNF-04 — Secret handling**
`[auth] headers` gets the same treatment the spec 007 `[auth] cookies` field
gets: attached at the transport, never serialized into `ScanResult` / reports /
metadata / logs / warnings / evidence. A dedicated test asserts a bearer token
does not leak into any reporter's output.

**RNF-05 — Bounded work**
OpenAPI seeding respects `max_pages` (GET seeds), the injection `request_budget`
/ `max_injection_points` (parameters), and `openapi_max_operations`. Every cap
hit is a scan **warning**, never an error.

**RNF-06 — Determinism and false-positive discipline**
- Same document + same target responses → identical seeds, points, ordering, and
  findings across runs (synthesized values are deterministic, operations sorted).
- `content.sri.missing` never fires on a same-origin resource.
- `content.mixed` never fires on an `http://`-served page or a protocol-relative
  URL.
- `disclosure.private-ip` never fires on the target's own host, and is capped
  per page.
- `disclosure.session-id-in-url` fires only on URLs the target produced, never on
  a scanner-crafted request.
- The hardened fixture profile yields zero findings for all four checks.

**RNF-07 — Non-destructive**
The injection pass still issues only `GET` and `POST` (spec 006). A `PUT` /
`PATCH` / `DELETE` operation from the import is recorded but never sent. An
auth-/destruction-shaped operation is not fuzzed. GET seeds are plain reads.
Header auth changes request headers, nothing else.

**RNF-08 — Python support**
CPython 3.12 and 3.13 (existing CI matrix).

**RNF-09 — Docs**
`docs/authenticated-scanning.md` gains a "Header and bearer authentication"
section (the flag, the host-gating, the secrecy guarantee, cookie vs header). A
new `docs/api-scanning.md` covers the OpenAPI import: what it extracts, how
seeding works, and the explicit limitations — **JSON only** (no YAML), **no
leaf-level JSON-body fuzzing**, **local `$ref`s only**, **GET/POST only**.
`docs/` documents the four checks. `README.md` gains the `v0.13` coverage row;
`CLAUDE.md` the layer-2/3 paragraphs and `Estado` line; `specs/README.md` the
roadmap row → `done`. Spec 013 moves `draft → approved → in progress → done`.

## Resolved during requirements

Settled with Ryan on 2026-09-08 (three via `AskUserQuestion`, the rest proposed
for approval):

1. **OpenAPI depth: endpoints + query/path parameters.** The import seeds
   operation URLs and registers query + path parameters (and form-urlencoded
   body fields) as injection points. A JSON request body is synthesized and sent
   for the baseline but its leaves are **not** injection points in 013 —
   leaf-level JSON fuzzing needs a new `InjectionPoint` source and is a separate
   spec. *(answered)*
2. **`--openapi` accepts JSON only.** A local `.json` file or an in-scope URL
   returning JSON. No new runtime dependency (`pyyaml` would break the
   no-new-dependency line held since spec 004). YAML is a documented fast-follow.
   *(answered)*
3. **Header auth is generic `--header "Name: Value"`, repeatable.** Any header —
   `Authorization: Bearer …`, `X-API-Key: …`, `X-Auth-Token: …`. `[auth]
   headers` list. Same host-gating and secrecy discipline as the spec 007
   cookie. *(answered)*
4. **The four passive checks land together in 013**, not split: `content.sri.
   missing`, `content.mixed`, `disclosure.session-id-in-url`,
   `disclosure.private-ip`. A new `Category.CONTENT` holds the two
   HTML-subresource checks. *(proposed — design may fold `content.mixed` under
   `Category.TLS` instead; see Open questions.)*
5. **`--openapi` parse failure is a hard error** before the scan runs (the user
   explicitly asked for the import). A document that parses but yields zero
   usable operations is a **warning**, and the scan continues.
6. **Only local `#/…` `$ref`s are resolved.** An external `$ref` (another file
   or a URL) is skipped with a warning — resolving it would mean more file reads
   or more egress.
7. **Engine + CLI only** — no Web API / dashboard work, following specs 005 /
   006 / 009 / 011 / 012. New check ids and `Category.CONTENT` surface
   automatically through `list-checks` and the existing `meta` route.
8. **`--header` reserves `Host` and `Content-Length`** (rejected — the transport
   computes them). `Cookie` via `--header` is allowed but `--cookie` is the
   documented path.
9. **`content.mixed` sits under `Category.CONTENT`** (with `content.sri.missing`)
   — detection is HTML parsing and the two subresource checks group cleanly.
10. **`content.mixed` is tested offline** against a synthesized `Page` with an
    `https://` URL in unit tests; the integration test asserts only the negative
    (no false positive on the `http://` fixture).
11. **OpenAPI `$ref`s resolve fully with a cycle guard** — a `$ref` chain is
    followed to the end; a cycle is broken and a type-based placeholder used at
    the break.

Approved on 2026-09-08 (decisions 9-11 from the requirements open questions).
