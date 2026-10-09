---
feature: HAR import — seed the crawl and the injection points of a single-page application from recorded browser traffic
status: done
date: 2026-10-09
related:
  - 021-har-import/requirements.md
  - 013-auth-and-api-surface/design.md
  - 018-post-form-crawl/design.md
  - 019-automated-login/design.md
origin: conception
---

# 021 — HAR import — design

## Overview

The HAR importer is the second *seed source*, next to `--openapi`. It turns a file into the same
`ApiOperation` records the OpenAPI importer returns, and from there everything already exists: the GET
operations seed the crawl (`extra_seeds`), the POST operations wait for the `POST` phase of spec 018, and
`enumerate_points` turns every operation into injection points. The new code is one module that reads and
*sanitises* a file, plus a handful of one-line wirings (ADR-1).

```
CLI --har / [scan] har
        │
        ▼
Orchestrator.run
  1. _log_in                                   (unchanged)
  2. _load_openapi        → list[ApiOperation] (unchanged, source="openapi")
  3. _load_har   (new)    → HarImport          crawler.har.load_har(path, target, max)
        merge_operations(openapi, har)         the OpenAPI operation wins on a tie
        one summary warning + the "looks authenticated" warning
  4. Crawler(extra_seeds=[op.seed_url …GET], post_operations=[…POST])   (unchanged call)
  5. … every pass as today; enumerate_points(operations=…) now sees source="har" points
```

What the importer does to one entry, in order: it is **well-formed** → **http(s) on the target's scheme
and in scope** → **GET or POST** → **not a static asset** → **not an auth / state-changing path**. The
first rule an entry fails decides its tally (the summary of RF-11). An entry that passes becomes an
operation whose query and body are **sanitised** (secret-named values and blobs replaced, a JSON body
reduced to its shape) before anything is stored. No header, cookie or response body is read at any point
(ADR-3).

The importer never opens a socket: `load_har` is a synchronous function over a local file. All request
gates (scope guard, rate limiter, Active Mode, `--submit-post-forms`, `robots.txt`) stay where they are
and apply to a HAR operation exactly as they apply to an OpenAPI one (RF-10).

## Module layout

```
src/webvigil/crawler/
├── har.py          NEW  load_har, HarImport, HarTally, merge_operations (+ private parsing helpers)
├── openapi.py      ApiOperation gains `source` and `seed_url`; nothing else changes
├── jsapp.py        script_app_warning(pages, *, har=False): the sentence also names --har
└── safety.py       unchanged (looks_unsafe_operation is reused as is)

src/webvigil/core/errors.py          + HarError(WebVigilError)
src/webvigil/core/config.py          ScanSection.har, har_max_operations
src/webvigil/core/orchestrator.py    _load_har next to _load_openapi; merge; seeds use op.seed_url
src/webvigil/checks/injection/
├── points.py       _operation_points: the point's source is operation.source (was the literal "openapi")
└── models.py       InjectionPoint.source docstring: "har" joins "openapi"
src/webvigil/cli/app.py              --har PATH → _build_config → scan_overrides["har"]
webvigil.example.toml, docs/api-scanning.md, docs/web-api.md (the field is absent), CHANGELOG.md, CLAUDE.md
tests/fixtures/app.py                one route the HAR reaches and the crawl cannot (both profiles)
```

`webvigil.api` and `web/` are untouched: `ScanCreate` has no `har` field and `build_scan_config` copies a
fixed list of keys (RF-12, "Web API" below). `pyproject.toml` is untouched (RNF-01).

## Data model

```python
@dataclass(frozen=True, slots=True)
class ApiOperation:
    ...                              # the eight existing fields, unchanged
    source: str = "openapi"          # "openapi" | "har": where the operation came from

    @property
    def seed_url(self) -> str:
        """What the crawler GETs for this operation."""
        # openapi: self.url (the query stays out, as in spec 013)
        # har:     self.url + "?" + urlencode(self.query) when the query is not empty
```

Every existing construction site stays valid (the default). The injection point's `source` becomes
`operation.source`, so an imported parameter is `"har"` and the existing `"openapi"` points are
byte-identical.

```python
@dataclass(slots=True)
class HarTally:
    entries: int = 0        # entries read (after the entry cap)
    out_of_scope: int = 0   # another host or scheme, or a non-http(s) URL
    static: int = 0         # image, font, stylesheet, script, media, source map
    other_method: int = 0   # not GET or POST
    unsafe: int = 0         # login / logout / delete / checkout … (looks_unsafe_operation)
    malformed: int = 0      # no usable request, URL or shape
    duplicate: int = 0      # same key as an operation already kept
    seeded_get: int = 0
    seeded_post: int = 0

@dataclass(frozen=True, slots=True)
class HarImport:
    operations: list[ApiOperation]   # stably ordered, capped, source="har"
    warnings: list[str]              # cap warnings and the "no usable entry" warning
    tally: HarTally
    authenticated: bool              # an in-scope entry carried a Cookie / Authorization header
    def summary(self) -> str: ...    # the RF-11 line; zero categories are left out
```

`ScanSection` gains `har: str | None = None` and `har_max_operations: int = Field(default=150, gt=0)`.

## Components

### `load_har(path, *, target, max_operations) -> HarImport`

1. **The file.** `path` containing `://` → `HarError` ("--har takes a local file"). Not a file → `HarError`
   naming the path. `stat().st_size` over 64 MiB → `HarError` that says so and suggests exporting
   without response bodies. Then `read_bytes().decode("utf-8-sig")` (a BOM is tolerated), `json.loads`;
   `ValueError` or `RecursionError` → `HarError("not a HAR file")`. Nothing is read from disk twice.
2. **The shape.** `doc["log"]["entries"]` must be a list, else `HarError("not a HAR file")`. Only the
   first 20,000 entries are walked; the rest are one warning ("read the first 20000 of N entries").
3. **Per entry** (`_classify`), returning an `ApiOperation` or the name of a tally field:

   | Step | Looks at | Fails → |
   |---|---|---|
   | well-formed | `request` is a dict; `method` and `url` are strings; URL ≤ 2048 characters; every parameter name ≤ 128 | `malformed` |
   | URL | `urlsplit`; scheme `http` / `https`; a hostname | `out_of_scope` |
   | scope | `target.in_scope(url)` **and** the scheme equals the target origin's scheme | `out_of_scope` |
   | method | upper-cased `method` in `{GET, POST}` | `other_method` |
   | static | `_is_static(entry)` (below) | `static` |
   | unsafe | `looks_unsafe_operation(op)` on the built operation | `unsafe` |

   The scope step comes before the method step on purpose: "14 other method" must count only entries
   of the target, not every `OPTIONS` preflight to a CDN.
4. **Build** (`_operation`): the URL is rebuilt from `scheme://netloc` **without userinfo**, the path,
   and no fragment. Query pairs come from `request.queryString` (HAR gives them decoded), falling back to
   `parse_qsl(urlsplit.query, keep_blank_values=True)`. A POST body is read from `request.postData`:
   `mimeType` starting `application/x-www-form-urlencoded` → `params`, else `parse_qsl(text)`;
   `multipart/form-data` → `params`, else the text parts of `text` split on the boundary in `mimeType`
   (a part with a `filename` is dropped); `application/json` (or `+json`) → `_json_shape(text)`; any
   other body type → the operation is kept with no body (it is still a route). A POST with no body and
   no query is kept too.
5. **Sanitise** (`_scrub`), applied to every query value and every form field value:
   a value longer than 256 characters, or whose parameter name matches `_SECRET_NAME_RE`, becomes the
   placeholder `"wv"` (the one `--openapi` uses for a string). The name is kept: it is still an
   injection point.
6. **Dedup, order, cap.** Operations are kept in file order, dropping a later one with the same
   `_key` (method, `url_template`, query names, body field names, `body_json`; `duplicate` is counted).
   Then `sort(key=(url_template, method, query names))`, and the first `max_operations` are kept with a
   warning for the rest.
7. **Authenticated?** For an in-scope entry only, `authenticated` is set when `request.headers` has a
   header *named* `cookie` or `authorization` (case-insensitive) or `request.cookies` is a non-empty
   list. The loop reads names and the length of a list; the values are never indexed (ADR-3).

### `_is_static(entry)`

In order, the first rule that decides wins: (1) the Chrome-style `_resourceType` (a string):
`document`, `xhr`, `fetch`, `ping`, `eventsource`, `other` → dynamic; `image`, `media`, `font`,
`stylesheet`, `script`, `texttrack`, `manifest` → static. (2) `response.content.mimeType`: a prefix of
`image/`, `font/`, `audio/`, `video/`, or `text/css`, `text/javascript`, `application/javascript`,
`application/font`, `application/wasm` → static; any other non-empty value → dynamic. (3) With neither,
the URL path's extension in a fixed set (`.js .mjs .css .map .png .jpg .jpeg .gif .svg .webp .avif .ico
.woff .woff2 .ttf .otf .eot .mp3 .mp4 .webm .wasm`) → static. Only `request` and the two named fields of
`response` are indexed (ADR-3).

### `_SECRET_NAME_RE` and `_json_shape`

The name is normalised first: camelCase is split (`accessToken` → `access Token`), `_` and `-` become
spaces, then lower-cased. A name is secret-like when a whole word of it is one of `token`, `key`,
`apikey`, `secret`, `password`, `passwd`, `pwd`, `auth`, `authorization`, `session`, `sid`, `jwt`,
`signature`, `otp`, `csrf`, `xsrf`, `credential`, `bearer` (an optional plural `s`). The list is the
RF-07 one plus `csrf`, `xsrf`, `pwd`, `apikey`, `authorization`, `credential` and `bearer`; it errs on
the side of replacing a value (a baseline `wv` is a smaller loss than a leaked token).

`_json_shape(text)` parses the body and returns a JSON *string* whose structure is the body's and whose
leaves are typed placeholders: string → `"wv"`, integer or float → `1`, boolean → `true`, null → `null`.
An array keeps **one** element's shape (an empty one stays `[]`); an object keeps up to 24 keys, to a depth
of 4, and the whole shape is cut off at the size bound `openapi.py` uses for a synthesised body
(`_MAX_BODY_UNITS`). A body that is not valid JSON, or is JSON `null` or a bare scalar, gives
`body_json=None` (the route is kept). Keys keep their names, including a secret-looking key: a name is
not a secret, the value was never stored.

### `merge_operations(primary, secondary) -> list[ApiOperation]`

Returns `primary` unchanged followed by every operation of `secondary` whose `_key` is not in `primary`.
The orchestrator calls it with the OpenAPI list first (RF-01: "the OpenAPI one winning on a tie").

### Orchestrator

```python
openapi_ops = await self._load_openapi(http, target, warnings)
har_ops = self._load_har(target, warnings)            # sync: the file is local
operations = tuple(merge_operations(openapi_ops, har_ops))
crawler = Crawler(http, target, self._config,
                  extra_seeds=[op.seed_url for op in operations if op.method == "GET"],
                  post_operations=[op for op in operations if op.method == "POST"])
```

`_load_har` is a no-op returning `()` when `[scan] har` is unset. Otherwise it calls `load_har`, appends
`har.warnings` and `har.summary()`, and appends **one** more warning when `har.authenticated` and the
scan has no `[auth] cookies`, no `[auth] headers` and no `[auth.login]`:

`the HAR recording looks authenticated, but this scan is not: give it --cookie, --header or --login-url
to reach those routes with a session`

(RF-08: no value, no cookie name, no header name.) The method is called after `_load_openapi` and before
the crawl, so a `HarError` is fatal before a request is sent, like an `OpenApiError`; the CLI already
turns any `WebVigilError` into exit code 4.

### Injection points

`_operation_points` only changes the literal `source="openapi"` of its GET and POST branches to
`source=operation.source`. A HAR operation has no path parameters (resolved decision 4), so
`"openapi-path"` never appears for it. The de-duplication in `_add` is by `InjectionPoint.key`, which
does not include `source`: a parameter the crawl, the OpenAPI document and the HAR all know is one point
(RF-06). A recorded `multipart/form-data` body is imported as `body_fields` and so is **sent
urlencoded**, as for an OpenAPI form (ADR-8).

### The JavaScript-app warning

`script_app_warning(pages, *, har=False)`. The condition is unchanged; the text ends with
`Give it the API with --openapi <file>, or browse the application with the browser's network panel open,
save the traffic as a HAR file and give it with --har <file>`. With `har=True` (a HAR was given and the
crawl is still thin) the second half is left out. The orchestrator passes `har=bool(self._config.scan.har)`.

## Interfaces

- **CLI:** `webvigil scan <url> --har traffic.har [--openapi api.json] [--cookie …]`. `--har PATH` is a
  `str | None` Typer option wired through `_build_config` into `scan_overrides["har"]`, like `--openapi`.
- **Config:** `[scan] har = "traffic.har"`, `har_max_operations = 150`. A `str` path; the CLI value wins.
- **Library:** `load_har(path, *, target, max_operations) -> HarImport`;
  `merge_operations(primary, secondary) -> list[ApiOperation]`; `ApiOperation.source`,
  `ApiOperation.seed_url`; `HarError`.
- **Web API / OpenAPI:** unchanged. `ScanCreate` has no `har` field; pydantic ignores an unknown field of
  a request, and `build_scan_config` copies only `max_pages` and `follow_robots` from the stored options,
  so no request can make the server read a file. `web/openapi.json` does not change.
- **Reports and metadata:** unchanged. The only trace of an import is the summary warning, and the
  `[scan]` table is not written into the result's metadata (verified in the first stage's tasks).

## ADRs

### ADR-1 — Reuse `ApiOperation`; add `source` and `seed_url`

**Decision.** The HAR importer returns `ApiOperation`s, with a `source` field (default `"openapi"`) and a
`seed_url` property.
**Alternatives.** (a) A new `HarEntry` record with its own path in the crawler and the enumerator.
(b) Convert HAR into a fake OpenAPI document and feed `load_openapi`.
**Why.** The crawler's POST phase, `looks_unsafe_operation`, `enumerate_points` and the de-duplication
by `InjectionPoint.key` all take `ApiOperation`; (a) would duplicate three call sites for no behaviour
difference. (b) would round-trip through a format that cannot express a recorded value and would make the
secret rules depend on a document the user never sees.
**Trade-off.** A small widening of a frozen dataclass that three modules import; the default keeps every
existing construction valid, and the OpenAPI points are byte-identical.

### ADR-2 — A HAR GET seed carries its query; an OpenAPI one still does not

**Decision.** `seed_url` returns `url?query` for `source="har"` and `url` for `"openapi"`.
**Alternatives.** Put the query into `ApiOperation.url`; make `seed_url` add the query for both sources.
**Why.** `_operation_points` builds a GET point from `operation.url` plus `operation.query`, so `url`
must stay query-free. An SPA endpoint often answers nothing without its parameters (RF-05), so the HAR
seed needs them. Doing the same for OpenAPI would change what a 1.0 scan requests with `--openapi`, which
RNF-06 forbids in a minor release.
**Trade-off.** The two sources differ in one property. Giving `--openapi` seeds their example query is a
sensible follow-up, recorded for the benchmark repeat (issue #148).

### ADR-3 — The importer indexes only the fields it needs, and reads header names, not values

**Decision.** The parser reads `request.method/url/queryString/postData`, `request._resourceType`,
`response.content.mimeType`, and the *names* of `request.headers` plus the *length* of `request.cookies`.
It never indexes a header value, a cookie, a response body or `timings`. `HarImport.authenticated` is a
`bool`.
**Alternatives.** Read headers and drop the sensitive ones by deny-list; lift the session (resolved
decision 1).
**Why.** A deny-list fails open the day a tool names a header differently; an allow-list of the few
fields needed fails closed, and there is nothing to scrub later. The "looks authenticated" signal needs
only the *presence* of a header, so no value ever enters memory the rest of the engine can reach.
**Trade-off.** The code cannot be generalised to "also import this header" without revisiting the
decision; that is the point.

### ADR-4 — Placeholders by name and size, shapes by type

**Decision.** `"wv"` replaces a value whose name is secret-like or whose length exceeds 256; a JSON body
is reduced to a typed shape.
**Alternatives.** Keep every recorded value; replace every value; detect secrets by entropy.
**Why.** Resolved decision 2: the recorded value is a better baseline (`?id=5` answers where `?id=wv`
may not) but a secret in a finding's location is a leak. A name list is deterministic and explainable;
entropy guesses drift and cannot be tested exhaustively. A JSON body is the commonest SPA shape and the
commonest carrier of personal data, and no JSON leaf is fuzzed (spec 013), so its values buy nothing.
**Trade-off.** A secret under an unlisted name (`?code=…`) is kept as a baseline value. Mitigated by the
256-character bound, by the injection pass sending its own payloads in place of the value, and by the
documented rule; the list can grow without a format change.

### ADR-5 — Scope: the engine's host rule plus the target's scheme, and the entry's own origin

**Decision.** An entry is in scope when `target.in_scope(url)` and the scheme equals the target's. The
operation keeps the entry's own `scheme://host[:port]`.
**Alternatives.** Rewrite every URL onto `target.origin` (what `--openapi` does); require an identical
origin including the port.
**Why.** A SPA's API often listens on another port or subdomain; rewriting would send the request to
the wrong place, and requiring the same port would drop the API. The engine's scope rule is host-based
everywhere; the HAR follows it, and `HttpClient`'s guard still checks every request. Requiring the
target's scheme avoids guessing whether a recorded `http://` request should be upgraded or downgraded.
Userinfo and the fragment are dropped so a `https://user:pass@host/` URL cannot carry credentials into
an operation.
**Trade-off.** A recording of an `http` site scanned as `https` imports nothing and says so in the
summary ("out of scope"); the user fixes the target URL.

### ADR-6 — Fatal for a bad file, soft for a bad entry

**Decision.** `HarError(WebVigilError)` for a missing or too-large file, invalid JSON, or a document
without `log.entries`; exit code `4` through the CLI's existing handler. A malformed entry, an entry
past the cap or an empty result is a counted skip or a warning.
**Alternatives.** Warn and continue on a bad file.
**Why.** The user asked for the import explicitly; a scan that silently ignores `--har` reads as "no
findings" on a surface it never saw. That is the same reasoning as `OpenApiError`. A HAR from a real
browser always has a few entries the importer does not understand, so those must not stop a scan.
**Trade-off.** One more exception class; it is tiny and mirrors the existing one.

### ADR-7 — Order and caps are deterministic and fixed in code, except `har_max_operations`

**Decision.** Stable sort by `(url_template, method, query names)`; 64 MiB, 20,000 entries, 256
characters, 2048-character URL, 128-character name, depth 4 and 24 keys are module constants;
`har_max_operations` is a `[scan]` key.
**Alternatives.** Make every cap a config key.
**Why.** The operation cap is the one a user tunes to the size of their application (as
`openapi_max_operations`); the others bound a hostile file and are not a scanning decision. Fixed
constants keep the surface small and stay "tuned defaults" under `docs/stability.md`.
**Trade-off.** A genuinely huge but benign HAR needs re-exporting without response bodies.

### ADR-8 — Multipart bodies import as form fields

**Decision.** The text parts of a recorded `multipart/form-data` body become `body_fields`, which the
crawler and the injection pass send urlencoded.
**Alternatives.** Add a `body_kind` field to `ApiOperation` and a multipart encoder in the injection
builder.
**Why.** `--openapi` has the same limit today and the injection pass's `build_request` has no
multipart builder; widening both is its own change. Most SPA POSTs are JSON.
**Trade-off.** A server that parses only multipart rejects the submission; the page is kept (an error
page is informative, as in spec 018) and the limit is documented.

## Impact on existing code

- `ApiOperation` is `frozen=True, slots=True`: adding a defaulted field and a property is source
  compatible; `tests/unit/test_crawler_openapi.py` and the injection tests construct it by keyword.
- `Orchestrator.run`: `extra_seeds` now uses `op.seed_url`, equal to `op.url` for every OpenAPI
  operation, so a scan without `--har` is byte-for-byte what it was (RNF-06).
- The four stub orchestrators of the unit tests that replace the crawler need no change (the `Crawler`
  interface does not grow).
- `script_app_warning` gains a keyword; its tests change the expected text.
- `docs/api-scanning.md` gains a "HAR import" section (how to record in Chrome / Firefox / Burp / ZAP,
  what is skipped and why); `docs/web-api.md` says the field is not exposed; `CLAUDE.md` gets a spec 021
  paragraph; `CHANGELOG.md` "Added".

## Risks

- **A recording is data the user does not control.** Hostile or oversized JSON is bounded by the file
  size, the entry count, the string lengths, the shape depth, and a `RecursionError` guard (RNF-02). The
  64 MiB cap does not bound the memory `json.loads` builds from it (several times the file size); the
  stdlib has no streaming parser and a dependency is out of scope (RNF-01). The error for an oversized
  file names the fix.
- **A secret under an unlisted parameter name is kept.** ADR-4. The summary and the docs say which
  names are replaced; a recording of a production session should be re-recorded against a test account.
- **A recorded GET with side effects.** A GET such as `/api/cart/add?id=3` passes the vocabulary filter
  and is requested by the crawl, in Passive Mode too. This is the OpenAPI situation, already accepted;
  the filter and the user's choice of what to record are the mitigations, and the docs say to record a
  read-only walk.
- **GraphQL.** A recorded query becomes a JSON shape with `"query": "wv"`, which the server rejects. The
  route is still seeded; fuzzing inside a query is a non-goal.
- **A recording from another environment.** Entries on another host are out of scope; entries on the
  target host that no longer exist answer `404` pages the crawl keeps, as for a stale OpenAPI.

## Test strategy

Follows `specs/README.md`: the logic is tested in unit by calling functions with built inputs;
integration attaches to the shared full scan; no determinism test of its own; about one test line per
`src/` line (~330 in `har.py` plus ~60 elsewhere).

- **Unit — `tests/unit/test_crawler_har.py`** (HAR documents built as dicts, written under `tmp_path`):
  - one trimmed, real-shaped document per tool of RF-02 (Chrome, Firefox, Burp, ZAP, mitmproxy, Safari),
    as a parametrized table: each loads and yields the same operations;
  - each filter and its tally: foreign host, other scheme, `ws:` / `data:`, static by `_resourceType`,
    by mime, by extension (and the `xhr` + `.js` case), `PUT` / `OPTIONS`, unsafe path, malformed entry,
    duplicate;
  - the build: query kept and in order, userinfo and fragment dropped, urlencoded / multipart / JSON /
    other body, a multipart file part dropped, the JSON shape (types, array, depth, keys, size bound,
    invalid JSON, scalar JSON);
  - the secret rules, parametrized over names (`token`, `access_token`, `accessToken`, `API-Key`,
    `password`, `sid`, `csrf`) and a negative table (`tokenizer` is not a word match, `monkey`, `q`,
    `limit`), plus the 256-character bound;
  - `authenticated`: set by a `Cookie` header, an `Authorization` header or `request.cookies`; not set by
    an out-of-scope entry's cookie; and the **adversarial file** (RNF-05): a session cookie, a bearer
    token, a `?token=` URL, a password in a form body, a header named `X-Api-Key`, an `Authorization` in
    a response — the serialised `HarImport` (operations, warnings, summary) contains none of the
    recognisable strings;
  - the caps: file size (a sparse file over the limit → `HarError` without reading it), the entry cap
    with its warning, `max_operations` with its warning, an empty result's warning, `RecursionError`;
  - the errors: a URL source, a missing path, a directory, invalid JSON, JSON without `log.entries`;
    a BOM is tolerated; the same file twice gives the same order and summary;
  - `merge_operations`: the primary wins on a tie, the rest is appended, nothing is duplicated.
- **Unit — existing files:** `test_crawler_openapi.py` (`source` / `seed_url` of an OpenAPI operation);
  injection points (`source="har"` for a GET and a POST operation, and one point for a parameter the
  crawl and the HAR share); `test_crawler_jsapp.py` (the new sentence, with and without `har=True`);
  `test_config.py` (the defaults, the TOML keys, `gt=0`); `test_cli.py` (`--har` overrides the TOML);
  `test_orchestrator.py` (HAR operations reach the crawler as seeds with their query and as
  `post_operations`; the merge with OpenAPI; the two warnings; a `HarError` is fatal before any
  request); `tests/api/test_mapping.py` (a stored `har` option never reaches the config) and
  `test_scans.py` (a `har` field in the request body is ignored).
- **Integration — `tests/integration/test_scan_fixture_app.py`** (attached to the full scan; `_full`
  writes a small HAR to `tmp_path`, as it does the OpenAPI document):
  - the fixture route linked from nowhere, named only in the HAR with its recorded query, is in
    `pages_scanned`, and on the insecure profile the reflected-XSS detector hits it with a point whose
    `source` is `har`; on the hardened profile it is reached and reports nothing;
  - the HAR also holds a foreign-host entry, a static asset, a `DELETE`, a login `POST` and an entry with
    `Cookie` / `Authorization` headers and a `?token=` URL: no request reaches the foreign host or the
    login route, and none of the secret strings appears in the JSON, SARIF, Markdown or HTML report of the
    scan;
  - a Passive scan with the same HAR sends no `POST` to a HAR `POST` route; the active scan with
    `--submit-post-forms` posts it once, with a JSON body of the recorded shape;
  - the summary warning carries the right tallies, and the "looks authenticated" warning appears (the
    full scan has `--cookie`, so a second, small scan with the HAR and no auth asserts it).
- **E2E / web:** not needed; no web file changes.
- **Gate:** `ruff → black → mypy → lint-imports → pytest` at the end of each stage; `lint-imports` proves
  `crawler.har` imports nothing from `checks` (RNF-01).

## Fixture app

One new route, `GET /spa/items?name=` (both profiles), linked from no page: the insecure profile reflects
`name` unescaped, the hardened one escapes it. The HAR in `_full` names it with `?name=widget`. The
existing `/login`, the `/transfer`-style routes and the foreign-host URL of the HAR are the "must not be
requested" cases; the fixture's request log (`post_log` of spec 018 and the access log) is where the test
reads what arrived.

## Deviations from the approved design

Recorded here so the design text above stays as approved; the as-built behaviour is below.

1. **The query comes from the URL only.** `request.queryString` is not read. Some exporters leave it
   empty or differently encoded, and the URL always carries the same pairs; indexing one field fewer also
   keeps with ADR-3. `parse_qsl(..., keep_blank_values=True, max_num_fields=100)` gives the same result
   for Chrome, Firefox, Burp, ZAP and mitmproxy documents.
2. **The unsafe-path rule is the union of two vocabularies.** `looks_unsafe_operation` (the `POST` phase
   filter of spec 018) does not know `checkout`, `pay` or `order`, which RF-09 names. `_is_unsafe` therefore
   also applies the OpenAPI importer's `_SKIP_OPERATION_RE`, the vocabulary RF-09 points to. The cost is
   that a `GET /api/order` listing is skipped, as it is for `--openapi`.
3. **The URL-length check follows the scheme check.** A long `data:` or `ws:` URL is "out of scope", not
   "malformed": the design table listed the length check under "well-formed", before the scheme.
4. **The documentation is its own file.** `docs/har-import.md` (a how-to) instead of a section of
   `docs/api-scanning.md`, which gains a pointer. The two modes of the Diátaxis split stay apart, and
   the HAR page has its own recording instructions and secret rules.
5. **The `ApiOperation` fields stay positional-compatible.** `source` has a default, so the unit tests
   that build operations positionally needed no change.

## Implementation notes

- **Where it landed.** `crawler/har.py` is 755 lines, most of it docstrings and the vocabulary tables;
  the logic is `load_har`, `_read_entries`, `_parse_request`, `_is_static`, `_operation`, `_body`,
  `_json_shape` and the secret-name rule. `ApiOperation.source` / `seed_url`, `_operation_points`, the
  orchestrator's `_load_har`, the CLI flag and the `script_app_warning` keyword are the only edits to
  existing code.
- **Tests.** The suite went from 1366 to 1499 collected tests (+133). `test_crawler_har.py` is 664 lines
  against the 755 of `har.py` (0.9); with the fixture routes, the integration harness and the wiring tests
  the added test lines are about 1.3 times the added source lines, over the 1.0 budget of
  `specs/README.md`. The excess is the table-driven filter, secret-name and per-tool cases, which are
  cheap to run, and the new scenarios read the existing shared full scans, so the two slow integration tests
  are the same ones as before (397 s and 194 s).
- **Integration.** The HAR is written once per session by an autouse fixture and passed to the full scan
  through `_full`, so no new full scan was added; the one extra scan is a small Passive one for the "looks
  authenticated" warning and the "Passive sends no `POST`" rule. The new fixture routes are `GET
  /spa/items?name=` (reflects `name` unescaped on the insecure profile) and `POST /spa/notes` (JSON, logged
  in `post_log`); the existing check that the POST phase sends no payload now skips the HAR-shaped body
  (`{"text": "wv"}`) as it skips the OpenAPI one. No budget of the integration config moved.
- **Manual check** (CLI against the fixture served by uvicorn, a hand-made HAR with a `Cookie` header, a
  JSON `POST`, a foreign host, a script and a login): Passive printed `HAR import: 5 entries read, 2
  operations seeded (1 GET, 1 POST); ignored: 1 out of scope, 1 static, 1 unsafe` and the "looks
  authenticated" warning, and sent no `POST`; Active with `--submit-post-forms` added `POST crawl: ... 1 API
  operation` (the recorded JSON shape) and, with the injection budget raised past the default 650 (the
  fixture is dense and starves it), `injection.xss.reflected` on `/spa/items` parameter `name`. The recorded
  session value appeared in neither report. A missing `--har` file exited with code 4.
