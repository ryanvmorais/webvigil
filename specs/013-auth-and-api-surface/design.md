---
feature: Auth width and API surface — header/bearer auth, OpenAPI import to seed points, four missing passive checks
status: done
date: 2026-09-08
related:
  - 001-foundation/design.md
  - 006-active-injection/design.md
  - 007-auth-flows/design.md
origin: conception
---

# 013 — Auth width and API surface — design

> Design notes: [engine boundaries](../../docs/notes/engine-boundaries.md) ·
> [why blind / OAST is not on the roadmap](../../docs/notes/why-not-oast.md) ·
> [false-positive discipline](../../docs/notes/false-positive-discipline.md).

## Overview

013 has **three independent parts**. None adds a new orchestrator pass, a
`Observations` field, a runtime dependency, or an API / dashboard change.

1. **Header / bearer auth.** `[auth] headers` (a `"Name: Value"` list) +
   `--header`. `HttpClient` attaches them to target-host requests next to where
   it already attaches the spec-007 cookie, with the same secrecy discipline. A
   ~10-line change plus the config field and the CLI flag.

2. **OpenAPI / Swagger import.** A new pure module `webvigil.crawler.openapi`
   parses a JSON OpenAPI 3.0 / 3.1 / Swagger 2.0 document into `ApiOperation`
   records. The orchestrator loads it before the crawl and uses it as a **seed
   source**: GET operation URLs are enqueued in the crawler (like sitemap
   seeds); every acted-on operation's query / path parameters (and
   form-urlencoded body fields) are synthesized into `InjectionPoint`s by the
   existing `enumerate_points`. There is **no `OpenApiScanner`** — the import
   feeds the machinery that already exists.

3. **Four passive checks.** `webvigil.checks.content` (new package,
   `Category.CONTENT`): `content.sri.missing`, `content.mixed`.
   `webvigil.checks.disclosure` (new module `leakage.py`):
   `disclosure.session-id-in-url`, `disclosure.private-ip`. All `PASSIVE`, all
   pure functions of `ctx.pages`.

```
Orchestrator.run
  Target.parse → _enforce_active_gate
  async with HttpClient(target, config):          # config.auth.headers attached here
      operations = await _load_openapi(http, target, warnings)   [013]  (fatal on parse error)
      crawler = Crawler(http, target, config, extra_seeds=[op.url for GET ops])   [013]
      pages   = await crawler.discover()           # GET operations now among the pages
      forms   = crawler.forms
      ...
      injection_hits = await _inject(..., operations=operations)  [013]
            InjectionScanner.run
              enumerate_points(pages, forms, operations, max_points=…)  [013]
                 + query / path points and form-body points for each operation
      ...
  checks fan over ctx:
      content.sri.missing / content.mixed          (Category.CONTENT)   [013, NEW]
      disclosure.session-id-in-url / disclosure.private-ip              [013, NEW]
```

## Module layout

| Path | Change | What |
|---|---|---|
| `src/webvigil/core/config.py` | edit | `AuthSection.headers: list[str] = []` + a validator (Name/Value shape; reject `Host` / `Content-Length`) + a `header_pairs` property. `ScanSection.openapi: str \| None = None` and `openapi_max_operations: int = 150` + docstrings. `with_overrides` docstring. |
| `src/webvigil/http/client.py` | edit | store `config.auth.header_pairs`; in `_request_with_retry`, attach each to a target-host request without overwriting a header the caller set (case-insensitive). |
| `src/webvigil/crawler/openapi.py` | **new** (~230 lines) | `ApiOperation` dataclass; `load_openapi(source, *, http, target, max_operations)` → `(list[ApiOperation], list[str])`; local `$ref` resolution with a cycle guard; base-URL reconciliation; deterministic value synthesis; `OpenApiError`. |
| `src/webvigil/core/errors.py` | edit | `class OpenApiError(WebVigilError)`. |
| `src/webvigil/crawler/crawler.py` | edit | `__init__(..., extra_seeds: Sequence[str] = ())`; enqueue them **before** the entry page's own links (an explicit `--openapi` prioritises the API surface); `self._authenticated` also true when `config.auth.headers`. |
| `src/webvigil/checks/injection/points.py` | edit | `enumerate_points(pages, forms, operations=(), *, max_points)` — synthesize query / path / form-body points (`source = "openapi"` / `"openapi-path"`) and merge into the existing dedup / sort / cap. `build_request` — a branch for `source == "openapi-path"` (substitute `value` into the `{name}` URL template). |
| `src/webvigil/checks/injection/engine.py` | edit | `InjectionScanner.__init__(..., operations: tuple[ApiOperation, ...] = ())`; pass to `enumerate_points`. |
| `src/webvigil/core/orchestrator.py` | edit | `_load_openapi(...)` (fatal on `OpenApiError`); `_inject(..., operations=...)`; thread `operations` from `run()`; pass `extra_seeds` to `Crawler`; `metadata.authenticated = bool(cookies or headers)`. |
| `src/webvigil/checks/content/__init__.py` | **new** | package marker + `from webvigil.checks.content import checks  # noqa: F401`. |
| `src/webvigil/checks/content/checks.py` | **new** (~150 lines) | `@register class SriMissingCheck` / `MixedContentCheck` (`Category.CONTENT`, `PASSIVE`). |
| `src/webvigil/checks/disclosure/leakage.py` | **new** (~130 lines) | `@register class SessionIdInUrlCheck` / `PrivateIpInBodyCheck` (`Category.DISCLOSURE`, `PASSIVE`). |
| `src/webvigil/checks/disclosure/__init__.py` | edit | import `leakage`. |
| `src/webvigil/checks/__init__.py` | edit | add `content` to `_load_builtin_checks`. |
| `src/webvigil/core/findings.py` | edit | `Category.CONTENT = "CONTENT"` (one member + a docstring line). |
| `src/webvigil/cli/app.py` | edit | `--header` (`list[str] \| None`, repeatable), `--openapi` (`str \| None`); thread through `_build_config`; `_emit` / `summary` gain `header_count`. |
| `src/webvigil/cli/_render.py` | edit | `summary(..., header_count: int = 0)` — the authenticated-scan line reports cookies **and** headers, counts only. |
| `webvigil.example.toml` | edit | `[auth] headers = []`; `[scan] openapi` / `openapi_max_operations` commented. |
| `tests/fixtures/app.py` | edit | insecure: `GET /openapi.json` (describes `GET /api/search?q=` — reflected-XSS handler, unlinked — and `POST /api/items`), `/legacy` (cross-origin `<script>` no `integrity`, `<a href=".../x;jsessionid=…">`), `/status` (body with `<!-- 10.1.2.3 -->`). Hardened: safe equivalents. |
| `tests/unit/test_config.py`, `test_http_client.py` | edit | `[auth] headers` validation + override; header attachment host-gating + caller-wins + secrecy. |
| `tests/unit/test_crawler_openapi.py` | **new** | the parser: 3.0 / 3.1 / 2.0 base URL; local `$ref` + cycle; external `$ref` → skip + warn; host mismatch → target origin + warn; malformed / non-OpenAPI → `OpenApiError`; `max_operations` cap; auth/destructive `operationId` excluded; value synthesis. |
| `tests/unit/test_injection_points.py` | edit | operation → query / path / body points; dedup vs a crawled query point; `build_request` path-template substitution. |
| `tests/unit/test_checks_content.py` | **new** | `SriMissingCheck` (cross-origin no `integrity` → MEDIUM; `integrity` no `crossorigin` → MEDIUM; same-origin → none; dedup). `MixedContentCheck` (synthesized `https` page + `http://` subresource → MEDIUM/LOW; `http` page → none; `//host` → none). |
| `tests/unit/test_checks_disclosure_leakage.py` | **new** | `SessionIdInUrlCheck` (query + `;jsessionid=`; value redacted; scanner-crafted URL → none). `PrivateIpInBodyCheck` (each range; target's own host → none; per-page cap). |
| `tests/unit/test_cli.py`, `test_findings.py` | edit | `--header` / `--openapi` flags; `list-checks` shows the four ids + `CONTENT`; `Category.CONTENT` round-trips. |
| `tests/integration/test_scan_fixture_app.py` | edit | `--openapi <fixture>/openapi.json` → injection finding on `/api/search` `q` (unlinked); the four passive checks fire on insecure, none on hardened; `--header "Authorization: Bearer <x>"` → `<x>` absent from the JSON report; `pages_scanned` with a seed. |
| `docs/authenticated-scanning.md`, `docs/api-scanning.md` (new), `README.md`, `CLAUDE.md`, `specs/README.md` | edit | header auth section; the OpenAPI import doc; coverage row; layer paragraphs; roadmap row. |

`import-linter`: `webvigil.crawler.openapi` imports only `webvigil.core` +
`webvigil.http`. `webvigil.checks.injection.points` importing
`webvigil.crawler.openapi.ApiOperation` is the **existing** `checks → crawler`
direction (`points.py` already imports `crawler.forms`). No contract changes.
Nothing under `src/webvigil/api/` or `web/`.

## Data model

### `AuthSection` — one new field

```python
cookies: list[str] = []
headers: list[str] = []           # "Name: Value" — spec 013; attached to target-host requests only

@field_validator("headers")
@classmethod
def _check_headers(cls, raw: list[str]) -> list[str]:
    for entry in raw:
        name, sep, _value = entry.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"invalid header {entry!r}: expected 'Name: Value'")
        if name.strip().lower() in {"host", "content-length"}:
            raise ValueError(f"header {name.strip()!r} is computed by the transport and cannot be set")
    return raw

@property
def header_pairs(self) -> tuple[tuple[str, str], ...]:
    """(name, value) for each entry; value keeps any ':' after the first."""
    return tuple((n.strip(), v.strip()) for n, _s, v in (e.partition(":") for e in self.headers))
```

The whole `[auth]` section is already never serialized into `ScanResult` /
reports / metadata (verified for cookies, spec 007). `headers` inherits that.

### `ScanSection` — two new fields

```python
openapi: str | None = None              # a local .json path or an in-scope URL returning JSON
openapi_max_operations: int = 150       # cap on operations seeded from the import
```

### `Category` — one new member

```python
CONTENT = "CONTENT"   # page content: subresource integrity, mixed content
```

Reporters and the dashboard treat `category` as an opaque string (verified 006
RF-19, re-verified for `Category.HTTP` in 012) — **no** API / OpenAPI / UI
change. `list-checks`, the check-catalogue API response, and the dashboard
filter pick it up from the data.

### `ApiOperation` — new (pure dataclass, `webvigil.crawler.openapi`)

```python
@dataclass(frozen=True, slots=True)
class ApiOperation:
    method: str                              # "GET" | "POST"
    url: str                                 # absolute; {path} segments filled with placeholders
    url_template: str                        # absolute; {name} segments kept verbatim
    query: tuple[tuple[str, str], ...]       # (name, synthesized value)
    path_params: tuple[tuple[str, str], ...] # (name, synthesized value)
    body_fields: tuple[tuple[str, str], ...] # form-urlencoded fields, else ()
    body_json: str | None                    # synthesized JSON body, else None
    operation_id: str
```

Never leaves `webvigil.crawler` except as an argument into
`enumerate_points`. No `Observations` field — the import is consumed at
enumeration time, not carried as a scan observation.

### `InjectionPoint` — one new `source` value, no field change

`source` gains `"openapi"` (a query / form-body point synthesized from an
operation — behaves exactly like a `"query"` / `"form"` point) and
`"openapi-path"` (a path-segment point — `base_url` holds the `{name}` template,
`params = ()`; `build_request` substitutes). `key` is unchanged
(`f"{method} {base_url} :: {param}"`), so dedup against crawl-derived points
works.

## Components

### 1. Header auth — `HttpClient` (RF-03, RF-04)

`__init__`: `self._auth_headers = config.auth.header_pairs`.

`_request_with_retry`, right after the cookie block:

```python
req_headers = dict(headers or {})
# spec 007 cookie block …
if self._auth_headers and _host_of(url) == self._target.host:      # spec 013
    present = {k.lower() for k in req_headers}
    for name, value in self._auth_headers:
        if name.lower() not in present:                            # a header the caller set wins
            req_headers[name] = value
```

- **Host-gated** exactly like the cookie: an out-of-scope asset or a cross-host
  redirect gets none of the configured headers.
- **Caller wins** so a detector that deliberately sets `Authorization` (none do
  today, but the contract is clean) is not clobbered.
- **Secrecy** is by omission: nothing in the engine writes request headers into a
  `Finding`, a warning, a `CheckError`, or the metadata. RNF-04 adds a test that
  asserts a bearer token is absent from every reporter's output.

`orchestrator.run`: `authenticated=bool(self._config.auth.cookies or self._config.auth.headers)`.
`crawler`: `self._authenticated = bool(config.auth.cookies or config.auth.headers)`
so the destructive-link heuristic also guards a header-authenticated crawl.

CLI: `--header "Name: Value"` (repeatable) → `auth_overrides["headers"]`
(whole-list replace, like `--cookie`); validated by the same pydantic model.
`_render.summary` line: `Authenticated scan: 1 cookie, 2 headers supplied`
(counts only).

### 2. OpenAPI import — `webvigil.crawler.openapi` (RF-05…RF-10)

```python
async def load_openapi(
    source: str, *, http: HttpClient, target: Target, max_operations: int
) -> tuple[list[ApiOperation], list[str]]:
    doc, warnings = await _fetch_document(source, http=http, target=target)   # OpenApiError on failure
    root = doc
    base = _base_url(doc, target, warnings)                                   # RF-06
    ops: list[ApiOperation] = []
    for path, item in (doc.get("paths") or {}).items():
        item = _resolve(item, root, set())
        shared = item.get("parameters", [])
        for method in ("get", "post"):                                        # RF-07: acted-on verbs
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            op_id = str(op.get("operationId", ""))
            if _EXCLUDE_FORM_RE.search(f"{path} {op_id}"):                    # RF-09: skip auth/destructive
                continue
            params = [_resolve(p, root, set()) for p in shared + op.get("parameters", [])]
            query = _values(params, "query")
            path_params = _values(params, "path")
            body_fields, body_json = _body(op, doc, root, warnings)           # RF-08
            template = _join(base, path)
            url = _fill_path(template, path_params)
            ops.append(ApiOperation(method.upper(), url, template, query,
                                    path_params, body_fields, body_json, op_id))
    ops.sort(key=lambda o: (o.url_template, o.method))
    if len(ops) > max_operations:                                            # RF-10
        warnings.append(f"OpenAPI import seeded the first {max_operations} of {len(ops)} operations")
        ops = ops[:max_operations]
    if not ops:
        warnings.append("OpenAPI document yielded no usable GET/POST operations")
    return ops, warnings
```

- **`_fetch_document`** — a `://` `source` must be `target.in_scope(source)`
  else `OpenApiError` (RNF-03); fetched via `http.get`; a non-200 or a body that
  is not JSON → `OpenApiError`. Otherwise `Path(source)`; not a file → error;
  `json.loads` → `OpenApiError` on `ValueError`. `doc` must have an `openapi`
  **or** `swagger` key → else `OpenApiError` (RF-05).
- **`_base_url`** — 3.x: `servers[0].url` (default `"/"`); 2.0:
  `schemes[0] + "://" + host + basePath`. A relative value joins `target.origin`;
  an absolute value whose host differs from the target's → path kept, host
  replaced with `target.origin`, warning (RF-06).
- **`_resolve`** — follows a `$ref` chain: `"#/..."` walks `root` by the JSON
  pointer; a non-`#/` ref returns `{}` and appends a one-time
  "external $ref skipped" warning; a `$ref` already in the visited set returns
  `{}` (cycle guard, Resolved decision 11).
- **`_values(params, loc)`** — for each `param` with `in == loc`: value =
  `param.get("example")` → `schema.get("example")` → `schema.get("default")` →
  `schema.get("enum", [None])[0]` → a **type-based placeholder** (`string` →
  `"wv"`, `integer`/`number` → `"1"`, `boolean` → `"true"`, else `"wv"`), always
  a `str`. Deterministic — no randomness (RNF-06).
- **`_body`** — 3.x `requestBody.content`: `application/x-www-form-urlencoded` →
  `body_fields` from the schema's properties (same synthesis); else
  `application/json` → `body_json` = `json.dumps` of the synthesized object
  (required props, values as above); else `(), None`. 2.0: `in: formData`
  params → `body_fields`; an `in: body` param's schema → `body_json`.
- **`_fill_path`** — `template.replace("{" + name + "}", quote(value, safe=""))`
  for each path param, so `url` is directly fetchable.

`OpenApiError` is a `WebVigilError`, so `cli.app` already maps it to
`ExitCode.OPERATIONAL` with the message printed — parse failure aborts the scan
before a single crawl request (RF-05, ADR-4).

### 3. Seeding — `Crawler` and `enumerate_points` (RF-09)

`Crawler.__init__(..., extra_seeds: Sequence[str] = ())`. In `discover()`:

```python
queue: deque[str] = deque()
for seed in self._extra_seeds:                 # spec 013 — before the entry page's links
    self._maybe_enqueue(seed, seen, queue)     # scope / logout / destructive guards still apply
self._enqueue_links(pages[0], seen, queue)
self._collect_and_enqueue_forms(pages[0], seen, queue)
await self._enqueue_sitemaps(robots, seen, queue)
```

Seeds are fetched through the same BFS: `max_pages`, `follow_robots`, scope
guard, rate limiter, `[auth]` cookies **and** headers all apply. A GET operation
that returns JSON just becomes a non-HTML `Page` (the four content checks skip
it; `disclosure.private-ip` still reads its body). A seed already discovered from
HTML is de-duplicated by `seen`.

`enumerate_points(pages, forms, operations=(), *, max_points)` — after the
existing query-from-pages and field-from-forms loops:

```python
for op in operations:
    filled_base = _fill_path(op.url_template, op.path_params)   # concrete path for query/body points
    for name, value in op.query:
        _add(InjectionPoint(op.method, _strip_query(filled_base), name, value,
                            _merge(op.query), query=(), source="openapi"))
    for name, value in op.path_params:
        _add(InjectionPoint(op.method, op.url_template, name, value, (), source="openapi-path"))
    for name, value in op.body_fields:                          # POST form-urlencoded
        _add(InjectionPoint("POST", _strip_query(filled_base), name, value,
                            op.body_fields, query=op.query, source="openapi"))
# then the existing points.sort(...) + max_points cap (one place, shared)
```

`_add` skips a `point.key` already seen — so an OpenAPI `q` parameter that the
crawler also discovered by fetching the seed URL is one point, not two.

`build_request` gains one branch:

```python
if point.source == "openapi-path":
    url = point.base_url  # the {name} template
    for name, current in point.params or ((point.param, point.original),):
        url = url.replace("{" + name + "}", quote(current if name != point.param else value, safe=""))
    return point.method, url, [], None
```

`InjectionScanner.__init__(..., operations=())` stores them; `run()` passes them
to `enumerate_points`. Everything downstream — baseline, `_ordered_kinds`, the
detectors, the budget — is unchanged; an OpenAPI point named `url` still
front-loads SSRF, one named `cmd` still front-loads cmdi, etc.

`orchestrator._inject` gains `operations` and forwards it; `_load_openapi` is
called inside the `HttpClient` context before `Crawler` is constructed.

### 4. `content.sri.missing` (RF-11)

```python
@register
class SriMissingCheck(Check):
    id = "content.sri.missing"
    name = "Subresource Integrity (SRI) missing on a cross-origin resource"
    category = Category.CONTENT
    default_severity = Severity.MEDIUM
    cwe = (353, 1104)
    references = ("https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity",)
```

`run`: for each `page` in `ctx.pages` that is `ok` and `is_html`, parse with
`selectolax`; for every `script[src]`, `link[rel~="stylesheet"][href]`,
`link[rel~="preload"|"modulepreload"][href][as=script|style]`:

- resolve the URL against `page.url`; if **same-origin** → skip (RNF-06).
- no `integrity` attribute → MEDIUM finding, title "cross-origin `<tag>` loaded
  without Subresource Integrity".
- `integrity` present, `crossorigin` absent → MEDIUM finding, title "SRI present
  but `crossorigin` missing — the integrity check cannot run".

Dedup by the resolved resource URL (a CDN script on every page → one finding),
`dedup_key = resource_url`, `Location(url=page.url)`, evidence = the element's
outer HTML (trimmed).

### 5. `content.mixed` (RF-12)

```python
@register
class MixedContentCheck(Check):
    id = "content.mixed"
    name = "Mixed content: an HTTPS page loads a resource over HTTP"
    category = Category.CONTENT
    default_severity = Severity.MEDIUM
    cwe = (319,)
```

`run`: for each `ok` + `is_html` page whose **`page.url` starts `https://`**,
parse and walk `script[src]`, `link[href]`, `img[src]`, `iframe[src]`,
`form[action]`, `source[src]`, `video[src]`, `audio[src]`, `object[data]`,
`embed[src]`. For each attribute value that, resolved against `page.url`, starts
`http://` (a `//host` protocol-relative URL inherits `https` → **not** mixed):

- active context (`script`, `link`, `iframe`, `form`, `object`, `embed`) → MEDIUM.
- passive context (`img`, `video`, `audio`, `source`) → LOW.

Dedup by the resolved `http://` URL. An `http://`-served page is skipped
entirely (there is nothing to downgrade). Tested offline against a synthesized
`Page(url="https://…")` (Resolved decision 10); the integration test asserts
only the negative on the `http://` fixture.

### 6. `disclosure.session-id-in-url` (RF-13)

```python
_SESSION_KEYS = ("jsessionid", "phpsessid", "aspsessionid", "asp.net_sessionid",
                 "sid", "sessionid", "session_id", "session", "auth", "authtoken",
                 "access_token", "token", "apikey", "api_key", "cfid", "cftoken")
_SESSION_RE = re.compile(
    rf"(?i)[?;&]({'|'.join(re.escape(k) for k in _SESSION_KEYS)})=([^&;#\s\"'<>]+)")
```

`run`: for each `page`, gather candidate URLs — `page.url`,
`page.requested_url`, `page.final_location` (an out-of-scope redirect target),
and every `<a href>` / `<form action>` resolved from the body. For each match:
one MEDIUM finding per distinct `(key, page.url)` (`Category.DISCLOSURE`,
`cwe = (598,)`), `dedup_key = key`, evidence shows `key=***` (the value
redacted). Only URLs the **target produced** are inspected — `ctx.pages` and
their links, never a scanner-crafted request — so a synthesized OpenAPI `token`
parameter is not flagged (RF-13).

### 7. `disclosure.private-ip` (RF-14)

```python
_PRIVATE_V4 = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r"|127(?:\.\d{1,3}){3}"
    r"|169\.254(?:\.\d{1,3}){2})\b")
_PRIVATE_V6 = re.compile(r"(?i)(?<![:.\w])(?:::1|f[cd][0-9a-f]{2}:[0-9a-f:]+)")
_PER_PAGE_CAP = 10
```

`run`: for each `ok` page with a body, find every distinct match; drop the
target's own resolved host if it is an IP literal (RNF-06); cap at
`_PER_PAGE_CAP` distinct addresses per page and note the total in the finding
when it truncates. One LOW finding per distinct `(page.url, address)`
(`Category.DISCLOSURE`, `cwe = (200,)`), evidence = a short redacted window
around the match (`redaction.apply("generic", window)`).

## Interfaces

- **CLI** — `--header "Name: Value"` (repeatable), `--openapi <path|url>`.
  `webvigil list-checks` gains four rows:
  `content.sri.missing | CONTENT | passive | MEDIUM`,
  `content.mixed | CONTENT | passive | MEDIUM`,
  `disclosure.session-id-in-url | DISCLOSURE | passive | MEDIUM`,
  `disclosure.private-ip | DISCLOSURE | passive | LOW`.
- **Config** — `[auth] headers` (list), `[scan] openapi` (str),
  `[scan] openapi_max_operations` (int).
- No new API route, no reporter field, no `openapi.json` (ours) change, no
  migration.

## ADRs

### ADR-1 — Header auth is generic and gets cookie-grade secrecy

**Decision.** `--header "Name: Value"`, any header, repeatable — not a dedicated
`--bearer TOKEN`. The value is attached only to target-host requests and never
enters a report / log / metadata / warning / evidence line, exactly as the spec
007 cookie.

**Alternatives.** (a) A narrow `--bearer` that only builds
`Authorization: Bearer …`. (b) A `--auth-header` limited to a known set.

**Why.** Real APIs authenticate with `X-API-Key`, `X-Auth-Token`, `Api-Key`,
custom tenant headers — a bearer-only flag would not reach them. A generic flag
is *less* code (one validated list, one attach loop) and composes with the
existing cookie path. The secrecy rule is the load-bearing part, and it is
already implemented for `[auth]`; `headers` inherits it.

**Trade-off.** A user can set a nonsense header. `Host` / `Content-Length` are
rejected; everything else is their call, same as `--cookie`.

### ADR-2 — OpenAPI import is a seed source, not a pass

**Decision.** The import produces `ApiOperation` records consumed at two existing
points — the crawler's seed queue (GET operations) and `enumerate_points` (all
operations' parameters). No `OpenApiScanner`, no `Observations.api_*`, no new
orchestrator stage.

**Alternatives.** (a) An `OpenApiScanner` pass mirroring `EnvelopeScanner` /
`DisclosureProbe` that issues its own requests. (b) Convert operations to
synthetic `Page` / `Form` objects and inject them into `pages` / `forms`.

**Why.** (a) duplicates the crawler (fetch, scope, robots, dedup) and the
injection pass (baseline, budget, detectors) for no gain — an operation URL *is*
a crawl seed and an operation parameter *is* an injection point. (b) pollutes the
shared `forms` tuple, so the passive CSRF check would flag every synthesized
form for a missing token (a false positive). Feeding `enumerate_points` directly
keeps synthetic points out of every other consumer.

**Trade-off.** `enumerate_points` grows an `operations` argument and `points.py`
imports `crawler.openapi` — an allowed `checks → crawler` edge, already present
for `crawler.forms`.

### ADR-3 — JSON only, no new dependency, hand-rolled `$ref`

**Decision.** `--openapi` accepts JSON only. `$ref` resolution is a ~20-line
JSON-pointer walk with a visited-set cycle guard. No `pyyaml`, no `prance` / `openapi-core`.

**Alternatives.** Add `pyyaml` (YAML is a common OpenAPI serialization) and/or a
spec-parsing library.

**Why.** WebVigil has added **no** new runtime dependency since spec 004; a
parser library pulls a transitive tree and its own CVE surface into a security
tool. The 90% case — a running API serving `/openapi.json`, or a `swagger.json`
build artifact — is JSON. Local `#/` refs cover the parameter/schema reuse that
real documents use; external refs are rare and skippable.

**Trade-off.** A user with a YAML-only spec must convert it (one command, any
tool). Documented as the first limitation in `docs/api-scanning.md`; a YAML
fast-follow can add `pyyaml` behind the same flag if demand is real.

### ADR-4 — `--openapi` parse failure is fatal, zero operations is a warning

**Decision.** An unreadable / unparseable / non-OpenAPI `--openapi` value raises
`OpenApiError` before the crawl. A document that parses but yields no GET/POST
operations logs a warning and the scan continues as if `--openapi` were unset.

**Alternatives.** Treat every import problem as a warning and continue.

**Why.** `--openapi` is an explicit request; silently scanning nothing of the
API because of a typo'd path or a truncated download is a worse failure than
stopping with a message. Zero *usable* operations, by contrast, is a legitimate
outcome (a spec of only `PUT`/`DELETE`, or all external `$ref`) and should not
abort a scan that still has a normal crawl to do.

**Trade-off.** A CI job that points at a sometimes-missing spec file now fails
instead of degrading. That is the correct signal — the alternative hides a
broken scan.

### ADR-5 — `Category.CONTENT` for the two subresource checks

**Decision.** `content.sri.missing` and `content.mixed` get a new
`Category.CONTENT`. `disclosure.session-id-in-url` and `disclosure.private-ip`
stay in `Category.DISCLOSURE`.

**Alternatives.** (a) `content.mixed` under `Category.TLS` (it is a transport
downgrade). (b) Both subresource checks under `Category.HEADERS`. (c) No new
category — put all four under `DISCLOSURE`.

**Why.** SRI and mixed content are both **"what the page's HTML tells the browser
to load"** — one group, and neither is a header or a TLS-handshake property. A
new enum member costs nothing downstream (opaque string, re-verified in 012).
Session-id-in-URL and private-IP-in-body are textbook information disclosure and
belong with the existing disclosure family.

**Trade-off.** `content.mixed` arguably overlaps TLS concerns; the CWE (319) and
the docs cross-reference it. A reader filtering by `TLS` will not see it — an
acceptable cost for a coherent `CONTENT` group.

### ADR-6 — Path-param injection via `source="openapi-path"`; JSON-body leaves deferred

**Decision.** A path parameter becomes an `InjectionPoint` whose `base_url` is
the `{name}` URL template and whose `build_request` branch substitutes the
payload into the path. A JSON request body is synthesized and sent for the
baseline but its leaves are not enumerated.

**Alternatives.** (a) Skip path parameters entirely in 013. (b) Also add
JSON-leaf points (a `source="json-body"` with JSON-pointer addressing and a
raw-body `build_request`).

**Why.** Path parameters are ~5 lines (`str.replace` on a template) and catch a
real class (IDOR-adjacent traversal / injection in `/files/{name}`). JSON-leaf
fuzzing is a genuinely larger change — a new point identity, JSON-path
serialization, a raw-body send path, and its own dedup story — and is better as a
focused follow-up than bolted onto this spec.

**Trade-off.** 013's API coverage is strong for query/path parameters and
form-urlencoded bodies, weak for JSON-body APIs (which it still *reaches* and
baselines, just does not fuzz field-by-field). Stated plainly in the docs and
`specs/README.md`.

### ADR-7 — Two small homes for the four checks, no shared base

**Decision.** `webvigil.checks.content` (new, 2 checks) and a new
`webvigil.checks.disclosure.leakage` module (2 checks). No `_ContentCheck` /
`_LeakageCheck` base class.

**Alternatives.** (a) One new `webvigil.checks.passive` grab-bag package. (b) A
shared base for "iterate `ctx.pages`, parse HTML, yield findings".

**Why.** The four checks share a loop shape but almost no logic (SRI parses tags,
private-IP regexes bodies). A base class would abstract three lines and obscure
four different detection rules. `content/` is a real category home;
`disclosure/leakage.py` sits with `errors.py` / `listing.py`, the existing
passive body-inspection checks.

**Trade-off.** Two new files instead of one. Matches how `headers/` and
`disclosure/` already split one category across modules.

## Impact

- **Backward compatible.** No `--header` and no `--openapi` → byte-for-byte the
  same scan. The four passive checks are new ids; a saved scan without them
  re-renders unchanged. `Category.CONTENT` is additive.
- **`pages_scanned`** grows only when `--openapi` seeds fetchable GET operations
  (bounded by `max_pages`). Integration assertions that pin `pages_scanned` are
  unaffected unless the test passes `--openapi`.
- **Injection budget.** OpenAPI query/path/body parameters are ordinary
  `InjectionPoint`s under the existing `request_budget` / `max_injection_points`
  / per-point cap. A large spec is bounded by `openapi_max_operations` (150) and
  then by `max_injection_points` (200). No cap re-tuning expected; Stage 6
  re-measures against the fixture.
- **No API / UI / reporter / migration change.** `list-checks` gains four rows.
- **Determinism.** Value synthesis is type-based and ref resolution is ordered;
  same document + same responses → identical seeds, points, ordering, findings
  (RNF-06).
- **Secrecy.** RNF-04 test: a bearer token passed via `--header` appears in no
  reporter output, the metadata, or a warning.

## Risks

| Risk | Mitigation |
|---|---|
| An auth header leaks into a report via some future evidence path | Nothing today writes request headers into a `Finding`; RNF-04 test guards it; `docs` states the guarantee so a contributor knows not to break it. |
| `--openapi` URL points off-host (SSRF-via-scanner) | `_fetch_document` requires `target.in_scope(source)`; an off-scope URL is `OpenApiError` before any request (RNF-03). |
| A hostile OpenAPI document (billion-laughs `$ref` cycle, giant `paths`) | Cycle guard on `$ref`; `openapi_max_operations` cap; `json.loads` is not entity-expanding; the doc is fetched through the scope-guarded client with the normal timeout. |
| Synthetic path-param `build_request` produces a malformed URL | `quote(value, safe="")` on every substitution; a template segment with no matching param is left as `{name}` and the request 404s harmlessly; unit-tested. |
| Synthetic OpenAPI forms flagged by the CSRF check | Synthetic points never enter the shared `forms` tuple — they go straight into `enumerate_points` (ADR-2). |
| `content.mixed` cannot be tested end-to-end (fixture is `http`) | Unit-tested against a synthesized `https` `Page`; integration asserts the negative only (Resolved decision 10). |
| `disclosure.private-ip` false positives on a normal page (a version string like `10.20.30`, a date) | `\b`-anchored full-dotted-quad regex per range; IPv6 ULA/loopback anchored against surrounding `:`/word chars; per-page cap; LOW severity. |
| `Category.CONTENT` breaks a hardcoded category list | Grep `api/` + `web/` in Stage 0 (as 006 / 012 did); `meta.py` returns `category` as a string, the dashboard derives its filter from data — none expected. |
| Seeds starve the HTML crawl under `max_pages` | Seeds are enqueued first (explicit `--openapi` = "prioritise the API"); documented; `max_pages` is raisable. |

## Testing

| Layer | File | Cases |
|---|---|---|
| unit — config | `test_config.py` | `[auth] headers` valid pair round-trips; missing `:` / empty name / `Host` / `Content-Length` → `ConfigError`; `header_pairs` keeps a `:` in the value; `--header` override replaces the file list; `[scan] openapi` / `openapi_max_operations` defaults + round-trip. |
| unit — http | `test_http_client.py` | configured header attached to a target-host request; **not** attached to an off-host request; a caller-set `Authorization` is not overwritten; `HttpStats` unchanged; a scan render with headers set contains neither name nor value. |
| unit — openapi | `test_crawler_openapi.py` (new) | 3.0 / 3.1 (`servers`) and 2.0 (`schemes`+`host`+`basePath`) base URLs; relative `servers[0].url` joined to origin; foreign host → target origin + warning; local `$ref` (parameter + nested schema) resolved; `$ref` cycle → placeholder; external `$ref` → skipped + one warning; missing file / bad JSON / no `openapi`|`swagger` key → `OpenApiError`; `operationId` `deleteUser` / path `/logout` excluded; `max_operations` cap → warning + truncation; value synthesis precedence (`example` > `default` > `enum` > type placeholder); `application/json` body → `body_json`, form body → `body_fields`. |
| unit — points | `test_injection_points.py` | a GET operation → one point per query param + one per path param (`source` set); a POST operation with a form body → body-field points; a point whose `key` matches a crawled query point is de-duplicated; `build_request` for an `openapi-path` point substitutes and URL-encodes; `max_points` still caps the merged set. |
| unit — crawler | `test_crawler.py` | `extra_seeds` are fetched, counted, scope-guarded, and de-duplicated against HTML links; a seed blocked by `robots.txt` (when `follow_robots`) is skipped. |
| unit — content | `test_checks_content.py` (new) | `SriMissingCheck`: cross-origin `<script>` no `integrity` → MEDIUM; `integrity` no `crossorigin` → MEDIUM (distinct title); same-origin → none; one finding for a CDN script on three pages. `MixedContentCheck`: synthesized `https` page + `http://` `<script>` → MEDIUM, + `http://` `<img>` → LOW; `//cdn/x` → none; `http://` page → none. |
| unit — disclosure leakage | `test_checks_disclosure_leakage.py` (new) | `SessionIdInUrlCheck`: `?PHPSESSID=` in `page.url`, `;jsessionid=` in an `<a href>`, `access_token=` in an out-of-scope `Location`; value redacted in evidence; a scanner-style URL not in `ctx.pages` → none. `PrivateIpInBodyCheck`: `10.` / `172.20.` / `192.168.` / `127.` / `169.254.` / `::1` each match; `203.0.113.5` (public) → none; target host `10.0.0.5` → none; 15 addresses on one page → 10 findings + a note. |
| unit — findings / cli | `test_findings.py`, `test_cli.py` | `Category.CONTENT` value + a `Finding` carrying it serialises / re-loads; `list-checks` shows the four ids with `CONTENT` / `DISCLOSURE`; `--header` / `--openapi` parsed and forwarded; a bad `--header` → usage error. |
| integration | `test_scan_fixture_app.py` | Active insecure + `--openapi http://<fixture>/openapi.json` → an `injection.xss.reflected` (or equivalent) finding on `/api/search` `q`, an endpoint no HTML links; `pages_scanned` includes the seeded GET. Passive insecure → `content.sri.missing` (`/legacy`), `disclosure.session-id-in-url` (`;jsessionid=`), `disclosure.private-ip` (`/status`); **no** `content.mixed` (fixture is `http`). Passive hardened → none of the four. Any scan with `--header "Authorization: Bearer wv-secret-123"` → `"wv-secret-123"` absent from the canonical JSON. Determinism: two runs, identical findings. |
| quality gate | — | `ruff → black → mypy src → lint-imports → pytest` green at every stage. |

## Open questions

None. Ready for `/spec tasks`.

## Implementation notes

Recorded at close (2026-09-08). What shipped, and where it differed from the
design above:

- **`_SKIP_OPERATION_RE` is local to `openapi.py`**, not imported from
  `points._EXCLUDE_FORM_RE`. Importing it would make `webvigil.crawler` depend on
  `webvigil.checks`, reversing the allowed direction. The two keyword sets are
  kept in sync by hand (the ADR-8 unification is still a follow-up).
- **`disclosure.session-id-in-url` only inspects target-produced URLs** —
  `<a href>`, `<form action>`, redirect `history` hops, and an out-of-scope
  `final_location`. It does **not** read `page.url` / `page.requested_url`: a
  crawler-fetched `--openapi` seed carries a synthesized value there, which would
  be a false positive. This is cleaner than plumbing "is this an openapi seed"
  through to the check.
- **`_SESSION_KEYS` is narrower than the requirements list.** Bare `token` and
  `auth` were dropped — a one-time `?token=` reset / verification link is a
  routine, defensible pattern and flagging it is noise. The list keeps the
  unambiguous session / credential names (`jsessionid`, `phpsessid`, `sid`,
  `sessionid`, `session_id`, `sessiontoken`, `authtoken`, `access_token`,
  `apikey`, `api_key`, `cfid`, `cftoken`, `aspsessionid`).
- **The two `content.*` checks and the two `disclosure.*` checks have no shared
  base** (ADR-7 held). `content/` is a new package; `disclosure/leakage.py` is a
  new module alongside `errors.py` / `listing.py`.
- **`disclosure.private-ip` confidence is `MEDIUM`**, not the default — an IP
  literal is an unambiguous match but "internal" is a heuristic (a documented
  `192.168.x` example in API docs is a match too). Severity stays `LOW`.
- **`--openapi` is threaded through the CLI in Stage 1** (with `--header`), not
  Stage 3 — the flag and its `_build_config` wiring are one edit; the
  orchestrator simply ignored `scan.openapi` until Stage 3.
- **`_operation_points` puts a POST operation's query parameters in
  `InjectionPoint.query`** (sent as-is on every body-fuzz request) rather than
  fuzzing them — `build_request`'s POST branch fuzzes `params` into the body and
  keeps `query` static. A POST query parameter is rare and is a documented gap.
- **The fixture's `/ping` link changed from `?host=127.0.0.1` to
  `?host=localhost`** — the literal loopback IP in the index-page HTML made
  `disclosure.private-ip` fire on every profile, breaking
  `test_hardened_profile_reports_nothing`. The link's value never mattered (the
  detectors send their own payloads).
- **The spec-013 passive-check content is inlined into the insecure index page**
  (`_SPEC_013_INSECURE`: a cross-origin SRI-less `<script>`, an `access_token=`
  in a third-party link, a `10.13.37.1` comment), not a new `/legacy` route. A
  new crawled page shifted the spec-008 stored-XSS Phase-B re-crawl past its
  60-page cap and broke two stored-XSS integration tests — inlining keeps
  `pages_scanned` and that budget unchanged. `/openapi.json` + `/api/find` +
  `/api/items` are on both profiles but linked from nowhere (only `--openapi`
  reaches them), so they add no crawl pages.
- **`content.mixed` has no integration coverage** beyond the negative (the
  fixture is served over HTTP). It is unit-tested against a synthesized `https://`
  `Page` (Resolved decision 10).
- **`Category.CONTENT`** added with no API / UI / OpenAPI / reporter change —
  re-confirmed `api/routes/meta.py` returns `check.category.value` (a string) and
  `web/src` derives its category filter from the data.
- **`_render._PASSIVE_DISCLOSURE_IDS` gained the two new `disclosure.*` ids** so
  the CLI summary's "exposed paths" count keeps counting only probe-fed findings.
- **No new runtime dependency** — OpenAPI parsing is `json` + a hand-rolled
  JSON-pointer `$ref` walk. `import-linter` contracts unchanged (the new
  `webvigil.crawler.openapi` imports only `webvigil.core` / `webvigil.http`; the
  new `webvigil.checks.content` imports only `webvigil.core` / `selectolax`).
- **pytest:** 678 at spec 012 close → **741** at 013 close (+63).
