---
feature: Request-envelope injection — CRLF / response splitting, host-header injection, in-band XXE, HTTP methods (Active Mode)
status: done
date: 2026-09-08
related:
  - 006-active-injection/design.md
  - 009-ssrf/design.md
  - 011-rce-injection/design.md
origin: conception
---

# 012 — Request-envelope injection — design

> Design notes: [why blind XXE / OAST is not on the roadmap](../../docs/notes/why-not-oast.md) ·
> [false-positive discipline](../../docs/notes/false-positive-discipline.md).

## Overview

012 adds **four checks** across **two mechanisms**:

- **`injection.crlf`** and **`injection.xxe`** are new detectors in the spec-006
  `InjectionScanner` pass — they mutate a parameter value / a POST body, which is
  what that pass already does. `crlf` is a `crlf` detector kind; `xxe` is an
  `xxe` detector kind that only runs when `[injection] xxe` is on and only on
  POST points.
- **`injection.host-header`** and **`http.methods.unsafe`** come from a **new
  bounded orchestrator pass**, `EnvelopeScanner`, that re-requests a *sample of
  the URLs the crawl already found* — once with a poisoned `Host` /
  `X-Forwarded-*` header, once with `OPTIONS`, once (per host) with `TRACE`. It
  is not an injection-point detector; it is the spec-005 `DisclosureProbe`
  pattern (a pass that fills `Observations`, thin checks turn the hits into
  findings).

Nothing else in the engine moves. **No new orchestrator concept** beyond the one
pass; **no API / UI / reporter change** (the new ids and the new `Category.HTTP`
surface as strings, exactly as `INJECTION` did in 006). The engine gains three
small HTTP-layer affordances — `TRACE` treated as idempotent, a `content=` body
override, and nothing else — all additive.

```
Orchestrator.run
  _inject            → InjectionScanner  [006]  + "crlf" / "xxe" detectors        [012]
  _inject_stored     → StoredXssScanner  [008]  unchanged
  _scan_envelope     → EnvelopeScanner            [012, NEW]
        for a capped URL sample:
          poisoned Host / X-Forwarded-Host / X-Forwarded-Server / X-Host / X-Original-Host
             → sentinel in body URL / Location / <base> / canonical, baseline-absent
                → EnvelopeHit(check_id="injection.host-header", category=INJECTION)
          OPTIONS → Allow / Public parsed; PUT|DELETE|PATCH|CONNECT on an app route
                → EnvelopeHit(check_id="http.methods.unsafe", category=HTTP)
        per host: TRACE → 200 echoing the request
                → EnvelopeHit(check_id="http.methods.unsafe", category=HTTP)
  → Observations.injection_hits += crlf/xxe hits
  → Observations.envelope_hits   = EnvelopeScanner hits
        CrlfCheck / XxeCheck            (kind, _InjectionCheck)     → Finding      [012]
        HostHeaderCheck                 (_EnvelopeCheck, INJECTION) → Finding      [012]
        HttpMethodsCheck                (_EnvelopeCheck, HTTP)      → Finding      [012]
```

## Module layout

| Path | Change | What |
|---|---|---|
| `src/webvigil/checks/injection/detect/crlf.py` | **new** (~120 lines) | `detect` — `%0d%0a`-prefixed payloads injecting a marker header / cookie / body; hit when `httpx` parsed the marker header back (or a body split), baseline-absent. |
| `src/webvigil/checks/injection/detect/xxe.py` | **new** (~120 lines) | `detect` — for a POST point, re-send the body as `application/xml` / `text/xml` with the external-entity payload set; hit on a `/etc/passwd` / `win.ini` signature (shared with `TRAVERSAL_SIGNATURES`) or a named XML-parser error, baseline-absent. |
| `src/webvigil/checks/injection/payloads.py` | edit | `CRLF_*` (payloads, marker header name) and `XXE_*` (payload templates, error-signature regexes). |
| `src/webvigil/checks/injection/points.py` | edit | `_HEADERLIKE_NAMES` + `is_headerlike(point)` (CRLF priority). |
| `src/webvigil/checks/injection/engine.py` | edit | `_DETECTORS["crlf"]` / `["xxe"]`; `_BASE_ORDER` (both late, `crlf` front-loaded by `is_headerlike`); `KIND_BY_CHECK_ID` gains `injection.crlf` / `injection.xxe`; `xxe` dropped from `selected_kinds` when `[injection] xxe` is off (like `sqli-time` / `time_based_sqli`); `_send` gains an optional `content` / `content_type` path for `xxe`. |
| `src/webvigil/checks/injection/checks.py` | edit | `_DESCRIPTION` / `_REMEDIATION` / `_REFERENCES` for `"crlf"` / `"xxe"`; `@register class CrlfCheck` / `XxeCheck` (`_InjectionCheck`). |
| `src/webvigil/checks/envelope/__init__.py` | **new** | package marker. |
| `src/webvigil/checks/envelope/scanner.py` | **new** (~220 lines) | `EnvelopeScanner` — the pass; `EnvelopeHit` dataclass; the Host-poisoning and OPTIONS/TRACE logic; a `_URL_SAMPLE_CAP` / `_REQUEST_CAP`. |
| `src/webvigil/checks/envelope/checks.py` | **new** (~90 lines) | `_EnvelopeCheck` base (filter `ctx.observations.envelope_hits` by `check_id`); `@register class HostHeaderCheck` (`Category.INJECTION`) / `HttpMethodsCheck` (`Category.HTTP`). |
| `src/webvigil/core/findings.py` | edit | `Category.HTTP = "HTTP"` (one enum member + a docstring line). |
| `src/webvigil/core/context.py` | edit | `Observations.envelope_hits: tuple[EnvelopeHit, ...] = ()` + a `TYPE_CHECKING` import. |
| `src/webvigil/core/orchestrator.py` | edit | `_scan_envelope(check_types, http, target, pages, forms, warnings)` — Active + a check selected → run `EnvelopeScanner`, catch-and-warn; wire its output into `Observations`. |
| `src/webvigil/core/config.py` | edit | `InjectionSection.xxe: bool = False` + docstring; optional `envelope_url_sample` / `envelope_budget` caps (config-only). |
| `src/webvigil/cli/app.py` | edit | `--xxe / --no-xxe`, threaded through `_build_config`. |
| `src/webvigil/http/client.py` | edit | `TRACE` into `_IDEMPOTENT`; `request(..., content: str \| bytes \| None = None)` passed to `httpx` (for `xxe` and, if needed, a raw-CRLF query). |
| `tests/fixtures/app.py` | edit | insecure: `/set-lang?lang=` (CRLF into `Set-Cookie`), `/reset` (host-header into a reset link), `/api/xml` (entity-resolving parser — simulated), a route advertising `TRACE` + `PUT` and echoing `TRACE`. Hardened: safe equivalents. |
| `tests/unit/test_injection_crlf.py`, `test_injection_xxe.py`, `test_envelope_scanner.py`, `test_checks_envelope.py` | **new** | the detectors + the pass + the checks via stubs. |
| `tests/unit/test_injection_points.py`, `…_engine.py`, `…checks_injection.py`, `…_cli.py`, `…_config.py`, `test_findings.py` (Category) | edit | `is_headerlike`; `_BASE_ORDER` / `KIND_BY_CHECK_ID`; `xxe` gating; check metadata; `list-checks`; the config field + CLI flag; `Category.HTTP`. |
| `tests/integration/test_scan_fixture_app.py` | edit | Active scan → the four checks (xxe with `--xxe`); zero on hardened; deterministic; `pages_scanned` bump. |
| `docs/active-injection.md`, `README.md`, `CLAUDE.md`, `specs/README.md` | edit | the new section / coverage row / layer-3 paragraph / roadmap. |

Nothing under `src/webvigil/api/` or `web/` changes. `import-linter`: the new
`webvigil.checks.envelope` is under the existing `webvigil.checks` source module
— the contract holds (it imports only `webvigil.core` / `webvigil.http`).

## Data model

### `InjectionHit` — reused unchanged

`kind` takes two new values, `"crlf"` and `"xxe"`. CWE stays on the check class
(`(113, 93)` for `crlf`, `(611, 827)` for `xxe`); `_InjectionCheck.run` untouched.

### `EnvelopeHit` — new (mirrors `ProbeHit`)

```python
@dataclass(frozen=True, slots=True)
class EnvelopeHit:
    check_id: str            # "injection.host-header" | "http.methods.unsafe"
    category: Category       # INJECTION | HTTP  — the check's category, carried on the hit
    url: str
    method: str              # "GET" | "OPTIONS" | "TRACE"
    param: str | None        # the poisoning header name, or None for a methods hit
    severity: Severity
    confidence: Confidence
    cwe: tuple[int, ...]
    title: str
    evidence: tuple[tuple[str, str], ...]
```

Lives in `webvigil.checks.envelope.scanner`; imported into
`webvigil.core.context` under `TYPE_CHECKING` and into
`webvigil.checks.envelope.checks` at runtime — the same visibility rule
`InjectionHit` follows.

### `Observations` — one new field

```python
envelope_hits: tuple[EnvelopeHit, ...] = ()
```

Filled once by `_scan_envelope`. `injection.host-header` / `http.methods.unsafe`
read it; every other check ignores it.

### `Category` — one new member

```python
HTTP = "HTTP"   # HTTP-protocol behaviour not tied to a single response header (methods, ...)
```

The API returns `category` as a string and the dashboard derives its filter from
the data (verified for 006), so `Category.HTTP` needs **no** API / UI / OpenAPI
change.

### `InjectionSection` — one new field

```python
xxe: bool = False   # opt-in: re-send POST bodies as XML with an external-entity payload
```

Plus optional `envelope_url_sample: int = 15` / `envelope_budget: int = 80`
(config-only, no CLI flag).

### `DetectCtx` — unchanged

`crlf` needs nothing new. `xxe` needs a raw body + content-type — handled by
`InjectionScanner._send` (below), not by a `DetectCtx` field, because only `xxe`
uses it and the send function already owns request construction.

## Components

### Payloads (`payloads.py`)

```python
# --- CRLF / HTTP response splitting (spec 012) --------------------------------------
CRLF_TOKEN_BYTES = 6
CRLF_HEADER = "X-WvInjected"
# {token} substituted by the detector. The first form is a raw CR LF (httpx percent-encodes
# it on the wire); the others are pre-encoded / overlong forms for parsers that decode twice
# or accept the unicode-newline trick.
CRLF_PAYLOADS: tuple[str, ...] = (
    "\r\n{header}: {token}",
    "%0d%0a{header}: {token}",
    "%0D%0A{header}:%20{token}",
    "\u560a\u560d{header}: {token}",          # unicode-newline (some Java stacks)
    "\r\n\r\n<html>wv{token}</html>",         # double CRLF → body split
    "\r\nSet-Cookie: wv{token}=1",            # response-header (session-fixation) split
)
CRLF_BODY_MARKER = "<html>wv{token}</html>"

# --- XXE (spec 012, opt-in) --------------------------------------------------------
XXE_CONTENT_TYPES = ("application/xml", "text/xml")
# {file} = a file:// URL; {dtd} = an in-scope URL for the external-DTD probe; {token} a marker.
XXE_PAYLOADS: tuple[str, ...] = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "{file}">]><r>wv{token}&xxe;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "{dtd}"> %p;]><r>wv{token}</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "A"><!ENTITY b "&a;&a;&a;">]><r>&b;wv{token}</r>',
)
XXE_FILES = ("file:///etc/passwd", "file:///c:/windows/win.ini")
# file signatures reuse payloads.TRAVERSAL_SIGNATURES.
XXE_ERROR_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(r"DOCTYPE is not allowed|DOCTYPE.*forbidden|external (?:entity|DTD)", re.I),
    re.compile(r"Entity ['\"]?\w+['\"]? not defined|undefined entity|EntityRef", re.I),
    re.compile(r"lxml\.etree\.XMLSyntaxError|xmlParseEntity|SAXParseException|"
               r"XMLParseError|ExpatError|DTD are not permitted", re.I),
    re.compile(r"entity expansion|entities expansion limit|maximum entity", re.I),
)
```

### `detect/crlf.py` (RF-01, RF-02, RF-06)

```python
_CHECK_ID = "injection.crlf"

async def detect(point, baseline, ctx) -> list[InjectionHit]:
    token = secrets.token_hex(payloads.CRLF_TOKEN_BYTES)
    header = payloads.CRLF_HEADER
    for template in _order_for(point):                     # is_headerlike → full set, else canary
        payload = point.original + template.format(header=header, token=token)
        resp = await ctx.send(point, payload)
        if resp is None:
            return []
        # 1. an injected response header httpx parsed back, absent from the baseline
        if resp.headers.get(header.lower()) == token and baseline.status_header(header) != token:
            return [_hit(point, payload, "response header", f"{header}: {token}")]
        # 2. an injected Set-Cookie
        cookie = resp.headers.get("set-cookie", "")
        if f"wv{token}=1" in cookie and f"wv{token}" not in baseline.raw_body \
           and "wv{token}" not in (baseline_setcookie := ...):
            return [_hit(point, payload, "Set-Cookie split", cookie)]
        # 3. a full response split — the marker body IS the response body
        marker_body = payloads.CRLF_BODY_MARKER.format(token=token)
        if resp.text.strip() == marker_body and marker_body not in baseline.raw_body:
            return [_hit(point, payload, "response body split", resp.text[:200])]
    return []
```

- **All three proofs require the marker absent from the baseline.** Proof 1 is the
  strongest (a header `httpx` actually parsed — not a body reflection). Proof 3
  requires the *entire* response body to be the injected marker, so a page that
  merely reflects the payload text is not a hit.
- `Baseline` gains a tiny helper (or the detector captures the baseline's
  `X-WvInjected` / `Set-Cookie` values itself on the first send) so "absent from
  the baseline" covers a target that always sets that header.
- `is_headerlike(point)` front-loads the full payload set; other points get the
  first two payloads only (canary), like 009/011.

### `detect/xxe.py` (RF-04, RF-06)

```python
_CHECK_ID = "injection.xxe"

async def detect(point, baseline, ctx) -> list[InjectionHit]:
    if point.method != "POST":
        return []                                          # content-type flip is POST-only
    token = secrets.token_hex(6)
    for content_type in payloads.XXE_CONTENT_TYPES:
        for template in payloads.XXE_PAYLOADS:
            for file_url in _files_for(template):          # only the SYSTEM-entity payload iterates files
                body = template.format(file=file_url, dtd=ctx.self_url, token=token)
                resp = await ctx.send(point, body, content_type=content_type)   # new send path
                if resp is None:
                    return []
                if (sig := _file_signature(resp.text, baseline.raw_body)) is not None:
                    return [_hit(point, body, Severity.HIGH, Confidence.HIGH, "local file read", sig)]
                if (err := _error_signature(resp.text, baseline.raw_body)) is not None:
                    return [_hit(point, body, Severity.HIGH, Confidence.MEDIUM, "XML parser error", err)]
    return []
```

- **`ctx.send(point, body, content_type=…)`** is a new keyword on the bound
  `Sender`: `InjectionScanner._send` builds a `POST` to `point.base_url` with
  `content=body`, `headers={"content-type": content_type}`, and **no** `data` /
  `params` (the XML body replaces the form body). `HttpClient.request` gains the
  matching `content=` param.
- `ctx.self_url` — a new `DetectCtx` field carrying an in-scope URL
  (`target.base_url`) so the parameter-entity payload's external DTD is *in
  scope* (the scope guard permits the fetch attempt; a real vulnerable parser
  then errors naming the DTD). WebVigil never hosts the DTD — the point is the
  *error*, not a successful fetch.
- File signatures reuse `payloads.TRAVERSAL_SIGNATURES`.

### `points.is_headerlike` (RF-02)

```python
_HEADERLIKE_NAMES = frozenset({
    "url", "redirect", "redirect_uri", "redir", "next", "return", "returnurl", "goto",
    "dest", "destination", "continue", "to", "out", "link", "callback",
    "lang", "language", "locale", "region", "country", "currency", "market", "site",
    "ref", "referer", "referrer", "source", "utm_source", "filename", "file", "name",
    "download", "attachment", "title", "id", "page", "view",
})

def is_headerlike(point) -> bool:
    return point.param.lower() in _HEADERLIKE_NAMES
```

### `engine.py`

```python
from webvigil.checks.injection.detect import crlf as crlf_detect, xxe as xxe_detect
from webvigil.checks.injection.points import ..., is_headerlike

_DETECTORS = { ..., "crlf": crlf_detect.detect, "xxe": xxe_detect.detect }
_BASE_ORDER = (
    "xss", "sqli-error", "sqli-boolean", "traversal", "redirect", "ssti", "crlf",
    "sqli-time", "cmdi", "xxe", "ssrf",
)
KIND_BY_CHECK_ID = { ..., "injection.crlf": "crlf", "injection.xxe": "xxe" }
```

`selected_kinds` filter gains: drop `"xxe"` when `not config.xxe` (mirrors the
`"sqli-time"` / `time_based_sqli` line). `_ordered_kinds` gains
`(is_headerlike, "crlf")`.

`_send` grows one branch:

```python
async def _send(self, point, value, *, time_based=False, content_type=None):
    if not (self._budget.take_time_based() if time_based else self._budget.take()):
        return None
    if content_type is not None:                              # xxe: raw body, not a form
        try:
            return await self._http.request(
                "POST", point.base_url, content=value,
                headers={"content-type": content_type}, crafted=True,
            )
        except (RequestFailed, OutOfScopeError):
            return None
    method, url, params, data = build_request(point, value)
    ...
```

### `webvigil.checks.envelope.scanner` — `EnvelopeScanner` (RF-03, RF-05)

```python
_SENTINEL = "webvigil.invalid"
_HOST_VECTORS = ("Host", "X-Forwarded-Host", "X-Forwarded-Server", "X-Host", "X-Original-Host")
_METHOD_VERBS = ("PUT", "DELETE", "PATCH", "CONNECT")
_URL_SAMPLE_CAP = 15
_REQUEST_CAP = 80
_SENTINEL_IN_URL = re.compile(rf"https?://[^\s\"'<>]*{re.escape(_SENTINEL)}", re.I)
_BASE_CANON = re.compile(
    rf"<base[^>]+href=[\"'][^\"']*{re.escape(_SENTINEL)}|"
    rf"rel=[\"']canonical[\"'][^>]+{re.escape(_SENTINEL)}|"
    rf"property=[\"']og:url[\"'][^>]+{re.escape(_SENTINEL)}", re.I)


class EnvelopeScanner:
    async def run(self) -> list[EnvelopeHit]:
        urls = self._sample_urls()          # entry + form pages + up to _URL_SAMPLE_CAP, dedup by path
        hits: list[EnvelopeHit] = []
        for url in urls:
            if self._spent >= _REQUEST_CAP:
                self._warn(...); break
            baseline = await self._get(url)               # plain GET, the diff anchor
            if baseline is None:
                continue
            hits += await self._host_header(url, baseline)
            hits += await self._options(url)
        hits += await self._trace(self._target.base_url)
        return hits
```

- **`_host_header(url, baseline)`** — for each `_HOST_VECTORS` entry, `GET url`
  with `headers={vector: _SENTINEL}` (for `"Host"` this overrides httpx's own).
  A hit needs `_SENTINEL_IN_URL.search(resp.text)` **or** `_SENTINEL` in
  `resp.headers.get("location", "")` **or** `_BASE_CANON.search(resp.text)`, and
  the *baseline* response not matching. Severity `HIGH` when the match is in
  `Location` or a link whose surrounding text matches
  `reset|token|password|confirm|verify|activate`; else `MEDIUM`. `param` = the
  vector name.
- **`_options(url)`** — `OPTIONS url`; parse `Allow` + `Public`. If any
  `_METHOD_VERBS` present **and** `url` is not a static asset
  (`resp.headers["content-type"]` not `image|font|css|javascript|octet-stream`
  and the path has no static extension), emit one hit listing them, `MEDIUM`,
  `cwe=(650,)`, note "not verified as unauthenticated".
- **`_trace(url)`** — `TRACE url`; a `200` whose body contains `TRACE ` + the
  request path (or an echoed header WebVigil sent, e.g. a random
  `X-Wv: <token>`) → hit, `MEDIUM`, `cwe=(693,)`, "Cross-Site Tracing (XST)".
- Every request through `self._http` (scope guard, rate limit, timeout). `Host:
  webvigil.invalid` is a header value on a request to the in-scope `url` —
  WebVigil issues no request to `webvigil.invalid`; a `Location` to it is
  recorded, not followed (spec 001 RF-04).

### `webvigil.checks.envelope.checks`

```python
class _EnvelopeCheck(Check):
    """Filter ctx.observations.envelope_hits for this check's id."""
    check_key: ClassVar[str]
    async def run(self, ctx) -> list[Finding]:
        return [
            self.finding(title=h.title, description=_DESC[self.check_key],
                         remediation=_FIX[self.check_key], severity=h.severity,
                         confidence=h.confidence,
                         location=Location(url=h.url, method=h.method, param=h.param),
                         evidence=[EvidenceItem.of(l, c) for l, c in h.evidence])
            for h in ctx.observations.envelope_hits if h.check_id == self.check_key
        ]

@register
class HostHeaderCheck(_EnvelopeCheck):
    id = "injection.host-header"; check_key = id
    name = "Host header injection"
    category = Category.INJECTION
    mode = ScanMode.ACTIVE
    default_severity = Severity.MEDIUM
    cwe = (644,)

@register
class HttpMethodsCheck(_EnvelopeCheck):
    id = "http.methods.unsafe"; check_key = id
    name = "Unsafe HTTP methods enabled"
    category = Category.HTTP
    mode = ScanMode.ACTIVE
    default_severity = Severity.MEDIUM
    cwe = (650, 693, 16)
```

`cwe` on the finding comes from the check class for host-header; for the methods
check the two shapes (XST vs advertised verbs) carry different CWEs, so
`HttpMethodsCheck` reads `h.cwe` from the hit instead of the class attribute (a
one-line override of `finding(...)`).

### `orchestrator._scan_envelope`

Mirrors `_probe_disclosure`: no-op unless Active **and** (`HostHeaderCheck` or
`HttpMethodsCheck` selected); construct `EnvelopeScanner(http, target,
self._config, pages, forms)`, `await .run()`, `except Exception` → warn; assign
`Observations.envelope_hits`.

### Fixture app (`tests/fixtures/app.py`, RF-13)

Insecure:

```python
def _set_lang_insecure(request):
    lang = unquote(request.query_params.get("lang", "en"))
    resp = PlainTextResponse(f"lang set to {lang.splitlines()[0]}")
    # simulate a split: the app writes the raw value into Set-Cookie; a permissive server
    # passes the injected header line through. (Starlette/h11 would reject a raw CRLF, so the
    # fixture parses the injected header out and sets it as a real, valid header — same
    # "fixture simulates the sink" pattern as spec 006's SLEEP() and spec 011's shell.)
    for line in lang.split("\r\n")[1:]:
        if ":" in line:
            name, _, val = line.partition(":")
            resp.headers[name.strip()] = val.strip()
    resp.headers["set-cookie"] = f"lang={lang.split(chr(13))[0]}"
    return resp


def _reset_insecure(request):
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    return HTMLResponse(f'<p>Reset link: <a href="https://{host}/reset?token=abc">click</a></p>')


async def _xml_insecure(request):
    body = (await request.body()).decode("utf-8", "replace")
    if "file:///etc/passwd" in body or "file:///c:/windows" in body.lower():
        return PlainTextResponse(_ETC_PASSWD)                  # entity resolved
    if "<!DOCTYPE" in body or "<!ENTITY" in body:
        return PlainTextResponse("lxml.etree.XMLSyntaxError: Entity 'xxe' not defined", 500)
    return PlainTextResponse("ok")


def _methods_insecure(request):                                # also answers TRACE
    if request.method == "TRACE":
        return PlainTextResponse(f"TRACE {request.url.path}\r\nhost: {request.headers.get('host')}")
    resp = PlainTextResponse("resource")
    resp.headers["allow"] = "GET, POST, PUT, DELETE, TRACE, OPTIONS"
    return resp
```

Hardened: `lang` whitelisted to `{"en","pt","es"}`; `/reset` builds the link from
a constant base URL; `/api/xml` returns `"DTDs are not permitted"` `400` for any
`<!DOCTYPE`; `/methods` `Allow: GET, POST, OPTIONS` and `405` on `TRACE`.

Links + routes added to both profiles; `/methods` registered for
`["GET", "POST", "PUT", "DELETE", "TRACE", "OPTIONS"]` on insecure but the
handler only *acts* on GET/TRACE.

## Interfaces

- **CLI** — `--xxe / --no-xxe` (default off). `webvigil list-checks` gains four
  rows: `injection.crlf | INJECTION | active | HIGH`,
  `injection.host-header | INJECTION | active | MEDIUM`,
  `injection.xxe | INJECTION | active | HIGH`,
  `http.methods.unsafe | HTTP | active | MEDIUM`.
- **Config** — `[injection] xxe` (bool), `envelope_url_sample` / `envelope_budget`
  (int, config-only).
- No new API route, no reporter field, no `openapi.json` change.

## ADRs

### ADR-1 — In-band only; blind XXE and request smuggling stay out

**Decision.** 012 detects XXE from the target's own response (file content
reflected, or a named parser error). No collaborator. No request-smuggling
detection at all.

**Alternatives.** (a) A parameter-entity OAST payload for blind XXE. (b) A
CL.TE / TE.CL timing probe for smuggling.

**Why.** Blind XXE needs a hosted collaborator — the exact line drawn for blind
SSRF (009) and blind command injection (011). Request smuggling needs raw-socket
framing control that `httpx` deliberately does not give, and its detection is a
notorious false-positive source that would poison the tool's credibility.

**Trace-off.** An XXE that is exploitable only blind (no echo, no error) is a
false negative; the docs say so and point at "pair with your own collaborator".

### ADR-2 — `crlf` / `xxe` in `InjectionScanner`; `host-header` / `methods` in a new pass

**Decision.** CRLF and XXE mutate a parameter value / a POST body — they are
injection-point detectors and join the 006 pass. Host-header poisoning and the
OPTIONS/TRACE probe are per-URL, not per-point — they get `EnvelopeScanner`, a
pass in the spec-005 `DisclosureProbe` mould.

**Alternatives.** (a) Force host-header into the injection-point model (treat the
`Host` header as a synthetic "point"). (b) Four separate passes. (c) Make the
methods check read `ctx.pages` and send from inside the check.

**Why.** (a) distorts the point model (a header is not a query/form parameter and
has no per-URL baseline in the 006 sense). (c) breaks the 006 coordinator rule
that checks never issue their own crafted requests. One shared `EnvelopeScanner`
for the two per-URL classes keeps the orchestrator to one new pass and reuses one
URL sample + one budget for both.

**Trade-off.** `EnvelopeHit` is a second hit type alongside `InjectionHit`. It is
small, mirrors `ProbeHit`, and lets one check be `INJECTION` and the other `HTTP`
from one list.

### ADR-3 — `http.methods.unsafe` is one check, `Category.HTTP`, Active

**Decision.** One check id covering both XST (TRACE) and advertised write verbs,
in a new `Category.HTTP`, `mode = ACTIVE`.

**Alternatives.** (a) Two ids (`http.methods.trace` + `.dangerous`). (b) Reuse
`Category.HEADERS`. (c) Safe Mode + a `--probe`-style flag (OPTIONS/TRACE are
idempotent).

**Why.** One check keeps `list-checks` honest (one row = "unsafe methods"), like
`injection.cmdi.os` covering echo + time. `Category.HTTP` is accurate — a method
is not a header — and costs one enum member with no API/UI change. Active because
sending any verb beyond `GET`/`POST` is where 006 drew the line, and the cost is
a handful of extra requests inside a scan that is already Active.

**Trade-off.** A user who wants OPTIONS/TRACE data from a Safe scan cannot get
it. Rare; documented.

### ADR-4 — XXE is opt-in (`--xxe`), off by default

**Decision.** The `xxe` detector runs only when `[injection] xxe` / `--xxe` is
set.

**Alternatives.** On by default like every other 006/009/011 detector.

**Why.** The `xxe` step **rewrites the request body** as XML and sends it to
endpoints that overwhelmingly expect a form — a burst of `400` / `415` on every
POST point, for a vulnerability class that is now rare (modern XML libraries
disable DTDs by default). Same reasoning as `--stored-xss` (008): a detector that
changes what it sends in a way most targets will reject earns an opt-in.

**Trade-off.** A default Active scan misses XXE. The docs make the flag
prominent; the roadmap note flags that XXE may split into its own spec if the
content-type flip proves near-useless against real targets (Resolved decision 2).

### ADR-5 — CRLF proof is an `httpx`-parsed header, not a body reflection

**Decision.** `injection.crlf` fires on a response **header** (or a full body
split) that `httpx` parsed back, absent from the baseline — never on the payload
string merely appearing in the page text.

**Alternatives.** Fire when `%0d%0a<marker>` is reflected anywhere in the
response.

**Why.** A reflected payload string is XSS/redirect territory (other detectors
own it). CRLF *injection* means the app wrote attacker bytes into the response
**headers** — the only faithful proof is a header line the HTTP client accepted
as real and that was not there before. This is what keeps `injection.crlf` from
overlapping `injection.xss.reflected` and from firing on every echoing endpoint.

**Trade-off.** A target behind a server that strips CRLF from header values
before sending (nginx, modern WSGI) is a false negative even if the app is
vulnerable — the split never reaches WebVigil. Documented; the fixture simulates
the permissive-server case.

### ADR-6 — Host-header severity: MEDIUM, HIGH in a reset/redirect context

**Decision.** `injection.host-header` default MEDIUM; the hit is HIGH when the
sentinel lands in a `Location` header or in a link whose context matches
`reset|token|password|confirm|verify|activate`.

**Alternatives.** Always MEDIUM; always HIGH.

**Why.** A reflected `Host` in a `<link canonical>` is an SEO / cache nuisance
(MEDIUM); the same reflection in a password-reset link is account takeover
(HIGH). WebVigil can tell the two apart from the surrounding markup, so it
should.

**Trade-off.** The context heuristic can misjudge; `confidence` reflects it and
the evidence quotes the line so a reviewer can see the call.

## Impact

- **Backward compatible.** All four checks run only in Active Mode with the check
  selected; `xxe` additionally needs `--xxe`. Passive scans and Active scans that
  disable the four are byte-for-byte unchanged.
- **Budget.** `crlf` ≈ 6 requests/point (2 for a non-headerlike point). `xxe` ≈
  12 requests/POST-point, only with `--xxe`. `EnvelopeScanner` ≈ `_URL_SAMPLE_CAP
  × (5 host vectors + 1 OPTIONS) + 1 TRACE` ≈ 90 worst case, capped at
  `_REQUEST_CAP`. The `InjectionScanner` per-point cap absorbs `crlf`; the
  envelope pass has its own budget. **Stage 0 of tasks.md re-measures against the
  fixture** and adjusts `_PER_POINT_REQUEST_CAP` / the envelope caps if needed
  (as 011 did).
- **`Category.HTTP`** is the first new category since spec 001. Reporters and the
  dashboard treat `category` as an opaque string — verified in 006 RF-19 — so no
  downstream change. `list-checks`, the check-catalogue API response, and the
  dashboard filter pick it up from the data.
- **No API / UI / reporter / migration change.** `list-checks` gains four rows.
- **Determinism.** Per-run `token`s vary; findings and fingerprints do not
  (`fingerprint` = `check_id` + URL + method + param).

## Risks

| Risk | Mitigation |
|---|---|
| `crlf` false positive from an echoing endpoint | Proof is an `httpx`-parsed header / a whole-body split, not a text reflection (ADR-5). Unit-tested with "payload reflected in body only → no hit". |
| `crlf` false negative behind a CRLF-stripping server | Documented; the fixture simulates the permissive case; three payload encodings widen coverage. |
| `xxe` floods POST endpoints with `400` | Opt-in (`--xxe`), off by default (ADR-4); the burst is bounded by the per-point cap; a `400`/`415` the baseline never returned is explicitly not a hit. |
| `xxe` external-DTD payload makes WebVigil hit an off-scope host | The `{dtd}` URL is `target.base_url` — **in scope**; the scope guard is unchanged; WebVigil hosts nothing. |
| Host-header pass follows a `Location` to `webvigil.invalid` | It does not — the scope guard blocks it; `Response.final_location` records it, the pass reads that as evidence (spec 001 RF-04). |
| `TRACE` / `OPTIONS` counted as non-idempotent → retried oddly / inflates `crafted_requests` | `TRACE` added to `_IDEMPOTENT` (it is safe); `OPTIONS` already there. |
| `Category.HTTP` breaks a hardcoded category list somewhere | Grep `api/` + `web/` in Stage 0 (as 006 did); none expected — `meta.py` returns `category` as `str`, the dashboard derives the filter from data. |
| `EnvelopeScanner` URL sample misses the vulnerable page | The sample front-loads the entry page + every form page (where reset links live); the cap is documented and raisable via config. |

## Testing

| Layer | File | Cases |
|---|---|---|
| unit — crlf | `tests/unit/test_injection_crlf.py` (new) | stub `send`: injected `X-WvInjected` header parsed back → HIGH; `Set-Cookie` split → HIGH; whole-body marker → HIGH; payload reflected in body text only → no hit; header already in baseline → suppressed; `is_headerlike` priority. |
| unit — xxe | `tests/unit/test_injection_xxe.py` (new) | `/etc/passwd` signature → HIGH/HIGH; parser-error-only → HIGH/MEDIUM; `400` with no signature → no hit; GET point → no hit; both content types tried; `content_type=` reaches the send path. |
| unit — envelope | `tests/unit/test_envelope_scanner.py` (new) | sentinel in `Location` / `<base>` / canonical / absolute URL → host-header hit (HIGH in a reset context, else MEDIUM); sentinel absent → no hit; each `X-Forwarded-*` vector; `Allow: …, PUT, DELETE` on an app route → methods hit; `Allow` on a static asset → no hit; `TRACE` echo → XST hit; the URL-sample cap + the request-budget warning; **never sends PUT/DELETE/PATCH** (request spy). |
| unit — checks | `tests/unit/test_checks_envelope.py` (new) | `HostHeaderCheck` → INJECTION MEDIUM finding from a `injection.host-header` hit; `HttpMethodsCheck` → HTTP finding, per-hit CWE; each ignores the other's hits; `[]` when no hit. |
| unit — engine/points/checks/cli/config | edits | `"crlf"` / `"xxe"` in `_BASE_ORDER` / `_DETECTORS` / `KIND_BY_CHECK_ID`; `xxe` dropped when `[injection] xxe` off; `is_headerlike`; `list-checks` shows the four; `--xxe` sets the field; `Category.HTTP` round-trips through the finding model + JSON reporter. |
| unit — Category | `tests/unit/test_findings.py` | `Category.HTTP` value; a `Finding` with it serialises / re-loads. |
| integration | `tests/integration/test_scan_fixture_app.py` | Active insecure → `injection.crlf` (`/set-lang` `lang`), `injection.host-header` (`/reset`), `http.methods.unsafe` (TRACE + advertised PUT); Active insecure + `--xxe` → `injection.xxe` (`/api/xml`); Active hardened → **zero**; passive → zero, no OPTIONS/TRACE/poisoned-Host/XML-body sent; deterministic; `pages_scanned` adjusted. |
| quality gate | — | `ruff → black → mypy src → lint-imports → pytest` green at every stage. |

## Open questions

None. Ready for `/spec tasks`.

## Implementation notes

Recorded at close (2026-09-08). What shipped, and where it differed from the
design above:

- **`EnvelopeHit` is leaner than sketched.** `Finding` has no `category`
  attribute (category lives on the check class), so `EnvelopeHit` dropped
  `category` and `cwe` — `HostHeaderCheck` (`cwe = (644,)`) and `HttpMethodsCheck`
  (`cwe = (650, 693, 16)` on every finding) carry them on the class. Fields:
  `check_id, url, method, param, severity, confidence, title, evidence`.
- **The envelope caps live in `[injection]`**, not a new `[envelope]` section —
  `envelope_url_sample` (15) and `envelope_budget` (**120**, not the 80 in the
  design; a 15-URL sample at ~7 requests each needs the headroom).
  `EnvelopeScanner` takes the full `ScanConfig` and reads
  `config.injection.envelope_*`.
- **`_HOST_VECTORS` is 4, not 5** — dropped `X-Original-Host` to bound the
  per-URL cost (baseline + 4 host probes + 1 OPTIONS = 6/URL).
- **`_trace` probes up to 4 sampled URLs**, not just the entry URL — a route can
  `405` TRACE even when the server supports it (the fixture models this: only
  `/resource` allows TRACE).
- **`crlf` sends its own benign baseline.** `Baseline` carries no response
  headers, so the detector does one `point.original` send first to learn what
  `X-WvInjected` / `Set-Cookie` the endpoint normally sets — "absent from the
  baseline" then holds for a target that always emits that header.
- **`xxe` is front-loaded for POST points** (`_is_post` in `_ordered_kinds`). It
  sits last in `_BASE_ORDER` and the per-point cap (35) was exhausted before it
  on a POST point that also runs xss/sqli/traversal/redirect; front-loading fixes
  it, and xxe only runs on POST points with `--xxe` anyway.
  `_PER_POINT_REQUEST_CAP` stayed 35; `request_budget` stayed 600.
- **`Category.HTTP`** added with no API/UI/reporter change — confirmed the
  dashboard derives its category filter from `check.category` in the data and
  `api/routes/meta.py` returns `check.category.value` (a string).
- **HTTP layer:** `TRACE` added to `_IDEMPOTENT`; `HttpClient.request` +
  `_request_with_retry` gained `content: str | bytes | None` threaded to
  `httpx.request` (for the XXE raw body).
- **The fixture simulates the CRLF split.** Starlette/h11 reject a raw CR/LF in a
  header value, so `_set_lang_insecure` parses the injected header line out of the
  `lang` value and sets it as a real, valid header — the "fixture simulates the
  sink" pattern from spec 006 `SLEEP()` / spec 011's shell. Whether a real
  permissive upstream surfaces a split header through `httpx` is a documented
  limitation, not tested.
- **The `/reset` link spawns a crawlable child** (`/reset/confirm?token=…`), so
  the insecure Active scan's `pages_scanned` grew; the hardened profile links the
  reset URL off-host (not followed), so `test_crawler_reaches_the_linked_pages`
  (hardened, passive) asserts **17**. The integration `scan` fixture passes
  `envelope_url_sample = 20` / `envelope_budget = 130` so the pass reaches
  `/reset` and `/resource` in the 17-page fixture.
- **pytest:** 639 at spec 011 close → **678** at 012 close (unit: +7 crlf, +6
  xxe, +9 envelope-scanner, +3 envelope-checks, +1 points, +3 engine, +1 checks,
  +2 config, +1 cli, +1 findings; integration: +6).
- **No API / UI / reporter / migration change.** `import-linter` contracts
  unchanged (the new `webvigil.checks.envelope` is under `webvigil.checks`).
- **Manual verification:** an Active scan of the fixture reports `injection.crlf`
  (`/set-lang` `lang`), `injection.host-header` (`/reset`, `Host` vector),
  `http.methods.unsafe` (`/resource`), and — with `--xxe` — `injection.xxe`
  (`/api/xml`); the hardened profile reports none; `webvigil list-checks` shows
  the four with `INJECTION` / `HTTP`; a request capture confirms only `GET` /
  `POST` / `OPTIONS` / `TRACE` left WebVigil and nothing went to
  `webvigil.invalid`.
