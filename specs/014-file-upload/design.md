---
feature: Unrestricted file upload + residual in-band active checks — LDAP / XPath / SSI injection (Active Mode)
status: done
date: 2026-09-08
related:
  - 006-active-injection/design.md
  - 008-stored-xss/design.md
  - 011-rce-injection/design.md
  - 012-protocol-injection/design.md
origin: conception
---

# 014 — File upload and residual in-band active checks — design

> Design notes: [why blind / OAST is not on the roadmap](../../docs/notes/why-not-oast.md) ·
> [false-positive discipline](../../docs/notes/false-positive-discipline.md).

## Overview

014 adds **four checks** across **two mechanisms**, exactly the shape spec 012
used:

- **`injection.ldap`**, **`injection.xpath`** and **`injection.ssi`** are new
  detectors in the spec-006 `InjectionScanner` pass. They mutate a parameter
  value and diff against the point's shared `Baseline` — the exact shape of the
  `sqli` detectors (error signature + a two-sided boolean differential). No new
  orchestrator pass, no new HTTP mechanic.
- **`upload.unrestricted`** comes from a **new bounded orchestrator pass**,
  `UploadScanner`, modelled on `StoredXssScanner` / `EnvelopeScanner`: for every
  discovered file-upload `<form>` (and one gated `PUT` probe) it submits benign
  marker files, fetches them back, and confirms in-band whether the target
  executed the file, served it inline, or stored it out of its directory. It is
  a pass that fills `Observations`; a thin check turns the hits into findings.
  It is opt-in (`--file-upload`), because it writes files the target keeps.

Nothing else in the engine moves. **No new orchestrator concept** beyond the one
pass; **no API / UI / reporter change** (the new ids and `Category.UPLOAD`
surface as strings, as `HTTP` did in 012 and `CONTENT` in 013). The engine gains
one HTTP-layer affordance — a `files=` passthrough to `httpx` for the multipart
upload — and nothing else.

```
Orchestrator.run
  _inject          → InjectionScanner  [006]  + "ldap" / "xpath" / "ssi" detectors   [014]
  _inject_stored   → StoredXssScanner  [008]  unchanged
  _scan_envelope   → EnvelopeScanner   [012]  unchanged
  _scan_upload     → UploadScanner             [014, NEW]  (Active + check selected + --file-upload)
        for every discovered multipart / file-input <form>:
          upload wv<token>.php  (<?php echo A*B;?>)  → fetch back → product, no source
                → UploadHit(outcome="server-exec",  severity=CRITICAL)
          upload wv<token>.html / .svg (<script>)    → fetch back → text/html, no attachment
                → UploadHit(outcome="inline-html",  severity=HIGH)
          upload ../../wv<token>-trav.html           → fetch from web root
                → UploadHit(outcome="traversal",    severity=HIGH)
          upload wv<token>.php.jpg / %00 / c-t spoof → fetch back → executed / inline
                → UploadHit(outcome=<as above>)
          (stored + retrievable, octet-stream + attachment)
                → UploadHit(outcome="inert-accept", severity=MEDIUM)
        once, gated: PUT wv<token>.txt / .html to the entry dir → GET back
                → UploadHit(outcome="put-upload",   severity=HIGH/CRITICAL)
  → Observations.injection_hits += ldap/xpath/ssi hits
  → Observations.upload_hits     = UploadScanner hits
        LdapCheck / XpathCheck / SsiCheck   (kind, _InjectionCheck)  → Finding   [014]
        UnrestrictedUploadCheck             (_UploadCheck, UPLOAD)    → Finding   [014]
```

## Module layout

| Path | Change | What |
|---|---|---|
| `src/webvigil/checks/injection/detect/ldap.py` | **new** (~130 lines) | `detect` — error probe (`)` / `*)(` / `(|`) → LDAP-parser signature, baseline-absent → HIGH; boolean probe (`*` / `*)(uid=*))(|(uid=*` widen vs `)(!(x=*)` no-change) → MEDIUM. |
| `src/webvigil/checks/injection/detect/xpath.py` | **new** (~130 lines) | `detect` — error probe (`'` / `"` / `]` / `count(//*`) → XPath/XQuery signature → HIGH; boolean probe (`' or '1'='1` vs `' and '1'='2`) → MEDIUM. |
| `src/webvigil/checks/injection/detect/ssi.py` | **new** (~110 lines) | `detect` — echo probe (`<!--#echo var="DATE_LOCAL"-->`, `<!--#printenv-->`, `<esi:vars>$(HTTP_HOST)</esi:vars>`) → evaluated output, baseline-absent → HIGH; marker probe (`<!--#echo var="wv<token>"-->`) → SSI-error string → MEDIUM. Never sends `#exec` / `#include`. |
| `src/webvigil/checks/injection/detect/_diff.py` | **new** (~40 lines) | `two_sided_split` (true≈baseline, false diverges — the `sqli` boolean rule) and `wider_then_same` (true grows past a factor, false unchanged — the LDAP/XPath result-set rule); `_ratio`. Extracted from `sqli.py` (which starts importing them). |
| `src/webvigil/checks/injection/payloads.py` | edit | `LDAP_ERROR` / `LDAP_ERROR_SIGNATURES` / `LDAP_BOOLEAN`, `XPATH_ERROR` / `XPATH_ERROR_SIGNATURES` / `XPATH_BOOLEAN_PAIRS`, `SSI_ECHO` / `SSI_EVAL_SIGNATURES` / `SSI_ERROR_SIGNATURE`. |
| `src/webvigil/checks/injection/points.py` | edit | `_LDAPLIKE_NAMES` + `is_ldaplike`, `_XPATHLIKE_NAMES` + `is_xpathlike`, `_SSILIKE_NAMES` + `is_ssilike`. |
| `src/webvigil/checks/injection/engine.py` | edit | `_DETECTORS["ldap"/"xpath"/"ssi"]`; `_BASE_ORDER` (all three after `sqli-time`, before `ssrf`); `KIND_BY_CHECK_ID` += 3; `_ordered_kinds` += `(is_ldaplike,"ldap")` etc.; `_PER_POINT_REQUEST_CAP` 35→**38**, and `_BASE_ORDER` documented. |
| `src/webvigil/checks/injection/stored.py` | edit | `_STORED_REFETCH_CAP` 60→**120** (specs 011-14 grew the crawl + guestbook-fuzz surface). |
| `src/webvigil/checks/injection/checks.py` | edit | `_DESCRIPTION` / `_REMEDIATION` / `_REFERENCES` for `"ldap"` / `"xpath"` / `"ssi"`; `@register class LdapCheck` / `XpathCheck` / `SsiCheck` (`_InjectionCheck`). |
| `src/webvigil/checks/upload/__init__.py` | **new** | package marker + `from webvigil.checks.upload import checks  # noqa: F401`. |
| `src/webvigil/checks/upload/scanner.py` | **new** (~320 lines) | `UploadScanner` — the pass; `UploadHit` dataclass; `UploadPayload` (filename, bytes, part content-type); form selection, payload build, retrieval, proof, the `PUT` probe; `_UPLOAD_BUDGET` fallback, per-form cap. |
| `src/webvigil/checks/upload/checks.py` | **new** (~90 lines) | `_UploadCheck` base (filter `ctx.observations.upload_hits`); `@register class UnrestrictedUploadCheck` (`Category.UPLOAD`). |
| `src/webvigil/checks/__init__.py` | edit | `upload` added to the `_load_builtin_checks` import tuple. |
| `src/webvigil/core/findings.py` | edit | `Category.UPLOAD = "UPLOAD"` (one enum member + a docstring line). |
| `src/webvigil/core/context.py` | edit | `Observations.upload_hits: tuple[UploadHit, ...] = ()` + a `TYPE_CHECKING` import + docstring line. |
| `src/webvigil/core/orchestrator.py` | edit | `_scan_upload(check_types, http, target, pages, forms, warnings)` — Active + `upload.unrestricted` selected + `[injection] file_upload` → run `UploadScanner`, catch-and-warn; Passive + flag → warning; wire output into `Observations`. |
| `src/webvigil/core/config.py` | edit | `InjectionSection.file_upload: bool = False`, `upload_budget: int = 80`; `request_budget` 600→**650**; docstring. |
| `src/webvigil/cli/app.py` | edit | `--file-upload / --no-file-upload`, threaded through `_build_config` (`auth`-style: `if file_upload is not None: injection_overrides["file_upload"] = file_upload`). |
| `src/webvigil/cli/_render.py` | edit | `summary(...)` notes "N file(s) uploaded" when the upload pass ran (design: a new `uploads: int = 0` kwarg, like `cookie_count`). |
| `src/webvigil/http/client.py` | edit | `request(..., files: _Files \| None = None)` and `_request_with_retry(..., files)` → `httpx` `files=`; `files` mutually exclusive with `data` / `content` (assert). |
| `webvigil.example.toml` | edit | `[injection]` gains commented `# file_upload = false` / `# upload_budget = 80`. |
| `tests/fixtures/app.py` | edit | insecure: an upload form on the index, `POST /upload` (store, no validation), `GET/PUT /files/{name}` (extension-guessed `Content-Type`, `.php` "executed" offline), `GET /dir?user=` (LDAP), `GET /xdoc?node=` (XPath), `GET /page?tpl=` (SSI). Hardened: safe equivalents. |
| `tests/unit/test_injection_ldap.py`, `test_injection_xpath.py`, `test_injection_ssi.py`, `test_upload_scanner.py`, `test_checks_upload.py` | **new** | the three detectors + the pass + the check, via stubs. |
| `tests/unit/test_injection_points.py`, `…_engine.py`, `…checks_injection.py`, `…_cli.py`, `…_config.py`, `test_findings.py`, `test_http_client.py` | edit | the `is_*like` helpers; `_BASE_ORDER` / `KIND_BY_CHECK_ID`; `list-checks`; `--file-upload`; the config fields; `Category.UPLOAD`; `request(files=)`. |
| `tests/integration/test_scan_fixture_app.py` | edit | Active + `--file-upload` insecure → the four checks; Active without the flag → 3 injection checks, no upload; passive → none; hardened → zero; deterministic. |
| `docs/active-injection.md` (or `docs/file-upload.md`), `README.md`, `CLAUDE.md`, `specs/README.md` | edit | the new sections / coverage row / layer-3 paragraph / roadmap. |

Nothing under `src/webvigil/api/` or `web/` changes. `import-linter`: the new
`webvigil.checks.upload` is under the existing `webvigil.checks` source module —
the contract holds (it imports only `webvigil.core` / `webvigil.http` /
`webvigil.crawler.forms`).

## Data model

### `InjectionHit` — reused unchanged

`kind` takes three new values: `"ldap"`, `"xpath"`, `"ssi"`. CWE stays on the
check class (`(90,)` / `(643,)` / `(97,)`); `_InjectionCheck.run` untouched.

### `UploadPayload` — new, internal to `webvigil.checks.upload.scanner`

```python
@dataclass(frozen=True, slots=True)
class UploadPayload:
    family: str            # "server-exec" | "client-exec" | "bypass" | "traversal"
    filename: str          # the multipart part filename (may contain ../, %00, ;)
    content: bytes         # a few hundred bytes, benign, carries wv<token>
    part_type: str         # the part's Content-Type ("application/octet-stream", "image/jpeg", ...)
    expects: str           # "product" | "script"  — what a successful retrieval must show
```

### `UploadHit` — new (mirrors `EnvelopeHit`)

```python
@dataclass(frozen=True, slots=True)
class UploadHit:
    outcome: str            # "server-exec" | "inline-html" | "traversal" | "put-upload" | "inert-accept"
    url: str                # the upload endpoint (form action) or the PUT path
    method: str             # "POST" | "PUT"
    field: str | None       # the file field name, or None for the PUT probe
    retrieved_from: str     # the URL the stored file was fetched back from
    severity: Severity
    confidence: Confidence
    title: str
    payload_name: str       # the payload filename that worked
    evidence: tuple[tuple[str, str], ...]
```

Lives in `webvigil.checks.upload.scanner`; imported into `webvigil.core.context`
under `TYPE_CHECKING` and into `webvigil.checks.upload.checks` at runtime — the
`InjectionHit` / `EnvelopeHit` visibility rule.

### `Observations` — one new field

```python
upload_hits: tuple[UploadHit, ...] = ()
```

Filled once by `_scan_upload`. `upload.unrestricted` reads it; every other check
ignores it.

### `Category` — one new member

```python
UPLOAD = "UPLOAD"   # how the app handles an uploaded file (type / content / where it is served)
```

The API returns `category` as a string and the dashboard derives its filter from
the data (verified in 006, re-verified in 012 / 013), so `Category.UPLOAD` needs
**no** API / UI / OpenAPI change.

### `InjectionSection` — two new fields, one bump

```python
file_upload: bool = False   # opt-in: upload benign marker files and fetch them back (writes to the target)
upload_budget: int = 80     # total requests UploadScanner may spend
request_budget: int = 650   # was 600 — ldap / xpath / ssi add three small families
```

### `DetectCtx` — unchanged

`ldap` / `xpath` / `ssi` need nothing new — they call `ctx.send(point, value)`
and diff against the baseline, exactly like `sqli`.

## Components

### Payloads (`payloads.py`)

```python
# --- LDAP injection (spec 014) ---------------------------------------------------------
LDAP_ERROR: tuple[str, ...] = (")", "*)(", "(|", "))")
LDAP_ERROR_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(r"LDAPException|javax\.naming\.directory|com\.sun\.jndi\.ldap", re.I),
    re.compile(r"Bad search filter|Search: Bad search filter|invalid DN syntax", re.I),
    re.compile(r"Protocol error|ldap_search|com_err|Operations error.*000004DC", re.I),
    re.compile(r"supplied argument is not a valid ldap|ldap_(?:bind|result)\(\)", re.I),
)
# (true widens the result set, false leaves it unchanged)
LDAP_BOOLEAN: tuple[tuple[str, str], ...] = (
    ("*)(uid=*))(|(uid=*", ")(!(objectClass=*)"),
    ("*", "x)(&(x=y)"),
)

# --- XPath / XQuery injection (spec 014) ----------------------------------------------
XPATH_ERROR: tuple[str, ...] = ("'", '"', "]", "count(//*", "' or ''='")
XPATH_ERROR_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(r"XPathException|XPathEvalError|lxml\.etree\.XPathEvalError", re.I),
    re.compile(r"System\.Xml\.XPath|MS\.Internal\.Xml|org\.jaxen|net\.sf\.saxon", re.I),
    re.compile(r"Expression must evaluate to a node-set|Invalid (?:XPath )?expression", re.I),
    re.compile(r"xmlXPathEval|unterminated string|SyntaxError:.*expression", re.I),
)
XPATH_BOOLEAN_PAIRS: tuple[tuple[str, str], ...] = (
    ("' or '1'='1", "' and '1'='2"),
    ("x' or 1=1 or 'x'='y", "x' and 1=2 and 'x'='y"),
)

# --- Server-Side Includes / ESI (spec 014) ------------------------------------------
SSI_ECHO: tuple[str, ...] = (
    '<!--#echo var="DATE_LOCAL"-->',
    "<!--#printenv-->",
    "<esi:vars>$(HTTP_HOST)</esi:vars>",
)
SSI_MARKER = '<!--#echo var="wv{token}"-->'          # undefined var → the SSI error string
SSI_EVAL_SIGNATURES: tuple[re.Pattern[str], ...] = (  # the *evaluated* output, not the directive
    re.compile(r"\b\d{4}-\d\d-\d\d\b|\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b.+\d{4}", re.I),
    re.compile(r"\b(?:DOCUMENT_ROOT|SERVER_SOFTWARE|HTTP_HOST|REQUEST_URI)=", re.I),
)
SSI_ERROR_SIGNATURE = re.compile(
    r"\[an error occurred while processing this directive\]|\[error processing directive\]", re.I
)
```

### `detect/_diff.py` (new — extracted from `sqli.py`)

```python
from difflib import SequenceMatcher

_SIMILAR = 0.95   # "same as baseline" floor
_GAP = 0.90       # "diverged from baseline" ceiling
_WIDEN = 1.30     # "materially larger" factor

def ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).quick_ratio()

def two_sided_split(baseline_norm: str, true_body: str, false_body: str) -> bool:
    """sqli's rule: TRUE stays ~= baseline, FALSE diverges."""
    return (ratio(baseline_norm, _norm(true_body)) >= _SIMILAR
            and ratio(baseline_norm, _norm(false_body)) <= _GAP)

def wider_then_same(baseline_norm: str, base_len: int,
                    true_body: str, false_body: str) -> bool:
    """LDAP/XPath rule: TRUE returns materially more, FALSE is unchanged."""
    return (len(true_body) >= base_len * _WIDEN
            and ratio(baseline_norm, _norm(false_body)) >= _SIMILAR)
```

`sqli.py` deletes its private `_ratio` / `_splits` and imports `ratio` /
`two_sided_split` from here — a pure move, asserted by the unchanged `sqli`
tests.

### `detect/ldap.py` (RF-08, RF-11, RF-12)

```python
_CHECK_ID = "injection.ldap"

async def detect(point, baseline, ctx) -> list[InjectionHit]:
    # 1. error probe
    for probe in payloads.LDAP_ERROR:
        resp = await ctx.send(point, point.original + probe)
        if resp is None:
            return []
        for sig in payloads.LDAP_ERROR_SIGNATURES:
            if sig.search(resp.text) and not sig.search(baseline.raw_body):
                return [_hit(point, point.original + probe, Severity.HIGH, Confidence.HIGH,
                             "LDAP filter error", _quote(sig, resp.text))]
    # 2. two-sided boolean (true widens the result set, false does not)
    for true_p, false_p in payloads.LDAP_BOOLEAN:
        true_r = await ctx.send(point, true_p)              # replace, not append: filter injection
        false_r = await ctx.send(point, point.original + false_p)
        if true_r is None or false_r is None:
            return []
        if wider_then_same(baseline.norm_body, baseline.length, true_r.text, false_r.text):
            # confirm once
            again = await ctx.send(point, true_p)
            if again and len(again.text) >= baseline.length * _WIDEN:
                return [_hit(point, true_p, Severity.MEDIUM, Confidence.MEDIUM,
                             "LDAP filter injection (result set widened)", ...)]
    return []
```

`detect/xpath.py` is the same file with the XPath payloads/signatures and
`two_sided_split` (XPath boolean is a classic true/false, not a result-set
widen).

### `detect/ssi.py` (RF-10, RF-12)

```python
_CHECK_ID = "injection.ssi"

async def detect(point, baseline, ctx) -> list[InjectionHit]:
    for directive in payloads.SSI_ECHO:
        resp = await ctx.send(point, point.original + directive)
        if resp is None:
            return []
        if directive in resp.text:
            continue                                        # reflected verbatim, not evaluated → not us
        for sig in payloads.SSI_EVAL_SIGNATURES:
            if sig.search(resp.text) and not sig.search(baseline.raw_body):
                return [_hit(point, ..., Severity.HIGH, Confidence.HIGH,
                             "SSI/ESI directive evaluated", _quote(sig, resp.text))]
    token = secrets.token_hex(5)
    marker = payloads.SSI_MARKER.format(token=token)
    resp = await ctx.send(point, point.original + marker)
    if resp and payloads.SSI_ERROR_SIGNATURE.search(resp.text) \
            and not payloads.SSI_ERROR_SIGNATURE.search(baseline.raw_body):
        return [_hit(point, marker, Severity.MEDIUM, Confidence.MEDIUM,
                     "SSI enabled (undefined-variable error)", ...)]
    return []
```

- The `directive in resp.text` guard is what stops `ssi` from firing on a plain
  reflecting endpoint (that is `xss` territory).
- **Never** `<!--#exec cmd=…-->` / `<!--#include file=…-->` — RF-10, Resolved
  decision 7.

### `points.py` — three heuristics (RF-11)

```python
_LDAPLIKE_NAMES = frozenset({
    "user", "username", "uid", "cn", "dn", "sn", "givenname", "mail", "email",
    "search", "filter", "group", "ou", "member", "role", "login", "account",
})
_XPATHLIKE_NAMES = frozenset({
    "xpath", "xml", "xquery", "query", "q", "search", "node", "path", "select",
    "filter", "id", "name", "user", "title", "field", "expr",
})
_SSILIKE_NAMES = frozenset({
    "page", "file", "include", "tpl", "template", "name", "msg", "message",
    "q", "search", "lang", "content", "body", "text", "title", "comment",
})

def is_ldaplike(point) -> bool:  return point.param.lower() in _LDAPLIKE_NAMES
def is_xpathlike(point) -> bool: return point.param.lower() in _XPATHLIKE_NAMES
def is_ssilike(point) -> bool:   return point.param.lower() in _SSILIKE_NAMES
```

### `engine.py`

```python
_DETECTORS = { ..., "ldap": ldap_detect.detect, "xpath": xpath_detect.detect, "ssi": ssi_detect.detect }
_BASE_ORDER = (
    "xss", "sqli-error", "sqli-boolean", "traversal", "redirect", "ssti", "crlf",
    "ssi", "sqli-time", "cmdi", "ldap", "xpath", "xxe", "ssrf",
)
KIND_BY_CHECK_ID = { ..., "injection.ldap": "ldap", "injection.xpath": "xpath", "injection.ssi": "ssi" }
```

`_ordered_kinds` gains `(is_ldaplike, "ldap")`, `(is_xpathlike, "xpath")`,
`(is_ssilike, "ssi")`. `_PER_POINT_REQUEST_CAP` 35 → **38** (three small
families; Stage 0 re-measures against the fixture, as 011 did). No `selected_kinds`
drop — all three are on whenever their check is selected (they are not opt-in and
not slow like `sqli-time` / `xxe`).

### `webvigil.checks.upload.scanner` — `UploadScanner` (RF-01..RF-06)

```python
_UPLOAD_PREFIXES = ("/uploads/", "/files/", "/media/", "/static/uploads/", "/upload/")
_MARKER = "wv{token}"

class UploadScanner:
    def __init__(self, http, target, config, pages, forms):
        self._http = http
        self._target = target
        self._budget = config.injection.upload_budget
        self._forms = forms
        self._pages = pages
        self._spent = 0
        self.warnings: list[str] = []

    async def run(self) -> list[UploadHit]:
        hits: list[UploadHit] = []
        for form in self._upload_forms():
            hits += await self._probe_form(form)
        hits += await self._probe_put()
        return hits
```

- **`_upload_forms()`** — every `Form` with a `type == "file"` field, `enctype`
  forced to `multipart/form-data`, minus `_EXCLUDE_FORM_RE` matches (imported from
  `points.py` or duplicated — a small regex; design picks import).
- **`_probe_form(form)`** — build the `UploadPayload` set (RF-03), then per
  payload:
  1. `POST form.action` with `files={field: (payload.filename, payload.content,
     payload.part_type)}` and `data={other fields: default value}` via
     `ctx.http.request("POST", …, files=…, data=…, crafted=True)`.
  2. a rejection (`4xx` the empty-file baseline upload did not return) → skip.
  3. `_retrieve(payload, upload_response, form.action)` (RF-04) → the served
     `Response` or `None`.
  4. `_classify(payload, served)` → an `UploadHit` or `None` (RF-05).
- **`_retrieve(...)`** — candidate URLs in order: any `absolute-or-rooted URL`
  containing `wv<token>` in the upload response body or `Location`; `payload
  base filename` under each `_UPLOAD_PREFIXES` entry and the form action's own
  directory; for `family == "traversal"`, `target.origin + "/" + basename` and
  the parent of each prefix. Each fetched with a scope-guarded `GET`; the first
  `2xx` whose body carries `wv<token>` wins.
- **`_classify(payload, served)`**:
  | condition | outcome | severity / confidence |
  |---|---|---|
  | body has `A*B` glued to `wv<token>`, no `<?php` / `<%` | `server-exec` | CRITICAL / HIGH |
  | `Content-Type` ∈ {text/html, application/xhtml+xml, image/svg+xml} and no `attachment` | `inline-html` | HIGH / HIGH |
  | `family == "traversal"` and `retrieved_from` is outside every upload prefix | `traversal` | HIGH / HIGH |
  | retrievable, `application/octet-stream` + `attachment` | `inert-accept` | MEDIUM / MEDIUM |
  | otherwise | (nothing) | — |
- **`_probe_put()`** (RF-06) — `PUT {entry-dir}/wv<token>.txt` with a marker
  body; on `200/201/204`, `GET` it back; if the marker is returned →
  `put-upload` HIGH; then repeat with `.html` and grade CRITICAL when it comes
  back as `text/html`. `PUT` is the one state-changing verb 014 sends, only here,
  only under `--file-upload`.
- **Budget** — every request calls `self._take()` first (`self._spent += 1;
  return self._spent <= self._budget`); a denied take ends the pass with a
  warning. A per-form cap (`_UPLOAD_PREFIXES` retrieval is the cost driver) keeps
  one pathological form from eating the whole budget.
- **Benign only** — `content` is `b"wv<token>=" + b"<?php echo 6*7; ?>"` /
  `b"<!doctype html><script>/*wv<token>*/</script>wv<token>"` /
  `b"wv<token> upload marker"` — nothing executable, nothing over ~200 bytes.

### `webvigil.checks.upload.checks`

```python
class _UploadCheck(Check):
    mode = ScanMode.ACTIVE
    async def run(self, ctx) -> list[Finding]:
        return [
            self.finding(
                title=h.title, description=_DESCRIPTION[h.outcome],
                remediation=_UPLOAD_FIX, severity=h.severity, confidence=h.confidence,
                location=Location(url=h.url, method=h.method, param=h.field),
                dedup_key=f"{h.field or 'PUT'}:{h.outcome}",
                evidence=[EvidenceItem.of(l, c) for l, c in h.evidence],
            )
            for h in ctx.observations.upload_hits
        ]

@register
class UnrestrictedUploadCheck(_UploadCheck):
    id = "upload.unrestricted"
    name = "Unrestricted file upload"
    category = Category.UPLOAD
    default_severity = Severity.HIGH
    cwe = (434, 646)
    references = (
        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    )
```

`_DESCRIPTION` is keyed on `outcome` (five short paragraphs); one shared
`_UPLOAD_FIX` (allow-list by content sniffing not extension, store outside the
web root, serve with `Content-Disposition: attachment` +
`X-Content-Type-Options: nosniff`, randomise the stored name, disable script
execution in the upload directory).

### `orchestrator._scan_upload`

Mirrors `_inject_stored`:

```python
async def _scan_upload(self, check_types, http, target, pages, forms, warnings) -> tuple[UploadHit, ...]:
    if self._config.scan.mode is not ScanMode.ACTIVE:
        return ()
    if not self._config.injection.file_upload:
        return ()
    if not any(c.id == "upload.unrestricted" for c in check_types):
        return ()
    try:
        scanner = UploadScanner(http, target, self._config, pages, forms)
        hits = await scanner.run()
    except Exception as exc:
        warnings.append(f"file-upload pass failed: {exc or type(exc).__name__}")
        return ()
    warnings.extend(scanner.warnings)
    return tuple(hits)
```

Plus, next to the stored-XSS warning at the top of `run()`:

```python
if self._config.injection.file_upload and self._config.scan.mode is not ScanMode.ACTIVE:
    warnings.append("file-upload testing requires --mode active — the upload pass did not run")
```

### Fixture app (`tests/fixtures/app.py`, RF-15)

Insecure — the "fixture simulates the sink" pattern (spec 006 `SLEEP()`, spec
011 shell, spec 012 CRLF): deterministic, offline, no real PHP / LDAP / XPath
engine.

```python
_UPLOADS: dict[str, tuple[str, bytes]] = {}          # name -> (content_type, body), on app.state

async def _upload_insecure(request):
    form = await request.form()
    up = form["avatar"]                               # starlette UploadFile
    name = up.filename or "file"
    body = await up.read()
    ctype = _guess_type(name)                         # .html->text/html, .svg->image/svg+xml, .php->php
    request.app.state.uploads[name.split("/")[-1] if ".." not in name else name] = (ctype, body)
    # a traversal name is stored at web root too
    if ".." in name:
        request.app.state.uploads[name.rsplit("/", 1)[-1]] = (ctype, body)
    return HTMLResponse(f'<p>saved: <a href="/files/{name.split("/")[-1]}">link</a></p>')

async def _files_insecure(request):
    name = request.path_params["name"]
    if request.method == "PUT":
        request.app.state.uploads[name] = (_guess_type(name), await request.body())
        return PlainTextResponse("created", 201)
    ctype, body = request.app.state.uploads.get(name, ("", b""))
    if not body:
        return PlainTextResponse("not found", 404)
    if ctype == "php":                                # "execute": evaluate the echo marker
        body = _fake_php(body)                        # <?php echo 6*7; ?>  ->  b"42"
        ctype = "text/html"
    return Response(body, media_type=ctype)           # no Content-Disposition

def _dir_insecure(request):                           # LDAP
    user = request.query_params.get("user", "")
    if any(c in user for c in ")(|") and "*)(" not in user and user != "*":
        return PlainTextResponse("LDAPException: Bad search filter", 500)
    rows = _ALL_USERS if ("*" in user) else _ONE_USER
    return PlainTextResponse("\n".join(rows))

def _xdoc_insecure(request):                          # XPath (param "node" — front-loads xpath)
    node = request.query_params.get("node", "")
    if node.count("'") % 2 == 1 and " or " not in node.lower():
        return PlainTextResponse("lxml.etree.XPathEvalError: Invalid expression", 500)
    hits = _CATALOGUE if ("or '1'='1" in node or "or 1=1" in node) else _CATALOGUE[:1]
    return PlainTextResponse("\n".join(hits))

def _page_insecure(request):                          # SSI
    tpl = request.query_params.get("tpl", "")
    out = tpl
    out = out.replace('<!--#echo var="DATE_LOCAL"-->', "Mon, 08 Sep 2026 12:00:00")
    out = out.replace("<!--#printenv-->", "DOCUMENT_ROOT=/var/www\nHTTP_HOST=demo.test")
    if re.search(r'<!--#echo var="wv\w+"-->', out):
        out = re.sub(r'<!--#echo var="wv\w+"-->',
                     "[an error occurred while processing this directive]", out)
    return HTMLResponse(f"<div>{out}</div>")
```

Hardened: `/upload` allow-lists `.png` / `.jpg` (else `400`), stores under a
random name, `/files/{name}` always `application/octet-stream` +
`Content-Disposition: attachment`, `PUT` → `405`; `/dir` and `/xdoc` use a fixed
row set for any payload; `/page` HTML-escapes `tpl` and processes no directive.

Routes + links added to both profiles (linked from the insecure index like
`_INJECTION_LINKS`), keeping the spec-008 Phase-B re-crawl under
`_STORED_REFETCH_CAP` — Stage 0 checks the page count and, if needed, inlines
the new links into `_INSECURE_PAGE` rather than adding a page (the spec-013
lesson).

## Interfaces

- **CLI** — `--file-upload / --no-file-upload` (default off). `webvigil
  list-checks` gains four rows: `injection.ldap | INJECTION | active | HIGH`,
  `injection.xpath | INJECTION | active | HIGH`, `injection.ssi | INJECTION |
  active | HIGH`, `upload.unrestricted | UPLOAD | active | HIGH`.
- **Config** — `[injection] file_upload` (bool), `upload_budget` (int),
  `request_budget` default 650.
- **Human summary** — an "N file(s) uploaded" note when the upload pass ran
  (the `cookie_count` pattern in `_render.summary`).
- No new API route, no reporter field, no `openapi.json` change.

## ADRs

### ADR-1 — `UploadScanner` is a new orchestrator pass, not injection-point detectors

**Decision.** File upload gets its own pass (`UploadScanner`), like
`StoredXssScanner` and `EnvelopeScanner`. LDAP / XPath / SSI join the existing
`InjectionScanner` pass.

**Alternatives.** (a) Model an upload form field as a synthetic `InjectionPoint`
and add an `upload` detector. (b) One pass for all four of 014.

**Why.** An upload test is *per form*, multi-step (submit → locate → fetch →
classify), and stateful (it writes a file, then reads it from a different URL) —
none of which fits the `InjectionPoint` / `Baseline` / one-detector-call model.
LDAP / XPath / SSI, by contrast, are textbook value injections with the `sqli`
shape (error signature + boolean differential) and belong in the pass that
already owns points, baselines and the shared budget.

**Trade-off.** A third hit type (`UploadHit`) alongside `InjectionHit` /
`EnvelopeHit`. It mirrors `EnvelopeHit`, is read by exactly one check, and keeps
the upload logic out of the injection engine.

### ADR-2 — the upload pass is opt-in (`--file-upload`), off by default

**Decision.** `UploadScanner` runs only with `[injection] file_upload` /
`--file-upload`, on top of Active Mode.

**Alternatives.** On by default in any Active scan (like `crlf` / `cmdi`).

**Why.** The pass **writes files the target stores** and WebVigil cannot reliably
delete — the exact situation that made `--stored-xss` (008) and `--xxe` (012)
opt-in. A default Active scan should not litter a staging server with
`wv<token>.php` / `.html` files.

**Trade-off.** A default Active scan misses unrestricted upload. The docs make
the flag prominent, next to `--stored-xss`.

### ADR-3 — LDAP / XPath / SSI reuse the `InjectionScanner` pass; extract a diff helper

**Decision.** Three new detector kinds in the 006 pass. `sqli.py`'s private
`_ratio` / `_splits` move to `detect/_diff.py` as `ratio` / `two_sided_split`,
plus a new `wider_then_same` for the LDAP/XPath result-set case.

**Alternatives.** (a) Copy the similarity helpers into each detector. (b) A
separate `SqlishScanner` pass for the "error + boolean" family.

**Why.** (a) is three copies of a subtle heuristic. (b) duplicates the point /
baseline / budget machinery for no gain — these are value injections. Extracting
the helper is a pure refactor the existing `sqli` tests pin.

**Trade-off.** `sqli.py` gains an import. Minimal; the helper is genuinely shared
now.

### ADR-4 — `Category.UPLOAD`, a new `Category` member

**Decision.** `upload.unrestricted` is `Category.UPLOAD`, a new enum member.

**Alternatives.** (a) `Category.INJECTION`. (b) `Category.DISCLOSURE`.

**Why.** Unrestricted upload is neither a payload-in-a-parameter injection nor an
information leak — it is its own OWASP category (A04:2021 sub-area, CWE-434).
Consistent with 012 adding `HTTP` and 013 adding `CONTENT`; the cost is one enum
member and one docstring line, no API / UI change (`category` is an opaque string
downstream — re-verified in 013).

**Trade-off.** A fourth new category in three specs. Each is a real, distinct
class; the dashboard filter absorbs them from the data.

### ADR-5 — one `upload.unrestricted` check, severity graded by proof

**Decision.** One check id; the finding severity is set from the `UploadHit`
outcome — `server-exec` CRITICAL, `inline-html` / `traversal` / `put-upload`
HIGH, `inert-accept` MEDIUM.

**Alternatives.** Separate ids (`upload.exec`, `upload.xss`, `upload.traversal`).

**Why.** One row in `list-checks` = "unrestricted file upload", like
`injection.cmdi.os` (echo + time) and `http.methods.unsafe` (TRACE + verbs). The
outcome and its severity are in the finding title and severity; a reviewer sees
the distinction without four catalogue entries.

**Trade-off.** Suppressing "just the low-severity inert-accept noise" means
suppressing the whole check. Acceptable — `--fail-on high` already filters it out
of a gate.

### ADR-6 — 014 sends `PUT`, which 012 refused — but only a benign marker, only under the opt-in

**Decision.** The `PUT` upload probe (RF-06) sends `PUT` of a marker file to the
entry directory, gated behind `--file-upload`.

**Alternatives.** Keep the spec-012 rule ("never send a verb beyond GET/POST/
OPTIONS/TRACE") and cover only `multipart` forms.

**Why.** WebDAV-style `PUT` upload is a real unrestricted-upload vector and the
only way to prove it in-band is to `PUT` a file and `GET` it back. `--file-upload`
already means "you have authorised me to write files to this target"; a single
bounded `PUT` of a benign marker to one directory is within that authorisation.
012's rule was about an *un-gated* Active scan.

**Trade-off.** The "no state-changing verbs" line now has one gated exception.
Documented in the check description and the docs; the body is inert; nothing
else (`DELETE` / `PATCH` / `PUT` elsewhere) changes.

### ADR-7 — benign markers, left in place, no cleanup

**Decision.** Every uploaded file is a few hundred inert bytes (a PHP `echo` of
`6*7`, an HTML `<script>` comment, a text marker). WebVigil does not attempt to
delete them.

**Alternatives.** (a) Try to `DELETE` each uploaded file after the test. (b)
Upload nothing that could render (skip the `.html` / `.svg` families).

**Why.** (a) means guessing a delete endpoint and sending `DELETE` — more
state-change, more guesswork, often impossible. (b) removes the strongest
in-band signal (an `.html` served as `text/html` *is* the stored-XSS proof). The
markers are harmless on their own; the `.html`/`.svg` ones only matter if a
victim's browser opens that exact URL, which the docs state — the same deal as a
stored-XSS marker (008).

**Trade-off.** A scanned target keeps a handful of `wv<token>.*` files. Bounded
(the per-form payload set is small), benign, documented.

### ADR-8 — `ssi` proves SSI evaluation only; the fixture simulates every sink offline

**Decision.** The `ssi` detector sends only `#echo` / `#printenv` / `<esi:vars>`
— never `#exec` / `#include`. The fixture fakes PHP execution, LDAP errors and
XPath errors deterministically and offline.

**Alternatives.** (a) `ssi` also sends `<!--#exec cmd="echo …"-->` (RCE proof).
(b) A real embedded LDAP / XPath engine in the test fixture.

**Why.** (a) is command injection — `injection.cmdi.os` owns it, and sending
`#exec` makes `ssi` a destructive detector. (b) adds a heavy test dependency for
no extra coverage — the detectors match on *response text*, which the fixture can
produce from a lookup table, exactly as spec 006's `SLEEP()` and spec 011's shell
do.

**Trade-off.** The fixture proves the detector's matching logic, not a real SSI /
LDAP / XPath engine's behaviour. This is the established fixture contract; real
engines are a manual-verification and integration concern.

## Impact

- **Backward compatible.** LDAP / XPath / SSI run only in Active Mode with their
  check selected; the upload pass additionally needs `--file-upload`. Passive
  scans and Active scans that disable the four are byte-for-byte unchanged.
- **Budget.** `ldap` ≈ 4-8 requests/point, `xpath` ≈ 4-8, `ssi` ≈ 4 — all inside
  the per-point cap (35 → 38). `request_budget` 600 → 650. `UploadScanner` has
  its own `upload_budget` (80): per form ≈ (1 baseline + ~10 payloads + ~10
  retrieval probes) ≈ 21, plus 4 for the `PUT` probe. **Stage 0 re-measures
  against the fixture** and adjusts (as 011 / 012 did).
- **`Category.UPLOAD`** — reporters and the dashboard treat `category` as an
  opaque string (verified 006, re-verified 012 / 013), so no downstream change.
  `list-checks`, the check-catalogue API response, and the dashboard filter pick
  it up from the data.
- **No API / UI / reporter / migration change.** `list-checks` gains four rows.
- **HTTP layer** — `request()` / `_request_with_retry()` gain a `files=`
  parameter forwarded to `httpx`; `files` is mutually exclusive with `data` /
  `content` (an `assert`, since only `UploadScanner` sets it). No behaviour
  change for any existing caller.
- **Determinism.** Per-run `wv<token>`s vary; findings and fingerprints do not
  (`fingerprint` = `check_id` + URL + method + param/field).

## Risks

| Risk | Mitigation |
|---|---|
| `ldap` / `xpath` boolean false positive on a noisy page | Two-sided differential (true widens / diverges **and** false does not) + a confirmation request, the `sqli` boolean discipline; unit-tested with "one-sided change → no hit". |
| `ssi` fires on a plain reflecting endpoint | The `directive in resp.text` guard: a verbatim echo is explicitly not a hit; only *evaluated* output (a rendered date, an env dump) or the SSI-error string counts. |
| Upload pass litters the target with files | Opt-in (`--file-upload`); benign inert markers; small bounded payload set per form (ADR-7); documented like `--stored-xss`. |
| Upload pass can't locate the stored file → false negative | Retrieval tries the response URL, five conventional prefixes, and the action's own directory; a target with a truly opaque storage URL is a documented limitation. |
| `PUT` probe changes server state unexpectedly | Only under `--file-upload`; only to the entry directory; only a benign marker body; never `DELETE` / `PATCH` (ADR-6). |
| `_PER_POINT_REQUEST_CAP` bump starves nothing / everything | Stage 0 re-measures against the fixture and tunes (011 precedent: 30→35; here 35→38). |
| `Category.UPLOAD` breaks a hardcoded category list | Grep `api/` + `web/` in Stage 0 (as 006 / 012 did); none expected — `meta.py` returns `category` as `str`. |
| Multipart `files=` interacts badly with the `[auth]` header attachment | `_request_with_retry` attaches `[auth]` cookies/headers *before* handing off to `httpx`; `files=` rides the same path; unit-tested that an `[auth]` header still lands on an upload request and never in a finding (RNF-07). |
| Stored-XSS Phase-B re-crawl pushed past `_STORED_REFETCH_CAP` by the new fixture links | Stage 0 checks the fixture page count; inline the new links into `_INSECURE_PAGE` rather than adding a page (the spec-013 fix). |

## Testing

| Layer | File | Cases |
|---|---|---|
| unit — ldap | `tests/unit/test_injection_ldap.py` (new) | stub `send`: LDAP error signature, baseline-absent → HIGH; result-set widen (true grows, false unchanged) + confirm → MEDIUM; one-sided change → none; signature already in baseline → suppressed; `is_ldaplike` priority. |
| unit — xpath | `tests/unit/test_injection_xpath.py` (new) | XPath error signature → HIGH; two-sided boolean split + confirm → MEDIUM; bare `5xx` → none; one-sided → none. |
| unit — ssi | `tests/unit/test_injection_ssi.py` (new) | evaluated date / env dump → HIGH; SSI-error string → MEDIUM; directive reflected verbatim → none; never sends `#exec` / `#include` (payload spy). |
| unit — _diff | `tests/unit/test_injection_diff.py` (new) | `two_sided_split` / `wider_then_same` truth tables; `sqli` tests still green after the move. |
| unit — upload scanner | `tests/unit/test_upload_scanner.py` (new) | form selection (file field in / login form out); each payload family built; retrieval by response URL vs conventional prefix vs web root (traversal); the five `_classify` branches + severities; rejection → no hit; budget cap → warning; `PUT` probe positive / negative; **uploads only benign markers**, **never sends DELETE/PATCH** (request spy); an `[auth]` header rides the upload but is absent from the hit evidence. |
| unit — upload check | `tests/unit/test_checks_upload.py` (new) | `UnrestrictedUploadCheck` renders one finding per hit; `Category.UPLOAD`; severity carried from the hit; `dedup_key` per (field, outcome); `[]` with no hits. |
| unit — engine/points/checks/cli/config/http | edits | `"ldap"` / `"xpath"` / `"ssi"` in `_BASE_ORDER` / `_DETECTORS` / `KIND_BY_CHECK_ID`; the three `is_*like`; `list-checks` shows the four; `--file-upload` sets the field; `file_upload` / `upload_budget` round-trip + override; `Category.UPLOAD` round-trips through the finding model + JSON reporter; `HttpClient.request(files=)` sends multipart, mutually exclusive with `data` / `content`. |
| unit — Category | `tests/unit/test_findings.py` | `Category.UPLOAD` value; a `Finding` with it serialises / re-loads. |
| integration | `tests/integration/test_scan_fixture_app.py` | Active + `--file-upload` insecure → `upload.unrestricted` (server-exec, inline-html, traversal, put shapes), `injection.ldap` (`/dir` `user`), `injection.xpath` (`/xdoc` `node`), `injection.ssi` (`/page` `tpl`); Active **without** `--file-upload` → the three injection checks, no upload file / `PUT` sent; passive → none, no multipart / `PUT` / LDAP / XPath / SSI payload; Active hardened + `--file-upload` → **zero**; deterministic; within budget. |
| quality gate | — | `ruff → black → mypy src → lint-imports → pytest` green at every stage. |

## Open questions

None. Ready for `/spec tasks`.

## Implementation notes

Recorded at close (2026-09-08). What shipped, and where it differed from the
design above:

- **`detect/_diff.py`** exports `ratio`, `two_sided_split`, `wider_then_same`
  (no `_norm` — it calls `normalize_body` directly). `sqli.py` kept a local
  `_GAP = 0.90` constant for its page-stability guard (a re-check that is not one
  of the two rules), and now imports `ratio` / `two_sided_split`. The `sqli`
  tests were untouched and stayed green.
- **`ldap` boolean probe** — the TRUE payload *replaces* the value with a
  widening filter (`*)(uid=*))(|(uid=*` / `*`); the FALSE payload is appended.
  Confirmation re-sends both. `xpath` appends both (a classic true/false).
- **`_PER_POINT_REQUEST_CAP` 35 → 38, `request_budget` 600 → 650** as designed;
  measured fine against the fixture — the three families fire within budget.
- **`_BASE_ORDER`** — all three new families (`ldap`, `xpath`, `ssi`) sit
  *after* `sqli-time` (order `… crlf, sqli-time, cmdi, ldap, xpath, ssi, xxe,
  ssrf`). The design sketch had `ssi` right after `crlf`; that pushed the
  budget-fragile `sqli-time` past the per-point cap on the dense fixture and it
  stopped firing — moved back.
- **The `_*LIKE_NAMES` lists are much narrower than the design sketch.** The
  sketch's `_XPATHLIKE_NAMES` included `id` / `q` / `name` / `title` and
  `_SSILIKE_NAMES` included `q` / `search` / `name` / `body` — generic names on
  which front-loading `xpath` / `ssi` crowded the per-point budget and starved
  `sqli-time` (`test_insecure_profile_active_finds_every_injection`). Final:
  `_LDAPLIKE_NAMES` = directory-specific (`user`, `uid`, `cn`, `dn`, `ou`,
  `member`, `samaccountname`, …); `_XPATHLIKE_NAMES` = XML/XPath-specific
  (`xpath`, `xquery`, `xsl`, `node`, `nodeset`, …); `_SSILIKE_NAMES` =
  include-specific (`ssi`, `shtml`, `include`, `file`, `page`, `tpl`,
  `template`, `partial`, `fragment`, …). Each detector still runs on any point
  from `_BASE_ORDER`, budget permitting — the lists only re-prioritise.
- **Fixture XPath endpoint param `title` → `node`** — with the narrower
  `_XPATHLIKE_NAMES`, `title` no longer front-loads `xpath`, and on the dense
  fixture `xpath` (`_BASE_ORDER` position 11) ran out of per-point budget before
  its first probe. `/xdoc?node=…` front-loads it — and a realistic XPath
  injection point does carry an XPath-flavored name.
- **`HttpClient.request(files=)`** — `_Files = dict[str, tuple[str, bytes, str]]`.
  `content` + `files` together raises `ValueError` (not an `assert` — it must
  fire under `-O`). The redirect loop resets `current_files` to `None` on a
  301/302/303 alongside `params` / `data`.
- **`UploadScanner._classify` order** — server-exec → **traversal** → inline-html
  → inert-accept. Traversal moved ahead of inline-html: a `../`-named HTML file
  served inline is the *traversal* finding (where it was written is the stronger
  signal). `_probe_form` drops any `inert-accept` hit when a stronger outcome
  also fired on the same form.
- **`_UPLOAD_PREFIXES`** is 7, not 5 — added `/img/` and `/assets/`.
- **Fixture** — a `Route("/{fname}", _root_file_insecure)` catch-all (insecure
  only, registered last) serves a traversal-named upload from the web root;
  `app.state.uploads` / `app.state.root_uploads` are reset per app. The upload
  `<form>` went into the shared `_FORMS` (both profiles) with a hidden
  `csrf_token` so `csrf.form.no-token` stays quiet — its only fuzzable field is
  the `type="file"` one, which the injection package already skips. Three links
  (`/dir`, `/xdoc`, `/page`) joined `_INJECTION_LINKS`, so the crawl reaches
  **20** pages (was 17); `test_crawler_reaches_the_linked_pages` updated. The
  LDAP / XPath fixtures fake the sink offline with a lookup table (spec 006
  `SLEEP()` pattern); `.php` / `.jsp` "execution" is a regex that collapses
  `marker:<?php echo A*B; ?>` to `marker:AB`.
- **`_render.summary`** gained `file_upload: bool` — a "File-upload testing:
  enabled — benign marker files were left on the target" note, not the
  "N file(s) uploaded" count the design sketched (the pass reports no count to
  the orchestrator; a boolean note is enough and matches the authenticated-scan
  line's spirit).
- **Integration `scan` fixture** — `file_upload` does **not** force Active Mode
  (unlike `active` / `stored_xss`), so a passive test can pass `file_upload=True`
  and assert the opt-in is ignored. The fixture's Active `[injection]` block also
  raises `request_budget` to 1200 (past the 650 model default): the insecure
  fixture is unusually dense — every injection class has a dedicated endpoint —
  and the slow `sqli-time` / stored-XSS phases need the headroom on it.
- **`_STORED_REFETCH_CAP` 60 → 120** (spec 008 constant). Specs 011-014 each
  added crawlable endpoints and detector families that fuzz a stored sink; on the
  fixture's guestbook (which stores every submission) the injection pass now
  leaves ~60 entries before the stored pass runs, so the marker's own entry sat
  past the old cap and the Phase B re-crawl stopped before reaching it
  (`test_stored_xss_found_on_the_insecure_guestbook`). A real target is bounded
  by its actual link count and Phase B still respects `request_budget`, so the
  larger ceiling costs nothing there. `docs/active-injection.md` updated.
- **No API / UI / reporter / migration change.** `Category.UPLOAD` is opaque
  downstream (`meta.py` returns `check.category.value`; the dashboard derives its
  filter from the data). `import-linter` contracts unchanged (the new
  `webvigil.checks.upload` is under `webvigil.checks`).
- **pytest:** 741 at spec 013 close → **791** at 014 close.
- **Manual verification:** an Active `--file-upload` scan of the fixture reports
  `upload.unrestricted` (multiple shapes), `injection.ldap` (`/dir`),
  `injection.xpath` (`/xdoc`), `injection.ssi` (`/page`); the hardened profile
  reports none; `webvigil list-checks` shows the four with `INJECTION` /
  `UPLOAD`; a request capture confirms the only state-changing verb is the gated
  `PUT` of a marker and no `[auth]` credential appears in the report.
