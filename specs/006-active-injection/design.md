---
feature: Active injection — reflected XSS, SQL injection, path traversal, open redirect (Active Mode)
status: done
date: 2026-09-06
related:
  - 001-foundation/design.md
  - 004-deps-fingerprint/design.md
  - 005-info-disclosure/design.md
origin: conception
---

# 006 — Active injection — Design

> Requirements: [`requirements.md`](requirements.md). This document is the *how*.
> Traceability tags (`— RF-NN` / `— RNF-NN`) point back to it.

## Overview

006 introduces the first `ACTIVE` checks. The shape mirrors spec 004 (dependency
fingerprint) and spec 005 (disclosure probe): **one orchestrator pass does the network
work and leaves structured hits on `ctx.observations`; thin checks turn hits into
findings** (ADR-1). The pass here is `InjectionScanner`.

```
Orchestrator.run()
  ├─ crawl (unchanged)                         → pages
  ├─ extract_forms(pages, target)   NEW        → forms          (webvigil.crawler.forms, ADR-3)
  ├─ _fingerprint(...)  (spec 004)
  ├─ _probe_disclosure(...)  (spec 005)
  ├─ _inject(check_types, http, target, pages, forms, warnings)  NEW   (ADR-1, ADR-2)
  │     └─ InjectionScanner.run()
  │           1. enumerate_points(pages, forms)        → injection points  (points.py, RF-06)
  │           2. per point: one shared baseline request                    (RF-07)
  │           3. per point: run the enabled detectors, drawing on one       (RF-08..RF-11)
  │              shared ActiveBudget                                        (RF-03, RF-12)
  │           4. collect InjectionHit[]  + cap warnings
  ├─ ScanContext(observations=Observations(... injection_hits=hits))
  └─ run checks  → the six injection.* checks filter hits by `kind`         (checks.py, RF-08..RF-11)
```

The pass runs **only** when `scan.mode is ACTIVE` **and** at least one `injection.*` check
is in the selected set (ADR-2) — so a passive scan is byte-for-byte unchanged and disabling
all six checks costs zero crafted requests.

Everything stays inside the engine's rules: new code in `webvigil.checks.injection` plus
small, additive changes to `webvigil.http` (verbs) and `webvigil.crawler` (forms); no new
runtime dependency (`re`, `difflib`, `urllib.parse`, `time`); the `import-linter` contract
is unchanged (all three packages are already `source_modules`). A `injection.*` finding is
an ordinary `Finding` with `location.method` / `location.param` populated (both modelled
since spec 001) and rides spec 001's four reporters and spec 002/003's persistence and
dashboard with **no migration and no `openapi.json` regen** (RF-19). The one reporter touch
is additive and general (SARIF `logicalLocations`, ADR-8).

## Module layout

```
src/webvigil/core/findings.py              + Category.INJECTION                      — RF-08
src/webvigil/core/config.py                + InjectionSection                        — ADR-4
src/webvigil/core/context.py               + Observations.injection_hits             — ADR-6
src/webvigil/core/orchestrator.py          + _inject() pass, _INJECTION_CHECK_IDS    — ADR-1, ADR-2

src/webvigil/http/client.py                get() → thin wrapper of request();        — ADR-9, RF-15
                                           request(method, url, *, params, data, headers)

src/webvigil/crawler/forms.py     NEW      Form, FormField, extract_forms()          — ADR-3, RF-05

src/webvigil/checks/injection/    NEW package  (Category.INJECTION, mode = ACTIVE)
    __init__.py                            imports checks so @register runs
    models.py                              InjectionPoint · Baseline · InjectionHit · ActiveBudget
    payloads.py                            the documented payload constants          — RNF-07
    points.py                              enumerate_points() + exclusion / priority heuristics — RF-04, RF-06
    engine.py                              InjectionScanner (baseline, fan-out, budget) — RF-07, RF-12
    detect/
        __init__.py
        xss.py                             reflected-XSS detector                    — RF-08
        sqli.py                            error / boolean / time detectors          — RF-09
        traversal.py                       path-traversal detector                   — RF-10
        redirect.py                        open-redirect detector                    — RF-11
    checks.py                              _InjectionCheck + the six Check classes   — RF-08..RF-11, RF-16

src/webvigil/cli/app.py                    + --time-based-sqli/--no-time-based-sqli  — RF-16
src/webvigil/cli/_render.py                + "Active injection: N finding(s)" line   — RF-16, ADR-7
src/webvigil/reporting/sarif.py            + logicalLocations when location.key set  — ADR-8, RF-18

docker/target.Dockerfile          NEW      the vulnerable target image              — RF-24
docker-compose.yml                         + profile-gated `target` service         — RF-24
webvigil.example.toml                      + [injection] block                      — ADR-4
pyproject.toml                             (no change — payloads are a .py module)
tests/fixtures/app.py                      + injectable insecure endpoints          — RF-20
```

## Components

### `Category.INJECTION` — RF-08

```python
class Category(StrEnum):
    HEADERS = "HEADERS"
    COOKIES = "COOKIES"
    TLS = "TLS"
    CORS = "CORS"
    DEPS = "DEPS"
    DISCLOSURE = "DISCLOSURE"
    INJECTION = "INJECTION"
```

Replaces the `# Reserved for later specs: INJECTION.` comment. The API returns
`check.category.value` as a plain string and the dashboard derives its filter list from the
data (verified: `api/routes/meta.py:30`, `web/src/app/(app)/checks/page.tsx:16`), so the
new value flows through with no schema or component change (RF-19).

### Form discovery — `webvigil/crawler/forms.py` — ADR-3, RF-05

Parsed once, from the bodies the crawler already fetched — **no new requests**. The
crawler's `discover()` is untouched; the orchestrator calls `extract_forms(pages, target)`
right after the crawl.

```python
@dataclass(frozen=True, slots=True)
class FormField:
    name: str
    type: str          # lower-cased <input type>; "textarea" / "select" for those elements
    value: str          # current value: @value, first <option>, or <textarea> text

@dataclass(frozen=True, slots=True)
class Form:
    method: str        # "GET" | "POST"  (anything else → "GET", per the HTML spec)
    action: str        # absolute, normalized; resolved against the page URL; empty action → page URL
    enctype: str       # "application/x-www-form-urlencoded" (default) | "multipart/form-data" | "text/plain"
    fields: tuple[FormField, ...]
    source_url: str

def extract_forms(pages: tuple[Page, ...], target: Target) -> tuple[Form, ...]:
    # selectolax; for each in-scope ok HTML page, for each <form>:
    #   - resolve action (urljoin(page.url, action or "")); drop if not target.in_scope(action)
    #   - method = "POST" if form@method.upper() == "POST" else "GET"
    #   - fields from <input> / <textarea> / <select> that carry a @name
    #   - dedup identical forms by (method, action, tuple(sorted(field names)))
```

`extract_forms` reports **every** in-scope form. The decision to fuzz or skip one (the
authentication / destruction heuristic — RF-04) lives in `points.py`, not here: the crawler
owns *what the site exposes*, the injection package owns *what to do with it* (ADR-3).

### HTTP verbs — `webvigil/http/client.py` — ADR-9, RF-15

`get()` becomes a one-line wrapper; a new `request()` carries the method through the same
scope guard, rate limiter, timeout, and manual redirect loop:

```python
_IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS"})
_METHOD_KEEPS_BODY_ON_REDIRECT = frozenset({307, 308})

async def request(
    self, method: str, url: str, *,
    params: dict[str, str] | list[tuple[str, str]] | None = None,
    data: dict[str, str] | list[tuple[str, str]] | None = None,
    headers: dict[str, str] | None = None,
    allow_out_of_scope: bool = False,
) -> Response: ...

async def get(self, url, *, headers=None, allow_out_of_scope=False) -> Response:
    return await self.request("GET", url, headers=headers, allow_out_of_scope=allow_out_of_scope)
```

Behaviour, all unchanged from spec 001 except where noted:

- **Scope guard** — same pre-flight `allows()` / `check()`; `data` never carries a URL we
  request, so an off-scope value in a form field is fine (RF-02).
- **Redirects** — same in-scope-only manual follow. A `301/302/303` drops to `GET` with no
  body (browser behaviour); `307/308` re-sends method + body. An out-of-scope `Location`
  still breaks the loop and is recorded in `final_location` / `redirected_out_of_scope`
  (the open-redirect detector reads exactly this — RF-11).
- **Retries** — `_request_with_retry(method, url, ...)`:
  - `method in _IDEMPOTENT`: retry on `TransportError` / `TimeoutException` **and** on a
    `5xx` (unchanged).
  - otherwise (`POST`): retry **only** on a pre-send `httpx.ConnectError` /
    `httpx.ConnectTimeout` (the request never reached the server); **never** on a `5xx` or a
    `ReadTimeout` — no double-submit (ADR-9).
- `HttpStats` gains `crafted_requests: int`, bumped by `request()` when `method != "GET"` or
  a caller flag says so; surfaced like the existing counters.

### `webvigil.checks.injection` — the package

#### `models.py` — RF-06, RF-07, RF-12

```python
@dataclass(frozen=True, slots=True)
class InjectionPoint:
    method: str                                   # "GET" | "POST"
    url: str                                       # request URL without the fuzzed query
    param: str                                      # the parameter under test
    original: str                                   # its current value
    params: tuple[tuple[str, str], ...]              # the full query (GET) or body (POST) set
    source: str                                     # "query" | "form"

    @property
    def key(self) -> str:                            # dedup identity — RF-06, RF-14
        return f"{self.method} {urlsplit(self.url)._replace(query='').geturl()} :: {self.param}"

@dataclass(frozen=True, slots=True)
class Baseline:
    status: int
    body: str                                       # whitespace-collapsed, volatile tokens masked
    raw_body: str                                    # untouched — for "signature absent from baseline"
    length: int
    elapsed_ms: float

@dataclass(frozen=True, slots=True)
class InjectionHit:
    kind: str          # "xss" | "sqli-error" | "sqli-boolean" | "sqli-time" | "traversal" | "redirect"
    check_id: str
    method: str
    url: str
    param: str
    severity: Severity
    confidence: Confidence
    title: str
    payload: str
    evidence: tuple[tuple[str, str], ...]            # (label, content) pairs → EvidenceItem.of in the check

@dataclass
class ActiveBudget:                                  # RF-03, RF-12, ADR-7
    request_limit: int                               # [injection] request_budget      (default 500)
    per_point_limit: int                             # _PER_POINT_REQUEST_CAP          (30)
    time_based_limit: int                            # _TIME_BASED_SLEEP_CAP           (8)
    spent: int = 0
    time_based_spent: int = 0
    point_spent: int = 0
    hit_request_cap: bool = False

    def take(self, n: int = 1) -> bool: ...           # False when request_limit or per_point_limit reached
    def take_time_based(self) -> bool: ...            # also decrements the general budget
    def start_point(self) -> None: ...                # resets point_spent
```

`ActiveBudget` is a plain object mutated from `async` code that never `await`s between the
check and the decrement, so the single event loop makes it safe without a lock (same
argument as `Observations` — `context.py:92`).

#### `payloads.py` — RNF-07

Module-level constants, heavily commented — the "documented in-repo payload set". No TOML,
no packaging artifact (contrast spec 005's catalogue, which needed structured per-entry
validators). Shape:

```python
XSS_TOKEN_BYTES = 6
XSS_PROBE = "wv{token}"                               # plain — is anything reflected at all?
XSS_BREAKERS = (                                      # {token} substituted per run
    'wv{token}"><svg/onload=wv{token}>',
    "wv{token}'></script><script>wv{token}</script>",
    '"><img src=x onerror=wv{token}>',
    "javascript:wv{token}",
)

SQLI_ERROR = ("'", '"', "')", "';", "\\", "' OR '1")
SQL_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("MySQL",      re.compile(r"You have an error in your SQL syntax|MySqlException|valid MySQL result", re.I)),
    ("PostgreSQL", re.compile(r"PSQLException|unterminated quoted string|syntax error at or near", re.I)),
    ("MSSQL",      re.compile(r"Unclosed quotation mark|Incorrect syntax near|System\.Data\.SqlClient", re.I)),
    ("Oracle",     re.compile(r"ORA-0\d{4}|quoted string not properly terminated", re.I)),
    ("SQLite",     re.compile(r'SQLITE_ERROR|unrecognized token|near ".+?": syntax error|sqlite3\.OperationalError', re.I)),
)
SQLI_BOOLEAN_PAIRS = (                                 # (true, false); appended to `original`
    ("' AND '1'='1", "' AND '1'='2"),
    (" AND 1=1-- -", " AND 1=2-- -"),
    ("') OR ('1'='1", "') AND ('1'='2"),
)
SQLI_TIME = (                                          # {d} = delay seconds
    ("MySQL",      "' AND SLEEP({d})-- -"),
    ("PostgreSQL", "' || pg_sleep({d})-- -"),
    ("MSSQL",      "'; WAITFOR DELAY '0:0:{d}'-- -"),
    ("generic",    " AND SLEEP({d})"),
)

TRAVERSAL = (                                          # targets /etc/passwd and win.ini
    "../../../../../../etc/passwd", "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini", "../../../../../../windows/win.ini",
)
TRAVERSAL_SIGNATURES = (
    re.compile(r"root:.*?:0:0:"),
    re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.I),
)

REDIRECT_SENTINEL = "webvigil.invalid"                 # RFC-guaranteed NXDOMAIN, never requested
REDIRECT_PAYLOADS = (
    "https://webvigil.invalid/", "//webvigil.invalid/", "https:/webvigil.invalid",
    "https:\\\\webvigil.invalid", "/\\webvigil.invalid", "\thttps://webvigil.invalid",
    "https://{host}@webvigil.invalid",                 # {host} = target host
)
```

#### `points.py` — RF-04, RF-06

```python
_FUZZ_TYPES = frozenset({"", "text", "search", "email", "url", "tel", "number", "textarea"})
_SKIP_TYPES = frozenset({"hidden", "submit", "button", "image", "file", "password",
                         "reset", "checkbox", "radio", "select"})
_EXCLUDE_FORM_RE = re.compile(
    r"log[\s_-]?in|log[\s_-]?out|sign[\s_-]?in|sign[\s_-]?out|sign[\s_-]?up|register|"
    r"delete|remove|destroy|\bdrop\b|password|passwd|reset|checkout|\bpay\b|purchase|"
    r"\border\b|transfer|unsubscribe|deactivate|logoff", re.I)
_PREFERRED_REDIRECT = frozenset({"next", "url", "redirect", "redirect_uri", "redir", "return",
    "returnurl", "return_to", "dest", "destination", "continue", "to", "goto", "target", "out", "link"})
_PATHLIKE_NAMES = frozenset({"file", "filename", "path", "page", "doc", "document", "template",
    "tpl", "include", "inc", "dir", "folder", "download", "attachment", "load", "read"})

def enumerate_points(
    pages: tuple[Page, ...], forms: tuple[Form, ...], *, max_points: int
) -> tuple[list[InjectionPoint], list[str]]:
    # query points: for each ok page, urlsplit(page.requested_url).query → one point per param name
    # form points:  for each form where not _EXCLUDE_FORM_RE.search(action + submit text + field names):
    #                 one point per field whose type in _FUZZ_TYPES
    # dedup on InjectionPoint.key; stable sort (url, param); if len > max_points → truncate + warning
```

`enumerate_points` also tags each point for the priority heuristic (Resolved-during-design
8): a point whose `param` is in `_PATHLIKE_NAMES` or whose `original` value looks path-like
is tried by the traversal detector first; a point whose `param` is in `_PREFERRED_REDIRECT`
is tried by the redirect detector first. Every point still gets XSS + error-based +
boolean-based SQLi; traversal / time-based / redirect fill the remaining budget
breadth-first after the prioritised points.

#### `engine.py` — `InjectionScanner` — RF-07, RF-12, RF-13

```python
_DETECTORS = {                       # kind → module-level async detect(point, baseline, http, budget, cfg)
    "xss":           xss.detect,
    "sqli-error":    sqli.detect_error,
    "sqli-boolean":  sqli.detect_boolean,
    "sqli-time":     sqli.detect_time,
    "traversal":     traversal.detect,
    "redirect":      redirect.detect,
}
_KIND_BY_CHECK_ID = {
    "injection.xss.reflected":       "xss",
    "injection.sqli.error-based":    "sqli-error",
    "injection.sqli.boolean-based":  "sqli-boolean",
    "injection.sqli.time-based":     "sqli-time",
    "injection.traversal.path":      "traversal",
    "injection.redirect.open":       "redirect",
}

class InjectionScanner:
    def __init__(self, http, target, config: InjectionSection, pages, forms, selected_kinds: set[str]): ...

    async def run(self) -> InjectionReport:
        points, warnings = enumerate_points(self._pages, self._forms,
                                            max_points=self._config.max_injection_points)
        budget = ActiveBudget(request_limit=self._config.request_budget,
                              per_point_limit=_PER_POINT_REQUEST_CAP,
                              time_based_limit=_TIME_BASED_SLEEP_CAP if self._config.time_based_sqli else 0)
        hits: list[InjectionHit] = []
        for point in _prioritised(points):
            if budget.spent >= budget.request_limit:
                warnings.append(f"active injection stopped at the {budget.request_limit}-request budget")
                break
            budget.start_point()
            baseline = await self._baseline(point, budget)
            if baseline is None:
                continue
            for kind in _ordered_kinds(point, self._selected_kinds):
                hits += await _DETECTORS[kind](point, baseline, self._http, budget, self._config)
        return InjectionReport(hits=hits, warnings=warnings + budget.warnings())
```

- **Baseline** (RF-07): one `request()` with the point's original values; `Baseline` keeps
  the raw body and a normalised body (whitespace collapsed, `_VOLATILE_RE` — CSRF inputs,
  ISO timestamps, long hex/uuid — masked) plus timing. Shared by every detector for that
  point; counts against the budget.
- Every crafted request goes through `self._http.request(...)` and is `take()`-gated on the
  budget. `RequestFailed` / `OutOfScopeError` are swallowed (the point is skipped), exactly
  like spec 004's `_fetch` and spec 005's `_get`.
- The scanner receives `selected_kinds` from the orchestrator (derived from `check_types`),
  so a disabled check's detector never runs (RF-16) and `time_based_sqli = false` drops
  `sqli-time` before any sleep.

#### The detectors — `detect/` — RF-08..RF-11, RF-13

Each is a module-level `async def` returning `list[InjectionHit]`. All comparison is against
the **shared baseline**; all use `_PER_POINT_REQUEST_CAP` via `budget.take()`.

**`xss.detect`** — RF-08
1. Send `XSS_PROBE` (plain token). If the token is not in `response.text` → return `[]`
   (nothing reflects; no point trying breakers).
2. Send one–two `XSS_BREAKERS`. A hit needs the breaker payload's **HTML-significant
   characters present verbatim** (`payload in response.text`, i.e. `<`, `>`, `"` came back
   unencoded — not `&lt;`, not `%3C`, not stripped) **and** `response.is_html`.
3. `context` from where the verbatim match sits (selectolax: element text / attribute /
   `<script>` / `href|src` value). `confidence = HIGH` for a clean tag/attribute break,
   `MEDIUM` when the match is only inside an existing `<script>` string literal.
4. Negative cases (`&lt;`, `%3C`, `text/plain`, comment-only) fail step 2 → `[]`.

**`sqli.detect_error`** — RF-09
- Send each `SQLI_ERROR` payload appended to `original`. Hit iff a `SQL_ERROR_SIGNATURES`
  regex matches `response.text` **and not** `baseline.raw_body`. `title` names the DBMS;
  `confidence = HIGH`.

**`sqli.detect_boolean`** — RF-09
- For the first `SQLI_BOOLEAN_PAIRS` entry: send TRUE, send FALSE.
- `ratio = difflib.SequenceMatcher(None, a, b).quick_ratio()` on normalised bodies.
- Candidate iff `ratio(baseline, true) >= _BOOLEAN_SIMILARITY (0.95)` **and**
  `ratio(baseline, false) <= _BOOLEAN_GAP (0.90)`.
- On a candidate: re-fetch the baseline once (stability — if it now differs from the first
  baseline by more than `1 - _BOOLEAN_GAP`, the page is dynamic → **discard**), then run a
  **second pair** and require the same split. Hit iff both rounds agree. `confidence = HIGH`.

**`sqli.detect_time`** — RF-09 (budget: `budget.take_time_based()`)
- Send a `D = 0` control and a `D = time_based_delay_s` payload (per DBMS dialect; stop at
  the first that reproduces).
- Candidate iff `elapsed(D) - max(elapsed(control), baseline.elapsed_ms) >= _TIME_DELTA_S
  (≈ delay − 1s)`.
- Confirm with `D = ceil(delay / 2)` and require the delta to roughly halve. Hit iff both
  hold. `confidence = HIGH` (two-point scaling) / `MEDIUM` (single delay only, budget
  exhausted before the confirm).

**`traversal.detect`** — RF-10
- Send `TRAVERSAL` payloads (path-like points first). Hit iff a `TRAVERSAL_SIGNATURES`
  regex matches `response.text` **and not** `baseline.raw_body`. Evidence quotes the leaked
  line (trimmed). `confidence = HIGH`.

**`redirect.detect`** — RF-11
- Send `REDIRECT_PAYLOADS` (preferred-name points first). Hit iff **any** of:
  `response.final_location` host == `REDIRECT_SENTINEL` (the HTTP layer refused to follow it
  off-scope and recorded it — RF-02); or a `3xx` `Location` header resolving to the
  sentinel; or `<meta http-equiv=refresh ... url=…sentinel>` / `location.href|replace(
  "…sentinel")` in the body. `confidence = HIGH` for the `Location`/`final_location` path,
  `MEDIUM` for the body-only (meta/JS) path.

#### `checks.py` — the six checks — RF-08..RF-11, RF-16

```python
class _InjectionCheck(Check):
    kind: ClassVar[str]
    category = Category.INJECTION
    mode = ScanMode.ACTIVE

    async def run(self, ctx: ScanContext) -> list[Finding]:
        return [
            self.finding(
                title=hit.title,
                description=_DESCRIPTION[self.kind],
                remediation=_REMEDIATION[self.kind],
                severity=hit.severity,
                confidence=hit.confidence,
                location=Location(url=hit.url, method=hit.method, param=hit.param),
                evidence=[EvidenceItem.of(label, content) for label, content in hit.evidence],
            )
            for hit in ctx.observations.injection_hits
            if hit.kind == self.kind
        ]

@register
class ReflectedXssCheck(_InjectionCheck):
    id = "injection.xss.reflected"; name = "Reflected cross-site scripting"
    kind = "xss"; default_severity = Severity.HIGH
    cwe = (79, 20); references = (OWASP_XSS,)

@register
class SqliErrorBasedCheck(_InjectionCheck):
    id = "injection.sqli.error-based"; name = "SQL injection (error-based)"
    kind = "sqli-error"; default_severity = Severity.HIGH; cwe = (89, 209)

@register
class SqliBooleanBasedCheck(_InjectionCheck):
    id = "injection.sqli.boolean-based"; name = "SQL injection (boolean-based blind)"
    kind = "sqli-boolean"; default_severity = Severity.HIGH; cwe = (89,)

@register
class SqliTimeBasedCheck(_InjectionCheck):
    id = "injection.sqli.time-based"; name = "SQL injection (time-based blind)"
    kind = "sqli-time"; default_severity = Severity.HIGH; cwe = (89,)

@register
class PathTraversalCheck(_InjectionCheck):
    id = "injection.traversal.path"; name = "Path traversal"
    kind = "traversal"; default_severity = Severity.HIGH; cwe = (22, 23)

@register
class OpenRedirectCheck(_InjectionCheck):
    id = "injection.redirect.open"; name = "Open redirect"
    kind = "redirect"; default_severity = Severity.MEDIUM; cwe = (601,)
```

`title` is set by the detector, e.g. `"Reflected XSS via the 'q' parameter"`,
`"SQL injection (MySQL) via the 'id' parameter"`, `"Open redirect via the 'next'
parameter"`. `Location.url` is the point URL **without** the fuzzed query, so the
fingerprint (`check_id` + url + `location.key` (= param) + `dedup_key=""`) collapses
`/search?q=a` and `/search?q=b` to one finding (RF-14).

### `ScanContext.observations.injection_hits` — ADR-6

```python
# context.py
if TYPE_CHECKING:
    from webvigil.checks.disclosure.probe import ProbeHit
    from webvigil.checks.injection.models import InjectionHit

@dataclass(slots=True)
class Observations:
    detections: tuple[Detection, ...] = ()
    probe_hits: tuple[ProbeHit, ...] = ()
    injection_hits: tuple[InjectionHit, ...] = ()
    _technologies: ...
    warnings: list[str] = ...
```

`TYPE_CHECKING`-only import, exactly like `ProbeHit` (spec 005 ADR-3). No runtime
dependency from `webvigil.core` on `webvigil.checks`.

### Orchestrator wiring — ADR-1, ADR-2

```python
from webvigil.checks.injection.engine import InjectionScanner, InjectionHit
from webvigil.checks.injection.checks import _KIND_BY_CHECK_ID   # or a public map
from webvigil.crawler.forms import extract_forms

async def run(self, raw_target: str) -> ScanResult:
    ...
    async with HttpClient(target, self._config) as http:
        pages = tuple(await Crawler(http, target, self._config).discover())
        forms = extract_forms(pages, target)
        check_types = self._select_checks(warnings)
        detections = await self._fingerprint(check_types, http, target, pages, warnings)
        probe_hits = await self._probe_disclosure(check_types, http, target, pages, warnings)
        injection_hits = await self._inject(check_types, http, target, pages, forms, warnings)
        context = ScanContext(..., observations=Observations(
            detections=detections, probe_hits=probe_hits, injection_hits=injection_hits))
        ...

async def _inject(self, check_types, http, target, pages, forms, warnings) -> tuple[InjectionHit, ...]:
    if self._config.scan.mode is not ScanMode.ACTIVE:
        return ()
    selected = {_KIND_BY_CHECK_ID[c.id] for c in check_types if c.id in _KIND_BY_CHECK_ID}
    if not selected:
        return ()
    report = await InjectionScanner(
        http, target, self._config.injection, pages, forms, selected
    ).run()
    warnings.extend(report.warnings)
    return tuple(report.hits)
```

The Active-Mode gate itself is untouched (`_enforce_active_gate`, spec 001). `_inject`
returns early on a passive scan, so the pass is genuinely inert there (RF-01).

### Config — `[injection]` — ADR-4

```python
class InjectionSection(_Section):
    """Active-injection tuning (spec 006). Only consulted on an Active scan."""
    request_budget: int = 500
    max_injection_points: int = 200
    time_based_sqli: bool = True
    time_based_delay_s: int = 5

class ScanConfig(_Section):
    ...
    disclosure: DisclosureSection = DisclosureSection()
    injection: InjectionSection = InjectionSection()
```

`with_overrides` gains `injection` in its docstring's section list. A separate section (not
extra keys on `[active]`) — ADR-4.

### CLI — RF-16

- **`scan`** gains one option:
  ```python
  time_based_sqli: Annotated[bool | None, typer.Option(
      "--time-based-sqli/--no-time-based-sqli",
      help="Send time-delay SQLi payloads during an Active scan (slower). On by default.",
  )] = None
  ```
  `_build_config` gains `time_based_sqli: bool | None`, builds
  `injection_overrides = {"time_based_sqli": time_based_sqli}` when not `None`, and passes
  `injection=injection_overrides` to `base.with_overrides(...)`. `request_budget`,
  `max_injection_points`, `time_based_delay_s` are config-file only (ADR-4,
  Resolved-during-requirements 7).
- **`list-checks`** — no code change; the six `injection.*` checks appear automatically with
  category `INJECTION`, mode `active`.
- **`_render.summary`** — after the disclosure block:
  ```python
  if result.metadata.mode is ScanMode.ACTIVE:
      n = sum(1 for f in result.findings if f.check_id.startswith("injection."))
      if n:
          _console.print(f"[red]Active injection: {n} finding{'' if n == 1 else 's'}[/]")
  ```
  No injection-point / crafted-request counts in the summary — they are not in `ScanResult`
  (ADR-7); a budget/point-cap hit rides `result.warnings` and is already printed.

### Reporters — RF-18, ADR-8

- JSON / HTML / Markdown — **no change**. `location.method` and `location.param` already
  serialise (JSON) and render (`_render` prints `location.key`; HTML/MD templates show the
  location line).
- **SARIF** — one additive change in `_result`, general (helps every finding that has a
  sub-location — cookies, headers — not just injection):
  ```python
  result = { ...existing... }
  if finding.location.key:
      result["locations"][0]["logicalLocations"] = [
          {"name": finding.location.key,
           "kind": "parameter" if finding.location.param else "member",
           "fullyQualifiedName": f"{finding.location.method} {finding.location.url}#{finding.location.key}"}
      ]
  return result
  ```
  Still one `rule` per `check_id` (`_unique_rules`, unchanged). The payload is in the
  finding `evidence`, which SARIF already folds into the result message via `description`.

### Web API / Web UI — RF-19

No change. Confirmed during design:

| Surface | Why nothing changes |
|---|---|
| DB schema / Alembic | `injection.*` findings are `Finding`s; spec 002 persists findings losslessly (`api/mapping.py`), `Location.method` / `Location.param` included. No migration. |
| `openapi.json` / `api-types.ts` | `CheckOut.category` is `str` (`api/schemas.py`); `INJECTION` needs no enum change. No regen. |
| `GET /api/checks` | `meta.py:30` emits `check.category.value` — the new value passes through. |
| Dashboard check catalogue + filter | `web/.../checks/page.tsx:16` derives the category list from the data — `INJECTION` appears on its own. |
| "New scan" form / scan detail | Active Mode + `authorized_by` already supported end to end (spec 002 `schemas.py:81`, spec 003). |

No `web` quality gate for this spec (nothing under `web/`, `webvigil.reporting` changes are
engine-side only and covered by `test_reporters.py`).

## Data model

### `InjectionPoint` / `Baseline` / `InjectionHit` / `ActiveBudget`

Internal to `webvigil.checks.injection` (`models.py`). Only `InjectionHit` crosses a module
boundary — into `context.py` under `TYPE_CHECKING` and into `checks.py` at runtime.

### `Form` / `FormField`

`webvigil.crawler.forms`. Consumed by `points.enumerate_points`. Not stored on `Page`, not
in `ScanResult`.

### `ScanResult`

**Unchanged.** No `injection`-shaped field (ADR-7). New `Category.INJECTION` value on
findings; cap warnings in `warnings`.

## Interfaces

### Check ids — RF-08..RF-11, RF-16

| id | kind | category | mode | default severity | confidence | cwe |
|---|---|---|---|---|---|---|
| `injection.xss.reflected` | `xss` | INJECTION | active | HIGH | HIGH / MEDIUM | 79, 20 |
| `injection.sqli.error-based` | `sqli-error` | INJECTION | active | HIGH | HIGH | 89, 209 |
| `injection.sqli.boolean-based` | `sqli-boolean` | INJECTION | active | HIGH | HIGH | 89 |
| `injection.sqli.time-based` | `sqli-time` | INJECTION | active | HIGH | HIGH / MEDIUM | 89 |
| `injection.traversal.path` | `traversal` | INJECTION | active | HIGH | HIGH | 22, 23 |
| `injection.redirect.open` | `redirect` | INJECTION | active | MEDIUM | HIGH / MEDIUM | 601 |

### Config — RF-16, ADR-4

| Key | Type | Default | Meaning |
|---|---|---|---|
| `[injection] request_budget` | int | `500` | Max crafted requests per scan (baselines + payloads + confirms). Hitting it → warning. |
| `[injection] max_injection_points` | int | `200` | Max injection points tested. Excess → warning. |
| `[injection] time_based_sqli` | bool | `true` | Send time-delay SQLi payloads. `false` drops `sqli-time` before any sleep. |
| `[injection] time_based_delay_s` | int | `5` | The `D` in `SLEEP(D)`; must stay below `[http] timeout_s`. |

CLI: `--time-based-sqli / --no-time-based-sqli` overrides `time_based_sqli`.

### `InjectionScanner` constants (internal, documented)

| Constant | Value | Meaning |
|---|---|---|
| `_PER_POINT_REQUEST_CAP` | `30` | Crafted requests against one injection point. |
| `_TIME_BASED_SLEEP_CAP` | `8` | Sleep-inducing requests per scan. |
| `_BOOLEAN_SIMILARITY` | `0.95` | TRUE-vs-baseline `quick_ratio` floor. |
| `_BOOLEAN_GAP` | `0.90` | FALSE-vs-baseline `quick_ratio` ceiling. |
| `_TIME_DELTA_S` | `4.0` | Min extra seconds for a time-based candidate at `D = 5`. |
| `XSS_TOKEN_BYTES` | `6` | `secrets.token_hex` length for the reflection marker. |
| `REDIRECT_SENTINEL` | `webvigil.invalid` | Off-scope host — never resolved, never requested. |

## ADRs

### ADR-1 — One `InjectionScanner` orchestrator pass; the six checks are hit-filters

**Decision.** All crafted-request work — form/point enumeration, baselines, payload
fan-out, detection — happens in `InjectionScanner`, run by the orchestrator. It leaves
`InjectionHit`s on `ctx.observations.injection_hits`. Each of the six `injection.*` checks
is ~10 lines: filter hits by `kind`, build findings.

**Alternatives.** (a) Each check self-contained: iterates points, sends its own payloads,
detects. (b) A shared helper the checks call into.

**Why.** The request budget and the per-point baseline need a **single owner**; six checks
running concurrently in the orchestrator's `TaskGroup` and each re-fuzzing every point
would multiply the request count by six and make the budget unenforceable. This is exactly
spec 004's `Fingerprinter` and spec 005's `DisclosureProbe` pattern — proven twice.

**Trade-off.** The pass must know which check ids are selected (to choose detectors); the
orchestrator passes that in. The checks are almost identical (a `_InjectionCheck` base
absorbs it).

### ADR-2 — The pass runs iff `mode == ACTIVE` AND ≥1 `injection.*` check is selected

Parallel to spec 004 ADR-3 and spec 005 ADR-2. `--mode passive` → `_inject` returns `()`
before any work (RF-01). `[checks] disabled` listing all six → `selected` is empty →
returns `()`; **zero** crafted requests, no enumeration (RF-16). Disabling only
`injection.sqli.time-based` (or passing `--no-time-based-sqli`) drops just that detector.

### ADR-3 — Forms parsed in `webvigil.crawler`, from crawled bodies, `discover()` unchanged

**Decision.** A new `webvigil/crawler/forms.py` with `Form` / `FormField` / a free
`extract_forms(pages, target)` function. The orchestrator calls it after the crawl. The
crawler issues **no new requests** — it parses `page.text` that is already in hand.
`Crawler.discover()` keeps returning `list[Page]`.

**Alternatives.** (a) `discover()` returns a `Discovery(pages, forms)` dataclass. (b) Parse
forms lazily inside the injection package from `ctx.pages`.

**Why.** (a) churns every `discover()` call site and every test. (b) puts "what the site
exposes" in the wrong layer. A free function in `webvigil.crawler` keeps the model where
crawl knowledge belongs (Resolved-during-requirements 10) with zero API disruption — the
same move spec 005 made by reading `ctx.pages` in its passive tier.

**Trade-off.** `extract_forms` is a second pass over the page bodies (cheap; selectolax,
already used by the crawler and the fingerprinter).

### ADR-4 — `[injection]` config section, not extra keys on `[active]`

**Decision.** Tuning lives in a new `[injection]` section (`request_budget`,
`max_injection_points`, `time_based_sqli`, `time_based_delay_s`). Requirements
Resolved-decision 7 said "`[active]` keys".

**Why the change.** `[active]` maps to `ActiveSection`, which **requires** `authorized_by`
and is `None` unless the user configures it — hanging tuning knobs off it couples "how
loud is the fuzzer" to "who authorised this". `[injection]` mirrors spec 005's
`[disclosure]` exactly (own section, own pydantic model, always present with defaults),
which is the established pattern for per-spec engine tuning.

**Trade-off.** One more top-level section in `webvigil.example.toml`. The attestation stays
in `[active]`; behaviour tuning is in `[injection]` — arguably clearer.

### ADR-5 — In-band, browserless detection only

**Decision.** XSS = verbatim reflection of HTML-significant characters + context analysis
(no JS execution). SQLi = DBMS error signature / confirmed boolean differential / confirmed
time delta. Traversal = known-file signature. Redirect = sentinel host in
`Location` / `final_location` / meta-refresh / JS assignment.

**Alternatives.** A headless browser (Playwright) for XSS and DOM sinks; an out-of-band
collaborator for blind SQLi, SSRF, and second-order.

**Why.** Spec 001 ruled out a headless browser; spec 004/005 established "the engine talks
only to the target". Both a browser and a collaborator break those. In-band detection is
also **deterministic** (RNF-04) — a headless run is not.

**Trade-off.** Misses DOM-only XSS, blind SQLi with errors suppressed and timing flat,
every second-order case, and (the reason SSRF is deferred) any callback-only vulnerability.
Documented in `docs/active-injection.md`.

### ADR-6 — One `InjectionHit` channel on `ctx.observations`, keyed by `kind`

Identical to spec 005 ADR-3 (`probe_hits`). `InjectionHit` in
`webvigil.checks.injection.models`, imported `TYPE_CHECKING`-only into `context.py`. The
six checks read it and filter — no runtime `core → checks` import, contract unchanged.

### ADR-7 — No `ScanResult` field; derive the CLI summary from findings

Spec 005 ADR-7 again. "N injection findings" in the human summary is
`sum(f.check_id.startswith("injection."))`. Injection-point count and crafted-request count
do **not** enter `ScanResult` — only the RF-03 cap warnings ride `ScanResult.warnings`. No
schema change → no reporter/API/UI ripple.

### ADR-8 — SARIF `logicalLocations`, added generally

`_result` gains a `logicalLocations` entry whenever `finding.location.key` is set. It is
**not** injection-specific — cookie and header findings get it too — and it is purely
additive (SARIF consumers that ignore `logicalLocations` are unaffected). The alternative,
stuffing the parameter into the message string only, loses machine-readability for the one
finding class where the sub-location is the whole point.

### ADR-9 — Non-idempotent requests never retry on a 5xx or read-timeout

`HttpClient.get` becomes `request("GET", …)`. `_request_with_retry` takes the method:
`GET`/`HEAD`/`OPTIONS` retry on transient errors **and** `5xx` (unchanged); `POST` retries
**only** on a pre-send `ConnectError` / `ConnectTimeout`. A `5xx` or a `ReadTimeout` on a
`POST` is returned as-is — the server may have processed it, and a blind re-POST could
double-submit a comment, an order, a vote.

### ADR-10 — The fixture's `/item` uses a real `sqlite3` connection

**Decision.** `tests/fixtures/app.py` gets a module-level `sqlite3` `:memory:` connection
(seeded 3-row `items` table) and a **sync** Starlette handler (Starlette runs `def`
handlers in a threadpool) that string-concatenates `id` into
`SELECT name FROM items WHERE id = '<id>'`, catches `sqlite3.OperationalError`, and returns
its text in a `500`. A `SLEEP(n)` / `pg_sleep(n)` token in `id` is intercepted **before**
the query and honoured with `time.sleep(min(n, 6))`.

**Why.** A real `OperationalError` gives the error-based detector an **authentic** SQLite
signature to match (`sqlite3.OperationalError: near "'": syntax error`), and real row-set
changes drive the boolean-based test. SQLite has no `SLEEP`, so time-based is simulated at
the token level — the detector only cares about the timing, not the SQL.

**Trade-off.** One sync handler in an otherwise-async fixture; `sqlite3` is stdlib so no
dependency. The hardened profile uses a parameterised query (`WHERE id = ?`) and returns
`404` for a non-integer `id`.

## Impact

| Area | Change |
|---|---|
| `webvigil.core.findings` | `Category.INJECTION` (one line). |
| `webvigil.core.config` | `InjectionSection` + one field on `ScanConfig`. |
| `webvigil.core.context` | `Observations.injection_hits` + a `TYPE_CHECKING` import. |
| `webvigil.core.orchestrator` | `_inject()` + `extract_forms` call + wiring (parallels `_probe_disclosure`). |
| `webvigil.http.client` | `get()` → `request()` refactor; method-aware retry; `HttpStats.crafted_requests`. |
| `webvigil.crawler` | new `forms.py` (~70 lines). `discover()` unchanged. |
| `webvigil.checks.injection` | new package (~600 lines incl. detectors + payloads). |
| `webvigil.cli` | one `scan` option; one `_render` summary line. |
| `webvigil.reporting.sarif` | `logicalLocations` (additive, ~6 lines). |
| Reporters JSON/HTML/MD | none. |
| `webvigil.api`, `web/` | none (RF-19). |
| Alembic / `openapi.json` | none. |
| deps | none. `import-linter` contract unchanged. |
| Docker | `docker/target.Dockerfile` + a profile-gated compose service (RF-24). |
| Fixture app | injectable insecure endpoints; safe hardened equivalents. |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Reflected-XSS false positive when the app reflects into a safe-but-unencoded spot (a `<title>`, a `text/plain` blob) | Medium | Verbatim-character check + `response.is_html` + context classification; `MEDIUM` confidence when context is ambiguous. |
| Boolean-based false positive on a dynamic page (ads, CSRF token, clock) | Medium | Normalised bodies with volatile tokens masked; a stability re-fetch discards dynamic pages; a second confirmation pair. Residual risk documented. |
| Time-based flakiness on a loaded CI runner | Medium | Generous `_TIME_DELTA_S`; a `D = 0` control must be fast; a scaling confirmation; `--no-time-based-sqli` and `time_based_sqli = false` escape hatches; the fixture uses a real, bounded sleep. |
| Request budget too low → misses findings on a large app | Low | `request_budget` is configurable; hitting it emits a clear warning naming the number. |
| POST fuzzing causes a state change (a posted comment) | Medium | `GET`/`POST` only, never `DELETE`/`PUT`; the exclusion heuristic; hidden/CSRF tokens preserved; the spec 001 Active-Mode banner already warns. Best-effort — a login form at `/session` slips through; documented. |
| `request()` redirect handling regresses `get()` | Low | `get()` becomes a literal pass-through; the full existing `test_http_client.py` suite runs unchanged, plus new POST cases. |
| Payload strings in a stored report trip a downstream scanner | Low | Evidence is bounded (spec 001 trimming) and carries only the proof marker; documented. |
| `webvigil.invalid` sentinel accidentally requested | Very low | `.invalid` is a guaranteed-unresolvable TLD; it is off-scope so the scope guard blocks it pre-flight regardless; the detector only reads `final_location`. |

## Testing — RNF-02, RNF-05

### Unit

| File | Covers |
|---|---|
| `tests/unit/test_crawler_forms.py` | action resolution (relative / empty / absolute / out-of-scope drop), method normalisation, field extraction (`input`/`textarea`/`select`), hidden-field preservation, dedup. |
| `tests/unit/test_injection_points.py` | query-param points, form-field points, `_FUZZ_TYPES` / `_SKIP_TYPES`, the exclusion regex (each keyword + an innocuous-form negative), cross-URL dedup, `max_injection_points` truncation + warning, priority tagging. |
| `tests/unit/test_injection_xss.py` | body / attribute-break / `<script>` / `href:javascript:` positives; entity-encoded / percent-encoded / `text/plain` / comment-only negatives; token-not-reflected short-circuit. |
| `tests/unit/test_injection_sqli.py` | all five DBMS error signatures; error signature already in baseline → no hit; boolean clean positive; unstable-baseline negative; always-different negative; time-based injected-delay positive; uniformly-slow negative; control-scaling confirm. Uses `pytest-httpx` with a small router. |
| `tests/unit/test_injection_traversal.py` | `passwd` + `win.ini` positives; signature-in-baseline negative; echoed-payload-only negative. |
| `tests/unit/test_injection_redirect.py` | `Location` sentinel positive (absolute / protocol-relative / backslash / `@`-confusion); `final_location` path; meta-refresh + JS body path; same-host negative. |
| `tests/unit/test_injection_engine.py` | budget exhaustion → warning + stop; per-point cap; `time_based_sqli = false` drops `sqli-time`; `selected_kinds` gating; baseline shared once per point. |
| `tests/unit/test_injection_orchestrator.py` | `_inject` returns `()` on passive; `()` when all six disabled; wires `injection_hits` onto the context; a raising `InjectionScanner` surfaces as a scan warning, not a crash (monkeypatch `orch_mod.InjectionScanner`). |
| `tests/unit/test_http_client.py` (additions) | `request("POST", …)` honours the scope guard + rate limiter; `5xx` on `POST` not retried; `ReadTimeout` on `POST` not retried; `ConnectError` on `POST` retried; `GET` behaviour unchanged; `307` keeps body, `303` drops it. |
| `tests/unit/test_config.py` (additions) | `[injection]` round-trips; unknown `[injection]` key rejected; `--time-based-sqli` override beats the file. |
| `tests/unit/test_cli.py` (additions) | `list-checks` shows the six; `--no-time-based-sqli` sets `config.injection.time_based_sqli = False`; active-scan summary line. |
| `tests/unit/test_reporters.py` (additions) | SARIF `logicalLocations` present when `location.param` set, absent otherwise; JSON/MD/HTML render `method` + `param`. |

### Integration — `tests/integration/test_scan_fixture_app.py`

- `test_insecure_profile_active_finds_every_injection` — one Active scan; assert
  `injection.xss.reflected` (×2: `q` GET, `body` POST), `injection.sqli.error-based`,
  `injection.sqli.boolean-based`, `injection.sqli.time-based`, `injection.traversal.path`,
  `injection.redirect.open`, each with the right `location.param` / `method` / severity.
- `test_insecure_profile_passive_finds_no_injection` — passive scan; no `injection.*`
  finding; the fixture's request log shows no crafted request.
- `test_hardened_profile_reports_nothing` — extend the existing loop to also run
  `--mode active`; still **zero** findings (now including `INJECTION`).
- `test_login_form_is_never_fuzzed` — Active scan; the fixture records every request; assert
  no request to `/login` carries a payload value.
- `test_active_scan_is_deterministic` — two Active runs, identical findings + fingerprints,
  both within `request_budget`.

The integration `scan` fixture's `_run` gains `mode="passive"` / `probe` / and now an
Active path (`ScanConfig.model_validate({..., "scan": {"mode": "active"}, "active":
{"authorized_by": "test"}})`). Time-based uses a real 2 s sleep in the fixture; the test
sets `time_based_delay_s = 2` to keep the suite fast.

### Fixture app — RF-20

Insecure profile adds (all `GET` unless noted):
- `/search?q=` — reflects `q` unescaped into HTML; also renders `<form method=get action=/search>`.
- `/item?id=` — sync handler, real `sqlite3` (ADR-10): broken quote → `500` with the
  `OperationalError` text; `1=1`/`1=2` change the row set; `SLEEP(n)` honoured.
- `/download?file=` — `open(web_root / file, "rb")`; a fixture `etc/passwd` sits under the
  root and is reachable via `../`.
- `/go?next=` — `RedirectResponse(next, status_code=302)`, no validation.
- `POST /comment` — `<form method=post>` with a hidden `csrf` field; reflects `body`
  unescaped; the `csrf` value must survive fuzzing.
- `POST /login` — `<form method=post action=/login>` `username` + `password`; the fuzzer
  must skip it (`_EXCLUDE_FORM_RE`).
- a request log (`app.state.requests`) the tests assert on.

Hardened profile: `/search` HTML-escapes `q`; `/item` uses `WHERE id = ?` and `404`s a
non-integer; `/download` resolves inside a jail and `404`s traversal; `/go` allow-lists;
`/comment` escapes. → zero findings.

### Docker target — RF-24

`docker/target.Dockerfile`: `FROM python:3.12-slim`, `pip install "starlette" "uvicorn"`,
`COPY tests/fixtures ./fixtures`, `CMD ["uvicorn", "fixtures.serve:app", "--host",
"0.0.0.0", "--port", "8080"]` (a 3-line `tests/fixtures/serve.py` exposing
`app = make_app("insecure")`). `docker-compose.yml` gains:

```yaml
  target:
    profiles: ["targets"]
    build: { context: ., dockerfile: docker/target.Dockerfile }
    ports: ["8080:8080"]
```

`docker compose --profile targets up target`, then
`webvigil scan http://localhost:8080 --mode active --authorized-by me`. Not part of the
default `docker compose up`. Documented in `docs/active-injection.md`.

## Resolved during design

1. **`[injection]` section instead of `[active]` keys** (ADR-4) — consistency with spec
   005's `[disclosure]`, decoupled from the attestation.
2. **Forms as a free `extract_forms()` in `webvigil.crawler`** (ADR-3) — not a `discover()`
   return-type change.
3. **The six checks are pure hit-filters; the scanner runs every detector** (ADR-1) — the
   requirements left "thin detectors vs. self-fuzzing checks" slightly open; the hit-filter
   model (spec 005's `_ProbeFedCheck`) won.
4. **`InjectionHit.evidence` is `(label, content)` pairs**, not pre-built `EvidenceItem`s —
   keeps `models.py` free of a `findings` import beyond the enums and matches how spec 005's
   `ProbeHit` carried primitives.
5. **SARIF `logicalLocations` added generally** (ADR-8) rather than an injection-only hack
   or a message-string-only parameter.
6. **Fixture `/item` uses real `sqlite3`** (ADR-10) for authentic error strings.
7. **`webvigil.invalid` as the open-redirect sentinel** — guaranteed NXDOMAIN, off-scope,
   never requested; the detector reads `final_location` only.
8. **Budget numbers** (500 / 200 / 30 / 8) carried over from Resolved-during-requirements 9;
   the implementation stage validates them against the fixture's real request count and may
   adjust with a note in "Implementation notes".

## Open questions

None. Ready for `/spec tasks`.

## Implementation notes

- **Budget defaults kept as designed** (500 / 200 / 30 / 8). The fixture app's insecure
  profile — 5 injection points — uses ~90 crafted requests for a full Active scan, well
  under 500. No cap warning fires in the integration tests.
- **`InjectionScanner.exhausted()` is a method, not a property.** mypy's
  `--warn-unreachable` narrows a nested-attribute guard (`self._budget.stopped`) to `False`
  for the rest of a loop iteration after an early `if …: break` at the loop top, and does
  not widen it across the intervening `await` calls — so the inner `break` reads as dead
  code. A method call is not narrowed. Renamed `ActiveBudget.stopped` → `exhausted()`.
- **`httpx` form bodies must be a `Mapping`, not a pair list.** `data=[("a", "1")]` takes
  httpx's deprecated raw-content path and yields a sync byte stream, which an `AsyncClient`
  rejects at send time (`"Attempted to send an sync request with an AsyncClient instance."`).
  `_build_request` returns `dict(fuzzed)` for the POST body; `params` stays a pair list
  (that path is fine). Repeated field names in one form collapse — acceptable for v0.6.
- **Boolean-based confirmation re-sends the same working pair** rather than requiring a
  second independent pair to also split. A real target usually has exactly one injectable
  context (quoted *or* numeric); demanding two working pairs produced false negatives. The
  detector loops the pairs as candidates and, on the first that splits, does a stability
  re-fetch + a repeat of that pair.
- **`_inject` wraps the pass in `try/except`** and turns a raising `InjectionScanner` into a
  scan warning (`"active injection pass failed: …"`), not a crash. Neither spec 004 nor 005
  did this for their passes; the injection pass has enough moving parts (five detectors,
  timing, differential maths) to justify the guard.
- **The fixture's `/download` is simulated, not a real filesystem read** (ADR-10 covers the
  real `sqlite3` for `/item`; `/download` checks whether the decoded, `\`-normalised param
  contains `etc/passwd` / `win.ini` and returns a fixture file). A real `../` read would
  either escape the test's temp jail into the host's real `/etc/passwd` or fail on Windows.
  `/item`'s `SLEEP(n)` is intercepted with a real `time.sleep` before the query, since
  SQLite has no sleep function.
- **`_render.summary` counts `injection.*` findings** only when `metadata.mode is ACTIVE`;
  no injection-point / crafted-request counts enter `ScanResult` (ADR-7).
- **SARIF `logicalLocations`** landed as designed (ADR-8) — additive, general, covers
  cookie/header sub-locations too. `test_reporters.py` asserts it appears iff
  `location.key` is set and validates the document against the 2.1.0 schema.
- **Docker target not build-verified** (no Docker in the implementation environment). The
  `docker/target.Dockerfile` + profile-gated compose service + `.dockerignore` negation for
  `tests/fixtures` are written to the spec-005 pattern; manual verification used a local
  `uvicorn` of the fixture instead (see below).
- **Final counts:** 431 pytest (was 361 at spec 005 close; +70). `mypy` 91 source files.
  `lint-imports` 2 contracts kept. No `web/` change, no Alembic migration, no
  `openapi.json` regen.

### Manual verification

`uvicorn tests.fixtures.serve:app` on `:9316`, then:

- `webvigil scan … --mode active --authorized-by …` → all six injection ids reported:
  `injection.sqli.error-based` (SQLite), `injection.sqli.boolean-based`,
  `injection.sqli.time-based` (MySQL; control 7 ms / injected 5005 ms),
  `injection.traversal.path` (leaked `root:x:0:0:…`), `injection.xss.reflected` ×2 (GET `q`
  and POST `body`), `injection.redirect.open` (`next` → `https://webvigil.invalid/`).
  Stderr summary line: `Active injection: 7 findings`.
- `--no-time-based-sqli` → 6 injection findings (time-based dropped).
- passive scan of the same target → 0 `injection.*` findings.
- `webvigil list-checks` → the six ids with `INJECTION` / `active`.
