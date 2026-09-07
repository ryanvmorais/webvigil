---
feature: Authenticated scanning (static cookies), CSRF detection, and form-driven crawling
status: done
date: 2026-09-06
related:
  - 001-foundation/design.md
  - 005-info-disclosure/design.md
  - 006-active-injection/design.md
origin: conception
---

# 007 — Authenticated scanning, CSRF detection, and form-driven crawling — Design

> Requirements: [`requirements.md`](requirements.md). This document is the *how*.
> Traceability tags (`— RF-NN` / `— RNF-NN`) point back to it.

## Overview

007 has three moving parts, all inside the engine's existing rules (pure library, no new
runtime dependency, scope guard and mode gate unchanged):

1. **Static-cookie auth** — the HTTP layer attaches configured cookies to every request
   whose host **is** the target host, and to no other (ADR-1). One new `[auth]` config
   section (ADR-4).
2. **Form-driven crawling** — form parsing moves *into* the crawl loop; the crawler submits
   safe in-scope `GET` forms with their default values and enqueues the results like any
   discovered link (ADR-2, ADR-3). A shared heuristic keeps it (and the `<a href>` crawl)
   off logout and — when authenticated — destructive URLs (ADR-5, `webvigil/crawler/safety.py`).
3. **CSRF detection** — a passive `csrf.form.no-token` check reads the parsed `<form>`
   inventory now on `ScanContext.forms` and the crawled `Set-Cookie` headers, and flags
   every state-changing form with no anti-CSRF token, weighted by the session cookie's
   `SameSite` (ADR-6, ADR-9).

```
Orchestrator.run()
  ├─ HttpClient(target, config)            + cookie header for in-scope requests   (ADR-1, RF-01/02)
  ├─ crawler = Crawler(http, target, config)
  │    discover():
  │      for each fetched page:
  │        parse_forms(page, target)                → this page's <form>s          (ADR-2, RF-05)
  │        enqueue <a href> links   — skip logout (always) / destructive (if auth) (ADR-5, RF-03)
  │        enqueue GET-form submission URLs  — same skip + auth-form skip          (ADR-3, RF-05/06)
  │    → pages ;  crawler.forms  (deduped, in-scope)                               (RF-07)
  ├─ forms = crawler.forms                  (replaces the old extract_forms call — ADR-2)
  ├─ _fingerprint(...) / _probe_disclosure(...) / _inject(..., forms, ...)   (specs 004/005/006, unchanged)
  ├─ ScanContext(pages=pages, forms=forms, observations=...)                       (RF-07)
  ├─ run checks
  │    └─ csrf.form.no-token  filters ctx.forms  (POST, not auth/search, no token) (ADR-6, RF-08)
  └─ ScanMetadata(authenticated = bool(config.auth.cookies), ...)                  (ADR-7, RF-02)
```

An anonymous scan (`[auth] cookies` empty, no `--cookie`) is byte-for-byte a v0.6 scan
**except** that the crawler now also submits `GET` forms — which is safe by construction
(RF-06) and gated by `[scan] submit_forms` (default `true`).

`csrf.*` findings are ordinary `Finding`s; the new `CSRF` category flows through spec
002/003 as a string exactly as `INJECTION` did (ADR-9). **No** migration, **no**
`openapi.json` regen, **no** dashboard change, **no** Web API scan-request change (RF-12).
Engine + CLI only.

## Module layout

```
src/webvigil/core/findings.py           + Category.CSRF                                  — RF-08, ADR-9
src/webvigil/core/config.py             + AuthSection (cookies) ; ScanSection.submit_forms — RF-01/06, ADR-4
src/webvigil/core/context.py            + ScanContext.forms  (TYPE_CHECKING import of Form) — RF-07
src/webvigil/core/result.py             + ScanMetadata.authenticated: bool = False        — RF-02, ADR-7
src/webvigil/core/orchestrator.py       crawler.forms replaces extract_forms(); metadata flag — ADR-2, ADR-7

src/webvigil/http/client.py             + cookie header on in-scope requests only          — RF-01/02, ADR-1

src/webvigil/crawler/forms.py           + FormField.checked ; parse_forms(page, target) ; submission_url(form) — RF-05, ADR-2/3
src/webvigil/crawler/safety.py   NEW    is_logout() · is_destructive() · is_auth_form()    — RF-03, ADR-5/8
src/webvigil/crawler/crawler.py         parse forms per page; submit GET forms; skip via safety — RF-03/05/06

src/webvigil/checks/csrf/        NEW package  (Category.CSRF, mode = PASSIVE)
    __init__.py                         imports checks so @register runs
    checks.py                           NoCsrfTokenCheck + token / session-cookie helpers   — RF-08/09

src/webvigil/checks/__init__.py         + csrf in _load_builtin_checks
src/webvigil/cli/app.py                 + --cookie (repeatable) → [auth] cookies            — RF-10
src/webvigil/cli/_render.py             + "Authenticated scan: N cookie(s)" / "CSRF: F form(s)" — RF-10

webvigil.example.toml                   + [auth] block ; [scan] submit_forms comment        — ADR-4
tests/fixtures/app.py                   + cookie-gated /account area, tokenless POST form, /logout — RF-13
docs/authenticated-scanning.md   NEW                                                        — RF-16
docs/{architecture,writing-checks}.md · README.md · CLAUDE.md · specs/README.md             — RF-16
```

No change to `pyproject.toml` (no dependency, no entry point — first-party checks register
via the `_load_builtin_checks` import). No change to `webvigil.api` / `web/` (RF-12).

## Components

### `Category.CSRF` — RF-08, ADR-9

```python
class Category(StrEnum):
    HEADERS = "HEADERS"
    COOKIES = "COOKIES"
    TLS = "TLS"
    CORS = "CORS"
    DEPS = "DEPS"
    DISCLOSURE = "DISCLOSURE"
    INJECTION = "INJECTION"
    CSRF = "CSRF"
```

`api/routes/meta.py` emits `check.category.value` (a `str`); `CheckOut.category` is `str`;
the dashboard derives its filter list from the data (all verified in spec 006 design). The
new value flows through with no schema or component change (RF-12).

### Cookie attachment — `webvigil/http/client.py` — RF-01, RF-02, ADR-1

`AuthSection` (below) validates the `name=value` format at config load. `HttpClient`
pre-computes the header once and attaches it only when the request host equals the target
host:

```python
class HttpClient:
    def __init__(self, target, config, *, transport=None):
        ...
        self._cookie_header = config.auth.as_header  # "" when no cookies configured

    async def _request_with_retry(self, method, url, headers, params, data, crafted):
        req_headers = dict(headers or {})
        if self._cookie_header and _host_of(url) == self._target.host:
            existing = req_headers.get("cookie")
            req_headers["cookie"] = f"{existing}; {self._cookie_header}" if existing else self._cookie_header
        ...
        response = await self._active_client.request(method, url, params=..., data=..., headers=req_headers)
```

- **In-scope only.** `_host_of(url) == self._target.host` — an exact host match. A redirect
  hop that left scope is never followed (spec 001), and an `allow_out_of_scope=True` fetch
  (robots/sitemap use the origin, which *is* the target host; nothing else fetches
  off-host) is by definition off-host, so the cookie is not attached (RF-02). Under
  `--scope subdomains` the cookie still goes to the **entry host only** — a `name=value`
  string carries no `Domain`, so widening it to sibling subdomains would be a guess; this
  is a documented limit (RF-16).
- **Never logged, never reported.** The header lives only in `req_headers` for the duration
  of the call. `RequestFailed` carries `url` + an error class name, never headers.
  `HttpStats` is unchanged. No reporter, warning, or metadata field carries a cookie value
  (RF-02, RNF-06) — asserted by `test_scan_fixture_app.py` (RF-14).
- httpx's own cookie jar is **not** used (`AsyncClient(cookies=…)` would send to every
  host) — ADR-1.

### `[auth]` config + `[scan] submit_forms` — RF-01, RF-06, ADR-4

```python
class AuthSection(_Section):
    """Static credentials for an authenticated scan (spec 007). Cookies only in v0.7."""

    cookies: list[str] = []  # each "name=value"; attached to in-scope requests only

    @field_validator("cookies")
    @classmethod
    def _check_pairs(cls, raw: list[str]) -> list[str]:
        for entry in raw:
            name, sep, _value = entry.partition("=")
            if not sep or not name.strip():
                raise ValueError(f"invalid cookie {entry!r}: expected 'name=value'")
        return raw

    @property
    def as_header(self) -> str:
        return "; ".join(entry.strip() for entry in self.cookies)


class ScanSection(_Section):
    mode: ScanMode = ScanMode.PASSIVE
    scope: Scope = Scope.HOST
    max_pages: int = 50
    follow_robots: bool = True
    submit_forms: bool = True  # crawler submits safe GET forms (spec 007, RF-06)


class ScanConfig(_Section):
    scan: ScanSection = ScanSection()
    ...
    injection: InjectionSection = InjectionSection()
    auth: AuthSection = AuthSection()
```

A malformed entry raises `ValidationError` → `ConfigError` through the existing
`model_validate_or_raise`, so the CLI prints one line and exits (RF-01, RF-10).
`with_overrides` gains `auth` in its docstring's section list. A `--cookie` list **replaces**
`[auth] cookies` (list keys replace under `{**current, **values}`, like `checks.disabled`) —
documented (RF-01).

### Form parsing in the crawl — `webvigil/crawler/forms.py` — RF-05, ADR-2

`FormField` gains `checked` (for checkbox/radio default inclusion). Two new functions
alongside the existing `Form` / `FormField` / `extract_forms`:

```python
@dataclass(frozen=True, slots=True)
class FormField:
    name: str
    type: str
    value: str
    checked: bool = False   # <input type=checkbox|radio checked>


def parse_forms(page: Page, target: Target) -> list[Form]:
    """Every in-scope <form> on ONE crawled page (no cross-page dedup)."""
    # the body of the current extract_forms loop, for a single page


def extract_forms(pages: tuple[Page, ...], target: Target) -> tuple[Form, ...]:
    """Every in-scope <form> across the crawl, de-duplicated (kept for callers/tests)."""
    seen, forms = set(), []
    for page in pages:
        for form in parse_forms(page, target):
            key = (form.method, form.action, tuple(f.name for f in form.fields))
            if key not in seen:
                seen.add(key)
                forms.append(form)
    return tuple(forms)


def submission_url(form: Form) -> str | None:
    """The GET URL this form submits to with its default values, or None if it is not a
    safe GET form the crawler should submit."""
    if form.method != "GET":
        return None
    pairs = [
        (f.name, f.value)
        for f in form.fields
        if f.type in _SUBMIT_VALUE_TYPES or (f.type in ("checkbox", "radio") and f.checked)
    ]
    split = urlsplit(form.action)
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs), ""))


_SUBMIT_VALUE_TYPES = frozenset(
    {"", "text", "search", "email", "url", "tel", "number", "hidden", "date", "textarea", "select"}
)
# omitted entirely: submit, button, image, reset, file, password
```

`submission_url` replaces any query already on the action with the default field values
(document order → deterministic, RNF-04).

### Link / form safety heuristic — `webvigil/crawler/safety.py` NEW — RF-03, ADR-5, ADR-8

```python
_LOGOUT_RE = re.compile(r"log[\s_-]?out|log[\s_-]?off|sign[\s_-]?out|(?:^|/)disconnect(?:$|/|\?)", re.I)
_DESTRUCTIVE_RE = re.compile(
    r"\b(?:delete|remove|destroy|drop|revoke|deactivate|disable|unsubscribe|cancel|purge|wipe)\b",
    re.I,
)
_AUTH_FORM_RE = re.compile(
    r"log[\s_-]?in|sign[\s_-]?in|sign[\s_-]?up|register|/auth\b|password|passwd|\bsearch\b", re.I
)


def is_logout(url: str) -> bool:
    """Follow-me-and-the-session-dies. Skipped always — authenticated or not (RF-03)."""
    parts = urlsplit(url)
    return bool(_LOGOUT_RE.search(f"{parts.path}?{parts.query}"))


def is_destructive(url: str) -> bool:
    """Looks state-changing. Skipped only on an authenticated crawl (RF-03)."""
    parts = urlsplit(url)
    return bool(_DESTRUCTIVE_RE.search(f"{parts.path}?{parts.query}"))


def is_auth_or_search_form(form: Form) -> bool:
    """A login / registration / search form — not a CSRF target, not fuzz-worthy."""
    haystack = form.action + " " + " ".join(f.name for f in form.fields)
    return bool(_AUTH_FORM_RE.search(haystack))
```

`reset` is deliberately **not** in `_DESTRUCTIVE_RE` (too many benign `?reset=1` filters);
"password reset" links are caught by neither and are documented as a known gap (RF-16).
Spec 006's `injection/points.py:_EXCLUDE_FORM_RE` is **left as-is** — consolidating the
three overlapping keyword sets is a follow-up, noted in "Resolved during design".

### Crawler wiring — `webvigil/crawler/crawler.py` — RF-03, RF-05, RF-06

```python
class Crawler:
    def __init__(self, http, target, config):
        ...
        self._authenticated = bool(config.auth.cookies)
        self._submit_forms = config.scan.submit_forms
        self._forms: dict[tuple[str, str, tuple[str, ...]], Form] = {}

    @property
    def forms(self) -> tuple[Form, ...]:
        return tuple(self._forms.values())

    async def discover(self) -> list[Page]:
        ...  # unchanged BFS shell
        # per fetched page, after _enqueue_links(page, ...):
        self._collect_and_enqueue_forms(page, seen, queue)
        ...

    def _maybe_enqueue(self, raw_url, seen, queue):
        if not urlsplit(raw_url).scheme.startswith("http"):
            return
        normalized = normalize_url(raw_url)
        if normalized in seen or not self._target.in_scope(normalized):
            return
        if is_logout(normalized) or (self._authenticated and is_destructive(normalized)):
            self._skipped_destructive += 1
            return
        seen.add(normalized); queue.append(normalized)

    def _collect_and_enqueue_forms(self, page, seen, queue):
        if not (page.ok and page.is_html):
            return
        for form in parse_forms(page, self._target):
            self._forms.setdefault((form.method, form.action, tuple(f.name for f in form.fields)), form)
            if not self._submit_forms or form.method != "GET":
                continue
            if is_auth_or_search_form(form) or is_logout(form.action) or (
                self._authenticated and is_destructive(form.action)
            ):
                continue
            url = submission_url(form)
            if url is not None:
                self._maybe_enqueue(url, seen, queue)
```

- `discover()` still returns `list[Page]` — no call-site churn (ADR-2, upholding 006 ADR-3's
  reasoning). The orchestrator reads `crawler.forms` afterwards.
- `_skipped_destructive` (an int) → the orchestrator turns a non-zero count into a scan
  **warning** ("declined to follow N link(s) that look state-changing"; RF-03). Logout skips
  are silent (an anonymous scan skipping `/logout` is unremarkable).
- Wait — `is_auth_or_search_form` also matches a **search** form, which we *do* want to
  submit (it is the canonical safe GET form). Resolved: the crawler's form-submit filter
  uses only `is_logout` + `is_destructive` + a login/register check; **search forms are
  submitted**. `is_auth_or_search_form` (search included) is the CSRF check's exclusion, a
  different question. Split into `is_auth_form(form)` (login/register/signup) and a separate
  `looks_like_search(form)` — see "Resolved during design 4".

### `ScanContext.forms` — RF-07

```python
# context.py
if TYPE_CHECKING:
    from webvigil.checks.disclosure.probe import ProbeHit
    from webvigil.checks.injection.models import InjectionHit
    from webvigil.crawler.forms import Form
    from webvigil.http.client import HttpClient, RedirectHop, Response


@dataclass(frozen=True, slots=True)
class ScanContext:
    config: ScanConfig
    target: Target
    http: HttpClient
    pages: tuple[Page, ...]
    entry: Page
    forms: tuple[Form, ...] = ()
    observations: Observations = field(default_factory=Observations, compare=False)
    _by_url: dict[str, Page] = field(default_factory=dict, compare=False)
```

`TYPE_CHECKING`-only import (like `InjectionHit`) — no runtime `core → crawler` dependency
(`crawler.forms` imports `core.context.Page`, so a runtime import here would be circular).
`tests/support.py:make_context` gains a `forms=()` parameter.

### Orchestrator — ADR-2, ADR-7

```python
async with HttpClient(target, self._config) as http:
    crawler = Crawler(http, target, self._config)
    pages = tuple(await crawler.discover())
    forms = crawler.forms                              # was: extract_forms(pages, target)
    if crawler.skipped_destructive:
        warnings.append(
            f"declined to follow {crawler.skipped_destructive} link(s) that look "
            "state-changing (authenticated crawl)"
        )
    check_types = self._select_checks(warnings)
    detections = await self._fingerprint(...)
    probe_hits = await self._probe_disclosure(...)
    injection_hits = await self._inject(check_types, http, target, pages, forms, warnings)
    context = ScanContext(
        config=self._config, target=target, http=http,
        pages=pages, entry=pages[0], forms=forms,
        observations=Observations(detections=detections, probe_hits=probe_hits,
                                  injection_hits=injection_hits),
    )
    findings, errors = await self._run_checks(check_types, context)
    ...

metadata = ScanMetadata(
    ...,
    authenticated=bool(self._config.auth.cookies),
)
```

`from webvigil.crawler.forms import extract_forms` import is dropped from the orchestrator
(the crawler owns it now); `Form` is still imported for the `_inject` signature type.

### `webvigil.checks.csrf` — RF-08, RF-09, ADR-6

```python
# checks.py
_TOKEN_NAME_RE = re.compile(
    r"csrf|xsrf|_token|authenticity_token|__requestverificationtoken|csrfmiddlewaretoken|"
    r"nonce|anti[\s_-]?forgery|request[\s_-]?token",
    re.I,
)
_SESSION_NAME_RE = re.compile(r"session|sess(?:id)?|sid|auth|jwt|(?:^|_|-)token", re.I)
OWASP_CSRF = "https://owasp.org/www-community/attacks/csrf"


def _is_token_field(field: FormField) -> bool:
    return bool(_TOKEN_NAME_RE.search(field.name))


def _session_samesite(pages: tuple[Page, ...]) -> str | None:
    """Weakest SameSite seen on a session-looking Set-Cookie across the crawl.

    Returns "none" (explicit or absent → cross-site sendable), "lax", "strict", or None
    (no session cookie observed at all).
    """
    seen: str | None = None
    for page in pages:
        for raw in page.headers.get_list("set-cookie"):
            morsel = SimpleCookie()
            morsel.load(raw)                       # http.cookies, stdlib
            for name, value in morsel.items():
                if not _SESSION_NAME_RE.search(name):
                    continue
                samesite = (value["samesite"] or "none").strip().lower() or "none"
                seen = _weaker(seen, samesite)
    return seen


@register
class NoCsrfTokenCheck(Check):
    id = "csrf.form.no-token"
    name = "Form without an anti-CSRF token"
    category = Category.CSRF
    mode = ScanMode.PASSIVE
    default_severity = Severity.MEDIUM
    cwe = (352,)
    references = (OWASP_CSRF, "https://owasp.org/www-project-web-security-testing-guide/")

    async def run(self, ctx: ScanContext) -> list[Finding]:
        samesite = _session_samesite(ctx.pages)
        confidence = {
            None: Confidence.MEDIUM, "none": Confidence.HIGH,
            "lax": Confidence.LOW, "strict": Confidence.LOW,
        }[samesite]
        findings: list[Finding] = []
        for form in ctx.forms:
            if form.method != "POST" or is_auth_form(form) or looks_like_search(form):
                continue
            if any(_is_token_field(f) for f in form.fields):
                continue
            findings.append(
                self.finding(
                    title=f"POST form to {_display(form.action)} has no anti-CSRF token",
                    description=_DESCRIPTION,
                    remediation=_REMEDIATION,
                    confidence=confidence,
                    location=Location(url=form.action, method="POST"),
                    dedup_key="no-token",
                    evidence=[
                        EvidenceItem.of("form", f"POST {form.action}  (found on {form.source_url})"),
                        EvidenceItem.of("fields", ", ".join(f.name for f in form.fields) or "(none)"),
                        EvidenceItem.of("session cookie", _samesite_note(samesite)),
                    ],
                )
            )
        return findings
```

- **Passive, no `ctx.http`** (RF-09 / Resolved-during-requirements 9). Everything comes from
  `ctx.forms` and the crawled responses' `Set-Cookie` headers.
- **Dedup** on `check_id` + `form.action` + `dedup_key` → the same action seen on several
  pages collapses to one finding (`compute_fingerprint` uses `location.url` + `location.key`;
  `location.key` is `""` here since there is no param/header/cookie, so the action URL
  carries the identity — acceptable, one finding per action) (RF-08).
- **`confidence`** — `HIGH` when a session cookie is sendable cross-site (no/`None`
  SameSite), `LOW` when `SameSite=Lax`/`Strict` mitigates it (the finding text says so),
  `MEDIUM` when no session cookie was seen (the form may still be authenticated by other
  means).
- **Exclusions** — `is_auth_form` (login/register/signup) and `looks_like_search` (GET
  method already filters most; a `POST` search is unusual but excluded by name). Documented
  blind spots (JS-injected token, header token via `<meta>`, double-submit cookie) go in
  `description` / `remediation` and `docs/authenticated-scanning.md` (RF-09, RF-16).

### `webvigil/checks/__init__.py`

```python
from webvigil.checks import (  # noqa: F401
    cookies, cors, csrf, deps, disclosure, headers, injection, tls,
)
```

### CLI — RF-10

`scan` gains one repeatable option:

```python
cookie: Annotated[
    list[str] | None,
    typer.Option("--cookie", help='Send this cookie on in-scope requests ("name=value"). Repeatable.'),
] = None
```

`_build_config` gains `cookie: list[str] | None`, builds `auth_overrides = {"cookies": cookie}`
when `cookie is not None`, passes `auth=auth_overrides` to `with_overrides`. A `ConfigError`
from a bad pair is already caught (`_build_config` is wrapped) → `_render.error` + exit.

`_render.summary(result, *, cookie_count: int = 0)` — `_emit` passes
`len(cfg.auth.cookies)`. After the injection block:

```python
if cookie_count:
    _console.print(f"[dim]Authenticated scan: {cookie_count} cookie(s) supplied[/]")
csrf_forms = sum(1 for f in result.findings if f.check_id == "csrf.form.no-token")
if csrf_forms:
    _console.print(
        f"[yellow]CSRF: {csrf_forms} form{'' if csrf_forms == 1 else 's'} without an "
        "anti-CSRF token[/]"
    )
```

The cookie **count** comes from `cfg`, never from `ScanResult` — no cookie data of any kind
enters the result object (ADR-7). `list-checks` shows `csrf.form.no-token` with no code
change.

### `webvigil.example.toml`

```toml
[auth]
# Static cookies for an authenticated scan. Each entry is "name=value" and is sent only on
# requests to the target host (never off-host, never written to a report). CLI: --cookie.
cookies = []

[scan]
# ... existing keys ...
# Submit safe GET forms (search, filters) during the crawl to widen coverage. POST forms
# are never submitted by the crawler.
submit_forms = true
```

## Data model

### `AuthSection` / `ScanSection.submit_forms`

`webvigil.core.config`. `AuthSection.cookies` is the raw `["name=value"]` list;
`as_header` is the joined `Cookie:` value. Consumed only by `HttpClient.__init__` and (for
the metadata bool + summary count) the orchestrator/CLI.

### `FormField.checked` / `submission_url` / `parse_forms`

`webvigil.crawler.forms`. `Form` / `FormField` shape otherwise unchanged from spec 006.

### `ScanContext.forms`

`tuple[Form, ...]`, populated once by the orchestrator from `crawler.forms`, read-only
during the check run. Not stored on `Page`, not in `ScanResult`.

### `ScanMetadata.authenticated`

```python
class ScanMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)
    target: str
    mode: ScanMode
    scope: Scope
    tool_version: str
    started_at: datetime
    finished_at: datetime
    pages_scanned: int
    counts: dict[str, int]
    authorized_by: str | None = None
    authenticated: bool = False        # spec 007 — cookies were supplied (no names/values)
```

Additive, defaults `False`, appears in the canonical JSON. `api/mapping.py:store_result`
maps `meta` field-by-field onto specific `Scan` columns and never touches `meta.authenticated`
(verified) — so **no migration, no schema change** (RF-12, ADR-7). SARIF/HTML/MD headers do
not surface it (a design choice — it is not a finding and not security-relevant to a
downstream tool); `webvigil report` round-trips it because it is in the JSON.

### `ScanResult`

Otherwise **unchanged.** New `Category.CSRF` value on findings; the "declined N links" and
"cookies may be expired" strings ride `warnings`.

## Interfaces

### Check ids — RF-08, RF-10

| id | category | mode | default severity | confidence | cwe |
|---|---|---|---|---|---|
| `csrf.form.no-token` | CSRF | passive | MEDIUM | HIGH / MEDIUM / LOW (SameSite-weighted) | 352 |

### Config — RF-01, RF-06, ADR-4

| Key | Type | Default | Meaning |
|---|---|---|---|
| `[auth] cookies` | list[str] | `[]` | `"name=value"` entries; attached to target-host requests only. CLI `--cookie` replaces this list. |
| `[scan] submit_forms` | bool | `true` | Crawler submits safe in-scope `GET` forms with default values. No CLI flag. |

CLI: `--cookie "name=value"` (repeatable) → `[auth] cookies`.

### Heuristic keyword sets (internal, documented — RF-16)

| Set | Applies to | Keywords |
|---|---|---|
| logout | links + GET-form actions, **always** | `logout`, `log-out`, `logoff`, `signout`, `sign-out`, `disconnect` |
| destructive | links + GET-form actions, **authenticated only** | `delete`, `remove`, `destroy`, `drop`, `revoke`, `deactivate`, `disable`, `unsubscribe`, `cancel`, `purge`, `wipe` |
| auth form | CSRF exclusion + crawler form-submit skip | `login`, `signin`, `signup`, `register`, `/auth`, `password` |
| CSRF token field | `csrf.form.no-token` | `csrf`, `xsrf`, `_token`, `authenticity_token`, `__requestverificationtoken`, `csrfmiddlewaretoken`, `nonce`, `anti-forgery`, `requesttoken` |
| session cookie | `csrf.form.no-token` SameSite lookup | name contains `session`, `sess`, `sid`, `auth`, `jwt`, `token` |

## ADRs

### ADR-1 — Static cookies attached in the HTTP layer, target-host only

**Decision.** `HttpClient` merges a `Cookie:` header into every request whose host equals
the target host, computed once from `config.auth.as_header`. httpx's cookie jar is not
used.

**Alternatives.** (a) `httpx.AsyncClient(cookies=…)` — the jar sends the cookies to *every*
host it contacts. (b) A `cookies=` parameter on every `get()`/`request()` call — threads
through the crawler, the fingerprinter, the disclosure probe, the injection engine.

**Why.** (a) leaks the session cookie to any third-party host a redirect or an asset
reference points at — unacceptable for a credential (RF-02). (b) is correct but touches
every call site for a cross-cutting concern that belongs in the one place all requests
already funnel through. Attaching in `_request_with_retry`, gated on an exact host match,
is one edit and is impossible to bypass.

**Trade-off.** Under `--scope subdomains` the cookie is sent to the entry host only, not to
in-scope sibling subdomains — a `name=value` string has no `Domain` and guessing one is
wrong more often than right. Documented (RF-16). A user who needs a subdomain-wide cookie
can run a scan per host.

### ADR-2 — Form parsing moves into the crawl; `discover()` return type unchanged

**Decision.** The crawler calls `parse_forms(page, target)` for each page it fetches,
accumulates a deduped `crawler.forms`, and (for safe `GET` forms) enqueues the submission
URL. `Crawler.discover()` still returns `list[Page]`. The orchestrator reads
`crawler.forms` instead of calling `extract_forms(pages, target)`.

**Alternatives.** (a) `discover()` returns `CrawlResult(pages, forms)`. (b) Keep
`extract_forms` as a post-crawl orchestrator call and have the crawler re-parse forms
internally for submission (parse twice).

**Why.** 006 ADR-3 already established "don't change `discover()`'s signature" (it churns
every call site and test). The crawler *must* see forms mid-crawl to submit them (RF-05),
so parsing there is unavoidable; exposing the result via a property is the minimal seam.
`extract_forms` stays as a pure helper for tests and any external caller.

**Trade-off.** `crawler.forms` is state on the crawler object read after `discover()` — a
mild departure from "everything comes back in the return value". Acceptable; `HttpClient`
already exposes post-run `stats` the same way.

### ADR-3 — The crawler submits `GET` forms only, with default values

**Decision.** For each in-scope `<form method="get">` that is not excluded, the crawler
builds `action?field=default&…` from the fields' current values and enqueues it as a
discovered URL, counted against `max_pages`. `POST` forms are recorded in `crawler.forms`
but never submitted by the crawler.

**Alternatives.** (a) Also submit `POST` forms (with default values). (b) A dedicated
form-exploration pass separate from the crawl.

**Why.** A `GET` form submission is, by HTTP semantics, safe and idempotent — it is what a
browser does when you press Enter in a search box. A `POST` submission is a state change and
would need the Active-Mode gate or its own consent; deferred (Non-goals). (b) duplicates
the crawl's BFS, `seen` set, `max_pages` accounting, and robots handling for no benefit.

**Trade-off.** Forms that require a `POST` to reveal new pages (a multi-step wizard) stay
invisible to the crawl. The injection pass (spec 006) still submits `POST` forms it is
pointed at — unchanged.

### ADR-4 — `[auth]` config section, not keys on `[active]`

**Decision.** Cookies live in a new `[auth]` section. `submit_forms` lives in `[scan]`
(next to `follow_robots`, `max_pages` — it is a crawl knob).

**Why.** `[active]` maps to `ActiveSection`, which requires `authorized_by` and is `None`
until configured; authentication is orthogonal to the Active-Mode attestation (an
authenticated scan is usually passive). Same reasoning as spec 006 ADR-4 choosing
`[injection]` over `[active]` keys.

**Trade-off.** One more top-level section. `[auth]` is the obvious home for the deferred
login-flow / header-auth keys when they land.

### ADR-5 — Destructive-link heuristic: logout always, the wider set only when authenticated

**Decision.** `is_logout(url)` → skipped on every scan. `is_destructive(url)` → skipped
only when `config.auth.cookies` is non-empty. A non-zero destructive-skip count becomes a
scan warning.

**Alternatives.** (a) Apply the full heuristic always. (b) Apply nothing; trust that
anonymous requests to `/delete/1` are harmless.

**Why.** Anonymous, a request to `/posts/5/delete` is almost always bounced to a login page
— skipping it only loses a redirect. Authenticated, that same request *deletes*. Gating the
wider set on "are we carrying credentials" targets the mitigation exactly where the risk
appears, while an anonymous scan keeps its current coverage. `/logout` is skipped always
because it is worthless to scan and, if the scan *is* authenticated, following it first
would silently break every subsequent request.

**Trade-off.** The heuristic is keyword-based and imperfect: a delete action at `/p/5`
(verb only in the HTTP method), a logout at `/session` (DELETE), a benign `/deleted-items`
listing — the first two are missed, the third is over-skipped. Documented (RF-16). A
missed destructive GET under authentication is the residual risk the Active-Mode banner
language already covers in spirit.

### ADR-6 — `csrf.form.no-token` is passive, `ctx.forms` + `Set-Cookie` only, SameSite-weighted

**Decision.** One passive check. It reads `ctx.forms` and the crawled responses'
`Set-Cookie` headers — no `ctx.http` request. It fires on non-excluded `POST` forms with no
recognised token field, at `HIGH` / `MEDIUM` / `LOW` confidence per the session cookie's
SameSite.

**Alternatives.** (a) Active confirmation — replay the form with the token stripped and see
if it is accepted. (b) Always `MEDIUM`, ignore SameSite.

**Why.** (a) is a payload-bearing, state-changing test — an Active-Mode check, deferred to
a broader session/CSRF spec (Non-goals). Token *absence* is a real, reportable weakness on
its own and is fully determinable by inspection. (b) throws away the single most important
piece of context: a token-less form behind a `SameSite=Strict` session cookie is barely
exploitable, and saying so (LOW + explanatory text) is far more useful than a flat MEDIUM.

**Trade-off.** False positives on apps that carry the token in a header injected by
framework JS (Angular, Rails-UJS), or use a double-submit-cookie with no form field. The
check cannot see those. `confidence`, the remediation text, and the docs call it out
explicitly.

### ADR-7 — `ScanMetadata.authenticated: bool`; no cookie data in `ScanResult`; CLI sources the count from config

**Decision.** Add `authenticated: bool = False` to `ScanMetadata`. The CLI summary's
"N cookie(s)" line reads `len(cfg.auth.cookies)` directly. No cookie name, value, or count
enters `ScanResult`.

**Alternatives.** (a) `authenticated_cookie_count: int` on the metadata. (b) Nothing on the
metadata; a CLI-summary-only line.

**Why.** A boolean records the security-relevant fact ("this scan saw the app as a logged-in
user") for the archived JSON and a future API surface, with zero risk of a value leaking. A
count is marginally more informative but is not needed in the persisted record, and the CLI
already has `cfg` in hand. (b) loses the fact from `webvigil report` re-renders.

**Trade-off.** `webvigil report old-scan.json` shows `authenticated: true` but cannot show
how many cookies — acceptable; the number is operational trivia, the fact is the signal.
Verified `api/mapping.py` ignores the new field, so no migration (RF-12).

### ADR-8 — Shared `webvigil/crawler/safety.py`; spec 006's `points.py` left untouched

**Decision.** The logout / destructive / auth-form predicates live in one new module the
crawler and the CSRF check import. Spec 006's `injection/points.py:_EXCLUDE_FORM_RE` is
**not** refactored to use it in this spec.

**Why.** The crawler and the CSRF check are the new consumers; giving them a shared home
now avoids a third copy. Touching `points.py` means re-running and re-reasoning about the
whole spec 006 injection-point test surface for a cosmetic gain — out of scope and a
needless regression risk. A follow-up can unify all three.

**Trade-off.** Two keyword sets with overlapping intent coexist until then. Documented.

### ADR-9 — New `Category.CSRF`, flows through the API/UI as a string

Identical to spec 006's handling of `Category.INJECTION`. `api/routes/meta.py` emits
`category.value`; `CheckOut.category` is `str`; the dashboard derives its filter from the
data. No migration, no `openapi.json` regen, no component change (RF-12). This is an
engine + CLI spec.

## Impact

| Area | Change |
|---|---|
| `webvigil.core.findings` | `Category.CSRF` (one line). |
| `webvigil.core.config` | `AuthSection`; `ScanSection.submit_forms`; `ScanConfig.auth`; `with_overrides` docstring. |
| `webvigil.core.context` | `ScanContext.forms` + a `TYPE_CHECKING` import. `make_context` param. |
| `webvigil.core.result` | `ScanMetadata.authenticated: bool = False`. |
| `webvigil.core.orchestrator` | read `crawler.forms`; drop the `extract_forms` call; destructive-skip warning; metadata flag. |
| `webvigil.http.client` | cookie header on target-host requests (`_request_with_retry`, ~5 lines). |
| `webvigil.crawler` | `forms.py`: `FormField.checked`, `parse_forms`, `submission_url`. new `safety.py` (~30 lines). `crawler.py`: per-page form collection + GET-form submission + skip logic. |
| `webvigil.checks.csrf` | new package (~120 lines). |
| `webvigil.checks.__init__` | `csrf` in the builtin import. |
| `webvigil.cli` | one `scan` option; two `_render` summary lines; `_emit` passes the cookie count. |
| Reporters JSON | `metadata.authenticated` appears (automatic). SARIF/HTML/MD: none. |
| `webvigil.api`, `web/` | none (RF-12). |
| Alembic / `openapi.json` | none. |
| deps | none. `import-linter` contract unchanged (`checks`, `crawler`, `http` already source modules). |
| Fixture app | cookie-gated `/account` + `/account/settings`, tokenless `POST /profile`, `GET /logout`, account links; hardened equivalents with a token + `SameSite`. |
| Docs | new `authenticated-scanning.md`; architecture / writing-checks / README / CLAUDE / roadmap. |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| A cookie value leaks into a report, log, or the metadata | Low | Header built in `_request_with_retry` only, attached by exact host match, never stored; `ScanResult` carries no cookie data; an integration test greps all four report formats for the fixture cookie value. |
| Authenticated crawl follows a destructive GET the heuristic misses | Medium | `is_destructive` keyword set; the Active-Mode-style residual-risk note in the docs; `submit_forms` and the crawl are still `max_pages`-bounded. A user scanning their own app is the expected operator. |
| Crawler skips a legitimate page whose URL contains `delete`/`cancel` (`/deleted-items`, `/cancellation-policy`) | Medium | Word-boundary regex; `reset` excluded; the wider set is authenticated-only; a scan warning names the skip count so the user can spot over-skipping; documented. |
| `csrf.form.no-token` false positive (header token via framework JS, double-submit cookie) | Medium | SameSite-weighted confidence (LOW when mitigated); `description`/`remediation` name the blind spots; hardened fixture proves the negative. |
| GET-form submission hits an expensive endpoint (a report generator behind a GET form) | Low | Same `max_pages` cap, concurrency cap, and per-host delay as any crawl fetch; default values only; `submit_forms = false` opt-out. |
| Form parsing in the crawl slows discovery | Low | selectolax, already parsing every page for `<a href>`; forms are a second `css()` call on the same tree. |
| `ScanContext` gaining a field breaks a positional constructor call somewhere | Low | `forms` is keyword-defaulted (`= ()`) and inserted before `observations`; `grep` for `ScanContext(` shows two call sites (orchestrator, `make_context`), both keyword. |

## Testing — RNF-02, RNF-05

### Unit

| File | Covers |
|---|---|
| `tests/unit/test_config.py` (additions) | `[auth] cookies` round-trips; a pair with no `=` / empty name → `ConfigError`; `[scan] submit_forms` default + override; unknown `[auth]` key rejected. |
| `tests/unit/test_http_client.py` (additions) | a configured cookie is sent on a target-host request; **absent** on an `allow_out_of_scope=True` request and on a different host; a caller-supplied `Cookie` header is preserved and appended to; no cookie configured → no header. |
| `tests/unit/test_crawler_safety.py` NEW | `is_logout` (`/logout`, `/account/log-out`, `?do=signout`, `/disconnect`; negative `/blogout`, `/login`); `is_destructive` (each keyword, word-boundary; negative `/undeletable`, `/reset-password` not matched); `is_auth_form` / `looks_like_search`. |
| `tests/unit/test_crawler_forms.py` (additions) | `FormField.checked` parsed; `submission_url` for a GET form with mixed field types (text/hidden/select/checkbox-checked/checkbox-unchecked/submit); `submission_url` returns `None` for a POST form; existing `extract_forms` tests still green via `parse_forms`. |
| `tests/unit/test_crawler.py` (additions) | GET search form → submission URL enqueued and fetched; POST form → not submitted; `/logout` link → never enqueued; authenticated + `/items/5/delete` link → skipped + count; anonymous + same link → followed; `submit_forms = false` → no form submission; form URLs count against `max_pages`. |
| `tests/unit/test_checks_csrf.py` NEW | token present (each recognised name) → nothing; token absent → finding; `POST` vs `GET` form; login form excluded; `SameSite=Lax` session cookie → LOW; no `SameSite` → HIGH; no session cookie → MEDIUM; same action on two pages → one finding; `location.method == "POST"`. |
| `tests/unit/test_context.py` (additions) | `ScanContext.forms` defaults to `()` and round-trips. |
| `tests/unit/test_reporters.py` (additions) | `metadata.authenticated` present in JSON, `true` when set; `webvigil report` round-trips it; SARIF/HTML/MD unaffected. |
| `tests/unit/test_cli.py` (additions) | `--cookie a=1 --cookie b=2` → `config.auth.cookies == ["a=1", "b=2"]`; a bad `--cookie` value → non-zero exit, one-line error; `list-checks` shows `csrf.form.no-token`; summary lines (cookie count, CSRF count). |

### Integration — `tests/integration/test_scan_fixture_app.py`

The `scan` fixture's `_run` gains `cookies: list[str] | None = None` → `raw["auth"] =
{"cookies": cookies}`.

- `test_authenticated_scan_reaches_the_account_area` — `_run("insecure",
  cookies=["session=abc123"])`; `/account` and `/account/settings` are in the crawled set.
- `test_anonymous_scan_stops_at_the_login_redirect` — no cookies; `/account/settings` is
  **not** crawled (the `/account` link 302s to `/login`).
- `test_crawler_submits_the_get_search_form` — any scan; `GET /search?q=` in
  `app.state.requests`.
- `test_crawler_never_submits_post_forms_or_logout` — a **passive** scan; no `POST /profile`
  or `POST /comment` from the crawler, no `GET /logout`, no `POST /login` in the request log.
- `test_csrf_check_flags_the_tokenless_profile_form` — authenticated passive scan of
  insecure; `csrf.form.no-token` for `POST /profile`; not present on hardened (extend the
  existing hardened-profile zero-findings loop).
- `test_cookie_value_never_appears_in_any_report` — render JSON, SARIF, HTML, Markdown of an
  authenticated scan; assert `"abc123"` is in none of them and in no warning.
- `test_authenticated_scan_is_deterministic` — two runs, identical findings + fingerprints +
  crawled-URL set.
- Existing crawl-count assertions (`test_crawler_reaches_the_linked_pages` and the anonymous
  page total) are recomputed: the home page now also links `/account` (→ `/login` when
  anonymous) and the crawler submits the `GET /search` form (`?q=`), so the anonymous page
  count rises by a documented delta.

### Fixture app — RF-13

Insecure profile adds:
- `GET /account` — sync handler: `request.cookies.get("session") == "abc123"` → `200` HTML
  linking `/account/settings` and `/logout` and rendering
  `<form method="post" action="/profile"><input name="nickname"></form>` (**no token**);
  else `RedirectResponse("/login", 302)`.
- `GET /account/settings` — same cookie gate → `200` (a deeper authed page).
- `POST /profile` — `200 "updated"` (`methods=["POST"]`).
- `GET /logout` — `200`/`RedirectResponse("/", 302)` clearing the cookie; the crawler must
  never request it.
- home page (`_INSECURE_PAGE`) gains `<a href="/account">account</a>`.

Hardened profile: `/account` gated on the `__Host-session` cookie; its `POST /profile` form
carries `<input type="hidden" name="csrf_token" value="…">`; the session cookie is already
`SameSite=Lax` (`_hardened`). `_PAGE` gains the same account link. → zero `CSRF` findings.

The existing `<form method="get" action="/search"><input name="q"></form>` (both profiles)
is what `test_crawler_submits_the_get_search_form` exercises — no fixture change for it.

## Resolved during design

1. **`[auth]` section, cookies validated in the pydantic model** (ADR-4) — a bad pair is a
   `ConfigError` at load, not a runtime surprise.
2. **Cookie attached in `_request_with_retry`, exact-host match** (ADR-1) — not the httpx
   jar, not a per-call parameter.
3. **`discover()` keeps returning `list[Page]`; `crawler.forms` is a property** (ADR-2) —
   upholds spec 006 ADR-3. The orchestrator drops its `extract_forms` call.
4. **`is_auth_form` and `looks_like_search` are separate predicates.** The crawler
   *submits* search forms (the canonical safe GET form) and skips login/register; the CSRF
   check excludes both. An earlier draft merged them and would have stopped the crawler
   submitting the one form it most wants to.
5. **`ScanMetadata.authenticated: bool`** (ADR-7) — additive, no migration (verified against
   `api/mapping.py`); the CLI count comes from `cfg`, not the result.
6. **`webvigil/crawler/safety.py` shared by the crawler and the CSRF check; spec 006's
   `points.py` untouched** (ADR-8) — unifying all three keyword sets is a follow-up.
7. **`reset` excluded from the destructive set** — `?reset=1` is a common benign filter;
   "password reset" is a documented gap, not worth the false-skips.
8. **CSRF confidence is SameSite-weighted** (ADR-6): no session cookie → MEDIUM, no/`None`
   SameSite → HIGH, `Lax`/`Strict` → LOW with an explanatory finding.
9. **`submit_forms` in `[scan]`, no CLI flag** — it is a crawl knob like `follow_robots`,
   which is also config-only.

## Open questions

None. Ready for `/spec tasks`.

## Implementation notes

Filled at close (2026-09-06).

- **`HttpClient` clears the httpx cookie jar before every request** — added during Stage 7,
  not foreseen in the ADRs. httpx keeps a per-client cookie jar by default, so a target's
  `Set-Cookie` (the fixture's insecure home page sets `session=abc123`) was being replayed
  on later requests and implicitly "authenticating" an anonymous scan. Clearing the jar in
  `_request_with_retry` makes the scanner send **exactly** the configured `[auth]` cookies
  and nothing it picked up implicitly — better for determinism (RNF-04) and keeps
  authentication config-driven. Documented in `docs/authenticated-scanning.md` and the
  architecture http bullet. No existing test relied on jar persistence.
- **`submission_url` field order is stable-parser order, not strict document order.**
  selectolax's `css("input, textarea, select")` groups by tag, so a `<select>` after a
  `<checkbox>` in the source comes out before it. Still fully deterministic (RNF-04); the
  design wording was softened from "document order".
- **`is_auth_form` vs `looks_like_search` stayed split** as the design's Resolved-item 4
  anticipated — the crawler submits search forms and skips login forms; the CSRF check
  excludes both.
- **`ScanMetadata.authenticated` needed no Web API change** — confirmed as predicted:
  `api/mapping.py:store_result` maps metadata field-by-field onto `Scan` columns and never
  reads `authenticated`, so the extra field is simply not persisted. No migration, no
  `openapi.json` regen. `Category.CSRF` flows through as a string (spec 006 precedent).
- **`test_the_login_form_is_never_fuzzed` (spec 006) was loosened**: the crawler now GETs
  `/login` as the redirect target of the cookie-gated `/account` link, which is harmless.
  The assertion now checks the login form is never *submitted with a payload* (`POST /login`
  or `GET /login?<params>`), which is the real intent.
- **Crawl-count assertion**: `test_crawler_reaches_the_linked_pages` went 8 → 9 (the
  submitted `GET /search?q=` plus `/account` → `/login`).
- **Final counts:** 501 pytest at Stage 7 (was 431 at spec 006 close; +70 by the end of the
  test stages). `mypy` 94 source files. `lint-imports` 2 contracts kept, 0 broken. No
  `web/` change, no Alembic migration, no `openapi.json` regen, no new dependency.
- **Manual verification** — `uvicorn tests.fixtures.serve:app` on `:9317`:
  - `webvigil scan … --cookie "session=abc123"` → `metadata.authenticated: true`, 14 pages
    crawled (reaches `/account` + `/account/settings`), `csrf.form.no-token` on
    `POST /profile` at `HIGH` confidence (the fixture's session cookie has no `SameSite`).
    Stderr: `Authenticated scan: 1 cookie supplied` / `CSRF: 1 form without an anti-CSRF
    token`.
  - anonymous scan → `authenticated: false`, no `csrf.*` findings (the account area 302s to
    `/login`).
  - `--cookie "session=UNIQUESECRET42"` → the value appears **0 times** in the JSON report.
  - `webvigil list-checks` → `csrf.form.no-token | CSRF | passive | MEDIUM`.
