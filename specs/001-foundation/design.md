---
feature: Foundation — scan engine, check contract, v0.1 passive coverage, reporters, CLI
status: done
date: 2026-09-06
related: [001-foundation/requirements.md]
origin: conception
---

# 001 — Foundation — Design

Traceability: every component and decision below cites the requirement(s) it satisfies
(`— RF-NN` / `— RNF-NN`). Requirements are in [requirements.md](requirements.md).

## Overview

WebVigil is one Python package, `webvigil`, split into a **pure engine** and a thin **CLI**.

```
webvigil.cli ──────────────► webvigil.core.Orchestrator
                                   │
        ┌──────────────────────────┼───────────────────────────┐
        ▼                          ▼                           ▼
 webvigil.http.HttpClient   webvigil.crawler.Crawler    webvigil.checks (registry)
 (rate limit, retry,             (a href + sitemap,          Check.run(ctx) -> [Finding]
  scope guard, redirects)         robots, max_pages)
        └──────────────────────────┬───────────────────────────┘
                                   ▼
                          webvigil.core.ScanResult
                                   │
                          webvigil.reporting.get_reporter(fmt)
                          JSON (canonical) · SARIF · HTML · Markdown
```

A scan is: **parse target → enforce mode gate → crawl in scope → run selected checks
concurrently against a shared `ScanContext` → dedupe findings → render one report.**

The engine is `asyncio`-based end to end; the CLI is the only place that calls
`asyncio.run` — RNF-03. No engine module imports `typer`, `rich`, `fastapi`, `sqlmodel`,
or `uvicorn` — RNF-01.

## Module layout

```
src/webvigil/
├── core/
│   ├── __init__.py        # public re-exports (Orchestrator, Target, ScanConfig, Finding, …)
│   ├── config.py          # ScanConfig + sections (pydantic v2), TOML load, CLI-override merge  — RF-26
│   ├── target.py          # Target, Scope, URL normalization                                    — RF-01, RF-02
│   ├── findings.py        # Severity, Confidence, Category, ScanMode, Finding, fingerprint       — RF-12, RF-13
│   ├── context.py         # ScanContext, Page                                                   — RF-06, RF-10
│   ├── result.py          # ScanResult, ScanMetadata, CheckError                                — RF-11, RF-21
│   ├── orchestrator.py    # Orchestrator, Active-mode gate                                       — RF-11, RF-15
│   └── errors.py          # WebVigilError hierarchy
├── http/
│   ├── __init__.py        # HttpClient
│   ├── client.py          # async wrapper over httpx.AsyncClient (retry, redirects, timeout)     — RF-05
│   ├── policy.py          # RateLimiter: concurrency semaphore + per-host delay                  — RF-03
│   ├── scope_guard.py     # ScopeGuard (pre-flight host check, per-redirect-hop check)           — RF-04
│   └── tls_probe.py       # stdlib ssl/socket per-version handshake probe (via asyncio.to_thread) — RF-19
├── crawler/
│   ├── __init__.py        # Crawler
│   ├── crawler.py         # BFS discovery, max_pages, URL de-dup                                 — RF-07
│   ├── robots.py          # robots.txt via urllib.robotparser                                    — RF-07
│   └── sitemap.py         # best-effort sitemap.xml parsing                                      — RF-07
├── checks/
│   ├── __init__.py        # Check, register, iter_checks(), load_plugins()
│   ├── base.py            # Check ABC + Finding-builder helper                                   — RF-08
│   ├── registry.py        # _REGISTRY, register(), entry-point discovery, duplicate-id guard     — RF-09
│   ├── headers/           # csp / hsts / frame_options / content_type_options / referrer_policy
│   │                      #  / permissions_policy / cross_origin_isolation / revealing_headers   — RF-16, RF-17
│   ├── cookies/flags.py   # CookieFlagsCheck                                                     — RF-18
│   ├── tls/check.py       # TlsHttpsCheck (consumes tls_probe + cryptography for cert parsing)   — RF-19
│   └── cors/check.py      # CorsCheck (adds one Origin-probe GET)                                — RF-20
├── reporting/
│   ├── __init__.py        # Reporter protocol, get_reporter(fmt), load_result(path)
│   ├── json_report.py     # canonical: ScanResult.model_dump_json / model_validate_json          — RF-21
│   ├── sarif.py           # hand-built SARIF 2.1.0 dict                                          — RF-22
│   ├── html.py            # Jinja2, single self-contained template                              — RF-23
│   ├── markdown.py        # summary table + per-finding sections                                — RF-23
│   └── templates/report.html.j2
└── cli/
    ├── __init__.py
    ├── app.py             # Typer app (existing `version`) + `scan`, `list-checks`, `report`     — RF-24
    ├── _render.py         # Rich summary → stderr                                               — RF-24
    └── _exit.py           # ExitCode enum + --fail-on evaluation                                — RF-25
```

Package data: `reporting/templates/*` is shipped in the wheel (`artifacts` under
`[tool.hatch.build.targets.wheel]`). The SARIF 2.1.0 JSON schema is test-only and lives at
`tests/data/sarif-2.1.0.json` (not packaged).

## Components

### Target and scope — RF-01, RF-02

```python
class Scope(StrEnum):
    HOST = "host"
    SUBDOMAINS = "subdomains"

@dataclass(frozen=True, slots=True)
class Target:
    entry_url: str        # normalized seed, scheme guaranteed
    host: str             # registered host of entry_url
    origin: str           # scheme://host[:port]
    scope: Scope

    @classmethod
    def parse(cls, raw: str, *, scope: Scope) -> "Target": ...
    def in_scope(self, url: str) -> bool: ...
```

- `parse`: if no scheme, prepend `https://`; reject non-`http(s)` schemes and unparseable
  input with `InvalidTargetError` — RF-01.
- Normalization (also used by the crawler for de-dup): lowercase scheme + host, drop default
  port, drop fragment, keep path + query, collapse `..`/`.`.
- `in_scope`: `HOST` → exact host match; `SUBDOMAINS` → equal to, or a dot-suffix of, the
  registrable domain derived from `host` (a small bundled public-suffix check; fall back to
  "last two labels" when unknown, documented as a limitation) — RF-02.

### HTTP layer — RF-05, RF-03, RF-04

```python
class HttpClient:
    def __init__(self, target: Target, config: ScanConfig): ...
    async def __aenter__(self) -> "HttpClient": ...
    async def get(self, url: str, *, headers: Mapping[str, str] | None = None,
                  allow_out_of_scope: bool = False) -> Response: ...
    @property
    def stats(self) -> HttpStats: ...   # requests, retries, blocked_out_of_scope
```

- Wraps one `httpx.AsyncClient(http2=True, follow_redirects=False,
  verify=config.http.verify_tls, timeout=config.http.timeout_s,
  headers={"user-agent": config.http.user_agent})`.
- **RateLimiter** (`policy.py`): an `asyncio.Semaphore(concurrency)` plus a per-host
  "not before" timestamp enforcing `delay_ms`. Every `get` and the TLS probe acquire it —
  RF-03. Concurrency is capped here, not per check (ADR-4).
- **Retry**: up to 2 retries (3 attempts) on `httpx.TransportError`, `httpx.TimeoutException`,
  or `500/502/503/504`, exponential backoff `0.5·2ⁿ` s with jitter. Exhausted retries raise
  `RequestFailed`, which the caller (crawler / check runner) records but does not propagate —
  RF-05.
- **Redirects**: handled manually. Each hop's `Location` is resolved and passed through
  `ScopeGuard`; an out-of-scope hop stops the chain and the response returned is the last
  in-scope one, with `.redirected_out_of_scope = True` and `.final_location` recorded for
  evidence (TLS check) — RF-04. Max 10 hops.
- **ScopeGuard**: `allow_out_of_scope=False` (default) → a target-external host raises
  `OutOfScopeError` *before* any socket work and increments `stats.blocked_out_of_scope` —
  RF-04. `robots.txt` and `sitemap.xml` fetches to the target origin are in scope normally.

`Response` is a thin frozen view: `url`, `requested_url`, `status_code`, `headers`
(`httpx.Headers`, case-insensitive, multi-value aware for `Set-Cookie`), `text`, `content`,
`elapsed_ms`, `history: list[RedirectHop]`, `redirected_out_of_scope`, `final_location`.

### TLS probe — RF-19

`tls_probe.probe(host: str, port: int = 443) -> TlsProbeResult` runs in
`asyncio.to_thread` and holds a RateLimiter slot for the duration:

```python
@dataclass(frozen=True)
class TlsProbeResult:
    reachable: bool
    negotiated_version: str | None
    offered_versions: dict[str, bool]     # {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"} → handshake ok
    peer_cert_der: bytes | None           # parsed by the check with `cryptography`
    error: str | None
```

- One `ssl.SSLContext` per version, each with `minimum_version == maximum_version`, attempt a
  handshake, record success/failure — RF-19. TLS 1.0/1.1 contexts may be unavailable on the
  running OpenSSL; that is reported as "could not test", not "safe".
- The check parses `peer_cert_der` with `cryptography.x509`: `not_valid_before/after`,
  `subject`/SAN vs `host`, signature hash algorithm, self-signed (issuer == subject).
- No third-party TLS dependency — ADR-8.

### Crawler — RF-07

```python
class Crawler:
    def __init__(self, http: HttpClient, target: Target, config: ScanConfig): ...
    async def discover(self) -> list[Page]: ...   # always includes the seed page first
```

- BFS from `target.entry_url`. Queue seeded additionally from `sitemap.xml` (found directly
  or via a `Sitemap:` line in `robots.txt`); malformed/missing sitemap is ignored — RF-07.
- For each URL: skip if not `in_scope`, if already visited (normalized), if
  `config.scan.follow_robots` and `robots.can_fetch(user_agent, url)` is false, or if
  `len(pages) >= config.scan.max_pages` — RF-07, RF-03.
- Fetch with `HttpClient.get`; on 2xx `text/html`, parse with `selectolax` and extract
  `<a href>` only. `RequestFailed` is recorded on the `Page` and crawling continues.
- `robots.txt` gates **crawler discovery only** — checks are never robots-gated (RF-07).
- GET only; no form discovery (spec 006).

### Check contract and registry — RF-08, RF-09, RF-10

```python
class Category(StrEnum):
    HEADERS = "HEADERS"; COOKIES = "COOKIES"; TLS = "TLS"; CORS = "CORS"
    # reserved for later specs: DEPS, DISCLOSURE, INJECTION

class ScanMode(StrEnum):
    PASSIVE = "passive"; ACTIVE = "active"

class Check(ABC):
    id: ClassVar[str]
    name: ClassVar[str]
    category: ClassVar[Category]
    mode: ClassVar[ScanMode] = ScanMode.PASSIVE
    default_severity: ClassVar[Severity]
    cwe: ClassVar[tuple[int, ...]] = ()
    references: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]: ...

    def finding(self, *, title: str, description: str, remediation: str,
                location: Location, severity: Severity | None = None,
                confidence: Confidence = Confidence.HIGH, dedup_key: str = "",
                evidence: Sequence[EvidenceItem] = ()) -> Finding:
        """Build a Finding pre-filled from this check's class metadata."""
```

- `@register` (in `registry.py`): asserts the required `ClassVar`s are set and non-empty,
  rejects a duplicate `id` with `DuplicateCheckId`, inserts into
  `_REGISTRY: dict[str, type[Check]]` — RF-09.
- Built-ins are registered by importing the `checks.headers`, `checks.cookies`, `checks.tls`,
  `checks.cors` subpackages from `checks/__init__.py`.
- `load_plugins()` iterates `importlib.metadata.entry_points(group="webvigil.checks")` and
  imports each — third-party checks need no change to WebVigil — RF-09.
- `iter_checks(*, mode, disabled) -> list[type[Check]]` is what the Orchestrator calls.

```python
@dataclass(frozen=True, slots=True)
class ScanContext:
    config: ScanConfig
    target: Target
    http: HttpClient
    pages: tuple[Page, ...]      # discovered pages, seed first  — RF-06
    entry: Page

    def page_for(self, url: str) -> Page | None: ...
```

Checks receive HTTP and pages only through `ScanContext`; they never build a client or read
globals — RF-10.

### Orchestrator — RF-11, RF-15

```python
class Orchestrator:
    def __init__(self, config: ScanConfig, *,
                 check_types: Sequence[type[Check]] | None = None): ...
    async def run(self, raw_target: str) -> ScanResult: ...
```

Flow:
1. `Target.parse(raw_target, scope=config.scan.scope)` — RF-01.
2. **Active-mode gate** — RF-15: if `config.scan.mode is ACTIVE` and
   `not config.active or not config.active.authorized_by.strip()` → raise
   `ActiveModeNotAuthorized`. (The interactive prompt is the CLI's job; by the time config
   reaches the engine, `authorized_by` is either present or the run is rejected.) The gate
   lives in the engine, not only the CLI — ADR-10.
3. `async with HttpClient(target, config) as http:`
   - `pages = await Crawler(http, target, config).discover()` — RF-07.
   - `ctx = ScanContext(config, target, http, tuple(pages), pages[0])`.
   - `selected = check_types or iter_checks(mode=config.scan.mode,
     disabled=config.checks.disabled)`; unknown disabled ids → `ScanResult.warnings` — RF-11.
   - Run checks concurrently in an `asyncio.TaskGroup`; each check's HTTP calls funnel
     through the shared RateLimiter, so the concurrency cap still holds — RF-03, ADR-4.
   - A check raising is caught per-task into `CheckError(check_id, message, traceback)`;
     the others finish — RF-08.
4. `findings = dedupe(all_findings)` by `fingerprint` — RF-12.
5. Return `ScanResult(metadata, findings, errors, warnings)` — RF-11.

Only `mode == PASSIVE` checks run in a passive scan; a gated active scan runs both — RF-11.
Since no `ACTIVE` check ships in 001, a gated active run currently executes the same passive
set, but the gate, banner, and `authorized_by` metadata all work end to end — RF-15.

### Reporting — RF-21, RF-22, RF-23

```python
class Reporter(Protocol):
    fmt: ClassVar[str]                 # "json" | "sarif" | "html" | "md"
    def render(self, result: ScanResult) -> str: ...

def get_reporter(fmt: str) -> Reporter: ...
def load_result(path: str) -> ScanResult:      # for `webvigil report`
    return ScanResult.model_validate_json(Path(path).read_text("utf-8"))
```

- **JSON** is canonical and lossless: `result.model_dump_json(indent=2, by_alias=True)`.
  `load_result` is its exact inverse. Every other reporter is a **pure function of
  `ScanResult`**, so `webvigil report scan.json --format <any>` works fully offline —
  RF-21, RF-24, ADR-6.
- **SARIF 2.1.0** — `sarif.py` builds the dict by hand (no library) — ADR-7:
  - one `run`; `tool.driver` = `{name: "WebVigil", version, informationUri, rules: [...]}`.
  - `rules`: one per distinct `check_id` present in findings — `id`, `name`,
    `shortDescription.text` = check name, `helpUri` = first reference,
    `properties.tags` = `[category]`, `properties["security-severity"]` = `"9.0" | "7.0" |
    "4.0" | "1.0"` for HIGH+/HIGH/MEDIUM/LOW+INFO (GitHub code-scanning ranking).
  - `results`: `ruleId` = check_id, `level` = `error` (CRITICAL/HIGH) | `warning` (MEDIUM) |
    `note` (LOW/INFO), `message.text` = finding title + one-line description,
    `locations[0].physicalLocation.artifactLocation.uri` = `finding.location.url`,
    `partialFingerprints["webvigil/v1"]` = `finding.fingerprint`.
  - Validated in tests against a bundled `sarif-2.1.0.json` schema — RF-22.
- **HTML** — `templates/report.html.j2`, Jinja2 with autoescape, one file, inline `<style>`,
  no external requests; sections ordered by severity; per finding: location, evidence
  (`<pre>`), remediation, CWE links, references. A summary header with counts per severity —
  RF-23.
- **Markdown** — a `| Severity | Count |` table, then `## [SEV] title` sections with
  location, fenced-block evidence, remediation — RF-23.

Deterministic ordering everywhere: findings sorted by `(-severity, check_id, location.url,
location.key)` — RNF-04.

### CLI — RF-24, RF-25, RF-26

`cli/app.py` extends the existing Typer app:

```
webvigil scan URL
   --mode [passive|active]        (default passive)                      — RF-14
   --scope [host|subdomains]      (default host)
   --format [json|sarif|html|md]  (default: none → Rich summary only)
   --output PATH
   --max-pages INT   --delay INT(ms)
   --authorized-by TEXT                                                  — RF-15
   --config PATH
   --fail-on [none|info|low|medium|high|critical]  (default none)        — RF-25
   --insecure / --verify-tls      (maps to http.verify_tls)
webvigil list-checks                                                     — RF-24
webvigil report SCAN_JSON --format [json|sarif|html|md] [--output PATH]  — RF-24
webvigil version                                                        (exists)
```

- **Config assembly** — RF-26: `ScanConfig.load(path)` reads TOML via `tomllib` into the
  pydantic model (`model_config = ConfigDict(extra="forbid")` → unknown keys raise); then
  `config.with_overrides(**cli_flags_that_were_set)` deep-merges only the flags the user
  actually passed. Precedence: CLI > file > model defaults (defaults mirror
  `webvigil.example.toml`).
- **Active prompt** — RF-15: if `--mode active` and no `--authorized-by`: when
  `sys.stdin.isatty()` prompt for the text (reject empty); otherwise exit `CONFIG` with an
  explanatory message. On success print the legal banner to stderr.
- **Output routing** — RF-24, ADR-9:
  - no `--format` → Rich summary table to **stderr**, nothing on stdout.
  - `--format F`, no `--output` → report on **stdout**, Rich summary on **stderr**.
  - `--format F --output P` → report to file `P`, one-line status on **stderr**, stdout empty.
- **Exit codes** — `_exit.py`, RF-25:

  | Code | Name | When |
  |---|---|---|
  | 0 | `OK` | scan completed; no finding ≥ `--fail-on` (or `--fail-on none`) |
  | 2 | `USAGE` | bad CLI arguments (Typer default) |
  | 3 | `FINDINGS` | at least one finding with `severity >= fail_on` |
  | 4 | `OPERATIONAL` | invalid target, network unreachable, config error |
  | 5 | `NOT_AUTHORIZED` | `--mode active` without authorization |
  | 1 | `INTERNAL` | uncaught error (bug) |

  `--fail-on` compares severity only — RF-25.
- `list-checks` loads plugins, then prints a Rich table of `id / category / mode /
  default_severity` for every registered check — RF-24.

## Data model — RF-12, RF-13

`findings.py` (all pydantic v2 `BaseModel`, `frozen=True` — ADR-2):

```python
class Severity(IntEnum):        # ordered — RF-13
    INFO = 0; LOW = 10; MEDIUM = 20; HIGH = 30; CRITICAL = 40

class Confidence(IntEnum):
    LOW = 10; MEDIUM = 20; HIGH = 30

class Location(BaseModel):
    url: str
    method: str = "GET"
    param: str | None = None
    header: str | None = None
    cookie: str | None = None
    @property
    def key(self) -> str:        # for fingerprint + ordering
        return self.param or self.header or self.cookie or ""

class EvidenceItem(BaseModel):
    label: str                  # "response headers", "Set-Cookie", "certificate", …
    content: str                # trimmed to ≤ 4 KiB

class Finding(BaseModel):
    check_id: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    evidence: tuple[EvidenceItem, ...] = ()
    location: Location
    remediation: str
    cwe: tuple[int, ...] = ()
    references: tuple[str, ...] = ()
    fingerprint: str            # set by `Check.finding`, never by hand
```

**Fingerprint** — RF-12: `sha256(f"{check_id}\n{location.url}\n{location.key}\n{dedup_key}")`,
first 16 hex chars. `dedup_key` is a short check-chosen string capturing the salient fact
(e.g. `"unsafe-inline"`, `"TLSv1.0"`, `""`). Two findings with equal fingerprints collapse to
one (first wins) in `Orchestrator.dedupe`.

**Contextual severity** — RF-12: `Check.finding(severity=...)` overrides `default_severity`
per finding (e.g. `HstsCheck` lowers to `LOW` when the site is already HTTP-only, since the
TLS check owns the primary finding).

`result.py`:

```python
class ScanMetadata(BaseModel):
    target: str
    mode: ScanMode
    scope: Scope
    authorized_by: str | None = None
    tool_version: str
    started_at: datetime
    finished_at: datetime
    pages_scanned: int
    counts: dict[str, int]          # severity name → count

class CheckError(BaseModel):
    check_id: str
    message: str
    traceback: str

class ScanResult(BaseModel):
    metadata: ScanMetadata
    findings: tuple[Finding, ...]
    errors: tuple[CheckError, ...] = ()
    warnings: tuple[str, ...] = ()
```

`config.py`:

```python
class ScanSection(BaseModel):     # extra="forbid"
    mode: ScanMode = ScanMode.PASSIVE
    scope: Scope = Scope.HOST
    max_pages: int = 50
    follow_robots: bool = True

class HttpSection(BaseModel):
    concurrency: int = 8
    delay_ms: int = 0
    timeout_s: float = 15
    user_agent: str = "WebVigil/0.1 (+https://github.com/ryanvmorais/webvigil)"
    verify_tls: bool = True

class ReportSection(BaseModel):
    format: Literal["json", "sarif", "html", "md"] = "json"
    output: str | None = None
    fail_on: Literal["none", "info", "low", "medium", "high", "critical"] = "none"

class ActiveSection(BaseModel):
    authorized_by: str

class ChecksSection(BaseModel):
    disabled: list[str] = []

class ScanConfig(BaseModel):
    scan: ScanSection = ScanSection()
    http: HttpSection = HttpSection()
    report: ReportSection = ReportSection()
    active: ActiveSection | None = None
    checks: ChecksSection = ChecksSection()
```

Matches `webvigil.example.toml` exactly; unknown sections/keys rejected — RF-26.

## Interfaces / contracts

### Check IDs (stable public surface)

| Check class | `id` | default severity |
|---|---|---|
| `CspCheck` | `http.headers.csp` | MEDIUM |
| `HstsCheck` | `http.headers.hsts` | MEDIUM |
| `FrameOptionsCheck` | `http.headers.frame-options` | MEDIUM |
| `ContentTypeOptionsCheck` | `http.headers.content-type-options` | LOW |
| `ReferrerPolicyCheck` | `http.headers.referrer-policy` | LOW |
| `PermissionsPolicyCheck` | `http.headers.permissions-policy` | INFO |
| `CrossOriginIsolationCheck` | `http.headers.cross-origin-isolation` | INFO |
| `RevealingHeadersCheck` | `http.headers.revealing` | LOW |
| `CookieFlagsCheck` | `http.cookies.flags` | MEDIUM |
| `TlsHttpsCheck` | `tls.https` | HIGH |
| `CorsCheck` | `http.cors.misconfiguration` | MEDIUM |

Each emits multiple findings distinguished by `dedup_key` (e.g. `http.headers.csp` +
`unsafe-inline` / `missing` / `permissive-default-src`). One class per header family so each
is independently testable and independently disableable via `checks.disabled` — RF-16, ADR-3.

### Entry-point contract (third-party checks) — RF-09

```toml
# a plugin's pyproject.toml
[project.entry-points."webvigil.checks"]
my_pack = "my_pack.checks"    # module imported at startup; its @register calls take effect
```

### JSON report shape — RF-21

`ScanResult` serialized with pydantic aliases; documented in `docs/` and covered by a
round-trip test (`model_validate_json(model_dump_json(x)) == x`). This is the only format
whose shape is a compatibility promise for 001.

## ADRs

### ADR-1 — Engine is a pure library; UI/persistence never imported
**Decision:** `core`, `http`, `crawler`, `checks`, `reporting` may not import `typer`,
`rich`, `fastapi`, `sqlmodel`, `uvicorn`. Enforced by an `import-linter` contract run in CI.
**Alternatives:** convention only; a single flat package.
**Why:** spec 002 (Web API) and future embedders reuse the engine; a leak now is expensive
later. A machine check prevents drift — RNF-01.
**Trade-off:** `rich` is barred from the engine, so progress/log output uses stdlib
`logging` and the CLI renders it; one extra dev dependency (`import-linter`).

### ADR-2 — pydantic v2 for every model (config, Finding, ScanResult)
**Decision:** all models are frozen pydantic `BaseModel`s.
**Alternatives:** stdlib `dataclasses` + manual (de)serialization; `attrs`.
**Why:** one mechanism for validation, `extra="forbid"` config parsing, and lossless
JSON round-trip that reporters and `webvigil report` depend on — RF-21, RF-26.
**Trade-off:** models are import-time heavier and a hard dependency of the engine (already
in the stack). Enums must be `IntEnum` to keep ordering after a JSON round-trip.

### ADR-3 — One check class per security-header family
**Decision:** `CspCheck`, `HstsCheck`, … rather than one `SecurityHeadersCheck`.
**Alternatives:** a single mega-check emitting many finding ids.
**Why:** each check gets focused vulnerable/hardened fixtures, and users can disable exactly
one via `checks.disabled` — RF-16.
**Trade-off:** ~8 small classes and some shared header-parsing helpers; a single response is
read by several checks (cheap — it is already cached, RF-06).

### ADR-4 — Concurrency capped at the HTTP layer, not per check
**Decision:** one shared `RateLimiter` (semaphore + per-host delay) inside `HttpClient`;
checks run in an unbounded `TaskGroup`.
**Alternatives:** a semaphore around check execution; a global work queue.
**Why:** "good neighbor" is about *requests to the target*, not CPU tasks. Checks are mostly
idle awaiting IO; bounding them instead would under-use the budget and still need per-request
limiting for the crawler — RF-03.
**Trade-off:** a buggy check could create many pending coroutines; acceptable (checks are
first-party in 001) and revisited if third-party checks misbehave.

### ADR-5 — Manual redirect handling in the HTTP wrapper
**Decision:** `httpx` with `follow_redirects=False`; the wrapper walks the chain, scope-checking
every hop.
**Alternatives:** `follow_redirects=True` with an event hook; a custom `httpx` transport.
**Why:** the scope guard must veto a cross-origin redirect *before* the request, and the TLS
check needs the exact HTTP→HTTPS hop as evidence — RF-04, RF-19.
**Trade-off:** we reimplement a little redirect logic (method/body on 301/302/303, `Location`
resolution, hop cap).

### ADR-6 — Canonical JSON = full `ScanResult`; other reporters are pure functions of it
**Decision:** JSON serializes the whole result losslessly; SARIF/HTML/Markdown take only a
`ScanResult`; `webvigil report` reloads JSON and can emit any format.
**Alternatives:** each format rendered only during a live scan; a separate slimmer "report
JSON".
**Why:** re-rendering offline (CI keeps `scan.json`, renders HTML for humans later) and one
source of truth — RF-21, RF-24.
**Trade-off:** the JSON carries everything (tracebacks, evidence blobs); size is acceptable
for a single-target scan.

### ADR-7 — SARIF built by hand, schema-tested
**Decision:** construct the SARIF dict directly; validate against a bundled 2.1.0 schema in
tests only.
**Alternatives:** `sarif-om` / `jschema-to-python`.
**Why:** WebVigil needs a small, fixed slice of SARIF; those libraries are heavy and
awkwardly typed. A schema test gives the same safety — RF-22, RNF-08.
**Trade-off:** we own the mapping; schema drift is caught by the test, not the type system.

### ADR-8 — TLS protocol probing via stdlib `ssl`, no `sslyze`
**Decision:** per-version handshake attempts with `ssl.SSLContext`, run in
`asyncio.to_thread`; certificate parsed with `cryptography`.
**Alternatives:** `sslyze`; shelling out to `openssl`/`testssl.sh`.
**Why:** version detection + certificate checks cover the v0.1 requirement with zero new
dependencies; deeper analysis is out of scope — RF-19, and confirmed with Ryan.
**Trade-off:** cannot enumerate cipher suites, and TLS 1.0/1.1 can be untestable when the
host OpenSSL disables them — reported honestly as "not tested".

### ADR-9 — CLI: report to stdout, everything human to stderr; enumerated exit codes
**Decision:** machine output (the report) on stdout; Rich summaries, banners, status on
stderr; a fixed `ExitCode` enum.
**Alternatives:** report to stdout with summary also on stdout; `--quiet` to suppress.
**Why:** `webvigil scan url --format sarif > r.sarif` must yield a clean file; CI branches on
the exit code — RF-24, RF-25, confirmed with Ryan.
**Trade-off:** users who pipe stderr to a log see banners there; documented.

### ADR-10 — Active-mode gate enforced in the Orchestrator
**Decision:** the engine raises `ActiveModeNotAuthorized` when active mode lacks
`authorized_by`; the CLI only *collects* the authorization (prompt) and shows the banner.
**Alternatives:** gate only in the CLI.
**Why:** spec 002's Web API is another caller; the safety invariant must live where every
caller passes through — RF-15.
**Trade-off:** the interactive prompt still has to live in the CLI, so the rule is expressed
in two layers (collect vs enforce).

## Impact

- **New source:** ~all of `webvigil.{core,http,crawler,checks,reporting}` and the new CLI
  commands. `cli/app.py` gains `scan`, `list-checks`, `report`.
- **Existing files touched:** `docs/writing-checks.md` and `docs/architecture.md` completed
  (RF-28); `README.md` quick-start verified against the real CLI (RF-28);
  `webvigil.example.toml` already matches the config model.
- **Dependencies:** no new *runtime* deps — `httpx`, `pydantic`, `typer`, `rich`, `jinja2`,
  `cryptography`, `selectolax` are already declared. **Dev deps to add:** `import-linter`
  (ADR-1), `jsonschema` (SARIF test, ADR-7), `trustme` (TLS test certificates).
- **Packaging (RF-29):** add a `Dockerfile` (engine + CLI, no `web` extra) and document
  `pipx install .` / `uv tool install .`; wheel `packages`/`artifacts` updated for templates
  and the test-only schema.
- **CI:** the existing `ci.yml` already runs ruff/black/mypy/pytest on 3.12+3.13; add an
  `import-linter` step and a `docker build` smoke step.

## Risks

| Risk | Mitigation |
|---|---|
| **False positives** erode trust — the project's biggest credibility risk. | Mandatory vulnerable + hardened fixtures per check; the hardened fixture-app profile asserts **zero** findings in an integration test (RF-27); every finding carries `confidence`. |
| Registrable-domain detection for `--scope subdomains` without a full PSL. | Bundle a tiny suffix set for common cases; fall back to last-two-labels; document the limitation; a full PSL is a later enhancement. |
| TLS 1.0/1.1 not testable on modern OpenSSL → silent under-reporting. | Probe result distinguishes "handshake refused" from "version unavailable locally"; the check reports the latter as an informational note, not a pass. |
| Manual redirect logic diverges from real browser/`httpx` behavior. | Unit tests for 301/302/303/307/308 method+body handling and the hop cap; keep the seed's pre-redirect and final URL both in evidence. |
| CORS probe (an extra `Origin` GET) is the most "active" thing Safe Mode does. | Documented in `SECURITY.md`/README as part of passive behavior (RNF-05); still a plain GET, still scope-guarded. |
| `asyncio.to_thread` for TLS probing under a high concurrency cap could exhaust the default thread pool. | The probe holds a RateLimiter slot, so in-flight probes are bounded by `concurrency`. |
| Engine purity regresses as later specs add features. | `import-linter` contract in CI fails the build (ADR-1). |

## Testing — RNF-02, RF-27

- **Unit — checks:** each check has `test_<check>.py` with a **vulnerable** `httpx` response
  fixture (asserts finding id, `severity`, `dedup_key`, evidence substring) and a **hardened**
  fixture (asserts `[]`). `pytest-httpx` mocks responses — RF-16..RF-20.
- **Unit — HTTP layer:** retry/backoff on transient errors; `OutOfScopeError` pre-flight;
  redirect chain stops at a cross-scope hop; `delay_ms` spacing; concurrency never exceeds
  the cap (instrumented counter).
- **Unit — TLS:** `trustme`-minted certs (expired, wrong host, self-signed) served by a
  localhost TLS socket; assert the corresponding findings. Version-probe logic tested against
  a local server pinned to one version.
- **Unit — crawler:** `max_pages` stop, URL de-dup/normalization, `robots.txt` disallow
  honored, malformed `sitemap.xml` ignored.
- **Unit — model:** `Finding` fingerprint stability and dedupe; `ScanResult` JSON round-trip;
  `ScanConfig` rejects unknown keys; CLI-override precedence.
- **Unit — reporters:** SARIF validates against the bundled 2.1.0 schema (`jsonschema`);
  HTML has no external URLs and escapes evidence; Markdown table counts match; ordering is
  deterministic (RNF-04).
- **Integration — fixture app (`tests/fixtures/app.py`, Starlette):** `insecure` and
  `hardened` profiles served via `httpx.ASGITransport`. Assert the insecure scan produces
  every HTTP/cookie/CORS/revealing-header finding the v0.1 checks target, and the hardened
  scan produces **zero** — RF-27. (TLS cases stay in the socket-based unit tests.)
- **Integration — CLI:** `CliRunner` for `scan` (stubbed Orchestrator), `list-checks`,
  `report` (offline re-render to each format), exit codes for `--fail-on`, the active-mode
  prompt/rejection paths.
- **Architecture:** `import-linter` contract test — the engine imports none of
  `typer/rich/fastapi/sqlmodel/uvicorn` (RNF-01).
- **Packaging smoke:** `docker build` in CI; a test that `pipx run --spec . webvigil version`
  works from a clean env is optional/manual.
- **Gate:** `/qualidade-python` (`ruff → black → mypy --strict → pytest`) green — RNF-02.

## Open questions

None blocking. Minor items deferred to implementation: exact CSP-directive heuristics
(threshold list), the bundled public-suffix subset contents, and the HSTS `max-age`
threshold value — all encoded as named constants with a short rationale comment.
