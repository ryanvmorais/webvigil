---
feature: Information disclosure — exposed files/routes, directory listing, stack traces, debug endpoints
status: done
date: 2026-09-06
related:
  - 005-info-disclosure/requirements.md
  - 001-foundation/design.md
  - 002-web-api/design.md
  - 004-deps-fingerprint/design.md
origin: conception
---

# 005 — Information disclosure — Design

Traceability: every component and decision cites its requirement (`— RF-NN` / `— RNF-NN`).
Requirements: [requirements.md](requirements.md).

## Overview

005 adds one new check package, `webvigil.checks.disclosure`, in two tiers:

- **Passive tier** — two ordinary `Check`s that read the responses the crawler already
  fetched (`ctx.pages`) and recognise framework error pages / stack traces (RF-01) and
  server-generated directory listings (RF-02). No new requests. Always run unless disabled.
- **Probe tier** — an **orchestrator pass** (`DisclosureProbe`, sibling of spec 004's
  `Fingerprinter`) that runs **only when `[disclosure] probe = true`** *and* at least one
  probe-fed `disclosure.*` check is selected. It calibrates the target's "not found" shape,
  requests a small curated catalogue of well-known sensitive paths + a few derived paths,
  content-validates each response, and produces `ProbeHit`s. Six thin probe-fed `Check`s
  turn hits of their family into `Finding`s.

Every finding is an ordinary `Finding`. **No new `ScanResult` field, no Alembic migration,
no `openapi.json` change, no dashboard change** — 005 is engine-only (RF-12, Resolved
decision 4). Findings persist and render through spec 001's four reporters and spec
002/003's existing plumbing unchanged.

```
Orchestrator.run
  ├─ crawl (unchanged) ───────────────────────► pages: tuple[Page]
  ├─ fingerprint pass (spec 004, unchanged)
  ├─ DisclosureProbe(http, target, catalogue, pages).run()                       — RF-04..09
  │      │  only if  config.disclosure.probe  AND  a probe-fed disclosure check is selected
  │      │  1. soft-404 calibration        2. catalogue GETs + content validation
  │      │  3. derived probes (<script>.map, VCS at discovered dirs)
  │      ▼
  │   ScanContext.observations.probe_hits  ◄── set once by the orchestrator      — ADR-3
  ├─ run checks concurrently
  │      disclosure.debug.error-page       ─ read ctx.pages  ─────────────► Findings  — RF-01
  │      disclosure.listing.directory-index ─ read ctx.pages ─────────────► Findings  — RF-02
  │      disclosure.vcs.exposed  / .config.dotenv-exposed / .config.manifest-exposed
  │      disclosure.backup.file-exposed / .debug.endpoint-exposed / .sourcemap.exposed
  │          └─ read ctx.observations.probe_hits, filter by family ──────► Findings  — RF-08
  ▼
ScanResult{ findings, warnings, ... }        — reporters + API + dashboard unchanged  — RF-11, RF-12
```

Engine purity (RNF-01): the new code lives under `webvigil.checks.disclosure` (already a
`source_module` — the `import-linter` contract is unchanged) and `webvigil.core`
(`orchestrator.py`, `context.py`, `config.py`), and imports only the stdlib (`re`, `json`,
`secrets`). No new dependency. No network beyond in-scope `GET`s.

## Module layout

```
src/webvigil/checks/disclosure/
├── __init__.py            # registers all 8 checks                                  — RF-08, RF-10
├── errors.py              # ErrorPageCheck (passive)                                 — RF-01
├── listing.py             # DirectoryListingCheck (passive)                          — RF-02
├── signatures.py          # compiled regex tables for error pages + listings         — RF-01, RF-02
├── probe.py               # DisclosureProbe: calibration, catalogue GETs, validation — RF-04..07, RF-09
├── catalogue.py           # load/parse data/paths.toml -> tuple[ProbeEntry]          — RF-05
├── checks.py              # the 6 probe-fed Check classes                            — RF-08
├── redaction.py           # secret redaction for evidence                            — RNF-06
└── data/
    └── paths.toml         # the curated catalogue (versioned, not user-extensible)   — RF-05

src/webvigil/core/
├── context.py             # Observations gains `probe_hits: tuple[ProbeHit, ...]`     — ADR-3
├── config.py              # ScanConfig gains `disclosure: DisclosureSection`         — RF-04
├── findings.py            # Category.DISCLOSURE is un-commented                       — RF-08
└── orchestrator.py        # run DisclosureProbe; feed probe_hits into ScanContext

src/webvigil/cli/
├── app.py                 # scan gains `--probe / --no-probe`; _build_config passes it — RF-10
└── _render.py             # summary line when probe findings exist                    — RF-10

webvigil.example.toml      # documents `[disclosure] probe = false`                    — RF-04
pyproject.toml             # hatch `artifacts` += disclosure/data/*.toml
tests/fixtures/app.py      # insecure profile exposes .git/.env/listing/trace/manifest  — RF-13
docs/information-disclosure.md   # new                                                 — RF-15
```

Reporters (`webvigil.reporting`), the Web API (`webvigil.api`), and `web/` are **not
touched** (RF-11, RF-12).

## Components

### `Category.DISCLOSURE` — RF-08

`findings.py`: the `# Reserved for later specs: DISCLOSURE, INJECTION.` comment becomes
`DISCLOSURE = "DISCLOSURE"` + `# Reserved for later specs: INJECTION.`

### Passive tier

#### `signatures.py` — RF-01, RF-02

Pure data: compiled regex tables, no I/O.

```python
@dataclass(frozen=True, slots=True)
class ErrorSignature:
    framework: str            # "Werkzeug", "Django", "Rails", "ASP.NET", "PHP", "Java", "Node"
    pattern: re.Pattern[str]  # matched against the response body
    interactive: bool         # True for the Werkzeug console (code-execution surface)
    severity: Severity        # HIGH interactive, MEDIUM stack trace, LOW lone PHP notice

ERROR_SIGNATURES: tuple[ErrorSignature, ...] = (...)

LISTING_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(r"<title>\s*Index of /"),               # Apache mod_autoindex
    re.compile(r"<title>Directory listing for /"),     # Python http.server
    re.compile(r"<h1>Index of /.*</h1>.*<pre>", re.S), # nginx autoindex / Apache
)
```

`match_error(body: str) -> ErrorSignature | None` returns the first (most specific) match;
`is_directory_listing(body: str) -> bool`.

The error patterns key on the framework's *chrome*, not on the words "error" or
"exception" alone — e.g. Werkzeug requires both `Werkzeug Debugger` and the traceback
markup; PHP requires `<b>(Fatal error|Warning|Notice)</b>:` **with** an `in <path> on line
N` tail. This keeps RF-01's hardened case (generic "Something went wrong") clean.

#### `ErrorPageCheck` — RF-01

```python
@register
class ErrorPageCheck(Check):
    id = "disclosure.debug.error-page"
    name = "Framework error page / stack trace exposed"
    category = Category.DISCLOSURE
    mode = ScanMode.PASSIVE
    default_severity = Severity.MEDIUM
    cwe = (215, 200)
    references = ("https://owasp.org/www-community/Improper_Error_Handling",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        seen: set[str] = set()
        for page in ctx.pages:
            if not page.ok or not page.is_html:
                continue
            sig = match_error(page.text)
            if sig is None or sig.framework in seen:
                continue
            seen.add(sig.framework)
            out.append(self.finding(
                title=f"{sig.framework} error page exposed",
                description=("The application returned a framework error page / stack "
                             "trace to the client. It reveals file paths, code, and "
                             "component versions and often indicates debug mode is on."),
                remediation=("Disable debug mode in production (e.g. DEBUG = False, "
                             "APP_DEBUG=false, <customErrors mode=\"On\">) and return a "
                             "generic error page."),
                severity=sig.severity,
                confidence=Confidence.HIGH if sig.interactive else Confidence.MEDIUM,
                location=Location(url=page.url),
                dedup_key=sig.framework,
                evidence=[EvidenceItem.of("Marker", _first_match_snippet(sig, page.text))],
            ))
        return out
```

De-duplicates on `framework` so the same debug page on many routes is one finding (RNF-04).

#### `DirectoryListingCheck` — RF-02

Same shape; `id = "disclosure.listing.directory-index"`, `default_severity = MEDIUM`,
`cwe = (548,)`. Iterates `ctx.pages`, emits one finding per listed URL, evidence = a
trimmed sample of the `<a>` entries. `dedup_key = page.url`.

### Probe tier

#### `catalogue.py` — RF-05

Loads `data/paths.toml` once (`functools.lru_cache`) and expands it.

```python
@dataclass(frozen=True, slots=True)
class ProbeEntry:
    path: str                       # relative, no leading slash: ".git/config"
    family: str                     # "vcs" | "config" | "manifest" | "backup" | "debug" | "sourcemap"
    check_id: str                   # the disclosure.* check that renders a hit
    severity: Severity
    confidence: Confidence
    title: str                      # "Version-control metadata exposed"
    description: str
    validator: Validator            # how to confirm the body is what the name implies
    redaction: str                  # "dotenv" | "json-env" | "generic" | "none"
    ok_status: frozenset[int]       # {200, 206}; {200, 403} only for ".git/" index

class Validator:
    """One of: a compiled content regex (+ min match count), a required content-type,
    or a JSON shape (parses AND contains one of `keys`). Applied to the response body."""
```

`load_catalogue() -> tuple[ProbeEntry, ...]` returns the parsed VCS / config / manifest /
debug entries verbatim, **plus** the backup cross-product generated from two small lists
in the file:

```toml
[backups]
basenames = ["index", "db", "database", "backup", "dump", "site", "www"]
suffixes  = [".bak", ".old", ".orig", ".save", "~", ".swp", ".zip", ".tar.gz", ".sql", ".sql.gz"]
# a ".sql" / ".sql.gz" hit is HIGH; the rest MEDIUM (encoded in the loader)
```

The target's own host label (`target.host.split(".")[0]`) is appended to `basenames` at
run time by `DisclosureProbe`, not stored in the file. Total catalogue size is a documented
constant (~100–130 after expansion). WebVigil adds **no** entries from user config
(Resolved decision 2).

`paths.toml` example entries:

```toml
[[entry]]
path = ".git/config"
family = "vcs"
check = "disclosure.vcs.exposed"
severity = "high"
title = "Version-control metadata exposed"
content = '\[core\]'
description = "A reachable .git/config lets an attacker recover source and history."

[[entry]]
path = ".env"
family = "config"
check = "disclosure.config.dotenv-exposed"
severity = "high"
title = "Environment file exposed"
content = '(?m)^(export\s+)?[A-Za-z_][A-Za-z0-9_]*='
min_matches = 2
redact = "dotenv"

[[entry]]
path = "package.json"
family = "manifest"
check = "disclosure.config.manifest-exposed"
severity = "low"
title = "Dependency manifest exposed"
json_keys = ["name", "dependencies", "devDependencies"]

[[entry]]
path = "actuator/env"
family = "debug"
check = "disclosure.debug.endpoint-exposed"
severity = "high"
title = "Spring Boot actuator/env exposed"
json_keys = ["propertySources"]
redact = "json-env"
```

#### `DisclosureProbe` — RF-04, RF-06, RF-07, RF-09

```python
_REQUEST_CAP = 150            # catalogue + derived; ADR-4
_CALIBRATION_PATHS = 3
_MAX_DERIVED_DIRS = 10        # Resolved decision 6

@dataclass(frozen=True, slots=True)
class ProbeHit:
    family: str
    check_id: str
    url: str
    path: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    status: int
    content_type: str
    redacted_body: str        # RNF-06 — never a raw secret

@dataclass(frozen=True, slots=True)
class ProbeReport:
    hits: tuple[ProbeHit, ...]
    paths_probed: int
    warnings: tuple[str, ...]

class DisclosureProbe:
    def __init__(self, http: HttpClient, target: Target,
                 catalogue: tuple[ProbeEntry, ...], pages: Sequence[Page]): ...
    async def run(self) -> ProbeReport: ...
```

`run()`:

1. **Calibrate (RF-06).** `GET` `_CALIBRATION_PATHS` random URLs —
   `f"{origin}/{secrets.token_hex(16)}"`, one with a `.env` suffix, one with a trailing
   `/`. Record a `Soft404` fingerprint: `{status, body-length band (±15 %), <title>,
   whether every random path returned an identical body}`. If the random paths return
   `200` with a stable body → SPA catch-all: remember that body hash. If they disagree and
   none is a clean `404` → `inconclusive`, add a warning (RF-09), continue with strict
   validation only.
2. **Build the request list.** The catalogue paths (resolved against `target.origin`), plus
   derived probes (RF-07):
   - for each distinct in-scope `<script src>` referenced by a crawled HTML page:
     `f"{script_url}.map"` as a `sourcemap`-family entry;
   - for the web root **and** each distinct in-scope directory prefix in the discovered
     page URLs (capped at `_MAX_DERIVED_DIRS`): the `vcs` entries re-based under that prefix.
   De-duplicate by absolute URL. Truncate at `_REQUEST_CAP`; a truncated list adds the
   warning `"information-disclosure probing stopped at the 150-request cap"` (RF-09).
3. **Fetch** every URL with `http.get(url)` — concurrency cap, per-host delay, scope guard,
   retries, `timeout_s` all apply (RF-09). Failures are swallowed (best-effort, like the
   sitemap parser).
4. **Classify each response as a hit** iff *all* hold (RF-06):
   - `response.status_code in entry.ok_status`;
   - the response is **not** the `Soft404` (status differs, or body-length outside the
     band, or — for a `200` SPA — body hash differs);
   - `entry.validator` passes on the body (regex with `min_matches`, or content-type, or
     JSON parses and carries a listed key).
5. **Redact** the body (`redaction.apply(entry.redaction, body)`) and build a `ProbeHit`.
   For `.git/` **directory** entries a `403` with an Apache/nginx forbidden body also
   counts (the dir exists) — `confidence = MEDIUM`.
6. Return `ProbeReport(hits, paths_probed=len(request_list), warnings)`.

`DisclosureProbe` issues only `GET`s, no payloads, no state change — it is Safe (RNF-03).

#### `redaction.py` — RNF-06

```python
_SECRET_RE = re.compile(r"(?i)(?:[A-Za-z0-9+/_-]{24,}={0,2}|AKIA[0-9A-Z]{16}|-----BEGIN[^-]+-----)")

def apply(strategy: str, body: str) -> str:
    if strategy == "dotenv":     return _redact_dotenv(body)     # KEY=***  (keep keys, comments)
    if strategy == "json-env":   return _redact_json_env(body)   # keep property names, mask "value"
    if strategy == "generic":    return _SECRET_RE.sub("***redacted***", body[:1024])
    return body[:1024]                                           # "none" — still length-bounded
```

Every `ProbeHit.redacted_body` goes through this **before** it is placed in a `Finding`, so
the raw secret never enters `ScanResult`, a report, or (via the API) the database. Unit-
tested (RF-14, RNF-06). `EvidenceItem.of` still applies its own 4 KB cap on top.

#### The six probe-fed checks — `checks.py`, RF-08, RF-10

```python
class _ProbeFedCheck(Check):
    family: ClassVar[str]
    category = Category.DISCLOSURE
    mode = ScanMode.PASSIVE

    async def run(self, ctx: ScanContext) -> list[Finding]:
        return [
            self.finding(
                title=f"{hit.title} at /{hit.path}",
                description=hit.description,
                remediation=_REMEDIATION[self.family],
                severity=hit.severity,
                confidence=hit.confidence,
                location=Location(url=hit.url),
                dedup_key=hit.path,
                evidence=[
                    EvidenceItem.of("Response", f"HTTP {hit.status} {hit.content_type}"),
                    EvidenceItem.of("Body (redacted)", hit.redacted_body),
                ],
            )
            for hit in ctx.observations.probe_hits
            if hit.family == self.family
        ]


@register
class VcsExposedCheck(_ProbeFedCheck):
    id = "disclosure.vcs.exposed"
    name = "Version-control metadata exposed"
    family = "vcs"
    default_severity = Severity.HIGH
    cwe = (527, 538)

@register
class DotenvExposedCheck(_ProbeFedCheck):
    id = "disclosure.config.dotenv-exposed"
    family = "config"
    default_severity = Severity.HIGH
    cwe = (538, 200)

@register
class ManifestExposedCheck(_ProbeFedCheck):
    id = "disclosure.config.manifest-exposed"
    family = "manifest"
    default_severity = Severity.LOW
    cwe = (538,)

@register
class BackupFileExposedCheck(_ProbeFedCheck):
    id = "disclosure.backup.file-exposed"
    family = "backup"
    default_severity = Severity.MEDIUM
    cwe = (538, 530)

@register
class DebugEndpointExposedCheck(_ProbeFedCheck):
    id = "disclosure.debug.endpoint-exposed"
    family = "debug"
    default_severity = Severity.MEDIUM
    cwe = (215, 497)

@register
class SourcemapExposedCheck(_ProbeFedCheck):
    id = "disclosure.sourcemap.exposed"
    family = "sourcemap"
    default_severity = Severity.MEDIUM
    cwe = (540, 200)
```

- **Per-finding severity** comes from the catalogue entry (`hit.severity`) — e.g. a `.sql`
  dump or `/actuator/env` entry carries `HIGH` while a generic `.bak` carries `MEDIUM`
  (RF-08). The class `default_severity` is the fallback / what `list-checks` shows.
- **Disable** any id via `[checks] disabled` — normal mechanism (RF-10). If **every**
  probe-fed id is disabled, `DisclosureProbe` is not constructed (orchestrator, below) —
  no calibration, no requests. The passive-tier checks still run.
- `cwe` is class-level (per family); `references` per family in `_REMEDIATION`'s sibling
  `_REFERENCES` map, applied like spec 004 (`self.finding(...)` then
  `model_copy(update={"references": ...})`), or set on the class where a single URL fits.

### `ScanContext.observations.probe_hits` — ADR-3

`context.py`, `Observations` gains one field (still a `@dataclass(slots=True)`):

```python
@dataclass(slots=True)
class Observations:
    detections: tuple[Detection, ...] = ()          # spec 004 — set once by the orchestrator
    probe_hits: tuple[ProbeHit, ...] = ()           # spec 005 — set once by the orchestrator
    _technologies: dict[tuple[str, str | None], Technology] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    # ... add_technology / add_warning / technologies unchanged
```

`ProbeHit` is defined in `webvigil.checks.disclosure.probe`; `context.py` imports it under
`TYPE_CHECKING` only (it already does this for `HttpClient`), keeping `core` free of a
runtime import from `checks`. (`Detection` is currently defined *in* `context.py`; `ProbeHit`
stays in the checks package because, unlike `Detection`, nothing in `core` or `reporting`
needs it — only the checks do. If mypy's `TYPE_CHECKING` cycle proves awkward,
`ProbeHit` moves to `context.py` beside `Detection` — implementation call.)

### Orchestrator wiring

`Orchestrator.run`, right after the fingerprint pass:

```python
selected = self._select_checks(warnings)
detections = await self._fingerprint(selected, http, target, pages, warnings)   # spec 004
probe_hits = await self._probe_disclosure(selected, http, target, pages, warnings)

context = ScanContext(
    ...,
    observations=Observations(detections=detections, probe_hits=probe_hits),
)
```

```python
_PROBE_FAMILIES = frozenset({"vcs", "config", "manifest", "backup", "debug", "sourcemap"})

async def _probe_disclosure(self, selected, http, target, pages, warnings):
    if not self._config.disclosure.probe:
        return ()
    if not any(getattr(c, "family", None) in _PROBE_FAMILIES for c in selected):
        return ()
    report = await DisclosureProbe(http, target, load_catalogue(), pages).run()
    warnings.extend(report.warnings)
    return report.hits
```

`orchestrator.py` already imports from `webvigil.checks.deps`; adding
`webvigil.checks.disclosure` is the same direction, no new dependency edge.

### Config — RF-04

`config.py`:

```python
class DisclosureSection(_Section):
    probe: bool = False

class ScanConfig(_Section):
    ...
    disclosure: DisclosureSection = DisclosureSection()
```

`webvigil.example.toml` gains:

```toml
[disclosure]
probe = false   # opt-in: GET a curated list of well-known sensitive paths
                # (.git, .env, backups, debug endpoints). Safe (GET only, in scope),
                # but noisier than the default passive scan. Not related to Active Mode.
```

The `[disclosure]` table is strict (`extra="forbid"` via `_Section`), like every other
section.

### CLI — RF-10

`app.py`, `scan`:

```python
probe: Annotated[
    bool | None,
    typer.Option("--probe/--no-probe", help="Probe for well-known exposed paths (.git, .env, backups)."),
] = None,
```

`_build_config` gains `probe: bool | None`; when not `None` it becomes a
`disclosure={"probe": probe}` override (CLI wins over the file — RF-04). `--probe` does
**not** touch `[active]` or the Active-Mode gate (ADR-6).

`_render.py`, `summary()` — after the technologies line, before the finding list:

```python
exposed = [f for f in result.findings
           if f.check_id.startswith("disclosure.")
           and f.check_id not in ("disclosure.debug.error-page",
                                  "disclosure.listing.directory-index")]
if exposed:
    _console.print(f"[yellow]Information disclosure: {len(exposed)} exposed path(s) found[/]")
```

`list-checks` already iterates the registry, so all eight `disclosure.*` ids appear with
`DISCLOSURE` / `passive` / their default severity — no code change (RF-10).

### Reporters — RF-11

**No change.** `disclosure.*` findings flow through JSON (canonical), SARIF (one `rule` per
`check_id` from `result.findings` — the reporter already derives rules from findings, not
the registry), HTML, and Markdown exactly like any other finding. There is **no** new
report section and **no** new top-level array (contrast spec 004's `technologies`).
`webvigil report scan.json` re-renders offline unchanged (RF-11, spec 001 RF-24).

### Web API / Web UI — RF-12

**No change.** `disclosure.*` findings are ordinary `Finding`s; spec 002's `mapping.py`
already persists every finding losslessly (RF-19) and `GET /api/scans/{id}` returns them
(RF-25). The dashboard's existing findings list and `check_id` filter render and filter
them with no component edit. **No migration, no `dump-openapi.py`, no `pnpm gen:api`, no
`web` gate** (RNF-02).

## Data model

### `data/paths.toml` — RF-05

TOML (Resolved decision 9): an array of `[[entry]]` tables plus one `[backups]` table.
Shipped in the wheel via `pyproject.toml` `[tool.hatch.build.targets.wheel].artifacts +=
"src/webvigil/checks/disclosure/data/*.toml"`. Loaded with `tomllib` (stdlib). Never
downloaded; there is no refresh script — the list is curated by hand and changes only in a
commit.

### `ProbeHit` / `ProbeReport` — internal

Not serialised. `ProbeHit` → `Finding` mapping happens in `_ProbeFedCheck.run`. `ProbeReport`
is consumed entirely inside the orchestrator (`hits` → `ScanContext`, `warnings` →
`ScanResult.warnings`).

### `ScanResult`

**Unchanged.** `paths_probed` is deliberately **not** added as a field (ADR-7); the CLI
summary derives "N exposed" from findings, and the two RF-09 exceptional conditions (cap
hit, inconclusive calibration) ride `ScanResult.warnings`.

## Interfaces

### Check ids

| id | tier | category | mode | default severity | source |
|---|---|---|---|---|---|
| `disclosure.debug.error-page` | passive | `DISCLOSURE` | `passive` | `MEDIUM` | `ctx.pages` |
| `disclosure.listing.directory-index` | passive | `DISCLOSURE` | `passive` | `MEDIUM` | `ctx.pages` |
| `disclosure.vcs.exposed` | probe | `DISCLOSURE` | `passive` | `HIGH` | `probe_hits` (`vcs`) |
| `disclosure.config.dotenv-exposed` | probe | `DISCLOSURE` | `passive` | `HIGH` | `probe_hits` (`config`) |
| `disclosure.config.manifest-exposed` | probe | `DISCLOSURE` | `passive` | `LOW` | `probe_hits` (`manifest`) |
| `disclosure.backup.file-exposed` | probe | `DISCLOSURE` | `passive` | `MEDIUM` | `probe_hits` (`backup`) |
| `disclosure.debug.endpoint-exposed` | probe | `DISCLOSURE` | `passive` | `MEDIUM` | `probe_hits` (`debug`) |
| `disclosure.sourcemap.exposed` | probe | `DISCLOSURE` | `passive` | `MEDIUM` | `probe_hits` (`sourcemap`) |

### Config

| key | type | default | effect |
|---|---|---|---|
| `[disclosure] probe` | bool | `false` | run the probe pass (needs ≥1 probe-fed check enabled) |

CLI: `--probe / --no-probe` (unset → use config). No other new flag or command.

### `DisclosureProbe` constants (internal, documented)

| constant | value | requirement |
|---|---|---|
| `_REQUEST_CAP` | 150 | RF-09, RNF-07 |
| `_CALIBRATION_PATHS` | 3 | RF-06 |
| `_MAX_DERIVED_DIRS` | 10 | Resolved decision 6 |

## ADRs

### ADR-1 — Probe tier is an orchestrator pass; passive tier is ordinary checks
**Decision:** `DisclosureProbe` runs in `Orchestrator.run` (like `Fingerprinter`), producing
`ProbeHit`s the six probe-fed checks consume from `ScanContext`. `ErrorPageCheck` and
`DirectoryListingCheck` are plain checks reading `ctx.pages`.
**Alternatives:** (a) one mega-check that fetches + validates + emits everything; (b) every
family probes independently inside its own check.
**Why:** the catalogue sweep and the soft-404 calibration are expensive shared work that
must run **once**, not six times. A single mega-check can't give per-family `check_id`s for
SARIF rules / `[checks] disabled` granularity (RF-08, RF-10). The passive tier needs no
requests, so it needs no pass. This mirrors spec 004 ADR-1 exactly.
**Trade-off:** the orchestrator gains a second feature branch (`_probe_disclosure` beside
`_fingerprint`); "probing" is not itself a registry entry — its on/off is
`config.disclosure.probe` AND the union of the six probe-fed ids (ADR-2).

### ADR-2 — The probe pass runs iff `probe = true` AND a probe-fed check is selected
**Decision:** `_probe_disclosure` returns `()` unless `config.disclosure.probe` is true and
at least one of the six probe-fed `disclosure.*` checks is in the selected set.
**Alternatives:** run whenever `probe = true` regardless of disabled checks; a separate
`[disclosure] families = [...]` list.
**Why:** one flag plus the existing `disabled` list — no new config surface. Disabling every
probe-fed check is a full opt-out of the network cost, matching spec 004 ADR-3.
**Trade-off:** the same slightly-surprising coupling spec 004 has — disabling "checks" also
disables a crawl-like pass. Documented in `docs/information-disclosure.md` and the
docstrings.

### ADR-3 — Reuse `ScanContext.observations`, add `probe_hits`
**Decision:** extend spec 004's `Observations` with `probe_hits: tuple[ProbeHit, ...]` set
once by the orchestrator; the probe-fed checks read it.
**Alternatives:** a new `ScanContext` field; a second return value from `Check.run`; thread
hits through finding evidence.
**Why:** `Observations` is exactly this — "structured input a check needs beyond
`ctx.pages`". `Check.run`'s signature stays `-> list[Finding]`; every existing and
third-party check is untouched. Safe under `asyncio` (set before the checks run, read-only
during).
**Trade-off:** `Observations` now serves two features; its name stays generic so that is
fine. `core` gains a `TYPE_CHECKING` import of `ProbeHit` from `checks` (already done for
`HttpClient`); if that cycle is awkward, `ProbeHit` moves next to `Detection` in
`context.py`.

### ADR-4 — Curated catalogue as a TOML data file with a per-entry validator
**Decision:** `data/paths.toml` — `[[entry]]` tables (path, family, check id, severity,
title, description, validator, redaction) plus a `[backups]` basename × suffix table the
loader expands. Shipped in the wheel; loaded with `tomllib`.
**Alternatives:** JSON (like spec 004's `retirejs.json`); a hardcoded Python table; a plain
path list with validators in code.
**Why:** the list is small and hand-curated (unlike the generated Retire.js DB), so a
human-diffable format with comments and inline validators wins. TOML matches
`webvigil.example.toml` and the config model. `tomllib` is stdlib — no dependency.
**Trade-off:** two formats in the repo (`retirejs.json` + `paths.toml`); acceptable — they
have opposite authoring models (machine-refreshed vs hand-curated).

### ADR-5 — Soft-404 calibration + per-entry content validation
**Decision:** before probing, `GET` 3 random paths to learn the "not found" shape; a probe
response is a hit only if it is not that shape **and** its body passes the entry's
validator (content regex / content-type / JSON shape).
**Alternatives:** trust the status code; `HEAD` requests; fixed 404-body heuristics.
**Why:** SPAs and custom 404 handlers routinely return `200` with the app shell for every
path — a status-only check would be a false-positive machine (RNF-05). The validator makes
a `.git/config` hit mean "this really is a git config", not "this URL returned bytes".
**Trade-off:** 3 extra requests per scan when probing; when calibration is inconclusive the
pass leans entirely on the validators and warns (RF-09). The random paths make the *request
set* non-deterministic, but **not the findings** (RNF-04) — the validators are pure.

### ADR-6 — `probe` is a Safe-Mode opt-in, not Active-Mode-gated
**Decision:** `[disclosure] probe` / `--probe` is independent of `--mode` and
`--authorized-by`. `_enforce_active_gate` is untouched; there is no new `active`
sub-config.
**Alternatives:** require `--mode active --authorized-by`; make `--mode active` imply
`--probe`.
**Why:** Resolved decision 1/5 — the probe pass sends only in-scope `GET`s with no payloads
and no state change. The legal-attestation gate exists for payload-bearing Active checks
(spec 001 RF-15); applying it to a `GET /.git/config` would be theatre and would make
WebVigil's baseline weaker than every comparable scanner. Off-by-default keeps spec 001's
"Safe Mode is nearly invisible" promise for anyone who doesn't opt in.
**Trade-off:** a user who runs `--mode active` still has to add `--probe` to get path
probing; documented. When `probe` is on it becomes the most active thing Safe Mode does,
superseding spec 001 RNF-05's note about the CORS probe — `docs/` says so.

### ADR-7 — No `ScanResult.paths_probed`; derive the summary from findings
**Decision:** the CLI summary prints `"Information disclosure: N exposed path(s) found"`
where `N` is counted from `disclosure.*` probe-family findings. The catalogue size is a
documented constant, not reported per-scan. No new `ScanResult` field.
**Alternatives:** add `ScanResult.probe = ProbeStats(probed, exposed)`; append a
`"probed N paths"` line to `ScanResult.warnings` on every run.
**Why:** RF-12 keeps 005 engine-only with no new serialised surface; a new `ScanResult`
field would flow into the JSON canonical shape and invite an API/UI follow-on. "N exposed"
is the number a user acts on; "N probed" is trivia when the catalogue is fixed and
documented.
**Trade-off:** RF-10's example line ("Probed N well-known paths, M exposed") is delivered as
"M exposed" only. See Open questions — Ryan can opt into the fuller line + a tiny stats
field.

### ADR-8 — Source-map detection is `<script>.map` probing, no JS body parse
**Decision:** for each in-scope `<script src>` a crawled page references, `DisclosureProbe`
`GET`s `<script-url>.map` and validates it is a source map (`{"version": 3, ... "sources":
[...]}`). It does **not** fetch the script body to read a `//# sourceMappingURL=` comment.
**Alternatives:** fetch every referenced script, parse the `sourceMappingURL` comment,
follow it (RF-03's "referenced resource" reading); a dedicated non-probe fetch path.
**Why:** the `.map` is named after the script in the overwhelming majority of real builds,
so appending `.map` finds it without a second round-trip per script. Keeping all source-map
work inside the probe pass means one fetch budget (`_REQUEST_CAP`) and one code path.
**Trade-off:** a build that renames its map (`app.js` → `app.abc123.js.map` via the
comment) is missed, and source-map detection now requires `--probe` — a deviation from
RF-03, which implied a referenced map is always followed. Flagged in Open questions.

### ADR-9 — Redaction is mandatory, centralised, and applied before the `Finding`
**Decision:** `redaction.apply(strategy, body)` runs inside `DisclosureProbe` before a
`ProbeHit` is built; `ProbeHit.redacted_body` is the only body a check ever sees.
**Alternatives:** redact in the check; redact in the reporter; store raw + redact on
display.
**Why:** the `Finding` is persisted (spec 002) and rendered in four formats — the raw
secret must never get that far (RNF-06). Doing it once, at the source, means no reporter or
API path can leak it.
**Trade-off:** a real secret is unrecoverable from the report — intended; the finding proves
exposure by structure (keys present, file shape correct), not by quoting the value.

## Impact

- **New:** `src/webvigil/checks/disclosure/**` (8 modules + `data/paths.toml`),
  `docs/information-disclosure.md`.
- **`webvigil.core`:** `findings.py` (un-comment `DISCLOSURE`), `context.py`
  (`Observations.probe_hits`), `config.py` (`DisclosureSection`), `orchestrator.py`
  (`_probe_disclosure` branch + `ScanContext` wiring).
- **`webvigil.cli`:** `app.py` (`--probe/--no-probe`, `_build_config`), `_render.py`
  (summary line).
- **`webvigil.reporting`, `webvigil.api`, `web/`:** untouched (RF-11, RF-12).
- **`pyproject.toml`:** `[tool.hatch.build.targets.wheel].artifacts +=
  "src/webvigil/checks/disclosure/data/*.toml"`. No new dependency. `[tool.importlinter]`
  unchanged (`webvigil.checks` is already a `source_module`). `[tool.mypy]` already covers
  `src`.
- **`webvigil.example.toml`:** `[disclosure] probe = false` documented.
- **`tests/fixtures/app.py`:** the insecure profile serves `/.git/config`, `/.git/HEAD`,
  `/.env`, `/uploads/` (a generated index, linked from a page), `/boom` (a Werkzeug-style
  trace, linked), `/package.json`; the hardened profile 404s them and `/boom` returns a
  generic page.
- **CI:** no new job. The `quality` matrix picks up the new tests. **No `web` job impact**
  (nothing under `web/` changes).
- **Docs:** `docs/information-disclosure.md` (new), `docs/architecture.md` (DISCLOSURE
  layer note), `docs/writing-checks.md` (a note that a check may consume
  `ctx.observations` and that a pass may issue bounded `ctx.http` requests — the
  calibration pattern as the example), `README.md` (coverage table), `CLAUDE.md`
  (architecture summary + `[disclosure] probe`), `specs/README.md` (roadmap → in progress
  → done). `SECURITY.md` unchanged (passive, opt-in, GET-only).

## Risks

| Risk | Mitigation |
|---|---|
| Soft-404 calibration wrong → probe pass floods findings on a `200`-for-everything SPA. | Per-entry content validators (ADR-5): a hit must *structurally* be the file; a body matching the SPA hash is dropped; inconclusive calibration → validators only + warning (RF-09). Hardened-fixture test asserts zero `DISCLOSURE` findings with probing on. |
| Probing trips a WAF / rate-limit / alerts the target's ops. | Off by default (ADR-6); `_REQUEST_CAP = 150`; every request through the shared limiter (concurrency + delay); GET-only; a `403`/`429` storm just yields non-hits. Docs frame it as "noisier than the default scan". |
| Error-page regexes over-match (flag a blog post that quotes a stack trace). | Signatures key on framework *chrome* (Werkzeug console markup, ASP.NET yellow-screen table, PHP `<b>Fatal error</b>: … in … on line N`), not the words alone; `is_html` gate; de-dup per framework; hardened fixture returns a generic page → nothing. |
| A real secret leaks into a report or the DB via a `.env` / `actuator/env` hit. | `redaction.apply` runs at the source before the `ProbeHit` exists (ADR-9); `ProbeHit.redacted_body` is the only body a check sees; unit test asserts no known-secret substring survives into the `Finding`. |
| `secrets.token_hex` calibration paths make scans non-deterministic. | The random paths only calibrate the *negative*; validators are pure, so the **finding set** is deterministic (RNF-04). A test runs the same fixture twice and diffs findings + fingerprints. |
| Derived VCS probes at every discovered directory explode the request count. | `_MAX_DERIVED_DIRS = 10` distinct prefixes; all derived probes count against `_REQUEST_CAP`; cap hit → warning, not error (RF-09). |
| `paths.toml` not shipped in the wheel → probe pass is empty when pip-installed. | `hatch artifacts` glob + a test that imports `webvigil.checks.disclosure.catalogue` and asserts `load_catalogue()` is non-empty from the installed location. |
| `Observations` gaining `probe_hits` risks a `core → checks` import cycle. | `TYPE_CHECKING`-only import (as for `HttpClient`); fallback is to move `ProbeHit` beside `Detection` in `context.py` (ADR-3). `lint-imports` + `mypy` in the gate catch a real cycle. |
| Manifest exposure overlaps spec 004's fingerprinter. | 005 only reports the file (`disclosure.config.manifest-exposed`); it does not parse it or touch `ScanResult.technologies` (Resolved decision 3). The two features share no code. |

## Testing — RNF-02, RNF-05

- **Signatures (unit):** each `ErrorSignature` matches its sample body and **not** a
  generic error page; `is_directory_listing` true for Apache / nginx / `http.server`
  samples, false for a normal link list.
- **Passive checks (unit):** `make_context` with hand-built `Page`s →
  `ErrorPageCheck` emits `HIGH` for the Werkzeug console, `MEDIUM` for a plain trace, one
  finding per framework; `DirectoryListingCheck` emits one per listed URL; hardened pages →
  nothing.
- **`catalogue.py` (unit):** `load_catalogue()` parses `paths.toml`, expands the backup
  cross-product, every `content` regex compiles, every entry's `check` is a registered id.
- **`redaction.py` (unit):** `dotenv` keeps keys and masks values; `json-env` keeps
  property names and masks `value`; `generic` masks long tokens / PEM blocks; no strategy
  lets a crafted `AKIA…` / 40-char hex through.
- **`DisclosureProbe` (unit, `pytest-httpx`):**
  - clean `404` calibration → a validated `/.git/config` `200` is a hit; a random `200`
    with SPA body is not.
  - SPA calibration (`200` everywhere, one body) → only content-validated responses hit.
  - inconclusive calibration → warning emitted, validators still applied.
  - `> _REQUEST_CAP` derived probes → list truncated + warning.
  - a `.map` for a referenced in-scope `<script>` that is a valid source map → `sourcemap`
    hit; an out-of-scope `<script>` → not requested.
  - `.git/` `403` with a forbidden body → `vcs` hit at `MEDIUM` confidence.
- **Probe-fed checks (unit):** `ctx.observations.probe_hits` seeded directly → each check
  emits only its family's hits, severity from the hit, `dedup_key = path`, redacted body in
  evidence.
- **Orchestrator:** `probe = false` → `DisclosureProbe` never constructed
  (`http.stats.requests` = crawl only); `probe = true` but all six probe-fed checks
  disabled → same; `probe = true` + checks enabled → `probe_hits` populated, findings
  emitted, RF-09 warnings surfaced.
- **Config / CLI:** `[disclosure] probe` round-trips; an unknown `[disclosure]` key is a
  hard error; `--probe` overrides a `false` file value and `--no-probe` overrides `true`;
  `--probe` does not trip the Active-Mode gate.
- **Integration (fixture app):**
  - insecure + `probe=true` → `disclosure.vcs.exposed`, `disclosure.config.dotenv-exposed`,
    `disclosure.config.manifest-exposed`, `disclosure.listing.directory-index`,
    `disclosure.debug.error-page` all present with expected ids/severities; the `.env`
    finding's evidence contains **no** raw secret value.
  - insecure + `probe=false` → only `disclosure.debug.error-page` and
    `disclosure.listing.directory-index` (the linked/crawled ones); no probe finding.
  - hardened (probe on **or** off) → **zero** `DISCLOSURE` findings (RF-13).
  - the same insecure scan run twice → identical findings + fingerprints (RNF-04).
- **Reporters:** a `ScanResult` with `disclosure.*` findings → SARIF has one `rule` per id,
  HTML/MD group them by severity, JSON round-trips through `load_result`; **no**
  "technologies"-style section is added.
- **`list-checks`:** all eight `disclosure.*` ids listed with `DISCLOSURE` / `passive`.
- **Packaging:** import `webvigil.checks.disclosure.catalogue` and load the catalogue from
  the installed path (not repo-relative).
- **Gate:** `/qualidade-python` (`ruff → black → mypy → pytest`) + `uv run lint-imports`
  green. **No `web` gate** — nothing under `web/` changes.

## Implementation notes

Resolved during implementation (2026-09-06):

1. **Soft-404 length band** — the ±15 % body-length heuristic (ADR-5) only applies to
   calibration bodies of **≥256 bytes**; below that, a short real file (`/.git/config`,
   `/package.json`) is too easily "close" to a short 404 page, so `looks_missing` relies on
   the SPA-shell hash and the status-code match alone. The content validator is the real
   guard.
2. **`_Soft404.looks_missing`** — treats a response as "not found" when its body hashes to a
   known SPA shell, or its status matches a calibration status that is ≥400, or (2xx-SPA
   case) its length is within the band of a calibration length.
3. **`ProbeHit.path`** is the **URL path** (`/app/.git/config`), not the catalogue
   `entry.path` (`.git/config`), so `dedup_key` distinguishes the same file found at
   different directory prefixes (RF-07). The finding title is `f"{hit.title} at {hit.path}"`.
4. **`redaction.py`** ships four strategies: `dotenv` (regex per line, keep key + comments),
   `json-env` (recursive scrub — mask any key named `value`/`password`/`secret`/`token`/…
   and any high-entropy leaf string), `generic` (`_SECRET_RE` over the first 1 KB — AWS /
   GitHub / Slack / JWT / PEM / long base64 / long hex), `none` (first 1 KB, structure
   kept). All outputs are length-bounded (≤2 KB) before `EvidenceItem.of` caps them again.
5. **`ProbeHit` lives in `webvigil.checks.disclosure.probe`**, imported into `context.py`
   under `TYPE_CHECKING` only — no `core → checks` runtime edge, `lint-imports` unchanged.
   The move-to-`context.py` fallback from ADR-3 was not needed.
6. **Catalogue** — `paths.toml` shipped ~78 base entries (vcs 8, config 13, manifest 9,
   debug 12) + a `[backups]` table (`6 basenames × 6 suffixes = 36`), so `load_catalogue()`
   returns ~114; the probe adds host-label backups and derived probes at scan time.
   `Validator` also supports a `magic` (byte-prefix) check for binary backups —
   not in the requirements draft but needed for `.zip` / `.sql.gz` / `.svn/wc.db`.
7. **`_render.summary`** prints `"Information disclosure: N exposed path(s) found"` counting
   `disclosure.*` findings that are **not** `error-page` / `directory-index` (ADR-7). No
   `ScanResult` field was added; the RF-09 cap / calibration warnings ride
   `ScanResult.warnings`.
8. **No `web` work** — as designed (RF-12), `webvigil.reporting`, `webvigil.api`, and `web/`
   were not touched; the SARIF reporter already derives one rule per `check_id` from the
   findings, so the eight `disclosure.*` ids appear there for free.

## Resolved during design

Confirmed with Ryan on 2026-09-06:

1. **"N probed" in the CLI summary (ADR-7):** ship **"M exposed path(s)"** only — no new
   `ScanResult` field. The catalogue size is documented and fixed.
2. **Source-map detection (ADR-8):** `<script-url>.map` probing only; a `sourceMappingURL`
   comment that points at a renamed `.map` is a documented miss, and source-map detection
   requires `--probe`. Accepted deviation from RF-03.
3. **`_REQUEST_CAP` = 150** (catalogue ~110 + derived ~40). A hard ceiling, not a target;
   only reached on large multi-directory sites.
4. **Debug-endpoint catalogue:** ship Apache `server-status` / `server-info`, Spring
   `actuator` / `actuator/env` / `actuator/health` / `actuator/mappings`, Symfony
   `_profiler`, ASP.NET `elmah.axd` / `trace.axd`, plus `phpinfo.php` / `info.php`. Grow it
   in later commits, not this spec.

## Open questions

None. Ready for `/spec tasks`.
