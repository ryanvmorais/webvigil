---
feature: Dependency fingerprinting — passive client-side library detection + known-vulnerability matching
status: done
date: 2026-09-06
related: [004-deps-fingerprint/requirements.md, 001-foundation/design.md, 002-web-api/design.md, 003-web-ui/design.md]
origin: conception
---

# 004 — Dependency fingerprinting — Design

Traceability: every component and decision cites its requirement (`— RF-NN` / `— RNF-NN`).
Requirements: [requirements.md](requirements.md).

## Overview

004 adds a **passive fingerprinting pass** to the engine and two **DEPS checks** that turn
its output into findings. The pass runs after the crawl, reads the HTML the crawler already
fetched, pulls the in-scope script resources those pages reference, and identifies JS
libraries + versions using rules from a **vendored Retire.js database**. Each detection is
matched against that same database's advisory entries; matches become
`deps.js.vulnerable-library` findings.

Every detection — vulnerable or not — is collected into a **technology inventory** on the
`ScanResult`, which flows through the four reporters, the Web API's persistence, and the
dashboard's scan-detail screen.

```
Orchestrator.run
  ├─ crawl (unchanged) ─────────────► pages: tuple[Page]
  ├─ Fingerprinter(http).scan(pages) ► detections     [only if a DEPS check is selected]  — RF-01..03
  │      │  parse <script>/<link>, fetch in-scope resources (bounded), apply DB rules
  │      ▼
  │   ScanContext.observations  ◄── checks append Technology + warnings here              — ADR-2
  ├─ run checks concurrently
  │      deps.js.vulnerable-library ─ match detections via AdvisoryProvider ─► Findings   — RF-06..09
  │      deps.js.library-detected   ─ INFO for version-undetermined detections            — RF-10
  ▼
ScanResult{ findings, technologies, warnings, ... }   — RF-12
  └─► reporters (JSON/SARIF/HTML/MD)                  — RF-13, RF-14
  └─► webvigil.api: scan.technologies JSON column ──► GET /api/scans/{id} ──► dashboard    — RF-17, RF-18
```

Engine purity is preserved (RNF-01): the new code lives in `webvigil.checks.deps` and
`webvigil.core`, imports only the stdlib + `selectolax` (already a dependency), and the
`import-linter` contract is unchanged (no new forbidden package, no new engine top-level
package). The only network reach to Retire.js is `scripts/update-retirejs-db.py` (RF-21).

## Module layout

```
src/webvigil/checks/deps/
├── __init__.py            # registers the two checks
├── fingerprint.py         # Fingerprinter: pages (+ http) -> list[Detection]              — RF-01..05
├── rules.py               # RetireJsRules: parse the vendored DB into compiled matchers   — RF-05, RF-06
├── advisories.py          # AdvisoryProvider protocol, Advisory, RetireJsProvider, match  — RF-07, RF-08, RF-11
├── check.py               # VulnerableLibraryCheck, LibraryDetectedCheck                  — RF-09, RF-10, RF-15
├── staleness.py           # provenance parsing + "DB is N days old" warning               — RF-22
└── data/
    ├── retirejs.json      # vendored community DB (normalised)                             — RF-06
    └── PROVENANCE.json    # { source_url, upstream_commit, upstream_etag, retrieved }      — RF-06, RNF-06

src/webvigil/core/
├── technology.py          # Technology model (+ DetectionMethod enum)                      — RF-12
├── result.py              # ScanResult gains `technologies: tuple[Technology, ...]`        — RF-12
├── context.py             # ScanContext gains `observations: Observations`                 — ADR-2
├── findings.py            # Category.DEPS is un-commented                                   — RF-09
└── orchestrator.py        # run the Fingerprinter; drain observations onto the result

src/webvigil/reporting/    # html.py, markdown.py: a "Detected technologies" section        — RF-13
src/webvigil/cli/_render.py# scan summary gains the "N libraries (M vulnerable)" line       — RF-16
src/webvigil/api/
├── db.py                  # Scan.technologies JSON column                                  — RF-17
├── mapping.py             # store/rebuild technologies                                     — RF-17
├── schemas.py             # ScanOut.technologies: list[TechnologyOut]                      — RF-17
└── migrations/versions/0002_scan_technologies.py                                           — RF-17

web/src/
├── components/technologies-table.tsx    # the new section                                  — RF-18
├── app/(app)/scans/[id]/page.tsx        # render it under the header                        — RF-18
└── lib/api-types.ts                     # regenerated from openapi.json                     — RF-18

scripts/update-retirejs-db.py            # maintainer refresh (network lives here only)      — RF-21
tests/fixtures/app.py                    # insecure profile serves a vulnerable library      — RF-19
```

## Components

### Technology model — RF-12

`webvigil/core/technology.py` — pure data, no imports beyond `pydantic` + `enum`:

```python
class DetectionMethod(StrEnum):
    HASH = "hash"            # exact sha1 of a fetched in-scope file       -> Confidence.HIGH
    SRI = "sri"              # integrity="sha384-..." matches a known hash -> Confidence.HIGH
    FILENAME = "filename"    # version captured from the resource filename -> Confidence.MEDIUM
    FILECONTENT = "filecontent"  # version from a banner/comment in a body -> Confidence.MEDIUM
    URI = "uri"              # library (rarely version) from the URL path  -> Confidence.LOW

class Technology(BaseModel):
    model_config = ConfigDict(frozen=True)
    name: str                       # Retire.js component name, e.g. "jquery"
    version: str | None             # None when recognised but unversioned (RF-10)
    detection: DetectionMethod
    source_url: str                 # a representative URL the library was seen at
    vulnerable: bool = False        # True iff a deps.js.vulnerable-library finding was raised
    advisories: tuple[str, ...] = ()  # advisory identifiers, when vulnerable
```

`ScanResult` gains `technologies: tuple[Technology, ...] = ()` (frozen model, so the JSON
reporter and `load_result` pick it up for free — RF-13, RF-14). Ordering is `(name, version
or "")` ascending, deduplicated on `(name, version)` (RNF-04).

### Detection — internal

`fingerprint.py` works in an internal `Detection` dataclass (not serialised); the check maps
surviving detections to `Technology`:

```python
@dataclass(frozen=True, slots=True)
class Detection:
    name: str
    version: str | None
    method: DetectionMethod
    source_url: str
    marker: str          # the raw filename / banner line / hash that matched -> evidence
```

### Fingerprinter — RF-01, RF-02, RF-03, RF-04, RF-05

```python
class Fingerprinter:
    def __init__(self, http: HttpClient, rules: RetireJsRules, *, max_fetches: int = 50): ...
    async def scan(self, pages: Sequence[Page]) -> list[Detection]: ...
```

1. **Collect resource references.** For every `page` in `pages` with `page.is_html`, parse
   `page.text` with `selectolax` and collect: `<script src>`, `<link href>` (rel
   stylesheet/preload), each element's `integrity` value, and the text of inline
   `<script>` blocks (no `src`). URLs are resolved against `page.url`.
2. **Classify each referenced URL** with the scope guard already on `http`:
   - **in scope** and not already a crawled `Page` → queued for a bounded GET (RF-03).
   - **out of scope** (CDN) → not fetched; URL + any SRI hash only (RF-03).
3. **Fetch** the in-scope queue through `http.get(url)`, honouring the existing concurrency
   cap + per-host delay. Stop at `max_fetches`; a truncated queue appends a warning
   `"dependency fingerprinting stopped at N resource fetches"` (RNF-07). Fetch failures are
   swallowed (best-effort, like `sitemap.xml`).
4. **Apply rules** (`RetireJsRules.identify`) to, per source: the URL, the SRI hash, the
   response body (`filecontent` + `hashes`), and inline `<script>` text (`filecontent`
   only).
5. **Deduplicate** to one `Detection` per `(name, version)`, preferring the
   higher-confidence method and a concrete version over `None` (RF-04). Returns the list.

`selectolax` is already used by the crawler — no new dependency (RNF-01). Inline-script
scanning covers the common "bundled vendored copy" case where the banner survives
minification.

### RetireJsRules — RF-05, RF-06

`rules.py` loads `data/retirejs.json` once (`functools.lru_cache`) and compiles it:

```python
class RetireJsRules:
    @classmethod
    def load(cls, path: Path = _VENDORED) -> "RetireJsRules": ...
    def identify(self, *, url: str | None, body: str | None,
                 sri_hash: str | None) -> list[Detection]: ...
    def advisories_for(self, name: str, version: str) -> list[Advisory]: ...   # used by the provider
```

- The vendored file keeps the upstream **`jsrepository` shape**: a map of component name →
  `{ extractors: { uri, filename, filecontent, hashes }, vulnerabilities: [...] }`.
  `extractors.filename` / `filecontent` / `uri` are regex templates with a `§§version§§`
  placeholder that WebVigil substitutes with a capturing version group at compile time.
  `extractors.hashes` maps a SHA-1 hex digest → exact version.
- WebVigil applies **only** what the file expresses. Non-`<script>` rules the DB carries
  (e.g. Bootstrap CSS `filecontent` rules) are honoured as-is; WebVigil adds no rules of its
  own (Resolved decision 9).
- A malformed or missing vendored file raises `ConfigError` at load — it is shipped in the
  package, so this only fires on a broken build.

### AdvisoryProvider and RetireJsProvider — RF-07, RF-08, RF-11

`advisories.py`:

```python
class Advisory(BaseModel):
    model_config = ConfigDict(frozen=True)
    identifiers: tuple[str, ...]     # ("CVE-2020-11022", "GHSA-gxr4-xjj5-5px2")
    summary: str
    severity: Severity               # mapped from the advisory's "severity" string
    severity_from_upstream: bool     # False when the DB entry had no severity (RF-08)
    first_safe_version: str | None   # lowest fixed boundary above the detected version
    info_urls: tuple[str, ...]
    cwe: tuple[int, ...]

class AdvisoryProvider(Protocol):
    def match(self, name: str, version: str) -> list[Advisory]: ...

class RetireJsProvider:
    def __init__(self, rules: RetireJsRules): ...
    def match(self, name: str, version: str) -> list[Advisory]:
        # evaluate each vulnerability's atOrAbove / below range against `version`
        # using packaging.version.parse (already an indirect dep) with a loose fallback
```

- **Range semantics (RF-07):** an entry matches when
  `(atOrAbove is None or v >= atOrAbove) and (below is None or v < below)`, plus the
  upstream `atOrAbove`/`below` `.x` shorthands. `first_safe_version` is the smallest `below`
  among matched entries (or the smallest `atOrAbove` of a *later* entry, when the DB models
  the fix that way).
- **Severity mapping (RF-08):** `low/medium/high/critical` → `Severity.LOW/MEDIUM/HIGH/CRITICAL`;
  absent → `Severity.MEDIUM` with `severity_from_upstream = False`.
- **No network.** `RetireJsProvider` reads only the compiled rules. An online provider
  (OSV) is a future spec — it implements the same `match` signature and nothing in
  `fingerprint.py` / `check.py` changes ([[osv-provider-deferred]]).
- **Version parsing:** `packaging` ships with `setuptools`/`pip` context but is not a
  guaranteed runtime dep — **decision deferred to implementation**: either add `packaging`
  to the base deps (tiny, ubiquitous) or vendor a ~30-line PEP 440-ish comparator. Leaning
  `packaging`.

### The checks — RF-09, RF-10, RF-15

Both live in `check.py`, share a module-level `_provider()` (lru-cached
`RetireJsProvider(RetireJsRules.load())`), and both read `ctx.observations` — neither issues
HTTP itself; the Fingerprinter already ran (see orchestrator wiring).

```python
@register
class VulnerableLibraryCheck(Check):
    id = "deps.js.vulnerable-library"
    name = "Vulnerable JavaScript library"
    category = Category.DEPS
    mode = ScanMode.PASSIVE
    default_severity = Severity.MEDIUM

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for det in ctx.observations.detections:
            if det.version is None:
                continue
            advisories = _provider().match(det.name, det.version)
            if not advisories:
                ctx.observations.add_technology(Technology(**_tech(det), vulnerable=False))
                continue
            top = max(advisories, key=lambda a: a.severity)
            ids = tuple(i for a in advisories for i in a.identifiers)
            ctx.observations.add_technology(
                Technology(**_tech(det), vulnerable=True, advisories=ids)
            )
            findings.append(self.finding(
                title=f"{det.name} {det.version} has known vulnerabilities",
                description=_describe(advisories),
                remediation=_remediation(det.name, advisories),
                severity=top.severity,
                confidence=_confidence(det.method),
                location=Location(url=det.source_url),
                dedup_key=f"{det.name}@{det.version}",
                evidence=[
                    EvidenceItem.of("Detection", f"{det.method}: {det.marker}"),
                    EvidenceItem.of("Advisories", "\n".join(ids)),
                ],
            ))
        return findings
```

```python
@register
class LibraryDetectedCheck(Check):
    id = "deps.js.library-detected"
    name = "JavaScript library detected (version undetermined)"
    category = Category.DEPS
    mode = ScanMode.PASSIVE
    default_severity = Severity.INFO

    async def run(self, ctx: ScanContext) -> list[Finding]:
        out = []
        for det in ctx.observations.detections:
            if det.version is not None:
                continue
            ctx.observations.add_technology(Technology(**_tech(det), vulnerable=False))
            out.append(self.finding(
                title=f"{det.name} detected, version undetermined",
                description="WebVigil recognised this library but could not read its "
                            "version, so it could not be checked against known "
                            "vulnerabilities.",
                remediation="Confirm the library version and keep it current.",
                confidence=Confidence.LOW,
                location=Location(url=det.source_url),
                dedup_key=f"{det.name}@?",
                evidence=[EvidenceItem.of("Detection", f"{det.method}: {det.marker}")],
            ))
        return out
```

- `cwe`/`references` on `VulnerableLibraryCheck` are **per-finding** (from the matched
  advisories), so the class-level `cwe`/`references` stay empty and `self.finding` is called
  and then `model_copy(update=...)` adds them — or the check builds the `Finding` directly.
  Small detail, deferred to implementation.
- **Disabling** either id works through the normal `[checks] disabled` path. If **both** are
  disabled, no DEPS check is selected, so the orchestrator skips the Fingerprinter entirely
  — zero extra requests, empty inventory (RF-15, ADR-3).
- The two checks both call `add_technology`; `Observations` deduplicates on `(name,
  version)` so the inventory has one entry per library regardless of which check saw it.

### ScanContext.observations — ADR-2

`context.py` gains one field on the (still-frozen) `ScanContext`:

```python
@dataclass(slots=True)
class Observations:
    """A side channel for structured output a check produces besides its findings."""
    detections: tuple[Detection, ...] = ()          # set once by the orchestrator
    _tech: dict[tuple[str, str | None], Technology] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def add_technology(self, tech: Technology) -> None:
        self._tech.setdefault((tech.name, tech.version), tech)

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    @property
    def technologies(self) -> tuple[Technology, ...]:
        return tuple(sorted(self._tech.values(), key=lambda t: (t.name, t.version or "")))
```

`ScanContext` holds `observations: Observations = field(default_factory=Observations)` —
mutable, shared by reference across the concurrently-run checks. `add_technology` /
`add_warning` are called only from synchronous check code between `await`s, so the plain
`dict`/`list` are safe under `asyncio` (single-threaded event loop). This is the **only**
new check-facing engine surface in 004.

### Orchestrator wiring

`Orchestrator.run`, after building `pages` and selecting `check_types`:

```python
selected = self._select_checks(warnings)
deps_selected = any(c.category is Category.DEPS for c in selected)
detections: tuple[Detection, ...] = ()
if deps_selected:
    rules = RetireJsRules.load()
    detections = tuple(await Fingerprinter(http, rules).scan(pages))
    warnings.extend(staleness_warning(rules))          # RF-22

context = ScanContext(..., observations=Observations(detections=detections))
findings, errors = await self._run_checks(selected, context)
warnings.extend(context.observations.warnings)

result = ScanResult(
    metadata=...,
    findings=deduped,
    technologies=context.observations.technologies,
    errors=tuple(errors),
    warnings=tuple(warnings),
)
```

Import note: `orchestrator.py` already imports from `webvigil.checks`, so importing the
Fingerprinter/rules from `webvigil.checks.deps` adds no new dependency direction.

### Reporters — RF-13, RF-14

- **JSON:** automatic — `technologies` is a `ScanResult` field; `load_result` is its inverse
  (RF-14). No code change.
- **SARIF:** no special-casing. `deps.js.vulnerable-library` becomes one `rule` like any
  check; `references[0]` (an advisory URL) is its `helpUri`; the finding fingerprint is the
  `partialFingerprint`. The inventory is **not** in SARIF (SARIF is a findings format).
- **Markdown / HTML:** a "Detected technologies" section before "Findings" when
  `result.technologies` is non-empty — a table of `name`, `version | "unknown"`, `detection`,
  and a `vulnerable` marker (text, not colour only — RNF-05 of spec 003 style). HTML reuses
  the existing severity-token CSS.

### CLI — RF-15, RF-16

`_render.py`'s terminal summary gains, when `result.technologies`:

```
Detected 7 client-side libraries (2 with known vulnerabilities)
```

`list-checks` already iterates the registry, so both new ids appear with `DEPS` / `passive`
/ their default severity — no code change (RF-15).

### Staleness warning — RF-22

`staleness.py`:

```python
STALE_AFTER_DAYS = 90

def staleness_warning(rules: RetireJsRules) -> list[str]:
    age = (date.today() - rules.provenance.retrieved).days
    if age > STALE_AFTER_DAYS:
        return [f"dependency advisory data is {age} days old; "
                f"run scripts/update-retirejs-db.py"]
    return []
```

- Surfaced as a **scan warning** (RF-22) — it rides the existing `ScanResult.warnings`,
  which the CLI, JSON/HTML/MD reports, and the API already show.
- `webvigil version` also calls `staleness_warning` and prints it to stderr.
- CI: the `quality` job runs `pytest`; a test asserts the provenance date parses and, if it
  is stale, emits a `warnings.warn` that CI surfaces but does not fail on. No new gate.

### Web API amendment — RF-17

Traces to **spec 002 RF-19** (lossless persistence) and **RF-25** (schema). Additive,
display-only, no execution/auth/queue change.

- `db.py`: `Scan` gains
  `technologies: list[dict] = Field(default_factory=list, sa_column=Column(JSON))`
  — same pattern as `warnings` / `check_errors`.
- `migrations/versions/0002_scan_technologies.py`: `op.add_column("scan",
  sa.Column("technologies", sa.JSON(), nullable=True))` inside `batch_alter_table`;
  `downgrade` drops it. The metadata-diff test from spec 002 covers it.
- `mapping.py`: `store_result` writes `[t.model_dump() for t in result.technologies]`;
  `rows_to_result` rebuilds `tuple(Technology(**t) for t in scan.technologies)` so reports
  regenerated from the DB include the section (RF-14).
- `schemas.py`: `ScanOut` gains `technologies: list[TechnologyOut]` (name, version,
  detection, source_url, vulnerable, advisories). It is on the **detail** payload only, not
  `ScanSummary`.
- `scripts/dump-openapi.py` + `pnpm gen:api` regenerate `web/openapi.json` +
  `api-types.ts`; the spec-003 CI drift check guards them.

No new endpoint — the inventory rides `GET /api/scans/{id}` (ADR-4).

### Web UI amendment — RF-18

Traces to **spec 003 RF-20/RF-22**. One new component, one screen edit.

- `web/src/components/technologies-table.tsx` — `TechnologiesTable({ items })`: a `<section>`
  with an `<h2>Detected technologies</h2>` and a `<table>` (library, version or "unknown",
  detection method, and a "Vulnerable" `<SeverityBadge>`-style tag that is a link to
  `?check_id=deps.js.vulnerable-library` on the same page). Hidden when `items` is empty.
- `scans/[id]/page.tsx` — render `<TechnologiesTable items={s.technologies} />` between the
  metadata `<dl>` and the "Findings" `<section>`.
- Covered by a component test (`renderWithClient`, MSW `ScanOut` fixture with a vulnerable
  and a clean entry) and included in the existing `jest-axe` assertion for the screen
  (RNF-05 of spec 003).
- The Playwright flow (spec 003 RNF-04) gains one assertion: after the fixture scan reaches
  `completed`, the "Detected technologies" section lists the vulnerable library seeded in
  RF-19.

## Data model

### Vendored `data/retirejs.json` — RF-06

Normalised subset of the upstream `jsrepository` file:

```json
{
  "$provenance": { "note": "see PROVENANCE.json" },
  "jquery": {
    "extractors": {
      "filename": ["jquery-(§§version§§)(\\.min)?\\.js"],
      "filecontent": ["/\\*!? jQuery v(§§version§§)"],
      "hashes": { "5c9d15e5f8...": "1.12.4" },
      "uri": ["/jquery/(§§version§§)/"]
    },
    "vulnerabilities": [
      {
        "atOrAbove": "1.0.0", "below": "3.5.0",
        "severity": "medium",
        "identifiers": {
          "summary": "Cross-site scripting via jQuery.htmlPrefilter",
          "CVE": ["CVE-2020-11022", "CVE-2020-11023"],
          "githubID": "GHSA-gxr4-xjj5-5px2"
        },
        "info": ["https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"],
        "cwe": ["CWE-79"]
      }
    ]
  }
}
```

- `§§version§§` → `([0-9][0-9.a-z\-]*)` at compile time (the upstream convention).
- WebVigil stores the file **as retrieved and normalised** by `update-retirejs-db.py`; it is
  not hand-edited.

### `data/PROVENANCE.json` — RF-06, RNF-06

```json
{
  "source_url": "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-master.json",
  "upstream_commit": "a1b2c3d4",
  "upstream_etag": "W/\"...\"",
  "retrieved": "2026-09-06",
  "license": "Apache-2.0",
  "attribution": "Retire.js contributors — https://github.com/RetireJS/retire.js"
}
```

`NOTICE` (new, repo root) records the Apache-2.0 bundle (RNF-06).

### `Technology` on the wire (`TechnologyOut`)

```
{ name: "jquery", version: "1.12.4", detection: "filename",
  source_url: "https://target/static/jquery-1.12.4.min.js",
  vulnerable: true, advisories: ["CVE-2020-11022", "CVE-2020-11023", "GHSA-gxr4-xjj5-5px2"] }
```

### DB

| Table | Change |
|---|---|
| `scan` | `+ technologies JSON NULL` (migration `0002`) — list of the object above |

## Interfaces

### Check ids

| id | category | mode | default severity | emits |
|---|---|---|---|---|
| `deps.js.vulnerable-library` | `DEPS` | `passive` | `MEDIUM` (per-finding from advisory) | one finding per vulnerable `(lib, version)` |
| `deps.js.library-detected` | `DEPS` | `passive` | `INFO` | one finding per recognised-but-unversioned library |

### Config

No new config keys. `[checks] disabled` accepts the two ids. `max_pages` does **not** bound
resource fetches; the internal `Fingerprinter(max_fetches=50)` constant does (ADR-5) —
**deferred to implementation:** whether to expose it as `[scan] max_resource_fetches`
(leaning no — keep the surface small).

### CLI

No new commands or flags. Behaviour changes: the `scan` summary line (RF-16), `list-checks`
rows (RF-15), and `version` staleness note (RF-22).

### `scripts/update-retirejs-db.py` — RF-21

```
python scripts/update-retirejs-db.py [--source URL] [--dry-run]
```

- GETs the upstream `jsrepository-master.json` (the community file), validates it parses,
  normalises it (drop upstream fields WebVigil never reads; keep `extractors` +
  `vulnerabilities`), writes `data/retirejs.json` + refreshes `data/PROVENANCE.json`.
- Uses `urllib.request` (stdlib) — no `httpx` here, so the script has zero extra deps and is
  obviously outside the engine.
- Prints a diff summary (`N components, +X / -Y vulnerabilities`). `--dry-run` writes
  nothing.
- Documented in `docs/dependency-fingerprinting.md`.

### Web API

`GET /api/scans/{id}` → `ScanOut` gains `technologies: TechnologyOut[]` (empty list for
scans run before 004 or with the checks disabled). Every other endpoint is unchanged.

## ADRs

### ADR-1 — Fingerprinting is an orchestrator pass, not a check
**Decision:** the `Fingerprinter` runs in `Orchestrator.run` (like the crawler), producing
`Detection`s that the DEPS checks consume from `ScanContext`. The checks do the advisory
matching and emit findings; they issue no HTTP.
**Alternatives:** (a) a single check that fetches + detects + matches internally; (b) extend
the `Check` contract to return structured observations alongside findings.
**Why:** the fingerprint result must land on `ScanResult.technologies` (RF-12), which a
check — contractually `-> list[Finding]` — cannot populate. Running the pass once in the
orchestrator also means the two DEPS checks share one set of fetches. Keeping detection out
of the check keeps the check unit-testable with hand-built `Detection`s (RF-20).
**Trade-off:** the orchestrator grows a feature-specific branch (`if deps_selected`), and
"fingerprinting" is not itself a registry entry — its on/off is the union of the two check
ids (ADR-3).

### ADR-2 — `ScanContext.observations` side channel
**Decision:** add a mutable `Observations` object to `ScanContext` so a check can record
`Technology` entries and `warnings` in addition to returning findings. The orchestrator
drains it onto the `ScanResult`.
**Alternatives:** a second return value from `Check.run`; a global; thread the inventory
back through the finding evidence and reconstruct it in the orchestrator.
**Why:** minimal, explicit, and confined — 004 is the only user. `Check.run`'s signature is
unchanged, so every existing check and third-party check is untouched. Safe under `asyncio`
(single thread, mutation only in sync sections).
**Trade-off:** `ScanContext` is no longer purely read-only; a check *could* misuse the
channel. Documented in `writing-checks.md` as "advanced, opt-in".

### ADR-3 — No separate "fingerprinting" toggle; it follows the DEPS checks
**Decision:** the Fingerprinter runs iff at least one `Category.DEPS` check is in the
selected set. Disabling both ids disables the pass and its network cost.
**Alternatives:** an always-on pass; a dedicated `[scan] fingerprint = true|false`.
**Why:** one obvious control (the existing `disabled` list), no new config, and the
expensive part (resource fetches) is opt-out. An always-on pass would add requests to every
scan including `--fail-on`-gated CI runs that don't want them.
**Trade-off:** a slightly surprising coupling — disabling a "check" also disables a crawl-like
pass. Called out in `docs/` and the check docstrings.

### ADR-4 — The inventory rides `GET /api/scans/{id}`, no new endpoint
**Decision:** `ScanOut.technologies`, populated from a `scan.technologies` JSON column.
**Alternatives:** `GET /api/scans/{id}/technologies` sub-resource (parallel to `/findings`).
**Why:** the inventory is small (tens of rows), always wanted with the detail view, and not
independently filterable — unlike findings (spec 002 RF-13). One fewer route, one fewer
query key in the UI.
**Trade-off:** a large inventory would bloat the detail payload; acceptable at this scale.

### ADR-5 — Bounded resource fetching, best-effort
**Decision:** the Fingerprinter fetches at most `max_fetches = 50` distinct in-scope
resources; fetch errors are swallowed; the cap emits a scan warning.
**Alternatives:** fetch everything; tie the bound to `max_pages`.
**Why:** matches the "good neighbour" ethos (spec 001 RF-03) and the sitemap parser's
best-effort stance. 50 covers real sites; a script-heavy page can't multiply request volume
without bound (RNF-07).
**Trade-off:** a huge site could have an un-fingerprinted library past the cap; the warning
makes that visible.

### ADR-6 — Vendored DB, offline matching, provider seam for later
**Decision:** ship a normalised Retire.js DB in the package; match against it with
`RetireJsProvider`; define `AdvisoryProvider` so an online provider can be added without
touching detection or the checks.
**Alternatives:** query OSV.dev / GitHub Advisories at scan time.
**Why:** Resolved decision 1 — keep the engine fully offline and CI non-flaky. The seam
keeps the online option cheap to add later ([[osv-provider-deferred]]).
**Trade-off:** the DB goes stale between refreshes; RF-22's warning and the provenance
header make the age visible, and `update-retirejs-db.py` is a one-command refresh.

### ADR-7 — Reuse `selectolax`; no HTML-parsing or version-parsing heavy deps
**Decision:** parse resource references with `selectolax` (already used by the crawler).
For version comparison, add `packaging` to the base dependencies (or vendor a tiny
comparator — implementation call).
**Alternatives:** regex the HTML; add `beautifulsoup4`; add `semver`.
**Why:** no new HTML dep; `packaging` is ~one file of value, ubiquitous, and pure-Python.
**Trade-off:** one new small base dependency (if `packaging` is chosen); the `import-linter`
"engine" contract already allows it (it only forbids UI/DB packages).

### ADR-8 — `Technology` lives in `webvigil.core`, not `webvigil.checks.deps`
**Decision:** the model is in `webvigil/core/technology.py`.
**Alternatives:** keep it in the checks package.
**Why:** `ScanResult` (core) references it, and `webvigil.reporting` renders it — both would
then import from `webvigil.checks`, a direction that currently does not exist.
**Trade-off:** `core` carries a model only the DEPS feature produces (as it already carries
`Finding` fields some checks never set).

## Impact

- **New:** `src/webvigil/checks/deps/**` (incl. `data/retirejs.json`, `data/PROVENANCE.json`),
  `src/webvigil/core/technology.py`, `scripts/update-retirejs-db.py`, `NOTICE`,
  `docs/dependency-fingerprinting.md`,
  `src/webvigil/api/migrations/versions/0002_scan_technologies.py`,
  `web/src/components/technologies-table.tsx` (+ its test).
- **`webvigil.core`:** `result.py` (+1 field), `context.py` (+`Observations`), `findings.py`
  (un-comment `DEPS`), `orchestrator.py` (fingerprint branch + drain).
- **`webvigil.reporting`:** `html.py`, `markdown.py` (technologies section). JSON/SARIF
  unchanged.
- **`webvigil.cli`:** `_render.py` summary line; `version` staleness note.
- **`webvigil.api`:** `db.py`, `mapping.py`, `schemas.py`, migration `0002`;
  `web/openapi.json` regenerated.
- **`web/`:** the new component, `scans/[id]/page.tsx`, `api-types.ts` regenerated, one
  Playwright assertion, one component test.
- **`pyproject.toml`:** `package-data` / `include` for `webvigil/checks/deps/data/*.json`
  (so it ships in the wheel); possibly `packaging` in `[project.dependencies]` (ADR-7).
  `[tool.importlinter]` unchanged. `[tool.mypy]` already covers `src`.
- **`tests/fixtures/app.py`:** the insecure profile serves a vulnerable library + its file
  (RF-19); a matching hardened-profile assertion.
- **CI:** no new job. The `quality` matrix picks up the new tests; the `web` job picks up the
  regenerated `api-types.ts` (drift check) and the extra Playwright assertion.
- **Docs:** `docs/dependency-fingerprinting.md` (new), `docs/architecture.md` (a DEPS layer
  note), `README.md` (check list + the new doc link), `CLAUDE.md` (architecture summary +
  the `update-retirejs-db.py` command), `specs/README.md` (roadmap → in progress → done),
  `SECURITY.md` (no change — passive, safe).

## Risks

| Risk | Mitigation |
|---|---|
| False positives from loose `filecontent` regexes (wrong lib or version). | Confidence tiering (RNF-05): `filecontent`/`filename` are `MEDIUM`, `uri` `LOW`; the hardened-fixture test asserts zero DEPS findings; version-uncertain → no vuln finding (RF-10). |
| Fetching in-scope scripts adds load / trips a WAF. | Bounded (`max_fetches`), rate-limited by the existing limiter, GET-only, opt-out by disabling both checks (ADR-3, ADR-5). |
| `ScanContext.observations` mutated from concurrent check tasks. | Single-threaded event loop; `add_*` only run in sync sections between `await`s; `setdefault` dedup is idempotent. A test runs both DEPS checks concurrently and asserts a stable inventory. |
| Vendored DB drifts from upstream shape on a future refresh. | `update-retirejs-db.py` validates + normalises; `RetireJsRules.load` raises `ConfigError` on a shape it can't compile; a test loads the real vendored file and compiles every rule. |
| `§§version§§` / range-shorthand parsing bugs vs. Retire.js semantics. | `advisories.py` unit tests with crafted entries covering `atOrAbove` only, `below` only, both, `.x` shorthand, and pre-release versions; cross-check a handful against the upstream `retire` CLI output during design. |
| Bundled/minified libraries with the banner stripped are missed. | Documented limitation; `hashes` extractor still catches exact vendored copies; inline-`<script>` scanning catches many bundles. Not a correctness bug — coverage. |
| Shipping `data/*.json` in the wheel is forgotten. | `pyproject.toml` `package-data` + a test that imports `webvigil.checks.deps` and loads the DB from the installed location (not a repo-relative path). |
| Stale DB gives users false confidence. | RF-22 warning in every scan + `webvigil version`; `PROVENANCE.json` date; docs tell maintainers to refresh before a release. |
| DB column added but old scans have `NULL`. | `mapping.rows_to_result` and `ScanOut` treat `None` as `[]`; the UI hides the empty section. |

## Testing — RNF-02, RNF-05

- **Rules:** load the real vendored `retirejs.json`; assert every `extractor` compiles and
  every `vulnerability` range parses. A small fixture DB (`tests/data/retirejs-mini.json`)
  for the logic tests.
- **Fingerprinter:** hand-built `Page`s →
  - `<script src="/static/jquery-1.12.4.min.js">` → `filename` detection, version `1.12.4`.
  - inline `<script>/*! jQuery v3.4.1 */…` → `filecontent` detection.
  - `<script src integrity="sha384-…">` where the hash is in `hashes` → `sri`, exact version.
  - CDN `<script src="https://code.jquery.com/jquery-3.4.1.min.js">` → detected from URL,
    **not fetched** (assert `http.stats.requests` unchanged for that URL).
  - > `max_fetches` in-scope resources → queue truncated + warning emitted.
- **AdvisoryProvider:** `match("jquery", "1.12.4")` → the CVE-2020-11022 advisory;
  `match("jquery", "3.6.0")` → none; severity mapping incl. missing severity; `first_safe_version`.
- **Checks (unit):** `ctx.observations.detections` seeded directly →
  `VulnerableLibraryCheck` emits the finding with the right severity/evidence/dedup;
  `LibraryDetectedCheck` emits INFO only for `version is None`; both populate the inventory;
  running both concurrently yields one inventory entry per library.
- **Orchestrator:** DEPS checks disabled → Fingerprinter not run (`http.stats.requests`
  reflects crawl only), `result.technologies == ()`. Enabled → inventory populated,
  `vulnerable` flags correct.
- **Integration (fixture app):** scan the **insecure** profile → `deps.js.vulnerable-library`
  present with the expected identifiers and a `technologies` entry `vulnerable=true`; scan
  the **hardened** profile → **zero** `DEPS` findings (RF-19).
- **Reporters:** HTML + Markdown contain the "Detected technologies" section with the
  vulnerable row marked; JSON round-trips `technologies` through `load_result` (RF-14);
  SARIF has the `deps.js.vulnerable-library` rule.
- **Staleness:** a provenance date > 90 days old → warning in `ScanResult.warnings` and from
  `webvigil version`; a fresh date → no warning.
- **API:** `store_result` → `rows_to_result` round-trips `technologies`; `GET /api/scans/{id}`
  returns them; migration `0002` `upgrade`/`downgrade` on a tmp DB + metadata-diff; a scan
  created before the column reads back as `[]`.
- **Web:** `TechnologiesTable` renders vulnerable + clean rows, hides when empty, no serious
  axe violations; the Playwright flow asserts the section after the fixture scan.
- **Gate:** `/qualidade-python` + `uv run lint-imports` green; the `web` gate green
  (`pnpm lint / format:check / typecheck / test / build`, `api-types.ts` drift, Playwright).

## Implementation notes

Resolved during implementation (2026-09-06):

1. **Version comparison** — `packaging` was added to `[project.dependencies]`; a loose
   numeric-tuple fallback (`numeric_version_key`) handles the non-PEP-440 versions the
   Retire.js data carries (ADR-7).
2. **`cwe`/`references` on `deps.js.vulnerable-library`** — the check builds the finding with
   `self.finding(...)` then `model_copy(update={"cwe": …, "references": …})` for the
   per-advisory values.
3. **`max_fetches`** — kept as an internal constant (`Fingerprinter(max_fetches=50)`); no
   config key.
4. **Upstream file** — `jsrepository-master.json` (community). `update-retirejs-db.py`
   normalises it: keeps `filename` / `filecontent` / `uri` / `hashes` extractors, drops the
   browser-only `func` and `filecontentreplace`; flattens `identifiers` to a string list
   (CVE + GHSA, else a `RETID-*` fallback) and moves reference URLs to `info`. Retire.js
   regexes that use JavaScript-only constructs (variable-width look-behind) are skipped at
   compile time rather than failing the load.
5. **SRI detection** — not implemented: the Retire.js DB stores SHA-1 file hashes, which do
   not match an SRI `sha384-…` attribute. `RetireJsRules.identify(url, body)` covers URL,
   filename, content banner, and exact file-hash (`HASH`) detection; `DetectionMethod.SRI`
   stays in the enum for a future provider. `Fingerprinter` is
   `Fingerprinter(http, target, rules)` (it needs the `Target` for the scope check).
6. **HTML report placement** — the "Detected technologies" table sits directly after the
   severity-summary table, before the findings.

## Open questions

None.
