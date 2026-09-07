---
feature: OSV.dev online advisory provider — opt-in known-vulnerability lookup for the dependency fingerprint
status: done
date: 2026-09-07
related:
  - 004-deps-fingerprint/design.md
  - 001-foundation/design.md
origin: conception
---

# 010 — OSV.dev online advisory provider — design

> Design note: [OSV.dev without an API key](../../docs/notes/osv-without-a-key.md).

## Overview

Spec 004's advisory matching is a two-part shape: the `Fingerprinter` orchestrator pass
produces `Detection(name, version, …)` records, and the `deps.js.vulnerable-library` check
turns each into a finding by calling `AdvisoryProvider.match(name, version) -> list[Advisory]`.
004 ships one provider — `RetireJsProvider`, over the vendored file, synchronous, no I/O.

This spec adds a **second advisory source, OSV.dev**, without disturbing that shape:

1. A new orchestrator pass, `_osv_lookup`, runs **right after** `_fingerprint` when
   `[deps] osv_online` is on and a `DEPS` check is selected. It hands the version-known
   detections to `OsvProvider`, which does **one** `POST /v1/querybatch` to find which
   packages have any advisory, then **one `POST /v1/query` per matched package** for the
   full records, normalises them to WebVigil's existing `Advisory` dataclass, and returns a
   `(name, version) -> tuple[Advisory, …]` map plus any warnings.
2. That map rides `Observations.osv_advisories` into the `ScanContext`.
3. `VulnerableLibraryCheck.run` merges, per detection, the advisories from
   `RetireJsProvider.match(...)` with `ctx.observations.osv_advisories.get((name, version))`,
   de-duplicating by shared identifier. Everything downstream — severity roll-up, dedup
   key, fingerprint, evidence, the inventory, all four reporters — is unchanged.

`AdvisoryProvider.match` stays **synchronous** (Resolved decision 3): the async network
work happens in the orchestrator pass, exactly like the fingerprint fetch pass, and the
check still sees a plain in-memory lookup.

With the flag **off**, none of this runs: no new pass, no new egress, byte-for-byte the
004 behaviour.

```
Orchestrator.run
  ├─ crawl
  ├─ _fingerprint         → detections: tuple[Detection]            [004]
  ├─ _osv_lookup          → osv_advisories: dict[(name,ver), (Advisory,…)]   [010, this spec]
  │     └─ OsvProvider.lookup(versioned_detections)
  │           POST {base_url}/v1/querybatch   (1 request — which packages have vulns?)
  │           POST {base_url}/v1/query        (1 per matched package — full records)
  │           normalise → Advisory ; memoise per (ecosystem,name,version)
  ├─ _probe_disclosure / _inject / _inject_stored                  [005/006/008]
  ├─ ScanContext(observations=Observations(detections=…, osv_advisories=…))
  └─ _run_checks
        └─ VulnerableLibraryCheck.run
              advisories = merge_advisories(
                  RetireJsProvider.match(name, version),          # offline floor
                  ctx.observations.osv_advisories.get((name,version), ()),  # online, opt-in
              )
```

## Module layout

| Path | Change | What |
|---|---|---|
| `src/webvigil/checks/deps/osv.py` | **new** (~200 lines) | `OsvProvider`, `OsvResult`, the npm-name map, the OSV-record → `Advisory` normaliser, the CVSS-base-score band helper. |
| `src/webvigil/checks/deps/advisories.py` | edit | add `merge_advisories(*groups) -> list[Advisory]` (identifier-intersection coalescing) — native to the `Advisory` type, reused by the check. |
| `src/webvigil/checks/deps/check.py` | edit | `VulnerableLibraryCheck.run` merges the OSV advisories from `ctx.observations` before shaping the finding. No new field on the finding. |
| `src/webvigil/core/context.py` | edit | `Observations` gains `osv_advisories: Mapping[tuple[str, str], tuple[Advisory, ...]] = {}` (typed via a `TYPE_CHECKING` import of `Advisory`, like `probe_hits` / `injection_hits`). |
| `src/webvigil/core/config.py` | edit | new `DepsSection` (`osv_online: bool`, `timeout_s: float`, `base_url: str`); wire onto `ScanConfig`; extend `with_overrides` docstring. |
| `src/webvigil/core/orchestrator.py` | edit | import `OsvProvider`; add `_osv_lookup`; call it after `_fingerprint`; pass the map into `Observations`. |
| `src/webvigil/cli/app.py` | edit | `--osv-online/--no-osv-online` option; `osv_online` param on `_build_config`; `deps` override dict; pass `osv_online` to `_emit`. |
| `src/webvigil/cli/_render.py` | edit | `summary(..., osv_online: bool = False)` prints an "advisory sources" line when it is on and a technology inventory exists. |
| `webvigil.example.toml` | edit | a `[deps]` block with `osv_online = false` + the two knobs, commented. |
| `docs/dependency-fingerprinting.md` | edit | an "OSV.dev online provider" section. |
| `README.md`, `CLAUDE.md`, `specs/README.md` | edit | coverage row / layer-3 paragraph / roadmap. |

No file under `src/webvigil/api/` or `web/` changes (Resolved decision 5).

## Data model

### `DepsSection` (new, in `core/config.py`)

```python
class DepsSection(_Section):
    """Dependency-fingerprint tuning (spec 004 / spec 010).

    ``osv_online`` is the only opt-in that makes the engine reach a host other than the
    target: with it on, detected npm library names + versions are sent to ``base_url``
    (OSV.dev) for a known-vulnerability lookup. Off by default; see
    docs/dependency-fingerprinting.md.
    """

    osv_online: bool = False
    osv_timeout_s: float = 10.0
    osv_base_url: str = "https://api.osv.dev"
```

`ScanConfig` gains `deps: DepsSection = DepsSection()`. `with_overrides` already deep-merges
any named section, so only the docstring's section list needs the word `deps`.

### `Observations.osv_advisories`

```python
# in Observations (dataclass, slots)
osv_advisories: Mapping[tuple[str, str], tuple[Advisory, ...]] = field(default_factory=dict)
```

Filled once by the orchestrator (empty dict when the pass does not run). Keyed by
`(detection.name, detection.version)` — the WebVigil library name, **not** the npm name, so
the check looks it up with the same key it already has. Read-only during the check run.

### `OsvResult` (new, in `deps/osv.py`)

```python
@dataclass(frozen=True, slots=True)
class OsvResult:
    advisories: dict[tuple[str, str], tuple[Advisory, ...]]  # (webvigil name, version) -> advisories
    warnings: tuple[str, ...] = ()
```

### `Advisory` — reused unchanged

The 004 dataclass already carries everything OSV needs to express:
`identifiers`, `summary`, `severity`, `severity_from_upstream`, `first_safe_version`,
`info_urls`, `cwe`. No new field.

## Components

### `OsvProvider` (`deps/osv.py`)

```python
_ECOSYSTEM = "npm"
_QUERYBATCH_CAP = 1000

class OsvProvider:
    def __init__(
        self,
        base_url: str,
        timeout_s: float,
        *,
        user_agent: str,
        transport: httpx.AsyncBaseTransport | None = None,  # tests inject a MockTransport
    ) -> None: ...

    async def lookup(self, detections: Sequence[Detection]) -> OsvResult:
        # 1. distinct (name, version), version is not None  -> in-scan memoisation (decision 4)
        # 2. map each name -> npm package name (_npm_name)
        # 3. POST /v1/querybatch  {queries: [{package:{name,ecosystem}, version}, ...]}
        #    chunked at _QUERYBATCH_CAP (never hit in practice)
        # 4. for each query whose result has >=1 vuln id:
        #       POST /v1/query {package:{name,ecosystem}, version}   -> {"vulns": [<record>, ...]}
        # 5. normalise every record -> Advisory ; group back under the webvigil (name, version) key
        # 6. return OsvResult(advisories=..., warnings=...)
        #
        # httpx.AsyncClient(base_url=base_url, timeout=timeout_s,
        #                   headers={"user-agent": user_agent}, transport=transport)
        # any httpx.HTTPError / json / schema error -> raise OsvLookupError(reason)
```

`OsvLookupError` is caught in the orchestrator (never propagates out of the pass). Partial
batch failure (some `/v1/query` calls fail after a good `querybatch`) → keep what
succeeded, add a warning naming the count.

### npm-name mapping (`_npm_name`)

Most Retire.js component names are already the npm package name. A small **curated dict**
covers the ones that differ; anything else passes through verbatim (RF-05). Seed set,
validated in a unit test against the vendored DB's component names:

```python
_NPM_NAME = {
    "angularjs": "angular",        # Retire "angularjs" == npm "angular" (1.x line)
    "jquery.ui": "jquery-ui",
    "jquery-ui-dialog": "jquery-ui",
    "mustache.js": "mustache",
    "handlebars.js": "handlebars",
    "prototypejs": "prototype",
    "dojo": "dojo",
    "ember": "ember-source",
    "ckeditor": "ckeditor4",
    "tinymce": "tinymce",
    # …extended during implementation from the vendored component list
}
```

An unmapped name that OSV does not recognise just yields no OSV advisories for that
detection — the Retire.js match still stands, no warning per name (RF-05).

### OSV record → `Advisory` (`_to_advisory`)

| `Advisory` field | Source in the OSV record |
|---|---|
| `identifiers` | `[record["id"], *record.get("aliases", [])]`, de-duped, order-stable (OSV id first). |
| `summary` | `record["summary"]`; else first sentence of `record["details"]` truncated to ~200 chars; else `""`. |
| `severity` | `_severity(record)` — see below. |
| `severity_from_upstream` | `True` when `_severity` found a real rating, `False` on the `MEDIUM` fallback. |
| `first_safe_version` | lowest `fixed` version across `affected[]` entries whose `package` matches `(npm, name)`, that is `> detected version` (reuse `_lt` / `numeric_version_key` from `advisories.py`); `None` if the record lists only `last_affected` / no fix. |
| `info_urls` | `[r["url"] for r in record.get("references", [])]` de-duped, plus `https://osv.dev/vulnerability/{id}`. |
| `cwe` | numeric ids parsed from `record["database_specific"]["cwe_ids"]` (`"CWE-79"` → `79`) when present, else `()`. |

### severity mapping (`_severity`, RF-07)

1. `database_specific.severity` (GHSA style) — `LOW→LOW`, `MODERATE`/`MEDIUM→MEDIUM`,
   `HIGH→HIGH`, `CRITICAL→CRITICAL`.
2. else the first `severity[]` entry of type `CVSS_V3` (or `CVSS_V4`) — parse the vector,
   compute the **base score**, band it: `0.1–3.9→LOW`, `4.0–6.9→MEDIUM`, `7.0–8.9→HIGH`,
   `9.0–10.0→CRITICAL`. The CVSS 3.0/3.1 base formula is a ~50-line pure function
   (`_cvss3_base`), deterministic, no dependency. CVSS v2 / unparseable vector → step 3.
3. else `Severity.MEDIUM`, `severity_from_upstream = False` (matches 004's
   `_DEFAULT_SEVERITY`; the finding's `_advisory_lines` already annotates
   "[severity not supplied upstream]").

### `merge_advisories` (`advisories.py`, RF-08)

```python
def merge_advisories(*groups: Iterable[Advisory]) -> list[Advisory]:
    """Coalesce advisories that share any identifier; union their data, keep the top severity."""
    buckets: list[list[Advisory]] = []
    for adv in itertools.chain.from_iterable(groups):
        ids = set(adv.identifiers)
        hit = next((b for b in buckets if ids & {i for a in b for i in a.identifiers}), None)
        if hit is None:
            buckets.append([adv])
        else:
            hit.append(adv)
    return [_coalesce(b) for b in buckets]   # deterministic: input order preserved
```

`_coalesce(bucket)`:
- `identifiers` = first-seen order across the bucket, de-duped.
- `severity` = `max(a.severity for a in bucket)`; `severity_from_upstream = any(...)`.
- `first_safe_version` = the **highest** non-null `first_safe_version` in the bucket
  (`numeric_version_key`) — the safe upgrade must clear every source's range.
- `summary` = first non-empty; if two differ, `" / ".join` the distinct ones.
- `info_urls`, `cwe` = union, order-stable.

Single-source detections (only Retire.js, or only OSV) pass through `_coalesce` as a
one-element bucket — a no-op beyond returning the advisory unchanged.

### `VulnerableLibraryCheck.run` change

```python
osv_map = ctx.observations.osv_advisories
for detection in ctx.observations.detections:
    if detection.version is None:
        continue
    advisories = merge_advisories(
        provider.match(detection.name, detection.version),
        osv_map.get((detection.name, detection.version), ()),
    )
    if not advisories:
        ctx.observations.add_technology(_technology(detection, vulnerable=False))
        continue
    ...  # unchanged from here: identifiers, add_technology(vulnerable=True), self._finding(...)
```

`_provider()` (the `lru_cache`d `RetireJsProvider`) is untouched. `LibraryDetectedCheck`
(version-undetermined) is untouched — OSV is never queried for a null version (RF-10 of 004
stands).

### orchestrator `_osv_lookup`

```python
async def _osv_lookup(
    self,
    check_types: Sequence[type[Check]],
    detections: tuple[Detection, ...],
    warnings: list[str],
) -> dict[tuple[str, str], tuple[Advisory, ...]]:
    """Query OSV.dev for the detected libraries when [deps] osv_online is on (RF-01, RF-09)."""
    if not self._config.deps.osv_online:
        return {}
    if not any(c.category is Category.DEPS for c in check_types):
        return {}
    versioned = tuple(d for d in detections if d.version is not None)
    if not versioned:
        return {}
    try:
        result = await OsvProvider(
            self._config.deps.osv_base_url,
            self._config.deps.osv_timeout_s,
            user_agent=self._config.http.user_agent,
        ).lookup(versioned)
    except OsvLookupError as exc:
        warnings.append(
            f"OSV.dev lookup failed: {exc}; reported advisories are from the offline "
            "database only"
        )
        return {}
    warnings.extend(result.warnings)
    return result.advisories
```

Call site in `run()`, immediately after the `_fingerprint` line:

```python
detections = await self._fingerprint(check_types, http, target, pages, warnings)
osv_advisories = await self._osv_lookup(check_types, detections, warnings)
...
observations=Observations(
    detections=detections,
    osv_advisories=osv_advisories,
    probe_hits=probe_hits,
    injection_hits=injection_hits + stored_hits,
),
```

### CLI

- `--osv-online/--no-osv-online` (tri-state `bool | None`, default `None`), help text:
  `"Look up detected libraries against OSV.dev (sends library names + versions to
  api.osv.dev). Off by default."`
- `_build_config(..., osv_online: bool | None)` → `deps_overrides["osv_online"] = osv_online`
  when not `None`; `config = base.with_overrides(..., deps=deps_overrides)`.
- `_emit(result, ..., osv_online=cfg.deps.osv_online)` → `_render.summary(result,
  cookie_count=..., osv_online=osv_online)`.
- `_render.summary`: after the "Detected N client-side libraries" line, when
  `osv_online and result.technologies`, print
  `"[dim]Advisory sources: offline database + OSV.dev[/]"`. (A failed lookup already shows
  the RF-09 warning in the warnings block.)

## Interfaces — OSV.dev

Base URL `https://api.osv.dev` (overridable via `[deps] osv_base_url` for tests). No auth.

### `POST /v1/querybatch`

Request:
```json
{ "queries": [
  { "package": { "name": "jquery", "ecosystem": "npm" }, "version": "3.4.1" },
  { "package": { "name": "lodash", "ecosystem": "npm" }, "version": "4.17.21" }
] }
```
Response (results are position-aligned to `queries`):
```json
{ "results": [
  { "vulns": [ { "id": "GHSA-gxr4-xjj5-5px2", "modified": "2023-..." },
               { "id": "GHSA-jpcq-cgw6-v4j6", "modified": "2023-..." } ] },
  {}
] }
```
An empty object / missing `vulns` / `[]` ⇒ that package is clean, no follow-up.

### `POST /v1/query` (one per package that had ≥1 id)

Request: `{ "package": { "name": "jquery", "ecosystem": "npm" }, "version": "3.4.1" }`
Response: `{ "vulns": [ <full OSV record>, … ] }` — server-side version-filtered, so every
record returned actually affects the queried version (RNF-05). Each record has `id`,
`aliases`, `summary`, `details`, `severity[]`, `affected[]` (`package`, `ranges[].events[]`
with `introduced` / `fixed`), `references[]`, `database_specific`.

`querybatch` `next_page_token` on a per-query result (many vulns) → follow once, bounded;
in practice a client library has a handful of advisories.

## ADRs

### ADR-1 — Augment the offline provider, never replace it

**Decision.** With `--osv-online` on, OSV advisories are **merged with** the Retire.js
results per detection (`merge_advisories`). The vendored DB is always consulted.

**Alternatives.** (a) OSV replaces Retire.js when the flag is on. (b) A provider chain that
stops at the first hit.

**Why.** The offline DB is the reliable floor — it works with no network and is what CI
depends on. A transient OSV outage must never *lose* coverage; it can only fail to *add*
some. Merging also gives the richer of two descriptions for a shared CVE.

**Trade-off.** A CVE covered by both sources is coalesced (identifier intersection), so the
merge logic has to be correct and deterministic; that is the cost of `merge_advisories` and
its tests. Ryan confirmed augment (Resolved decision 1).

### ADR-2 — A new orchestrator pass, not an async provider protocol

**Decision.** Keep `AdvisoryProvider.match` synchronous. Do the network work in
`Orchestrator._osv_lookup` (mirroring `_fingerprint`), and hand the check a pre-populated
`(name, version) -> advisories` map on `Observations`.

**Alternatives.** (a) Make the `AdvisoryProvider` protocol `async` and give the check an
`await provider.match(...)`; `RetireJsProvider.match` becomes a trivial `async def`.
(b) Run OSV lookups lazily from inside the check via `asyncio` from sync code.

**Why.** The orchestrator already owns every "gather structured observations before checks
run" pass (fingerprint, probe, inject). One batched call there is the natural fit, keeps
all egress decisions in one file, and leaves `RetireJsProvider`, the `Protocol`, and every
existing test untouched. The check stays a pure sync transform of observations.

**Trade-off.** `Observations` grows a field and the check reads two sources instead of one.
The `AdvisoryProvider` seam is now "sync `match` for offline data; batch pass for online" —
a future online provider follows the OSV pattern, not a plug into `match`. Acceptable: the
seam's real value (the `Advisory` shape + the check not caring about the source) holds.
Ryan confirmed the sync/pass approach (Resolved decision 3).

### ADR-3 — `querybatch` to filter, then `/v1/query` per matched package

**Decision.** One `POST /v1/querybatch` for all detections, then one `POST /v1/query` for
each package that came back with ≥1 vulnerability id.

**Alternatives.** (a) `POST /v1/query` for every detection directly (skip querybatch) —
full records in one step, but N requests even when everything is clean. (b) `querybatch`
then `GET /v1/vulns/{id}` per id — simplest per call, but M requests for M advisories on
one package.

**Why.** The common case is "a handful of libraries, none or one vulnerable". `querybatch`
answers "which of these matter?" in a single round trip; most scans then do **zero or one**
follow-up. Per-package `/v1/query` returns all of a package's records at once and is
version-filtered server-side. Ryan confirmed (Resolved decision 2).

**Trade-off.** Two endpoint shapes to model and mock instead of one. Bounded and covered by
RNF-06.

### ADR-4 — Its own `httpx.AsyncClient`, outside the scope guard

**Decision.** `OsvProvider` builds a private `httpx.AsyncClient(base_url=…)` with an
injectable `transport`. It does **not** use the scan's `HttpClient`.

**Alternatives.** (a) Add an `allow_host` escape hatch to `HttpClient` / `ScopeGuard` and
route OSV through it. (b) A stdlib `urllib.request` call like `scripts/update-retirejs-db.py`.

**Why.** `HttpClient` is deliberately target-scoped — cookies (spec 007), the rate limiter,
the redirect policy, the scope guard all assume "the target". Punching a hole in it for a
third party is exactly the coupling the guard exists to prevent. A separate client keeps
"the target-scoped client only ever talks to the target" literally true (RF-10), and
`httpx` (already a dependency) gives async + a clean `MockTransport` seam for tests, which
`urllib` does not.

**Trade-off.** Retries / timeout / UA are re-specified in one small place instead of
inherited. Minimal — one `AsyncClient` construction with `timeout=` and a UA header.

### ADR-5 — Compute the CVSS base score in-tree; default `MEDIUM` otherwise

**Decision.** Prefer `database_specific.severity`; else parse a CVSS v3 vector and band its
base score with a ~50-line pure `_cvss3_base`; else `Severity.MEDIUM` with
`severity_from_upstream=False`.

**Alternatives.** (a) Add the `cvss` PyPI package. (b) `database_specific.severity` only,
default everything else. (c) Map straight from the vector's textual severity if present.

**Why.** No new dependency (RNF-01). GHSA-sourced OSV records — the bulk of npm advisories
— carry `database_specific.severity` and never reach the formula. Pure-CVE records often
carry only the vector; the v3.0/v3.1 base formula is fixed, public, and deterministic, so
an in-tree function is safe and testable. Unparseable (CVSS v2, malformed, v4-only for
now) degrades exactly like 004's missing-severity case, which the UI already handles.

**Trade-off.** ~50 lines of arithmetic to carry and unit-test. Contained in `osv.py`.

### ADR-6 — New `[deps]` config section

**Decision.** A dedicated `DepsSection` (`osv_online`, `osv_timeout_s`, `osv_base_url`).

**Alternatives.** Fold `osv_online` into `[checks]` or `[http]`.

**Why.** Matches the per-feature convention already in the file (`[disclosure]`,
`[injection]`), keeps the OSV knobs discoverable together, and leaves a home for a future
provider or for surfacing 004's existing fetch cap. Ryan confirmed (Resolved decision 7).

**Trade-off.** A section with one meaningful switch today. The `[injection]` section
started the same way.

### ADR-7 — Engine + CLI only; no `ScanResult` field

**Decision.** No change to `webvigil.api`, `web/`, the reporters, or `ScanResult`. The
"OSV was consulted" note is a CLI-summary line derived from `cfg.deps.osv_online`, not from
the result.

**Alternatives.** Add `ScanResult.advisory_sources` / a per-finding `source` field and
render it everywhere.

**Why.** 008's precedent — a self-contained engine feature that flows through existing
finding/inventory plumbing needs no schema change. The OSV origin is already visible in a
finding via its `https://osv.dev/vulnerability/{id}` reference URL. Ryan confirmed
(Resolved decisions 5, and RF-14).

**Trade-off.** Re-rendering a saved JSON cannot say "OSV ran" — but it never could say
"Retire.js ran" either; the advisories themselves are in the JSON. Acceptable.

### ADR-8 — In-scan memoisation only, no persistent cache

**Decision.** De-duplicate `(ecosystem, name, version)` within a single `lookup` call; no
disk cache, no cross-scan reuse, no bypass flag.

**Alternatives.** A per-user cache dir with a TTL (the original RF-11).

**Why.** A disk cache brings location, TTL, invalidation, corruption, and concurrency
questions for a feature whose whole point is *freshness*. One `querybatch` + a few
`/v1/query` calls per scan is cheap. Ryan confirmed (Resolved decision 4); cross-scan
caching is a clean follow-up if scan volume ever makes it worth it.

**Trade-off.** Every opted-in scan pays one round trip even when re-run seconds later.
Bounded by RNF-06 and the timeout.

### ADR-9 — Ecosystem is always `npm`

**Decision.** Every OSV query uses `"ecosystem": "npm"`.

**Alternatives.** Try `npm` then fall back to an unscoped OSV query (`{"name": …,
"version": …}` with no ecosystem).

**Why.** 004 fingerprints **client-side JavaScript** libraries only; those are npm
packages. An unscoped query invites cross-ecosystem name collisions (`jquery` the npm
package vs. a same-named package elsewhere) and false positives. Scoping to `npm` is the
precise statement of what we detected.

**Trade-off.** A library published only outside npm gets no OSV match. Out of 004's scope
anyway.

## Impact

- **Backward compatible.** Flag off ⇒ identical behaviour, identical output, no new
  requests. All existing `deps.*` tests pass unchanged.
- **New egress, gated.** Flag on ⇒ requests to exactly one host (`osv_base_url`), carrying
  only `{name, ecosystem, version}` triples. Documented in `--help` and the docs
  (RNF-02, RNF-07).
- **`Observations` shape.** One new optional field, default empty — safe for every existing
  construction site (only the orchestrator builds `Observations` with args).
- **CLI surface.** One new option, one new summary line.
- **Config surface.** One new section; `webvigil.toml` files without it are unaffected
  (`DepsSection()` default). The Web API's passthrough `[web]` handling is unchanged; a
  `[deps]` table in a shared `webvigil.toml` is simply read by the engine and ignored by
  `webvigil.api`'s strict `WebConfig` — same as `[injection]` today.
- **Determinism.** Given fixed OSV responses, identical findings/inventory/fingerprints
  (RNF-04). `merge_advisories` and `_coalesce` preserve input order; identifier and URL
  lists are de-duped order-stably.

## Risks

| Risk | Mitigation |
|---|---|
| OSV schema drift (fields renamed, `database_specific` shape varies by source) | Normaliser reads defensively (`.get`, type guards); any `KeyError`/`TypeError` in a single record → skip that record + a warning, never crash the pass. Recorded-payload unit tests pin the shapes we rely on. |
| CVSS formula bugs | `_cvss3_base` unit-tested against the spec's published vector→score examples; on any parse failure it degrades to the `MEDIUM` default rather than guessing. |
| npm-name mismatch → silent misses | Curated map seeded from the vendored component list; a unit test enumerates 004's components and asserts each maps to a plausible npm name or is deliberately passthrough. Misses are non-fatal (Retire.js still matches). |
| OSV slow / flaky in CI | The feature is opt-in and off in every existing test except the dedicated integration test, which uses a `MockTransport`. No real network call in the suite (RF-16). |
| A huge inventory → many `/v1/query` calls | Bounded by 004's 50-resource fetch cap → ≤50 detections → ≤50 follow-up calls, only for packages with a hit. Timeout (RF-02) caps wall-clock; partial failure degrades per RF-09. |
| `merge_advisories` wrongly coalescing distinct CVEs | Coalescing requires a **shared identifier**; distinct CVEs with disjoint alias sets stay separate. Unit-tested with a shared-CVE pair and a disjoint pair. |
| User expects OSV to run without `--mode active` | It is not an Active feature — it runs in Safe Mode like the rest of 004. Documented; no gate needed (it sends no payload to the target). |

## Testing

| Layer | File | Cases |
|---|---|---|
| unit — normaliser | `tests/unit/test_deps_osv.py` (new) | record→`Advisory` (all fields); missing `summary` → `details` fallback; `aliases` into identifiers, OSV id first; `references` + canonical URL; `cwe_ids` parse. |
| unit — severity | same | GHSA `database_specific.severity` each band (incl. `MODERATE`→MEDIUM); CVSS v3 vector → band (spec example vectors); no severity → `MEDIUM` + `severity_from_upstream=False`; CVSS v2 → default. |
| unit — first_safe_version | same | single `fixed` event; multiple ranges pick the lowest `> detected`; `last_affected` only → `None`; non-matching `affected.package` ignored. |
| unit — name map | same | `angularjs`→`angular`; unmapped passthrough; every vendored component name resolves to a non-empty npm name. |
| unit — provider I/O | same | `querybatch` all-clean → **zero** `/v1/query` calls; one hit → one follow-up; in-scan memoisation (repeated `(name,version)` → one query); `MockTransport` 500 / timeout / bad JSON → `OsvLookupError`; partial `/v1/query` failure → kept results + warning. |
| unit — merge | `tests/unit/test_deps_advisories.py` | `merge_advisories`: shared-CVE pair coalesces (union ids/urls/cwe, max severity, highest safe version); disjoint pair stays two; single-source passthrough; deterministic order. |
| unit — check | `tests/unit/test_checks_deps.py` | with `observations.osv_advisories` set: OSV-only advisory produces a finding where Retire.js found none; inventory flips to `vulnerable=True`; merged finding severity = max. |
| unit — orchestrator | `tests/unit/test_deps_orchestrator.py` | flag off → `OsvProvider` never constructed; flag on + no DEPS check → not constructed; flag on + no versioned detection → not called; flag on → map reaches `Observations` and merges; `OsvLookupError` → warning + Retire.js-only result. |
| unit — config | `tests/unit/test_config.py` | `DepsSection` defaults; round-trips; `osv_online` override wins over file; unknown `[deps]` key → `ConfigError`. |
| unit — CLI | `tests/unit/test_cli.py` | `--osv-online` sets `cfg.deps.osv_online` over a config file; summary prints the "Advisory sources" line when on with an inventory; `list-checks` unchanged. |
| integration | `tests/integration/test_scan_fixture_app.py` | `_run(profile, osv_online=True)` with a `MockTransport` OSV stub: insecure profile → vuln finding carries the OSV id; hardened profile → **zero** DEPS findings; OSV stub returns 503 → RF-09 warning + Retire.js-only finding; deterministic across two runs. |
| quality gate | — | `ruff → black → mypy (strict) → lint-imports → pytest` green (tasks.md stage gates). |

Integration harness: mirror the existing `HttpClient` transport injection —
`monkeypatch.setattr(orch_mod, "OsvProvider", functools.partial(OsvProvider,
transport=httpx.MockTransport(_osv_handler)))` — so no code path reaches the real network.

## Open questions

None. Ready for `/spec tasks`.

## Implementation notes

Recorded at close (2026-09-07). What shipped, and where it differed from the design above:

- **Followed the design.** The orchestrator pass (`_osv_lookup`), the sync-seam approach,
  `merge_advisories` / `_coalesce`, the private `httpx.AsyncClient` with an injectable
  `transport`, the `[deps]` section, the CLI flag + summary line, and "no `ScanResult`
  field" all landed as written. No API/`web/` change.
- **Config knob names:** `DepsSection` fields are `osv_online`, `osv_timeout_s`,
  `osv_base_url` (prefixed, so the section has room for non-OSV knobs later).
- **CVSS parser (`_cvss3_base`)** covers CVSS v3.0 and v3.1 (shared base formula), returns
  `None` for a non-v3 / malformed vector or an unknown metric value; `_band` maps a score
  to a `Severity` (0.0 → `None`). Unit-tested against the published worked scores (9.8,
  6.1, 3.7). CVSS v2 / v4 vectors fall through to the `MEDIUM` default like 004's
  no-severity case. `_severity` prefers `database_specific.severity` (GHSA band,
  `MODERATE→MEDIUM`), which covers the bulk of npm advisories and never reaches the formula.
- **`_NPM_NAME`** seed map: `angularjs→angular`, `jquery.ui`/`jquery-ui-dialog→jquery-ui`,
  `mustache.js→mustache`, `handlebars.js→handlebars`, `prototypejs→prototype`,
  `ember→ember-source`, `ckeditor→ckeditor4`, plus identity entries. A test asserts every
  vendored component name resolves to a non-empty npm name (unmapped → verbatim).
- **`querybatch` pagination:** `_querybatch` chunks at `_QUERYBATCH_CAP = 1000` but a
  per-query `next_page_token` (many vulns on one package) is **not** followed — the
  follow-up `POST /v1/query` returns the full set anyway, so the token is unused. Noted as
  a non-issue.
- **Resilience:** a bad `querybatch` (status, transport error, non-JSON, wrong shape)
  raises `OsvLookupError` → the orchestrator turns it into the RF-09 warning and returns
  `{}`. A per-package `/v1/query` failure *after* a good `querybatch` is caught inside
  `lookup`, keeps the other packages, and adds a warning naming the package.
- **pytest:** 536 at spec 008 close → **587** at 010 close (+51). Stage gates: 539 / 544 /
  574 / 580 / 582 / 587. One pre-existing intermittent failure
  (`tests/api/test_scans.py::test_list_pagination_and_status_filter`, timestamp ordering)
  appeared once in a full run and did not recur; unrelated to this spec.
- **Manual verification:** `webvigil scan … --osv-online` against the fixture app (OSV
  stubbed) — the `deps.js.vulnerable-library` finding gains an `osv.dev/vulnerability/`
  reference and the "Advisory sources: offline database + OSV.dev" summary line;
  `--no-osv-online` omits both; a 503 from the OSV host yields the "OSV.dev lookup failed"
  warning with the offline finding intact. `webvigil list-checks` unchanged (two `deps.*`
  ids).
