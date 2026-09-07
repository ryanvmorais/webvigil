---
feature: OSV.dev online advisory provider — opt-in known-vulnerability lookup for the dependency fingerprint
status: done
date: 2026-09-07
related:
  - 001-foundation/requirements.md
  - 004-deps-fingerprint/requirements.md
origin: conception
---

# 010 — OSV.dev online advisory provider

## Context and problem

Spec 004 shipped passive client-side dependency fingerprinting. After the crawl, the
`Fingerprinter` pass identifies each `(library, version)` a target serves; the
`deps.js.vulnerable-library` check matches every detection against advisories through an
`AdvisoryProvider` seam and emits one finding per vulnerable version, with a
detected-technology inventory carrying the rest.

004 ships **exactly one** provider: `RetireJsProvider`, backed entirely by a vendored,
offline copy of the Retire.js community database
(`src/webvigil/checks/deps/data/retirejs.json`). That was a deliberate scope cut, recorded
at the time (Resolved decision 1, `memory/osv-provider-deferred`): keep 004 fully offline
and shippable, and design the seam so an **online** provider can be dropped in later
without touching the fingerprinter or the checks.

The vendored database has two structural limits:

- **It goes stale.** It only advances when a maintainer runs
  `scripts/update-retirejs-db.py` and commits the result. Between refreshes, newly
  disclosed advisories for libraries the target runs are invisible. 004 RF-22 already
  surfaces a soft "N days old" warning for exactly this reason.
- **Its coverage is Retire.js's coverage.** Retire.js tracks a curated set of front-end
  libraries. Advisories that exist in the wider ecosystem (GHSA / OSV records for the same
  npm package) but were never added to the Retire.js repository are never matched.

[OSV.dev](https://osv.dev/) is a free, aggregated vulnerability database (Google /
OpenSSF). It covers the `npm` ecosystem — which is where client-side JS libraries live —
requires **no API key**, and offers a batch query endpoint. Adding it as a second,
**opt-in** `AdvisoryProvider` closes both gaps for users who accept one explicit network
call to a third-party service.

### Where it sits

```
webvigil.checks.deps
       │
       ├── fingerprint.py       detect (library, version)              [004, unchanged]
       │
       └── advisories.py        AdvisoryProvider seam                   [004]
              ├── RetireJsProvider    vendored file, no network         [004, unchanged]
              └── OsvProvider         api.osv.dev, opt-in               [010]  ← this spec

opt-in gate:   [deps] osv_online = false   /   --osv-online     (default off)
egress:        POST /v1/querybatch  (once)  +  POST /v1/query  (per matched package)
```

The opt-in is the whole point. 004 RNF-03 promised "no network egress beyond in-scope GET
requests for resources the target's own pages reference". This spec is the first engine
feature that **deliberately** reaches a host other than the target, so it is off by
default, requires an explicit flag, talks to exactly one hard-coded host, and degrades to
the 004 behaviour on any failure.

Like every earlier spec it stays inside the engine's rules: the new code lives in
`webvigil.checks.deps`, imports nothing from `webvigil.cli` / `webvigil.api` / `web/`, and
adds no new runtime dependency (`httpx` is already an engine dependency).

## Goals

- A second `AdvisoryProvider`, `OsvProvider`, that resolves a detected `(library, version)`
  to WebVigil-native `Advisory` records by querying **OSV.dev**, reusing the existing
  `Advisory` shape so the check, the inventory, and all four reporters are unchanged.
- An **opt-in gate**: `--osv-online` / `[deps] osv_online` (default `False`). With it off,
  a dependency scan behaves exactly as in 004 (vendored Retire.js only, no third-party
  egress).
- **One batched lookup per scan**, not one call per detection: collect every
  version-known detection, query `POST /v1/querybatch` once, then fetch the full record
  for each returned vulnerability id.
- **Graceful degradation**: any network error, timeout, non-2xx response, or malformed
  payload from OSV.dev produces a scan **warning**, not an error, and the scan still
  reports whatever the vendored Retire.js provider found.
- **Composition with the offline provider**: when `osv_online` is on, OSV advisories are
  **merged** with the vendored-database advisories for the same detection, de-duplicated by
  identifier (CVE / GHSA / OSV id and their aliases), so a library covered by both sources
  yields one finding, not two.
- **In-scan memoisation**: a `(library, version)` that appears twice in one scan is queried
  once. No persistent cache (Resolved decision 4).
- **Determinism under fixed inputs**: given the same detections and the same OSV responses
  (mocked), the scan produces the same findings, identifiers, severities, and fingerprints
  across runs.
- Fixture / unit coverage that never touches the real network: `OsvProvider` is unit-tested
  against recorded OSV payloads, and the integration scan mocks the OSV host.
- Docs: an OSV-provider section in `docs/dependency-fingerprinting.md` (what it queries,
  the opt-in, the privacy note, the limitations), plus the usual
  README / CLAUDE / specs-roadmap updates.

## Non-goals

- **Making OSV the default.** The vendored Retire.js database stays the default and the
  only source used when the flag is off. This spec does not remove it, shrink it, or change
  its refresh script.
- **Replacing Retire.js when the flag is on.** OSV augments; it does not substitute. (If
  Ryan prefers "replace" — see Open question 1.)
- **Server-side / backend dependencies.** 004's non-goal stands: no PyPI / RubyGems / Go /
  Maven lookups, no reading the target's manifests. `OsvProvider` queries the `npm`
  ecosystem only, for the same client-side JS detections 004 already produces.
- **Other online providers.** No GitHub Advisory API, no NVD, no Snyk. The seam stays open
  for them; this spec ships only OSV.
- **CVSS computation or enrichment.** Severity is taken from what the OSV record carries
  (GHSA `database_specific.severity` string, or the CVSS vector's base severity band). No
  call to a CVSS calculator, no NVD detail fetch.
- **Reachability / call-graph analysis.** Unchanged from 004: a detected vulnerable version
  is reported regardless of whether the flawed path is exercised.
- **Persisting OSV data anywhere.** No vendored file, no on-disk cache, no "refresh script".
  OSV is queried live each scan (with in-scan memoisation only — Resolved decision 4).
- **A Web API / dashboard toggle.** Following 008's precedent, this spec is engine + CLI
  only. The opt-in is not exposed through `webvigil.api` or the Next.js UI (Resolved
  decision 5).
- **Querying OSV for version-undetermined detections.** As in 004 RF-10, a detection with
  `version = null` is never matched against any provider.
- **Proxy / offline-mirror configuration** for OSV beyond a base-URL override used by the
  test suite. No authenticated proxy support, no self-hosted OSV mirror handling.

## Personas

| Persona | Needs from 010 |
|---|---|
| **Security-conscious developer** | "Is there anything newer than my last DB refresh affecting the jQuery I ship?" — coverage that does not depend on when the vendored file was last updated. |
| **Pentester / consultant** | On an engagement where outbound calls to `api.osv.dev` are acceptable, the most complete advisory match available, still exportable in the existing report formats. |
| **CI pipeline author** | The default unchanged — offline, no flaky external call. Opt in only on jobs that tolerate the network dependency; a transient OSV outage must not fail the build. |
| **Privacy-conscious user** | A clear statement of exactly what leaves the machine (library names + versions, to one Google-operated host) and an easy way to keep it fully offline (the default). |

## Functional requirements

### Opt-in and configuration

**RF-01 — Opt-in flag, default off**
- **Given** no `--osv-online` flag and no `[deps] osv_online` setting, **when** a
  dependency scan runs, **then** only `RetireJsProvider` is consulted and **no** request is
  made to any host other than the target — identical to 004.
- **Given** `--osv-online` **or** `[deps] osv_online = true`, **when** a dependency scan
  runs (i.e. a `DEPS` check is selected and at least one version-known library is
  detected), **then** `OsvProvider` is consulted **in addition to** `RetireJsProvider`
  (augment, not replace — Resolved decision 1).
- **Given** both the flag and the file setting, **then** the CLI flag wins (same precedence
  as every other override — spec 006 pattern).

**RF-02 — Configuration surface**
- A new `[deps]` config section carries at least `osv_online: bool = false`.
- The section also carries a documented request **timeout** (proposed default: 10 s total)
  and an **OSV base URL** whose default is `https://api.osv.dev` and which exists so the
  test suite can point at a local mock. Both are optional with defaults; a typo in a known
  key is a hard error, consistent with every other section.
- **Given** `webvigil scan --help`, **then** `--osv-online / --no-osv-online` is listed
  with a one-line description that mentions the third-party egress.

**RF-03 — No effect without a DEPS check**
- **Given** `--osv-online` but no `DEPS` check selected (all `deps.js.*` ids disabled, or a
  check filter that excludes them), **then** the fingerprint pass does not run and
  `OsvProvider` is never invoked — no OSV request is made. Same gating as 004's
  fingerprint pass.

### Querying OSV.dev

**RF-04 — Batched query**
- **Given** the set of distinct version-known detections from the fingerprint pass, **when**
  `OsvProvider` runs, **then** it issues **one** `POST {base_url}/v1/querybatch` request
  whose body lists one query per detection: `{ "package": { "name": <npm name>,
  "ecosystem": "npm" }, "version": <version> }`.
- **Given** more distinct detections than OSV's documented batch cap (1000), **then** the
  queries are chunked into as few requests as possible; in practice a scan produces far
  fewer and this is a single request.
- **Given** the batch response, **then** for every query that returned one or more
  vulnerability ids, the full records are fetched with **one `POST /v1/query` per package**
  (Resolved decision 2) — so that summary, aliases, severity, affected ranges, references,
  and CWE ids are available.

**RF-05 — Library name to npm package mapping**
- **Given** a detection whose library name (as produced by the Retire.js rules) differs
  from its npm package name, **when** the OSV query is built, **then** a small documented
  mapping table translates it (e.g. `angularjs` → `angular`, `jquery.ui` → `jquery-ui`).
- **Given** a name not in the mapping, **then** the name is used verbatim as the npm
  package name (best effort).
- **Given** a name that cannot be resolved to any OSV package (empty `vulns` for a name
  known to be vulnerable via Retire.js), **then** that is silently acceptable — the
  Retire.js match still stands. No warning per unmatched name.

**RF-06 — Advisory normalisation**
- **Given** an OSV vulnerability record, **when** `OsvProvider` converts it to an
  `Advisory`, **then**:
  - `identifiers` = the OSV id plus every entry in `aliases` (CVE, GHSA), de-duplicated,
    order-stable.
  - `summary` = the record's `summary`, or the first sentence / truncated `details` when
    `summary` is absent.
  - `severity` = mapped per RF-07.
  - `first_safe_version` = the lowest `fixed` version across the record's `affected[]`
    ranges whose events apply to the detected version's range and ecosystem; `null` when
    the record lists no fixed version.
  - `info_urls` = the record's `references[].url` (deduplicated), plus the canonical
    `https://osv.dev/vulnerability/{id}` link.
  - `cwe` = numeric CWE ids from `database_specific.cwe_ids` (or equivalent) when present,
    else empty.
  - `severity_from_upstream` = `true` when RF-07 found a real severity, `false` when it
    fell back to the default.

**RF-07 — Severity mapping**
- **Given** an OSV record with `database_specific.severity` of `"LOW"` / `"MODERATE"` /
  `"MEDIUM"` / `"HIGH"` / `"CRITICAL"` (GHSA style), **then** it maps to
  `Severity.LOW / MEDIUM / MEDIUM / HIGH / CRITICAL`.
- **Given** no such string but a CVSS vector in `severity[]`, **then** the vector's base
  score band maps to WebVigil severity (0.1–3.9 → LOW, 4.0–6.9 → MEDIUM, 7.0–8.9 → HIGH,
  9.0–10.0 → CRITICAL).
- **Given** neither, **then** the `Advisory` uses the same documented default as 004
  (`Severity.MEDIUM`) and `severity_from_upstream = false`, so the finding notes it — the
  existing `_advisory_lines` "[severity not supplied upstream]" annotation applies
  unchanged.

**RF-08 — Provider composition and de-duplication**
- **Given** `osv_online` is on, **when** the `deps.js.vulnerable-library` check assembles a
  finding for a detection, **then** it collects advisories from **both** providers and
  merges them: two advisories are the same when their identifier sets intersect (any shared
  CVE / GHSA / OSV id or alias). Merged entries keep the union of identifiers, references,
  and CWE ids, and the **higher** severity.
- **Given** the merge, **then** the finding's overall severity, dedup key, and fingerprint
  are computed exactly as in 004 — the check's finding-shaping logic (RF-09 of 004) is
  unchanged; only the advisory list feeding it grows.
- **Given** OSV finds a vulnerability the vendored DB missed for a version Retire.js
  considered clean, **then** a `deps.js.vulnerable-library` finding is now produced for
  that detection where 004 produced none, and the inventory entry flips to
  `vulnerable: true`.

### Resilience

**RF-09 — Graceful degradation**
- **Given** the OSV host is unreachable, the request times out, returns a non-2xx status,
  or returns a body that cannot be parsed, **when** `OsvProvider` runs, **then** it
  contributes **zero** advisories, appends **one** scan warning
  (`"OSV.dev lookup failed: <reason>; reported advisories are from the offline database
  only"`), and the scan completes normally with the Retire.js results and exit code
  unaffected by the OSV failure.
- **Given** a partial batch response (some queries answered, some errored), **then** the
  answered queries are used and a warning notes the partial result.
- **Given** an OSV rate-limit response (HTTP 429), **then** it is treated as a lookup
  failure per the above — no automatic retry loop within a scan.

**RF-10 — Scope guard unaffected**
- `OsvProvider` reaches **only** the configured OSV base URL host. It never sends the
  target's cookies, headers, or auth (spec 007) to OSV, and never sends anything about the
  target beyond detected library names and versions.
- The target-scoped `HttpClient` and its scope guard are **not** used for OSV; the provider
  uses its own client restricted to the OSV host. The engine still makes no other
  off-target request.

### Caching

**RF-11 — In-scan memoisation only (no persistent cache — Resolved decision 4)**
- **Given** the same `(ecosystem, name, version)` tuple appears more than once among the
  detections of **one** scan, **then** it is queried against OSV **once**; the result is
  reused within that scan.
- There is **no** on-disk cache and **no** cross-scan reuse. Every scan with the flag on
  pays one `querybatch` round-trip (plus the per-package record fetches). This trades the
  cache-invalidation surface for simplicity; the network cost is bounded by RNF-06 and the
  timeout of RF-02.
- Consequently there is **no** `--osv-no-cache` / cache-bypass flag — there is nothing to
  bypass. (Decision 6 named `--osv-no-cache` before decision 4 removed the cache; the
  design records this. If Ryan later wants cross-scan caching it is a follow-up.)

**RF-12 — Nothing about the target is retained**
- The only per-scan state `OsvProvider` holds is the in-memory `(ecosystem, name, version)`
  → advisories map from RF-11, discarded when the scan ends. No target URL, hostname,
  cookie, finding, or scan artefact is ever written anywhere by this provider.

### CLI and reporting

**RF-13 — Summary and provenance**
- **Given** a human-readable scan summary (no `--format`) with `--osv-online`, **then** the
  existing "Detected N client-side libraries (M with known vulnerabilities)" line is
  unchanged, and a short note indicates OSV.dev was consulted (e.g.
  `"advisory sources: offline database + OSV.dev"`), or the warning from RF-09 if it
  failed.
- **Given** a finding whose advisories came (partly) from OSV, **then** its evidence /
  references make the OSV source visible through the `https://osv.dev/vulnerability/{id}`
  links already required by RF-06 — no new finding field.

**RF-14 — Reporters unchanged**
- No reporter (JSON / SARIF / HTML / Markdown) gains a field or a section for this spec.
  OSV advisories flow through the identical `Advisory` → finding → inventory path. A saved
  canonical JSON re-renders offline exactly as in 004 RF-14 (the OSV data is already baked
  into the findings and inventory at scan time).

**RF-15 — `list-checks` unchanged**
- No new check id. `deps.js.vulnerable-library` and `deps.js.library-detected` are the only
  DEPS checks; `--osv-online` changes what feeds the first one, not the catalogue.

### Tests

**RF-16 — Offline test suite**
- `OsvProvider` normalisation (RF-06, RF-07), name mapping (RF-05), merge / de-dup (RF-08),
  and degradation (RF-09) are unit-tested against **recorded** OSV payloads and simulated
  failures — no real network call.
- The integration scan of the fixture app runs with `osv_online=true` against a **mocked**
  OSV host (`pytest-httpx`), asserting: (a) the vulnerable library still produces its
  finding, now carrying an OSV id; (b) the hardened profile still produces **zero** DEPS
  findings; (c) a simulated OSV outage yields the RF-09 warning and the Retire.js-only
  result.
- A test asserts RF-11's memoisation: a scan whose detections repeat a `(name, version)`
  issues exactly one OSV query for it.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.checks.deps` and imports nothing from `webvigil.cli`,
`webvigil.api`, or `web/`. It adds no new runtime dependency — `httpx` is already an engine
dependency. The `import-linter` contract is unchanged.

**RNF-02 — Opt-in egress, clearly scoped**
With `osv_online` off, the scan makes zero off-target requests (004 RNF-03 preserved). With
it on, the **only** new egress is to the configured OSV host, carrying only npm package
names and versions. This is stated in the docs and in `--help`.

**RNF-03 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy` covering the new
modules. No API/UI gate work (this spec does not touch them).

**RNF-04 — Determinism**
Given the same detections and the same OSV responses (mocked), a scan produces the same
findings, identifiers, severities, inventory, and fingerprints across runs, with stable
ordering everywhere. Identifier and reference lists are order-stable.

**RNF-05 — False-positive discipline**
- Version-undetermined detections are never queried (RF-10 of 004 stands).
- An OSV record whose `affected` ranges do not actually cover the detected version /
  ecosystem does not produce an advisory (the batch endpoint already version-filters;
  normalisation must not re-introduce a non-matching range).
- The hardened fixture profile yields zero DEPS findings with the flag on (RF-16).

**RNF-06 — Bounded work**
At most one `querybatch` request plus one `POST /v1/query` per package that returned at
least one vulnerability id (Resolved decision 2). The package count is bounded by the
distinct version-known detections, itself bounded by 004's 50-resource fetch cap. No
unbounded pagination, no retry loop. The request timeout (RF-02) caps the added wall-clock
cost; on timeout the scan proceeds per RF-09.

**RNF-07 — Privacy note**
The docs state plainly what is sent (library names + versions), to whom (`api.osv.dev`,
Google / OpenSSF), when (only with the flag, once per scan), and how to stay fully offline
(the default). No target URL, hostname, cookie, or finding ever leaves the machine.

**RNF-08 — Python support**
Runs on CPython 3.12 and 3.13 (existing CI matrix).

**RNF-09 — Docs**
`docs/dependency-fingerprinting.md` gains an OSV-provider section (query, opt-in, privacy,
limitations). `README.md`'s coverage table, `CLAUDE.md`'s layer-3 `deps` paragraph, and
`specs/README.md`'s roadmap are updated; 010 moves to `in progress` then `done`.

## Resolved during requirements

Settled with Ryan on 2026-09-07:

1. **Augment, not replace (RF-01, RF-08).** With `--osv-online` on, OSV advisories are
   **merged** with the vendored Retire.js results — the offline database stays the floor,
   OSV widens the coverage. OSV never substitutes Retire.js.
2. **Full-record fetch: `POST /v1/query` per package (RF-04, RNF-06).** After the single
   `querybatch`, fetch the full records with one `POST /v1/query` per package that returned
   any vulnerability id — fewer requests than per-id `GET`, and complete records.
3. **Sync seam kept (RF-08, design).** `AdvisoryProvider.match` stays synchronous. The
   orchestrator runs an OSV lookup pass **before** the checks (like the fingerprint pass),
   batch-fetches everything, and hands the check a pre-populated `(name, version)` →
   advisories map. `RetireJsProvider` and the check's finding-shaping are otherwise
   untouched.
4. **No persistent cache (RF-11, RF-12).** In-scan memoisation only — a repeated
   `(name, version)` within one scan is queried once. No on-disk cache, no cross-scan
   reuse, and therefore no cache-bypass flag. Cross-scan caching is a possible follow-up.
5. **Engine + CLI only (RF-14, Non-goals).** No Web API or dashboard change, following
   spec 008's precedent. `[deps] osv_online` is read by the engine; the API neither exposes
   nor blocks it (it already passes `webvigil.toml` through), but this spec adds no endpoint
   or UI toggle and does no `web` gate work.
6. **Cache-bypass flag: not added (superseded by decision 4).** `--osv-no-cache` was the
   pick before the cache itself was cut; with no cache there is nothing to bypass.
7. **New `[deps]` config section.** A dedicated `[deps]` table holds `osv_online` plus the
   `timeout` / `base_url` tuning knobs — matching the per-feature convention (`[disclosure]`,
   `[injection]`) and leaving room for a future provider.

## Open questions

None. Ready for `/spec design`.
