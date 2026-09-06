---
feature: Dependency fingerprinting — passive client-side library detection + known-vulnerability matching
status: done
date: 2026-09-06
related: [001-foundation/requirements.md, 002-web-api/requirements.md, 003-web-ui/requirements.md]
origin: conception
---

# 004 — Dependency fingerprinting

## Context and problem

Specs 001–003 shipped the engine + CLI, the Web API, and the dashboard. Every check WebVigil
runs today looks at the **transport and the response envelope**: TLS, headers, cookies, CORS.
Nothing looks at **what the page is built with**.

Outdated client-side JavaScript libraries are one of the most common real-world web findings:
jQuery below 3.5 (XSS via `$.htmlPrefilter`), Bootstrap below 4.3.1 (XSS in tooltips),
old Angular, lodash prototype pollution, Moment.js ReDoS, and so on. A developer who ships a
five-year-old `jquery.min.js` from their own `/static/` directory has a known, CVE-numbered
XSS on their site — and WebVigil is completely blind to it.

This spec adds **passive technology fingerprinting** of the client-side stack: it identifies
JavaScript libraries and their versions from what the target already serves, then matches
each detected `(library, version)` against a **vendored [Retire.js](https://retirejs.github.io/)
advisory database** and reports a finding for every version with a known vulnerability.

It stays inside the engine's existing rules: pure library, no new heavy dependency, Safe Mode
by default, the scope guard unchanged, and — like every earlier spec — **fully offline**. The
advisory data ships in the repo; a maintainer script refreshes it out of band.

### Where it sits

```
webvigil.checks.deps          new check package  (Category.DEPS, mode = PASSIVE)
       │
       ├── fingerprint          detect (library, version) from URLs / SRI / content
       │
       └── AdvisoryProvider     interface — match a detection against advisories
              └── RetireJsProvider   reads the vendored jsrepository DB   [004]
              └── (online provider, e.g. OSV)                            [future spec]

vendored data:  src/webvigil/checks/deps/data/retirejs.json   (Apache-2.0, attributed)
refresh:        scripts/update-retirejs-db.py                  (network here only)
```

The engine still imports nothing from `webvigil.cli`, `webvigil.api`, or `web/`. The
`import-linter` "engine stays independent" contract is unchanged (no new forbidden package —
detection uses the stdlib: `json`, `re`, `hashlib`).

A **minimal, additive** touch reaches spec 002 (persist the detected-technology list) and
spec 003 (show it on the scan-detail screen). Both are display-only and traced below (RF-17,
RF-18), in the spirit of spec 003's RF-31 escape hatch.

## Goals

- A **passive fingerprinting** step that detects client-side JS libraries and versions from:
  script/resource **URLs**, **Subresource Integrity** hashes, inline `<script>` markers, and
  the **content of in-scope** script resources.
- A **vendored Retire.js advisory DB** and a `RetireJsProvider` that matches a detected
  `(library, version)` against it, yielding CVE / GHSA identifiers, a summary, and a severity.
- A `deps.js.vulnerable-library` check (`Category.DEPS`, `mode = PASSIVE`) that emits one
  finding per vulnerable `(library, version)`, deduplicated across pages, with an
  "upgrade to ≥ X" remediation.
- An **`AdvisoryProvider` seam** so an online provider (OSV, GitHub Advisories) can be added
  in a later spec without changing the check or the fingerprinter.
- A **detected-technology inventory** (a `technologies` array on `ScanResult`) surfaced in
  all four reports, persisted by the Web API, and shown on the dashboard's scan-detail
  screen — so non-vulnerable detections are not lost.
- A maintainer script (`scripts/update-retirejs-db.py`) that refreshes the vendored DB with a
  recorded provenance header. Network lives **only** in this script.
- Fixture-app coverage: the insecure profile serves a known-vulnerable library; the hardened
  profile serves none — integration tests assert the finding on one and **zero** DEPS
  findings on the other.
- Docs: a dependency-fingerprinting section (how detection works, the vendored DB, how to
  refresh it, the limitations), plus the usual README / CLAUDE / specs-roadmap updates.

## Non-goals

- **Server-side / backend fingerprinting** beyond spec 001's revealing-headers check
  (RF-17). No detection of the web framework, language runtime, or their versions. No
  analysis of Python / Ruby / PHP / Go dependencies.
- **Reading local manifests** (`package.json`, `requirements.txt`, lockfiles) from the
  user's disk. There is no `--manifest` flag. WebVigil scans a running target, not a repo.
- **Consuming manifests the target exposes over HTTP** (`/package.json`, `/composer.lock`,
  source maps as a dependency source). Detecting and reporting such exposed files is
  **spec 005** (information disclosure); 004 does not depend on or duplicate it.
- **Active probing** — no speculative requests for common library paths
  (`/js/jquery.min.js`, `/vendor/…`). 004 fetches only resources the target's own pages
  reference. It runs in Safe Mode and is safe against production.
- **Online advisory lookups** (OSV, NVD, GitHub Advisory API). The provider seam is designed
  for them; none is implemented here.
- **CVSS scoring or enrichment** beyond the severity/identifiers the vendored DB already
  carries. No calls to a CVSS calculator, no NVD detail fetch.
- **Automatic DB updates** — not at scan time, not a CI job that commits a refresh. The
  vendored file changes only when a maintainer runs the script and commits it.
- **Broad Wappalyzer-style tech detection** — CDNs, WAFs, analytics, tag managers, CMS
  fingerprints. Scope is security-relevant **JS libraries** with advisory coverage.
- **Reachability analysis** — 004 does not try to determine whether the vulnerable code path
  is actually invoked. A detected vulnerable version is reported regardless of use.
- **SBOM output** (CycloneDX, SPDX). A possible later reporter; not here.
- **Fetching cross-origin resources.** Scripts served from a third-party CDN
  (`code.jquery.com`, `cdn.jsdelivr.net`) are out of scope for the scope guard and are
  **not** downloaded; they are fingerprinted from the URL and any SRI hash only.

## Personas

| Persona | Needs from 004 |
|---|---|
| **Security-conscious developer** | "Is the jQuery I'm shipping actually vulnerable?" — a finding that names the library, the version, the CVE/GHSA ids, what the flaw is, and the first fixed version. |
| **CI pipeline author** | A SARIF result for an outdated library so `--fail-on high` can block a deploy, produced with no network call and no flaky external API. |
| **Pentester / consultant** | A quick, reliable inventory of the client-side stack of a target, with the vulnerable entries flagged, exportable in the existing report formats. |
| **Check author / contributor** | `Category.DEPS` and the fingerprint/advisory split as the reference pattern for content-based checks (everything so far only reads headers). |

## Functional requirements

### Fingerprinting

**RF-01 — Detection sources**
- **Given** a discovered in-scope page, **when** the fingerprinter runs, **then** it inspects,
  for each referenced script/style resource: the resource **URL** (path and filename), the
  element's **`integrity`** attribute (SRI hash), and — for **in-scope** resources — the
  fetched **body**; plus the **inline `<script>`** contents of the page itself.
- **Given** a detection, **then** it records: `library`, `version` (or `null`), the
  `detection method` (`uri` \| `filename` \| `filecontent` \| `hash` \| `sri`), the
  `source url`, and a `confidence` derived from the method (RNF-05).

**RF-02 — Version extraction**
- **Given** a recognised library, **when** a version string is present in the filename
  (`jquery-3.4.1.min.js`), a content banner/comment (`/*! jQuery v3.4.1 …`), or matches a
  known per-version file hash, **then** that version is recorded.
- **Given** the library is recognised but no version can be determined, **then** the
  detection is kept with `version = null` and **no** vulnerability match is attempted
  (RF-10).

**RF-03 — Resource fetching and scope**
- **Given** a page references a script/style resource on an **in-scope** host that the
  crawler has not already fetched, **when** the fingerprinter needs its body, **then** it
  fetches it with a GET through `ctx.http` — so the concurrency cap, per-host delay, and
  scope guard all apply.
- **Given** the resource is on an **out-of-scope** host (a CDN), **then** it is **not**
  fetched; detection falls back to the URL and the SRI hash.
- **Given** the number of distinct in-scope resources exceeds a documented cap, **then**
  fetching stops at the cap and the scan records a warning (RNF-07).

**RF-04 — Deduplication**
- **Given** the same `(library, version)` is detected on several pages or from several
  sources, **when** findings are assembled, **then** they collapse to **one** finding. The
  finding `fingerprint` is keyed on `library` + `version` (+ advisory id), **not** the URL,
  so re-runs and multi-page sites are stable (RNF-04).

**RF-05 — Data-driven catalogue**
- The set of recognised libraries and their identification rules (URI regexes, content
  regexes, file hashes) comes from the **vendored Retire.js repository data** (RF-06), not a
  hand-maintained per-library table in WebVigil's source. Adding coverage = refreshing the
  vendored file.
- WebVigil applies **whatever rules the vendored DB expresses** — script URIs, content
  markers, hashes, and any non-`<script>` rules the DB carries (Retire.js includes some).
  It does not add identification rules of its own (Resolved decision 9).

### Advisory matching

**RF-06 — Vendored advisory database**
- **Given** a checkout, **then** the Retire.js advisory database is present at a documented
  path under `src/webvigil/checks/deps/data/` and is loaded from disk — never downloaded at
  scan time.
- The vendored file carries a **provenance header**: upstream source URL, upstream commit or
  ETag, and the retrieval date. Its Apache-2.0 licence and attribution are retained (RNF-06).

**RF-07 — Match semantics**
- **Given** a detection with a concrete `version`, **when** it is matched against the DB,
  **then** the library's advisory entries are evaluated with Retire.js range semantics
  (`atOrAbove` / `below` / `atOrAbove`+`below`), and every matching advisory is collected.
- **Given** a matching advisory, **then** WebVigil extracts its identifiers (CVE ids, GHSA
  ids, issue/bug URLs), its summary, its severity, and the **first non-vulnerable version**
  (the lowest `below`/`atOrAbove` boundary above the detected version).

**RF-08 — Severity mapping**
- **Given** an advisory severity of `low` / `medium` / `high` / `critical`, **then** it maps
  to `Severity.LOW` / `MEDIUM` / `HIGH` / `CRITICAL`.
- **Given** an advisory with no severity, **then** the finding uses a documented default
  (proposed: `MEDIUM`) and the finding notes that the severity was not supplied upstream.

**RF-09 — Finding shape**
- **Given** at least one advisory matches a detected `(library, version)`, **when** the check
  emits a finding, **then**:
  - `check_id` = `deps.js.vulnerable-library`, `category` = `DEPS`, `mode` = `PASSIVE`.
  - `title` = `"<library> <version> has known vulnerabilities"`.
  - `severity` = the **highest** severity among the matched advisories.
  - `location.url` = a representative source URL where the library was seen.
  - `description` lists each matched advisory: identifier(s) + one-line summary.
  - `evidence` = the detection method and the raw marker (filename, banner line, or hash)
    plus the matched advisory identifiers.
  - `remediation` = `"Upgrade <library> to <first safe version> or later."`
  - `cwe` = CWE ids carried by the advisories (when present); `references` = advisory URLs
    plus the MITRE CWE links.

**RF-10 — Unknown-version handling**
- **Given** a recognised library with `version = null`, **then** **no**
  `deps.js.vulnerable-library` finding is produced for it (a version-less library cannot be
  matched without guessing — RNF-05).
- **Given** such a detection, **then** it is recorded in the inventory (RF-12) **and** the
  check emits one `INFO` finding `deps.js.library-detected` — `"<library> detected, version
  undetermined"` — so the user knows coverage was attempted but incomplete. This is the only
  case that produces a `deps.js.library-detected` finding; recognised libraries with a known
  version go to the inventory only.

**RF-11 — Advisory-provider seam**
- Matching is performed through an `AdvisoryProvider` interface: given a `(library, version)`
  it returns zero or more advisory records in a WebVigil-native shape.
- 004 ships exactly one implementation, `RetireJsProvider`, backed by the vendored file
  (RF-06). It performs **no** network I/O.
- **Given** a future online provider is added, **then** the fingerprinter and the check
  require no change — only provider selection/config does.

### Detected-technology inventory

**RF-12 — Inventory on the scan result**
- **Given** a scan, **when** it completes, **then** the `ScanResult` carries a
  **technology inventory**: one entry per distinct detected `(library, version)` with
  `name`, `version` (nullable), `detection method`, a representative `source url`, and
  `vulnerable: bool` (true when RF-09 produced a finding for it).
- The inventory is **deterministic** and stably ordered (by name, then version).
- An entry being in the inventory is **not** a finding on its own; only RF-09 creates
  findings.

### Reporting

**RF-13 — Reporters include dependency data**
- **Given** a completed scan with a non-empty inventory, **when** rendered as **JSON**, the
  inventory is a top-level array (canonical, feeds `webvigil report`).
- **Given** **SARIF**, `deps.js.vulnerable-library` is one `rule` (per the check), each
  finding is a `result` with the advisory ids in `partialFingerprints` and an advisory URL
  as `helpUri`.
- **Given** **HTML** / **Markdown**, a "Detected technologies" section lists the inventory,
  vulnerable rows marked, above or beside the findings section.

**RF-14 — Offline re-render unchanged**
- **Given** a saved canonical JSON, **when** `webvigil report scan.json --format …` runs,
  **then** it re-renders every format — including the technologies section — with no network
  request (the inventory is in the JSON; mirrors spec 001 RF-24).

### CLI

**RF-15 — Catalogue and suppression**
- **Given** `webvigil list-checks`, **then** `deps.js.vulnerable-library` and
  `deps.js.library-detected` appear with their category (`DEPS`), mode (`PASSIVE`), and
  default severity.
- **Given** `[checks] disabled = ["deps.js.vulnerable-library"]` (or the same for
  `deps.js.library-detected`), **then** that check does not run — same mechanism as every
  other check. Disabling the matcher does not disable the fingerprinter that feeds the
  inventory unless both ids are disabled (a design detail).

**RF-16 — Scan summary line**
- **Given** `webvigil scan <url>` with the human-readable summary (no `--format`), **when**
  the scan completes, **then** the summary includes a line such as
  `"Detected N client-side libraries (M with known vulnerabilities)"`.

### Web API amendment (minimal, additive — traces to spec 002)

**RF-17 — Persist and expose the inventory**
- **Given** RF-12's inventory, **when** a scan finishes, **then** the API persists it
  alongside the scan (a `scan.technologies` JSON column or a `technology` child table — a
  design call), covered by an Alembic migration.
- **Given** `GET /api/scans/{id}` (or a `GET /api/scans/{id}/technologies` sub-resource),
  **then** the inventory is returned in the response, display-only.
- No change to scan execution, auth, queueing, or existing response fields. This extends
  spec 002 RF-19 (lossless persistence) and RF-25 (schema); it is listed in
  `004-deps-fingerprint/design.md` under "API amendments" with that trace, exactly as spec
  003 RF-31 requires.

### Web UI amendment (minimal — traces to spec 003)

**RF-18 — "Detected technologies" on scan detail**
- **Given** the dashboard's `/scans/{id}` screen for a completed scan, **then** it shows a
  "Detected technologies" section: library, version, detection method, and a **vulnerable**
  badge that links to the matching finding(s) in the same view. Source is RF-17.
- **Given** the inventory is empty, **then** the section is hidden (or shows a neutral empty
  state).
- No other screen changes. Covered by a component test and included in the existing
  accessibility assertion. `api-types.ts` is regenerated from the amended `openapi.json` and
  drift-checked (spec 003 RF-03 / RNF-08).

### Fixture app and tests

**RF-19 — Vulnerable library in the fixture**
- **Given** the `tests/fixtures` app's **insecure** profile, **then** at least one page
  references a self-hosted script whose filename and content banner identify a
  **known-vulnerable** version (e.g. a stub `jquery-1.12.4.min.js` with the matching
  `/*! jQuery v1.12.4 */` header) covered by the vendored DB.
- **Given** the **hardened** profile, **then** it references a current version or no
  third-party library.
- **Given** an integration scan of the insecure profile, **then** the
  `deps.js.vulnerable-library` finding is present with the expected identifiers; **given** a
  scan of the hardened profile, **then** **zero** `DEPS` findings are reported
  (false-positive guard, mirrors spec 001 RF-27).

**RF-20 — Matching and detection unit tests**
- Fingerprint extraction (each detection method) and advisory matching (range semantics,
  severity mapping, first-safe-version, unknown-version → no finding) are unit-tested with
  crafted inputs and a small vendored-DB fixture subset — not only through the integration
  scan.

### Database maintenance

**RF-21 — Refresh script**
- **Given** `python scripts/update-retirejs-db.py`, **then** it downloads the upstream
  Retire.js community database, normalises it to the vendored shape, and writes it to the
  path in RF-06 with a fresh provenance header (source URL, upstream commit/ETag, date).
- This script is the **only** place in the project that reaches the Retire.js servers. The
  engine, CLI, and API never do.
- `docs/` documents when and how to run it.

**RF-22 — Staleness warning**
- **Given** the vendored DB's provenance date is more than **90 days** old, **when**
  `webvigil version` runs or a scan completes, **then** a **soft warning** is surfaced
  ("dependency advisory data is N days old; run `scripts/update-retirejs-db.py`") — in the
  scan's warnings list and on the `version` output.
- **Given** the same condition in CI, **then** the `web`/`quality` pipeline prints the
  warning but **does not fail** — refreshing the file is a maintainer action, not a gate.

## Non-functional requirements

**RNF-01 — Engine purity, no new heavy dependency**
New code lives in the engine (`webvigil.checks.deps` and any fingerprint/advisory helper
module) and imports nothing from `webvigil.cli`, `webvigil.api`, or `web/`. Detection and
matching use the standard library (`json`, `re`, `hashlib`) — no new runtime dependency is
added to the base install. If a new top-level engine package is introduced, the
`import-linter` `source_modules` list is extended to cover it.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy` covering the new
modules. If RF-17 is implemented: the API's `TestClient` suite plus a migration test pass.
If RF-18 is implemented: the `web` gate (`pnpm lint / format:check / typecheck / test /
build`, the Playwright flow, and the `api-types.ts` drift check) passes. The Python `quality`
matrix and the `docker` job are otherwise unchanged.

**RNF-03 — Offline and safe against production**
A dependency scan makes **no** network egress beyond in-scope GET requests for resources the
target's own pages reference. It sends no payloads and no state-changing requests. Spec 001
RNF-05 still holds: the CORS probe remains the most active thing Safe Mode does.

**RNF-04 — Determinism**
Given the same target responses and the same vendored DB, a scan produces the same
inventory, the same findings, and the same fingerprints across runs, with stable ordering in
every report.

**RNF-05 — False-positive discipline**
- A detection with an uncertain version never produces a vulnerable-library finding (RF-10).
- `confidence` reflects the detection method: `hash` / `sri` exact match → `HIGH`; version in
  `filename` or a content `banner` → `MEDIUM`; looser content heuristic → `LOW`.
- The hardened fixture profile yields zero `DEPS` findings (RF-19).

**RNF-06 — Provenance and licensing**
The vendored Retire.js data keeps its Apache-2.0 notice and attribution. A `NOTICE` (or
`THIRD_PARTY_LICENSES`) file is added or updated to record it. The refresh script stamps the
upstream version into the file so its age is always visible.

**RNF-07 — Bounded work**
Fetching referenced in-scope resources is bounded by a documented cap and by the existing
concurrency / delay policy. A page with hundreds of `<script>` tags cannot multiply the
request count without limit; hitting the cap is recorded as a scan warning, not an error.

**RNF-08 — Python support**
Runs on CPython 3.12 and 3.13 (the existing CI matrix).

**RNF-09 — Docs**
A new `docs/` section (or file) explains how detection works, what the vendored DB is, how to
refresh it (RF-21), and the known limitations (no version → no match; CDN scripts are
URL/SRI only; no reachability analysis). `README.md`'s check list, `CLAUDE.md`'s architecture
summary, and `specs/README.md`'s roadmap are updated; 004 moves to `in progress` then `done`.

## Resolved decisions

Settled with Ryan on 2026-09-06:

1. **Advisory source (RF-06, RF-11):** vendor the Retire.js community database in the repo
   and match against it **offline**. An online provider (OSV.dev covers npm + PyPI without a
   key) is designed as a swappable `AdvisoryProvider` but **deferred to a later spec** — 004
   ships only `RetireJsProvider`.
2. **Input surface (Non-goals):** **remote passive detection only**. No `--manifest` flag
   reading files from the user's disk, and no consumption of manifests the target exposes
   over HTTP — the latter overlaps spec 005 (information disclosure) and is left to it.
3. **Detection surface (RF-03, RNF-03):** **pure passive**. The check inspects only the
   pages the crawler discovered and the in-scope resources those pages reference. No
   speculative or probe requests for common library paths. It runs in Safe Mode.
4. **Web UI (RF-17, RF-18):** a **minimal, explicit** addition — a "Detected technologies"
   section on the scan-detail screen — fed by a minimal additive API/persistence change. No
   other dashboard screens change.
5. **Inventory representation (Open q. 1 / RF-12):** option **(a)** — a `technologies` array
   on `ScanResult`, persisted by the API. The schema-change cost (four reporters, a spec-002
   migration, the dashboard) is accepted for the product story.
6. **Version-unknown detections (Open q. 2 / RF-10):** record the library in the inventory
   **and** emit one `INFO` `deps.js.library-detected` finding ("version undetermined"), so
   incomplete coverage is visible rather than silent.
7. **Staleness signal (Open q. 3 / RF-22):** a **soft warning** when the vendored DB is more
   than 90 days old — surfaced by `webvigil version` and in the scan warnings, printed but
   non-failing in CI. No hard gate.
8. **Check granularity (Open q. 4):** only `deps.js.vulnerable-library` (plus the
   version-undetermined `deps.js.library-detected` from decision 6). No `deps.js.outdated` —
   the Retire.js DB has no reliable "latest version" to compare against.
9. **Non-JS rules (Open q. 5 / RF-05):** apply whatever the vendored Retire.js DB expresses,
   including its non-`<script>` rules. WebVigil adds **no** identification rules of its own.

## Open questions

None. Ready for `/spec design`.
