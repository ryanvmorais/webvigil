---
feature: Information disclosure — exposed files/routes, directory listing, stack traces, debug endpoints
status: done
date: 2026-09-06
related:
  - 001-foundation/requirements.md
  - 002-web-api/requirements.md
  - 003-web-ui/requirements.md
  - 004-deps-fingerprint/requirements.md
origin: conception
---

# 005 — Information disclosure

## Context and problem

Specs 001–004 shipped the engine + CLI, the Web API, the dashboard, and passive
dependency fingerprinting. Every check so far reads what the target **hands back on its
own**: response headers, cookies, TLS, CORS, the HTML the crawler discovered, the scripts
those pages reference. WebVigil never asks the target for anything the target did not
already point at.

That leaves a whole class of very common, very cheap findings untouched: an application
that deploys its `.git/` directory to the web root, a `.env` file reachable at
`https://target/.env`, a `db_backup.sql` next to `index.php`, an Apache `Index of /`
listing an upload directory, a Django `DEBUG = True` traceback on every 500, Spring Boot's
`/actuator/env` dumping the environment. These are not exotic. They are the first thing a
consultant checks and the most frequent cause of a real breach — a leaked `.env` is a
leaked database password.

This spec adds **information-disclosure detection** in two tiers:

- **Passive analysis** (always on, no extra requests): recognise framework error pages,
  stack traces, and directory-listing pages in the responses the crawler already fetched.
- **Well-known-path probing** (opt-in, off by default): with an explicit toggle, issue
  bounded, in-scope `GET` requests for a small, curated list of notoriously sensitive
  paths (`.git/config`, `.env`, backups, debug endpoints, exposed manifests) and report
  the ones that are actually reachable and actually contain what their name implies.

Like every earlier spec it stays inside the engine's rules: a pure library, no new heavy
dependency (detection is `re` + `json`), Safe Mode by default, the scope guard unchanged,
the good-neighbor policy applied to every request, fully offline.

### Where it sits

```
webvigil.checks.disclosure          new check package  (Category.DISCLOSURE, mode = PASSIVE)
       │
       ├── error / listing analysis   passive — reads pages the crawler already fetched
       │
       └── probe pass                 opt-in — bounded GETs for a curated path catalogue
              ├── soft-404 calibration    learn the target's "not found" shape first
              ├── content validation      a hit must look like what its name implies
              └── derived probes           <script>.map for referenced in-scope scripts

curated catalogue:  src/webvigil/checks/disclosure/data/paths.<ext>   (versioned in-repo)
```

The engine still imports nothing from `webvigil.cli`, `webvigil.api`, or `web/`. The
`import-linter` "engine stays independent" contract is unchanged (no new forbidden
package). Findings flow through spec 001's four reporters and — with **no change to
`webvigil.api` or the dashboard** — persist and render through spec 002/003's existing
plumbing, because a `Finding` is a `Finding`. This is an **engine-only** spec.

## Goals

- **Passive error/listing detection**: `disclosure.*` checks that recognise stack traces,
  framework debug pages (Werkzeug, Django, Rails, ASP.NET, PHP, Java, Node), and
  auto-generated directory listings in already-crawled responses — no extra requests.
- An **opt-in probe pass** (`[disclosure] probe`, default `false`; `--probe` /
  `--no-probe`) that, when enabled, issues bounded in-scope `GET`s for a **small curated
  catalogue** of well-known sensitive paths and reports the reachable ones.
- **Soft-404 calibration + per-entry content validation** so a hit is only reported when
  the response is not the target's "not found" page **and** its body matches what the path
  implies (`/.git/config` is an ini with `[core]`; `/.env` is `KEY=VALUE` lines;
  `/package.json` is JSON with `name`/`dependencies`).
- **Derived probes**: for each in-scope script the crawl referenced, probe its
  `.map` (source map) and report an exposed one.
- **Secret redaction**: any secret-bearing body (`.env`, `/actuator/env`, `.npmrc`) is
  reduced to keys-only before it enters a `Finding` (which is persisted and rendered).
- A **curated catalogue** shipped as a versioned data file under
  `src/webvigil/checks/disclosure/data/`, documented, not user-extensible in this spec.
- Fixture-app coverage: the insecure profile exposes `.git`, `.env`, a listing, a stack
  trace, and a manifest; the hardened profile exposes none — integration tests assert the
  findings on one and **zero** `DISCLOSURE` findings on the other.
- Docs: an information-disclosure section (what it detects, why probing is opt-in, the
  catalogue, the limitations, the redaction rule) plus the usual README / CLAUDE /
  specs-roadmap updates.

## Non-goals

- **Active error induction** — appending `'`, `<script>`, oversized values, or malformed
  input to parameters to *trigger* a stack trace or a SQL error. 005 reads error pages the
  crawl already surfaced (and the calibration 404 it issues itself); deliberately breaking
  the app is **spec 006** (Active injection).
- **Content-discovery brute force** — dirbuster/gobuster/ffuf-style enumeration with a
  large wordlist. 005's catalogue is a *small, curated list of names that are sensitive by
  definition*, not a search for unknown content. No `--wordlist` flag.
- **Parsing exposed manifests to enumerate dependencies**, and **feeding them into spec
  004's technology inventory or CVE matching**. 005 confirms the file is exposed and
  reports it; it does not read the dependency tree. The specs stay decoupled (spec 004
  Non-goals said the reverse).
- **`.git` exfiltration / repository reconstruction** (git-dumper-style). 005 reports that
  `.git/` is reachable; it does not download objects or rebuild the tree.
- **Full-body secret scanning** (Gitleaks/trufflehog-style regexes for API keys across
  every HTML/JS response). High false-positive rate; a possible later spec. 005 only
  redacts and reports secrets found in a *confirmed* exposed config file.
- **Cloud metadata endpoints** (`169.254.169.254`, `metadata.google.internal`). Reaching
  those is SSRF — spec 006 — not an in-scope-path disclosure.
- **Authenticated-only disclosure** — pages reachable only with a session. Spec 007.
- **Probing requiring the Active-Mode gate.** The probe pass sends only in-scope `GET`s
  with no payloads and no state change; it is gated by its own opt-in toggle, not by
  `--mode active --authorized-by` (Resolved decision 1).
- **Any change to `webvigil.api`, the database schema, `openapi.json`, or the dashboard.**
  005 produces `Finding`s and nothing else; the existing spec 002/003 plumbing carries
  them (Resolved decision 4). No migration, no `pnpm gen:api`, no `web` gate.
- **Broad Wappalyzer-style server fingerprinting.** Server/framework identification beyond
  spec 001's revealing-headers check is still out (spec 004 Non-goals).
- **A "missing `security.txt`" finding.** The absence of `/.well-known/security.txt` is a
  nice-to-have, not a disclosure; its presence is not a problem. Skipped.

## Personas

| Persona | Needs from 005 |
|---|---|
| **Security-conscious developer** | "Did I just deploy my `.git/` folder / my `.env` / a database dump to production?" — a HIGH finding that names the exact URL and what it leaks, with a server-config fix. |
| **CI pipeline author** | A SARIF result for an exposed `.env` or `.git` so `--fail-on high` blocks the deploy — produced with no network call to a third party and no flakiness. Probing stays *off* unless the pipeline opts in. |
| **Pentester / consultant** | One flag (`--probe`) turns on a fast, reliable sweep of the paths they check by hand on every engagement — VCS dirs, backups, `/actuator`, profilers — with the noise bounded and the hits content-validated. |
| **Check author / contributor** | `Category.DISCLOSURE`, the soft-404 calibration, and the passive-tier/probe-tier split as the reference pattern for a check that needs its own requests but must stay Safe. |

## Functional requirements

### Passive analysis (always on — no requests beyond the crawl)

**RF-01 — Framework error / stack-trace detection** (`category = DISCLOSURE`)
- **Given** a crawled in-scope response whose body matches a known error-page or
  stack-trace signature, **when** the check runs, **then** it emits a finding that names
  the framework/runtime and quotes the matched marker (trimmed).
- Recognised at minimum: Python `Traceback (most recent call last):`; the **Werkzeug /
  Flask interactive debugger** (`Werkzeug Debugger`, the traceback console); Django's
  `DEBUG` traceback page (`You're seeing this error because you have DEBUG = True`); Rails
  `ActionView` / `ActionController` exception pages; ASP.NET "Server Error" / yellow-screen
  (`[HttpException`, stack-trace table); PHP `Fatal error:` / `Warning:` / `Notice:` with a
  file path and line; Java/JSP exception dumps (`java.lang.*Exception`, `at
  com.…(…java:NN)`); Node/Express (`Error:` followed by `at …(/…:NN:NN)`).
- **Given** the interactive Werkzeug debugger (code-execution surface), **then** the
  severity is `HIGH`; **given** a non-interactive stack trace, **then** `MEDIUM`; **given**
  a single PHP `Notice`/`Warning` with a path, **then** `LOW`.
- **Given** a generic, trace-free error page ("Something went wrong"), **then** nothing is
  reported.
- `dedup_key` is the framework + a normalised marker, so the same debug page on many routes
  collapses to one finding.

**RF-02 — Directory-listing detection** (`category = DISCLOSURE`)
- **Given** a crawled in-scope response that is a server-generated index — `<title>Index
  of /…`, `Directory listing for /…` (Python `http.server`), Apache `mod_autoindex`
  markup, nginx `autoindex` markup — **when** the check runs, **then** a `MEDIUM` finding
  reports the listed URL and a sample of the entries (trimmed).
- **Given** an ordinary page that merely contains a list of links, **then** nothing is
  reported (the signature is the generated-index chrome, not "has links").

**RF-03 — Referenced-resource disclosure** (passive, bounded — spec 004 RF-03 rule)
- **Given** a crawled page references an **in-scope** resource the crawler did not fetch
  and that reference itself points at disclosable content — a `//# sourceMappingURL=` in a
  fetched script, a `<link rel="…">` to a `.map` — **when** the check needs it, **then** it
  fetches it with a `GET` through `ctx.http` (concurrency cap, per-host delay, scope guard
  all apply), bounded by the RF-09 cap.
- **Given** the referenced resource is out of scope (a CDN), **then** it is **not** fetched.
- A `disclosure.sourcemap.exposed` finding for a **referenced** source map is reported
  **regardless of the `probe` toggle** (the target pointed at it). A *guessed* source map
  is RF-07 and needs the toggle.

### Well-known-path probing (opt-in)

**RF-04 — The `probe` toggle**
- **Given** `[disclosure] probe = true` in the config **or** `--probe` on the CLI (CLI
  wins), **when** a scan runs, **then** the probe pass executes. **Given** the default
  (`false` / `--no-probe`), **then** no probe request is issued and probe-only
  `disclosure.*` checks emit nothing; RF-01/RF-02/RF-03 still run.
- The probe pass does **not** require `--mode active` or `--authorized-by`. It issues only
  in-scope `GET` requests, sends no payloads, and makes no state-changing request. When
  enabled it is the most active thing a Safe-Mode scan does (superseding spec 001 RNF-05's
  note about the CORS probe) and the docs (RNF-09) say so.
- **Given** `--probe` together with `--mode active`, **then** both apply independently;
  Active Mode does not by itself enable probing and vice versa (Open question 1).

**RF-05 — Curated path catalogue**
- **Given** a checkout, **then** the catalogue lives at a documented path under
  `src/webvigil/checks/disclosure/data/` as a versioned data file, loaded from disk, never
  downloaded. It is **small** (target 80–150 entries) and grouped by family:
  - **VCS**: `.git/config`, `.git/HEAD`, `.git/index`, `.gitignore`-adjacent leaks,
    `.svn/entries`, `.svn/wc.db`, `.hg/store/00manifest.i`, `.bzr/branch/branch.conf`.
  - **env / server config**: `.env`, `.env.local`, `.env.production`, `.env.development`,
    `.htaccess`, `.htpasswd`, `web.config`, `appsettings.json`, `config.php.bak`,
    `settings.py.bak`, `docker-compose.yml`, `Dockerfile`.
  - **backups / dumps**: for a small set of common basenames (`index`, `db`, `database`,
    `backup`, `dump`, `site`, `www`, and the target host label) with the suffixes `.bak`,
    `.old`, `.orig`, `.save`, `~`, `.swp`, `.zip`, `.tar.gz`, `.tgz`, `.sql`, `.sql.gz`.
  - **debug / admin**: `server-status`, `server-info` (Apache `mod_status`), `actuator`,
    `actuator/env`, `actuator/health`, `actuator/mappings` (Spring Boot), `_profiler`
    (Symfony), `phpinfo.php`, `info.php`, `.git/` (index page), `elmah.axd`,
    `trace.axd` (ASP.NET), `__debug__` / Django-debug-toolbar markers.
  - **manifests**: `package.json`, `composer.json`, `composer.lock`, `Gemfile`,
    `Gemfile.lock`, `yarn.lock`, `pnpm-lock.yaml`, `.npmrc`, `bower.json`.
- **Given** an entry, **then** it carries: the relative path, the `disclosure.*` check id it
  feeds, and a **content-validation rule** (a content regex and/or an expected
  content-type) a response must satisfy to count as a hit (RF-06).
- WebVigil adds **no** probing rules from user config in this spec (parallel to spec 004
  Resolved decision 9). Growing the catalogue = editing the versioned file.

**RF-06 — Soft-404 calibration and hit validation**
- **Given** the probe pass starts, **when** it runs, **then** it first requests one or more
  random, highly-unlikely paths (e.g. `/{32-hex}` and `/{32-hex}.env`) to learn the
  target's "not found" response shape: status code, a body-length band, and salient
  markers (title, a catch-all SPA shell).
- **Given** a probe response, **then** it is a **hit** only when **all** hold: the status
  is success-like for that family (`200`/`206`; `403` counts only for the "`.git/`
  directory index" case); the response does **not** match the soft-404 fingerprint (a
  200-returning SPA catch-all is discarded); and the body satisfies the entry's
  content-validation rule — e.g. `/.git/config` contains `[core]` and
  `repositoryformatversion`; `/.git/HEAD` matches `^ref: refs/`; `/.env` has ≥2 lines
  matching `^[A-Za-z_][A-Za-z0-9_]*=`; `/package.json` parses as JSON containing `name`
  or `dependencies`; `phpinfo.php` contains `<title>PHP ` and `phpinfo()`;
  `/actuator/env` parses as JSON with `propertySources`.
- **Given** the calibration is inconclusive (the target answers `200` for everything and
  content validation cannot disambiguate a family), **then** probing still runs but only
  the strict content rule can produce a finding, and the scan records a warning noting
  reduced confidence (RF-09).

**RF-07 — Derived probes**
- **Given** probing is enabled, **when** the pass runs, **then** for each **in-scope**
  script referenced by a crawled page it also `GET`s `<script-url>.map` and, if the body is
  a valid source map (`{"version": 3, … "sources": [...]}`), reports
  `disclosure.sourcemap.exposed` (`MEDIUM` — leaks original source paths and, when
  `sourcesContent` is present, the source itself).
- **Given** probing is enabled, **when** the pass runs, **then** for the web root **and**
  for each distinct in-scope directory prefix seen in the discovered page URLs (capped, see
  Open question 2), it probes the VCS entries from RF-05.
- All derived probes count against the RF-09 cap.

**RF-08 — Finding shapes**
One check class per family, all `category = DISCLOSURE`, `mode = PASSIVE`:

| Check id | What it reports | Default severity |
|---|---|---|
| `disclosure.vcs.exposed` | reachable `.git` / `.svn` / `.hg` / `.bzr` metadata | `HIGH` |
| `disclosure.config.dotenv-exposed` | reachable `.env` / `.htpasswd` / `appsettings.json` / config backup with secrets | `HIGH` |
| `disclosure.config.manifest-exposed` | reachable `package.json` / `composer.lock` / lockfile / `.npmrc` | `LOW` (`MEDIUM` if `.npmrc` carries a token) |
| `disclosure.backup.file-exposed` | reachable backup / archive / editor swap / source dump (`.sql` dump → `HIGH`) | `MEDIUM` |
| `disclosure.debug.endpoint-exposed` | reachable `server-status` / `actuator*` / `phpinfo` / profiler / `*.axd` (`/actuator/env`, `phpinfo` → `HIGH`) | `MEDIUM` |
| `disclosure.debug.error-page` | stack trace / framework debug page in a crawled response (RF-01) | `MEDIUM` (`HIGH` interactive) |
| `disclosure.listing.directory-index` | server-generated directory listing (RF-02) | `MEDIUM` |
| `disclosure.sourcemap.exposed` | reachable JavaScript source map (RF-03 referenced, RF-07 guessed) | `MEDIUM` |

- **`title`** names the artefact and the URL, e.g. `"Version-control metadata exposed at
  /.git/config"`.
- **`location.url`** is the exact probed/observed URL.
- **`evidence`** carries the detection: the URL, the response status/content-type, and a
  **redacted** snippet of the body (RNF-06) — for `.env` the keys with values replaced by
  `***`, for a manifest the first bytes, for a stack trace the top frames.
- **`remediation`** is family-specific: block dotfiles and VCS dirs at the web server /
  reverse proxy; remove the backup/dump from the web root; disable `autoindex` /
  `mod_status`; set `APP_DEBUG=false` / `DEBUG = False` / `<customErrors mode="On">`;
  restrict `/actuator` to an internal management port.
- **`cwe`** per family: `538` (file/dir information exposure), `527` (VCS repository
  exposure), `548` (directory listing), `215` / `11` (debug information / ASP.NET debug
  left on), `497` (sensitive system information), `200` (general).
- **Deduplication**: `fingerprint` is keyed on `check_id` + the artefact path, **not** the
  page it was linked from, so multi-page sites and re-runs are stable (RNF-04).

**RF-09 — Bounded work and warnings**
- **Given** the number of probe requests (catalogue + derived) would exceed a documented
  cap, **when** the pass runs, **then** it stops at the cap and the scan records a warning
  ("information-disclosure probing stopped at the N-request cap"), not an error (parallel
  to spec 004 RNF-07).
- **Given** the RF-06 calibration was inconclusive, **then** a warning notes the reduced
  confidence.
- Every probe request goes through `ctx.http`, so the concurrency cap, per-host delay,
  scope guard, retries, and `timeout_s` all apply unchanged.

### CLI

**RF-10 — Catalogue, toggle, suppression, summary**
- **Given** `webvigil list-checks`, **then** every `disclosure.*` check appears with
  category `DISCLOSURE`, mode `PASSIVE`, and its default severity.
- **Given** `webvigil scan <url> --probe`, **then** the probe pass runs; **given**
  `--no-probe` or the default, **then** it does not. The equivalent config key is
  `[disclosure] probe`.
- **Given** `[checks] disabled = ["disclosure.vcs.exposed"]` (or any other id), **then**
  that check does not run — same mechanism as every other check. **Given** every
  probe-fed `disclosure.*` check is disabled, **then** the probe pass is skipped entirely
  (no network cost), even with `--probe` (parallel to spec 004 ADR-3); RF-01/02 still run.
- **Given** the human-readable summary (no `--format`) and `--probe`, **then** it includes
  a line such as `"Probed N well-known paths, M exposed"`. Without `--probe` the line is
  omitted.

### Reporting

**RF-11 — Reporters unchanged in shape**
- **Given** a completed scan, **then** `disclosure.*` findings render through the four
  existing reporters with no new section and **no new top-level array** (contrast spec
  004's `technologies` inventory): JSON lists them among `findings`; SARIF emits one `rule`
  per `disclosure.*` check id used, each finding a `result` with the artefact URL as
  `helpUri`/location and the fingerprint in `partialFingerprints`; HTML and Markdown group
  them by severity like any other finding.
- **Given** a saved canonical JSON, **when** `webvigil report scan.json --format …` runs,
  **then** every format re-renders with no network request (spec 001 RF-24, spec 004
  RF-14).

### Web API / Web UI

**RF-12 — No amendment**
- **Given** a scan run through the Web API, **then** `disclosure.*` findings persist and
  are returned by `GET /api/scans/{id}` through spec 002's existing lossless finding
  persistence (RF-19) and schema (RF-25) — **no** migration, **no** schema change, **no**
  new field.
- **Given** the dashboard's scan-detail screen, **then** the findings appear in the
  existing findings list and filters with **no** component change and **no** `openapi.json`
  / `api-types.ts` regeneration.
- This is stated here so the design phase does not reopen it: 005 touches the engine only.
  Contrast spec 004 RF-17/RF-18, which needed a new inventory surface; 005 does not.

### Fixture app and tests

**RF-13 — Disclosure surface in the fixture** (mirrors spec 001 RF-27, spec 004 RF-19)
- **Given** the `tests/fixtures` app's **insecure** profile, **then** it serves, in
  addition to its current surface: `/.git/config` (valid git ini), `/.git/HEAD`, `/.env`
  (fake `KEY=VALUE` secrets), an `Index of /uploads` listing page, a route that returns a
  Werkzeug-style interactive-debugger / stack-trace body, and `/package.json` (valid JSON
  manifest).
- **Given** the **hardened** profile, **then** all of those return `404`, and its error
  route returns a generic trace-free page.
- **Given** an integration scan of the insecure profile **with probing enabled**, **then**
  `disclosure.vcs.exposed`, `disclosure.config.dotenv-exposed`,
  `disclosure.config.manifest-exposed`, `disclosure.listing.directory-index`, and
  `disclosure.debug.error-page` are all reported with the expected ids and severities.
- **Given** an integration scan of the insecure profile **without probing**, **then** only
  the passive-tier findings (`disclosure.debug.error-page`,
  `disclosure.listing.directory-index` — for a listing page that is linked/crawled) are
  reported and **no** probe-only finding appears.
- **Given** an integration scan of the **hardened** profile (probing on **or** off),
  **then** **zero** `DISCLOSURE` findings are reported (false-positive guard).

**RF-14 — Unit tests**
- Soft-404 calibration (learns the fingerprint; a SPA-catch-all `200` is not a hit); per
  family content validation (`.git/config`, `.env`, manifest, `phpinfo`, `/actuator/env`);
  `.env` value redaction (keys kept, values `***`, no secret in the resulting `Finding`);
  derived source-map probe (referenced vs guessed); dedup across pages; the catalogue-cap
  warning — all unit-tested with crafted responses and a small catalogue fixture, not only
  through the integration scan.

### Documentation

**RF-15 — Docs**
- A new `docs/information-disclosure.md`: what the passive tier detects, what the probe
  tier does and **why it is opt-in and does not need Active Mode**, the catalogue and how
  to grow it, the redaction rule, and the limitations (curated list — not content
  discovery; no `.git` exfiltration; no manifest parsing; no active error induction).
- `docs/architecture.md` (the checks-layer bullet), `docs/writing-checks.md` (a note that
  a check may run its own bounded `ctx.http` requests, with the calibration pattern as the
  example), `README.md`'s coverage table, `CLAUDE.md`'s architecture summary, and
  `specs/README.md`'s roadmap are updated; 005 moves `draft → approved → in progress →
  done`.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.checks.disclosure` (plus any helper module) and imports
nothing from `webvigil.cli`, `webvigil.api`, or `web/`. Detection uses the standard library
(`re`, `json`, `hashlib`); no runtime dependency is added. If a new top-level engine
package is introduced, the `import-linter` `source_modules` list is extended.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy` covering the new
modules. **No** `web` gate and **no** API migration test are in scope (RF-12). The Python
`quality` matrix and the `docker` job are otherwise unchanged.

**RNF-03 — Offline and safe against production**
The passive tier issues no requests beyond the crawl. The probe tier, only when enabled,
issues in-scope `GET`s for the curated catalogue and the derived paths — no payloads, no
state-changing requests, no out-of-scope egress. Default off. When on, it is documented as
the most active Safe-Mode behaviour.

**RNF-04 — Determinism**
Given the same target responses and the same catalogue, a scan produces the same findings
and the same fingerprints across runs, with stable ordering in every report. The random
calibration paths do not affect which findings are produced (only that a family is
probed).

**RNF-05 — False-positive discipline**
- A probe hit is reported only after soft-404 calibration **and** per-entry content
  validation (RF-06); a SPA catch-all `200` never produces a finding.
- `confidence` reflects the evidence: exact content match (`.git/config` ini,
  `/actuator/env` JSON) → `HIGH`; a name/status match with a weak body signal → `MEDIUM`.
- The hardened fixture profile yields zero `DISCLOSURE` findings with probing on or off
  (RF-13).

**RNF-06 — Secret hygiene**
Any body that can carry a credential — `.env`, `/actuator/env`, `.npmrc`, a `*.sql` dump, a
config backup — is redacted to non-secret structure (keys, section names, first N bytes
with obvious secret patterns masked) **before** it is placed in a `Finding`. The raw secret
never enters the `ScanResult`, the database, or a report. Unit-tested (RF-14).

**RNF-07 — Bounded work**
Probing (catalogue + derived) is capped at a documented number of requests and by the
existing concurrency/delay policy. A target with many discovered directories cannot
multiply the request count without limit; hitting the cap is a scan warning, not an error.

**RNF-08 — Python support**
Runs on CPython 3.12 and 3.13 (the existing CI matrix).

**RNF-09 — Docs**
Per RF-15. The opt-in nature of probing and its relationship to Safe Mode / Active Mode is
stated explicitly so a user is never surprised by an outbound request.

## Resolved decisions

Settled with Ryan on 2026-09-06:

1. **Probing consent model (RF-04):** an **opt-in flag within Safe Mode**
   (`[disclosure] probe`, `--probe`), default **off**, **not** gated by
   `--mode active --authorized-by`. The requests are non-intrusive in-scope `GET`s; the
   legal-attestation gate is for payload-bearing Active checks. Keeping it off by default
   preserves spec 001's "Safe Mode is nearly invisible" promise; one flag gives pentesters
   the feature.
2. **Catalogue ambition (RF-05):** a **small curated list** (~80–150 entries) of paths that
   are sensitive *by definition*, shipped as a versioned in-repo data file, **not**
   user-extensible in this spec. Not a dirbuster-style content-discovery wordlist.
3. **Exposed manifests (RF-08, Non-goals):** **report-only**. A
   `disclosure.config.manifest-exposed` finding names the file; 005 does **not** parse it,
   enumerate dependencies, or feed spec 004's technology inventory / CVE matching. The
   specs stay decoupled.
4. **Web API / Web UI (RF-12):** **no amendment**. `disclosure.*` findings are ordinary
   `Finding`s and ride spec 002's lossless persistence and spec 003's existing findings
   view unchanged. No migration, no `openapi.json` regen, no dashboard change. 005 is an
   engine-only spec.
5. **Active Mode and probing (RF-04):** **orthogonal**. `--probe` and `--mode active` are
   independent toggles; neither implies the other. Documented as such.
6. **Derived VCS probe breadth (RF-07):** probe the VCS entries at the **web root plus each
   distinct in-scope directory prefix** seen in discovered page URLs, capped at ~10 prefixes
   and counting against the RF-09 request cap.
7. **`robots.txt` / `sitemap.xml` path disclosure:** **out of scope for 005** — a
   `Disallow:` entry is a weak, noisy signal. No `disclosure.hints.*` finding. Revisit if
   requested later.
8. **Partial VCS exposure severity (RF-08):** `HIGH` when **any** of `.git/HEAD`,
   `.git/config`, or `.git/index` validates — source and history are recoverable either way.
9. **Catalogue file format (RF-05):** **TOML** — human-diffable, comments allowed, and the
   per-entry content-validation rule fits a table cleanly. Consistent with
   `webvigil.example.toml` and the config model.

## Open questions

None. Ready for `/spec design`.
