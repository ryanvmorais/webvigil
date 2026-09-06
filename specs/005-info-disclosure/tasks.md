---
feature: Information disclosure — exposed files/routes, directory listing, stack traces, debug endpoints
status: done
date: 2026-09-06
related: [005-info-disclosure/requirements.md, 005-info-disclosure/design.md]
origin: conception
---

# 005 — Information disclosure — Tasks

Ordered, small tasks grouped by stage. Each references the requirement(s) / ADR(s) it
satisfies. The last task of every stage is a quality gate: `/qualidade-python`
(`ruff → black → mypy → pytest`) **+** `uv run lint-imports`.

**No `web` stage** — 005 touches nothing under `web/`, `webvigil.reporting`, or
`webvigil.api` (RF-11, RF-12). Write failing tests first where it pays (`signatures`,
`catalogue`, `redaction`, `probe`, the checks). All new code lives in
`src/webvigil/checks/disclosure/**` and four files under `src/webvigil/core/**` plus
`src/webvigil/cli/**`.

---

## Stage 0 — Category, config, catalogue data file, packaging

- [x] `webvigil/core/findings.py`: replace the `# Reserved … DISCLOSURE …` comment with
  `DISCLOSURE = "DISCLOSURE"` and leave `# Reserved for later specs: INJECTION.`. — RF-08
- [x] `webvigil/core/config.py`: add `class DisclosureSection(_Section)` with `probe: bool =
  False`; `ScanConfig` gains `disclosure: DisclosureSection = DisclosureSection()`. — RF-04
- [x] `webvigil.example.toml`: document `[disclosure] probe = false` with the "opt-in,
  GET-only, in-scope, unrelated to Active Mode, noisier than the default scan" note. — RF-04, ADR-6
- [x] `src/webvigil/checks/disclosure/__init__.py` + `data/` package; write
  `data/paths.toml`: `[[entry]]` tables (path, family, check, severity, title, and a
  validator — `content` regex + optional `min_matches`, `content_type`, `json_keys`, or
  `magic` — plus optional `redact` / `ok_status`) for the **vcs**, **config**, **manifest**,
  and **debug** families, and a `[backups]` table (`basenames`, `suffixes`). — RF-05, ADR-4
- [x] `pyproject.toml`: `[tool.hatch.build.targets.wheel].artifacts +=
  "src/webvigil/checks/disclosure/data/*.toml"`. — design §Impact
- [x] Tests: `ScanConfig` round-trips `[disclosure] probe`; an unknown `[disclosure]` key is
  a `ConfigError`; the CLI override wins. — RF-04, RF-08
- [x] Quality gate. — 228 passed; ruff/black/mypy/lint-imports green.

## Stage 1 — Error-page and directory-listing signatures + passive checks

- [x] `webvigil/checks/disclosure/signatures.py` (pure data, no I/O): `ErrorSignature`
  (frozen: `framework`, compiled `pattern`, `interactive: bool`, `severity`) + `ErrorMatch`,
  `ERROR_SIGNATURES` for Werkzeug (interactive), Django `DEBUG`, Rails, ASP.NET
  yellow-screen, PHP fatal + PHP notice, Java/JSP, Node/Express, generic Python traceback;
  `LISTING_SIGNATURES` (Apache, nginx, `http.server`). `match_error(body) -> ErrorMatch |
  None` (with a trimmed snippet), `is_directory_listing(body) -> bool`. — RF-01, RF-02
- [x] `webvigil/checks/disclosure/errors.py`: `ErrorPageCheck`
  (`id="disclosure.debug.error-page"`, `Category.DISCLOSURE`, `PASSIVE`,
  `default_severity=MEDIUM`, `cwe=(215, 200)`) — iterate `ctx.pages`, one finding per
  framework (`dedup_key=framework`), severity/confidence from the signature, evidence = the
  marker snippet. — RF-01
- [x] `webvigil/checks/disclosure/listing.py`: `DirectoryListingCheck`
  (`id="disclosure.listing.directory-index"`, `MEDIUM`, `cwe=(548, 200)`) — one finding per
  listed URL (`dedup_key=path`), evidence = a sample of the entries. — RF-02
- [x] Register both in `disclosure/__init__.py`; add `disclosure` to
  `webvigil/checks/__init__.py`'s `_load_builtin_checks`. — RF-10
- [x] Tests: `test_disclosure_signatures.py` (each signature fires on its sample, generic
  page does not match, listings true/false); `test_checks_disclosure_passive.py` (Werkzeug
  → HIGH, trace → MEDIUM, dedup per framework, quiet on a clean page, listing one-per-url). — RF-01, RF-02, RNF-05
- [x] Quality gate. — 247 passed; ruff/black/mypy/lint-imports green.

## Stage 2 — Catalogue loader

- [x] `webvigil/checks/disclosure/catalogue.py`: `ProbeEntry` (frozen), `Validator`
  (`content` regex + `min_matches`, `content_type`, `json_keys`, `magic` — any passes),
  `load_catalogue() -> tuple[ProbeEntry, ...]` (`lru_cache`, `tomllib`,
  `importlib.resources`), `backup_spec()` + `build_backup_entry()` for the host-label
  expansion. `[backups]` → basename × suffix cross-product (`.sql`/`.sql.gz` → HIGH, rest
  MEDIUM; archives validated by magic bytes, `.sql` by dump markers, editor/`.bak` by
  source/secret markers). — RF-05, ADR-4
- [x] Tests (`test_disclosure_catalogue.py`): `load_catalogue()` parses the shipped file,
  ≥60 entries, every `check_id` in `PROBE_CHECK_IDS`, every family present, backups expanded,
  `.git/` allows `403`, `.env` needs 2 KV lines, JSON/magic validators, `build_backup_entry`,
  every regex compiles (parametrized over the catalogue). — RF-05, Risks
- [x] Quality gate. — 332 passed; ruff/black/mypy/lint-imports green.

## Stage 3 — Redaction

- [x] `webvigil/checks/disclosure/redaction.py`: `apply(strategy, body) -> str` with
  `dotenv` (keep keys + comments, values → `***`), `json-env` (recursive scrub — keep
  property names, mask secret-named keys + high-entropy leaf strings), `generic` (first
  1 KB, `_SECRET_RE` masks AWS/GitHub/Slack/JWT/PEM/long-b64/long-hex), `none` (first 1 KB,
  structure kept). All length-bounded. — RNF-06, ADR-9
- [x] Tests (`test_disclosure_redaction.py`): dotenv keeps keys hides values; json-env
  keeps `propertySources` masks values; generic kills `AKIA…` / long hex / PEM; every
  strategy bounded. — RNF-06
- [x] Quality gate. — ruff/black/mypy green; redaction tests pass.

## Stage 4 — DisclosureProbe

- [x] `webvigil/checks/disclosure/probe.py`: constants, `ProbeHit` (frozen, redacted body
  only), `ProbeReport` (`hits`, `paths_probed`, `warnings`), `_Soft404`,
  `DisclosureProbe(http, target, catalogue, pages)`. — RF-04, RF-09, ADR-1
- [x] Calibration: `GET` 3 `secrets.token_hex` URLs (one `.env` suffix, one trailing `/`);
  `_Soft404` = statuses + body lengths + SPA-shell hashes; `looks_missing` = hash match, or
  same 4xx/5xx status, or same-2xx-status with a length band (only for bodies ≥256 B).
  Inconclusive (all distinct 2xx) → warning + validators only. — RF-06, ADR-5
- [x] Request list: catalogue under `target.origin`; host-label backups; `<script>.map` for
  each in-scope `.js` referenced by crawled HTML; `vcs` entries re-based under each
  discovered dir prefix (cap 10). De-dup by URL, truncate at `_REQUEST_CAP` + warning. — RF-05, RF-07, RF-09, ADR-8
- [x] Fetch via `http.get` (policy applies), swallow failures; hit iff `status in
  ok_status` **and** not `looks_missing` **and** validator passes (a `403` on a `.git/`
  entry bypasses the content validator at MEDIUM confidence). Redact before building the
  `ProbeHit`. — RF-06, RNF-03, RNF-06, ADR-9
- [x] Tests (`test_disclosure_probe.py`, `pytest-httpx`): clean-404 → validated
  `/.git/config` is a hit, random 200 is not; SPA 200-for-all → only content-validated
  hits; inconclusive calibration → warning + still validates; `_REQUEST_CAP` monkeypatched
  → truncation warning; in-scope `<script>.map` → sourcemap hit, CDN script not requested;
  `.git/` 403 → MEDIUM-confidence hit; run twice → identical hits. — RF-06, RF-07, RF-09, RNF-04
- [x] Quality gate. — 344 passed; ruff/black/mypy/lint-imports green.

## Stage 5 — Probe-fed checks + `Observations.probe_hits`

- [x] `webvigil/core/context.py`: `Observations` gains `probe_hits: tuple[ProbeHit, ...] =
  ()` (`ProbeHit` imported under `TYPE_CHECKING`, as `HttpClient` already is). — ADR-3
- [x] `webvigil/checks/disclosure/checks.py`: `_ProbeFedCheck` base (`family` ClassVar,
  `Category.DISCLOSURE`, `PASSIVE`, `run` filters `ctx.observations.probe_hits` by
  `family` → `self.finding(...)` with severity/confidence from the hit, `dedup_key=hit.path`,
  evidence = `HTTP {status} · {content_type}` + redacted body, remediation from
  `_REMEDIATION[family]`, class-level `references` per family); the six `@register`
  subclasses with the design's ids / severities / CWEs. — RF-08, RF-10
- [x] Register the six in `disclosure/__init__.py`. — RF-10
- [x] Tests (`test_checks_disclosure_probe_fed.py`): each check emits only its family;
  severity from the hit not the class default; no hits → no findings; `dedup_key=path`
  (two `.git/config` at different prefixes → two fingerprints); redacted body in evidence;
  all eight `disclosure.*` ids registered under `Category.DISCLOSURE`. — RF-08, RF-10, RNF-06
- [x] Quality gate. — 349 passed; ruff/black/mypy/lint-imports green.

## Stage 6 — Orchestrator wiring

- [x] `webvigil/core/orchestrator.py`: `_PROBE_FAMILIES` frozenset; `_probe_disclosure(
  check_types, http, target, pages, warnings)` — `()` unless `config.disclosure.probe`
  **and** a selected check has `family in _PROBE_FAMILIES`; else
  `DisclosureProbe(http, target, load_catalogue(), pages).run()`, extend `warnings`,
  return `report.hits`. Wired after `_fingerprint`; `probe_hits` passed into
  `Observations(...)`. — RF-04, ADR-1, ADR-2
- [x] Tests (`test_disclosure_orchestrator.py`): `probe=false` → `DisclosureProbe`
  monkeypatched to raise, never called; `probe=true` + only a non-probe-fed disclosure
  check → same; `probe=true` + probe-fed check → `/.git/config` finding emitted;
  `_REQUEST_CAP` monkeypatched → the cap warning reaches `result.warnings`. — RF-04, RF-09, ADR-2
- [x] Quality gate. — 353 passed; ruff/black/mypy/lint-imports green.

## Stage 7 — CLI

- [x] `webvigil/cli/app.py`: `scan` gains `--probe/--no-probe` (`bool | None = None`);
  `_build_config` gains `probe: bool | None` → `disclosure={"probe": probe}` override when
  not `None`. `--probe` does not touch `[active]` or the Active gate. — RF-04, RF-10, ADR-6
- [x] `webvigil/cli/_render.py`: `summary()` prints `"Information disclosure: N exposed
  path(s) found"` counting `disclosure.*` findings that are not `error-page` /
  `directory-index`. — RF-10, ADR-7
- [x] Tests (in `test_cli.py`): `--probe` sets `config.disclosure.probe`; `--no-probe`
  overrides a `true` file; `--probe` alone exits 0 (no Active gate); the summary line;
  `list-checks` shows the disclosure ids + `DISCLOSURE`. — RF-04, RF-10
- [x] Quality gate. — 358 passed; ruff/black/mypy/lint-imports green.

## Stage 8 — Fixture app and integration tests

- [x] `tests/fixtures/app.py`: the **insecure** profile also serves `/.git/config`,
  `/.git/HEAD`, `/.env` (fake secrets), `/uploads/` (`Index of /uploads`, linked), `/boom`
  (Werkzeug-style debugger body, linked), `/package.json`; routes added only for
  `profile == "insecure"`. Hardened is unchanged (404s them all). — RF-13
- [x] Integration test (`test_scan_fixture_app.py`): insecure + `probe=True` →
  `disclosure.vcs.exposed` / `config.dotenv-exposed` / `config.manifest-exposed` /
  `listing.directory-index` / `debug.error-page` all present; the `.env` evidence has
  `SECRET_KEY` but not the secret value; `result.errors == ()`. — RF-13, RNF-06
- [x] Integration test: insecure + `probe=False` → only `debug.error-page` +
  `listing.directory-index`; hardened (probe on **and** off) → zero findings; the insecure
  probe scan run twice → identical `(check_id, fingerprint)` set. — RF-13, RNF-04, RNF-05
- [x] The spec 001 `test_hardened_profile_reports_nothing` now loops `probe` on/off; still
  zero. — RF-13
- [x] Quality gate. — 361 passed; ruff/black/mypy/lint-imports green.

## Stage 9 — Docs, roadmap, verification, close

- [x] `docs/information-disclosure.md` (new): the two tiers, why probing is opt-in and not
  Active-gated, calibration + content validation, redaction, the catalogue, the limitations
  (curated list not content discovery; no `.git` exfiltration; no manifest parsing; no
  active error induction; source maps need `--probe`). — RF-15, RNF-09
- [x] `docs/architecture.md` (DISCLOSURE bullet + specs list), `docs/writing-checks.md`
  (`probe_hits` + orchestrator-pass `ctx.http` + calibration note), `README.md` (coverage
  table v0.5 shipped + `--probe` quick-start line), `CLAUDE.md` (checks layer +
  Estado → next is `006-active-injection`). — RF-15, RNF-09
- [x] `specs/README.md`: `005-info-disclosure` → **done**; all three spec files
  `status: done`; design "Implementation notes" filled. — RNF-09
- [x] Manual verification: `webvigil scan http://127.0.0.1:9207/ --probe --format md` on the
  insecure fixture shows `.env` / `.git/config` / `.git/HEAD` (HIGH), `package.json` (LOW),
  Werkzeug debugger (HIGH), directory listing (MEDIUM), and the summary line "Information
  disclosure: 4 exposed paths found"; without `--probe` only the Werkzeug + listing
  findings; the `.env` evidence is `SECRET_KEY=***` etc. (no secret value); `list-checks`
  shows all eight ids. — RF-11, RF-12
- [x] Final full quality gate: 361 passed; ruff / black / mypy (79 files) / lint-imports
  (2 contracts KEPT) green. No `web/` change (0 files).
