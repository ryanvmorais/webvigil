---
feature: OSV.dev online advisory provider — opt-in known-vulnerability lookup for the dependency fingerprint
status: done
date: 2026-09-07
related:
  - 010-osv-online/requirements.md
  - 010-osv-online/design.md
origin: conception
---

# 010 — OSV.dev online advisory provider — Tasks

Ordered, small, each tagged with the requirement it satisfies. The last task of every stage
is the quality gate (`ruff → black → mypy src → lint-imports → pytest`). No `web` gate
(Resolved decision 5 / RNF-03). Tasks are `[ ]` until done; `/spec implementar` marks them
`[x]` one by one and records the pytest count on each gate line. Baseline at spec 008
close: **536 passed**.

## Stage 0 — `[deps]` config section

- [x] `webvigil/core/config.py`: add `DepsSection(_Section)` with `osv_online: bool = False`,
  `osv_timeout_s: float = 10.0`, `osv_base_url: str = "https://api.osv.dev"` and the
  "only opt-in that reaches a non-target host" docstring. Add `deps: DepsSection =
  DepsSection()` to `ScanConfig` (after `injection`). Add `deps` to the section list in the
  `with_overrides` docstring. — RF-01, RF-02, ADR-6
- [x] `webvigil.example.toml`: add a `[deps]` block after `[injection]` — commented
  `osv_online = false` ("look up detected libraries against OSV.dev; sends library names +
  versions to api.osv.dev; CLI: --osv-online"), plus `osv_timeout_s` / `osv_base_url` shown
  commented at their defaults. — RF-02
- [x] Tests (`test_config.py`): `[deps]` defaults (`osv_online False`, timeout `10.0`, base
  url); round-trips through `model_dump` → `model_validate`; an `osv_online` override wins
  over a file value; an unknown `[deps]` key raises `ConfigError`. — RF-02, RNF-05
- [x] Quality gate. — 539 passed; ruff/black/mypy/lint-imports green.

## Stage 1 — `Observations.osv_advisories` + `merge_advisories`

- [x] `webvigil/core/context.py`: add `osv_advisories: Mapping[tuple[str, str],
  tuple[Advisory, ...]] = field(default_factory=dict)` to `Observations` (import `Advisory`
  under `TYPE_CHECKING`, string annotation, like `probe_hits` / `injection_hits`). Update
  the `Observations` docstring. — ADR-2
- [x] `webvigil/checks/deps/advisories.py`: add `merge_advisories(*groups: Iterable[Advisory])
  -> list[Advisory]` — coalesce advisories that share ≥1 identifier; deterministic, input
  order preserved. Add `_coalesce(bucket)` — first-seen-order de-duped `identifiers`,
  `max` severity, `severity_from_upstream = any(...)`, highest non-null `first_safe_version`
  (`numeric_version_key`), first non-empty `summary` (join distinct with `" / "`), union
  `info_urls` / `cwe` order-stable. A one-element bucket returns its advisory unchanged. —
  RF-08, ADR-1
- [x] Tests (`test_deps_advisories.py` additions): shared-CVE pair → one coalesced advisory
  (union ids/urls/cwe, top severity, highest safe version); disjoint pair → two; a
  three-advisory transitive chain (A~B, B~C) → one bucket; single-source passthrough;
  ordering is stable across input permutations of non-overlapping advisories. — RF-08, RNF-04
- [x] Quality gate. — 544 passed; ruff/black/mypy/lint-imports green.

## Stage 2 — `webvigil/checks/deps/osv.py`

- [x] New module. `OsvLookupError(Exception)`. `OsvResult` (frozen slots — `advisories:
  dict[tuple[str, str], tuple[Advisory, ...]]`, `warnings: tuple[str, ...] = ()`).
  `_ECOSYSTEM = "npm"`, `_QUERYBATCH_CAP = 1000`. — RF-04, ADR-3
- [x] `_NPM_NAME: dict[str, str]` — curated map (`angularjs→angular`, `jquery.ui→jquery-ui`,
  `mustache.js→mustache`, `handlebars.js→handlebars`, `prototypejs→prototype`,
  `ember→ember-source`, `ckeditor→ckeditor4`, … seed from the vendored component list) and
  `_npm_name(name) -> str` (map or verbatim). — RF-05
- [x] `_cvss3_base(vector: str) -> float | None` — CVSS 3.0/3.1 base-score formula, pure,
  returns `None` on a non-v3 / malformed vector. `_band(score: float) -> Severity`
  (`0.1–3.9 LOW`, `4.0–6.9 MEDIUM`, `7.0–8.9 HIGH`, `9.0–10.0 CRITICAL`). — RF-07, ADR-5
- [x] `_severity(record) -> tuple[Severity, bool]` — `database_specific.severity` (GHSA
  band, `MODERATE→MEDIUM`) → `(mapped, True)`; else first `CVSS_V3`/`CVSS_V4` entry via
  `_cvss3_base` + `_band` → `(banded, True)`; else `(_DEFAULT_SEVERITY, False)`. — RF-07
- [x] `_to_advisory(record, *, detected_version) -> Advisory` — identifiers (`id` first,
  then `aliases`, de-duped); `summary` (`summary` → first sentence of `details` ≤200 →
  `""`); `_severity`; `first_safe_version` (lowest `fixed` across `affected[]` entries
  matching `(npm, name)` that is `> detected_version` via `_lt`; `None` otherwise);
  `info_urls` (`references[].url` + `https://osv.dev/vulnerability/{id}`, de-duped); `cwe`
  (`database_specific.cwe_ids` `"CWE-79"→79`). Read defensively — a per-record
  `KeyError`/`TypeError` skips that record. — RF-06, RNF-05
- [x] `OsvProvider.__init__(base_url, timeout_s, *, user_agent, transport=None)` and
  `async def lookup(self, detections: Sequence[Detection]) -> OsvResult`:
  - distinct `(name, version)` with `version is not None`; in-scan memoisation. — RF-11
  - `_npm_name` each; `POST {base_url}/v1/querybatch` `{queries:[{package:{name,ecosystem},
    version}]}`, chunked at `_QUERYBATCH_CAP`; result list is position-aligned. — RF-04
  - per query with ≥1 returned id: `POST {base_url}/v1/query` `{package, version}` →
    `{"vulns":[record,…]}`; `_to_advisory` each; group under the **webvigil** `(name,
    version)` key. — RF-04, ADR-3
  - `httpx.AsyncClient(base_url=…, timeout=timeout_s, headers={"user-agent": user_agent},
    transport=transport)`; any `httpx.HTTPError` / JSON / top-level schema error →
    `raise OsvLookupError(reason)`; a per-package `/v1/query` failure after a good
    `querybatch` → keep the rest, append a warning. — RF-09, ADR-4
- [x] Tests (`test_deps_osv.py`, new) with `httpx.MockTransport`:
  - normaliser: all `Advisory` fields from a recorded GHSA record and a recorded CVE-only
    record; missing `summary` → `details` fallback; `cwe_ids` parsed; canonical osv.dev URL
    appended. — RF-06
  - severity: each GHSA band incl. `MODERATE`→MEDIUM; a known CVSS v3 vector → expected
    band (use the CVSS spec's worked examples); no severity → `(MEDIUM, False)`; a v2
    vector → `(MEDIUM, False)`. — RF-07
  - `first_safe_version`: single `fixed`; multiple ranges → lowest `> detected`;
    `last_affected`-only → `None`; a non-matching `affected.package` ignored. — RF-06
  - name map: `angularjs→angular`; unmapped passthrough; **every** vendored component name
    (`RetireJsRules.load()` components) resolves to a non-empty npm name. — RF-05
  - provider I/O: all-clean `querybatch` → **zero** `/v1/query` calls; one hit → exactly one
    follow-up; a `(name, version)` repeated across detections → one query (memoisation);
    transport 500 / connect-timeout / non-JSON body → `OsvLookupError`; a partial
    `/v1/query` failure → kept results + a warning string. — RF-04, RF-09, RF-11
- [x] Quality gate. — 574 passed; ruff/black/mypy/lint-imports green.

## Stage 3 — check merge + orchestrator pass

- [x] `webvigil/checks/deps/check.py`: in `VulnerableLibraryCheck.run`, replace
  `advisories = provider.match(detection.name, detection.version)` with
  `advisories = merge_advisories(provider.match(detection.name, detection.version),
  ctx.observations.osv_advisories.get((detection.name, detection.version), ()))`. Nothing
  else changes (identifiers, `add_technology`, `_finding`). `LibraryDetectedCheck`
  untouched. — RF-08, RF-15
- [x] `webvigil/core/orchestrator.py`: `from webvigil.checks.deps.osv import OsvLookupError,
  OsvProvider`. Add `async def _osv_lookup(self, check_types, detections, warnings) ->
  dict[tuple[str, str], tuple[Advisory, ...]]` — `{}` unless `config.deps.osv_online`
  **and** a `Category.DEPS` check is selected **and** ≥1 version-known detection;
  `OsvProvider(config.deps.osv_base_url, config.deps.osv_timeout_s,
  user_agent=config.http.user_agent).lookup(versioned)` in `try/except OsvLookupError` →
  the RF-09 warning + `{}`; on success `warnings.extend(result.warnings)` and return
  `result.advisories`. Call it in `run()` right after the `_fingerprint` line; pass
  `osv_advisories=…` into `Observations(...)`. — RF-01, RF-03, RF-09, RF-10, ADR-2
- [x] Tests (`test_deps_orchestrator.py` additions):
  - flag off → `OsvProvider` never constructed (`monkeypatch` a boom); — RF-01
  - flag on + only a non-DEPS check → not constructed; flag on + DEPS check but no versioned
    detection → `lookup` not called; — RF-03
  - flag on → a stubbed `OsvProvider` map reaches `Observations` and the check emits a
    finding for an OSV-only advisory + inventory `vulnerable=True`; — RF-08
  - a stub raising `OsvLookupError` → the RF-09 warning, Retire.js-only findings still
    present, no crash. — RF-09
- [x] Tests (`test_checks_deps.py` additions): `observations.osv_advisories` preset →
  merged finding severity is the `max` of the two sources; an OSV advisory whose CVE
  matches a Retire.js one → a single finding, identifiers unioned. — RF-08
- [x] Quality gate. — 580 passed; ruff/black/mypy/lint-imports green.

## Stage 4 — CLI

- [x] `webvigil/cli/app.py`: `scan` gains `osv_online: Annotated[bool | None,
  typer.Option("--osv-online/--no-osv-online", help="Look up detected libraries against
  OSV.dev (sends library names + versions to api.osv.dev). Off by default.")] = None`.
  `_build_config` gains `osv_online: bool | None`; build `deps_overrides` and fold
  `{"osv_online": osv_online}` when not `None`; add `deps=deps_overrides` to the
  `with_overrides(...)` call. Pass `osv_online=cfg.deps.osv_online` into `_emit`. — RF-01
- [x] `webvigil/cli/_render.py`: `summary(result, *, cookie_count=0, osv_online=False)` —
  after the "Detected N client-side libraries" block, when `osv_online and
  result.technologies`, print `"[dim]Advisory sources: offline database + OSV.dev[/]"`.
  `app.py` `_emit` threads `osv_online` through both `_render.summary` call sites. — RF-13
- [x] Tests (`test_cli.py` additions): `--osv-online` → `cfg.deps.osv_online is True` over a
  config file that set it `false`; `--no-osv-online` → `False`; default → file value; the
  summary prints the "Advisory sources" line when on with an inventory and omits it when
  off; `list-checks` output unchanged (still two `deps.*` ids). — RF-01, RF-13, RF-15
- [x] Quality gate. — 582 passed; ruff/black/mypy/lint-imports green.

## Stage 5 — Integration tests

- [x] `tests/integration/test_scan_fixture_app.py`: `scan` fixture `_run` gains `osv_online:
  bool = False`; when set, `raw["deps"] = {"osv_online": True, "osv_base_url":
  "http://osv.test"}` and `monkeypatch.setattr(orch_mod, "OsvProvider",
  functools.partial(OsvProvider, transport=httpx.MockTransport(_osv_handler)))`. Add
  `_osv_handler` returning a canned `querybatch` (a hit for the fixture's vulnerable jQuery
  version, clean for anything else) + a canned `/v1/query` full record; a second handler
  `_osv_down` returning 503. — RF-16
- [x] Tests: `test_osv_online_adds_the_osv_id_to_the_jquery_finding` (the
  `deps.js.vulnerable-library` finding's references include an `osv.dev/vulnerability/`
  URL); `test_osv_online_hardened_profile_still_reports_no_deps_findings`;
  `test_osv_outage_warns_and_falls_back_to_the_offline_database` (`_osv_down` →
  "OSV.dev lookup failed" warning, jQuery finding still present from Retire.js);
  `test_osv_online_scan_is_deterministic` (two runs → identical findings + fingerprints);
  `test_osv_not_queried_without_the_opt_in` (no request to `osv.test` in the handler call
  log). — RF-16, RNF-04
- [x] Quality gate. — 587 passed; ruff/black/mypy/lint-imports green.

## Stage 6 — Docs, roadmap, verification, close

- [x] `docs/dependency-fingerprinting.md`: new "## OSV.dev online provider (`--osv-online`)"
  section — what it queries (`querybatch` then per-package `/v1/query`, `npm` ecosystem),
  the opt-in and default-off, the exact data that leaves the machine (names + versions to
  `api.osv.dev`), no persistent cache, graceful degradation, and the limitations (npm only,
  no reachability, name-map best effort). Update the "No online lookups" bullet under "What
  it does not do" to "Online lookups are opt-in via `--osv-online` (OSV.dev); off by
  default, the match stays fully offline." — RNF-07, RNF-09
- [x] `README.md`: coverage table `v0.10` row (OSV.dev online advisory provider, opt-in,
  link to the docs section); a `--osv-online` quick-start line under the dependency example.
  `CLAUDE.md`: layer-3 `webvigil.checks.deps` paragraph gains the OSV provider (opt-in
  `--osv-online` / `[deps] osv_online`, augments the vendored Retire.js match, one host);
  `Estado` line → `010-osv-online` concluída, remaining = `009-ssrf`. `specs/README.md`:
  roadmap row `010-osv-online` → **done** (`v0.10`) with the link; adjust the `>` note that
  lists the two remaining tech-debt specs. — RNF-09
- [x] Set all three `010` spec files to `status: done`; add an "Implementation notes"
  section to `design.md` (final `_NPM_NAME` contents, the CVSS parser's real coverage,
  whether `querybatch` pagination was ever needed, the pytest delta, anything that shifted
  from the design). — RNF-09
- [x] Manual verification: `uvicorn tests.fixtures.serve:app` (or a real target with a known
  outdated library) — `webvigil scan … --osv-online` against a stack with an outdated jQuery
  shows the `deps.js.vulnerable-library` finding carrying an `osv.dev/vulnerability/` link
  and the "Advisory sources: offline database + OSV.dev" summary line; the same scan with
  `--no-osv-online` omits both; point `--osv-online` at a scan where `osv_base_url` is
  unreachable and confirm the "OSV.dev lookup failed" warning with the offline finding still
  reported. Record what was sent (names + versions only) from a request capture. — RNF-02, RNF-07
- [x] Final full quality gate: ruff / black / mypy / lint-imports (contracts unchanged) /
  pytest — 587 passed. — RNF-03
