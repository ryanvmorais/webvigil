---
feature: In-band SSRF detection — cloud metadata, loopback/internal, file:// (Active Mode)
status: done
date: 2026-09-07
related:
  - 009-ssrf/requirements.md
  - 009-ssrf/design.md
origin: conception
---

# 009 — In-band SSRF detection — Tasks

Ordered, small, each tagged with the requirement it satisfies. The last task of every stage
is the quality gate (`ruff → black → mypy src → lint-imports → pytest`). No `web` gate, no
config/CLI change (Resolved decisions 2, 5 / RNF-01). Tasks are `[ ]` until done; `/spec
implementar` marks them `[x]` one by one and records the pytest count on each gate line.
Baseline at spec 010 close: **587 passed**.

## Stage 0 — Payloads, signatures, `is_urllike`

- [x] `webvigil/checks/injection/payloads.py`: add the SSRF section — `SSRF_METADATA`,
  `SSRF_FILE`, `SSRF_INTERNAL` payload tuples (`{host}` templated, as the redirect payloads
  are) and `SSRF_METADATA_SIGNATURES`, `SSRF_INTERNAL_SIGNATURES`, `SSRF_ERROR_SIGNATURES`
  compiled-regex tuples, with the design's comments. `file://` detection reuses the
  existing `TRAVERSAL_SIGNATURES` — no new `/etc/passwd` regex. — RF-03, RF-04, RF-05, RF-06, RF-07
- [x] `webvigil/checks/injection/points.py`: add `_URLLIKE_NAMES`, `_URLLIKE_VALUE`, and
  `def is_urllike(point: InjectionPoint) -> bool` (name in the set **or** value matches the
  URL regex). — RF-02
- [x] Tests (`test_injection_points.py` additions): `is_urllike` true for `url` / `callback`
  / `next` names and for `http://…` / `//…` values; false for a plain `q=hello`. — RF-13
- [x] Quality gate. — 588 passed; ruff/black/mypy/lint-imports green.

## Stage 1 — The `ssrf` detector

- [x] `webvigil/checks/injection/detect/ssrf.py` (new): `_METADATA_ID`, `_INTERNAL_ID`,
  `_GATEWAY_STATUS = frozenset({502, 503, 504})`, and `async def detect(point, baseline,
  ctx) -> list[InjectionHit]` — iterate `SSRF_METADATA` → `SSRF_FILE` → `SSRF_INTERNAL`,
  substitute `{host}` from `ctx.host`, `await ctx.send(point, payload)`, stop on `None`,
  return `[hit]` on the first of `_metadata_hit` / `_file_hit` / `_internal_hit` /
  `_error_hit`. — RF-01, RF-08
- [x] `_metadata_hit` — per `(provider, pattern)` in `SSRF_METADATA_SIGNATURES`: present in
  `response.text`, absent from `baseline.raw_body` → `InjectionHit(kind="ssrf-metadata",
  check_id=_METADATA_ID, severity=CRITICAL, confidence=HIGH, title=f"SSRF to the {provider}
  instance metadata service via '{point.param}'", …)`, evidence = point line + payload +
  marker snippet. — RF-03, RF-08
- [x] `_file_hit` — only when `payload.lower().startswith("file:")`; per pattern in
  `payloads.TRAVERSAL_SIGNATURES`: present, baseline-absent → `kind="ssrf-internal"`,
  `severity=HIGH`, `confidence=HIGH`, `title=f"SSRF local file read (file://) via
  '{point.param}'"`, evidence includes the leaked line. — RF-04, RF-08
- [x] `_internal_hit` — per `(service, pattern)` in `SSRF_INTERNAL_SIGNATURES`: present,
  baseline-absent → `kind="ssrf-internal"`, `severity=HIGH`, `confidence=HIGH`,
  `title=f"SSRF to an internal service ({service}) via '{point.param}'"`. — RF-05, RF-08
- [x] `_error_hit` — `_authority(payload)` (text between `://` and next `/`, minus any
  `user@`) must be non-empty **and** present in `response.text`; then a baseline-absent
  `SSRF_ERROR_SIGNATURES` match **or** (`response.status_code in _GATEWAY_STATUS` and
  `!= baseline.status`) → `kind="ssrf-internal"`, `severity=HIGH`, `confidence=MEDIUM`,
  `title=f"SSRF — the '{point.param}' parameter is fetched server-side"`. No URL echo → no
  hit. — RF-06, RF-08, ADR-4
- [x] `_point_evidence`, `_snippet`, `_authority`, `_first_match` helpers — mirror
  `detect/sqli.py` / `detect/traversal.py` style. — RF-08
- [x] Tests (`test_injection_ssrf.py`, new) with a stub `send` returning canned `Response`s:
  each metadata provider → CRITICAL `ssrf-metadata`; `file:///etc/passwd` → HIGH
  `ssrf-internal` with the leaked line; Redis / nginx fingerprint → HIGH `ssrf-internal`;
  SSRF error + URL echo → MEDIUM; `502` + URL echo → MEDIUM; generic `500` no echo → no
  hit; payload echoed but no marker → no hit; signature already in the baseline →
  suppressed; `{host}` substituted from `ctx.host`; first hit wins; `send` → `None` stops
  the detector. — RF-13
- [x] Quality gate. — 600 passed; ruff/black/mypy/lint-imports green.

## Stage 2 — Engine wiring

- [x] `webvigil/checks/injection/engine.py`: `from webvigil.checks.injection.detect import
  ssrf as ssrf_detect`; add `is_urllike` to the `points` import; `_DETECTORS["ssrf"] =
  ssrf_detect.detect`; `_BASE_ORDER = ("xss", "sqli-error", "sqli-boolean", "traversal",
  "redirect", "ssrf", "sqli-time")`; `KIND_BY_CHECK_ID` gains
  `"injection.ssrf.metadata": "ssrf"` and `"injection.ssrf.internal": "ssrf"` (with a
  one-line comment: two ids, one detector); `_ordered_kinds` gains `(is_urllike, "ssrf")`
  in the front-load loop. — RF-01, RF-02, RF-11, ADR-2, ADR-5
- [x] Tests (`test_injection_engine.py` additions): `"ssrf"` in `_BASE_ORDER` and
  `_DETECTORS`; both ssrf ids map to `"ssrf"` in `KIND_BY_CHECK_ID`; `_ordered_kinds` puts
  `ssrf` first for a `url` point and omits it when neither ssrf kind is selected. — RF-11
- [x] Quality gate. — 603 passed; ruff/black/mypy/lint-imports green.

> The orchestrator-level SSRF test needs the check classes, so it lands in Stage 3.

## Stage 3 — The two checks

- [x] `webvigil/checks/injection/checks.py`: add `_DESCRIPTION["ssrf-metadata"]` /
  `_DESCRIPTION["ssrf-internal"]`, `_REMEDIATION["ssrf-metadata"] =
  _REMEDIATION["ssrf-internal"]` (the design's SSRF-prevention text), `_SSRF_REFS` +
  `_REFERENCES["ssrf-metadata"] = _REFERENCES["ssrf-internal"]`; `@register class
  SsrfMetadataCheck(_InjectionCheck)` — `id = "injection.ssrf.metadata"`, `name = "SSRF —
  cloud metadata service"`, `kind = "ssrf-metadata"`, `default_severity = Severity.CRITICAL`,
  `cwe = (918,)`; `@register class SsrfInternalCheck(_InjectionCheck)` — `id =
  "injection.ssrf.internal"`, `name = "SSRF — internal resource"`, `kind = "ssrf-internal"`,
  `default_severity = Severity.HIGH`, `cwe = (918,)`. `_InjectionCheck.run` reused
  unchanged. — RF-09, RF-10, ADR-3
- [x] Tests (`test_checks_injection.py` additions): add both `(SsrfMetadataCheck,
  "ssrf-metadata")` and `(SsrfInternalCheck, "ssrf-internal")` to `_ALL`; a `ssrf-metadata`
  hit → one CRITICAL finding with `Location(url=<point>, method=…, param=…)` and the marker
  in evidence; a `ssrf-internal` hit → HIGH; `[]` when no matching hit; id / category /
  mode / default severity assertions. — RF-09, RF-10, RF-11
- [x] Tests (`test_cli.py` additions): `list-checks` shows `injection.ssrf.metadata` and
  `injection.ssrf.internal` with `INJECTION` / `active` / `CRITICAL` resp. `HIGH`. — RF-11
- [x] Quality gate. — 606 passed; ruff/black/mypy/lint-imports green.

## Stage 4 — Fixture app, integration tests

- [x] `tests/fixtures/app.py`: `_fetch_insecure` — a proxy that recognises the SSRF
  payloads for a deterministic offline proof: a `169.254.169.254` / obfuscated /
  `metadata.google` / `100.100.100.200` URL returns a canned AWS-creds JSON
  (`"Code":"Success"` + `"AccessKeyId"`); a `file:` URL returns `_ETC_PASSWD` (for
  `passwd`) else placeholder text; a loopback / encoded-loopback URL returns a
  `redis_version:` banner; a non-matching absolute URL returns `"failed to fetch <url>:
  Connection refused"` with `502`; a non-absolute value returns a clean `"preview of …"`
  body (the baseline). `_fetch_hardened` — allow-list (`https://cdn.example.com/` /
  `https://api.example.com/`); everything else → `"blocked: destination not on the
  allow-list"` `400` (identical to the baseline). Add `/fetch` to both profiles'
  `_INJECTION_ROUTES` (GET); add `<a href="/fetch?url=/preview">` to the insecure landing
  page / `_LINKS` so the crawler discovers the `url` parameter. — RF-12, ADR-1
- [x] Tests (`test_scan_fixture_app.py` additions):
  `test_ssrf_metadata_found_on_the_insecure_fetch_endpoint` (an `injection.ssrf.metadata`
  finding, param `url`, AWS marker in evidence);
  `test_ssrf_internal_found_on_the_insecure_fetch_endpoint`;
  `test_hardened_fetch_endpoint_reports_no_ssrf`;
  `test_ssrf_scan_is_deterministic`. Recompute any `pages_scanned` assertion the new
  `/fetch` link shifts. — RF-12
- [x] Quality gate. — 609 passed (+1 pre-existing API-test flake, passes in isolation); ruff/black/mypy/lint-imports green.

## Stage 5 — Docs, roadmap, verification, close

- [x] `docs/active-injection.md`: add an **SSRF** section — the two checks and their
  severities; the four in-band proofs; the payload categories (metadata targets incl.
  Kubernetes, loopback + encodings, `file://`); that `--mode active` is the only gate;
  and an explicit statement that **blind SSRF is not covered — it needs a future opt-in
  collaborator spec**. Update the "What it detects" table with the two rows. Replace the
  "No SSRF" bullet under "What it does not do" with "in-band SSRF shipped in v0.9; blind
  SSRF still needs a collaborator (deferred)". — RNF-08
- [x] `README.md`: coverage table `v0.9` row (in-band SSRF, link to the docs section);
  a `--mode active` SSRF note near the injection quick-start line if useful. `CLAUDE.md`:
  layer-3 `webvigil.checks.injection` paragraph gains `injection.ssrf.*` (in-band only,
  no collaborator, no config); `Estado` line → `009-ssrf` concluída, roadmap now clear
  except a future `011-ssrf-oast`. `specs/README.md`: `009-ssrf` roadmap row → **done**
  (`v0.9`) with the link; add a `>`-note that blind SSRF was split out to a future opt-in
  `011-ssrf-oast` (parallel to 010 following 004). — RNF-08
- [x] Set all three `009` spec files to `status: done`; add an "Implementation notes"
  section to `design.md` (final payload / signature contents, whether any obfuscated URL
  form had to be dropped for `httpx`, the pytest delta, the `pages_scanned` change,
  anything that shifted from the design). — RNF-08
- [x] Manual verification: `uvicorn tests.fixtures.serve:app` — an Active scan
  (`--mode active --authorized-by me`) reports `injection.ssrf.metadata` (CRITICAL) and
  `injection.ssrf.internal` (HIGH) on `GET /fetch` param `url`, evidence carrying the
  payload and the proof; a scan of the hardened profile reports neither; `webvigil
  list-checks` shows both ids. Confirm from a request capture that WebVigil connected only
  to the target host (the SSRF payloads never left as outbound requests of their own). — RNF-03, RNF-05
- [x] Final full quality gate: ruff / black / mypy / lint-imports (contracts unchanged) /
  pytest — 610 passed. — RNF-02
