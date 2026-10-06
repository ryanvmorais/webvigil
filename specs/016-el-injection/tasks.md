---
feature: In-band expression-language injection — SpEL, OGNL, JEXL, MVEL, Unified EL (Active Mode)
status: done
date: 2026-10-06
related:
  - 016-el-injection/requirements.md
  - 016-el-injection/design.md
origin: conception
---

# 016 — In-band expression-language injection — Tasks

Ordered, small, each tagged with the requirement / ADR it satisfies. The last task of
every stage is the quality gate (`ruff → black → mypy src → lint-imports → pytest`).
Engine only — no `web` gate, no API migration, no config key (RNF-01, RNF-02).

The full suite takes about 30 minutes, so a stage gate runs lint, types, import contracts
and the **test files that stage touched**; the **full** `pytest` runs at Stage 3 (the first
stage that changes the integration fixture) and at Stage 4 (close). The baseline test count
is recorded when Stage 0 starts and the delta when the spec closes.

Baseline before 016 (clean `main`, after the spec 015 close and the Dependabot work that
followed): **812 collected**. At 016 close: **921 passed** (+109: `test_injection_el` 47,
`test_injection_payloads` 22, `test_fixture_el` 26, and 14 added to existing files —
points 1, engine 4, checks 1, orchestrator 3, integration 5). The two full runs are the
numbers above, not per-stage snapshots; a full run takes about an hour on this machine.

## Stage 0 — Behaviour-neutral prep: public helpers, payloads, heuristic

- [x] `webvigil/checks/injection/detect/ssti.py`: rename the four helpers `el.py` will
  reuse to public names — `_engine_from_error` → `engine_from_error`, `_engine_first` →
  `engine_first`, `_identify_engine` → `identify_engine`, `_hit` → `build_hit` — and update
  their call sites in the same file. No logic change. — ADR-1
- [x] `webvigil/checks/injection/payloads.py`: EL section — `EL_DELIMITERS`,
  `EL_AMBIGUOUS_HINTS`, `EL_BARE_WHOLE`, `EL_BARE_ESCAPE`, `EL_SPEL_PROBE`,
  `EL_OGNL_PROBE`, `EL_UNTERMINATED`, `EL_ERROR_SIGNATURES` (five dialects), with the `#`
  rationale above each group and the marker-discipline note. — RF-02, RF-03, RF-04
- [x] `webvigil/checks/injection/points.py`: `_EXPRLIKE_NAMES`, `_EXPRLIKE_VALUE` and
  `is_exprlike`, same shape and docstring as `is_commandlike`. — RF-06
- [x] Tests: `test_injection_points.py` — `is_exprlike` true for `filter` / `rule`
  and for a value containing `#{` / `T(`, false for `message` / `q` / `id`. A payloads test —
  `EL_AMBIGUOUS_HINTS` ⊆ the hints of `arith_payloads`; each signature regex matches one
  hand-written error string per dialect and none of the Jinja2 / Twig strings. — RF-03,
  RF-06, RF-12
- [x] Quality gate: ruff / black / mypy / lint-imports green; `pytest tests/unit` for
  `test_injection_ssti.py`, `test_injection_points.py`, the payloads test. The `ssti` tests
  pass untouched, which is the proof the rename changed nothing. — RNF-02
  46 passed (`test_injection_ssti.py` untouched, `test_injection_points.py`, the new
  `test_injection_payloads.py`). `_EXPRLIKE_NAMES` is narrower than RF-06 listed (no `q` /
  `query` / `search` / `msg` / `message` / `title`): the 014 comment in `points.py` records
  that a front-loaded generic name starves the fast detectors; those points get the canary.

## Stage 1 — The detector

- [x] `webvigil/checks/injection/detect/el.py`: module docstring (what it proves, how it
  relates to `ssti`, the three entry points); `_Form` and `_Verdict` dataclasses with
  `Attributes:`; `_forms(marker, templates, full, engine)` building the ordered list from
  the Form tables (combined / el-only × full / canary), the template-only entries taken
  from `arith_payloads` minus `EL_AMBIGUOUS_HINTS`. — RF-02, RF-06, ADR-1
- [x] `el.py`: `_dialect_from_error(text, baseline_text)` and `_unterminated_probe` (two
  requests, only on full points when no signature has appeared yet). — RF-03
- [x] `el.py`: `_probe_type_access(...)` — SpEL then OGNL through `form.wrap`, fresh
  three-digit `n`, success on `<marker><n>` absent from the baseline, plus dialect naming
  from an EL signature in the probe's own response; skips the redundant probe when the
  dialect is already known. — RF-04, ADR-3
- [x] `el.py`: `_classify(...)` implementing the Classification table, `build_hit`-style
  builders for the `el` hit (title, evidence pairs `Injection point` / `Payload` /
  `Evaluated expression` / `Type access` / `Dialect` / `Error signature`) and the
  signature-only hit; the severity / confidence table verbatim. — RF-04, RF-05, RF-07,
  ADR-2, ADR-4
- [x] `el.py`: `_run(point, baseline, ctx, *, templates)`, `detect_el`, `detect_combined`;
  every `ctx.send` stops the routine on `None`. — RF-01, RF-02, RF-05
- [x] Tests, `tests/unit/test_injection_el.py` (stubs `_spel`, `_spel_sandboxed`, `_ognl`,
  `_ognl_static_off`, `_freemarker`, `_unified_el`, `_jinja`, `_reflect`): arithmetic per
  form incl. `%{}` and both bare variants; echoed literal and product-without-marker are
  not hits; baseline suppression; stop-on-`None` at every stage; one case per row of the
  Classification and Severity tables; signature-only MEDIUM; signature-in-baseline ignored;
  unterminated probe only on full points; request counts per point type match the Request
  budget table; **parity** — the `test_injection_ssti` scenarios replayed against
  `detect_combined` give equal `ssti` hits; a forbidden-token guard on every probe payload
  (`Runtime`, `ProcessBuilder`, `System`, `Class`, `File`). — RF-02..RF-07, RF-12, RNF-03,
  RNF-05
- [x] Quality gate: ruff / black / mypy / lint-imports green; `pytest
  tests/unit/test_injection_el.py tests/unit/test_injection_ssti.py`. — RNF-02
  93 passed across `test_injection_el.py`, `test_injection_ssti.py`, `test_injection_payloads.py`
  and `test_injection_points.py`. Deviations from the design text, none behavioural: the
  detector entry points took `ssti.CANARY_LIMIT` public as a fifth rename; `_forms` lost its
  unused `point` argument; the evidence excerpt is the matched line (up to 120 characters),
  not the bare regex match, and a probe's own refusal is preferred over the stage-1
  signature as the named evidence.

## Stage 2 — Engine wiring and the check

- [x] `webvigil/checks/injection/engine.py`: import `el` as `el_detect`; `_DETECTORS` gains
  `"el"` and `"ssti+el"`; `_BASE_ORDER` gains `"el"` after `"ssti"`;
  `KIND_BY_CHECK_ID["injection.el"] = "el"`; `(is_exprlike, "el")` in the front-load
  predicates; `_merge_el` and its call at the end of `_ordered_kinds`; the comment block
  above `_PER_POINT_REQUEST_CAP` left for Stage 3 to update with the measurement. — RF-01,
  RF-06, ADR-1
- [x] `webvigil/checks/injection/checks.py`: `_DESCRIPTION["el"]`, `_REMEDIATION["el"]`,
  `_REFERENCES["el"]` (URLs opened and confirmed while writing), and
  `ExpressionLanguageInjectionCheck` (`id = "injection.el"`, `cwe = (917, 94)`,
  `default_severity = HIGH`). — RF-08
- [x] Tests: `test_injection_engine.py` — `_ordered_kinds` for the four selected-set
  combinations (`ssti` only → `"ssti"`; `el` only → `"el"`; both → one `"ssti+el"` at the
  earlier position, with and without a front-loading name); `KIND_BY_CHECK_ID` maps the new
  id. `test_checks_injection.py` — id / category / mode / severity / CWE / references, one
  finding per `el` hit, `[checks] disabled = ["injection.el"]` drops the kind. `test_cli.py`
  — `list-checks` shows `injection.el` with `INJECTION` / `active` / `HIGH`. — RF-08,
  RF-09, RF-12
- [x] Quality gate: ruff / black / mypy / lint-imports green; `pytest` on the three test
  files above plus `test_injection_el.py`. — RNF-02
  134 passed across the five files. Added beyond the task text: three orchestrator tests in
  `test_injection_orchestrator.py` (an OGNL target reports `injection.el`; with both checks
  selected one proof is one finding; with only `injection.ssti` no EL-only payload is sent).
  The `references` URLs were opened while writing (the OWASP page redirects to
  `community.owasp.org`, like the other `_OWASP` entries).

## Stage 3 — Fixture app, integration, budget re-measure

- [x] `tests/fixtures/app.py`: the `ast`-based evaluator (`_el_eval`) — integer and string
  constants, unary minus, `+ - * //`, string concatenation on `+`, the one allow-listed
  `abs` reached from `T(java.lang.Math).abs(...)` / `@java.lang.Math@abs(...)` only on
  routes that allow static calls; no call to `eval` / `exec`. — ADR-5, RNF-03
- [x] `tests/fixtures/app.py`: the insecure routes `GET /report?filter=1` (bare, SpEL),
  `GET /banner?caption=hello` (`%{…}`, OGNL), `GET /rule?cond=ok` (`#{…}` + bare, static
  rejected with `EL1005E`), their `SpelParseException` / `ognl.ParseException` 500 bodies,
  the hardened twins (escape and echo, never evaluate), the links in `_INJECTION_LINKS`,
  and the route tables for both profiles. Update the module docstring's spec list. —
  RF-10
- [x] `tests/unit/test_fixture_el.py`: the evaluator accepts arithmetic, concatenation and
  the allow-listed call; rejects other calls, attribute access, names and comprehensions. —
  ADR-5, RF-12
- [x] `tests/integration/test_scan_fixture_app.py`: insecure Active → `injection.el` for
  `/report` (SpEL, CRITICAL, param `filter`), `/banner` (OGNL, CRITICAL, `caption`),
  `/rule` (SpEL, HIGH, `cond`); no `injection.ssti` for those points; `/greet` still
  `injection.ssti` (Jinja); Passive → none and no crafted request; hardened Active → zero
  `injection.el`; two runs give the same findings and fingerprints. — RF-10, RF-11, RNF-05
- [x] **Budget re-measure (RNF-04):** run the insecure Active scan, record
  requests-per-point for the new routes and for `/greet` / `/ping`; change
  `_PER_POINT_REQUEST_CAP` (38), `request_budget` (650 default, the test's 1200),
  `max_pages` (90) and the "~13 injection points" comment **only if** a later detector is
  starved or the stored-XSS re-crawl stops short; write the numbers into the comment above
  `_PER_POINT_REQUEST_CAP` and into `design.md` "Implementation notes". — RNF-04
- [x] Quality gate: ruff / black / mypy / lint-imports green; **full `pytest`**. — RNF-02
  921 passed, no failure, no skip. Deviations from the task text: `/rule` evaluates `#{…}`
  only (a bare `ok` would be an identifier error in the baseline); the routes HTML-escape
  the text they do not evaluate, so they raise no incidental reflected-XSS finding; the
  crawl-count assertion went 20 → 23. **Budget re-measure:** `/banner?caption=` (the canary
  path, behind xss / sqli / traversal / redirect) was starved at the old cap of 38 and found
  from 39; `_PER_POINT_REQUEST_CAP` is **42**, one request of margin over the minimum.
  `request_budget` (650) and the integration test's 1200 / `max_pages = 90` were enough
  unchanged.

## Stage 4 — Docs, roadmap, verification, close

- [x] `docs/active-injection.md`: the checks table gains `injection.el`; a new
  "Expression-language injection" section (the proof, the HIGH / CRITICAL split, the
  `Math.abs` probe, the relationship with `injection.ssti`, why `eval()` is not covered);
  the **Coverage boundaries** row rewritten (EL covered, `eval()` still out); the
  per-point cap and budget lines if Stage 3 changed them. — RF-14
- [x] `README.md` "Scope and limitations" and the coverage table; `CLAUDE.md` layer-3
  injection paragraph and the `Estado` line (`016` concluída); `docs/stack.md` if it names
  the injection detectors; `specs/README.md` roadmap row → **done** and the note listing EL
  as out of scope is corrected. — RF-14
- [x] All three `016` spec files → `status: done`; `design.md` "Implementation notes"
  section (the measured request counts, any deviation from this design and why, the
  pytest delta). — RF-14
- [x] Manual verification: an Active scan of the fixture (via the ASGI transport) reports
  the three `injection.el` findings with the expected dialect and severity; the hardened
  profile reports none; `webvigil list-checks` shows `injection.el`; `[checks] disabled =
  ["injection.el"]` removes it and leaves `injection.ssti` as before; egress is
  target-only. — RNF-03, RNF-06
- [x] Final full quality gate: ruff / black / mypy / lint-imports / pytest, count recorded
  in the header above. — RNF-02
  921 passed; ruff / black / mypy / lint-imports green. The README gained a `v0.16` row
  (015 had no delivery label, so the table skips `v0.15`).
