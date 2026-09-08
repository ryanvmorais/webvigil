---
feature: In-band RCE injection — OS command injection (echo + time-based) and SSTI (Active Mode)
status: done
date: 2026-09-08
related:
  - 011-rce-injection/requirements.md
  - 011-rce-injection/design.md
origin: conception
---

# 011 — In-band RCE injection (command injection, SSTI) — Tasks

Ordered, small, each tagged with the requirement / ADR it satisfies. The last task
of every stage is the quality gate (`ruff → black → mypy src → lint-imports →
pytest`). Engine + CLI only — no `web` gate, no API migration (RNF-01, RNF-02).

Baseline at spec 009/010 close: **610 passed**. At 011 close: **639 passed**
(+29: cmdi 9, ssti 7, points 1, config 1, cli 2, engine 3, checks 1, orchestrator
2, integration 4). Stages 0-5 were verified with a full run at close; the counts
below are the batch results, not per-stage snapshots.

## Stage 0 — Payloads, heuristic, config plumbing, budget re-measure

- [x] `webvigil/checks/injection/payloads.py`: command-injection section —
  `CMDI_MARKER_BYTES`, `CMDI_ECHO_POSIX` (11 templates: separators + `${IFS}` +
  quote-breakers wrapping `echo {marker}=$(({a}*{b}))`), `CMDI_ECHO_WINDOWS` (2
  `& echo … & set /a`), `CMDI_TIME` ((label, template): POSIX `sleep`/`$()`/
  backtick/`|`/`%0a`, Windows `ping -n {d1}` / `timeout /t {d}`). — RF-02, RF-03
- [x] `webvigil/checks/injection/payloads.py`: SSTI section — `SSTI_MARKER_BYTES`,
  `SSTI_POLYGLOT`, `SSTI_ERROR_SIGNATURES` (8 engines), `SSTI_ENGINE_PROBE`
  (`%s`-templated, not `.format`), `arith_payloads(marker, a, b)` (8 f-string
  payloads, marker glued to the expression). — RF-05, RF-06
- [x] `webvigil/checks/injection/points.py`: `_COMMANDLIKE_NAMES` +
  `is_commandlike` (front-loads both detectors); the narrower `_SHELL_NAMES` +
  `is_shell_param` (gates cmdi's full echo set and its time stage). — RF-04
- [x] `webvigil/checks/injection/detect/__init__.py`: `DetectCtx.time_based_cmdi:
  bool = True` + attr doc. — RF-03, ADR-3
- [x] `webvigil/core/config.py`: `InjectionSection.time_based_cmdi: bool = True` +
  docstring; `request_budget` default 500 → 600; `webvigil.example.toml` +
  `docs/active-injection.md` updated. — RF-11, RNF-04
- [x] Tests: `test_injection_points.py` — `is_commandlike` true `cmd`/`host`/
  `template`, false `q`/`email`, value shape not a signal. `test_config.py` —
  `time_based_cmdi` default + round-trip + override. — RF-04, RF-11, RF-14
- [x] **Budget re-measure (Resolved decision 6):** measured against the fixture —
  `_PER_POINT_REQUEST_CAP` 30 → 35 (45 let `sqli-time` run on non-vulnerable
  points and drain the shared 8-sleep sub-budget); `request_budget` 500 → 600;
  `_TIME_BASED_SLEEP_CAP` stays 8, enabled by `time_based_sqli` **or**
  `time_based_cmdi`. — RNF-04, ADR-7
- [x] Quality gate. — ruff/black/mypy/lint-imports green; full pytest green.

## Stage 1 — The `cmdi` detector

- [x] `webvigil/checks/injection/detect/cmdi.py` (new): `detect` — marker +
  random operands; `_echo`; then `_time` when `ctx.time_based_cmdi` **and**
  `is_shell_param(point)` (a `sleep` on a template sink just wastes budget). —
  RF-01, RF-02, RF-03, ADR-2, ADR-3
- [x] `_echo` — `CMDI_ECHO_POSIX` for an `is_shell_param` point, else a 3-payload
  canary; needle `f"{marker}={a*b}"` present and baseline-absent → CRITICAL/HIGH.
  Then `CMDI_ECHO_WINDOWS` — marker present, product within 200 chars after it,
  marker baseline-absent → CRITICAL/MEDIUM. — RF-02, RF-07, ADR-4, ADR-6
- [x] `_time` — mirrors `sqli.detect_time`: `{d}=0` control, `time_based=True`
  slow payload, `>= (delay-1)*1000` ms delta, half-delay confirm scales →
  CRITICAL/HIGH (MEDIUM when the confirm was budget-denied). — RF-03, RF-07
- [x] `_echo_hit` / `_point_evidence` / `_snippet` helpers — mirror
  `detect/sqli.py`. — RF-07
- [x] Tests (`test_injection_cmdi.py`, new, 9): POSIX arithmetic → CRITICAL/HIGH;
  reflected literal → no hit; marker-only → no hit; needle-in-baseline (monkey-
  patched marker) → suppressed; Windows two-token → CRITICAL/MEDIUM; time delay →
  hit; uniformly slow → no hit; `time_based_cmdi=False` → no sleep payload;
  `send`→`None` stops. — RF-14
- [x] Quality gate. — green.

## Stage 2 — The `ssti` detector

- [x] `webvigil/checks/injection/detect/ssti.py` (new): `detect` — stage 1
  polyglot → `_engine_from_error`; stage 2 `arith_payloads` (`_engine_first` when
  known, `[:4]` canary for a non-`is_commandlike` point); needle
  `f"{marker}{a*b}"` present and baseline-absent → `_identify_engine` if unknown
  → `_hit`. — RF-01, RF-05, RF-06, ADR-7
- [x] `_engine_from_error` — first `SSTI_ERROR_SIGNATURES` match in the polyglot
  response, absent from the baseline. — RF-05
- [x] `_identify_engine` — one `SSTI_ENGINE_PROBE` send; `marker+"7777777"` →
  "Jinja2/Nunjucks", `marker+"49"` → "Twig", else `None`. — RF-06
- [x] `_hit` — HIGH/HIGH, title names the engine or "engine unknown", evidence =
  point + payload + `("Evaluated expression", f"{needle}  (= {a} * {b})")`. —
  RF-06, RF-07, ADR-5
- [x] Tests (`test_injection_ssti.py`, new, 7): Jinja error → engine named +
  arithmetic hit; engine from polyglot alone (Twig); arithmetic fires with no
  stage-1 error; reflected literal → no hit; product without marker → no hit;
  needle-in-baseline → suppressed; `send`→`None` on the polyglot stops. — RF-14
- [x] Quality gate. — green.

## Stage 3 — Engine wiring

- [x] `webvigil/checks/injection/engine.py`: import `cmdi` / `ssti` + `is_commandlike`;
  `_DETECTORS["ssti"]` / `["cmdi"]`; `_BASE_ORDER = ("xss", "sqli-error",
  "sqli-boolean", "traversal", "redirect", "ssti", "sqli-time", "cmdi", "ssrf")`;
  `KIND_BY_CHECK_ID` gains both ids; `_ordered_kinds` gains `(is_commandlike,
  "cmdi")` / `(is_commandlike, "ssti")`; `DetectCtx(..., time_based_cmdi=…)`; time
  sub-budget enabled when either time flag is on. — RF-01, RF-03, RF-04, RF-10, ADR-3, ADR-7
- [x] Tests (`test_injection_engine.py`, +3): both in `_BASE_ORDER` / `_DETECTORS`
  / `KIND_BY_CHECK_ID`; front-loaded for a `host` point, not for `q`; time
  sub-budget non-zero when only `time_based_cmdi` is on. — RF-10, RF-14
- [x] Quality gate. — green.

## Stage 4 — The two checks, CLI flag

- [x] `webvigil/checks/injection/checks.py`: `_CMDI_FIX` / `_SSTI_FIX`;
  `_DESCRIPTION` / `_REMEDIATION` / `_REFERENCES` for `"cmdi"` / `"ssti"`;
  `@register class OsCommandInjectionCheck` (`injection.cmdi.os`, CRITICAL,
  `cwe = (78, 77)`) / `TemplateInjectionCheck` (`injection.ssti`, HIGH,
  `cwe = (1336, 94)`). `_InjectionCheck.run` unchanged. — RF-08, RF-09, ADR-2, ADR-5
- [x] `webvigil/cli/app.py`: `--time-based-cmdi / --no-time-based-cmdi`, threaded
  through `_build_config` → `injection_overrides["time_based_cmdi"]`. — RF-11
- [x] Tests: `test_checks_injection.py` — both in `_ALL` + a metadata/finding-shape
  test. `test_injection_orchestrator.py` (+2) — `selected_kinds` contains `"cmdi"`
  when selected; a target that evaluates the arithmetic → CRITICAL finding; no
  cmdi/ssti payload when only the XSS check is selected. `test_cli.py` (+2) —
  `list-checks` shows both; `--no-time-based-cmdi` sets the config field. —
  RF-08, RF-09, RF-10, RF-11
- [x] Quality gate. — green.

## Stage 5 — Fixture app, integration tests

- [x] `tests/fixtures/app.py`: `import jinja2`; `_CMDI_SLEEP_RE` / `_CMDI_ARITH_RE`;
  `_ping_insecure` (sync — interprets `sleep`/`ping -n`/`timeout` via bounded
  `time.sleep`, evaluates the arithmetic echo, else a canned line) / `_ping_hardened`
  (host `re.fullmatch` guard → 400); `_greet_insecure` (name into
  `jinja2.Template` source, `TemplateError` → 500 with `jinja2.exceptions.<Name>`)
  / `_greet_hardened` (`jinja2.Template(src, autoescape=True).render(name=…)` —
  bare `Template` does not autoescape). `/ping` + `/greet` in both profiles'
  route tuples + the shared link block. — RF-12, ADR-4
- [x] Tests (`test_scan_fixture_app.py`, +4): command injection on `/ping` `host`
  (CRITICAL); SSTI on `/greet` `name` (HIGH, engine "Jinja*"); hardened `/ping` +
  `/greet` report neither; two runs → identical fingerprints. `pages_scanned`
  12 → 14; the active `scan` fixture now passes `max_pages = 90` so the spec-008
  stored-XSS re-crawl clears the extra guestbook entries the wider injection pass
  creates. — RF-12, RF-13
- [x] Quality gate. — green.

## Stage 6 — Docs, roadmap, verification, close

- [x] `docs/active-injection.md`: "Command injection & SSTI" section (both
  techniques, engine ID, Windows caveat, "truly blind command injection is not
  covered — pair with a collaborator", link `notes/why-not-oast.md`); the two
  table rows; the `[injection]` block (`request_budget` 600, `time_based_cmdi`,
  per-point cap 35); the "What it does not do" list. — RNF-08
- [x] `README.md` coverage table `v0.11` row + the roadmap note. `CLAUDE.md`
  layer-3 injection paragraph (`injection.cmdi.os` / `injection.ssti`,
  `time_based_cmdi`, `_SHELL_NAMES`, cap bumps) + `Estado` line → `011` concluída,
  `012`-`014` planned. `specs/README.md` roadmap row → **done**, note updated. —
  RNF-08
- [x] All three `011` spec files → `status: done`; `design.md` "Implementation
  notes" section (broader `_COMMANDLIKE_NAMES` + narrow `_SHELL_NAMES`; `_time`
  gated on `is_shell_param`; cap 35 not 45 and why; base order; the Windows
  baseline guard; `/greet` is XSS+SSTI vulnerable and the `autoescape` fix; the
  `%s` engine probe; the `max_pages` test knob; pytest delta; `pages_scanned`). —
  RNF-08
- [x] Manual verification: an Active scan of the fixture (via the ASGI transport)
  reports `injection.cmdi.os` (CRITICAL, param `host`, `wv…=<product>` evidence)
  and `injection.ssti` (HIGH, param `name`, engine "Jinja2/Nunjucks"); the
  hardened profile reports neither; `webvigil list-checks` shows both ids;
  `--no-time-based-cmdi` drops the sleep payloads. Engine egress is target-only
  (payloads are parameter values). — RNF-03, RNF-05, RNF-06
- [x] Final full quality gate: ruff / black / mypy / lint-imports (2 contracts
  kept) / pytest — **639 passed**. — RNF-02
