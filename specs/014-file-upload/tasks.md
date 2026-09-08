---
feature: Unrestricted file upload + residual in-band active checks — LDAP / XPath / SSI injection (Active Mode)
status: done
date: 2026-09-08
related:
  - 014-file-upload/requirements.md
  - 014-file-upload/design.md
origin: conception
---

# 014 — File upload and residual in-band active checks — Tasks

Ordered, small, each tagged with the requirement / ADR it satisfies. The last
task of every stage is the quality gate (`ruff -> black -> mypy src ->
lint-imports -> pytest`). Engine + CLI only — no `web` gate, no API migration
(RNF-01, RNF-02).

Baseline at spec 013 close: **741 passed**. At 014 close: **791 passed** (+50).

## Stage 0 — Payloads, the diff refactor, plumbing

- [x] `webvigil/checks/injection/detect/_diff.py` (new): `ratio`,
  `two_sided_split` (TRUE≈baseline, FALSE diverges — the `sqli` boolean rule),
  `wider_then_same` (TRUE grows past `_WIDEN`, FALSE unchanged — the LDAP/XPath
  result-set rule), `_norm` (wraps `normalize_body`). — ADR-3
- [x] `webvigil/checks/injection/detect/sqli.py`: delete the private `_ratio` /
  `_splits`, import `ratio` / `two_sided_split` from `_diff`. Pure move — the
  `sqli` tests must stay green untouched. — ADR-3
- [x] `webvigil/checks/injection/payloads.py`: `LDAP_ERROR`,
  `LDAP_ERROR_SIGNATURES`, `LDAP_BOOLEAN`; `XPATH_ERROR`,
  `XPATH_ERROR_SIGNATURES`, `XPATH_BOOLEAN_PAIRS`; `SSI_ECHO`, `SSI_MARKER`,
  `SSI_EVAL_SIGNATURES`, `SSI_ERROR_SIGNATURE`. — RF-08, RF-09, RF-10
- [x] `webvigil/checks/injection/points.py`: `_LDAPLIKE_NAMES` + `is_ldaplike`,
  `_XPATHLIKE_NAMES` + `is_xpathlike`, `_SSILIKE_NAMES` + `is_ssilike`. — RF-11
- [x] `webvigil/core/findings.py`: `Category.UPLOAD = "UPLOAD"` + docstring line. — RF-07, ADR-4
- [x] `webvigil/core/config.py`: `InjectionSection.file_upload` (False),
  `upload_budget` (80), `request_budget` 600 -> 650 + docstring;
  `webvigil.example.toml` `[injection]` comments. — RF-14, ADR-2
- [x] `webvigil/http/client.py`: `request(..., files: _Files | None = None)` and
  `_request_with_retry(..., files)` -> `httpx` `files=`; assert `files` is not
  combined with `data` / `content`. `_Files` type alias. — RF-17, design "HTTP layer"
- [x] Grep `src/webvigil/api/` + `web/` for a hardcoded `Category` list
  (`HEADERS`, `TLS`, ...) — confirm `meta.py` returns `check.category.value` and
  the dashboard derives its filter from data (as 006 / 012 / 013). — ADR-4, Risks
- [x] Fixture page-count check: deferred to Stage 7 (the links land with the
  fixture routes). Plan: inline into `_INSECURE_PAGE` if the count is tight
  (spec-013 lesson). — Risks
- [x] Tests: `test_injection_diff.py` (new — 6 helper truth-table cases),
  `test_config.py` (`file_upload` / `upload_budget` default + override),
  `test_findings.py` (`Category.UPLOAD` string member),
  `test_http_client.py` (`request(files=)` sends multipart; `ValueError` when
  combined with `content`). — RF-17
- [x] Quality gate. — ruff / black / mypy (109 files) / lint-imports (2 kept) /
  affected unit suites all green.

## Stage 1 — The `ldap` detector

- [x] `webvigil/checks/injection/detect/ldap.py`: `detect` — error probe
  (`LDAP_ERROR` -> `LDAP_ERROR_SIGNATURES`, baseline-absent -> HIGH/HIGH); boolean
  probe (`LDAP_BOOLEAN`: TRUE replaces the value with a widening filter, FALSE
  appends a no-op; `wider_then_same` + one confirmation send -> MEDIUM/MEDIUM). A
  one-sided size change or a bare `5xx` is not a hit. — RF-08, RF-11, RF-12
- [x] Tests (`test_injection_ldap.py`): error signature -> HIGH; result-set widen
  + confirm -> MEDIUM; one-sided change -> none; signature already in baseline ->
  suppressed; `is_ldaplike` priority; `send` -> None stops. — RF-17
- [x] Quality gate. — ruff / black / mypy / lint-imports / affected unit suites green.

## Stage 2 — The `xpath` detector

- [x] `webvigil/checks/injection/detect/xpath.py`: `detect` — error probe
  (`XPATH_ERROR` -> `XPATH_ERROR_SIGNATURES` -> HIGH/HIGH); boolean probe
  (`XPATH_BOOLEAN_PAIRS`, `two_sided_split` + confirm -> MEDIUM/MEDIUM). Bare
  `5xx` / one-sided -> none. — RF-09, RF-11, RF-12
- [x] Tests (`test_injection_xpath.py`): error signature -> HIGH; two-sided split
  + confirm -> MEDIUM; bare `5xx` -> none; one-sided -> none; `is_xpathlike`
  priority. — RF-17
- [x] Quality gate. — ruff / black / mypy / lint-imports / affected unit suites green.

## Stage 3 — The `ssi` detector

- [x] `webvigil/checks/injection/detect/ssi.py`: `detect` — echo probe
  (`SSI_ECHO`; skip when the directive is reflected **verbatim**; a
  `SSI_EVAL_SIGNATURES` match absent from the baseline -> HIGH/HIGH); marker
  probe (`SSI_MARKER` with a fresh token -> `SSI_ERROR_SIGNATURE`, baseline-absent
  -> MEDIUM/MEDIUM). Never emits `#exec` / `#include`. — RF-10, RF-12, ADR-8
- [x] Tests (`test_injection_ssi.py`): evaluated date / env dump -> HIGH;
  SSI-error string -> MEDIUM; directive reflected verbatim -> none; payload spy:
  no `#exec` / `#include`; `is_ssilike` priority. — RF-17
- [x] Quality gate. — ruff / black / mypy / lint-imports / affected unit suites green.

## Stage 4 — Engine wiring + the three `injection.*` checks

- [x] `webvigil/checks/injection/engine.py`: import the three detectors +
  `is_ldaplike` / `is_xpathlike` / `is_ssilike`; `_DETECTORS["ldap"/"xpath"/"ssi"]`;
  `_BASE_ORDER = ("xss", "sqli-error", "sqli-boolean", "traversal", "redirect",
  "ssti", "crlf", "sqli-time", "cmdi", "ldap", "xpath", "ssi", "xxe", "ssrf")`
  (all three of the new families sit *after* `sqli-time` so they cannot starve it);
  `KIND_BY_CHECK_ID` gains the three ids; `_ordered_kinds` gains the three
  `(predicate, kind)` pairs; `_PER_POINT_REQUEST_CAP` 35 -> 38 (re-measure against
  the fixture in Stage 7, tune if needed). — RF-08, RF-09, RF-10, RF-11
- [x] `webvigil/checks/injection/checks.py`: `_DESCRIPTION` / `_REMEDIATION` /
  `_REFERENCES` for `"ldap"` / `"xpath"` / `"ssi"`; `@register class LdapCheck`
  (HIGH, `cwe = (90,)`) / `XpathCheck` (HIGH, `cwe = (643,)`) / `SsiCheck` (HIGH,
  `cwe = (97, 94)`), all `_InjectionCheck`. — RF-08, RF-09, RF-10, RF-13
- [x] Tests: `test_injection_engine.py` (three in `_BASE_ORDER` / `_DETECTORS` /
  `KIND_BY_CHECK_ID`; each front-loaded for a matching point);
  `test_checks_injection.py` (three in `_ALL` + a metadata / finding-shape test). —
  RF-13, RF-17
- [x] Quality gate. — ruff / black / mypy / lint-imports / affected unit suites green.

## Stage 5 — The `UploadScanner` pass

- [x] `webvigil/checks/upload/__init__.py` (new): package marker +
  `from webvigil.checks.upload import checks  # noqa: F401`.
- [x] `webvigil/checks/upload/scanner.py` (new): `UploadPayload` / `UploadHit`
  dataclasses; `UploadScanner`:
  - `_upload_forms` (every `Form` with a `type == "file"` field, `_EXCLUDE_FORM_RE`
    filtered);
  - `_payloads(token)` — the four families (RF-03): `server-exec` (`.php` +
    `.phtml` / `.jsp` / `.asp` variants), `client-exec` (`.html` / `.svg`),
    `bypass` (`.php.jpg`, `.pHtml`, `.html%00.jpg`, `image/jpeg` part on a `.html`
    name), `traversal` (`../../wv<token>-trav.html` + `..%2f` / backslash /
    leading-slash);
  - `_probe_form` — empty-file baseline upload, then per payload: `POST` with
    `files=` + `data=` (other fields at default), skip a `4xx` the baseline did
    not return, `_retrieve`, `_classify`;
  - `_retrieve` — response-body / `Location` `wv<token>` URL, then `_UPLOAD_PREFIXES`
    + the action's directory, then (traversal) web root + prefix parents; each a
    scope-guarded `GET`;
  - `_classify` — the five branches / severities (RF-05);
  - `_probe_put` — `PUT wv<token>.txt` / `.html` to the entry dir, `GET` back
    (RF-06);
  - `_take` budget counter (`upload_budget`), per-form cap, `warnings`. Benign
    markers only; never `DELETE` / `PATCH`. — RF-01..RF-06, ADR-1, ADR-6, ADR-7, RNF-03, RNF-04
- [x] `webvigil/core/context.py`: `Observations.upload_hits` + `TYPE_CHECKING`
  import + docstring line. — design "Data model"
- [x] `webvigil/core/orchestrator.py`: `_scan_upload(...)` — no-op unless Active
  **and** `[injection] file_upload` **and** `upload.unrestricted` selected; run
  `UploadScanner`, catch-and-warn; assign `Observations.upload_hits`. The
  Passive-Mode + `file_upload` warning next to the stored-XSS one.
  `webvigil/checks/__init__.py` imports the `upload` package. — RF-01, RF-13, ADR-1
- [x] Tests (`test_upload_scanner.py`): form selection (file field in / login
  form out); each payload family built; retrieval by response URL vs prefix vs
  web root; the five `_classify` branches + severities; rejection -> no hit;
  budget cap -> warning; `PUT` probe positive / negative; request spy: only
  benign markers, no `DELETE` / `PATCH`; an `[auth]` header rides an upload
  request and is absent from the hit evidence. — RF-17, RNF-07
- [x] Quality gate. — ruff / black / mypy / lint-imports / full unit suite green.

## Stage 6 — The `upload.unrestricted` check, CLI flag, summary

- [x] `webvigil/checks/upload/checks.py` (new): `_UploadCheck` base (renders
  `ctx.observations.upload_hits`); `_DESCRIPTION` keyed on `outcome`; one
  `_UPLOAD_FIX`; `@register class UnrestrictedUploadCheck` (`Category.UPLOAD`,
  ACTIVE, HIGH, `cwe = (434, 646)`, OWASP references). `dedup_key` =
  `f"{field or 'PUT'}:{outcome}"`. — RF-07, ADR-5
- [x] `webvigil/cli/app.py`: `--file-upload / --no-file-upload`, threaded through
  `_build_config` -> `injection_overrides["file_upload"]`. — RF-14
- [x] `webvigil/cli/_render.py`: `summary(...)` gains `uploads: int = 0` and notes
  "N file(s) uploaded" when the upload pass ran; `_emit` in `app.py` passes the
  count. — RF-14
- [x] Tests: `test_checks_upload.py` (one finding per hit; `Category.UPLOAD`;
  severity from the hit; `dedup_key`; `[]` with no hits); `test_cli.py`
  (`list-checks` shows the four ids + `UPLOAD`; `--file-upload` sets the field;
  the summary note). — RF-13, RF-14, RF-17
- [x] Quality gate. — ruff / black / mypy / lint-imports / full unit suite green.

## Stage 7 — Fixture app, integration tests

- [x] `tests/fixtures/app.py`: insecure — an upload form in `_FORMS` (both
  profiles, with a CSRF token so the CSRF check stays quiet), `_upload_insecure`
  (store, no validation, `../` name stored at the web root too), `_files_insecure`
  (GET serves extension-guessed `Content-Type`, `.php`/`.jsp` "executed" via
  `_run_marker_script`; PUT stores), `_root_file_insecure` (a `/{fname}` catch-all,
  last, serving the traversal file from the web root), `_dir_insecure` (LDAP —
  canned `Bad search filter` on unbalanced parens, widened list on `*`),
  `_xdoc_insecure` (XPath, param `node` — canned `XPathEvalError` on an odd quote count,
  full catalogue on a tautology), `_page_insecure` (SSI — evaluates `#echo` /
  `#printenv` / `<esi:vars>`, emits the SSI error for `wv<token>`). Hardened
  equivalents (allow-list, `attachment` + `octet-stream`, `PUT` 405, fixed row
  sets, escaped `tpl`). `/dir?user` / `/xdoc?node` / `/page?tpl` links in `_INJECTION_LINKS`;
  routes in both `_INJECTION_ROUTES` profiles. `app.state.uploads` /
  `root_uploads` reset per app. — RF-15, ADR-8
- [x] Budget re-measure: `_PER_POINT_REQUEST_CAP` 38 / `upload_budget` 80 hold
  against the fixture; the LDAP / XPath / SSI detectors and the upload pass all
  fire within budget on the insecure profile. — RF-11, Impact
- [x] Tests (`test_scan_fixture_app.py`): Active + `--file-upload` insecure ->
  `upload.unrestricted` (multiple shapes) + `injection.ldap` / `.xpath` / `.ssi`;
  Active **without** `--file-upload` -> the three injection checks, no
  `POST /upload` / `PUT`; passive + `file_upload=True` -> none, no LDAP / XPath /
  SSI payload or `PUT` (the `scan` fixture does **not** force active on
  `file_upload`, so this path is exercised); Active hardened + `--file-upload` ->
  **zero** spec-014 findings; deterministic fingerprints;
  `test_crawler_reaches_the_linked_pages` -> **20** (was 17: +/dir +/xdoc +/page).
  The `scan` fixture gains `file_upload` / threads it into `[injection]`. — RF-16
- [x] Quality gate. — ruff / black / mypy (115 src) / lint-imports (2 kept) /
  the 6 spec-014 integration tests green.

## Stage 8 — Docs, roadmap, verification, close

- [x] `docs/active-injection.md`: a "File upload — `--file-upload` (opt-in)"
  section (the four upload outcomes + the MEDIUM inert-accept case, the `PUT`
  probe, benign markers left in place) and an "LDAP / XPath / SSI injection"
  section (how each is proved in-band). A "Coverage boundaries" subsection under
  "What it does not do" — the full table of what active coverage leaves out and
  why (DOM XSS, blind/OAST, EL / `eval()` / NoSQLi / HPP / RFI, stateful-login
  tests, smuggling, zip-slip / image-library RCE / AV evasion). The `[injection]`
  block and detector table updated. — RNF-09
- [x] `README.md` `v0.14` coverage row + roadmap note (links Coverage boundaries).
  `CLAUDE.md` layer-3 paragraph + `Estado` line -> `011`–`014` concluídas, next
  `v1.0`. `specs/README.md` roadmap row -> **done**; roadmap prose updated. — RNF-09
- [x] All three `014` spec files -> `status: done`; `design.md` "Implementation
  notes" section filled; the pytest count (**791**) recorded here and in
  `design.md`. — RNF-09
- [x] Manual verification: an Active scan of the insecure fixture reports
  `injection.ldap` (`/dir` `user`), `injection.xpath` (`/xdoc` `node`),
  `injection.ssi` (`/page` `tpl`) and (with `--file-upload`) `upload.unrestricted`
  in several shapes; the hardened profile reports none; `webvigil list-checks`
  shows the four with `INJECTION` / `UPLOAD`; a request capture confirms the only
  state-changing verb is the gated `PUT` of a benign marker and no `[auth]`
  credential appears in the report. — RNF-03, RNF-05, RNF-06, RNF-07
- [x] Final full quality gate: `ruff` / `black` / `mypy src` (115 files) /
  `lint-imports` (2 contracts kept) / `pytest` — **791 passed** (was 741 at spec
  013 close, +50). — RNF-02
