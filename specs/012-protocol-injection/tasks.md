---
feature: Request-envelope injection — CRLF / response splitting, host-header injection, in-band XXE, HTTP methods (Active Mode)
status: done
date: 2026-09-08
related:
  - 012-protocol-injection/requirements.md
  - 012-protocol-injection/design.md
origin: conception
---

# 012 — Request-envelope injection — Tasks

Ordered, small, each tagged with the requirement / ADR it satisfies. The last
task of every stage is the quality gate (`ruff -> black -> mypy src ->
lint-imports -> pytest`). Engine + CLI only — no `web` gate, no API migration
(RNF-01, RNF-02).

Baseline at spec 011 close: **639 passed**. At 012 close: **678 passed** (+39).
Stages 0 and 5 landed together (the `EnvelopeScanner` package + the orchestrator
wiring are small and the checks needed the scanner to exist); the log groups
them.

## Stage 0 + 5 — Payloads, plumbing, the `EnvelopeScanner` pass

- [x] `webvigil/checks/injection/payloads.py`: `CRLF_TOKEN_BYTES`, `CRLF_HEADER`,
  `CRLF_PAYLOADS` (raw CRLF + `%0d%0a` + upper-encoded + unicode-newline +
  double-CRLF body + `Set-Cookie` split), `CRLF_BODY_MARKER`. — RF-01
- [x] `webvigil/checks/injection/payloads.py`: `XXE_CONTENT_TYPES`, `XXE_FILES`,
  `XXE_PAYLOADS` (SYSTEM entity / parameter-entity / bounded nested),
  `XXE_ERROR_SIGNATURES`. File signatures reuse `TRAVERSAL_SIGNATURES`. — RF-04
- [x] `webvigil/checks/injection/points.py`: `_HEADERLIKE_NAMES` +
  `is_headerlike`. — RF-02
- [x] `webvigil/core/findings.py`: `Category.HTTP`. — RF-10, ADR-3
- [x] `webvigil/core/context.py`: `Observations.envelope_hits` + `TYPE_CHECKING`
  import. `webvigil/core/config.py`: `InjectionSection.xxe` (False),
  `envelope_url_sample` (15), `envelope_budget` (120) + `webvigil.example.toml`.
  `webvigil/http/client.py`: `TRACE` into `_IDEMPOTENT`; `request(content=)`
  threaded through `_request_with_retry` to `httpx`. — RF-04, RF-05, RF-06, RF-12
- [x] `webvigil/checks/envelope/__init__.py` + `scanner.py` — `EnvelopeHit`
  dataclass; `EnvelopeScanner` — `_sample_urls` (entry + form pages + cap, dedup
  by path), per-URL Host poisoning (`_HOST_VECTORS` = Host, X-Forwarded-Host,
  X-Forwarded-Server, X-Host), `_options` (Allow parsing + static-asset guard),
  `_trace` (probes up to 4 sampled URLs; token-echo detection); `_send` (budget
  counter, scope guard, catch-and-continue); never sends a state-changing verb. —
  RF-03, RF-05, RF-06, ADR-2, RNF-03, RNF-06
- [x] `webvigil/checks/envelope/checks.py` — `_EnvelopeCheck` base (filter
  `envelope_hits` by `check_id`); `@register class HostHeaderCheck`
  (`Category.INJECTION`, ACTIVE, MEDIUM, `cwe = (644,)`) / `HttpMethodsCheck`
  (`Category.HTTP`, ACTIVE, MEDIUM, `cwe = (650, 693, 16)`). — RF-08, RF-10
- [x] `webvigil/core/orchestrator.py`: `_scan_envelope(...)` — no-op unless Active
  and a fed check selected; run `EnvelopeScanner`, catch-and-warn; assign
  `Observations.envelope_hits`. `_ENVELOPE_CHECK_IDS` const;
  `webvigil/checks/__init__.py` imports the `envelope` package. — RF-03, RF-05, RF-11
- [x] Tests: `test_injection_points.py` (`is_headerlike`), `test_config.py`
  (`xxe` default + override), `test_findings.py` (`Category.HTTP`),
  `test_envelope_scanner.py` (9 — Location/`<base>`/canonical/absolute-URL hits,
  reset-context HIGH, each X-Forwarded vector, static-asset guard, TRACE echo,
  **request spy: no PUT/DELETE/PATCH/CONNECT**, budget warning, form-page
  sampling), `test_checks_envelope.py` (3 — metadata + finding shape + cross
  filtering). — RF-15
- [x] Quality gate. — ruff/black/mypy/lint-imports green; unit suite green.

## Stage 1 — The `crlf` detector

- [x] `webvigil/checks/injection/detect/crlf.py`: `detect` — own benign baseline
  send (the `Baseline` model has no headers), then full `CRLF_PAYLOADS` for an
  `is_headerlike` point else the first 2 (canary). Proof 1: an `X-WvInjected`
  header `httpx` parsed back, absent from the benign baseline -> HIGH/HIGH.
  Proof 2: a `Set-Cookie` split. Proof 3: the whole response body equals the
  marker. A body-text reflection is not a hit. — RF-01, RF-02, RF-06, ADR-5
- [x] Tests (`test_injection_crlf.py`, 7): header parsed back -> HIGH;
  `Set-Cookie` split; whole-body split; body-text reflection -> no hit; header
  always set by the target -> suppressed; `is_headerlike` canary; `send` -> None
  stops. — RF-15
- [x] Quality gate. — green.

## Stage 2 — The `xxe` detector

- [x] `webvigil/checks/injection/detect/__init__.py`: `DetectCtx.self_url` (the
  target origin) + `Sender` protocol gains `content_type`.
  `webvigil/checks/injection/engine.py`: `InjectionScanner._send` gains
  `content_type` — POST `point.base_url` with `content=value` and a
  `Content-Type` header, no params/data. — RF-04
- [x] `webvigil/checks/injection/detect/xxe.py`: `detect` — `[]` for a non-POST
  point; per `XXE_CONTENT_TYPES` x `XXE_PAYLOADS` (SYSTEM payload also iterating
  `XXE_FILES`), `ctx.send(point, body, content_type=ct)`. Hit on a
  `TRAVERSAL_SIGNATURES` match (HIGH/HIGH) else an `XXE_ERROR_SIGNATURES` match
  (HIGH/MEDIUM), both baseline-absent. — RF-04, RF-06
- [x] Tests (`test_injection_xxe.py`, 6): file signature -> HIGH/HIGH;
  parser-error-only -> HIGH/MEDIUM; plain `400` -> no hit; GET point -> `[]`;
  both content types tried; signature in the baseline -> suppressed. — RF-15
- [x] Quality gate. — green.

## Stage 3 — Engine wiring for `crlf` / `xxe`

- [x] `webvigil/checks/injection/engine.py`: import the two detectors +
  `is_headerlike`; `_DETECTORS["crlf"]` / `["xxe"]`; `_BASE_ORDER = ("xss",
  "sqli-error", "sqli-boolean", "traversal", "redirect", "ssti", "crlf",
  "sqli-time", "cmdi", "xxe", "ssrf")`; `KIND_BY_CHECK_ID` gains both ids;
  `_ordered_kinds` gains `(is_headerlike, "crlf")` and `(_is_post, "xxe")` (xxe
  is last in `_BASE_ORDER` and the per-point cap starved it on a POST point);
  `selected_kinds` drops `"xxe"` when `not config.xxe`. — RF-01, RF-02, RF-04, RF-11, ADR-4
- [x] Tests (`test_injection_engine.py`, +3): both in `_BASE_ORDER` / `_DETECTORS`
  / `KIND_BY_CHECK_ID`; `crlf` front-loaded for a `lang` point; `xxe` in
  `selected_kinds` only when `[injection] xxe` is on. — RF-11, RF-15
- [x] Quality gate. — green.

## Stage 4 — The `injection.crlf` / `injection.xxe` checks, CLI flag

- [x] `webvigil/checks/injection/checks.py`: `_DESCRIPTION` / `_REMEDIATION` /
  `_REFERENCES` for `"crlf"` / `"xxe"`; `@register class CrlfCheck` (HIGH,
  `cwe = (113, 93)`) / `XxeCheck` (HIGH, `cwe = (611, 827)`), both
  `_InjectionCheck`. — RF-07, RF-09
- [x] `webvigil/cli/app.py`: `--xxe / --no-xxe`, threaded through `_build_config`
  -> `injection_overrides["xxe"]`. — RF-12
- [x] Tests: `test_checks_injection.py` (both in `_ALL` + a metadata/finding
  test), `test_cli.py` (`list-checks` shows the four ids + `HTTP`; `--xxe` sets
  the field). — RF-07, RF-09, RF-11, RF-12
- [x] Quality gate. — green.

## Stage 6 — Fixture app, integration tests

- [x] `tests/fixtures/app.py`: `import unquote`; insecure `_set_lang_insecure`
  (parses an injected header out of `lang` and sets it as a real header — the
  fixture simulates the permissive-server split, h11 rejects a raw CRLF),
  `_reset_insecure` (link built from Host / X-Forwarded-Host), `_xml_insecure`
  (async — resolves `file://` payloads to `_ETC_PASSWD`, else a canned
  `lxml.etree.XMLSyntaxError`), `_resource_insecure` (advertises TRACE + PUT +
  DELETE, echoes TRACE). Hardened equivalents. `/api/xml` form in `_FORMS`; the
  three links in `_INJECTION_LINKS`; routes in both profiles. — RF-13, ADR-5
- [x] Tests (`test_scan_fixture_app.py`, +6): CRLF on `/set-lang` `lang`;
  host-header on `/reset`; unsafe methods on `/resource`; XXE on `/api/xml` only
  with `xxe=True`; hardened profile reports none; deterministic fingerprints.
  Passive scan asserts no OPTIONS/TRACE sent.
  `test_crawler_reaches_the_linked_pages` -> **17** (hardened, passive). The
  `scan` fixture's Active config gains `xxe`, `envelope_url_sample = 20`,
  `envelope_budget = 130`. — RF-14
- [x] Quality gate. — green.

## Stage 7 — Docs, roadmap, verification, close

- [x] `docs/active-injection.md`: a "Request-envelope injection" section — the
  four classes, how each is proved in-band, the CRLF-stripping-server caveat, the
  `--xxe` opt-in, and an explicit statement that **blind XXE and request
  smuggling are not covered**. The four table rows; the `[injection]` block. —
  RNF-08
- [x] `README.md` `v0.12` coverage row + roadmap note. `CLAUDE.md` layer-3
  paragraph + `Estado` line -> `012` concluída, `013`-`014` planned.
  `specs/README.md` roadmap row -> **done**. — RNF-08
- [x] All three `012` spec files -> `status: done`; `design.md` "Implementation
  notes" section. — RNF-08
- [x] Manual verification: an Active scan of the fixture reports the four checks
  (xxe with `--xxe`); the hardened profile reports none; `webvigil list-checks`
  shows the four with `INJECTION` / `HTTP`; a request capture confirms only
  `GET` / `POST` / `OPTIONS` / `TRACE` left WebVigil and nothing went to
  `webvigil.invalid`. — RNF-03, RNF-05, RNF-06
- [x] Final full quality gate: ruff / black / mypy / lint-imports (2 contracts
  kept) / pytest — **678 passed**. — RNF-02
