---
feature: Auth width and API surface — header/bearer auth, OpenAPI import to seed points, four missing passive checks
status: done
date: 2026-09-08
related:
  - 013-auth-and-api-surface/requirements.md
  - 013-auth-and-api-surface/design.md
origin: conception
---

# 013 — Auth width and API surface — Tasks

Ordered, small, each tagged with the requirement / ADR it satisfies. The last
task of every stage is the quality gate (`ruff → black → mypy src →
lint-imports → pytest`). Engine + CLI only — no `web` gate, no API migration
(RNF-01, RNF-02).

Baseline at spec 012 close: **678 passed**. At 013 close: **741 passed** (+63).

## Stage 0 — Plumbing: config fields, `Category.CONTENT`, `OpenApiError`

- [x] `webvigil/core/findings.py`: `Category.CONTENT = "CONTENT"` + a docstring
  line ("page content: subresource integrity, mixed content"). — RF-15, ADR-5
- [x] `webvigil/core/errors.py`: `class OpenApiError(WebVigilError)`. — RF-05
- [x] `webvigil/core/config.py`: `AuthSection.headers: list[str] = []` with a
  `_check_headers` validator (`Name: Value` shape; reject `Host` /
  `Content-Length` case-insensitively) and a `header_pairs` property (value
  keeps any `:` after the first). `ScanSection.openapi: str | None = None` and
  `openapi_max_operations: int = 150` + `Attributes:` lines. `with_overrides`
  docstring mentions `[auth] headers` and `[scan] openapi`. — RF-01, RF-02, RF-05, RF-10
- [x] `webvigil.example.toml`: `[auth] headers = []` with a comment
  ("CLI: --header \"Name: Value\" (repeatable), which replaces this list"); a
  commented `[scan] openapi` / `openapi_max_operations`. — RNF-09
- [x] Grep `src/webvigil/api/` + `web/src/` for a hardcoded category list (as
  spec 006 / 012 did); confirm `Category.CONTENT` needs no API / UI / OpenAPI
  change. — Risks
- [x] Tests: `test_findings.py` (`Category.CONTENT` value; a `Finding` carrying
  it serialises / re-loads); `test_config.py` (`[auth] headers` valid pair
  round-trips; missing `:` / empty name / `Host` / `Content-Length` →
  `ConfigError`; `header_pairs` keeps a `:` in the value; `[scan] openapi` /
  `openapi_max_operations` defaults + round-trip). — RF-18
- [x] Quality gate. — ruff / black / mypy (104 files) / lint-imports (2 kept) green;
  `test_config.py` + `test_findings.py` green. `web/src` derives its category
  filter from data, `api` returns `category` as a string — `Category.CONTENT`
  needs no API / UI change.

## Stage 1 — Header / bearer authentication, end to end

- [x] `webvigil/http/client.py`: store `config.auth.header_pairs`; in
  `_request_with_retry`, after the cookie block, attach each configured header
  to a request whose host is the target host, skipping any name the caller
  already set (case-insensitive). — RF-03
- [x] `webvigil/core/orchestrator.py`: `metadata.authenticated =
  bool(self._config.auth.cookies or self._config.auth.headers)`.
  `webvigil/crawler/crawler.py`: `self._authenticated =
  bool(config.auth.cookies or config.auth.headers)`. — RF-04
- [x] `webvigil/cli/app.py`: `--header` (`list[str] | None`, repeatable,
  `"Name: Value"`); thread through `_build_config` → `auth_overrides["headers"]`
  (whole-list replace); `_emit` passes `header_count=len(cfg.auth.headers)`.
  `webvigil/cli/_render.py`: `summary(..., header_count: int = 0)` — the
  authenticated-scan line reports cookies and headers, counts only.
  `--openapi` (`str | None`) added here too, threaded to `scan.openapi` (acted
  on in Stage 3). — RF-02, RF-04
- [x] Tests: `test_http_client.py` (attached to a target-host request; not to an
  off-host request; a caller-set `Authorization` wins); `test_cli.py` (`--header`
  parsed and forwarded / replaces a file list; a malformed `--header` → clean
  error; the `"1 cookie + 1 header"` summary line with the token absent);
  `test_config.py` (`--header` override replaces the file list). The
  report-render secrecy assertion lands in the Stage 6 integration test (the
  header never enters `ScanResult`). — RF-18, RNF-04
- [x] Quality gate. — ruff / black / mypy / lint-imports green;
  `test_http_client.py` + `test_cli.py` + `test_config.py` + `test_findings.py`
  + `test_crawler.py` + `test_orchestrator.py` green.

## Stage 2 — The OpenAPI / Swagger parser

- [x] `webvigil/crawler/openapi.py` (new): `ApiOperation` frozen dataclass;
  `load_openapi(source, *, http, target, max_operations) -> (list[ApiOperation],
  list[str])`; `_fetch_document` (in-scope URL via `http.get`, or a local file;
  `OpenApiError` on a missing file / bad JSON / non-200 / a body that is not
  JSON / no `openapi` and no `swagger` key); `_base_url` (3.x `servers[0].url`
  default `"/"`; 2.0 `schemes[0]`+`host`+`basePath`; relative → joined to
  `target.origin`; foreign host → path kept, origin replaced, warning);
  `_resolve` (local `#/` JSON-pointer walk; external `$ref` → `{}` + one-time
  warning; visited-set cycle guard); `_values(params, loc)` (deterministic
  `example` → `default` → `enum[0]` → type placeholder); `_body` (form-urlencoded
  → `body_fields`, `application/json` → `body_json`, else none; 2.0 `formData` /
  `in: body`); `_fill_path` (`{name}` → `quote(value, safe="")`). Operations
  limited to `get` / `post`; `_EXCLUDE_FORM_RE` on `path + operationId`; sort by
  `(url_template, method)`; `max_operations` cap → warning; empty → warning. —
  RF-05, RF-06, RF-07, RF-08, RF-09, RF-10, ADR-3, ADR-4
- [x] Tests: `test_crawler_openapi.py` (new) — 3.0 / 3.1 / 2.0 base URLs;
  relative `servers[0].url`; foreign host → target origin + warning; local
  `$ref` (parameter + nested schema) resolved; `$ref` cycle → placeholder;
  external `$ref` → skipped + one warning; missing file / bad JSON / not an
  OpenAPI doc → `OpenApiError`; `operationId` `deleteUser` / path `/logout`
  excluded; `max_operations` cap → warning + truncation; value-synthesis
  precedence; `application/json` body → `body_json`, form body → `body_fields`. —
  RF-18
- [x] Quality gate. — ruff / black / mypy (105 files) / lint-imports green; 19 openapi tests green.

## Stage 3 — Seeding the crawl and the injection pass

- [x] `webvigil/crawler/crawler.py`: `__init__(..., extra_seeds: Sequence[str]
  = ())`; in `discover()`, enqueue the seeds through `_maybe_enqueue` **before**
  the entry page's links / forms / sitemaps. — RF-09
- [x] `webvigil/checks/injection/points.py`: `enumerate_points(pages, forms,
  operations: tuple[ApiOperation, ...] = (), *, max_points)` — synthesize a
  point per query param, per path param (`source = "openapi-path"`, `base_url` =
  the `{name}` template), and per form-urlencoded body field (`source =
  "openapi"`); merge into the existing `seen` dedup, `points.sort`, and
  `max_points` cap. `build_request` — a branch for `source == "openapi-path"`
  that substitutes and URL-encodes the payload into the template. — RF-09, ADR-6
- [x] `webvigil/checks/injection/engine.py`: `InjectionScanner.__init__(...,
  operations: tuple[ApiOperation, ...] = ())`; pass to `enumerate_points` in
  `run()`. — RF-09
- [x] `webvigil/core/orchestrator.py`: `_load_openapi(http, target, warnings)`
  — no-op returning `()` when `[scan] openapi` is unset; else `load_openapi(...)`,
  re-raising `OpenApiError` (fatal, before the crawl); extend `warnings`. Call it
  inside the `HttpClient` context before `Crawler`; pass `extra_seeds=[op.url for
  op in operations if op.method == "GET"]`. `_inject(..., operations=...)` forwards
  them to `InjectionScanner`; thread `operations` from `run()`. — RF-05, RF-09
- [x] Tests: `test_injection_points.py` (a GET operation → query + path points; a
  POST operation with a form body → body points; a point whose `key` matches a
  crawled query point is de-duplicated; `build_request` path-template
  substitution; `max_points` caps the merged set); `test_crawler.py`
  (`extra_seeds` fetched, counted, scope-guarded, de-duplicated against HTML
  links; a seed blocked by `robots.txt` is skipped). — RF-18
- [x] Quality gate. — ruff / black / mypy (105 files) / lint-imports green; injection + crawler + orchestrator + openapi unit tests green.

## Stage 4 — `content.sri.missing` and `content.mixed`

- [x] `webvigil/checks/content/__init__.py` (new): package marker + `from
  webvigil.checks.content import checks  # noqa: F401`.
  `webvigil/checks/content/checks.py` (new): `@register class SriMissingCheck`
  (`Category.CONTENT`, `PASSIVE`, MEDIUM, `cwe = (353, 1104)`) — cross-origin
  `script[src]` / `link[rel~=stylesheet]` / `preload`|`modulepreload` with no
  `integrity` (or `integrity` but no `crossorigin`); same-origin skipped; dedup
  by resource URL. `@register class MixedContentCheck` (`Category.CONTENT`,
  `PASSIVE`, MEDIUM, `cwe = (319,)`) — an `https://` page referencing an
  `http://` subresource (active → MEDIUM, passive → LOW); `//host` not flagged;
  `http://` page skipped; dedup by URL. — RF-11, RF-12, ADR-5, ADR-7, RNF-06
- [x] `webvigil/checks/__init__.py`: add `content` to `_load_builtin_checks`.
- [x] Tests: `test_checks_content.py` (new) — SRI: cross-origin no `integrity` →
  MEDIUM; `integrity` no `crossorigin` → MEDIUM (distinct title); same-origin →
  none; a CDN script on three pages → one finding. Mixed: synthesized `https`
  page + `http://` `<script>` → MEDIUM, + `http://` `<img>` → LOW; `//cdn/x` →
  none; `http://` page → none. — RF-18
- [x] Quality gate. — ruff / black / mypy (107 files) / lint-imports green; 8 content tests + registry + cli green.

## Stage 5 — `disclosure.session-id-in-url` and `disclosure.private-ip`

- [x] `webvigil/checks/disclosure/leakage.py` (new): `@register class
  SessionIdInUrlCheck` (`Category.DISCLOSURE`, `PASSIVE`, MEDIUM, `cwe = (598,)`)
  — a `_SESSION_KEYS` key (narrowed: no bare `token` / `auth`) as a query or
  `;name=value` path parameter in an `<a href>`, a `<form action>`, a redirect
  `history` hop, or `page.final_location` — **not** `page.url` /
  `page.requested_url` (a scanner-crafted `--openapi` seed carries a value
  there); value redacted; dedup by `(key, redacted URL)`; only target-produced
  URLs. `@register class PrivateIpInBodyCheck`
  (`Category.DISCLOSURE`, `PASSIVE`, LOW, `cwe = (200,)`) — an RFC-1918 /
  loopback / link-local / IPv6 ULA-or-loopback literal in a body; drop the
  target's own host; `_PER_PAGE_CAP = 10` with a note on truncation; redacted
  context window. — RF-13, RF-14, ADR-7, RNF-06
- [x] `webvigil/checks/disclosure/__init__.py`: import `leakage`.
- [x] Tests: `test_checks_disclosure_leakage.py` (new) — session id: `?PHPSESSID=`
  in `page.url`, `;jsessionid=` in an `<a href>`, `access_token=` in an
  out-of-scope `Location`; value redacted; a URL not in `ctx.pages` → none.
  private ip: each range matches; `203.0.113.5` → none; target host `10.0.0.5`
  → none; 15 addresses on one page → 10 findings + a note. — RF-18
- [x] `test_cli.py`: `list-checks` shows the four ids with `CONTENT` /
  `DISCLOSURE`. `test_findings.py` already covers `Category.CONTENT`. — RF-15, RF-18
- [x] Quality gate. — ruff / black / mypy (108 files) / lint-imports green; leakage + content + cli + disclosure-registry tests green. `_render._PASSIVE_DISCLOSURE_IDS` extended so the two new checks are not counted as exposed paths.

## Stage 6 — Fixture app, integration tests

- [x] `tests/fixtures/app.py`: `GET /openapi.json` (both profiles) declaring
  `GET /api/find` (query `q`, insecure handler reflects `q` unescaped — reflected
  XSS; **not linked** from any HTML page) and `POST /api/items` (form field
  `name`). The passive-check content is **inlined into the insecure index page**
  (`_SPEC_013_INSECURE`: a cross-origin SRI-less `<script>`, an `access_token=`
  in a third-party `<a href>`, a `10.13.37.1` HTML comment) rather than a new
  `/legacy` route — a new crawled page shifts the spec-008 stored-XSS re-crawl
  past its 60-page cap. The `/ping` link value changed `127.0.0.1` → `localhost`
  (a literal loopback IP in the shared index HTML would trip
  `disclosure.private-ip` on both profiles). — RF-16, ADR-4
- [x] Tests: `test_scan_fixture_app.py` (+5) — Active insecure + `--openapi
  http://<fixture>/openapi.json` → an `injection.xss.reflected` on `/api/find`
  `q` (an endpoint no HTML links) and a `GET /api/find?` in the request log;
  passive insecure → `content.sri.missing`, `disclosure.session-id-in-url`
  (`access_token`, value redacted), `disclosure.private-ip`, **no**
  `content.mixed` (fixture is `http`); a `--header` bearer token is absent from
  the canonical JSON (even via the `/resource` TRACE echo); two `--openapi` runs
  → identical fingerprints. — RF-17, RNF-04, RNF-06
- [x] Re-measured the injection budget against the fixture with `--openapi` — no
  starvation; `openapi_max_operations` / the per-point cap unchanged. — RNF-05
- [x] Quality gate. — ruff / black / mypy / lint-imports green; the stored-XSS +
  spec-013 integration subset green (13 tests).

## Stage 6b — Secrecy fix in the spec-012 envelope pass

- [x] `webvigil/checks/envelope/scanner.py`: `_SECRET_HEADER_LINE` masks
  `Authorization` / `Cookie` / `X-API-Key` / … header lines a TRACE echo
  reflects, before they enter the XST finding's evidence — a configured `[auth]`
  header is a target-host request header, so a `/resource`-style TRACE echo would
  otherwise leak it (RNF-04). — RNF-04
- [x] Test: `test_envelope_scanner.py` (+1) — a TRACE echo reflecting
  `authorization:` / `cookie:` → masked in the evidence.
- [x] Quality gate. — green.

## Stage 7 — Docs, roadmap, verification, close

- [x] `docs/authenticated-scanning.md`: a "Header and bearer authentication"
  section — the `--header` flag, `[auth] headers`, host-gating, the secrecy
  guarantee, cookie vs header. `docs/api-scanning.md` (new): the OpenAPI import
  — what it extracts, how seeding works, and the explicit limitations (**JSON
  only**, **no leaf-level JSON-body fuzzing**, **local `$ref`s only**,
  **GET/POST only**, robots still honoured, foreign server host → target
  origin). `docs/content-checks.md` (new) for `content.*`;
  `docs/information-disclosure.md` extended for the two `disclosure.*`;
  `docs/active-injection.md` enumeration step mentions `--openapi`. — RNF-09
- [x] `README.md` `v0.13` coverage row + the roadmap note. `CLAUDE.md`: the
  layer-3 paragraph (the four checks, `Category.CONTENT`, header auth, OpenAPI
  import) and the `Estado` line → `013` concluída, `014` opcional.
  `specs/README.md` roadmap row → **done** with the delivered scope; the
  `> 011 a 014` note updated ("011, 012 e 013 estão entregues"). — RNF-09
- [x] All three `013` spec files → `status: done`; `design.md` "Implementation
  notes" section (what shipped, where it differed). — RNF-09
- [x] Manual verification: an Active scan of the fixture with
  `--openapi http://demo.test/openapi.json` reaches `/api/find` (an unlinked
  endpoint) and reports the XSS finding; a passive scan reports
  `content.sri.missing` / `disclosure.session-id-in-url` / `disclosure.private-ip`
  on the insecure profile and none on the hardened; `webvigil list-checks` shows
  the four with `CONTENT` / `DISCLOSURE`; a request capture confirms nothing went
  to a host other than the target and a `--header` bearer token is absent from
  the JSON report. — RNF-03, RNF-04
- [x] Final full quality gate: `ruff → black → mypy src → lint-imports (2
  contracts kept) → pytest` — **741 passed** (was 678 at spec 012 close). — RNF-02
