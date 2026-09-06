---
feature: Foundation — scan engine, check contract, v0.1 passive coverage, reporters, CLI
status: done
date: 2026-09-06
related: [001-foundation/requirements.md, 001-foundation/design.md]
origin: conception
---

# 001 — Foundation — Tasks

Ordered, small tasks grouped by stage. Each references the requirement(s) it satisfies.
The last task of every stage is a quality gate (`/qualidade-python`:
`ruff → black → mypy --strict → pytest`). Work top to bottom; mark `[x]` after each.

TDD where it pays: for the checks and the model, write the failing test first.

---

## Stage 0 — Setup

- [x] Add dev dependencies `import-linter`, `jsonschema`, `trustme` to `pyproject.toml`
  (`[dependency-groups].dev`); run `uv sync --all-extras`. — RNF-02, ADR-1, ADR-7
- [x] Create the engine module skeleton per the design layout. (Modules written directly
  with their stage-1..8 content rather than as empty stubs.) — design §"Module layout"
- [x] Add the `importlinter` contract: `core`, `http`, `crawler`, `checks`, `reporting`
  must not import `typer`, `rich`, `fastapi`, `sqlmodel`, `uvicorn`, `webvigil.cli`; added
  `uv run lint-imports` as a CI step in `.github/workflows/ci.yml`. — RNF-01, ADR-1
- [x] Quality gate.

## Stage 1 — Core model and config

- [x] `core/errors.py`: `WebVigilError` base + `InvalidTargetError`, `OutOfScopeError`,
  `RequestFailed`, `ActiveModeNotAuthorized`, `DuplicateCheckId`, `ConfigError`. — design §"errors.py"
- [x] `core/findings.py`: `Severity`/`Confidence` (`IntEnum`), `Category`/`ScanMode`
  (`StrEnum`), `Location` (+ `.key`), `EvidenceItem` (4 KiB trim), `Finding` (frozen). — RF-12, RF-13
- [x] `core/findings.py`: `compute_fingerprint(check_id, location, dedup_key)` →
  `sha256(...)[:16]`; wired via `Check.finding` (Stage 4) — `Finding.fingerprint` is required. — RF-12
- [x] `core/result.py`: `ScanMetadata`, `CheckError`, `ScanResult` (frozen pydantic). — RF-11, RF-21
- [x] `core/config.py`: `ScanSection`/`HttpSection`/`ReportSection`/`ActiveSection`/
  `ChecksSection`/`ScanConfig` with `extra="forbid"`; `ScanConfig.load(path)` via `tomllib`;
  `ScanConfig.with_overrides(**set_flags)` deep-merge. — RF-26
- [x] `core/target.py`: `Scope`, `Target.parse` (scheme default, reject non-http(s)),
  `normalize_url`, `in_scope(url)` + bundled registrable-suffix subset. — RF-01, RF-02
- [x] Tests: `Finding` fingerprint stability + equality; `ScanResult` JSON round-trip;
  `ScanConfig` rejects unknown keys and applies CLI > file > default precedence;
  `Target.parse`/`in_scope` for host & subdomains, invalid input raises. — RF-01, RF-02, RF-12, RF-21, RF-26
- [x] Quality gate.

## Stage 2 — HTTP layer

- [x] `http/policy.py`: `RateLimiter(concurrency, delay_ms)` — `asyncio.Semaphore` +
  per-host "not-before" clock; async context-manager `slot(host)`. — RF-03
- [x] `http/scope_guard.py`: `ScopeGuard(target)` with `check(url)` raising `OutOfScopeError`
  and `allows(url) -> bool`. — RF-04
- [x] `http/client.py`: `Response` view; `HttpClient` over
  `httpx.AsyncClient(http2=True, follow_redirects=False, verify=..., timeout=...)`;
  retry (2×, backoff+jitter, on transport/timeout/5xx); manual redirect walk with
  per-hop scope check, hop cap 10, `redirected_out_of_scope`/`final_location`; `stats`. — RF-05, RF-04
- [x] `http/tls_probe.py`: `probe(host, port=443) -> TlsProbeResult` via `asyncio.to_thread`,
  holding a `RateLimiter` slot; per-version `SSLContext` handshake; distinguish
  "refused" vs "unavailable locally"; return peer cert DER. — RF-19, ADR-8
- [x] Tests (`pytest-httpx`): retry then success / then `RequestFailed`; `OutOfScopeError`
  pre-flight (no socket); redirect chain stops at cross-scope hop and keeps evidence URLs;
  `delay_ms` spacing; in-flight requests never exceed `concurrency` (instrumented). — RF-03, RF-04, RF-05
- [x] Tests (`trustme` + localhost TLS socket): expired / wrong-host / self-signed cert;
  single-version server → correct `offered_versions`. — RF-19
- [x] Quality gate.

## Stage 3 — Crawler and context

- [x] `crawler/robots.py`: fetch + parse `robots.txt` via `urllib.robotparser`; expose
  `can_fetch(ua, url)` and discovered `Sitemap:` URLs; missing file → allow-all. — RF-07
- [x] `crawler/sitemap.py`: best-effort `sitemap.xml` parse (stdlib XML); malformed/missing
  → `[]`, never raises. — RF-07
- [x] `core/context.py`: `Page` (requested/final url, status, headers, body, elapsed,
  history, error), `ScanContext` (frozen) + `page_for(url)`. — RF-06, RF-10
- [x] `crawler/crawler.py`: `Crawler.discover()` — BFS from seed + sitemap seeds, `<a href>`
  extraction (`selectolax`), normalize/de-dup, `in_scope` filter, `follow_robots` gate,
  `max_pages` stop; seed page always first; `RequestFailed` recorded, crawl continues. — RF-07, RF-03
- [x] Tests: `max_pages` stop; URL normalization/de-dup; `robots` disallow honored and
  ignored when `follow_robots=false`; malformed sitemap ignored; checks not robots-gated. — RF-07
- [x] Quality gate.

## Stage 4 — Check contract and registry

- [x] `checks/base.py`: `Check` ABC (ClassVars + abstract `async run`) + `finding(...)`
  helper that pre-fills class metadata and computes the fingerprint. — RF-08
- [x] `checks/registry.py`: `_REGISTRY`, `@register` (validate required ClassVars,
  `DuplicateCheckId` guard), `load_plugins()` over
  `entry_points(group="webvigil.checks")`, `iter_checks(*, mode, disabled)`. — RF-09, RF-11
- [x] `checks/__init__.py`: re-export `Check`, `register`, `iter_checks`, `load_plugins`;
  import built-in check subpackages so their `@register` runs. — RF-09
- [x] Tests: `@register` rejects missing metadata; duplicate `id` raises; fake-distribution
  entry point is discovered; `iter_checks` filters by `mode` and `disabled`, unknown
  disabled id surfaced as a warning. — RF-09, RF-11
- [x] Quality gate.

## Stage 5 — Orchestrator

- [x] `core/orchestrator.py`: `Orchestrator(config, check_types=None)`; `run(raw_target)` —
  parse target → active-mode gate (`ActiveModeNotAuthorized`) → `HttpClient` ctx →
  `Crawler.discover()` → build `ScanContext` → select checks → run in `asyncio.TaskGroup`
  (HTTP concurrency still bounded by the shared `RateLimiter`) → per-check `CheckError`
  capture → `dedupe` by fingerprint → assemble `ScanResult` (metadata, counts, warnings). — RF-11, RF-15, RF-03
- [x] `core/__init__.py`: finalize public re-exports
  (`Orchestrator, Target, Scope, ScanConfig, ScanContext, ScanResult, Finding, Severity,
  Confidence, Category, ScanMode` + error types). — design §"Overview"
- [x] Tests: passive run selects only `PASSIVE` checks; active without `authorized_by`
  raises; gated active run executes and records `authorized_by` in metadata; one check
  raising does not stop the others (recorded as `CheckError`); duplicate findings dedupe;
  unknown disabled id → `warnings`. — RF-11, RF-15
- [x] Quality gate.

## Stage 6 — v0.1 checks

Each check ships with a **vulnerable** fixture (asserts id, `severity`, `dedup_key`,
evidence substring) and a **hardened** fixture (asserts `[]`). — RF-16

- [x] `checks/headers/_parsing.py`: shared helpers (CSP directive split, `Set-Cookie`
  attribute parse, header presence/normalization). — RF-16, RF-17, RF-18
- [x] `CspCheck` (`http.headers.csp`): missing / `unsafe-inline` / `unsafe-eval` /
  permissive `default-src` + tests. — RF-16
- [x] `HstsCheck` (`http.headers.hsts`): missing on HTTPS / low `max-age` / no
  `includeSubDomains`; contextual downgrade when site is HTTP-only + tests. — RF-16, RF-12
- [x] `FrameOptionsCheck` (`http.headers.frame-options`): neither XFO nor CSP
  `frame-ancestors` + tests. — RF-16
- [x] `ContentTypeOptionsCheck` (`http.headers.content-type-options`): not `nosniff` + tests. — RF-16
- [x] `ReferrerPolicyCheck` (`http.headers.referrer-policy`): missing / leaking value + tests. — RF-16
- [x] `PermissionsPolicyCheck` (`http.headers.permissions-policy`): missing (INFO) + tests. — RF-16
- [x] `CrossOriginIsolationCheck` (`http.headers.cross-origin-isolation`): COOP/COEP/CORP
  missing (INFO) + tests. — RF-16
- [x] `RevealingHeadersCheck` (`http.headers.revealing`): `Server` w/ version, `X-Powered-By`,
  `X-AspNet-Version`, `X-Runtime` + tests. — RF-17
- [x] `CookieFlagsCheck` (`http.cookies.flags`): missing `Secure`/`HttpOnly`,
  `SameSite=None` w/o `Secure`, `__Host-`/`__Secure-` prefix violations, broad
  `Domain`/`Path`; scans every in-scope response + tests. — RF-18
- [x] `TlsHttpsCheck` (`tls.https`): legacy protocol versions, cert expiry/hostname/weak-sig/
  self-signed (`cryptography`), no HTTP→HTTPS redirect, HSTS misalignment, basic mixed
  content + tests (socket-based). — RF-19
- [x] `CorsCheck` (`http.cors.misconfiguration`): one `Origin:` probe GET; reflective ACAO,
  `*` + `Allow-Credentials` + tests. — RF-20
- [x] Quality gate.

## Stage 7 — Reporters

- [x] `reporting/__init__.py`: `Reporter` protocol, `get_reporter(fmt)`, `load_result(path)`;
  shared deterministic sort `(-severity, check_id, location.url, location.key)`. — RF-21, RNF-04
- [x] `reporting/json_report.py`: canonical `model_dump_json(indent=2, by_alias=True)`;
  document the shape in `docs/`. — RF-21
- [x] `reporting/sarif.py`: hand-built 2.1.0 dict (driver, `rules` per used `check_id`,
  `results` with `level`, `security-severity`, `partialFingerprints`); bundle
  `reporting/schemas/sarif-2.1.0.json`; validation test with `jsonschema`. — RF-22, ADR-7
- [x] `reporting/templates/report.html.j2` + `reporting/html.py`: single self-contained file,
  inline CSS, no external requests, grouped by severity, summary header. — RF-23
- [x] `reporting/markdown.py`: severity-count table + per-finding sections. — RF-23
- [x] Tests: SARIF schema-valid; HTML has zero external URLs and escapes evidence; Markdown
  counts match; all reporters produce byte-identical output across repeated runs. — RF-22, RF-23, RNF-04
- [x] Quality gate.

## Stage 8 — CLI

- [x] `cli/_exit.py`: `ExitCode` enum (`OK=0, INTERNAL=1, USAGE=2, FINDINGS=3,
  OPERATIONAL=4, NOT_AUTHORIZED=5`) + `evaluate(result, fail_on) -> ExitCode`. — RF-25
- [x] `cli/_render.py`: Rich summary table written to **stderr**. — RF-24
- [x] `cli/app.py` `scan`: assemble `ScanConfig` (`load` + `with_overrides`), active-mode
  prompt when TTY / reject with `OPERATIONAL` otherwise, legal banner to stderr, run
  `Orchestrator`, route output (no `--format` → summary only; `--format` → report to stdout;
  `--output` → file + status line), map errors to exit codes. — RF-24, RF-14, RF-15, RF-26, ADR-9
- [x] `cli/app.py` `list-checks`: `load_plugins()` then Rich table of
  `id / category / mode / default_severity`. — RF-24
- [x] `cli/app.py` `report`: `load_result(path)` → `get_reporter(fmt).render()` → stdout or
  `--output`; no network. — RF-24, ADR-6
- [x] Tests (`CliRunner`): `scan` with stubbed `Orchestrator` for each output mode; exit
  codes per `--fail-on`; active-mode prompt accepted / empty-rejected / non-TTY-rejected;
  `list-checks`; `report` re-renders every format offline. — RF-24, RF-25, RF-15
- [x] Quality gate.

## Stage 9 — Fixture app and integration

- [x] `tests/fixtures/app.py`: Starlette app with `insecure` and `hardened` profiles
  (headers, cookies, CORS, revealing `Server`). — RF-27
- [x] Integration test via `httpx.ASGITransport`: insecure scan reports every
  HTTP/cookie/CORS/revealing-header finding the v0.1 checks target; hardened scan reports
  **zero** findings. — RF-27, RNF-05
- [x] Quality gate.

## Stage 10 — Docs, packaging, verification

- [x] Complete `docs/writing-checks.md` against the final contract (RF-08/09/10) with a
  worked example and the vulnerable+hardened testing rule. — RF-28
- [x] Verify `docs/architecture.md` spec reference resolves; align wording with the shipped
  design. — RF-28
- [x] Update `README.md` quick-start commands to match the implemented CLI and document the
  CORS-probe caveat (RNF-05). — RF-28
- [x] Add `Dockerfile` (engine + CLI, no `web` extra); add a `docker build` smoke step to
  `ci.yml`; document `pipx install .` / `uv tool install .`. — RF-29
- [x] Update `[tool.hatch.build.targets.wheel]` to ship `reporting/templates/*`; keep the
  SARIF schema test-only. — RF-29
- [x] Run the manual verification checklist from `requirements.md` §Verification equivalent:
  live `scan` to HTML + SARIF, `--fail-on high` exit code, `pipx`/`docker` run. — RF-24, RF-25, RF-29
- [x] Final full quality gate; set `requirements.md`, `design.md`, `tasks.md`,
  and this spec's frontmatter `status: done`.
