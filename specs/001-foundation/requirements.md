---
feature: Foundation — scan engine, check contract, v0.1 passive coverage, reporters, CLI
status: done
date: 2026-09-06
related: []
origin: conception
---

# 001 — Foundation

## Context and problem

WebVigil is an open-source web application vulnerability scanner for developers. It must
be usable both in development (terminal, CI, pre-deploy) and against production (only
non-intrusive checks). Today the repository is a scaffold: packages, `pyproject.toml`, CI,
`LICENSE`, `SECURITY.md` and a `version` CLI command exist, but there is no engine, no
check contract, no reporters, and no real `scan` command.

This spec establishes the foundation every later spec builds on: the pure scan engine, the
check plugin contract, the finding model, the "good neighbor" policy, the Safe/Active mode
gate, the first set of passive checks (v0.1), the four report formats, and the CLI. When it
lands, WebVigil is a working open-source CLI scanner (`v0.1`).

Layered architecture (from `docs/architecture.md`, unchanged by this spec):

```
Interfaces      CLI (webvigil.cli)          [Web API is spec 002 — out of scope here]
Scan Engine     webvigil.core (Orchestrator, Target, Finding, config)
                webvigil.http · webvigil.crawler · webvigil.checks
Reporting       webvigil.reporting (JSON · SARIF · HTML · Markdown)
```

The engine (`core`, `http`, `crawler`, `checks`, `reporting`) is a pure library: it must
not import Typer, FastAPI, SQLModel, or any UI/persistence concern.

## Goals

- A reusable, pure-Python **scan engine** driven by a single `Orchestrator`.
- A stable **check plugin contract** with decorator registration and third-party discovery
  via entry points.
- A canonical **`Finding` / `Severity`** model with fingerprint-based deduplication.
- **Safe Mode (`PASSIVE`) as the default**, safe to point at production; **Active Mode
  (`ACTIVE`)** reachable only through an explicit authorization gate (no active checks ship
  in this spec — only the mode and its gate).
- An always-on **"good neighbor" policy**: concurrency cap, request delay, page-count limit,
  and a scope guard that blocks out-of-scope hosts.
- **v0.1 passive coverage** as the reference implementation of the check contract:
  security headers, revealing headers, cookie flags, TLS/HTTPS, CORS.
- Four **reporters**: JSON (canonical), SARIF 2.1.0, HTML (standalone), Markdown.
- A **CLI** (`scan`, `list-checks`, `report`, `version`) with a `--fail-on` threshold that
  drives the process exit code for CI use.
- A **test target application** with an "insecure" and a "hardened" profile; integration
  tests assert every expected finding on the insecure profile and **zero** findings on the
  hardened one (false-positive guard).

## Non-goals

- Web API, FastAPI, persistence, authentication, async scan execution as a service — **spec 002**.
- Next.js Web UI — **spec 002**.
- Active injection checks (XSS, SQLi, SSRF, path traversal, open redirect) — **spec 005**.
  Only the `ACTIVE` mode value and its authorization gate are in scope here.
- Dependency / technology fingerprinting and CVE matching — **spec 003**.
- Information-disclosure checks (exposed `.git`/`.env`, directory listing, debug endpoints) — **spec 004**.
- Authenticated / session-aware scanning and CSRF checks — **spec 006**.
- Queued or distributed scan execution (workers, `arq`, Redis).
- Exhaustive TLS cipher-suite enumeration. v0.1 covers protocol versions and certificate
  properties via the `ssl`/`socket` stdlib; deeper analysis (e.g. `sslyze`) is a later enhancement.
- JavaScript rendering / headless browser crawling. The crawler parses served HTML only.
- Form discovery and submission during crawling — **spec 006**.
- Publishing to PyPI (tracked separately). Note: `pipx install .` and a CLI `Dockerfile`
  **are** in scope for 001 (RF-29).

## Personas

| Persona | Needs from 001 |
|---|---|
| **CI pipeline author** | Machine-readable output (SARIF/JSON), a meaningful exit code via `--fail-on`, a run that is safe against production and finishes within a bounded time. |
| **Security-conscious developer** | A readable local report (HTML/terminal/Markdown) with severity, evidence, and remediation guidance for each finding; confidence that Safe Mode changes nothing on the target. |
| **Check author / contributor** | A documented, stable `Check` contract; a `ScanContext` that already carries fetched pages and responses; a test pattern (vulnerable + hardened fixtures). |
| **Security researcher / pentester** | Explicit, auditable Active Mode gating and scope restriction, so the tool cannot be pointed outside an authorized target by accident. |

## Functional requirements

### Target, scope, and policy

**RF-01 — Target normalization**
The engine builds a `Target` from a user-supplied URL.
- **Given** a URL with no scheme, **when** a scan starts, **then** `https://` is assumed and
  the normalized target is recorded.
- **Given** a URL with a path, query, or fragment, **when** the `Target` is built, **then**
  the scope host and origin are derived and the entry URL is preserved as the crawl seed.
- **Given** an input that is not a valid HTTP(S) URL (e.g. `ftp://`, `not a url`), **when**
  a scan starts, **then** it fails immediately with a clear error and a non-zero exit code.

**RF-02 — Scope model**
- **Given** `--scope host` (default), **when** the crawler or a check considers a URL, **then**
  only URLs on the exact target host are in scope.
- **Given** `--scope subdomains`, **when** a URL on a subdomain of the registrable domain is
  considered, **then** it is in scope.
- **Given** any other host, **when** it is considered, **then** it is out of scope regardless
  of setting.

**RF-03 — "Good neighbor" policy (always on)**
Every run enforces, with no way to disable: a concurrency cap, a per-host request delay, a
crawler page-count limit, and the scope guard (RF-04).
- **Given** a configured concurrency of *N*, **when** the orchestrator runs checks and the
  crawler fetches pages, **then** no more than *N* requests to the target are in flight at once.
- **Given** a configured delay of *D* ms, **when** two consecutive requests go to the same
  host, **then** they are separated by at least *D* ms.
- **Given** `--max-pages M`, **when** the crawler has discovered *M* in-scope pages, **then**
  it stops discovering new pages.
- Defaults come from `webvigil.example.toml` (`concurrency = 8`, `delay_ms = 0`,
  `max_pages = 50`, `timeout_s = 15`).

**RF-04 — Scope guard**
- **Given** any component issues an HTTP request through the engine's HTTP layer, **when**
  the request URL's host is out of scope, **then** the request is blocked before any network
  I/O and the event is surfaced (logged / counted), not silently dropped.
- **Given** a redirect response whose `Location` points to an out-of-scope host, **when** the
  HTTP layer would follow it, **then** it does not follow across the scope boundary; the
  redirect target is still recorded as evidence where relevant (e.g. TLS HTTP→HTTPS check).

### HTTP layer

**RF-05 — Async HTTP client wrapper**
- **Given** a scan, **when** any component needs HTTP, **then** it uses the shared async
  client wrapper (over `httpx`), never a raw client, so policy (RF-03/04), retries, and
  timeouts apply uniformly.
- **Given** a transient failure (connection error, 5xx on an idempotent GET, timeout),
  **when** a request is made, **then** it is retried up to a bounded number of times with
  backoff; a permanent failure is recorded and does not abort the whole scan.
- **Given** `verify_tls = false` (config or `--insecure`-style flag), **when** requests are
  made, **then** certificate verification is disabled *for the HTTP client only* and the
  TLS check (RF-15) still evaluates and reports the certificate problem.
- The client sends the configured `user_agent` and honors `timeout_s`.

**RF-06 — Base-response cache**
- **Given** the entry URL and each crawled page, **when** it is first fetched, **then** the
  response (status, headers, body, timing, final URL after in-scope redirects) is cached in
  the `ScanContext` so multiple checks reuse one fetch.

### Crawler

**RF-07 — Lightweight in-scope discovery**
- **Given** the seed URL, **when** the crawler runs, **then** it fetches the seed, extracts
  `<a href>` links, and enqueues those that are in scope (RF-02), bounded by `max_pages`
  (RF-03) and de-duplicated by normalized URL.
- **Given** the target exposes `sitemap.xml` (directly or via `robots.txt`), **when** the
  crawler runs, **then** it may seed the queue from the sitemap's in-scope URLs (bounded by
  `max_pages`). Sitemap parsing is best-effort: a missing or malformed sitemap is not an error.
- **Given** `follow_robots = true` (default), **when** the crawler considers a URL disallowed
  by the target's `robots.txt`, **then** it does not fetch it.
- **Given** `follow_robots = false`, **when** crawling, **then** `robots.txt` is ignored.
- `robots.txt` restricts **crawler discovery only**. Checks operate on already-discovered
  in-scope pages and are never gated by `robots.txt`.
- The crawler performs GET requests only. Form discovery and submission are out of scope
  (spec 006).

### Check contract, registry, and context

**RF-08 — Check contract**
A check is a class exposing this metadata and behavior:

| Field | Meaning |
|---|---|
| `id` | Stable dotted identifier, e.g. `http.headers.csp-missing` |
| `name` | Human-readable title |
| `category` | `HEADERS` \| `COOKIES` \| `TLS` \| `CORS` (extensible: `DEPS`, `DISCLOSURE`, `INJECTION`) |
| `mode` | `PASSIVE` \| `ACTIVE` |
| `default_severity` | `Severity` |
| `cwe` | list of CWE ids |
| `references` | list of URLs |
| `run(ctx)` | `async` → `list[Finding]` |

- **Given** a check whose `run` raises, **when** the orchestrator executes it, **then** the
  exception is caught, recorded as a scan error against that `check_id`, and the remaining
  checks still run.
- **Given** a check returns findings, **when** the orchestrator collects them, **then** each
  finding is stamped with the originating `check_id`.

**RF-09 — Registration and discovery**
- **Given** a check class decorated with `@register`, **when** the module is imported, **then**
  the check is available in the registry.
- **Given** a third-party package that declares a `webvigil.checks` entry point, **when**
  WebVigil starts, **then** its checks are discovered without any code change to WebVigil.
- **Given** two checks with the same `id`, **when** the registry loads them, **then** it
  raises a clear configuration error naming the duplicate id.

**RF-10 — ScanContext**
`ScanContext` passed to every check carries: the HTTP client wrapper, the `Target`
(scope + policy), the resolved configuration, the list of discovered pages, and the
base-response cache (RF-06). Checks must not construct their own HTTP client or read global
state.

**RF-11 — Orchestrator**
- **Given** a run in `PASSIVE` mode (default), **when** the orchestrator selects checks,
  **then** only `mode == PASSIVE` checks run.
- **Given** a run in `ACTIVE` mode that passed the gate (RF-13), **when** checks are selected,
  **then** both `PASSIVE` and `ACTIVE` checks run.
- **Given** `--checks`/`disabled` configuration, **when** checks are selected, **then**
  disabled ids are excluded and an unknown id in the list is reported as a warning.
- **Given** all selected checks finished, **when** the orchestrator assembles the result,
  **then** findings are deduplicated by `fingerprint` (RF-12) and the result carries scan
  metadata: target, mode, start/end time, counts per severity, and per-check errors.

### Findings and severity

**RF-12 — Finding model**
A `Finding` has: `check_id`, `severity`, `confidence` (`LOW`/`MEDIUM`/`HIGH`), `title`,
`description`, `evidence` (trimmed request/response snippets), `location` (URL and optional
param/header/cookie name), `remediation`, `cwe`, `references`, `fingerprint`.
- **Given** two findings with the same `check_id`, `location`, and salient evidence key,
  **when** fingerprints are computed, **then** they are equal and the pair deduplicates to one.
- **Given** a check needs to raise or lower severity for context (e.g. missing HSTS on a
  site already served only over HTTP), **when** it emits the finding, **then** it may set a
  severity different from `default_severity`.

**RF-13 — Severity levels**
`Severity` is an ordered enum `INFO < LOW < MEDIUM < HIGH < CRITICAL`. Ordering is used by
`--fail-on` (RF-25) and by report grouping.

### Scan modes and authorization gate

**RF-14 — Safe Mode default**
- **Given** no `--mode` flag, **when** a scan runs, **then** it runs in `PASSIVE` mode:
  only observation, no attack payloads, no state-changing requests.

**RF-15 — Active Mode gate**
- **Given** `--mode active` **without** `--authorized-by`, **when** the scan is invoked in a
  non-interactive context, **then** it refuses to start with an explanatory error and a
  non-zero exit code.
- **Given** `--mode active` without `--authorized-by` in an interactive terminal, **when**
  invoked, **then** the CLI prompts for the authorization text and refuses if it is empty.
- **Given** `--mode active --authorized-by "<text>"`, **when** the scan starts, **then** a
  legal-warning banner is shown, the authorization text is recorded in the scan metadata and
  every report, and Active checks become eligible.
- **Given** Active Mode, **when** any check runs, **then** it is still bound by the scope
  guard (RF-04) — payloads never leave the target scope.
- Note: no `ACTIVE` checks exist in this spec, so an Active run currently executes the same
  passive checks. The gate and metadata must still work end to end.

### v0.1 checks (all `PASSIVE`)

Each check below ships with unit tests using a **vulnerable** fixture (finding reported,
correct severity + evidence) and a **hardened** fixture (nothing reported).

**RF-16 — Security headers checks** (`category = HEADERS`)
Implemented as **one check class per header family** (e.g. `CspCheck`, `HstsCheck`,
`FrameOptionsCheck`, `ContentTypeOptionsCheck`, `ReferrerPolicyCheck`, `PermissionsPolicyCheck`,
`CrossOriginIsolationCheck`), so each can be tested and disabled independently via its `id`.
Evaluate on the entry response (and each crawled page where it adds signal):
- **CSP**: missing; `unsafe-inline` / `unsafe-eval` present; overly permissive `default-src`
  (e.g. `*`).
- **HSTS**: missing on an HTTPS response; `max-age` below a threshold; missing
  `includeSubDomains`; (informational) missing `preload`.
- **X-Frame-Options** / CSP `frame-ancestors`: neither present.
- **X-Content-Type-Options**: not `nosniff`.
- **Referrer-Policy**: missing or set to a leaking value (`unsafe-url`).
- **Permissions-Policy**: missing (informational).
- **COOP / COEP / CORP**: missing (informational / low).
- **Given** an HTTPS response with no `Strict-Transport-Security`, **when** the check runs,
  **then** a `MEDIUM` finding `http.headers.hsts-missing` is reported with the response
  headers as evidence.
- **Given** a response with `Content-Security-Policy` containing `script-src 'unsafe-inline'`,
  **when** the check runs, **then** a finding identifies the weak directive and quotes it.
- **Given** a response carrying a strong CSP, HSTS with a long `max-age` + `includeSubDomains`,
  `X-Content-Type-Options: nosniff`, a `frame-ancestors` policy, and a sane `Referrer-Policy`,
  **when** the check runs, **then** no finding is reported.

**RF-17 — Revealing-headers check** (`category = HEADERS`)
- **Given** a response with `Server: Apache/2.4.41 (Ubuntu)`, `X-Powered-By`, `X-AspNet-Version`,
  or `X-Runtime`, **when** the check runs, **then** a `LOW`/`INFO` finding per revealed header
  quotes the header value.
- **Given** a response with none of those headers (or `Server` reduced to a product with no
  version), **when** the check runs, **then** no finding is reported.

**RF-18 — Cookie flags check** (`category = COOKIES`)
For every `Set-Cookie` on any in-scope response:
- Missing `Secure` on an HTTPS site; missing `HttpOnly`; missing or `SameSite=None` without
  `Secure`.
- `__Host-` / `__Secure-` prefix present but constraints not met.
- `Domain` or `Path` scoped more broadly than the setting URL.
- **Given** `Set-Cookie: session=abc; Path=/` on an HTTPS response, **when** the check runs,
  **then** a `MEDIUM` finding reports the missing `Secure` and `HttpOnly` flags, `location`
  naming the cookie.
- **Given** `Set-Cookie: __Host-session=abc; Secure; HttpOnly; Path=/; SameSite=Lax`, **when**
  the check runs, **then** no finding is reported.

**RF-19 — TLS / HTTPS check** (`category = TLS`)
- Protocol versions offered by the host: flag TLS 1.0 / 1.1 as findings; TLS 1.2 acceptable;
  TLS 1.3 preferred (informational when absent).
- Certificate: expired / not-yet-valid; expiring soon (threshold); hostname mismatch; weak
  signature algorithm (e.g. SHA-1); self-signed for a public target.
- `http://` entry URL that does not redirect to `https://`.
- HSTS present but site reachable over plaintext without redirect (misalignment).
- Basic mixed content: an HTTPS page referencing `http://` sub-resources in the served HTML.
- **Given** a target offering TLS 1.0, **when** the check runs, **then** a `MEDIUM`/`HIGH`
  finding `tls.protocol.legacy-version` names the version.
- **Given** an `http://` target that returns 200 with no redirect, **when** the check runs,
  **then** a `HIGH` finding reports "no HTTPS / no redirect to HTTPS".
- **Given** a target on TLS 1.2+ with a valid, matching, strong certificate and an
  HTTP→HTTPS redirect, **when** the check runs, **then** no finding is reported.
- Scope note: protocol enumeration is a per-version `ssl`/`socket` stdlib handshake probe
  and covers version detection only. **No third-party TLS dependency** (e.g. `sslyze`) is
  added in 001; cipher-suite grading is out of scope (see Non-goals).

**RF-20 — CORS check** (`category = CORS`)
- **Given** a request with `Origin: https://evil.example` and the response echoes
  `Access-Control-Allow-Origin: https://evil.example`, **when** the check runs, **then** a
  finding reports reflective ACAO; if `Access-Control-Allow-Credentials: true` is also present
  the severity is `HIGH`.
- **Given** `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`,
  **when** the check runs, **then** a `HIGH` finding is reported (invalid + dangerous combo).
- **Given** no CORS headers, or a fixed non-reflective allow-list origin, **when** the check
  runs, **then** no finding is reported.

### Reporting

**RF-21 — JSON reporter (canonical)**
- **Given** a completed scan, **when** rendered as JSON, **then** the output contains scan
  metadata (target, mode, timestamps, `authorized_by` if any, tool version) and the full
  list of findings with every `Finding` field. This format is the input to `report` (RF-24).
- The JSON is stable and documented (a schema or documented shape).

**RF-22 — SARIF 2.1.0 reporter**
- **Given** a completed scan, **when** rendered as SARIF, **then** the output validates
  against the SARIF 2.1.0 schema: one `run`, a `driver` with `rules` (one per check id used),
  and `results` mapping findings to rules with `level` derived from severity and a
  `partialFingerprints` entry from the finding fingerprint.
- **Given** a SARIF file uploaded to GitHub code scanning, **then** findings appear with
  location and rule metadata.

**RF-23 — HTML and Markdown reporters**
- **Given** a completed scan, **when** rendered as HTML, **then** the output is a single
  self-contained file (inline CSS, no external requests) grouping findings by severity, with
  evidence and remediation, and a summary header.
- **Given** a completed scan, **when** rendered as Markdown, **then** the output is suitable
  for pasting into a PR or issue: a summary table plus a section per finding.

### CLI

**RF-24 — Commands**

```
webvigil scan <url> [--mode passive|active] [--scope host|subdomains]
                    [--format json|sarif|html|md] [--output PATH]
                    [--max-pages N] [--delay MS] [--authorized-by TEXT]
                    [--config PATH] [--fail-on none|info|low|medium|high|critical]
webvigil list-checks
webvigil report <scan.json> --format json|sarif|html|md [--output PATH]
webvigil version
```

- **Given** `webvigil scan <url>` with no `--format`, **when** it runs, **then** it prints a
  human-readable summary to the terminal (Rich, on stderr).
- **Given** `--format <fmt>` without `--output`, **when** the scan finishes, **then** the
  report is written to **stdout** (pipeable) and the human-readable summary goes to
  **stderr**.
- **Given** `--output PATH`, **when** the scan finishes, **then** the report is written there
  and only a short status line goes to stderr; stdout stays empty.
- **Given** `webvigil list-checks`, **when** it runs, **then** it lists every registered
  check with `id`, `category`, `mode`, and `default_severity`.
- **Given** `webvigil report scan.json --format <fmt>`, **when** it runs, **then** it
  re-renders the saved scan into **any** of the four formats without performing any network
  request (the canonical JSON carries everything SARIF/HTML/Markdown need).

**RF-25 — `--fail-on` exit code**
- **Given** `--fail-on high`, **when** the scan produces at least one finding of severity
  `HIGH` or `CRITICAL`, **then** the process exits non-zero (dedicated code for "findings at
  or above threshold").
- **Given** `--fail-on none` (default), **when** the scan completes without an operational
  error, **then** the process exits zero regardless of findings.
- **Given** an operational failure (invalid target, network unreachable, config error),
  **then** the process exits with a distinct non-zero code, separate from the findings code.
- `--fail-on` compares **severity only**. A per-confidence filter (`--min-confidence`) is a
  later enhancement, not part of 001.

**RF-26 — Config file and precedence**
- **Given** a `webvigil.toml` (or `--config PATH`), **when** a scan runs, **then** values are
  read from it; **when** a CLI flag is also given, **then** the CLI flag wins.
- **Given** `webvigil.example.toml` keys, **then** the config model accepts exactly those
  sections/keys and rejects unknown keys with a clear error.

### Test target application

**RF-27 — Insecure vs hardened fixture app**
- A minimal Starlette app under `tests/fixtures/` serves two profiles: **insecure** (no
  security headers, cookies without flags, reflective CORS, revealing `Server` header, …)
  and **hardened** (all of the above corrected).
- **Given** a scan against the **insecure** profile, **when** it completes, **then** every
  finding the v0.1 checks are designed to catch is present.
- **Given** a scan against the **hardened** profile, **when** it completes, **then** **zero**
  findings are reported (false-positive guard). TLS-specific cases that need a real socket
  are covered by unit tests with crafted certificates/sockets rather than the fixture app.

### Documentation

**RF-28 — Fill the stubs**
- `docs/writing-checks.md` is completed to describe the final contract (RF-08/09/10) with a
  worked example and the testing requirement.
- `docs/architecture.md` "authoritative design lives in specs/001-foundation" reference
  resolves (the spec exists).
- `README.md` quick-start commands match the implemented CLI (RF-24).

### Packaging

**RF-29 — Installable CLI**
- **Given** a checkout, **when** a user runs `pipx install .` (or `uv tool install .`),
  **then** the `webvigil` command is available outside the dev environment and
  `webvigil scan <url>` works.
- **Given** the repository `Dockerfile`, **when** the image is built and run
  (`docker run <image> scan <url>`), **then** the CLI runs the scan. The image bundles the
  engine + CLI only (no Web API extra).
- Publishing the image or wheel to a registry is **not** in scope; a reproducible local
  build is.

## Non-functional requirements

**RNF-01 — Engine purity**
`webvigil.core`, `webvigil.http`, `webvigil.crawler`, `webvigil.checks`, `webvigil.reporting`
must not import `typer`, `fastapi`, `sqlmodel`, `uvicorn`, or `rich`. Enforced by a test that
imports each engine module with those packages shadowed, or an import-linter contract.

**RNF-02 — Type safety and style**
`uv run ruff check .`, `uv run black --check .`, `uv run mypy src` (strict), and
`uv run pytest` all pass. New public functions and classes have docstrings (English).

**RNF-03 — Async throughout the engine**
The HTTP layer, crawler, checks, and orchestrator are `asyncio`-based. The CLI is the only
place that starts an event loop.

**RNF-04 — Determinism**
Given the same target responses, a scan produces the same set of findings and the same
fingerprints across runs. Report output ordering is stable (e.g. by severity then check id
then location).

**RNF-05 — Safe against production**
A `PASSIVE` scan issues only GET requests to in-scope URLs, sends no attack payloads, and
performs no state-changing requests. The CORS probe (RF-20), which adds an `Origin` header
to an otherwise normal GET, is the most active thing Safe Mode does and must be documented
as such.

**RNF-06 — Bounded runtime**
A default scan (`max_pages = 50`, `concurrency = 8`) of a small site completes within a
predictable time; the crawler and orchestrator honor `timeout_s` per request and never hang
on a slow host.

**RNF-07 — Python support**
Runs on CPython 3.12 and 3.13 (CI matrix already configured).

**RNF-08 — Licensing / provenance**
All new code is original or compatibly licensed; SARIF generation is schema-driven, not a
vendored heavy dependency.

## Resolved decisions

All open questions from the draft were resolved with Ryan on 2026-09-06:

1. **Header check granularity (RF-16):** one check class per header family — better
   testability and per-check `disabled` control.
2. **`--fail-on` (RF-25):** severity only in 001; `--min-confidence` is a later enhancement.
3. **Crawler link sources (RF-07):** `<a href>` + optional `sitemap.xml` in 001; form
   discovery deferred to spec 006.
4. **TLS enumeration (RF-19):** stdlib `ssl` per-protocol handshake probing is accepted for
   001; no third-party dependency (`sslyze`) added now.
5. **`report` re-render (RF-24):** supports all four formats — the canonical JSON carries
   everything SARIF/HTML/Markdown need.
6. **`--format` without `--output` (RF-24):** report to stdout, human summary to stderr.
7. **Packaging (RF-29):** `pipx install .` and a CLI `Dockerfile` are in scope for closing
   001; registry publishing is not.
8. **`robots.txt` scope (RF-07):** restricts crawler discovery only; checks operate on
   already-discovered in-scope pages.

## Open questions

None. Ready for `/spec design`.
