# Architecture

WebVigil is organized in layers. Each layer only depends on the ones below it.

```
Web UI            web/  (Next.js dashboard — talks only to the Web API)
Interfaces        CLI (webvigil.cli)   ·   Web API (webvigil.api, extra `web`)
                        \                        /
Scan Engine            webvigil.core  (Orchestrator, Target, Finding, config)
                  webvigil.http · webvigil.crawler · webvigil.checks
Reporting              webvigil.reporting  (JSON · SARIF · HTML · Markdown)
Persistence       webvigil.api.db  (SQLite via SQLModel + Alembic, web only)
```

## Rules

- `webvigil.core` and the other engine packages (`http`, `crawler`, `checks`, `reporting`)
  are a pure library. They must not import Typer, Rich, FastAPI, SQLModel, Alembic, PyJWT,
  or argon2 — a CI `import-linter` contract enforces this. `webvigil.cli` and
  `webvigil.api` do not import each other.
- The CLI and the Web API are thin clients of the same `Orchestrator`.
- `webvigil.checks.deps` adds passive dependency fingerprinting: the orchestrator runs a
  fingerprint pass (not a check) that identifies client-side JS libraries and matches them
  against a vendored Retire.js database; two `deps.*` checks turn the result into findings
  and a technology inventory on the `ScanResult`. Offline by default; an opt-in
  `_osv_lookup` pass (`--osv-online`) additionally queries OSV.dev and merges the result.
  See [dependency-fingerprinting.md](dependency-fingerprinting.md).
- `webvigil.checks.disclosure` adds information-disclosure detection: two passive checks
  read already-crawled responses (stack traces, directory listings), and — only when
  `[disclosure] probe` / `--probe` is on — the orchestrator runs a probe pass that requests
  a curated catalogue of well-known sensitive paths (`.git`, `.env`, backups, debug
  endpoints), content-validates each, and feeds six probe-fed `disclosure.*` checks.
  GET-only, in-scope, off by default; see
  [information-disclosure.md](information-disclosure.md).
- `webvigil.checks.injection` adds the first Active-Mode checks (spec 006): reflected XSS,
  SQL injection (error / boolean / time), path traversal, and open redirect. The
  orchestrator runs one bounded `InjectionScanner` pass — enumerate injection points (query
  params + `<form>` fields parsed from crawled bodies), baseline each once, fan the
  detectors under a shared request budget — and six thin `injection.*` checks turn its hits
  into findings. Gated by `--mode active --authorized-by`; `GET`/`POST` only; in-band
  detection (no headless browser, no out-of-band collaborator). Spec 008 adds
  `injection.xss.stored`: a separate `StoredXssScanner` pass (after the reflected one, opt-in
  via `--stored-xss`) submits `<wvstored…>` markers, then re-crawls (`Crawler.recrawl`,
  depth 1) to find them rendered unescaped on another page. See
  [active-injection.md](active-injection.md).
- The `webvigil.http` client exposes `request(method, …)` for verbs beyond `GET`; a
  non-idempotent request is never retried on a `5xx` or read timeout. Configured `[auth]`
  cookies (spec 007) are attached to target-host requests only, and the client discards
  anything the target sets via `Set-Cookie` so a scan sends exactly what is configured.
- `webvigil.checks.csrf` adds one passive check (spec 007): `csrf.form.no-token` flags a
  state-changing `POST` form with no anti-CSRF token, weighted by the session cookie's
  `SameSite`. It reads `ScanContext.forms` — the `<form>` inventory the crawler now parses
  during `discover()` and also uses to submit safe `GET` forms. See
  [authenticated-scanning.md](authenticated-scanning.md).
- The Web API adds persistence and a single-slot in-process `ScanRunner` (one scan runs at
  a time; the rest queue). It never reimplements crawling, checks, or reporting.
- The Next.js web UI (`web/`) talks only to the Web API, never to the engine directly. In
  every environment the Next server proxies `/api/*` to the API, so the browser stays
  same-origin and no CORS is involved. See [web-ui.md](web-ui.md).

## Scan flow

1. Parse the target URL, build the `Target` (scope + politeness policy).
2. Enforce the Active-Mode gate: `active` mode without an `authorized_by` attestation is
   refused here, in the engine, so every caller is bound by it.
3. The `HttpClient` opens; all requests route through its shared rate limiter (concurrency
   cap + per-host delay) and scope guard.
4. The crawler discovers in-scope pages — `<a href>` links plus optional `sitemap.xml`
   seeds — bounded by `max_pages` and gated by `robots.txt`.
5. The orchestrator selects registered checks whose `mode` is allowed and that are not in
   `checks.disabled`, then runs them concurrently against a shared `ScanContext`.
6. Findings are collected, deduplicated by fingerprint, ordered deterministically, and
   returned in a `ScanResult` alongside per-check errors and warnings.
7. A reporter renders the result (JSON is canonical; SARIF / HTML / Markdown are pure
   functions of it, so `webvigil report` re-renders any format offline).

See [writing-checks.md](writing-checks.md) for the check plugin contract,
[web-api.md](web-api.md) for running the Web API, and [stack.md](stack.md) for
every technology in the project — what it does and why it was chosen.

The authoritative designs live under [`specs/`](../specs/) — `001-foundation` (engine + CLI),
`002-web-api` (persistence + API), `003-web-ui` (the Next.js dashboard),
`004-deps-fingerprint` (passive dependency fingerprinting), `005-info-disclosure`
(exposed files, directory listing, stack traces, debug endpoints),
`006-active-injection` (reflected XSS, SQLi, path traversal, open redirect),
`007-auth-flows` (authenticated scanning with static cookies, CSRF detection,
form-driven crawling), `008-stored-xss` (two-phase inject-then-recrawl stored XSS),
and `010-osv-online` (opt-in OSV.dev online advisory provider for the dependency
fingerprint).
