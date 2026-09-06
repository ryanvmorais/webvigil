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

See [writing-checks.md](writing-checks.md) for the check plugin contract and
[web-api.md](web-api.md) for running the Web API.

The authoritative designs live under [`specs/`](../specs/) — `001-foundation` (engine + CLI),
`002-web-api` (persistence + API), and `003-web-ui` (the Next.js dashboard).
