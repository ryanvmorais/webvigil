# Architecture

WebVigil is organized in layers. Each layer only depends on the ones below it.

```
Interfaces        CLI (webvigil.cli)   ·   Web API (webvigil.api)
                        \                        /
Scan Engine            webvigil.core  (Orchestrator, Target, Finding, config)
                  webvigil.http · webvigil.crawler · webvigil.checks
Reporting              webvigil.reporting  (JSON · SARIF · HTML · Markdown)
Persistence           SQLite via SQLModel  (web only)
```

## Rules

- `webvigil.core` and the other engine packages (`http`, `crawler`, `checks`, `reporting`)
  are a pure library. They must not import Typer, Rich, FastAPI, SQLModel, or Uvicorn — a
  CI `import-linter` contract enforces this.
- The CLI and the (future) Web API are thin clients of the same `Orchestrator`.
- The Next.js web UI talks only to the Web API, never to the engine directly.

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

See [writing-checks.md](writing-checks.md) for the check plugin contract.

The authoritative design lives in
[`specs/001-foundation/`](../specs/001-foundation/).
