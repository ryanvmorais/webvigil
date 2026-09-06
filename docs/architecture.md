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

- `webvigil.core` and the other engine packages are a pure library. They must not import
  FastAPI, SQLModel, Typer, or any UI/persistence concern.
- The CLI and the Web API are thin clients of the same `Orchestrator`.
- The Next.js web UI talks only to the Web API, never to the engine directly.

## Scan flow

1. Parse the target URL, build the `Target` (scope + politeness policy).
2. Crawler discovers in-scope pages (bounded by `max_pages`).
3. Orchestrator selects checks whose `mode` is allowed for this run (Active Mode is opt-in).
4. Checks run with bounded concurrency against the shared `ScanContext`.
5. Findings are aggregated, deduplicated by fingerprint, and assigned severity.
6. A reporter renders the result (JSON / SARIF / HTML / Markdown).

See [writing-checks.md](writing-checks.md) for the check plugin contract.

The authoritative design lives in [`specs/001-foundation/`](../specs/).
