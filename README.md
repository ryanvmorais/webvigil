# WebVigil

A web application vulnerability scanner for developers. It helps teams find and fix
security misconfigurations in web apps, both **in development** (terminal, CI, pre-deploy)
and **in production** (non-intrusive checks that are safe to run against live systems).

WebVigil ships as a reusable **scan engine**, a **CLI**, and an optional **web dashboard**
built on top of the same engine.

> **Status:** early development (`v0.x`). The API, CLI flags, and report formats may change.

---

## Safe by default

WebVigil runs in **Safe Mode** by default: it only observes responses, headers, TLS
configuration, cookies, and page content. It never sends attack payloads and is safe to
point at production. The one request it adds beyond plain page fetches is a single GET
with an `Origin` header, used to detect reflective CORS — still a read-only GET, still
restricted to the target scope.

**Active Mode** (payload injection: XSS, SQLi, SSRF, etc.) is opt-in, requires an explicit
authorization flag, and is intended for development and staging environments only.

### Authorized use only

Only scan systems you own or are explicitly authorized to test. Unauthorized scanning may
be illegal. See [SECURITY.md](SECURITY.md).

---

## Planned coverage

| Version | Focus |
|---|---|
| `v0.1` | Security headers, technology-disclosure headers, cookie flags, TLS/HTTPS configuration, CORS misconfiguration (all passive) |
| `v0.2` | Web dashboard (FastAPI + SQLite + Next.js) |
| `v0.3` | Dependency / technology fingerprinting and known-CVE matching |
| `v0.4` | Information disclosure and misconfiguration (exposed files, directory listing, debug endpoints) |
| `v0.5` | Active Mode: injection testing (XSS, SQLi, SSRF, path traversal, open redirect) |
| `v0.6` | Authenticated scanning and session/CSRF checks |

---

## Quick start

> Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run webvigil scan https://example.com
uv run webvigil scan https://example.com --format html --output report.html
uv run webvigil list-checks
uv run webvigil report report.json --format md      # re-render a saved scan, offline
```

By default the scan prints a summary to your terminal (stderr). With `--format` it writes
the report to stdout (or `--output PATH`), so you can pipe it.

Use in CI — fail the build on high-severity findings:

```bash
uv run webvigil scan "$TARGET_URL" --format sarif --output results.sarif --fail-on high
```

Exit codes: `0` clean · `3` findings at or above `--fail-on` · `4` operational error
(bad target, unreachable host, config) · `5` Active Mode without `--authorized-by`.

Install the CLI standalone with `pipx install .` or `uv tool install .`, or run it from the
bundled image: `docker build -t webvigil . && docker run --rm webvigil scan https://example.com`.

---

## Web API

An optional FastAPI service keeps a history of scans in SQLite and runs them through the
same engine. It is single-user and local-first; a browser dashboard is planned separately.

```bash
pip install "webvigil[web]"        # or: uv sync --all-extras
webvigil-web serve                 # http://127.0.0.1:8000  (OpenAPI docs at /docs)
# or: docker compose up --build
```

The database is created and migrated on first start; open `/docs` to create the account.
See [docs/web-api.md](docs/web-api.md) for configuration, auth, and backup.

---

## Development

```bash
uv sync
uv run ruff check .
uv run black --check .
uv run mypy src
uv run lint-imports    # the engine must not import Typer/Rich/FastAPI/SQLModel/Uvicorn
uv run pytest
```

See [docs/](docs/) for architecture and a guide to writing your own checks.

---

## License

[Apache-2.0](LICENSE)
