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
point at production.

**Active Mode** (payload injection: XSS, SQLi, SSRF, etc.) is opt-in, requires an explicit
authorization flag, and is intended for development and staging environments only.

### Authorized use only

Only scan systems you own or are explicitly authorized to test. Unauthorized scanning may
be illegal. See [SECURITY.md](SECURITY.md).

---

## Planned coverage

| Version | Focus |
|---|---|
| `v0.1` | Security headers, cookie flags, TLS/HTTPS configuration, CORS misconfiguration (all passive) |
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
```

Use in CI — fail the build on high-severity findings:

```bash
uv run webvigil scan "$TARGET_URL" --format sarif --output results.sarif --fail-on high
```

---

## Development

```bash
uv sync
uv run ruff check .
uv run black --check .
uv run mypy src
uv run pytest
```

See [docs/](docs/) for architecture and a guide to writing your own checks.

---

## License

[Apache-2.0](LICENSE)
