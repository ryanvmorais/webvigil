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

| Version | Focus | Status |
|---|---|---|
| `v0.1` | Security headers, technology-disclosure headers, cookie flags, TLS/HTTPS configuration, CORS misconfiguration (all passive) | shipped |
| `v0.2` | Web API (FastAPI + SQLite, persistent scans, queued execution) | shipped |
| `v0.3` | Web dashboard (Next.js) | shipped |
| `v0.4` | Passive dependency fingerprinting: client-side JS libraries + known-vulnerability matching against a vendored Retire.js database ([docs](docs/dependency-fingerprinting.md)) | shipped |
| `v0.5` | Information disclosure: stack traces and directory listings (passive), plus opt-in probing for exposed `.git`/`.env`/backups/debug endpoints ([docs](docs/information-disclosure.md)) | shipped |
| `v0.6` | Active Mode: injection testing — reflected XSS, SQL injection (error/boolean/time), path traversal, open redirect ([docs](docs/active-injection.md)) | shipped |
| `v0.7` | Authenticated scanning (static cookies), CSRF detection, and form-driven crawling ([docs](docs/authenticated-scanning.md)) | shipped |
| `v0.8` | Stored / persistent XSS: opt-in two-phase inject-then-recrawl detection ([docs](docs/active-injection.md#stored-xss----stored-xss-opt-in)) | shipped |
| `v0.9` | In-band SSRF: cloud metadata service, loopback / internal resources, `file://` — detected from the target's own responses ([docs](docs/active-injection.md#ssrf--cloud-metadata-loopback-file)) | shipped |
| `v0.10` | Opt-in OSV.dev online advisory lookup for dependency fingerprinting, augmenting the vendored Retire.js database ([docs](docs/dependency-fingerprinting.md#osvdev-online-provider---osv-online)) | shipped |
| `v0.11` | Active Mode: in-band OS command injection (arithmetic echo + time-based) and server-side template injection ([docs](docs/active-injection.md#command-injection--ssti)) | shipped |
| `v0.12` | Active Mode: request-envelope injection — CRLF / response splitting, host-header injection, opt-in in-band XXE, and an HTTP-methods (TRACE / verb) check ([docs](docs/active-injection.md#request-envelope-injection)) | shipped |
| `v0.13` | Header / bearer authentication (`--header`), OpenAPI / Swagger import to seed the crawl and the injection pass (`--openapi`), and four passive checks: missing Subresource Integrity, mixed content, session identifier in a URL, private IP in a body ([docs](docs/api-scanning.md)) | shipped |
| `v0.14` | Active Mode: LDAP / XPath / SSI injection (in-band, error signature + differential), and opt-in unrestricted file-upload testing (`--file-upload`) — a benign marker uploaded with a dangerous name / type, then fetched back to prove execution, inline rendering, or a path-traversal write ([docs](docs/active-injection.md#file-upload----file-upload-opt-in)) | shipped |

> Stored XSS shipped in `v0.8` (opt-in `--stored-xss`); in-band SSRF in `v0.9`; the OSV.dev
> online advisory provider in `v0.10` (opt-in `--osv-online`); command injection + SSTI in
> `v0.11`; request-envelope injection in `v0.12` (XXE opt-in `--xxe`); header/bearer auth +
> OpenAPI import in `v0.13`; LDAP / XPath / SSI injection + opt-in file upload in `v0.14`
> (`--file-upload`). **Blind SSRF, truly blind command injection, blind XXE, and HTTP
> request smuggling are not on the roadmap** — each needs an out-of-band collaborator (a
> server the scanner hosts and the target calls back to) or raw-socket control, which the
> "engine talks only to the target" rule and the repository-only distribution rule out. Pair
> WebVigil with your own collaborator (Burp Collaborator, interactsh) for the blind cases.
> YAML OpenAPI documents (convert to JSON first) and leaf-level JSON-body fuzzing are `v0.13`
> limitations, not permanent. Automated login-form flows and session-security tests were on
> the original `v0.7` line and are not yet scheduled — each needs the stateful login flow or
> Active Mode. The full accounting of what active coverage deliberately leaves out is in
> [`docs/active-injection.md`](docs/active-injection.md#coverage-boundaries).

---

## Quick start

> Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run webvigil scan https://example.com
uv run webvigil scan https://example.com --format html --output report.html
uv run webvigil scan https://example.com --probe   # also probe for exposed .git/.env/backups
uv run webvigil scan https://example.com --mode active --authorized-by "you / engagement"  # injection + in-band SSRF testing
uv run webvigil scan https://example.com --mode active --authorized-by me --stored-xss     # + stored XSS (writes markers)
uv run webvigil scan https://example.com --cookie "session=<paste from your browser>"      # authenticated scan
uv run webvigil scan https://example.com --osv-online                                      # also check libraries against OSV.dev
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
same engine. It is single-user and local-first.

```bash
pip install "webvigil[web]"        # or: uv sync --all-extras
webvigil-web serve                 # http://127.0.0.1:8000  (OpenAPI docs at /docs)
```

The database is created and migrated on first start; open `/docs` to create the account.
See [docs/web-api.md](docs/web-api.md) for configuration, auth, and backup.

---

## Web UI

A Next.js dashboard for the Web API: first-run setup, login, scan history, a new-scan form,
scan detail with filterable findings, report preview and download, the check catalogue, and
a settings screen. It is a thin client of the API — it never talks to the engine.

```bash
# API on :8000 in one shell (see above), then:
cd web
pnpm install
pnpm dev                           # http://localhost:3000

# or the whole stack in containers:
docker compose up --build          # dashboard on http://localhost:3000
```

The dashboard calls same-origin `/api/*`; Next proxies that to the API, so no CORS is
involved. See [docs/web-ui.md](docs/web-ui.md).

---

## Development

```bash
uv sync
uv run ruff check .
uv run black --check .
uv run mypy src
uv run lint-imports    # the engine must not import Typer/Rich/FastAPI/SQLModel/Uvicorn
uv run pytest

# Web UI (in web/):
pnpm install && pnpm lint && pnpm typecheck && pnpm test && pnpm build
pnpm test:e2e         # Playwright: setup → scan → report → logout, fully offline
```

See [docs/](docs/) for architecture and a guide to writing your own checks.

---

## Design notes

Short essays on the reasoning behind specific decisions — the *why* behind a spec's ADRs,
written up on their own. Full index in [docs/notes/](docs/notes/).

- [The OAST problem: why blind SSRF is the one thing WebVigil won't do](docs/notes/why-not-oast.md)
- [False-positive discipline in an active scanner](docs/notes/false-positive-discipline.md)
- [Detecting stored XSS means writing data you can't take back](docs/notes/stored-xss-markers.md)
- [Keeping a security engine honest with import-linter](docs/notes/engine-boundaries.md)
- [OSV.dev without an API key](docs/notes/osv-without-a-key.md)

---

## License

[Apache-2.0](LICENSE)
