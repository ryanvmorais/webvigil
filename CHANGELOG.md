# Changelog

All notable changes to WebVigil are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/); what that promises is in
[docs/stability.md](docs/stability.md).

The `v0.1` to `v0.20` milestones in the README are the steps the project was built in, each
designed as a spec under [`specs/`](specs/). None of them was released: `1.0.0` is the first
release and contains all of them.

## [Unreleased]

## [1.0.0] - 2026-10-08

The first release.

### Added

**Scanner and CLI**
- `webvigil scan` in **Safe Mode** by default (passive: it reads and sends no crafted request),
  `list-checks`, `report` (re-render a saved scan offline) and `version`.
- Reports in JSON (canonical, with a `schema_version`), SARIF 2.1.0, HTML and Markdown;
  `--fail-on` and documented exit codes for CI.
- A `webvigil.toml` configuration file (every key can be overridden by a flag), a scope guard,
  bounded concurrency, a request delay, a page limit and `robots.txt` handling on every scan (a warning says when it kept URLs out of the crawl, when the target stopped answering, or when the
  entry page looks like a JavaScript application the crawler cannot see into).
  A response body is read up to `[http] max_body_bytes` (10 MiB, after decompression) and the rest is
  dropped with a warning, so a hostile or oversized response cannot exhaust the scanner's memory.

**Passive checks**
- Security headers and technology-disclosure headers, cookie flags, TLS and HTTPS configuration,
  CORS misconfiguration.
- Client-side dependency fingerprinting with known-vulnerability matching against a vendored
  Retire.js database, and an opt-in OSV.dev lookup (`--osv-online`).
- Information disclosure: stack traces and directory listings, plus opt-in probing for exposed
  `.git`, `.env`, backups and debug endpoints (`--probe`).
- Subresource Integrity, mixed content, a session identifier in a URL, a private IP in a body.
- CSRF: forms that carry no anti-CSRF token.
- Session security: weak or predictable session ids (`session.id.weak`), with opt-in anonymous
  sampling (`--sample-sessions`).

**Active Mode** (`--mode active --authorized-by "<name / engagement>"`, in-band, every finding
confirmed against a per-request baseline)
- Reflected XSS; SQL injection (error, boolean and time based); path traversal; open redirect;
  SSRF (cloud metadata, loopback and internal hosts, `file://`); OS command injection; server-side
  template injection; expression-language injection (SpEL, OGNL, JEXL, MVEL, Unified EL); CRLF
  injection; host-header injection; LDAP, XPath and SSI injection; dangerous HTTP methods.
- Opt-in, each off by default and documented as writing to the target or making a real request:
  stored XSS (`--stored-xss`), file upload (`--file-upload`), XXE (`--xxe`), CSRF confirmation
  (`--confirm-csrf`), POST crawling (`--submit-post-forms`), automated login (`--login-url`) and
  the logout test (`--test-logout`).
- Session fixation (`session.fixation`) and a logout that does not invalidate the session
  (`session.logout.not-invalidated`), which build on the automated login.

**Authenticated and API scanning**
- Static cookies (`--cookie`) and headers (`--header`); an automated form login that keeps the
  session and logs in again when it drops (one attempt, never another credential, the password
  only from the environment or a prompt); OpenAPI / Swagger import (`--openapi`).

**Web API and dashboard** (optional, in the repository)
- A FastAPI service with SQLite persistence and a queued scan runner, and a Next.js dashboard for
  it.
  `docker compose` publishes them on `127.0.0.1` only; see [Who can reach it](docs/web-api.md#who-can-reach-it).
  Login attempts are throttled (a wait that doubles up to 5 minutes), and changing the password signs
  the other sessions out.

**Packaging**
- A package for PyPI: the engine, the CLI and (with the `web` extra) the Web API, published from a
  GitHub Release with PyPI Trusted Publishing (no stored token) after a dry run on TestPyPI. The
  dashboard stays in the repository. See [releasing](docs/releasing.md).
- A container image for the CLI on `ghcr.io/ryanvmorais/webvigil` (`linux/amd64` and `linux/arm64`; tags
  `X.Y.Z`, `X.Y`, `X` and `latest`), built, smoke-tested and vulnerability-scanned before it is pushed,
  with signed build provenance and an SBOM.
- `selectolax` is capped below 1.0: version 1.0 removed the parser the engine imports.

**Quality and security of the project**
- Strict typing, an import contract that keeps the engine independent of the CLI, the API and the
  database, 1137 tests, a CI matrix on Python 3.12 to 3.14, Lighthouse CI for the dashboard, CodeQL
  and Dependabot.
- A security policy with private vulnerability reporting, a code of conduct, and the
  [stability policy](docs/stability.md).

[Unreleased]: https://github.com/ryanvmorais/webvigil/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ryanvmorais/webvigil/releases/tag/v1.0.0
