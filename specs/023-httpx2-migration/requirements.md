---
feature: Engine HTTP client migration — move the engine from httpx to httpx2 with no change in what a scan reports (issue #304)
status: done
date: 2026-11-22
related:
  - 001-foundation/design.md
  - 010-osv-online/requirements.md
  - 019-automated-login/design.md
origin: conception
---

# 023 — Engine HTTP client migration

## Context and problem

The engine's HTTP client is `httpx[http2]`. Its last stable release is 0.28.1, from December 2024, and it
has no published security advisory: nothing is broken today. Meanwhile the stack around the engine has
moved to [`httpx2`](https://github.com/pydantic/httpx2), the continuation of the project maintained by
Pydantic. Starlette's test client already uses it, and so does this repository's test suite, which leaves
the engine and its tests on two different HTTP stacks.

The HTTP client shapes what the scanner sees and reports, so the move is a behaviour question before it is
a rename. This spec settles what has to stay the same and how that is checked.

### What the code and the libraries say (checked on 2026-11-22)

- **The engine imports the client in eight modules:** `http/client.py`, `http/session.py`,
  `http/decoding.py`, `http/addresses.py`, `http/tls_probe.py`, `core/context.py`,
  `checks/session/cookies.py` and `checks/deps/osv.py`. Two of them build a client: `http/client.py` (the
  scan) and `checks/deps/osv.py` (the OSV.dev lookup).
- **The public names match.** Every name in `httpcore.__all__` is in `httpcore2.__all__`, and `httpx2` keeps
  every name of `httpx.__all__` except the `main` command-line entry point, which the engine does not use.
  With `httpx` and `httpcore` aliased to `httpx2` and `httpcore2`, the whole test suite gives the same result
  as on `httpx` (2409 passed, 22 skipped, on Windows with Python 3.14), and `mypy` reports one redundant
  `cast`.
- **Certificate verification is the real difference.** With `verify=True`, `httpx` 0.28 trusts the `certifi`
  bundle unless `SSL_CERT_FILE` or `SSL_CERT_DIR` is set. `httpx2` does not depend on `certifi`: it uses the
  operating system's verifier on Windows and macOS, and OpenSSL's system paths on Linux. Left at its default,
  the same certificate could get a different verdict depending on where the scan runs.
- **The address guard reaches into private attributes.** `http/addresses.py` swaps the network backend on
  the client's own transport (`_transport._pool._network_backend`), because there is no public option for it
  and a custom transport would turn off the proxies from the environment. The same layout exists in `httpx2`,
  and an unrecognised layout is already an error rather than a scan without the guard.
- **The redirect hook depends on client internals too.** `_hide_location` in `http/client.py` (#328) moves a
  redirect's `Location` away from the client, which would otherwise parse it even with
  `follow_redirects=False`.
- **The test mock has no `httpx2` release.** `pytest-httpx` 0.36.2 requires `httpx==0.28.*`. The suite uses
  five of its methods (`add_response`, `add_callback`, `add_exception`, `get_requests`, `reset`), in 115 calls
  across 14 test files.

**This spec covers replacing `httpx` and `httpcore` with `httpx2` and `httpcore2` in the engine, keeping one
fixed source of certificate trust, and replacing the test mock with one that lives in the repository.** A scan
of the same target reports the same findings before and after.

### Where it sits

```
src/webvigil/http/tls.py (new)     the one TLS context every engine client uses
src/webvigil/http/client.py        the scan's client: httpx2, the fixed TLS context
src/webvigil/checks/deps/osv.py    the OSV client: httpx2, the fixed TLS context
src/webvigil/http/addresses.py     the address guard on the httpcore2 transport
src/webvigil/http/*, core/context.py, checks/session/cookies.py   imports and types
tests/                             an in-repository `httpx_mock` fixture replaces pytest-httpx
pyproject.toml, uv.lock            httpx2[http2] and certifi in; httpx and pytest-httpx out
```

## Goals

- The engine runs on `httpx2` and `httpcore2`; `httpx`, `httpcore` and `pytest-httpx` leave the dependency
  graph.
- Certificate verification trusts the same certificates as today, on every platform.
- The guarantees of the HTTP layer hold: address guard, scope, credentials, redirects, body cap, deadlines,
  decoding, HTTP/2 and cookies.
- A scan of the same target gives the same findings, severities and fingerprints.
- The suite keeps its strictness and stays offline.

## Non-goals

- **The operating system's trust store as an option.** No new flag or configuration key (resolved
  decision 1).
- **New `httpx2` features** such as Server-Sent Events, WebSocket or `zstd` and `brotli` decoding. The engine
  keeps asking for the codings it decodes itself.
- **A public way to install the address guard.** The engine keeps the transport seam it has today.
- **A new detection, check, flag, configuration key or report field.**
- **The Web API and the dashboard.** Their test client already runs on `httpx2`, and neither changes.
- **Raising the minimum Python version**, which stays at 3.12.

## Personas

- **As a developer scanning a site**, I want the upgrade to report what the previous version reported, so that
  a CI baseline does not change because a library did.
- **As someone running the scanner on Windows, Linux or in the container image**, I want the same certificate
  verdict on each, so that a result does not depend on the machine.
- **As a user behind a corporate proxy or a private CA**, I want `SSL_CERT_FILE`, `SSL_CERT_DIR` and the proxy
  variables to keep working.
- **As a contributor**, I want one HTTP stack in the engine and in the tests, and a mock I can read in the
  repository.

## Functional requirements

### RF-01 — The engine runs on httpx2

- **Given** the source of `webvigil`
  **When** its imports are read
  **Then** no module imports `httpx` or `httpcore`, and the eight modules listed above use `httpx2` and
  `httpcore2`.
- **Given** a clean install of the package, with or without the `web` extra
  **When** its dependencies are listed
  **Then** `httpx2`, `httpcore2`, `h2` and `certifi` are present, and `httpx` and `httpcore` are not.

### RF-02 — One fixed source of certificate trust

- **Given** certificate verification on (the default) and neither `SSL_CERT_FILE` nor `SSL_CERT_DIR` set
  **When** an engine client is built
  **Then** it trusts exactly the `certifi` bundle.
- **Given** `SSL_CERT_FILE` set
  **When** an engine client is built
  **Then** it trusts that file. **Given** only `SSL_CERT_DIR` set, it trusts that directory. `SSL_CERT_FILE`
  wins when both are set, as it does today.
- **Given** a certificate issued by a CA that is only in the operating system's trust store
  **When** the engine connects with verification on
  **Then** the connection is refused for an untrusted certificate, on Windows, Linux and in the container image.
- **Given** either engine client, on any platform
  **When** its TLS context is read
  **Then** it is a standard-library `ssl.SSLContext` verified by OpenSSL, never a platform verifier.

### RF-03 — Verification off works as today

- **Given** `--insecure` (`verify_tls = false`)
  **When** the scan's client connects
  **Then** it does not verify the certificate or the host name.
- **Given** the OSV.dev client
  **When** it connects
  **Then** it always verifies, whatever `verify_tls` says, as it does today.

### RF-04 — The address guard holds

- **Given** a public target whose name resolves to an internal address
  **When** the engine connects
  **Then** the connection is refused.
- **Given** a name in a scan
  **When** it is connected to more than once
  **Then** it is resolved once, the connection goes to the checked IP, and TLS still verifies the certificate
  against the host name.
- **Given** a proxy set in the environment
  **When** the scan's client is opened
  **Then** the proxy is still honoured.
- **Given** a client whose transport does not have the expected layout
  **When** the guard is installed
  **Then** it raises an error, and no scan runs without the guard.

### RF-05 — Redirects and credentials

- **Given** a redirect whose `Location` the client could not parse (`https:\\host/`, `mailto:x`)
  **When** the engine receives it
  **Then** the response reaches the engine with its `Location`, as in #328.
- **Given** a redirect
  **When** the engine follows it
  **Then** scope, port and the rule on where credentials may be sent apply to each hop, as today.

### RF-06 — Body cap, deadlines and decoding

- **Given** a response over `[http] max_body_bytes`, compressed or not
  **When** it is read
  **Then** at most that many bytes are kept at each stage, and the response is marked as truncated.
- **Given** a request that runs past `[http] total_timeout_s`, or a scan past `[scan] max_duration_s`
  **When** the deadline passes
  **Then** it ends as it does today.
- **Given** a `gzip` or `deflate` response, valid or corrupt
  **When** it is decoded
  **Then** the engine's own decoder handles it, and `Accept-Encoding` lists only the codings it decodes.

### RF-07 — HTTP/2

- **Given** a server that negotiates HTTP/2
  **When** the engine connects
  **Then** the request goes over HTTP/2, through the same address guard and TLS context.

### RF-08 — Cookies and sessions

- **Given** the session jar, automated login and the session checks
  **When** they read `Set-Cookie` headers and apply Domain, Path, Secure and expiry
  **Then** they accept, send and drop the same cookies as today.

### RF-09 — Same scan, same report

- **Given** the fixture application scanned with the same configuration, before and after the migration
  **When** the two JSON reports are compared, leaving out timestamps and durations
  **Then** findings, severities, check ids and fingerprints are identical, and `schema_version` does not change.

### RF-10 — An in-repository test mock

- **Given** a test that uses the `httpx_mock` fixture
  **When** the mock replaces `pytest-httpx`
  **Then** the calls the suite makes (`add_response`, `add_callback`, `add_exception`, `get_requests`, `reset`,
  and the `httpx_mock` marker) keep their meaning, and the assertions of the existing tests do not change.
- **Given** a request no registered response matches
  **When** it is sent
  **Then** the test fails.
- **Given** a registered response that was never requested, in a test without
  `assert_all_responses_were_requested=False`
  **When** the test ends
  **Then** the test fails.
- **Given** a registered response that is not reusable
  **When** it has been served once
  **Then** it is not served again.

### RF-11 — Tests

See the test strategy in the design. The suite must cover: the TLS context as a unit (the three sources, their
precedence, verification off, the context type on every platform); a real TLS connection to a local server
with a throwaway CA, trusted and untrusted; the contract of the mock (RF-10); and an import guard for RF-01. The
existing tests of RF-04 to RF-08 keep their assertions.

## Non-functional requirements

### RNF-01 — Dependencies

The runtime dependencies shall declare `httpx2[http2]>=2.16.0,<3` and `certifi`. The upper bound is deliberate:
the address guard depends on private attributes of the transport, so a new major version goes through the CI
before it reaches an install (resolved decision 3). `httpx` and `pytest-httpx` leave `pyproject.toml` and
`uv.lock`.

### RNF-02 — A minor release

The change fits a minor release under [`docs/stability.md`](../../docs/stability.md): commands, configuration,
check ids, report schema and fingerprints do not change. The types of the provisional Python API that expose
`httpx` objects, such as the headers of a response, become `httpx2` objects, and the CHANGELOG says so under
**Changed**.

### RNF-03 — The engine boundary

The `import-linter` contract keeps passing: the engine imports no interface or persistence package.

### RNF-04 — Every step leaves `main` working

The work lands in independent pull requests. The mock and the fixed TLS context land first, while the engine is
still on `httpx`, so the change that swaps the client is small and every merge keeps the full CI green.

### RNF-05 — The suite stays fast and offline

No test talks to the real network, a real TLS test stays on the loopback interface, and the whole suite keeps
running in under 2 minutes with coverage. Per-file line and branch coverage of `src/webvigil` does not drop.

## Resolved decisions

1. **Certificate trust stays on one fixed source (issue #304).** Every engine client gets a context built from
   `certifi`, or from `SSL_CERT_FILE` or `SSL_CERT_DIR`. The operating system's store was discarded: a scan's
   verdict would depend on the machine it runs on, and a security scanner's result has to be reproducible. A
   private CA keeps working through the two environment variables.
2. **The test mock moves into the repository.** No `pytest-httpx` release supports `httpx2`, and the suite uses
   a small part of its API. Waiting would leave the migration without a date, and keeping it would keep `httpx`
   in the development dependencies.
3. **`httpx2` is capped below the next major version.** `selectolax` already follows this rule in
   `pyproject.toml`, for the same reason: the engine depends on details a major version may change.
