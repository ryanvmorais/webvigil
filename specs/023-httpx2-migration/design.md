---
feature: Engine HTTP client migration — move the engine from httpx to httpx2 with no change in what a scan reports (issue #304)
status: approved
date: 2026-11-22
related:
  - 001-foundation/design.md
  - 010-osv-online/requirements.md
  - 019-automated-login/design.md
origin: conception
---

# 023 — Engine HTTP client migration — design

## Overview of the approach

The migration is a rename with two exceptions, and both exceptions land first, while the engine is still on
`httpx`:

1. **The test mock moves into the repository** (`tests/http_mock.py`), so the suite stops depending on a plugin
   tied to `httpx==0.28.*`.
2. **Certificate trust becomes explicit** (`http/tls.py`). Every engine client receives a context the engine
   built, so the default of the HTTP library no longer decides what is trusted.

With those in place, swapping the client is a mechanical change of imports and dependencies, and any test that
turns red points at the library rather than at one of the two changes above (ADR-5).

### What was measured (2026-11-22, `httpx` 0.28.1 against `httpx2` 2.16.2, Python 3.14, Windows)

| Surface | Inputs | Result |
|---|---|---|
| Requests built | 2063 strings (every string literal under `checks/`, plus crafted control, Unicode and encoding cases), in 13 shapes: path, query, params, fragment, form, raw body, header, cookie, `Host`, multipart field and filename, absolute URL | 26 819 requests, 0 differences in method, raw path, URL, host, port, headers or body |
| Responses through `HttpClient` | 69 raw responses on loopback: malformed status lines and headers, duplicate or invalid lengths, chunked, truncated, `gzip` and `deflate` (valid, corrupt, over the cap), charsets, redirects | 0 differences in status, headers, text, content, truncation, redirect history or failure class |
| `SessionJar` | 27 `Set-Cookie` values read back for 4 URLs | 0 differences |
| HTTP/2 over TLS | a local `h2` server through `HttpClient` | same version, status, body and repeated headers |

The source comparison agrees: the URL parser, the transport and the exception classes differ in formatting and
typing. The differences that matter are the default TLS context (ADR-1) and the proxy's TLS context (ADR-2).

## Module layout

```
src/webvigil/http/tls.py              new: client_ssl_context(), pin_proxy_trust()
src/webvigil/http/client.py           passes the context; pins the proxy trust; imports
src/webvigil/checks/deps/osv.py       passes the context; pins the proxy trust; imports
src/webvigil/http/addresses.py        imports (httpcore2)
src/webvigil/http/tls_probe.py        imports (httpcore2)
src/webvigil/http/session.py          imports
src/webvigil/http/decoding.py         imports
src/webvigil/core/context.py          imports
src/webvigil/checks/session/cookies.py   imports
src/webvigil/checks/headers/_parsing.py  drops a cast httpx2's types make redundant
tests/http_mock.py                    new: HttpxMock and the httpx_mock fixture
tests/conftest.py                     exposes the fixture
tests/unit/test_http_mock.py          new: the mock's contract (RF-10)
tests/unit/test_http_tls.py           new: the TLS context and proxy trust (RF-02, RF-03)
tests/unit/test_http_stack.py         new: no module imports httpx or httpcore (RF-01)
pyproject.toml, uv.lock               httpx2[http2], certifi; pytest-httpx and httpx out; `httpx_mock` marker
```

## Data model

None. No configuration key, report field, database column or schema version changes.

## Components

### `client_ssl_context` (`http/tls.py`)

Builds the context of one client:

| `verify` | Environment | Context |
|---|---|---|
| `True` | `SSL_CERT_FILE` set | `ssl.create_default_context(cafile=<file>)` |
| `True` | only `SSL_CERT_DIR` set | `ssl.create_default_context(capath=<dir>)` |
| `True` | neither | `ssl.create_default_context(cafile=certifi.where())` |
| `False` | ignored | `ssl.SSLContext(PROTOCOL_TLS_CLIENT)`, `check_hostname = False`, `CERT_NONE` |

An empty variable counts as unset, and a path that cannot be read raises at client creation. Both match what
`httpx` 0.28 does today. Each call returns a new context (ADR-1).

### `pin_proxy_trust` (`http/tls.py`)

Walks the transports mounted from the proxy variables and gives each **`https://` proxy** the context for the
connection to the proxy itself: `ssl.create_default_context()` plus `certifi`, the trust `httpcore` 1.0.9 applies
today (ADR-2). An `http://` proxy has no such connection and is left alone. A mount with a layout this code does
not recognise raises `RuntimeError`, the rule `install` already follows for the address guard.

The connection through the proxy to the target keeps the client's own context, so `verify_tls` and RF-02 apply to
the target whether or not a proxy is in the way. `--insecure` does not turn off the verification of the proxy,
as it does not today.

### The two clients

- **`HttpClient.__aenter__`** passes `verify=client_ssl_context(verify=config.http.verify_tls)`. With no test
  transport, it calls `install(...)` and then `pin_proxy_trust(...)`.
- **`OsvProvider._client`** passes `verify=client_ssl_context()`, always verifying, and calls
  `pin_proxy_trust(...)`.

### `HttpxMock` and the `httpx_mock` fixture (`tests/http_mock.py`)

The fixture patches `httpx2.AsyncHTTPTransport.handle_async_request` with `monkeypatch`, so a client built the
normal way, with the address guard installed, reaches the mock instead of a socket. It implements what the suite
uses, with the semantics of `pytest-httpx` 0.36.2:

| Call | Meaning |
|---|---|
| `add_response(status_code=200, headers=None, content=None, text=None, json=None, url=None, is_reusable=False)` | register an answer, optionally only for one URL; query parameters compare regardless of order |
| `add_callback(callback, url=None, is_reusable=False)` | the callback receives the request and returns a response; `None` counts as no match |
| `add_exception(exception, url=None, is_reusable=False)` | raise it, attaching the request to a `RequestError` |
| `get_requests()` | every request received, in order, with its body read |
| `reset()` | forget requests, registrations and unmatched requests |
| `@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)` | allow registered answers that were never used |

**Selection.** Of the registrations that match a request, the first one not yet used answers. When all were used,
the last one answers if it is reusable. Otherwise the request is unmatched: it is recorded and raises
`TimeoutException`, the exception the engine's retry path sees today.

**At teardown** the test fails if a registration was never used (unless the marker allows it) or if any request
was unmatched. A response is handed back unread, so the client can stream it through `_read_capped`.

## Interfaces

```python
# src/webvigil/http/tls.py
def client_ssl_context(*, verify: bool = True) -> ssl.SSLContext: ...
def pin_proxy_trust(client: httpx2.AsyncClient) -> None: ...
```

No public interface changes. `http/` is outside the compatibility surface of `docs/stability.md`. The types that
expose the client's objects, such as `Response.headers`, become `httpx2` types (RNF-02).

## ADRs

### ADR-1 — Every engine client gets a new, explicit TLS context

**Decision.** `http/tls.py` builds the context, and both clients pass it as `verify=`. It is never `verify=True`.

**Alternatives.** (a) Leave the default of `httpx2`: the verdict would depend on the platform (resolved decision 1).
(b) Set `SSL_CERT_FILE` for the process: it changes the behaviour of anything else in an embedding application.
(c) Share one context across clients: the transport writes the ALPN protocols onto the context it receives, and
the scan's client speaks HTTP/2 while the OSV client does not.

**Why.** One function holds the trust rule, and a test can check that the context a client uses is the one that
function returned.

**Trade-off.** The engine now owns a rule the library used to apply, and `certifi` becomes a direct dependency.

### ADR-2 — The TLS connection to an HTTPS proxy keeps today's trust

**Decision.** A proxy from the environment with an `https://` URL gets `ssl.create_default_context()` plus
`certifi`, set on the private `_proxy_ssl_context` of its pool.

**Alternatives.** (a) The target's context, which is `certifi` only: a corporate proxy whose CA is in the system
store would stop working. (b) The default of `httpcore2`: the proxy connection would move to the platform's
verifier on Windows and macOS. (c) Rebuild the mounts from the environment with `Proxy(ssl_context=...)`: it
reimplements the parsing of the proxy variables and of `NO_PROXY`.

**Why.** It is the same trust and the same verifier as today, in a few lines, and a user behind a proxy sees no
change.

**Trade-off.** One more private attribute. An unknown layout raises instead of connecting with another context,
and the upper bound on `httpx2` (resolved decision 3) keeps a major version from arriving untested.

### ADR-3 — A plain rename, with no import alias

**Decision.** Modules write `import httpx2` and `import httpcore2`, and code says `httpx2.Headers`.

**Alternatives.** (a) `import httpx2 as httpx`: a smaller diff, but every reader is told the wrong library.
(b) `httpx2.alias_httpx()`: its documentation reserves it for applications and says libraries should never call
it, because it changes what `import httpx` means for the whole process.

**Why.** WebVigil is also a library that can share a process with code using the real `httpx`.

**Trade-off.** A larger diff in the swap, all of it mechanical.

### ADR-4 — The mock patches the transport method and implements only what the suite uses

**Decision.** A small in-repository module with the same fixture name, marker and call shapes.

**Alternatives.** (a) Keep `pytest-httpx` under an alias: `httpx` stays in the development graph, and the plugin
would run against a library it does not declare. (b) Wait for its `httpx2` support: no date. (c) Inject
`MockTransport` through the `transport=` seam: rewrites 166 test functions, and a client with a test transport
skips `install`, so the tests would stop exercising the guarded path.

**Why.** The assertions of the existing tests stay as they are, which is what makes the replacement checkable.

**Trade-off.** About 130 lines of test infrastructure to maintain, covered by their own contract tests.

### ADR-5 — Order of delivery: mock, TLS context, swap

**Decision.** Three code pull requests in that order, each with the whole CI green (RNF-04).

**Alternatives.** One pull request: a red test could come from the mock, the context or the library, and the
review could not tell them apart.

**Why.** On `httpx` the first two change no behaviour, so they are proved on the current stack.

**Trade-off.** Some lines are touched twice, because `tls.py` and the mock import `httpx` until the swap.

## Impact on existing code

- **Imports and annotations** change in the eight engine modules, in `tests/support.py` and in the test files that
  use `httpx` or `httpcore` directly. Old specs are a historical record and are not rewritten.
- **Dependencies.** `httpx[http2]>=0.28.1` becomes `httpx2[http2]>=2.16.0,<3`. `certifi>=2026.10.23` is added.
  `httpcore2` stays transitive, pinned to an exact version by `httpx2`, as `httpcore` is today. `pytest-httpx` and
  the separate `httpx2` entry of the test group are removed.
- **Documentation.** `docs/stack.md`, `docs/checks-internals.md`, `docs/active-injection.md`,
  `docs/notes/engine-boundaries.md`, `CLAUDE.md`, the `pyproject.toml` comments and the CHANGELOG.
- **No change** to the CLI, configuration, report schema, check ids, fingerprints, Web API, dashboard or image.

## Test strategy

Everything runs offline. A real TLS connection stays on loopback, on the `trustme` server of `tests/conftest.py`.

| Guard | Test | Positive control | Seen failing by |
|---|---|---|---|
| RF-01 no old imports | AST walk over `src/webvigil` | the same walker flags a snippet with `import httpx` | adding `import httpx` to an engine module |
| RF-02 sources and precedence | unit, `monkeypatch` on the environment and on `certifi.where` | each source is asserted by the CA the context holds or by the path it received | swapping the order of the two variables |
| RF-02 the client uses the built context | both clients, `_pool._ssl_context is` the context returned by a spy | the spy was called | passing `verify=True`, on every platform |
| RF-02 untrusted CA refused | real handshake with a CA outside the trust source | the same server, CA trusted, answers 200 | loading the wrong bundle |
| RF-03 verification off | real handshake with an untrusted CA and `verify_tls=False` | the same call with `verify_tls=True` is refused | leaving `check_hostname` on |
| RF-03 OSV always verifies | OSV client with `verify_tls=False` in the scan's configuration | its context requires a certificate | passing the scan's flag |
| ADR-2 proxy trust | `HTTPS_PROXY` set: the pool holds the pinned context, and a connection built from it uses that context | `HTTP_PROXY` set: the context stays `None` | removing the call to `pin_proxy_trust` |
| ADR-2 unknown layout | a fake mount raises `RuntimeError` | a real mount passes | removing the check |
| RF-10 mock contract | selection order, reuse, unmatched, unused, marker, reset, exception, unread response | each failure case has a passing twin | breaking each rule in `tests/http_mock.py` |

**The existing tests are the guard of RF-04 to RF-08.** Their assertions do not change in any of the pull requests.
The mock pull request compares `uv run pytest --cov` before and after, on the same Python, per file; no line or
branch may stop being covered.

**RF-09** is checked once, at the end, not by a new permanent test (`test_full_scan_is_deterministic` already
guards determinism): the fixture application is scanned in Active Mode from `main` before the swap and after it,
and the two JSON reports are compared without timestamps and durations.

**Budget.** About 60 lines of `src/` and 130 of mock. The tests stay near the ratio of `specs/README.md` for the
TLS module. The mock's contract tests go past it, because they replace the guarantees of a dropped dependency.

## Deviations

1. **RF-07, test strategy.** The strategy counts the existing tests as the guard of RF-04 to RF-08, but no existing
   test exchanges HTTP/2. Stage 1 adds one real exchange on loopback, so RF-07 has a permanent guard.
2. **`pin_proxy_trust`, known mounts.** The design treats any mount other than an HTTP proxy as an unknown layout.
   Two more are valid and are skipped: a `NO_PROXY` entry, which has no transport, and a SOCKS proxy, which works
   today when `socksio` is installed and has no TLS connection to the proxy. Raising on them would break those
   setups.
3. **`client_ssl_context`, unreadable paths.** The design says a path that cannot be read raises at client creation.
   That holds for `SSL_CERT_FILE`. A missing `SSL_CERT_DIR` raises nothing, in `httpx` 0.28 as well, because OpenSSL
   only reads the directory during verification, so the handshake is refused instead. The behaviour is unchanged.
