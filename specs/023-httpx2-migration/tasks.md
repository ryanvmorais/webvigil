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

# 023 — Engine HTTP client migration — Tasks

Ordered, small, each tagged with the requirement or ADR it satisfies. Each stage is one pull request, cut from an
up-to-date `main` after the previous one is merged (RNF-04, ADR-5). The spec itself lands first, in its own pull
request.

The last task of every stage is the quality gate:

```bash
uv run ruff check .
uv run black --check .
uv run mypy src
uv run lint-imports
uv run pytest --cov
uv build && uv run --no-project python scripts/check-package.py dist
```

Every new or changed test is seen failing once, by breaking the line it guards, and the pull request says what was
broken (`specs/README.md`, "Testing a spec", rule 9). The sabotage of each guard is listed in the design's test
strategy.

## Stage 0 — The in-repository test mock (still on `httpx`)

- [x] `tests/`: record the baseline on `main`, on one Python version: the test count and `uv run pytest --cov
  --cov-report=json:coverage-before.json`, kept outside the repository. — RNF-05
- [x] `tests/http_mock.py`: `HttpxMock` with `add_response`, `add_callback`, `add_exception`, `get_requests` and
  `reset`; the selection rule; the unmatched path raising `httpx.TimeoutException`; the unread response; a
  `verify()` the fixture calls at teardown; the `httpx_mock` fixture patching
  `httpx.AsyncHTTPTransport.handle_async_request`. — RF-10, ADR-4
- [x] `tests/conftest.py`: expose the fixture. `pyproject.toml`: declare the `httpx_mock` marker under
  `[tool.pytest.ini_options]`, remove `pytest-httpx`, and run `uv lock`. — RF-10, RNF-01
- [x] `tests/unit/test_http_mock.py`: the contract of the design's table (selection order, reuse, unmatched
  request, unused registration, marker, reset, exception with its request, callback returning `None`, URL match
  regardless of query order, response read through `aiter_raw`), each failure with a passing twin. — RF-10, RF-11
- [x] Break each rule of `tests/http_mock.py` once and watch its contract test fail. — RF-11
- [x] Confirm that no existing test assertion changed, and compare coverage per file against the baseline: no line
  or branch of `src/webvigil` stops being covered. — RF-10, RNF-05
- [x] `docs/stack.md`: replace the `pytest-httpx` entry with the in-repository mock. — ADR-4
- [x] Quality gate: ruff, black, mypy, import-linter and the package check green; 2493 passed, 2 skipped.

## Stage 1 — One explicit TLS context (still on `httpx`)

- [x] `pyproject.toml`: add `certifi>=2026.10.23` to the runtime dependencies, and run `uv lock`. — RNF-01, ADR-1
- [x] `src/webvigil/http/tls.py`: `client_ssl_context(*, verify=True)` with the design's table, and
  `pin_proxy_trust(client)`, raising `RuntimeError` on a layout it does not recognise. — RF-02, RF-03, ADR-1, ADR-2
- [x] `src/webvigil/http/client.py`: pass `verify=client_ssl_context(verify=config.http.verify_tls)`, and call
  `pin_proxy_trust` after `install` when there is no test transport. — RF-02, RF-03, RF-04, ADR-1, ADR-2
- [x] `src/webvigil/checks/deps/osv.py`: pass `verify=client_ssl_context()` and call `pin_proxy_trust`. — RF-02,
  RF-03, ADR-1, ADR-2
- [x] `tests/unit/test_http_tls.py`: the three sources and their precedence; verification off; both clients use the
  returned context; a real handshake with a trusted and an untrusted CA; the OSV client always verifies; the proxy
  trust on `https://` and `http://` proxies; the unknown layout. — RF-02, RF-03, RF-11, ADR-2
- [x] `tests/unit/test_http_tls.py`: a real HTTP/2 exchange through `HttpClient` on loopback, against a small `h2`
  server with a `trustme` certificate, asserting the negotiated version, the status, the body and repeated
  headers; the control is the same request to a server that offers only HTTP/1.1. — RF-07, RF-11
- [x] Apply each sabotage of the design's test strategy for this stage and watch the test fail. — RF-11
- [x] Quality gate: ruff, black, mypy, import-linter and the package check green; 2522 passed, 2 skipped.

## Stage 2 — The swap to `httpx2`

- [x] Record the RF-09 baseline from `main`: serve `tests.fixtures.serve:app` with `uv run uvicorn --port 8080`, run
  `uv run webvigil scan http://127.0.0.1:8080 --mode active --authorized-by local-test --format json --output
  before.json`, and keep the report outside the repository. — RF-09
- [x] `pyproject.toml`: replace `httpx[http2]` with `httpx2[http2]>=2.16.0,<3`, drop the separate `httpx2` entry of
  the test group and its comment, and run `uv lock`. Confirm that `httpx` and `httpcore` left `uv.lock`. — RF-01,
  RNF-01
- [x] The eight engine modules and `http/tls.py`: `import httpx2` and `import httpcore2`, with annotations,
  docstrings and comments following. — RF-01, ADR-3
- [x] `src/webvigil/checks/headers/_parsing.py`: drop the redundant `cast`. — RF-01
- [x] `tests/`: rename the imports and references, `tests/http_mock.py` included, with no change to any assertion.
  Check it by comparing the diff with `httpx2` and `httpcore2` normalized back. — RF-04, RF-05, RF-06, RF-08, RF-10
- [x] `tests/unit/test_http_stack.py`: the AST guard over `src/webvigil`, with its positive control. — RF-01, RF-11
- [x] `CHANGELOG.md`, `[Unreleased]`, **Changed**: the HTTP client is now `httpx2`, certificate trust is unchanged,
  and the provisional Python API exposes `httpx2` types. — RNF-02
- [x] Quality gate, with `lint-imports` confirming the engine boundary: green; 2537 passed, 2 skipped. — RNF-03,
  RNF-05

## Stage 3 — Cross-platform check and documentation

- [x] RF-09: repeat the scan of Stage 2 from the new `main`, and compare the two JSON reports without timestamps and
  durations. Findings, severities, check ids, fingerprints and `schema_version` are identical. — RF-09, RNF-02
- [x] `.github/workflows/`: confirm the whole CI matrix on the swap's merge commit: `quality` on Linux and Windows
  for every Python version, `package`, `docker` and `compose`. — RF-02, RNF-04
- [x] Build the image and check, from inside it, that the engine's context loads the `certifi` bundle and that a
  scan of the `target` service of the Compose file completes. — RF-01, RF-02
- [x] `docs/stack.md`, `docs/checks-internals.md`, `docs/active-injection.md`, `docs/notes/engine-boundaries.md` and
  `CLAUDE.md`: `httpx2` in place of `httpx`, and the trust rule of ADR-1 and ADR-2 where the HTTP layer is
  described. — RNF-02
- [x] `design.md`: fill in `## Implementation notes` with the measurements. Set `status: done` in the three files and
  on the roadmap of `specs/README.md`; the pull request closes #304. — RF-11
- [x] Quality gate: ruff, black, mypy, import-linter and the package check green; 2537 passed, 2 skipped.
