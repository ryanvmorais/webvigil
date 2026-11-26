---
feature: Security regression gates — failure injection with markers at every stage, every sensitive point inventoried by a test, and the hardening left from the 1.6.0 review
status: done
date: 2026-11-25
related:
  - 001-foundation/design.md
  - 002-web-api/design.md
  - 020-session-security/design.md
  - 024-secret-values/requirements.md
  - 025-safe-output/requirements.md
  - 026-destination-policy/requirements.md
origin: conception
---

# 027 — Security regression gates — design

## Overview of the approach

The spec has three parts that do not depend on each other.

**The failure-injection suite** (`tests/failure/`) runs the scanner, the CLI and the Web API while a fault plan
fails one request or call per stage, and then searches every output for markers. A table lists the stages and the
kinds of failure each one gets. Three harnesses run it:

- the **scan** harness: the full fixture scan through the CLI, with an `httpx2` transport that applies the plan;
- the **CLI** harness: short runs that fail before or after the scan (resolver, files, report writers);
- the **API** harness: the Web API's runner and database, fed the results of the scan harness and failures of its
  own.

A pass is attributed to its stage by wrapping the orchestrator's pass methods in the test, so the engine gains no
test hook (ADR-2). Each scan run gives every stage a different kind of failure, and the kinds rotate over the runs,
so a few scans cover every pair of stage and kind (ADR-1). The suite fixes what it finds in the same pull request
(ADR-4).

**The inventory** (`tests/sensitive_points.py` and `tests/unit/test_sensitive_point_inventory.py`) is a
syntax-tree walker of the source that lists every sensitive point by family, following exception text through
variables, wrapping exceptions and fields, with the verdicts as a table of reasons in the test (ADR-5).

**The hardening** is six small changes:

- the setup route takes a slot of the Argon2 ceiling;
- a trusted proxy's name is refreshed under a lock;
- the dashboard's server appends the connection's address on an upgrade too;
- `robots.txt` gets a disallow-all result for a server error, keeps a trailing `?` and decodes a cut file with its
  charset;
- the logout test chooses by the credential rule.

### What was checked (2026-11-25, on `main` at `10e5df9`)

- **The stages.** `Orchestrator.run` (`core/orchestrator.py:112`) calls its passes in a fixed order, as plain
  awaits, with no list: the login, the OpenAPI and HAR imports, the crawl (`Crawler.discover`), then fingerprint,
  OSV, probe, injection, stored XSS, envelope, upload, CSRF, session, and the passive checks. Each pass from
  fingerprint to session catches `Exception` and keeps only the type's name (`_PassFailure`). The checks keep the
  type's name and a traceback of frames and type names only.
- **What the HTTP client raises.** `RequestFailed(url, reason)`, where `reason` comes from
  `http/failures.py::failure_kind` and is never an exception's text. A `5xx` after the retries is returned as a
  response, not raised. An exception that is not an `httpx2` error is not caught by the client.
- **Where a failure is not handled yet**, by reading. The suite is expected to fail on these first:
  - the CLI writes a report with no handling of `OSError`, and a reporter that raises is not caught either: the
    scan ends with a traceback and exit code `1`;
  - some steps run outside a pass's `try`: loading the Retire.js rules, the staleness warning, loading the
    disclosure catalogue, the address warnings and the final scrub;
  - the OpenAPI importer puts the JSON parser's message in its error, and `webvigil report` puts the text of an
    `OSError` or `ValueError` in its error line;
  - the Web API runner logs an unexpected engine error with `logger.exception`, so the log holds the exception's
    message.
- **The test seams.** `tests/http_mock.py` can raise any exception or return any response per URL.
  `tests/support.py::HandlerTransport` wraps a handler as a transport. The integration scan
  (`tests/integration/test_scan_fixture_app.py:287`) runs the real orchestrator over `httpx2.ASGITransport` with the
  OSV provider on a `MockTransport`. With a custom transport, the address guard is not installed. The fixture
  application has no switch to fail a route; the suite wraps it.
- **The canaries of spec `024`.** `test_secrets_never_appear_in_any_output` (integration) and the CLI canary
  (`tests/unit/test_cli.py:580`) search raw, percent-encoded (both forms) and JSON-escaped spellings. They do not
  search HTML-escaped, `repr` or base64 spellings.
- **Cost.** One full fixture scan takes about 2.5 s on a developer machine, without coverage.
- **The inventory today.** A walk of these families finds 213 points in `src/webvigil` and `web/src`: 54 where
  exception text becomes output, 66 project exceptions with a dynamic message, and 93 dangerous operations (30
  file, 24 regex, 13 code, 8 network, 7 SQL, 6 crypto, 2 HTML, 2 redirect, 1 XML).
- **An upgrade through the dashboard.** Run locally with `next start` and the preload: a WebSocket handshake to
  `/api/*` is forwarded with the client's `X-Forwarded-For` unchanged, and the API answers `403` before any route
  runs, because it has no WebSocket route. A `POST` with `Upgrade` and an `h2c` upgrade are not forwarded at all.
- **The logout test.** `_find_logout` (`checks/session/scanner.py:414`) accepts any URL `may_request` allows, so
  under `--scope subdomains` it can choose a sibling subdomain, which the session cookies do not reach.

## Module layout

```
tests/failure/__init__.py
tests/failure/table.py            the stages, the kinds of failure, the fault plan            (new)
tests/failure/faults.py           the fault transport, the OSV stub, the seams that raise     (new)
tests/failure/outputs.py          collects every output of a run, searches it for markers     (new)
tests/failure/test_scan.py        the scan harness                                            (new)
tests/failure/test_cli.py         the CLI harness                                             (new)
tests/failure/test_api.py         the API harness                                             (new)
tests/failure/test_table.py       the table check (RF-06) and the plan's determinism         (new)
tests/sensitive_points.py         the walker of the inventory                                 (new)
tests/unit/test_sensitive_point_inventory.py   the table of reasons and the gate             (new)
tests/support.py                  spellings(): the seven forms a marker is searched in       (changed)
src/webvigil/api/routes/setup.py  the hash inside a slot of the Argon2 ceiling                 (changed)
src/webvigil/api/client_address.py  the refresh under a lock                                   (changed)
web/src/server/forwarded-for.mjs  the upgrade event too                                       (changed)
src/webvigil/crawler/robots.py    disallow-all on a server error, trailing `?`, charset cut   (changed)
src/webvigil/http/client.py       decode_text() exposed for a cut body                         (changed)
src/webvigil/crawler/crawler.py   robots_unreadable                                            (changed)
src/webvigil/core/orchestrator.py the robots warning; the steps outside a pass's try          (changed)
src/webvigil/checks/session/scanner.py  the logout chosen by may_carry_credentials             (changed)
src/webvigil/cli/app.py           a report that cannot be written or rendered                  (changed)
src/webvigil/api/runner.py        the portable traceback in the log                            (changed)
```

The fixes the suite forces (ADR-4) land in the files that hold each failure path; the list above names the ones
known from reading.

## Data model

All in `tests/failure/table.py`:

```python
class Kind(StrEnum):
    REFUSED = "refused"          # httpx2.ConnectError
    RESET = "reset"              # httpx2.ReadError
    TIMEOUT = "timeout"          # httpx2.ReadTimeout
    SERVER_ERROR = "server-error"  # a 503 whose body and headers carry the marker
    BAD_BODY = "bad-body"        # a gzip Content-Encoding over bytes that are not gzip
    RAISES = "raises"            # a RuntimeError from inside the call, not an httpx2 error
    RESOLVER = "resolver"        # the address guard's resolver raises
    FILE_READ = "file-read"      # OSError reading an input file
    FILE_WRITE = "file-write"    # OSError writing a report
    DB = "db"                    # a statement that raises (sqlalchemy.exc.OperationalError)

@dataclass(frozen=True)
class Stage:
    name: str                    # "crawl", "fingerprint", "osv", "report-write", "api-store", ...
    seam: str                    # what the plan wraps: "Orchestrator._fingerprint", "OsvProvider", ...
    harness: Literal["scan", "cli", "api"]
    kinds: tuple[Kind, ...]

STAGES: Final[tuple[Stage, ...]]           # one row per stage
DEPENDENCIES: Final[Mapping[str, str]]     # inventory key of a connection or file operation -> stage name
```

`Marker` values are built from the stage and the kind, so a match names where it came from:
`wv-cred-<name>-<hex8>` for a credential, `wv-fail-<stage>-<kind>-<hex8>` for a failure. A failure's text is
`<marker> + HOSTILE`, where `HOSTILE` holds an escape sequence, a CR LF that imitates a log line, a right-to-left
override, a zero-width space and 20 Ki characters of padding, past the 16 Ki bound of `Text`.

## Components

### The table and the fault plan (`tests/failure/table.py`)

The stages of the scan harness are the orchestrator's passes in their order, plus `crawl` (`Crawler.discover`) and
`target` (the target URL itself, which the crawl must not lose in the other runs). Their kinds are `REFUSED`,
`RESET`, `TIMEOUT`, `SERVER_ERROR`, `BAD_BODY` and `RAISES`. For the OSV stage, whose client reads JSON, `BAD_BODY`
is a `200` whose body is not JSON.

The plan is a pure function:

```python
def fault_for(run: int, stage: Stage, index: int, url: str, attempt: int) -> Kind | None
```

- The stage's kind in run `r` is `stage.kinds[(r + position) % len(stage.kinds)]`, where `position` is the stage's
  row in the table. Over `len(kinds)` runs every stage gets every kind once, and no two neighbouring stages get the
  same kind in one run (ADR-1).
- The stage's first request fails on its first attempt only, so the client's retry is exercised and the pass goes
  on.
- A request whose URL's SHA-256 falls in bucket 0 of 8 fails on every attempt, so the pass's give-up path runs. The
  target URL is exempt outside the `target` stage, so one failure does not end the scan before the later stages.
- `RAISES` is raised once, from inside the pass's first call to the client, so the pass's own `except` (or its
  absence) is what runs.

### The fault transport and the seams (`tests/failure/faults.py`)

- `FaultTransport(inner, plan, run)`: an `httpx2.AsyncBaseTransport` around the fixture's `ASGITransport`. It reads
  the current stage from a `ContextVar`, counts the stage's requests and attempts, and either forwards the request
  or applies the kind. Every fault it applies is recorded with its marker, for the positive controls.
- `attributed(orchestrator_cls)`: a context manager that wraps each pass method named in the table, and
  `Crawler.discover`, so the `ContextVar` names the stage while it runs. It wraps by name from the table; a name
  that no longer exists on the class fails.
- `failing_osv(plan, run)`: the OSV provider's `MockTransport` handler, with the same plan.
- `failing_resolver(marker)`, `failing_read(path, marker)`, `failing_write(path, marker)`,
  `failing_render(reporter, marker)`: `monkeypatch` helpers for the CLI harness.
- `failing_store(marker)`, `failing_claim(marker)`, `raising_orchestrator(exc)`: for the API harness.

### The outputs (`tests/failure/outputs.py`)

`Outputs` collects, for one run: the CLI's standard output and standard error (separately), the report file, the
same result re-rendered by `webvigil report` in the other three formats, and every log record at `DEBUG` on the
root logger (message, arguments, `exc_text` and every attribute, as the integration scan's `_LogLines` does). For
the API harness it collects every response body and header of the scan, findings, report and list routes, every row
of every table as text, and the server log.

Two searches run over it:

- `credential_hits(outputs, markers)`: every place a credential marker appears in any spelling of
  `tests/support.py::spellings`. It must be empty (RF-03).
- `failure_hits(outputs, markers)`: every place a failure marker appears, with the output's name. Each hit must be
  in an output the table allows for that kind (RF-04): a project exception's message in the error line and
  `scan.error`; the body of a `SERVER_ERROR` in a finding's evidence, which is site content (spec `025`); the text
  of a `DB` failure in the server log. Wherever a hit is allowed, the output must hold no raw control,
  bidirectional or zero-width character and no padding run longer than its bound.

`spellings(value)` in `tests/support.py` gives the raw value, `quote` and `quote_plus`, JSON-escaped, HTML-escaped,
`repr` without its quotes, and standard and URL-safe base64 of the value. The two canaries of spec `024` switch to
it, which makes them stricter.

### The scan harness (`tests/failure/test_scan.py`)

One test per run, `len(kinds)` runs (six). Each run invokes the CLI with the integration scan's full configuration
(Active Mode, the automated login, the session tests, the OpenAPI and HAR imports, upload, CSRF, stored XSS, OSV)
and the credential markers in every `[auth]` cookie and header, a bearer token and the login password. The session
cookies the fixture issues are read from its state after the run and searched as credentials too. The
orchestrator's `HttpClient` gets the `FaultTransport`; backoff is zeroed as in the integration scan.

Each run asserts:

- the exit code is `0`, `3` or `4`, and standard error holds no `Traceback`;
- the JSON report was written and reads back; a pass whose `RAISES` fault ran has its failure warning, and the
  requests that failed for good are counted in the scan's request warnings;
- `credential_hits` is empty and every `failure_hits` entry is allowed;
- the positive controls of RF-05: each credential marker is in the requests the fixture received, each recorded
  fault holds its marker, and every stage of the run recorded at least one fault.

The scan harness keeps the results of its runs for the API harness, so the Web API is checked on the same results
without scanning again (ADR-3).

### The CLI harness (`tests/failure/test_cli.py`)

Short runs against the fixture with the passive profile, or against a host that never resolves:

- `resolver`: the address guard's resolver raises a `ConnectError` with the marker; the run uses the real transport,
  because the guard is installed only there. The scan ends with exit code `4`.
- `openapi-read`, `har-read`, `config-read`: the file exists but reading it raises `OSError` with the marker.
- `openapi-parse`: the OpenAPI document is not JSON.
- `report-write`: writing the report raises `OSError` with the marker; the scan ends with exit code `4` and one
  error line.
- `report-render`: one reporter raises `RuntimeError` with the marker; the same.
- `report-read`: `webvigil report` over a file whose read raises `OSError` with the marker.

Each run applies the same assertions and searches as the scan harness.

### The API harness (`tests/failure/test_api.py`)

- **The results of the scan harness**: each is returned by a stand-in orchestrator to the real `ScanRunner`, with a
  scan created through `POST /api/scans` carrying credential markers in its options. The scan, findings, report
  (four formats) and list routes are read and searched with the database rows and the log.
- **Failures of its own**: the orchestrator raises a `RuntimeError` with the marker (the runner stores
  `internal error`; the log holds the type and the frames, not the message), raises a `WebVigilError` with the marker
  (stored in `scan.error`, bounded and neutralized), the store raises `OperationalError` with the marker, and the
  claim of the next queued scan raises the same.

### The table check (`tests/failure/test_table.py`)

- **Every pass has a row (RF-06).** The syntax tree of `Orchestrator.run` gives every awaited `self._<name>(...)`
  call and the call of `discover`. Each must be a stage's seam. A positive control runs the same reading over a
  throwaway class with one more pass and expects it to be reported.
- **Every dependency has a row.** Every entry of `CONNECTIONS` (the destination inventory of spec `026`) and every
  `file` and `sql` point of the sensitive-point inventory is a key of `DEPENDENCIES`, which names its stage. An entry
  with no key fails, and so does a key with no entry.
- **The plan is fixed.** `fault_for` over the same arguments twice gives the same answers, and over all runs gives
  every stage every one of its kinds.

### The inventory walker (`tests/sensitive_points.py`)

A walker of the source: Python by syntax tree, the dashboard by text pattern. It is never
imported by the package and never imports the code it reads.

- **Python families:** `error` (exception text that reaches a logger, the terminal, a collection, a `raise`, a
  return value or an attribute, followed through variables, wrapping exceptions and fields of objects across
  files), `message` (a project exception raised with a dynamic value in its message) and the operations: `command`,
  `code`, `deserialization`, `sql`, `file`, `xml`, `regex` (dynamic pattern), `html`, `redirect`, `network`,
  `crypto`.
- **Dashboard families**, by pattern over `web/src`: `html`, `code`, `command`, `redirect`, `regex`, `network`,
  `crypto`, `client-secret`.
- **What is read:** the files `git ls-files` lists under `src/webvigil` and `web/src`, without tests, vendored data
  and generated files (`api-types.ts`).
- **A point's key:** `<module>:<function> <family> <callee>`, for example
  `webvigil.reporting:read_report file open`. For the dashboard, `<path> <family> <match>`. When the same key occurs
  more than once in one function, the second is `#2`, in source order.

### The inventory gate (`tests/unit/test_sensitive_point_inventory.py`)

`SENSITIVE_POINTS: Final[Mapping[str, str]]` maps each key to the reason it is safe, in one line that names the
guard (`"safe_text(..., Sink.TERMINAL): bounded and neutralized"`, `"the path is the user's --output"`). The
tests:

- every point found has a line, and every line has a point (the same shape as `OUTPUT_SINKS`);
- no reason is empty;
- the throwaway source of RF-07: one point of each family, Python and dashboard, including text followed through a
  variable, a wrapping exception and a field; every one is found;
- the walk counts every call it read, and the count is larger than the table, so a walker that stopped reading
  cannot pass.

### The setup route (`api/routes/setup.py`)

`create_first_user` hashes inside `throttle.check_slot()`, the same slots as login. Without a slot it answers `429`
with `Retry-After: BUSY_RETRY_S` and the message `too many password checks in progress: try again shortly`. The
`409` before the hash stays first, so a set-up instance still answers `409` without asking for a slot.

### The trusted-proxy lookup (`api/client_address.py`)

`TrustedProxies._name_addresses` keeps the fast path without a lock. On expiry it takes a `threading.Lock`, checks
the expiry again, and resolves only if no other thread did meanwhile. A thread that waited reads the fresh tuple.
A failed lookup is the empty set, as today.

### The dashboard's server (`web/src/server/forwarded-for.mjs`)

The patched `emit` rewrites the header on `"upgrade"` as on `"request"`: both events carry the request as their
first argument. Other events are left alone.

### `robots.txt` (`crawler/robots.py`, `crawler/crawler.py`, `http/client.py`)

- `load` returns `Robots.disallow_all(reason)` when the response is `5xx` or the request raises `RequestFailed`.
  `Robots.unreadable` holds the reason (`"HTTP 503"`, the failure kind), and `can_fetch` answers `False` for every
  URL. An `OutOfScopeError` stays allow-all: `robots.txt` is at the target's origin, so it cannot happen.
- The crawler fetches the target URL as it does today, before asking `robots.txt`, and exposes
  `robots_unreadable`. The orchestrator then adds one warning in place of the count warning:
  `robots.txt could not be read (<reason>): only the target URL was crawled; set follow_robots = false under [scan]
  to crawl without it`.
- `_request_target` keeps a `?` that ends the URL's path with an empty query, read from the URL before its
  fragment, so `/a?` is `/a?` and a rule `/a?` matches it.
- `http/client.py` exposes `decode_text(content, content_type)`, the decoding `Response.text` uses today. `load`
  calls it on the part within the limit, cut at its last line feed, so a large file is decoded with its charset like
  a smaller one.

### The logout test (`checks/session/scanner.py`)

`_find_logout` keeps a link or a form only when `may_carry_credentials` allows its URL, and keeps looking otherwise.
A configured `logout_url` that may not carry the credentials gives the warning `session logout test skipped:
[auth.login] logout_url may not receive the scan's credentials`; with no endpoint at all, the warning stays
`session logout test skipped: no logout endpoint found`.

### The fixes the suite forces

Known from reading, each proved by the suite failing before it:

- **Writing or rendering a report.** `cli/app.py` catches `OSError` around the write and `Exception` around a
  reporter, prints one error line in the project's words (`could not write the report to <path> (<type>)`,
  `could not render the <format> report (<type>)`) and exits with `4`.
- **Steps outside a pass's `try`.** The Retire.js rules, the staleness warning and the disclosure catalogue load
  inside their pass's `try`, so their failure becomes that pass's warning. The address warnings and the scrub are
  not wrapped: a failure there ends the scan through the CLI's and the runner's handling of an unexpected error,
  because a result that may not be scrubbed must not be written.
- **Third-party text in a message.** The OpenAPI importer says `not valid JSON (line <n>, column <m>)` from the
  parser's position, not its message. `webvigil report` says `could not read <path> (<type>)`.
- **The server log of an engine error.** The runner logs the message `scan <id> failed (<type>)` with the portable
  traceback the checks already use (`orchestrator._portable_traceback`, moved to `core/output.py`), not
  `logger.exception`.

A failure the suite finds beyond these is fixed in the same step. One that exposes a credential in a released
version stops the step and follows [`SECURITY.md`](../../SECURITY.md).

## Interfaces

- **CLI.** No new option. New error lines for a report that cannot be written or rendered, both with exit code `4`
  (documented as "operational error"). A new warning for an unreadable `robots.txt`.
- **Web API.** `POST /api/setup` may answer `429` with `Retry-After`, as `POST /api/auth/login` does. The scan error
  of an unexpected engine failure stays `internal error`.
- **Configuration.** No new key. `[scan] follow_robots` keeps its meaning; the warning names it.
- **Report schema.** No change; `schema_version` stays.

## ADRs

### ADR-1 — A few scans, each failing every stage with a rotating kind

**Decision.** The scan harness runs `len(kinds)` full scans. In each run every stage fails with one kind, and the
kind of each stage moves by one row per run.

**Alternatives.** (a) One scan per pair of stage and kind: about 90 scans, over 3 minutes. (b) One scan per kind with
every stage failing the same way: neighbouring stages hide each other's failures. (c) Random choice per run.

**Why.** Six scans give every stage every kind, at about 15 s without coverage. Rotation keeps the failures of one
run different from stage to stage, so a warning names one cause. A fixed rule repeats (resolved decision 3).

**Trade-off.** Two stages that fail in one run can mask an interaction that only one of them would show alone.
The CLI and API harnesses cover the single failures that end a scan.

### ADR-2 — The test names the stage; the engine gains no hook

**Decision.** The suite wraps the orchestrator's pass methods by name, from the table, and a `ContextVar` names the
running stage for the fault transport.

**Alternatives.** (a) A stage callback in the engine. (b) Attribute requests by URL patterns.

**Why.** A hook would be engine code that exists only for tests and that a plugin could use. URL patterns break when
a pass changes its paths. The table check (RF-06) reads `Orchestrator.run`, so a renamed or new pass fails the test
instead of going unattributed.

**Trade-off.** The table depends on private method names; a refactor of the orchestrator updates the table in the
same pull request.

### ADR-3 — Three harnesses, and the API reads the scan harness's results

**Decision.** Full scans only in the scan harness; the CLI harness runs short scans for failures before and after a
scan; the API harness feeds the scan harness's results to the real runner instead of scanning again.

**Alternatives.** (a) Run every failure through both the CLI and the API. (b) Unit tests per component only.

**Why.** The Web API stores and serves a result; scanning again through it would double the cost and test the
engine twice. The address guard is installed only on the real transport, so the resolver needs a run of its own.
Unit tests alone would not search the outputs a user sees.

**Trade-off.** The API harness does not see a failure that happens only in a scan the API started; the runner's
own failures are injected directly.

### ADR-4 — The suite fixes what it finds, in the same pull request

**Decision.** Each step that adds a part of the suite also fixes the failures that part finds, with the failing run
as the test seen failing first.

**Alternatives.** (a) Land the suite with expected failures (`xfail`) and fix later.

**Why.** An `xfail` gate passes while the defect is there. The fixes known from reading are small and local.

**Trade-off.** A step's size depends on what its part finds; a step that finds more than a small fix stops for a
decision.

### ADR-5 — The inventory is a syntax-tree walker in the tests, with reasons in the test

**Decision.** `tests/sensitive_points.py` walks the source by family; the reasons live in
`SENSITIVE_POINTS` in the test, keyed by module, function, family and callee.

**Alternatives.** (a) A script under `scripts/` with a verdict file keyed by fingerprint. (b) Extend one of the three
inventories of specs `024` to `026`.

**Why.** A key that names the function and the call reads in a diff and survives lines added above it; a
fingerprint does not read. The three inventories each answer one question (a reveal, an output, a destination);
this one answers whether a point is safe at all, over families they do not cover (resolved decision 1).

**Trade-off.** The walker is about 600 lines of test code, well past the line budget of `specs/README.md`, because
the gate is the deliverable.

### ADR-6 — A `robots.txt` server error keeps the target URL and replaces the count warning

**Decision.** On a server or network error the crawl keeps only the target URL, and one warning says why and how to
turn `follow_robots` off.

**Alternatives.** (a) Fetch nothing at all. (b) Retry `robots.txt` later in the scan.

**Why.** The target URL is fetched today before `robots.txt` is asked, and a disallow-all file already leaves the
scan with that page; the error case matches it (resolved decision 2). A scan reads `robots.txt` once, so a later
retry would be a new rule. The count warning would say "kept the crawler from N URLs", which hides the cause.

**Trade-off.** A site whose `robots.txt` is broken gets a one-page crawl until the user turns `follow_robots` off.

### ADR-7 — The dashboard appends the address on an upgrade instead of refusing it

**Decision.** The same rewrite runs on the `upgrade` event.

**Alternatives.** (a) Refuse every upgrade to `/api/*` in the dashboard.

**Why.** It is one line in the code that already owns the header, and it keeps the rule "every forwarded request
ends with the connection's address" true without a second policy. Refusing would need its own handler and would
have to change if the API ever served a WebSocket.

**Trade-off.** None.

### ADR-8 — The next minor release, no milestone

**Decision.** The change goes in the next minor release, with the changes of specs `025` and `026` if that release
is not out yet. The roadmap row's delivery is `—`.

**Alternatives.** (a) A patch release.

**Why.** The `robots.txt` rule, the setup `429` and the new error lines are changes of behaviour that fit a minor
release (`docs/stability.md`), and no command, option, key, check id, exit code or schema field changes. The spec
delivers no product feature.

**Trade-off.** None.

## Impact on existing code

- **Engine.** `robots.py` gains a disallow-all result and two matching fixes; the crawler and the orchestrator
  carry its warning; the session pass chooses its logout by the credential rule; the orchestrator moves three steps
  inside their pass's `try` and the portable traceback to `core/output.py`; the OpenAPI importer's message changes.
- **CLI.** The write and render of a report are handled; `webvigil report`'s read error changes.
- **Web API.** The setup route takes a slot; the proxy lookup takes a lock; the runner's log line changes.
- **Dashboard.** The server patch handles `upgrade`; its test "leaves other events alone" uses another event.
- **Tests.**
  - `tests/support.py` gains `spellings`; the integration and CLI canaries use it instead of their own copies.
  - `test_api_throttle.py` or `test_login_throttle_and_sessions.py` gains the setup cases; the robots, crawler,
    session scanner and client address tests gain their cases.
  - `pyproject.toml` collects `tests/failure/`.
- **Documentation.**
  - [`docs/writing-checks.md`](../../docs/writing-checks.md): a new pass needs a row in the failure table and lines in
    the inventory.
  - [`docs/architecture.md`](../../docs/architecture.md) or the crawler's documentation: `robots.txt` on a server
    error.
  - The project's agent notes: one line each for the failure table and the inventory.
  - `CHANGELOG.md` `[Unreleased]`:
    - **Changed:** the `robots.txt` rules and warning, the setup `429`, the dashboard's forwarding of an upgrade,
      the new error lines of the CLI and the server log line of an engine error.
    - **Fixed:** the logout choice under `--scope subdomains`; a report that cannot be written ends with exit code
      `4` instead of a traceback; anything else the suite finds.

## Test strategy

The `specs/README.md` rules apply, with one stated exception: the failure-injection suite runs its own scans
(rule 2), because a failing scan cannot share the integration scan's result.

**Budget.** The failure-injection suite takes at most 20 s of the CI run with coverage; the pull request that adds
the scan harness states its measurement. Past 20 s, two kinds share a run on alternating stages before the merge.

**The failure-injection suite (RF-01 to RF-06).** As in the components above. How each guard is seen failing:

- `credential_hits`: on a branch, `safe_text` stops redacting one credential; the scan run goes red. Undone.
- `failure_hits`: the CLI's error line prints `str(exc)`; the CLI run goes red. Undone.
- The positive controls: the fault transport stops applying faults (every recorded list empty); the controls go
  red before the searches pass vacuously.
- The table check: a pass method is renamed in a throwaway class; the check names it.
- The plan: `fault_for` uses the run number alone; the "every stage every kind" test goes red.
- Each fix the suite forces is proved by its run failing on `main` first (ADR-4).

**The inventory (RF-07).** The gate over the source, and the throwaway source with one point per family. Seen
failing: a family is removed from the walker (the throwaway test names it), and a new `open()` in a listed function
is added on a branch (the gate names the `#2` key).

**Setup (RF-08).** In `tests/api/`: the slots are held by a test throttle with `max_concurrent_checks=0` → `429`
with `Retry-After` and no row in `user`. Positive control: a free slot creates the account; a second setup gets `409`
without taking a slot. Seen failing by hashing outside the slot.

**Proxy lookup (RF-09).** `TrustedProxies` with a resolver stub that blocks on an event and counts calls, a fake
clock past the expiry, and eight threads asking at once → one call, every thread gets the stub's answer. A failing
stub → every thread gets `False`. Positive control: before the expiry, no call. Seen failing by removing the lock.

**Dashboard (RF-10).** In `forwarded-for.test.ts`: emitting `"upgrade"` with a request rewrites the header. Positive
control: `"request"` still does; `"connection"` is left alone. Seen failing by dropping the `upgrade` branch.

**`robots.txt` (RF-11, RF-12).** In `test_crawler.py` and the robots tests, through `httpx_mock`: `503` and a refused
connection → only the target URL fetched and the warning; `404`, an empty `200` and a missing file → the queue goes
through. Positive control: a `200` file with no rule lets the queue through. A rule `Disallow: /a?` against `/a?`,
`/a?x` (disallowed) and `/a` (allowed). A 600 KiB `latin-1` file with a rule in a non-ASCII path within the limit →
matched as a small file's rule is. Seen failing by reverting each change in turn.

**Logout (RF-13).** In `test_session_scanner.py`: under `--scope subdomains`, a logout link on a sibling subdomain and
none on the target's origin → no hit and the warning "no logout endpoint found". The same with a logout on the
target's origin after the sibling → the origin's is used. A configured sibling `logout_url` → the new warning. Seen
failing on `main` first: the sibling link is chosen and the hit is reported (the false positive of RF-13).

**Same scan, same requests (RF-14).** The baseline of spec `026` is taken again before the first step and compared
after the last: the requests the fixture receives in the four configurations and the JSON reports. The fixture's
`robots.txt` answers `200`, and its logout is on the target's origin, so no difference is expected.

**Mutation.** Every changed guard (`setup`, `_name_addresses`, `load`, `_request_target`, `_find_logout`, the CLI's
write handling) goes through mutation testing in batch; the score and the triage of survivors go in each pull
request.

## Deviations

1. **The concurrent proxy-lookup tests sit in `tests/api/test_login_abuse.py` (RF-09, test strategy).** The
   tasks put them under `tests/unit/`. The existing tests of `TrustedProxies` (a name resolved again after its
   time to live, a name that does not resolve, a request with no header) already live in that file, with the
   test clock and the resolver helper the new tests build on, so the new ones sit next to them.
2. **The `robots.txt` warning is tested in `tests/unit/test_orchestrator.py` (RF-11, test strategy).** The tasks
   put "only the target URL fetched after a `503`, and the warning" in `test_crawler.py`. The crawler only exposes
   `robots_unreadable`; the warning is the orchestrator's, so `test_crawler.py` checks what is fetched and the
   reason, and the orchestrator's test, with its crawler stub, checks the one warning in place of the count.
3. **The configured `logout_url` is checked before `_find_logout` (RF-13).** A refused `logout_url` needs its own
   warning, so the session pass asks `may_carry_credentials` before it looks for an endpoint, and `_find_logout`
   returns a configured URL as given. Links and forms are checked inside `_find_logout`, as designed.
4. **The walker reads every node, and the count of calls read equals the source's (RF-07, ADR-5).** The walk
   behind the design's count read the module level and function bodies only: a class body, a lambda, a decorator, a
   default value and an annotation were never read. Each node now belongs to one scope (the module, a class body
   or a function), so the fourth test asserts that the calls read equal every call of the source, which is
   stronger than "larger than the table".
5. **Some names of the families changed (RF-07).** SQLModel's `session.exec` matched the `exec` builtin, and
   `selectolax`'s `node.text()` matched SQLAlchemy's `text`; the builtins and `text` now match only when called
   bare, so the first is `sql` and the second is not a point. `network` also lists the `httpx2` clients and
   transports, `crypto` the `ssl` contexts and `jwt`, `code` the `entry_points` of the plugins and `file` any
   `.open`. On the dashboard, `redirect` also lists `router.push`, `router.replace`, `redirect(` and
   `location.assign` / `replace`, and leaves out a variable declared as `location`. This is why the walk finds
   201 points where the design's reading found 213.
6. **The dashboard has an `error` family too (RF-07).** The text of a caught error used in a `catch` block or an
   `onError` / `.catch` callback is a point, as on the Python side. The key of a Python `error` point names the
   output the text reaches, with its destination when there is one: `raise:RequestFailed`, `log:logger.warning`,
   `return`, `field`.
7. **`webvigil report` keeps the message of a report that does not load (RF-04).** The design says
   `could not read <path> (<type>)` for every read error. An `OSError` is named by its type; a
   `ValueError` keeps its message, which `load_result` writes itself from the report's own field
   names (spec `025`), so `not a valid WebVigil report: 1 error, at findings[0].title` still says
   what is wrong.
8. **The log the harnesses search is the project's (RF-03, "The outputs").** The design collects every
   record of the root logger at `DEBUG`. The collector keeps the records of the loggers whose output
   the project owns: `webvigil` and its children, and `httpx2` and `uvicorn.error`, which the Web
   API treats. Another package's logger, such as the `DEBUG` trace of `httpcore2`, which repeats an
   exception's text, is left as that package configures it: the engine used as a library never
   changes another package's logger (spec `025`, ADR-4), and neither the CLI nor the Web API turns
   it on. A test keeps the rule, with a record of each kind.
9. **The table (RF-02, RF-06).** The check reads every call on `self` in `Orchestrator.run`, not only
   the awaited ones, so the HAR import, a plain call, is a seam too; the two calls that are not passes
   (the Active-Mode gate and the check selection) are named with a reason. The report stages' seams
   are the two helpers the fix added, `_rendered` and `_write_report`. The trusted-proxy lookup
   (`api/client_address.py`), an entry of `CONNECTIONS`, gets a row of its own, `api-proxies`, for
   the API harness. The TLS probe belongs to the `checks` stage; the harnesses turn the TLS check off
   on the plain-HTTP fixture, as the integration scan does, so its socket stays covered by the
   socket-based unit tests.
10. **The plan's test checks neighbours too (RF-02, ADR-1).** Rotating by the run number alone still
    gives every stage every kind, so the design's sabotage would pass "every stage every kind"; the
    same test asserts that two neighbouring scan stages never share a kind in one run, which is what
    the rotation by row is for, and that goes red.
11. **The CLI harness has four more runs (RF-02, RF-05).** A clean run against the fixture wrapped as a
    site that echoes `Cookie` and `Authorization` into its `Server` header: the positive control of
    the collector (the streams, the report and its three re-renders) and of the credential search,
    with the scrub's `[redacted]` in the report. `webvigil report --output` gets a write failure and a
    render failure, the second added after a mutant that bypassed the render handling survived. A
    seam helper takes the test's `monkeypatch` first, and `failing_render` takes the format.
12. **`spellings` gives eight forms (RF-03).** The design's seven count the two base64 alphabets as one.
13. **The stages that can end the scan fail alone (RF-02, ADR-1; decided on 2026-11-26).** The login,
    the OpenAPI import, the target URL and the crawl end the scan on some kinds by design (a login
    that fails, a document that does not load, a target that does not answer, an unexpected error),
    and the OSV lookup has nothing to ask when the fingerprint pass failed. Run as designed, four of
    the six full scans ended at the login, the OpenAPI import or the crawl, so most later stages got
    two of their six kinds. The table marks these five stages `alone`: each gets six runs of its own,
    one per kind, in a light configuration, with every other stage left alone. The six full runs
    rotate the kinds over the nine passes the scan goes on after (`TOGETHER`), and two neighbours
    still never share a kind. Every pair of stage and kind still runs once.
14. **An unexpected error exits with `1` (RF-02).** The design's assertion lists `0`, `3` and `4`. A
    `RuntimeError` from the login, the OpenAPI import, the target URL or the crawl, and a Public
    Suffix List that cannot be read, are not failures the engine names. The CLI ends them with one
    line, `the scan stopped on an unexpected error (<type>)`, and `1`, the code
    [`docs/stability.md`](../../docs/stability.md) gives an unexpected error. A run asserts that `1`
    comes with that line and only with it.
15. **The count warning is not asserted (RF-02).** The design asserts that the requests that failed
    for good are counted in the scan's request warnings. That warning is for a target that stopped
    answering: it needs 20 failures and a fifth of the requests. The plan fails one URL in eight, so
    the warning never appears, and it keeps its floors.
16. **The `checks` stage has a check of its own (RF-02, RF-05).** With the TLS check off on the
    plain-HTTP fixture, no check sends a request, so the stage had nothing to fail. The harness
    registers a throwaway check, `failure-suite.echo`, that sends one request through the scan's
    client and quotes the body as evidence. Its server-error run is the positive control that a
    failure's text reaches a report where it may, cut and with its controls shown.
17. **The vendored files have runs of their own (RF-02, ADR-4).** The plan fails requests; the
    Retire.js rules, their provenance, the catalogue of exposed paths and the Public Suffix List are
    files. Each file `DEPENDENCIES` gives a scan stage gets one run that fails its read, after its
    cache is cleared, and a test keeps the list in step with the table. The catalogue is read twice
    in a scan, by `load_catalogue` before the probe and by `backup_spec` inside it; the second run
    reads the first before it fails the file. The Public Suffix List is read under
    `--scope subdomains` at the first scope decision, and its failure ends the scan as an unexpected
    error: the scope cannot be decided without it.
18. **The fixture takes the login's password (RF-03).** `make_app` takes `password`, so the password
    is a credential marker like the cookie and the bearer token. The session ids the fixture issued
    are searched as whole tokens, as the integration canary searches them: the insecure profile's
    count up and can appear inside a random hex value.
19. **`failing_osv` is the fault transport with its stage fixed to `osv`**, not a `MockTransport`
    handler, and the fault transport takes the set of stages that fail in the run. `attributed`
    takes the classes it wraps, so a test can wrap throwaway ones.
20. **The Web API's credential markers are its own (RF-03).** The tasks put credential markers in
    the scan's options. The Web API takes no credential for a scan: `ScanCreate` has no such field,
    and a target with one is refused (spec `024`). Its markers are the account's password, the
    signing key of its sessions and the session token the login issued, each with its control (the
    login with the password, the token verified with the key); the scan harness's three come in the
    result, with the session ids the fixture issued.
21. **The API harness takes the six full runs (ADR-3, RNF-06).** Each full run holds a failure of
    every pass the scan goes on after, with the echo check's quoted server error among them. Through
    the API a result costs about 0.6 s with coverage on a developer machine, so the thirty runs
    alone would take the failure suite past its budget; their stages end the scan or leave one
    warning, which the CLI harness already searches.
22. **The API's JSON escapes hidden characters (RF-04, ADR-4).** The design searches every output a
    failure may reach for raw characters. The database is checked for the bound only: a stored value
    is bounded and neutralized where it is shown (spec `025`, the `STORE` profile). The API's JSON is
    checked like a report, and its first run found FastAPI's encoder writing the bidirectional and
    zero-width characters of a finding's evidence and of a scan's error raw (JSON escapes only the
    C0 controls). The API's default response, `EscapedJSONResponse` in `api/app.py`, passes the
    document through `safe_text(Sink.JSON)`, as the JSON report does; a parser reads the same
    values. The `422` keeps its own response, whose messages are already shown on one line.
23. **The log collector leaves the exception object out (RF-03).** `LogLines` keeps every attribute
    of a record but `exc_info`: every formatter writes `exc_text`, which the project's filter
    rebuilt, and the object's `repr` repeated the whole message, past every bound, where no handler
    prints it.
24. **The portable traceback reaches the record through `extra` (RF-04, ADR-4).** The runner logs
    `scan <id> failed (<type>)` with no `exc_info`, and the filter makes the `PORTABLE_TRACEBACK`
    value the record's `exc_text`, cut as `safe_traceback` cuts. With `exc_info` attached, a handler
    that formats the exception itself, not `exc_text`, would print the message again.
25. **The proxy lookup has a run (RF-02, RF-06).** The `api-proxies` row (deviation 9) gets the run
    the tasks left out: the resolver raises with the marker on the login. The login works, the
    forwarded address is not believed, and the text reaches no output. It passed on `main`.
26. **A numbered output keeps its family (RF-04).** `family` kept the number `Outputs.add` gives a
    second output of a name with no colon (`server-log#5`), so the second record of the log could
    not hold what the first may. It now drops the number, and a test keeps it.
27. **The stability page says how `httpcore2` logs (RF-04).** The Python API part of
    `docs/stability.md` gains a factual note: the engine never changes the level or the handlers of
    another package's logger, and `httpcore2` at `DEBUG` logs the headers of every response, the
    target's session cookies included, so a program that embeds the engine keeps that logger at
    `INFO` or above. The code does not change: the project's filter covers the loggers the project
    owns (spec `025`, ADR-4).
28. **The two-minute bound of the whole suite holds on Linux CI (RNF-06).** On the developer
    machine of Stage 0 the suite with coverage went from 120 s to 151 s, the failure suite being
    37 s of it. On CI, with coverage, it takes 53 s to 68 s on Linux, the required checks, and 106 s
    to 111 s on Windows with Python 3.13 to 3.15; on Windows with Python 3.12 it took 194 s before
    Stage 0 and 246 s at the end. The bound is read on Linux CI, and the other times are recorded
    here.

## Implementation notes

- **Stage 0.** The baseline was taken on `main` at `d3f05ae` (Python 3.15.2, Windows): 3769 tests collected
  (3765 passed and 4 skipped on Windows), 98 % line and branch coverage in total, the per-file table, and the
  suite in 120 s with coverage. The four scans ran through the CLI in Active mode with every opt-in except the
  time-delay detectors, with the OpenAPI import and the exposed-path probe (no HAR and no OSV lookup), against
  the fixture application served by `uvicorn` on `localhost`, which recorded every request it received:

  | Scan | Requests | Findings | Duration |
  |---|---|---|---|
  | anonymous | 1321 | 61 | 66.4 s |
  | `[auth]` cookie and headers | 1321 | 61 | 61.7 s |
  | automated login and session tests | 1348 | 65 | 62.8 s |
  | `--scope subdomains` | 1321 | 61 | 61.7 s |

  The setup route hashes inside a password-check slot, the proxy lookup runs under a lock with the expiry checked
  again inside it, and the dashboard rewrites the header on `upgrade`. Each new test failed once with the line it
  guards broken: the route of `main` (the hash with no slot) and the hash moved after the slot's block, the
  lookup of `main` (no lock) and the lock without its second expiry check, and the `upgrade` branch dropped.
  Mutation over `create_first_user` and `_name_addresses`: 28 mutants (21 generated over the guards, 7 by hand
  over the slot, the `429`'s status, message and `Retry-After`, the lock, the store of the answer and its time
  to live), 28 killed, and every new test killed at least one. The first run timed out on the mutant that never
  stores the answer: the test waited out a fixed number of short polls, each a scheduler tick on Windows, and
  left the resolver held when its assertion failed. The wait is now bounded in seconds and the resolver is
  released in a `finally`, and the mutant is killed.
- **Stage 1.** `load` refuses every URL on a `5xx` after the retries (`HTTP <status>`) and on a network error (the
  failure kind, `ConnectError` for a refused connection); a scope refusal, a `4xx`, a missing and an empty file
  allow every URL. Keeping the `?` of an empty query also means that a rule `/a$` no longer covers `/a?`, which
  the `CHANGELOG.md` entry says. `decode_text` builds the decoding on `httpx2`'s own, so `Response.text` reads as
  before. Each new test failed once on `main` (the sibling logout link chosen and the hit reported, `/a` fetched
  after the `503`, the rule `/caf%EF%BF%BD/` read from the cut file) and once with each change reverted in turn
  (eleven sabotages). Mutation over `load`, `_request_target`, `verdict`, `_find_logout`, the logout pass,
  `decode_text`, the crawler's assignment and the orchestrator's warning: 114 mutants (99 generated over the
  guards, 15 by hand over the reasons, the charset, the `?`, the assignment and `decode_text`), 103 killed. Four
  survivors of the first run led to tests: a charset that decodes to a lone surrogate (`decode_text` replaces
  it), a configured `logout_url` used where the crawl links another logout, and a `GET` logout form and a `POST`
  form that is not a logout, neither submitted. Of the 11 left, 3 are equivalent: an empty `200` parses to no rule;
  a missing `Content-Type` decodes as UTF-8 either way; resolving an empty `href` gives the page's own URL, which
  is not a logout. The other 8 are guards this stage does not change: seven in the logout pass (the reference
  page, the cookie snapshot, the `5xx` logout, two on the replay's status, a page that is not HTML and an `href`
  that does not resolve) and the 500 KiB boundary of `robots.txt`.
- **Stage 2.** The walk reads the 149 Python and 78 dashboard files `git ls-files` lists in scope, in about one
  second, and finds 201 points: 58 `error`, 63 `message`, 21 `regex`, 20 `crypto`, 13 `sql`, 12 `file`, 7
  `network`, 3 `redirect`, 2 `html`, 1 `code` and 1 `xml` (192 in Python, 9 on the dashboard; no `command`,
  `deserialization` or `client-secret` point). Each reason was written after reading the point's code and the
  guard it names (`safe_text` at the sinks, `display_url`, `failure_kind`, `describe_validation_error`, the log
  filter's `safe_traceback`, bound SQL parameters, a vendored file, the user's own path); no point lacked one, so
  `src/` is unchanged and the stage has no mutation run. Each test failed once with the line it guards broken
  (nine sabotages): the `xml` names and the `client-secret` pattern removed from the walker, the fields no
  longer followed across files, the text no longer followed through variables (each named by the throwaway
  test), class bodies left unread (the calls read fell from 5733 to 3470), an unparsed file not reported, an
  empty reason, a stale line, and a second `Path(path).open("rb")` in `load_result` (the gate names
  `webvigil.reporting:load_result file .open#2`). The walker is about 1,000 lines, against the 600 of ADR-5: the
  lists of names take one line per name as `black` lays them out.
- **Stage 3.** The failure suite is 29 tests in about 2.5 s: 11 for the table, 6 for the searches and 12
  CLI runs. On `main`, four runs failed, each for the defect its fix removes: `report-write` and
  `report-render` ended with exit code `1` and an unhandled `OSError` or `RuntimeError`,
  `report-read` printed the `OSError`'s text (the marker on standard error), and `openapi-parse` printed
  the JSON parser's message. The other runs passed on `main`: the resolver, the configuration, the
  OpenAPI document and the HAR file were already named by type. Each test failed once with the line
  it guards broken (thirteen sabotages): the scrub skipped (the clean run finds both credentials), the
  three new error lines and the OpenAPI line printing the exception's text, the read, resolver and
  render seams that never raise (their controls go red), a seam renamed in the table, the plan
  rotating by run alone, a dependency left out of the table, the log filter keeping every logger, and
  `spellings` without base64. Mutation over `report`, `_emit`, `_write_or_print`, `_rendered`,
  `_write_report` and the JSON branch of `_fetch_document`: 39 mutants (14 generated over the guards,
  20 by hand over the handlers, their messages, exit codes and bypasses, 5 aimed at the runs no other
  mutant failed: the read messages of the configuration, OpenAPI and HAR files and the failure kind),
  39 killed, and every new run killed at least one. The one survivor of the first round, a
  `webvigil report` whose render bypassed the handling, led to the render run of deviation 11.
- **Stage 4.** The scan harness is 41 runs: 6 full runs of the integration scan's configuration with the
  nine passes the scan goes on after failing at once, 30 runs alone (the login, the OpenAPI import, the
  target URL, the crawl and the OSV lookup, one per kind) in a light configuration, and 5 runs of a
  vendored file; with the table check and the two tests of `attributed`, the failure suite is 73 tests,
  about 39 s with coverage on a developer machine and 12 to 17 s on CI (Linux, Python 3.12 to 3.15),
  within the 20 s budget. Run as designed first, four of the six full scans ended
  at the login, the OpenAPI import or the crawl (deviation 13). On `main`, eight runs failed, each for the
  defect its fix removes: a `RuntimeError` from the login, the OpenAPI import, the target URL or the crawl
  ended with a traceback and exit code `1`, and an unreadable Retire.js database, its provenance, the
  catalogue of exposed paths or the Public Suffix List did too. Typer 0.29 prints no local variables, and a
  check with the credentials kept out of the source showed none of them in the traceback; it showed the
  exception's text, which is why the line names the type only. Every other run passed on `main`. Each test
  failed once with the line it guards broken (seven sabotages): the fault transport applying no fault and a
  pass that does not name its stage (the controls go red), a seam renamed in the table, `attributed`
  restoring nothing, the echo check quoting nothing (the control of RF-04 goes red), and the CLI's handler
  narrowed or printing the exception's text. Mutation over `_fingerprint`, `_probe_disclosure` and the
  CLI's handler: 21 mutants (11 generated over the guards, 10 by hand over the moves into the `try`, the
  handlers, the type names and the exit code), 19 killed, and every new run killed at least one. The two
  left survive the whole suite and are guards this stage does not change: `_fingerprint` and
  `_probe_disclosure` run with no check selected that reads their result.
- **Stage 5.** The API harness is 11 runs: the six full runs' results through the real runner and
  every route, and five failures of its own (the engine raising a `RuntimeError` and a
  `WebVigilError`, the store and the claim raising `OperationalError`, the proxy name that does not
  resolve). With two more tests of the searches, the failure suite is 86 tests, about 37 s with
  coverage on a developer machine against 32 s without the API harness. On CI, with coverage, it
  takes about 18.7 s (3.12), 13.5 s (3.13), 19.0 s (3.14) and 18.1 s (3.15) on Linux, plus under
  0.6 s for the last ten checks of the table, read from the progress line that holds only failure
  tests and the `--durations` of the four full runs on the line before; within the 20 s budget, so
  no two kinds share a run. On `main`, the `RuntimeError`
  run failed: the server log held the exception's message. Once the API's JSON was searched like a
  report, the full run whose echo check got a server error and the `WebVigilError` run failed on
  the raw bidirectional and zero-width characters of the JSON (deviation 22). Every other run passed
  on `main`. Each test failed once with the line it guards broken (twelve sabotages): the stand-in
  returning a result without the markers (the controls go red), the loop stopping after a failed
  claim, the claim and store seams that never raise, the proxy lookup letting the resolver's error
  through, `family` keeping the number, the stored outputs checked for raw characters and not checked
  at all, the log collector keeping `exc_info`, the API's default response back to FastAPI's, and its
  render without the escapes. Mutation over `_run_scan`, `SafeLogFilter.filter` and `_cut_lines`: 13
  mutants (all by hand: the log call, its type name and traceback, the stored errors, the store's
  log, the filter's branches and the cut), 13 killed, with the two of the JSON response above, 15 of
  15. The two runs no mutant failed, the full runs and the claim, each failed under a sabotage.
- **Stage 6.** The four scans of the baseline ran again on `main` at `7c5ede6`, against the same
  recording fixture: 1321, 1321, 1348 and 1321 requests, as before, and 61, 61, 65 and 61 findings,
  in 60 s to 62 s each. The requests are the same multiset once the random values are masked
  (hex runs of eight or more characters, then digit runs); 340 of each scan (345 with the
  automated login) differ before the mask, all of them injection probes that carry the scan's random
  token. In the reports, `schema_version`, the warnings, the errors, the technologies, the counts
  and, for every finding, the check id, the severity, the fingerprint, the location and the masked
  title are identical; the titles differ only by the random name of the uploaded file and the
  number it printed. The suite went from 3769 to 3907 tests (3903 passed and 4 skipped on Windows),
  in 151 s with coverage (deviation 28). Total coverage stays at 98 %, with 172 lines and 135
  branches left uncovered against 191 and 142, and no file of `src/webvigil` leaves more lines or
  branches uncovered than at Stage 0, or has a lower percentage. The baseline folder was then deleted. This stage changes no code.
