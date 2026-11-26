---
feature: Destination policy — one place decides what each URL may receive, and a public name that resolves only to internal addresses is reported
status: in progress
date: 2026-11-25
related:
  - 001-foundation/design.md
  - 019-automated-login/design.md
  - 020-session-security/design.md
  - 023-httpx2-migration/design.md
  - 024-secret-values/requirements.md
origin: conception
---

# 026 — Destination policy — design

## Overview of the approach

A new engine module, `core/destination.py`, holds every answer to "what may this URL receive". It is a set of
pure functions over the scan's `Target`:

- `may_request`: whether the URL may be requested at all (the scope rule).
- `may_carry_credentials`: whether it may get the credentials and whether its cookies may be kept.
- `keeps_data`: whether a redirect may replay a body or query to it.
- `without_credentials`: a caller's headers with the credential ones removed when the URL may not get them.
- `is_target_host`: whether the URL names the target's host, used for messages only.
- `is_public_name`: whether a host name is one the internet resolves, which the address guard needs for
  RF-06.

`Target.in_scope` and `Target.carries_credentials` stay as they are and remain the two rules. The module is the
only code in the package that calls them (ADR-1).

Every sender moves to the module:

- **The HTTP client:**
  - its scope check, the credential attachment, the re-login check and the `Set-Cookie` intake ask the module;
  - its two redirect helpers become `keeps_data` and `without_credentials`;
  - `without_credentials` now also runs on the first request, which closes the first gap (RF-03, ADR-2);
  - `ScopeGuard` and the unused `allow_out_of_scope` bypass go away (ADR-3).
- **The session jar** asks `may_carry_credentials` in place of its own host match (ADR-4).
- **The passes** (the login, the session tests, the crawler, forms, OpenAPI, HAR, fingerprint, disclosure probe
  and upload) replace their `in_scope`, `carries_credentials` and host comparisons with the module's functions.
  None of them changes what it sends.

The address guard records two facts as it resolves:

- the target is a public name that resolved only to internal addresses (RF-06);
- a host had internal addresses left out next to public ones (RF-07).

At the end of the scan the orchestrator turns them into warnings, next to the existing blocked-address warning
(ADR-5, ADR-6).

A syntax-tree test over the source fails on any destination decision outside the module, and on any new place
that opens a network connection. Each such place must be in an inventory with its reason (RF-09, ADR-7).

### What was checked (2026-11-25, on `main` at `a0744b5`)

- **Who calls the two rules.** Outside `core/target.py`:
  - 35 calls in 13 modules call `in_scope` or `carries_credentials`.
  - 15 comparisons in 8 modules compare a `host`, `hostname`, `scheme`, `port`, `origin` or `netloc` attribute.
    Some of these are destination decisions (`auth/login.py:349`, `crawler/openapi.py:329`). The others are
    parsing rules: a HAR entry's scheme, a `Secure` cookie over plain `http`, the TLS check's scheme.
- **Whether any pass sends a credential header of its own.** Only the session tests do
  (`checks/session/scanner.py:341, 392`), and each is gated first by `_may_get_cookies`. The envelope pass sends
  a forged `Host` and forwarding headers, never `Cookie` or `Authorization`. So filtering a pass's own
  credential headers on the first request (RF-03) changes no request a scan sends today (RF-08).
- **`allow_out_of_scope`.** No caller in `src/` passes it. Two tests in `test_http_client.py` use it, and three
  fake clients copy its signature.
- **The Public Suffix List and internal names.** The list's default rule makes every unlisted top-level label a
  suffix of its own, so `registrable_domain` returns `app.local` for `app.local`, `app.internal` for
  `app.internal` and `cluster.local` for `svc.cluster.local`. The vendored list does list `onion`, `arpa` and
  `home.arpa`. "Has a registrable domain" is therefore not "is a public name" (ADR-5).
- **The integration scans** run over `httpx2.ASGITransport`. With a custom transport the address guard is not
  installed, so the shared scan never resolves a name, and RF-06 and RF-07 are tested on the guard itself.
  The fixture application of the RF-08 baseline runs under `uvicorn` on `127.0.0.1`, where the guard is
  installed and the target is internal, so no new warning is expected there.

## Module layout

```
src/webvigil/core/destination.py       new: the policy functions, CREDENTIAL_HEADERS, SPECIAL_USE_LABELS
src/webvigil/core/target.py            unchanged rules; docstrings point to core/destination.py
src/webvigil/http/client.py            asks the policy; first-request credential filter; no ScopeGuard,
                                       no allow_out_of_scope
src/webvigil/http/scope_guard.py       removed
src/webvigil/http/__init__.py          no ScopeGuard export
src/webvigil/http/session.py           SessionJar(target): pairs_for asks may_carry_credentials
src/webvigil/http/addresses.py         AddressGuard records AddressNotices; address_warnings()
src/webvigil/core/orchestrator.py      appends address_warnings() next to blocked_address_warning()
src/webvigil/auth/login.py             _check_gate and _check_delegated ask the policy
src/webvigil/checks/session/scanner.py _may_get_cookies and the logout finder ask the policy
src/webvigil/checks/{deps/fingerprint,disclosure/probe,upload/scanner}.py   may_request
src/webvigil/crawler/{crawler,forms,har,openapi}.py                         may_request, is_target_host
tests/unit/test_destination.py         new: the table of destination cases, is_public_name
tests/unit/test_destination_inventory.py  new: the syntax-tree gate
tests/unit/test_http_addresses.py      the two notices and their warnings
tests/unit/test_http_redirect_credentials.py  a pass's own credential header on the first request
tests/unit/test_session_jar.py         pairs_for against the policy
tests/integration/test_scan_fixture_app.py    OSV requests of the full scan carry nothing of the target
```

## Data model

`core/destination.py`:

| Name | Type | Meaning |
|---|---|---|
| `CREDENTIAL_HEADERS` | `frozenset[str]` | `{"cookie", "authorization"}`, moved from `http/client.py` |
| `SPECIAL_USE_LABELS` | `frozenset[str]` | Top-level labels that never name a site on the internet: `alt`, `arpa`, `example`, `internal`, `invalid`, `local`, `localhost`, `onion`, `test` (the IANA special-use names, RFC 6761, 6762, 7686, 8375 and 9476, and the `internal` label ICANN reserved for private use) |

`http/addresses.py`:

| Name | Type | Meaning |
|---|---|---|
| `AddressNotices` | frozen dataclass | What the guard saw that the user should know |
| `AddressNotices.internal_target` | `str \| None` | The target host, when it is a public name that resolved only to internal addresses |
| `AddressNotices.left_out` | `tuple[tuple[str, int], ...]` | `(host, internal addresses dropped)` per host, in the order first resolved |
| `MAX_LEFT_OUT_LINES` | `int` | `10`: hosts named one per line before the summary line (RF-07) |

No report field, configuration key or database column is added. The warnings go into `ScanResult.warnings`,
which every output already carries.

## Components

### The policy (`core/destination.py`)

```python
def may_request(target: Target, url: str) -> bool: ...
def may_carry_credentials(target: Target, url: str) -> bool: ...
def keeps_data(target: Target, current_url: str, next_url: str, *, credentialed: bool) -> bool: ...
def without_credentials(
    target: Target, headers: Mapping[str, str] | None, url: str, *, auth_names: Iterable[str]
) -> dict[str, str] | None: ...
def is_target_host(target: Target, url: str) -> bool: ...
def is_public_name(host: str) -> bool: ...
```

- **`may_request`** returns `target.in_scope(url)`.
- **`may_carry_credentials`** returns `target.carries_credentials(url)`. It answers both "may the credentials go"
  and "may its `Set-Cookie` be kept", which are one rule today and stay one.
- **`keeps_data`** is the rule of `HttpClient._withholds_data`, negated. Data is withheld only when
  `credentialed` is true, the current URL may carry the credentials and the next one may not. The client
  computes `credentialed` as it does today: the scan holds a session, a static cookie or an `[auth]` header, and
  the request is not anonymous.
- **`without_credentials`** is the rule of `HttpClient._hop_headers`. It returns `headers` unchanged when the URL
  may carry the credentials. Otherwise it returns a copy without `CREDENTIAL_HEADERS` and without the configured
  `[auth]` header names (case-insensitive). `None` and an empty mapping come back as they went in.
- **`is_target_host`** compares the URL's lower-cased host with `target.host`. It replaces the two inline
  comparisons whose result chooses a message (the login's delegated-login message, the OpenAPI server warning).
  It never decides what is sent.
- **`is_public_name`** is true when `host` is a dotted DNS name (not an IP literal, not one label) and its
  top-level label is a rule of the vendored list (an exact rule, or the base of a wildcard rule). The top-level
  label must also not be in `SPECIAL_USE_LABELS`. The list is parsed once per process (`load_rules` is cached).

The module imports `Target` only for typing and the list from `core/suffixes.py`. It holds no state, so two
callers asking about the same URL get the same answer by construction (RF-01).

### The HTTP client (`http/client.py`)

| Today | After |
|---|---|
| `ScopeGuard(target)`, `self._guard.allows(url)` / `.check(url)` | `may_request(self._target, url)`, raising `OutOfScopeError(url)` itself |
| `allow_out_of_scope` on `get` / `request` / `_send_with_redirects` | removed (ADR-3) |
| `on_target = self._target.carries_credentials(url)` | `may_carry_credentials(self._target, url)` |
| re-login check `self._target.carries_credentials(url)` | `may_carry_credentials` |
| `_withholds_data(current, next)` | `not keeps_data(..., credentialed=self._credentialed())` |
| `_hop_headers(headers, url)` on hops only | `without_credentials(...)` on the first request and every hop (RF-03) |
| `_CREDENTIAL_HEADERS` | `destination.CREDENTIAL_HEADERS` |

`_credentialed()` is the private helper that holds the "has credentials and not anonymous" test now inlined in
`_withholds_data`. The `[auth]` header names come from `self._auth_headers`, as today.

The credential filter runs once in `_send_with_redirects`, before the first `_request_with_retry`, and then on
every hop as before. The client's own cookies and `[auth]` headers keep being added inside `_request_with_retry`,
after the filter, only when `may_carry_credentials` says yes. A filtered caller header is dropped silently, as on
a hop today. A pass that needs to know beforehand checks `may_carry_credentials` itself, which is what the
session tests do so that they can warn and skip.

### The session jar (`http/session.py`)

`SessionJar.__init__` takes the `Target` instead of its host. In `pairs_for`, `may_carry_credentials(target, url)`
replaces the inline host-name match. The stdlib jar then applies `Secure`, `Path` and expiry as today. The
`repr` shows the target's origin instead of its host. `absorb` is unchanged: the client calls it only for a
response that `may_carry_credentials` allows, and the `Secure`-over-`http` filter in `_jar_view` is a cookie
rule, not a destination one (it is in the inventory with that reason).

### The passes

Each one is a rename with no change in behaviour:

- **The automated login (`auth/login.py`).**
  - `_check_gate` asks `may_request` and `may_carry_credentials`.
  - The landing page check asks `may_request`.
  - `_check_delegated` picks its message with `is_target_host(...) or may_request(...)`.
  - `SessionJar(target)`.
- **The session tests (`checks/session/scanner.py`).** `_may_get_cookies` asks `may_carry_credentials` and keeps
  its warning. The logout finder asks `may_request`.
- **The crawler (`crawler/crawler.py`, `forms.py`, `har.py`)** asks `may_request` for links, form actions and HAR
  entries. The HAR import's scheme comparison is a parsing rule and stays, with its line in the inventory.
- **The OpenAPI import (`crawler/openapi.py`).** The document URL check asks `may_request`. The `servers` warning
  asks `is_target_host`.
- **The dependency fingerprint, the disclosure probe and the upload pass** ask `may_request`. The probe's
  host-label read (`probe.py:250`) builds a wordlist and decides no destination; it is in the inventory with
  that reason.

### The address guard (`http/addresses.py`)

`AddressGuard.addresses` already pins the target first and then each host, under one lock. It now also records,
under the same lock, the first time it sees each host:

- **The internal target.** When the target's own resolution has no public address (`_public_only` comes out
  false) and `is_public_name(target_host)` is true, it sets `internal_target`. It allows every address, as
  today.
- **The addresses left out.** When `_public_only` is true and a host's resolution holds both public and
  internal addresses, it appends `(host, number of internal addresses)` to `left_out`. That host's allowed list
  is its public addresses, as today. A host with only internal addresses still raises `BlockedAddressError`
  and is counted in `blocked_address`, as today.

`AddressGuard.notices()` returns an `AddressNotices` snapshot. `address_warnings(notices) -> list[str]` builds the
lines:

- **Internal target:** `the target host {host} is a public name but resolves only to internal addresses
  (loopback, private, link-local); the scan ran against them: check that this is the machine you meant to scan`.
- **Addresses left out:** one line per host, up to `MAX_LEFT_OUT_LINES`: `{host} resolves to {n} internal
  address(es) besides its public ones; the scan used only the public addresses`. Past the cap, one line:
  `{k} more host(s) resolve to internal addresses besides their public ones`.

The TLS probe resolves through the same guard, so its connection is recorded too. When a proxy is set in the
environment the guard is not consulted for HTTP, as today, and no notice is recorded. The architecture document
says so.

### The orchestrator (`core/orchestrator.py`)

After `blocked_address_warning(http.stats)`, it extends `warnings` with `address_warnings(http.addresses.notices())`.
The warnings reach the terminal summary, every report, the Web API and the dashboard through the outputs of
spec `025`, with no change there.

### The inventory gate (`tests/unit/test_destination_inventory.py`)

The test parses every module under `src/webvigil` and records three kinds of site, each as `module:qualname` of
the enclosing function:

- **Rule calls:** any call of an attribute named `in_scope` or `carries_credentials`. They are allowed only in
  `webvigil.core.destination`.
- **Destination comparisons:** any `Compare` node with an operand that is an attribute named `host`,
  `hostname`, `scheme`, `port`, `origin` or `netloc`. Each one outside `core/destination.py` and
  `core/target.py` must be in `COMPARISONS`, a mapping from site to reason.
- **Network openings:** any call of `httpx2.AsyncClient`, `httpx2.Client`, `socket.create_connection`,
  `socket.socket`, `getaddrinfo`, `asyncio.open_connection` or `urlopen`. Each one must be in `CONNECTIONS`, a
  mapping from site to reason. Today's entries:
  - the scan client (`http/client.py`);
  - the OSV client (`checks/deps/osv.py`);
  - the TLS probe's socket, opened to an address the guard returned (`http/tls_probe.py`);
  - the system resolver (`http/addresses.py`);
  - the Web API's resolution of `web.trusted_proxies` names (`api/client_address.py`).

An unlisted site fails, and so does a listed site with no matching call left. The shape is the one of the
reveal inventory of spec `024` and the sink inventory of spec `025`.

## Interfaces

- **Command line, configuration, report schema, Web API:** unchanged. Two new warning texts can appear in
  `warnings` (RF-06, RF-07).
- **Python API (provisional, `docs/stability.md`):**
  - `webvigil.http.ScopeGuard` is removed.
  - The `allow_out_of_scope` keyword of `HttpClient.get` and `HttpClient.request` is removed.
  - `SessionJar` takes a `Target`.
  - `webvigil.core.destination` is new, and `docs/writing-checks.md` points a plugin to it.
  - `Target.in_scope` and `Target.carries_credentials` stay, so a third-party plugin that calls them keeps
    working.
- **Wire:** byte for byte the same requests for the same scan (RF-08).

## ADRs

### ADR-1 — A module of pure functions over `Target`, the only caller of its two rules

**Decision.** `core/destination.py` holds the decisions as functions that take the `Target`. The scope and
credential rules stay in `Target`, unchanged, and the module is the only code in the package that calls them.

**Alternatives.**

- (a) A `DestinationPolicy` object built once per scan and passed to the client, the jar, the login and every
  pass through `ScanContext`.
- (b) Move the bodies of `in_scope` and `carries_credentials` into the new module and leave delegates in
  `Target`.

**Why.**

- The decisions hold no state, so a function of the target gives the same answer to every caller by
  construction (RF-01), with no object to thread through the constructors of the crawler, the importers and the
  passes.
- Keeping the rule bodies where they are leaves `test_target.py` and the rules untouched (resolved decision 2),
  and the table of RF-02 runs against both the module and the rules.
- Under (b) the two modules would import each other.

**Trade-off.** Nothing stops a third-party plugin from calling `Target.in_scope` directly; the gate covers the
package only. The plugin guide says to use the module.

### ADR-2 — The client filters a caller's credential headers on the first request too

**Decision.** `without_credentials` runs before the first send as well as on every hop. The session tests keep
their own check, now for its warning only.

**Alternatives.**

- (a) Keep the filter on hops, and require each pass that sends a credential header to check first, enforced by
  the inventory.
- (b) Refuse such a request with an error instead of dropping the header.

**Why.**

- The gap is that the rule depends on each pass remembering it (RF-03). Applying it where every request passes
  closes it for a pass that does not exist yet.
- Dropping the header matches what a hop does today, and what the client does with its own credentials.
- An error would turn a pass's mistake into a failed scan, and the session tests already show how to warn
  instead.

**Trade-off.** A pass that sends a credential header to the wrong place gets no error, only a request without
it; its verdict can be wrong. The session tests' pattern (check, warn, skip) stays the documented way.

### ADR-3 — `ScopeGuard` and `allow_out_of_scope` are removed

**Decision.** The client asks `may_request` and raises `OutOfScopeError` itself. The keyword that skipped the
check goes away, and the tests that used it build an in-scope URL or a target that covers it.

**Alternatives.** (a) Keep `ScopeGuard` as a wrapper over `may_request`. (b) Keep `allow_out_of_scope` and list it
in the inventory.

**Why.** `ScopeGuard` was the first "single place" for one of the rules. With the module it is a second name for
the same answer. A bypass with no caller in the package is a way around the policy that a future change could
use without anything failing. Both are internal under `docs/stability.md`.

**Trade-off.** A plugin importing `webvigil.http.ScopeGuard` breaks. The CHANGELOG says so under **Changed**, as
the stability page asks for a provisional name.

### ADR-4 — The session jar asks the credential rule instead of matching the host

**Decision.** `SessionJar` holds the `Target`, and `pairs_for` returns nothing for a URL that
`may_carry_credentials` refuses.

**Alternatives.** (a) Keep the host match, and rely on every caller asking the rule first.

**Why.** The two rules agree today only because the client checks first. The session tests call `pairs_for`
directly, after a check of their own. One rule in the jar makes a new direct caller safe (RF-04).

**Trade-off.** None observable: every current caller already asks the same rule first (RF-08).

### ADR-5 — A public name is one under a listed top-level label that is not special-use

**Decision.** `is_public_name` asks for a dotted name whose top-level label is a rule of the vendored Public
Suffix List and is not in `SPECIAL_USE_LABELS`.

**Alternatives.**

- (a) Any name with a registrable domain.
- (b) Any dotted name.
- (c) Ask the DNS whether the name exists publicly.

**Why.**

- (a) and (b) would warn on `app.local`, `app.internal` and `svc.cluster.local`, which are the common lab and
  cluster names (the list's default rule makes them registrable).
- The list does carry `onion`, `arpa` and `home.arpa`, so the special-use labels are checked explicitly rather
  than trusted to be missing.
- (c) is a network call to a resolver other than the system's, which crosses "the engine only talks to the
  target".

**Trade-off.** A private name under a listed top-level label (a company's `corp.example.com` served by
split-horizon DNS) gets the warning. That is the case the warning is for: the user reads it and keeps the scan
(resolved decision 1).

### ADR-6 — The guard records notices; the warnings are capped at ten hosts

**Decision.** The address guard records what it saw as `AddressNotices`. The orchestrator turns them into
warnings at the end of the scan: one line for an internal target, one line per host with addresses left out up
to ten, then one summary line.

**Alternatives.**

- (a) Log at the moment of resolution.
- (b) Print in the terminal before the first request.
- (c) One warning per host with no cap.

**Why.**

- The guard is the only place that sees both the target's and each host's resolution, at the moment of
  pinning.
- The result's warnings are the one channel every output already carries, including the Web API and the
  dashboard.
- Under `--scope subdomains` the site chooses its links, so the number of hosts is the site's to choose; a cap
  keeps the warnings bounded.
- Printing before the first request would need a channel the CLI does not have. The decision of 2026-11-23 is
  to warn and continue, not to stop.

**Trade-off.**

- The warning arrives with the result, after the scan ran.
- Behind a proxy set in the environment, nothing is recorded, as the guard does not apply there.

### ADR-7 — The gate is a syntax-tree inventory of rule calls, comparisons and connections

**Decision.** `test_destination_inventory.py`, as described in Components, with `COMPARISONS` and `CONNECTIONS`
mappings from site to reason.

**Alternatives.** (a) A behavioural canary only: a scan with every pass on, asserting no credential reaches a
second host. (b) Lint rules (`ruff` banned calls).

**Why.** A canary proves today's passes, not tomorrow's. The inventory fails on the change itself, and gives a
reviewer one list with a reason per site, as specs `024` and `025` do (RF-09). Banned-call lint cannot express
"allowed only in this module, with a reason elsewhere".

**Trade-off.** The comparison rule matches attribute names, so a comparison through a local variable
(`host = parts.hostname; host == ...`) is missed. The behavioural tests of RF-03 to RF-05 and review cover that.

### ADR-8 — The next minor release, no milestone

**Decision.** The change goes in the next minor release, with spec `025`'s changes if that release is not out
yet. The roadmap row's delivery is `—`.

**Alternatives.** (a) A patch release.

**Why.** Commands, options, configuration keys, check ids, exit codes, the report schema and fingerprints do not
change. The new warnings and the removed provisional names fit a minor release (`docs/stability.md`). The spec
delivers no product feature, like `023` to `025`.

**Trade-off.** None.

## Impact on existing code

- **Engine.** The client, the jar, the login, the session tests, the crawler, the importers and three passes
  change their imports and their calls, with no change in what they send. `http/scope_guard.py` is deleted.
- **Tests.**
  - `test_http_client.py`: two tests use `allow_out_of_scope`. They are rewritten to prove the out-of-scope refusal
    and an in-scope URL instead.
  - `test_envelope_scanner.py`, `test_injection_engine.py`, `test_upload_scanner.py`: their fake clients drop the
    keyword.
  - Tests that build a `SessionJar(host)` pass a `Target`.
- **Documentation.**
  - [`docs/architecture.md`](../../docs/architecture.md): the scope guard paragraph becomes the destination
    policy, and the address guard paragraph gets the two warnings and the proxy note.
  - [`docs/writing-checks.md`](../../docs/writing-checks.md): ask `webvigil.core.destination`, not `Target`, and a
    new comparison or connection needs its inventory line.
  - [`docs/checks-internals.md`](../../docs/checks-internals.md): the `Target.in_scope` mention becomes
    `may_request`.
  - The project's agent notes: one line saying that every destination decision goes through
    `core/destination.py`.
  - `CHANGELOG.md` `[Unreleased]`:
    - **Security:** a pass's own credential headers follow the client's rule on the first request.
    - **Changed:** the two warnings, and the removal of `ScopeGuard` and `allow_out_of_scope`.

## Test strategy

The `specs/README.md` rules apply: logic in unit tests, integration attached to the shared scan, about one test
line per `src/` line, the whole suite under 2 minutes, no real network and no real resolver.

**`tests/unit/test_destination.py`:**

- **The table (RF-02).** One parametrized table of `(target, scope, url)` rows. The rows cover:
  - scheme and the `https` upgrade, in both directions;
  - host case and a trailing dot;
  - explicit and default ports, and the `80`/`443` pair;
  - sibling, parent and deeper subdomains under each `--scope`;
  - IPv4 and IPv6 literals, a one-label host, a public-suffix target (`github.io`);
  - a malformed URL, a non-`http` scheme and userinfo.

  Each row states the expected `may_request` and `may_carry_credentials`, and asserts that they equal
  `Target.in_scope` and `Target.carries_credentials`. Seen failing by making `may_carry_credentials` return
  `may_request`.
- **`keeps_data`.** The four combinations of current and next URL against `credentialed` true and false. Seen
  failing by dropping the `credentialed` test.
- **`without_credentials`.** `Cookie`, `Authorization` and an `[auth]` name in mixed case are dropped for a
  refused URL. The positive control is the same headers kept whole for the origin. `None` and `{}` pass through.
- **`is_public_name`.**
  - Expected true: `app.example.com`, `example.co.uk`, `www.alice.github.io`, an `xn--` label under `com`, a
    wildcard base (`x.y.ck`).
  - Expected false: `app.local`, `app.internal`, `svc.cluster.local`, `x.home.arpa`, `x.onion`, `x.test`,
    `x.localhost`, `app`, `localhost`, `10.0.0.5`, `::1`.

  Seen failing by removing `SPECIAL_USE_LABELS` (`x.onion` turns true) and by using `registrable_domain` instead
  (`app.local` turns true).

**The client (RF-03), `test_http_redirect_credentials.py`.** A request with an explicit `Cookie` and
`Authorization`, under `--scope subdomains`, sent to a sibling subdomain:

- the headers are not on the wire, on the first request and after a redirect;
- the positive control is the same request to the origin, where they are on the wire;
- seen failing on `main` (the first request carries them).

The existing redirect tests keep their expectations, which shows that the move of `_hop_headers` and
`_withholds_data` changed nothing.

**The jar (RF-04), `test_session_jar.py`.** `pairs_for` returns nothing for another port, for plain `http` from an
`https` target and for a sibling subdomain. It returns the cookies for the origin and for the `https` upgrade of
an `http` target. `Secure` and `Path` still apply (the existing tests). Seen failing by restoring the host
match (the other-port row returns cookies).

**OSV (RF-05), attached to the shared full scan.** The `_osv_up` stub records each request it gets. A new test
over the cached full scan (automated login, `[auth]` cookie and header, `--osv-online`) asserts that no OSV
request carries a `Cookie`, an `Authorization`, a configured `[auth]` header name, the session cookie's value or
the target's host. The positive control is that the fixture received the `[auth]` header on the same scan, and
that the stub was called. Seen failing by forwarding the scan's headers to the OSV client in a scratch change.

**The address notices (RF-06, RF-07), `test_http_addresses.py`.** The resolver is stubbed.

- An internal target under a public name is recorded and produces its warning. `addresses()` returns the internal
  addresses, which is the positive control that the scan reaches them.
- Each non-public name of the `is_public_name` table records nothing.
- A public target and a host with two public and one internal address record `(host, 1)`, and the allowed list
  is the two public ones.
- Twelve such hosts give ten lines and the summary line.
- A host with only internal addresses still raises `BlockedAddressError` and records nothing new.

Seen failing by removing each record.

**The orchestrator wiring.** One unit test runs the orchestrator over a stub client whose guard returns a notice,
and finds both warnings in `result.warnings`. Seen failing by removing the `extend`.

**The inventory (RF-09), `test_destination_inventory.py`.** The walk with its positive controls over a throwaway
source string:

- an unlisted `in_scope` call fails;
- an unlisted `parts.hostname == x` fails;
- an unlisted `httpx2.AsyncClient(...)` fails;
- a stale entry fails.

Seen failing by adding a `target.in_scope(url)` to a scratch copy of a pass.

**Same scan, same requests (RF-08).** As in specs `024` and `025`, a baseline is recorded on `main` before the
first change and the same scans are repeated when the spec closes. The fixture application is served by
`uvicorn` and scanned in four configurations:

- anonymous;
- with `[auth]` cookies and headers;
- with the automated login and the session tests;
- with `--scope subdomains`, against `localhost`. A one-label host stays an exact match, so this scan proves only
  that the scope code path sends the same requests; the subdomain cases are in the table.

The requests the fixture received and the JSON reports are saved outside the repository. When the spec closes,
they are compared, leaving out timestamps, durations and per-run random values. Any difference fails.

**Mutation (RNF-06).** `core/destination.py`, the changed functions of `http/client.py`, `SessionJar.pairs_for`,
`AddressGuard.addresses`, `AddressGuard.notices` and `address_warnings` go through mutation testing in batch at
the end of each stage that changes them. Every changed function has a killed mutant, every survivor is triaged,
and the score goes in the pull request.

## Deviations

1. **`without_credentials` returns a copy for a URL that may carry the credentials (components, ADR-2).** The
   design said `headers` come back unchanged. They come back as a new mapping with every entry, so the caller's
   mapping is never the one the client sends on and the signature needs no cast. `None` still comes back as
   `None`.

## Implementation notes

- **Stage 0.** The RF-08 baseline was taken on `main` at `25c33d2` (Python 3.15.2, Windows): 3613 tests
  collected, 97 % line and branch coverage in total, the per-file table, and the suite in 85 s with coverage. The
  four scans ran through the CLI in Active mode with every opt-in except the time-delay detectors, against the
  fixture application served by `uvicorn` on `localhost`, which recorded every request it received. The server
  was started with the project's interpreter (`python -m uvicorn`), because on Windows stopping `uv run` leaves
  its child process holding the port.

  | Scan | Requests | Findings | Duration |
  |---|---|---|---|
  | anonymous | 1323 | 60 | 103.4 s |
  | `[auth]` cookie and headers | 1323 | 60 | 103.7 s |
  | automated login and session tests | 1316 | 63 | 48.6 s |
  | `--scope subdomains` | 1323 | 60 | 103.2 s |

  A second run of the `--scope subdomains` scan gave the same findings and warnings and the same requests once
  the per-run random values are masked (the markers, the probe operands and the random tokens: 676 of its
  requests differ before the mask). The anonymous and the `--scope subdomains` scans received the same requests
  under the same mask. The Stage 4 comparison applies it.
- **Stage 0 tests and mutation.** `tests/unit/test_destination.py` holds 118 tests, 56 of them rows of the
  table. Each sabotage of the test strategy failed its tests: `may_carry_credentials` returning `may_request`
  (15 rows), `keeps_data` without its `credentialed` test, `is_public_name` without `SPECIAL_USE_LABELS`
  (`x.onion`, `x.home.arpa`) and through `registrable_domain` (`app.local` and ten more). Mutation over
  `core/destination.py`: 51 mutants (30 generated over the guards, 21 by hand over the constants, the rules
  and the header filter), 49 killed and 2 equivalent (the `TYPE_CHECKING` import). The first run left 8 other
  survivors: seven special-use labels and the IP literal check, which the vendored list already refuses on its
  own. A test now feeds `is_public_name` a list that carries every special-use label and a numeric rule. One
  more survivor showed that `is_target_host` lower-cased a host `urlsplit` already lower-cases, and the call was
  removed.
- **Stage 1.** The client and the session jar ask the module. Each new or rewritten test failed once with the
  line it guards broken: the first request sent with the caller's headers unfiltered (the two first-request
  tests), the jar back on the host match (another port and plain `http` from an `https` target), the client
  without its `OutOfScopeError` (the two refusal tests), and the credential rule replaced by the scope rule
  (the two sibling-subdomain tests). Mutation over the changed functions of `http/client.py` and
  `SessionJar.pairs_for`: 101 mutants (90 generated over the guards, 11 by hand over the calls that changed),
  94 killed. Three survivors are equivalent: the `on_target` test before `pairs_for`, which the jar now asks
  itself (ADR-4), an empty session list that rebuilds the same static cookie header, and the `[auth]` loop over
  an empty list. Four are on lines the stage did not change (the `learn` after a retry, the pending-jar
  fallback and the parse of the `Cookie` header in `pairs_for`). The first run left two more on changed lines,
  and each got a test: a 401 from a sibling subdomain no longer counts as a dropped session only through the
  credential rule, and the jar's `repr` names the target origin.
- **Stage 2.** Every pass asks the module, with no change in what it sends. The session tests' docstring now says
  that the client would drop their explicit cookie header off the origin, which is why they ask first. The
  inventory holds six comparison sites and five network openings, the five the Components list. Its tests
  failed once each with a `target.in_scope` call, a `hostname` comparison and an `httpx2.AsyncClient` added in
  turn to `crawler/forms.py`. The full scan now turns the OSV lookup on, so the RF-05 test runs on the scan with
  the automated login and the `[auth]` cookie and header. It failed once with the scan's `[auth]` headers
  forwarded to the OSV client. Mutation over `_check_gate`, the landing page check, `_check_delegated` and
  `_may_get_cookies`: 18 mutants (17 generated over the guards, 1 by hand), 16 killed. The hand mutant drops
  `may_request` from the landing page check and is equivalent: `response.url` is the last URL the client
  requested, and the client requests only what `may_request` allows. The other survivor makes the landing
  page's ternary always true, on a line the stage did not change.
- **Stage 3.** The guard records the two notices under its lock, the first time it sees each host, and the
  orchestrator turns them into warnings after the blocked-address one. Each new test failed once with the line
  it guards broken: the internal-target record removed, the `is_public_name` test dropped (eleven lab, cluster
  and address names then warned), the left-out record removed, the first-time check removed (a host asked twice
  was counted twice), the summary line removed, and the orchestrator's `extend` removed. Mutation over
  `AddressGuard.addresses`, `AddressGuard.notices` and `address_warnings`: 39 mutants (28 generated over the
  guards, 11 by hand over the records, the counts, the cap and the orchestrator's call), 38 killed. The survivor
  makes the guard work out `_public_only` on every call; it is equivalent, as the target's resolution is pinned
  and gives the same answer each time.
