---
feature: Automated login — find the login form, submit credentials, capture the session, re-authenticate when it drops (Active Mode, opt-in)
status: done
date: 2026-10-07
related:
  - 019-automated-login/requirements.md
  - 007-auth-flows/design.md
  - 013-auth-and-api-surface/design.md
  - 017-csrf-confirmation/design.md
  - 018-post-form-crawl/design.md
origin: conception
---

# 019 — Automated login — design

## Overview

A login is two small pieces that meet inside `HttpClient`:

1. An **`Authenticator`** that performs the handshake (GET the login page → find the form →
   submit once → follow the redirect chain → verify) *through the `HttpClient`*, so the scope
   guard, the rate limiter and the redirect loop all apply.
2. A **`Session`** the `HttpClient` consults: a cookie jar that survives the handshake, a
   "did the session drop?" test, and a single-flight `recover()` that calls the
   Authenticator again.

```
Orchestrator.run
  └─ HttpClient (open)
       ├─ session = Session(...)            built from [auth.login] + credentials (Active only)
       ├─ Authenticator(http, target, cfg, creds).login()   ── verified, or LoginFailedError (exit 4)
       ├─ http.use_session(session)         from here on: jar cookies on target-host requests
       ├─ crawl / passes / checks           unchanged; every request may trigger recover()
       └─ result = scrub(result, session.secrets)
```

`HttpClient.request` becomes: *snapshot generation → send → if the response signals a dropped
session → `recover(generation)` (serialised, capped) → send once more*. Nothing above
`HttpClient` knows a session exists, which is why the crawler, the injection passes and every
check work unchanged (RF-10).

## Module layout

| File | Change |
|---|---|
| `src/webvigil/http/session.py` | **new.** `SessionJar` (wraps `httpx.Cookies`), `Session` (jar, generation, relogin budget, drop test, `recover`, secrets), `DropMatcher`. No import of the crawler or of `Authenticator`. |
| `src/webvigil/http/client.py` | `use_session()`, `handshake()` context manager (a `ContextVar`), cookie attach / absorb in `_request_with_retry`, the drop-and-retry wrapper in `request`. `Response` unchanged. |
| `src/webvigil/auth/__init__.py`, `auth/login.py` | **new.** `Credentials`, `Authenticator`, `LoginResult`, form picking, verification. Imports `http`, `core`, and `crawler.forms` / `crawler.safety` (engine-internal; the layering contract only bans UI/DB frameworks). |
| `src/webvigil/auth/scrub.py` | **new.** `scrub_result(result, secrets)`. |
| `src/webvigil/crawler/forms.py` | `parse_forms_html(text, url, target)` extracted from `parse_forms` so the Authenticator can parse a `Response` without building a `Page`. `form_body` reused as is. |
| `src/webvigil/core/config.py` | `LoginSection` and `AuthSection.login`; `AuthSection.configured` / `has_session` helpers. |
| `src/webvigil/core/errors.py` | `LoginFailedError(WebVigilError)`. |
| `src/webvigil/core/result.py` | `LoginSummary`, `ScanMetadata.login`. |
| `src/webvigil/core/orchestrator.py` | `credentials=` ctor kwarg, the login step, the Passive/Active warning, the scrub, metadata. |
| `src/webvigil/crawler/crawler.py`, `checks/csrf/checks.py` | the two `bool(auth.cookies or auth.headers)` / `bool(auth.cookies)` tests move to the config helpers. |
| `src/webvigil/cli/app.py`, `cli/_render.py` | `--login-url`, `--username`, `--password-env`, the prompt, the summary line. |
| `tests/fixtures/app.py` | the stateful `/signin` area (see "Fixture app"). |

No new runtime dependency (`httpx.Cookies` and `selectolax` already do the work).

## Data model

### Configuration (`[auth.login]`)

```toml
[auth.login]
url = "https://app.example/signin"        # required, in scope
username = "scanner@example.com"          # required
password_env = "WEBVIGIL_LOGIN_PASSWORD"  # the NAME of the variable; never the password
# optional overrides (RF-03)
username_field = "email"
password_field = "pass"
form_index = 0
extra_fields = ["tenant=acme"]
logged_in_marker = "Sign out"             # regex over the body
logged_out_marker = "Sign in"
check_url = "https://app.example/account"
max_relogins = 3                          # 0..10
```

```python
class LoginSection(_Section):
    url: str
    username: str
    password_env: str = "WEBVIGIL_LOGIN_PASSWORD"
    username_field: str | None = None
    password_field: str | None = None
    form_index: int | None = None          # >= 0
    extra_fields: list[str] = []           # "name=value", validated like cookies
    logged_in_marker: str | None = None    # compiled in a validator: a bad regex is a ConfigError
    logged_out_marker: str | None = None
    check_url: str | None = None
    max_relogins: int = 3                  # ge=0, le=10
```

- A `model_validator(mode="before")` rejects a `password` key with "the password never goes in
  the config file: put it in an environment variable and name it with `password_env`" (RF-02).
  The base `_Section` already forbids unknown keys.
- `AuthSection.login: LoginSection | None = None`; two properties:
  `configured -> bool` (`cookies or headers or login`) replaces the three
  `bool(auth.cookies or auth.headers)` sites, and `has_session -> bool` (`cookies or login`)
  replaces the CSRF check's `bool(auth.cookies)`.
- The password is **not** a config field. It travels as `Credentials`, a frozen dataclass
  whose `__repr__` hides the password, from the CLI (or an embedding caller) to
  `Orchestrator(cfg, credentials=...)`. When the caller passes none and `[auth.login]` is set,
  the Orchestrator reads `os.environ[password_env]`; absent → `LoginFailedError` ("set
  `WEBVIGIL_LOGIN_PASSWORD`").
- Dumping or round-tripping a `ScanConfig` therefore cannot leak the password (RF-02).

### Result

```python
class LoginSummary(BaseModel):          # frozen
    relogins: int
    session_lost: bool

class ScanMetadata(BaseModel):
    ...
    login: LoginSummary | None = None   # None: no login configured
```

`authenticated` keeps its meaning ("credentials of any kind were supplied") and is `True` when
`auth.configured`. The JSON report gains `metadata.login` (`null` for every scan without a
login); SARIF/HTML/Markdown are untouched. The API's `rows_to_result` leaves it `None`.

### The session

```python
class SessionJar:
    """A cookie jar that only ever holds the session (RF-07)."""
    def begin(self) -> None            # start a handshake: an empty pending httpx.Cookies
    def commit(self) -> None           # pending becomes the live jar; remember its names
    def rollback(self) -> None
    def absorb(self, raw: httpx.Response, *, handshake: bool) -> None
    def pairs_for(self, url: str) -> list[tuple[str, str]]
    @property
    def values(self) -> frozenset[str]  # every cookie value ever held (for scrubbing)

class Session:
    jar: SessionJar
    generation: int                     # +1 on every successful (re)login
    max_relogins: int
    relogins: int
    lost: bool
    def looks_dropped(self, response: Response) -> bool
    async def recover(self, seen: int) -> bool
    def summary(self) -> LoginSummary
    secrets: set[str]                   # the password + jar.values
```

## Components

### `SessionJar` — `httpx.Cookies` with two rules

- **Handshake mode** (`absorb(handshake=True)`): every `Set-Cookie` of every hop goes into the
  *pending* jar, and the pending jar is what is sent on the next hop, as a browser would.
  `httpx.Cookies.extract_cookies(raw)` and `set_cookie_header` give Domain/Path/Secure/expiry
  handling (RF-07 last bullet) from the stdlib `http.cookiejar` instead of a hand-rolled
  parser. A `Max-Age=0` / past `Expires` removes the cookie (the standard way a login clears
  its pre-login cookie).
- **Live mode** (`absorb(handshake=False)`): only a cookie whose *name* is already in the jar
  is accepted (rotation). Everything else the target sets is dropped, which keeps the
  determinism argument of spec 007 for everything but the session.
- `pairs_for(url)` returns `[]` for any host other than the target host.
- Every value that enters either jar is added to `values` for scrubbing.

### `HttpClient` changes

```python
def use_session(self, session: Session) -> None
@contextlib.asynccontextmanager
async def handshake(self) -> AsyncIterator[None]   # sets _HANDSHAKE (a ContextVar) and jar.begin()
```

- **Attach** (in `_request_with_retry`, replacing the cookie block): the cookie header is the
  static `[auth] cookies` pairs *minus the names the session holds*, then the session pairs;
  target host only. With no session the block is byte-identical to today.
- **Absorb**: after each raw response, `session.jar.absorb(raw, handshake=_HANDSHAKE.get())` —
  this is inside the per-hop function, so the redirect chain of the login `POST` (and of the
  handshake `GET`) contributes every hop's `Set-Cookie`. `self._active_client.cookies.clear()`
  stays: httpx's own jar is never used.
- **Drop and retry** (in `request`, which keeps its signature):

  ```python
  seen = session.generation if session else 0
  response = await self._send_with_redirects(...)          # today's body, renamed
  if session and not _HANDSHAKE.get() and _is_target(url) and session.looks_dropped(response):
      if await session.recover(seen):
          response = await self._send_with_redirects(...)  # once; its verdict is returned as is
  return response
  ```

  A `ContextVar` (not an attribute) so a re-login running in one task does not switch other
  tasks' requests into handshake mode.
- `Response` gains nothing; `looks_dropped` reads `status_code`, the final URL, `history` and
  `text`.

### `Session.looks_dropped` (RF-08)

True when, for a target-host request:

1. `status_code == 401`; or
2. the final URL (after in-scope redirects) is the login URL or `is_login_url(final)`, **and**
   the *requested* URL was not itself a login URL **and** it is not in `known_login_redirects`
   (see ADR-6); or
3. `logged_out_marker` matches the body (a compiled regex, `search`, body truncated at 200 KB).

Never `403`, never `5xx`, never an out-of-scope redirect. When `check_url` is configured the
signal is only a *suspicion*: `recover` fetches `check_url` (in handshake context, so no
recursion) and re-logs in only if that page itself looks logged out (login redirect, 401 or
marker) — a payload that draws a redirect to the login page no longer costs a re-login.

### `Session.recover(seen)` (RF-09)

```python
async def recover(self, seen: int) -> bool:
    async with self._lock:
        if self.generation != seen:          # someone re-logged in while we waited
            return True
        if self.relogins >= self.max_relogins:
            self.lost = True
            return False
        if not await self._confirm_dropped():  # check_url said "still logged in"
            return False
        self.relogins += 1                   # failed attempts count too
        ok = await self._relogin()           # Authenticator.login(), inside http.handshake()
        return ok
```

`generation` is bumped only by a *committed* login. On a failed re-login the live jar is
untouched (`rollback`), `relogins` was already spent, and the next suspicious response asks
again — until the cap, after which `lost` is set and the scan continues unauthenticated with a
warning (open question 3).

### `Authenticator.login()` (RF-04, RF-05, RF-06)

Runs inside `async with http.handshake():`.

1. **Gate checks, before any request.** `login.url` in scope (the `HttpClient`'s guard raises
   `OutOfScopeError`; mapped to `LoginFailedError`); `login.url` is `https` whenever the
   target is `https`.
2. `GET login.url` → absorb cookies. A non-2xx, non-HTML or out-of-scope redirect (an SSO hop:
   `response.redirected_out_of_scope`) fails with "login redirects to `<host>`: delegated
   login is not supported".
3. **Pick the form**: `parse_forms_html(body, final_url, target)`, keep `POST` forms with a
   `password`-typed field. `form_index` (over the candidates) wins; zero candidates → fail
   listing the forms seen (action + field names, no values); several and no `form_index` →
   fail listing them. The picked form's `action` must be in scope and not downgrade the scheme.
4. **Pick the fields**: `password_field` or the form's one password input; `username_field`
   or the nearest preceding `text` / `email` input (parser order); an override naming a field
   the form lacks → fail naming the override (RF-03).
5. **Body**: `form_body(form, sentinel="", replace={user_field: username, pass_field: password,
   **extra_fields})`. Hidden fields, CSRF tokens and the submit button travel as the browser
   would send them.
6. **Submit once**: `http.request("POST", action, data=body | files=..., headers={"Origin":
   target.origin, "Referer": page_url})`. The client's redirect loop follows the chain and
   absorbs each hop. `RequestFailed` here is *not* retried by the Authenticator (the client's
   own non-idempotent rule already forbids retrying after a read timeout); a `5xx` is a failed
   login.
7. **Verify** (RF-06, first rule that decides):
   (a) `logged_out_marker` on the final body → fail; `logged_in_marker` → success;
   (b) `check_url` fetched in the handshake context with the pending jar: logged-out looking →
   fail, else success;
   (c) heuristic: the final page has no password input **and** the pending jar holds a cookie
   it did not hold after step 2 → success; has the password input again **or** no new cookie →
   fail; the rest → *inconclusive*.
8. On success `jar.commit()`, `generation += 1`; on failure `jar.rollback()` and
   `LoginFailedError(message)` where the message carries the final URL, status and which
   observation decided — never a body, a cookie or the password. **Inconclusive** commits and
   returns `LoginResult(confirmed=False)`; the Orchestrator turns it into a warning.

### Orchestrator, CLI and the summary

- After `HttpClient` opens and **before** `_load_openapi` (the OpenAPI document may sit behind
  the login): if `auth.login` is set and the mode is Active, build `Session`, `Authenticator`,
  call `login()`, `http.use_session(session)`. Passive with a login configured appends the
  RF-01 warning ("a login requires --mode active — no login was attempted") and proceeds as an
  unauthenticated scan.
- After the checks: `warnings.extend(session.warnings())` (session lost, failed re-logins,
  unconfirmed login), `metadata.login = session.summary()`, and
  `result = scrub_result(result, session.secrets)`.
- `LoginFailedError` is a `WebVigilError`, so `cli/app.py` already maps it to exit 4
  (`ExitCode.OPERATIONAL`) with `_render.error`.
- **CLI.** `--login-url`, `--username`, `--password-env` (default `WEBVIGIL_LOGIN_PASSWORD`);
  all merge into `auth.login` *deep* (a CLI `--username` overrides the file's, the rest of the
  file's `[auth.login]` survives — `with_overrides` is shallow per section, so `_build_config`
  merges the login dict itself). The password: `os.environ.get(password_env)`, else
  `typer.prompt(hide_input=True)` when stdin is a TTY, else a usage error (exit 2). Resolved
  *before* the scan starts and handed over as `Credentials`.
- **Summary** (`_render.summary`): `auth: logged in (N re-logins)` / `auth: session lost after
  N re-logins` / `auth: login not confirmed`, from `result.metadata.login`; the username comes
  from the CLI's own config, never the result.

### Scrubbing (RF-11)

`scrub_result(result, secrets)` serialises the `ScanResult` to JSON, replaces every secret by
`[redacted]` and validates it back. Each secret is replaced in four spellings — raw, JSON
string escape, `urllib.parse.quote` and `quote_plus` — because a target reflects a password
as a form body (`quote_plus`) or inside a JSON error. Secrets under 4 characters are not
scrubbed (replacing `"1"` would shred the report); the docs say so. The pass runs once, at
the end, over findings (evidence, title, description), warnings, errors and metadata, so no
check needs to know about secrets. The report fingerprint does not depend on evidence text,
so a scrub never changes a fingerprint.

## Interfaces

| Surface | Change |
|---|---|
| CLI | `--login-url TEXT`, `--username TEXT`, `--password-env NAME` on `scan`; help says it makes a real login with that account. |
| Config | `[auth.login]` (above); a `password` key is a `ConfigError`. |
| Engine | `Orchestrator(config, *, check_types=None, credentials: Credentials | None = None)`. |
| JSON report | `metadata.login: {relogins, session_lost} | null`. |
| Exit codes | a failed login is `OPERATIONAL` (4); a missing password without a TTY is `USAGE` (2). |
| Web API / UI | unchanged. |

## ADRs

### ADR-1 — The session lives in `HttpClient`, not in the crawler or a pass

**Decision.** Cookie attach, absorb and the drop-retry sit in `HttpClient`.
**Alternatives.** A wrapper client; each pass asks the Authenticator.
**Why.** Every pass (crawler, injection, envelope, upload, CSRF, probe, OSV lookups to the
target) already goes through `HttpClient`; 15+ call sites would otherwise each learn about
sessions, and a missed one would silently scan logged out. **Trade-off.** `HttpClient` grows
by about 60 lines and one more mode; the no-session path is byte-identical and covered by the
existing tests.

### ADR-2 — `httpx.Cookies` as the jar, not a hand-rolled one

**Decision.** `SessionJar` wraps `httpx.Cookies` (stdlib `http.cookiejar` underneath).
**Alternative.** A dict of name→value built from `Set-Cookie`.
**Why.** Domain, Path, Secure and expiry rules are exactly the part that is easy to get
subtly wrong (and the fixture's `__Host-` cookie would be wrongly sent over http). **Trade-off.**
`cookiejar`'s domain matching is stricter on dotless hosts (`localhost`); the fixture target is
`demo.test`, and the unit tests pin the `localhost` / IP cases so a regression shows.

### ADR-3 — A `ContextVar` marks the handshake

**Decision.** `handshake()` sets a `ContextVar`; `request()` and the absorb step read it.
**Alternatives.** A `handshake=True` argument on `request`; an instance flag.
**Why.** The re-login runs while other tasks are mid-request; an instance flag would put
their responses into handshake mode, an argument would have to be threaded through the
redirect loop and every `get` wrapper. A `ContextVar` is inherited by exactly the task that
called `handshake()`. **Trade-off.** Implicit state; contained to one module and tested with
two concurrent tasks.

### ADR-4 — Single-flight re-login by generation number

**Decision.** `recover(seen)` takes a lock and compares `seen` with `generation`.
**Alternative.** A bare lock plus a "re-logging" flag.
**Why.** Ten concurrent requests that all got a `401` must produce **one** login (the
lockout counter, RF-09) and ten retries; the generation tells the late ones they are already
covered. **Trade-off.** One integer; trivial to test deterministically with an event.

### ADR-5 — Verification order: markers, then `check_url`, then a heuristic

**Decision.** As RF-06. **Alternative.** Only the heuristic. **Why.** "302 after POST" is
what a rejected login does on many apps; the heuristic (no password input and a new cookie)
is right for the common case but is last, and its "neither" outcome is *inconclusive*, not a
guess. **Trade-off.** An app that sets a cookie on a failed login *and* shows no form (JSON
error page) reads as success; `logged_out_marker` / `check_url` exist for it.

### ADR-6 — A login redirect is a suspicion until proven, and learned once

**Decision.** A redirect to a login URL is a drop signal unless that requested URL already
redirected to login right after a successful (re)login — recorded in `known_login_redirects`
when the retry still lands on the login page, and never signalled again.
**Alternative.** Treat every login redirect as a drop (re-login loops on an app that bounces
unauthorised users to the login page); never use redirects (misses the most common expiry).
**Why.** Bounded by the cap either way; this wastes at most one re-login per such URL.
**Trade-off.** One re-login is spent before the URL is learned; `check_url` avoids even that.

### ADR-7 — A `LoginFailedError` stops the scan; the rest continues with a warning

**Decision.** RF-06 and open question 3 as approved. **Why.** A scan the user thinks is
authenticated but is not is worse than no scan; an *unconfirmed* login or a lost session has
already produced a partial result worth keeping.

### ADR-8 — The password is outside `ScanConfig`

**Decision.** `Credentials` is a separate argument. **Alternative.** A `SecretStr` field.
**Why.** `ScanConfig` is dumped, merged (`with_overrides` does `model_dump`) and round-tripped;
even a masked secret in that object is one `.get_secret_value()` away from a log line. A
dataclass that never joins the config cannot be serialised by accident. **Trade-off.** The
Orchestrator takes one more argument.

### ADR-9 — Scrub once at the end, over the serialised result

**Decision.** `scrub_result`. **Alternative.** Redact where evidence is built (as
`disclosure/redaction.py` does for its own catalogue). **Why.** Evidence is built in dozens
of checks; a single pass cannot be forgotten by a new one. **Trade-off.** A JSON round trip of
the result (milliseconds) and the short-secret blind spot (documented).

### ADR-10 — Login requests bypass `robots.txt` and the crawl budget

**Decision.** The Authenticator talks to `HttpClient` directly: no `robots.txt`, no
`max_pages` count, but the rate limiter and scope guard apply. **Why.** The user named the
URL; `robots.txt` governs crawlers, and the login is not a crawl. **Trade-off.** None
significant; the request count appears in `HttpStats`.

## Fixture app

The existing `/login` (a tokenless form used by the CSRF and auth-form tests) and the
"any non-empty `session` cookie" gate stay. Beside them, in **both** profiles:

| Route | Behaviour |
|---|---|
| `GET /signin` | form with `email`, `password`, hidden `csrf`; sets a pre-login cookie `pre=<token>` |
| `POST /signin` | `csrf` must equal `pre`; wrong password → `200` + the form + "Invalid credentials"; right → sets `session=<opaque>` and `302 /signin/done` |
| `GET /signin/done` | sets `welcome=1`, `302 /account` (so the session cookie is set on a hop that is not the last) |
| `/account`, `/account/settings` | the existing gate (any non-empty `session`), now also reached by the real login — so the full integration scan can swap its static cookie for the login |
| `GET /portal/ping` | `200` while the session lives; **expires after `session_ttl` authenticated requests** (then `302 /signin` for HTML, `401` JSON for `/portal/api`) |
| `GET /blocked` | `403` WAF-style page, session untouched |
| `GET /sso` | `302` to `https://idp.webvigil.invalid/authorize` |

State on `app.state`: `login_log` (every attempt, ok or not, in order), `sessions`, and a
**lockout counter** (the hardened profile refuses logins after 3 failures, answering `429`).
`make_app(profile, *, session_ttl=None)` — `None` means never expires. The hardened profile
enforces the CSRF token strictly and sets `HttpOnly; SameSite=Lax` (it cannot set `Secure`:
the fixture target is `http://demo.test/` and a `Secure` cookie must not be sent there, which
is exactly what `SessionJar` guarantees, tested separately in a unit test).

## Request budget

A login costs 2 + (redirect hops) requests (`GET` page, `POST`, each hop) plus one for
`check_url`. `1 + max_relogins` logins at most (default 4): about 20 requests worst case, all
through the rate limiter. No change to `request_budget` or the per-point cap.

## Impact on existing code

- `HttpClient`: one new mode; every existing `HttpClient` test must pass unchanged.
- Three `bool(auth...)` sites now use the config helpers; behaviour identical without a login.
- `ScanMetadata` gains one optional field; the JSON report gains `metadata.login`.
  `tests/unit/test_reporters.py` is the only test that pins the metadata shape.
- `crawler/forms.py`: a pure extraction.
- No change to `web/`, `openapi.json`, the DB or the API.

## Risks

| Risk | Mitigation |
|---|---|
| An app locks the account after N failures and the login is wrong | one attempt, ever; a failed login stops the scan before the crawl (RF-06); docs say so |
| Re-login loop on a flapping session | `max_relogins` cap; failed attempts count; ADR-6 |
| A payload draws a redirect to the login page | `check_url` confirmation; ADR-6; `403` is not a signal |
| The jar sends a cookie the browser would not (or omits one it would) | `httpx.Cookies`; unit tests for Secure/Path/expiry/host-only |
| A target reflects the password / session id into a finding | `scrub_result` in four spellings; short-secret blind spot documented |
| Login form variants the heuristic cannot read (JS, multi-step) | non-goals; overrides; a clear failure that lists what was found |
| `ContextVar` leaks handshake mode into a task | tested with two concurrent tasks; set/reset in `try/finally` |
| `cookiejar` rejects cookies on odd hosts | ADR-2 tests for `localhost` and IPs |

## Test strategy

Follows [`specs/README.md`, "Testes de uma spec"](../README.md#testes-de-uma-spec): logic in
unit, integration attached to a shared scan, budget about 1.0 test line per source line.

**Unit** (`tests/unit/`)

- `test_session_jar.py` — handshake absorbs every hop; live mode accepts rotation only;
  Secure on http, Path, Domain/host-only, expiry/`Max-Age=0` removal; non-target host gets
  nothing; `values` collects every value. Table-driven.
- `test_http_session.py` — `HttpClient` with a `MockTransport`: no session = identical request
  bytes; attach merges static + jar (login wins a name clash); drop → one re-login → one retry;
  the retry's verdict is returned as is; `403`/`5xx` never re-login; **single flight** (N
  concurrent `401`s → one login); the cap and `lost`; `check_url` confirmation; ADR-6
  learning; two concurrent tasks and the `ContextVar`.
- `test_auth_login.py` — form picking (one, none, several, `form_index`), field picking and
  overrides, body with hidden fields and extras, multipart, scope/scheme gates, SSO redirect,
  the verification order including the *inconclusive* outcome, the single `POST`, the error
  messages carry no secret. Table-driven over small HTML pages.
- `test_auth_scrub.py` — four spellings, short secrets, nesting in evidence/warnings/metadata,
  fingerprint unchanged.
- `test_config.py` (existing tables get rows): `[auth.login]` defaults and bad values, the
  `password` key, a bad regex, `max_relogins` range.
- `test_cli.py` (existing table gets rows): the flags merge deep into the file's login,
  password from env / prompt / usage error, exit 4 on a failed login, the summary line.
- `test_check_metadata.py`: unchanged — no new check.

**Integration** (`tests/integration/test_scan_fixture_app.py`, shared scans)

- The `_full` scan's static `session` cookie becomes the login (`[auth.login]` +
  `credentials`), the bearer header stays. Existing assertions about the authenticated area
  must still pass; new ones: one `login_log` entry and no second, no secret in any report
  format (extends `test_secrets_never_appear_in_any_report`), `metadata.login.relogins == 0`.
- **One** new scan configuration, Active, with `session_ttl` small: it exercises expiry →
  re-login → continued crawl, and asserts `relogins >= 1` and exactly `1 + relogins` entries
  in `login_log`. Justified because TTL changes the app and would perturb the shared scans.
- A Passive scan with a login configured: warning, no `/signin` request in the log.
- The wrong-password and lockout cases are unit tests (`MockTransport`), not scans.

**Safety invariants**, each in a test: Passive sends no login; one `POST` per login; a wrong
password is never retried; credentials never reach another host; password and session value
in no report/log/metadata; the lockout counter equals the logins made.

## Deviations from the approved requirements

1. **RF-12 paths.** The requirement says `/login` becomes the stateful login. The existing
   `/login` is a tokenless form that the CSRF/auth-form tests and the crawler-safety tests
   depend on, and open question 5 settled that the old routes stay; so the real login is
   `/signin` (+ `/signin/done`, `/portal/*`, `/blocked`, `/sso`), and `/account*` accept both.
2. **RF-08(b).** "From a URL that did not redirect there before" is implemented as ADR-6
   (confirm with `check_url` when configured; otherwise learn a URL after one wasted
   re-login), which is bounded and testable.
3. **RF-11 metadata.** The requirement says "the scan metadata records the same facts"; the
   design adds `metadata.login` (`relogins`, `session_lost`). The username is *not* recorded
   (the CLI summary takes it from its own config).
4. **RF-13 integration.** "Replaces the static session cookie of the full scan" is adopted;
   the one extra scan configuration the requirement allowed *is* needed (expiry), and is the
   only one.
5. **Short secrets.** Secrets under 4 characters are not scrubbed (RF-11 is silent); documented.
6. **Login before `--openapi`.** The requirements do not order the two; the login runs first
   so an OpenAPI document served behind it can be fetched.

7. **Scrubbing is field by field, not over the serialised JSON (ADR-9 amended).** A password
   such as `high` or `passive` would have rewritten a severity or a mode in a text replace over
   the whole document. `scrub_result` rewrites only the free-text fields: finding title,
   description, remediation, evidence content and the location's url / param / header / cookie,
   technology `source_url`, check-error message and traceback, and the warnings. Structural
   fields, ids and the stored fingerprint are never touched.
8. **The fixture drops `/portal/*`, `/blocked` and `/sso`.** The session store lives in the
   gate of the existing `/account*` pages (`_session_ok`): an issued session counts its
   authenticated requests and dies after `session_ttl`, while any other non-empty cookie stays
   "logged in" as before. That makes the expiry scan work on pages the crawler already fetches,
   with no new linked pages for the passive checks to read. The `403` block page, the SSO redirect
   and the wrong-password / lockout cases are covered where they are cheap: the unit tests' own
   sites (`test_http_session.py`, `test_auth_login.py`) and `test_fixture_signin.py`.
9. **`LoginSummary` also carries `confirmed`.** The summary line must not say "logged in" for a
   login nothing could confirm; the field defaults to `True`.
10. **The heuristic's three outcomes.** The login form still on the final page fails the login;
    no form and a new or changed cookie confirms it; no form and no new cookie is
    *inconclusive* (an app that reuses the pre-login session id looks exactly like that). The
    requirements' "no new cookie" failure message therefore applies to the form-still-there
    case only.
11. **`Session.recover(seen, url)`** takes the requested URL (the `check_url` veto learns it),
    `HttpClient.quiet()` exists beside `handshake()` (the confirmation must use the live jar
    without drop detection), and the login body is sent as `content=urlencode(pairs)` with an
    explicit `Content-Type` — `httpx` refuses `data=` with a list of pairs on an async client,
    the same reason the CSRF pass does it.
12. **Test seams.** `cli.app._interactive()` (CliRunner has no terminal) and
    `tests.support.HandlerTransport` (an in-process transport that rebuilds the answer over a byte
    stream, because `httpx` records `elapsed` only on a closed stream).

13. **The landing page is the default confirmation reference.** The first full integration scan
    showed a `401` page unrelated to the session costing a real login (the fixture has one). The
    confirmation of RF-08 / ADR-6 therefore asks `check_url` **or**, without one, the page the last
    login ended on, and the "known bouncer" rule now covers the `401` signal as well as the login
    redirect. With no reference at all the suspicion stands.

## Open questions

None blocking. For the tasks phase: whether `Credentials` should also expose a
`from_environment()` helper for embedders (proposed: yes, 5 lines).
