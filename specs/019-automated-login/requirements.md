---
feature: Automated login — find the login form, submit credentials, capture the session, re-authenticate when it drops (Active Mode, opt-in)
status: done
date: 2026-10-07
related:
  - 007-auth-flows/requirements.md
  - 013-auth-and-api-surface/requirements.md
  - 017-csrf-confirmation/requirements.md
  - 018-post-form-crawl/requirements.md
origin: conception
---

# 019 — Automated login

## Context and problem

Issue #52. Authenticated scanning today takes a session you already have: `--cookie
"name=value"` (spec 007) or `--header "Authorization: Bearer …"` (spec 013). The scanner
attaches it to every request to the target host and does nothing else. Two things follow
([`docs/authenticated-scanning.md`](../../docs/authenticated-scanning.md), "What is
deferred"):

- **The session expires mid-scan.** A long Active scan outlives a short-lived session; from
  that request on every response is the login page, and every check that needs the logged-in
  area silently reads the wrong thing. Nothing says so.
- **Nothing is stateful.** `HttpClient` clears every cookie the target sets on every request
  (`self._active_client.cookies.clear()`, spec 007) so a scan is deterministic and
  authentication stays config-driven. The scanner cannot log in, rotate a session, or notice
  that it was logged out.

**What exists, and what does not.**

- The crawler already **finds** login forms: `is_auth_form` and `is_login_url`
  (`webvigil.crawler.safety`) recognise them in order to **skip** them (017, 018: a login form
  is never submitted by a crawl pass).
- `form_body` (`webvigil.crawler.forms`) already builds a body from a form with its hidden
  fields, which is exactly what a login form with a CSRF token needs.
- `HttpClient` has a scope guard, a rate limiter and a manual in-scope redirect loop; none of
  it keeps cookies between requests.
- There is **no** notion of a session in the engine: no jar, no "logged in" verdict, no
  re-login.

This is the prerequisite of issue #53 (session fixation, logout invalidation, weak session
ids), which needs to log in on its own, more than once, and compare sessions.

### Where it sits

```
 before the crawl                 during the scan
 ┌─────────────────────┐          ┌──────────────────────────────────────────┐
 │ Authenticator.login │  jar     │ HttpClient: attaches the session jar to  │
 │  GET login page     │ ───────▶ │ target-host requests; on a "session      │
 │  submit credentials │          │ dropped" signal asks the Authenticator   │
 │  follow redirects   │          │ to re-login (once, serialised) and       │
 │  verify "logged in" │ ◀─────── │ retries the request once                 │
 └─────────────────────┘ re-login └──────────────────────────────────────────┘
```

Credentials go to one place (the login form's action, in scope), and the session value never
leaves the process.

## Goals

- An **opt-in automated login**, off by default, usable only in Active Mode (`--mode active
  --authorized-by` **and** a configured login), that logs in once before the crawl with a
  username and a password the user supplies.
- **Form detection with overrides**: the login form is found from the page the user points at
  (the form with a password input), its hidden fields (CSRF-on-login tokens included) are
  carried, and every guess can be overridden in config.
- **A real session**: the cookies the target sets during the login handshake (the pre-login
  cookie, every hop of the redirect chain, the final one) become the scan's session, attached
  to target-host requests only.
- **An honest verdict**: the login is *verified* — success is something observed, not assumed
  from a `200` — and a failure stops the scan with a clear message instead of producing an
  unauthenticated report that looks authenticated.
- **Re-authentication**: when the session drops mid-scan, one serialised re-login and one
  retry of the request that noticed, bounded by a cap, never a loop.
- **No guessing, ever**: one attempt per login, never a retry with other credentials.
- **Secrets stay secret**: the password never reaches a config file, a report, a log, a
  warning or the metadata, and neither does a session value.
- **Fixture-app coverage** for both profiles, deterministic and offline: a login with a CSRF
  token and a redirect chain, a session that expires after N requests, a wrong-password
  path, a lockout counter.
- **Docs** corrected: the "Automated login" bullet leaves "What is deferred".

## Non-goals

- **CAPTCHA, MFA / TOTP, SSO and delegated login** (OAuth, OIDC, SAML, "log in with …"). A
  login that redirects to another host fails with a clear error (RF-05). Whoever needs those
  keeps pasting a cookie.
- **Login forms built by JavaScript**, and **multi-page logins** (username on one page,
  password on the next): no headless browser (since spec 001).
- **JSON / token logins** (`POST /api/login` returning a bearer token). Different mechanic
  (a response body to parse, a token to place in a header); open question 4.
- **Password guessing, credential stuffing, account enumeration, brute force.** One
  attempt, the user's own credentials. A "login brute-force" check stays out of the roadmap.
- **Registration, password reset, "remember me" handling, account creation.**
- **Session-security checks** (fixation, logout invalidation, weak ids). That is issue #53,
  a spec of its own that builds on this one.
- **Web API / dashboard changes.** Engine and CLI only, as in 006–018. Storing a password in
  the Web UI's database is a decision with its own risks and is not made here.
- **A general cookie jar.** An unauthenticated scan stays as stateless as spec 007 made it;
  only a configured login turns the jar on.

## Personas

| Persona | Needs from 019 |
|---|---|
| **Security-conscious developer** | Point WebVigil at a staging app with a test account and get the logged-in area scanned, without copying a browser cookie that dies in 30 minutes. |
| **Pentester / consultant** | A long Active scan that survives session expiry and says when it could not, so "no findings behind the login" means tested, not blind. |
| **CI pipeline author** | Credentials from the environment (never the repo), a deterministic login, and a non-zero exit when the login fails, so the pipeline does not go green on a scan that never authenticated. |
| **Check author / contributor** | A `Session` the engine exposes (jar, re-login), the building block issue #53 needs. |
| **Application owner worried about lockout** | A promise that WebVigil makes exactly one login attempt and never varies the credentials. |

## Functional requirements

### Gate and configuration

#### RF-01 — Opt-in, Active Mode only

- **Given** `[auth.login]` configured (CLI `--login-url`) and `--mode active --authorized-by`
  **When** the scan starts
  **Then** the login of RF-04 runs before the crawl.
- **Given** a Passive scan, or an Active scan with no login configured
  **Then** no login request is sent and the scan is byte-for-byte what it is today.
- **Given** a login configured outside Active Mode
  **Then** a scan warning says it requires `--mode active` and nothing is sent — the
  behaviour of every opt-in used in the wrong mode since 008. (Open question 1.)
- **Given** a static `--cookie` / `--header` **and** a login
  **Then** both apply; a cookie the login sets overrides a static one of the same name.

#### RF-02 — Where the credentials come from

- **Given** the CLI
  **Then** `--login-url`, `--username` and the *name* of an environment variable that holds
  the password (default `WEBVIGIL_LOGIN_PASSWORD`, `--password-env` to change it) are the
  inputs. There is **no** `--password VALUE` flag: it would land in shell history and the
  process list.
- **Given** an interactive terminal and no password in the environment
  **Then** the CLI prompts for it without echo; non-interactive and no password is a usage
  error.
- **Given** `[auth.login]` in the config file
  **Then** it may hold `url`, `username`, `password_env` and the optional overrides of RF-03
  — **never** the password itself; a `password` key is a configuration error that says why.
- **Given** the password
  **Then** it is read once, held in memory only, and never copied into `ScanConfig`'s
  serialised form, the scan metadata, a report, a log line or a warning.

#### RF-03 — Overrides

- **Given** the form detection of RF-04 picks the wrong form or field
  **Then** the user can set `username_field`, `password_field` (input names), `form_index`
  (nth form on the login page, 0-based) and `extra_fields` (fixed `name=value` pairs, e.g. a
  tenant or a "remember me" box).
- **Given** the success check of RF-06 cannot be inferred
  **Then** `logged_in_marker` / `logged_out_marker` (a regular expression over the response
  body) and `check_url` (an in-scope URL that answers differently when logged out) refine it.
- **Given** an override that does not match the page (a field name the form lacks)
  **Then** the login fails with a message that names the override, not a silent default.

### Logging in

#### RF-04 — The handshake

- **Given** an in-scope `login_url`
  **When** the login runs
  **Then** it (1) `GET`s the login page, absorbing any cookie the page sets; (2) finds the
  login form — the form with a password input, or the one the overrides name; (3) builds the
  body from the form's own fields (hidden fields, CSRF tokens, defaults) with the username
  and the password in their fields, and the overrides applied; (4) submits it to the form's
  `action` with `Origin` / `Referer` of the target, the form's own `enctype` (urlencoded or
  multipart without a file); (5) follows the redirect chain in scope.
- **Given** the whole handshake
  **Then** every `Set-Cookie` of every hop (the `GET`, the `POST`, each redirect) is applied
  to a temporary jar and sent on the next hop, as a browser would; the resulting jar becomes
  the session (RF-07).
- **Given** a login page with no form carrying a password input, or with several and no
  `form_index`
  **Then** the login fails and the message lists what was found (RF-06).
- **Given** the login `POST`
  **Then** it is sent **once** — no retry on a `5xx`, on a timeout or on a "wrong password"
  answer. A failed attempt is a failed login.

#### RF-05 — Scope and credentials never travel

- **Given** a `login_url` or a form `action` out of scope
  **Then** the login fails before anything is sent to it.
- **Given** a redirect during the handshake that leaves the scope (an SSO provider)
  **Then** the chain is not followed, the login fails with "login redirects to <host>:
  delegated login is not supported", and the credentials have only ever gone to the in-scope
  form action.
- **Given** a login form served over `http` while the target is `https`, or a form whose
  action downgrades the scheme
  **Then** the login fails: the password is never sent in clear.

#### RF-06 — Verifying, and failing loudly

- **Given** the handshake finished
  **Then** the login is **verified** by this order of evidence, the first that applies
  deciding: (a) `logged_out_marker` present → failed; `logged_in_marker` present →
  success; (b) a `check_url` fetched with the new session no longer looks logged out;
  (c) the heuristic: the final page has no password input, **and** the target set at least
  one cookie during the handshake that was not there before.
- **Given** a failed login
  **Then** the scan stops before the crawl with a message that says what was observed (final
  URL, status, "the login form is still there", "no new cookie") — never the password or a
  cookie value — and the CLI exits with the operational code (4), so a pipeline goes red.
- **Given** an inconclusive verdict (no marker, no `check_url`, the heuristic neither clearly
  succeeds nor fails)
  **Then** the scan continues with a warning that says the login could not be confirmed. The
  alternative — stopping — is open question 3.
- **Given** a wrong-password answer
  **Then** it is never retried, with the same or any other credential.

### The session

#### RF-07 — The session jar

- **Given** a successful login
  **Then** the session is the cookie jar of the handshake, held by the `HttpClient` and
  attached (as a `Cookie` header) to requests whose host is the target host and to no other,
  with the same discipline as the static cookie of spec 007.
- **Given** a response during the scan that rotates a session cookie the jar already holds
  (`Set-Cookie` with the same name)
  **Then** the jar takes the new value; any other cookie the target sets is still dropped, so
  the stateless contract of 007 holds for everything but the session.
- **Given** no login configured
  **Then** the `HttpClient` behaves exactly as today (cookies cleared on every request).
- **Given** a cookie with `Secure` on an `http` target, `Path`, `Domain`, or an expiry in the
  past
  **Then** the jar honours the attributes it needs to avoid sending a cookie the browser
  would not (secure-only, path prefix, expired = removed); it does not model anything else.

#### RF-08 — Detecting a dropped session

- **Given** a request made with the session
  **Then** it signals "the session dropped" when (a) the status is `401`; or (b) it is
  redirected to the login URL (`is_login_url`, or the configured `login_url`) from a URL that
  did not redirect there before; or (c) `logged_out_marker` matches the body.
- **Given** a `403`, a `5xx`, or a WAF-looking block page
  **Then** it is **not** a dropped session: an injection payload that draws a `403` must not
  trigger a re-login.
- **Given** the signal on a request that is itself part of the login handshake
  **Then** it is ignored (no recursion).

#### RF-09 — Re-authentication

- **Given** the signal of RF-08
  **When** the login of RF-04 is repeated
  **Then** it is **serialised** — concurrent requests that all noticed the drop wait for one
  re-login — and each request that noticed is **retried once** with the new session.
- **Given** a retry that signals the drop again
  **Then** its response is returned as it is; there is no second retry.
- **Given** `max_relogins` (default 3, in `[auth.login]`)
  **When** the cap is reached
  **Then** no further re-login is attempted, a scan warning says the session was lost for
  the rest of the scan, and the scan **continues** with the last jar (open question 3).
- **Given** a re-login that fails
  **Then** it counts against the cap, is reported in the warnings, and is not retried.
- **Given** a re-login
  **Then** it uses the same credentials, the same form and the same single-attempt rule as
  RF-04; a lockout counter on the target (RF-12) goes up by one per login, never faster.

### Effect on the rest of the scan

#### RF-10 — Login and logout stay out of the crawl

- **Given** the crawl and the 017 / 018 passes
  **Then** they still skip login, logout and password forms (`is_auth_form`, `is_logout`);
  the session is the *only* thing that logs in, and it does so through the Authenticator.
- **Given** a logged-in scan
  **Then** the crawler reaches the authenticated pages with the session jar like it does
  with a static cookie today; nothing in the crawl changes.

#### RF-11 — Secrets in output

- **Given** the password and every session cookie value (the first one and each rotation)
  **Then** each is registered as a secret for the scan and scrubbed from evidence, warnings,
  log lines and the report if a target reflects it (a page that echoes the session id, an
  error that quotes the form body).
- **Given** the scan summary
  **Then** it says `auth: logged in (N re-logins)` or `auth: session lost after N re-logins`
  — the username may appear, the password, a cookie name's value and the login URL's query
  string never do — and the scan metadata records the same facts, no more.
- **Given** the reporters
  **Then** they are unchanged (no new field in JSON / SARIF / HTML / Markdown beyond the
  metadata facts above).

### Fixture app and tests

#### RF-12 — Vulnerable and hardened endpoints

- **Given** the fixture app, both profiles
  **Then** `/login` becomes a real, stateful login: a username and password check against a
  fixed test account, a **CSRF token** in a hidden field tied to a pre-login cookie, a
  **redirect chain** (`POST /login` → `/login/done` → `/account`), a **session cookie** set
  on a hop that is not the last, and a **wrong-password** answer (`200` with the form and an
  error).
- **Given** the fixture
  **Then** a **session that expires** after a configurable number of authenticated requests
  (the next one is redirected to `/login`), a **`403` WAF-style** route, a **lockout
  counter** (failed and successful attempts counted per app), and an **SSO-style redirect**
  to another host.
- **Given** the existing routes that read "any non-empty `session` cookie is logged in"
  **Then** they keep working for `--cookie` scans: the stateful login is an addition, not a
  rewrite.

#### RF-13 — Tests, within the suite's budget

Follows [`specs/README.md`, "Testes de uma spec"](../README.md#testes-de-uma-spec).

- **Unit** (the bulk): form detection and overrides, body building with hidden fields, the
  redirect-chain cookie handling, the verification order (marker, `check_url`, heuristic),
  the drop signal (`401`, redirect to login, marker; not `403`), single-flight re-login,
  the cap, the jar rules (secure, path, expiry, rotation, host-only), scrubbing, the config
  rules (no `password` key, env var, missing password).
- **Integration**: attach to a shared scan. The login replaces the static session cookie of
  the full scan (`_full`) if the findings are equivalent; if not, at most **one** new shared
  scan configuration, justified in the design. Assertions: logged in, authenticated area
  reached, one login attempt on the lockout counter, no secret in any report.
- **Safety invariants**, each in a test: a Passive scan sends no login; exactly one login
  `POST` per login; a wrong password is never retried; credentials never go to another host;
  the password and the session value are in no report, log or metadata.
- Budget: about 1.0 test line per source line, the suite near its 10-minute mark.

### Reporting and docs

#### RF-14 — Docs

- `docs/authenticated-scanning.md`: a "Automated login" section (flags, config, the
  handshake, the verdict, re-login, what it will never do) and the bullet leaves "What is
  deferred"; the credentials advice (environment, never the repo).
- `README.md`, `CLAUDE.md` (architecture paragraph and state line), `specs/README.md`
  roadmap, `docs/stack.md` only if a dependency appears (none expected).
- The CLI help for `--login-url`, `--username`, `--password-env` says it makes a real login
  request and uses the account given.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.http` / `webvigil.core` (a `Session` and an `Authenticator`) and
the config / orchestrator / CLI wiring; `httpx` and `selectolax` already do the work; no new
runtime dependency. The engine imports nothing from `webvigil.cli` / `webvigil.api` / `web/`;
`import-linter` unchanged.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green. No `web` gate work.

**RNF-03 — Safe by default**
No login is attempted unless a login is configured **and** the scan is Active. One attempt
per login, no guessing, no retry with other credentials. The CLI help, the docs and the
summary say that a real login is made and which account it is.

**RNF-04 — Bounded work**
At most `1 + max_relogins` logins per scan (default 4), each of at most the handshake's
requests (a redirect chain is capped by the existing redirect limit); no unbounded loop on a
flapping session.

**RNF-05 — Determinism**
Same target, same credentials → same findings and fingerprints: session values differ
between runs and appear in no output; the order of the handshake is fixed.

**RNF-06 — Scope guard intact**
Every login request goes through the `HttpClient`, its scope guard and its rate limiter; no
new host is ever contacted, and the credentials only reach the in-scope form action.

**RNF-07 — Secrets**
The password never leaves the process except to the login form's action; neither it nor any
session value is written to a file, a log, a warning, a report or the metadata, and a
target that reflects one has it scrubbed.

**RNF-08 — Python support**
No syntax or API newer than the project's Python floor.

## Resolved decisions

1. **Active Mode only.** A login is a `POST` that creates a session (and may touch a lockout
   counter). The Passive contract is "sends no `POST`, safe to point at production"; the
   exception for "it is only a login" is the first crack in it (but see open question 1).
2. **No `--password VALUE` flag.** Shell history and the process list leak it. An environment
   variable name, or a prompt, are the only inputs.
3. **One attempt, never a variation.** Account lockout is a real harm, and a scanner that
   tries a second password has crossed from "scan" into "brute force".
4. **Verify, do not assume.** A `302` after a login `POST` is also what a failed login
   returns on half the apps. Evidence first (marker, `check_url`), heuristic last, and a
   failure stops the scan.
5. **`403` is not a dropped session.** An injection payload that draws a block page would
   otherwise trigger a re-login per payload.
6. **The jar is not a general jar.** Only a configured login turns it on, and only session
   cookies are kept after the handshake: the determinism argument of spec 007 stays.
7. **Engine and CLI only.** The Web API would have to store a password; that is a security
   decision of its own.

## Open questions

All five were answered on 2026-10-07 by approving the proposals as written:

1. **Active Mode only** (not Passive). RF-01 stands.
2. **Password input:** environment variable name plus an interactive no-echo prompt. No
   `--password-stdin`.
3. **Inconclusive login and a lost session continue with a warning** (not stop). A *failed*
   login still stops the scan (RF-06).
4. **JSON / token logins are out of scope** (a possible spec 021).
5. **The old "any non-empty cookie" fixture routes stay**; the real login is added beside them
   (RF-12 — but see the design's deviation 1 on the paths).
