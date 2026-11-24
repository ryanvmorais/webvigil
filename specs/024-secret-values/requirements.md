---
feature: Secret values — one type for every credential and session value, which cannot be printed, logged or serialized by accident
status: in progress
date: 2026-11-24
related:
  - 007-auth-flows/requirements.md
  - 013-auth-and-api-surface/requirements.md
  - 019-automated-login/design.md
  - 020-session-security/design.md
  - 002-web-api/design.md
origin: conception
---

# 024 — Secret values

## Context and problem

WebVigil holds credentials in two places. The scanner holds the `[auth]` cookies and headers (`--cookie`,
`--header`), the automated login's password and the session cookies the target issues. The Web API holds the
session signing secret and the passwords sent to setup, login and password change. Every one of these values
is a plain `str` today, and keeping it out of terminals, logs, reports and the database depends on each call
site remembering to.

Every guarantee in place today is local to one call site:

- **One field hides itself.** `Credentials.password` (`auth/login.py`) is `field(repr=False)`. The `[auth]`
  cookies and headers (`core/config.py`), the session jar (`http/session.py`), the cookies a login sees
  (`CookieTransition`), the Web API's `session_secret` (`api/config.py`) and the password fields of the API
  bodies (`api/schemas.py`) are plain strings inside models whose default `repr` and `model_dump` print them.
- **The scrub list is assembled by hand.** `scrub_result` (`auth/scrub.py`) hides what it is given, and the
  orchestrator gives it `AuthSection.secret_values` plus `Session.given_secrets` plus the jar's values. A new
  credential is scrubbed only if someone adds it to one of those lists.
- **Messages avoid values by convention.** A configuration error names the setting and its position
  (`describe_validation_error`), a target error does not repeat the input, a network failure is named by its
  type. Each of these was a separate fix: the error-output advisory of 1.6.0
  ([GHSA-38gf-jvgw-g2pq](https://github.com/ryanvmorais/webvigil/security/advisories/GHSA-38gf-jvgw-g2pq)) and,
  before it, the releases that added `--cookie`, `--header` and the Python-bytes spelling to the scrub one at
  a time.
- **A URL can carry a credential.** A target such as `https://user:password@host/` is accepted. The scanner
  drops the userinfo without a word and scans anonymously. The Web API stores the URL as given and returns it
  in every scan listing.

Every one of these defects was found and fixed one call site at a time. A new credential, a new log line or a
new serialization would need the same care again, and nothing would fail if it were missing.

**This spec gives every credential and session value one type that refuses to become text, confines reading
the value to the few places that send it, derives the scrub list from that type, and refuses a credential
written into a URL.** What a scan sends and what it reports do not change.

### Where it sits

```
src/webvigil/core/secrets.py (new)   the secret type and the walk that collects a scan's secrets
src/webvigil/core/config.py          [auth] cookies and headers hold secrets; URL settings refuse userinfo
src/webvigil/core/target.py          a target with userinfo is refused
src/webvigil/auth/login.py           Credentials.password and CookieTransition hold secrets
src/webvigil/auth/scrub.py           takes the collected secrets instead of hand-built lists
src/webvigil/http/client.py, http/session.py   read a value only where it is sent
src/webvigil/checks/session/*        read a session value only where it is analysed
src/webvigil/cli/app.py              --cookie, --header and the password prompt become secrets at once
src/webvigil/api/*                   session_secret, password fields, the 422 body, stored targets
tests/                               the type's contract, the reveal inventory, the end-to-end canary
```

## Goals

- One project-owned type holds every credential and session value the scanner and the Web API keep in memory.
- Turning that type into text never shows the value: `str`, `repr`, `format`, logging, exception messages and
  tracebacks, the terminal, JSON, pydantic dumps and pickling.
- Reading the value is an explicit call, made only at the places that send or check it, and a test lists
  those places.
- The report is scrubbed of every secret the scan holds, collected from the type, with no list to keep up.
- A credential written into a configured URL is refused, in the CLI and in the Web API.
- A scan of the same target sends the same requests and reports the same findings and fingerprints.

## Non-goals

- **Where the scrubbed result goes.** The terminal, the report formats, the database and the dashboard keep
  receiving the result as they do today; this spec changes what the result is scrubbed of, not the output
  path.
- **Which destinations may receive a credential.** The origin rule (`Target.carries_credentials`) and the
  redirect rules do not change.
- **The scrub thresholds.** A given secret under 4 characters is still not scrubbed (with its warning), and a
  value the target issued is still scrubbed only when it looks like a session id (resolved decision 4).
- **The login's username and `extra_fields`.** Neither is a secret (resolved decision 3).
- **Encrypting the Web API database.** The password hash and the generated signing secret stay in the SQLite
  file, which is created readable by its owner only.
- **Wiping memory.** Python strings cannot be erased; the type controls how a value leaves, not how long it
  lives.
- **Proxy credentials.** The proxy URL in the environment is read by the HTTP library and never held by the
  engine; that does not change.
- **A new flag, configuration key, check or report field**, such as a file or environment variable for
  `--cookie` and `--header`. The command line, the configuration keys and `schema_version` stay as they are.
- **Credentials for Web API scans.** The API accepts no cookie, header or password for a scan, and still
  does not.

## Personas

- **As a developer running an authenticated scan in CI**, I want no cookie, token or password in the job log,
  the report or a traceback, whatever goes wrong during the scan.
- **As a contributor adding a credential option or a log line**, I want the type to keep the value hidden,
  and a test to tell me when I read it somewhere new, so that I do not have to remember every rule.
- **As someone running the Web API**, I want the signing secret and the passwords sent to the API kept out of
  logs, error responses and the scan list.
- **As a user who typed `https://user:password@host/`**, I want to be told the credential is not used, rather
  than get an anonymous scan that looks authenticated.

## Functional requirements

### Secret type

### RF-01 — A secret never becomes text by accident

- **Given** a secret holding a value
  **When** it is passed to `str`, `repr`, `format`, an f-string or `%`
  **Then** the text is a fixed marker that may carry a label (the kind of credential and, for a cookie or a
  header, its name), and never the value or any part of it.
- **Given** a secret inside a container, a dataclass, a pydantic model or an exception's arguments
  **When** that holder is printed, logged, rendered by the terminal or formatted into a traceback
  **Then** the value does not appear.
- **Given** a secret
  **When** its length or truthiness is asked
  **Then** the answer is the value's, so that a check such as "too short to scrub" or "is a cookie set" keeps
  working without reading the value.

### RF-02 — A secret cannot be serialized by accident

- **Given** a secret
  **When** `json.dumps` or `pickle.dumps` is called on it or on a structure that holds it
  **Then** the call fails with an error that names the secret type, and no output is written.
- **Given** a pydantic model with a secret field
  **When** it is dumped in Python mode and validated again (as `ScanConfig.with_overrides` does)
  **Then** the secret survives the round trip intact.
- **Given** the same model
  **When** it is dumped in JSON mode
  **Then** the field holds the marker, never the value.
- **Given** a secret
  **When** it is copied (`copy`, `deepcopy`)
  **Then** the copy holds the same value.

### RF-03 — Reading the value is explicit and inventoried

- **Given** a secret
  **When** code needs the value
  **Then** it calls one named method; there is no attribute, conversion or operator that yields the value.
- **Given** the source of `webvigil`
  **When** a test lists every call of that method
  **Then** each one is in a declared inventory of call sites (building the request headers, the login body,
  analysing a session id, signing and checking a session token, hashing and verifying a password, building the
  scrub list), and a call outside the inventory fails the test.
- **Given** a secret and a plain string with the same text
  **When** they are compared
  **Then** they are not equal, so a value is never compared or looked up as a string by mistake; two secrets
  with the same value are equal and hash alike.

### Where secrets are held

### RF-04 — Scan credentials are secrets from the moment they enter

- **Given** `--cookie`, `--header`, the `[auth]` table of a configuration file, or a `ScanConfig` built in
  Python from strings
  **When** the configuration is validated
  **Then** each cookie value and each header value is held as a secret, while its name stays plain text.
- **Given** an automated login whose password comes from the environment variable or the prompt
  **When** the `Credentials` are built
  **Then** the password is a secret.
- **Given** a configuration with credentials
  **When** the configuration, the orchestrator or the HTTP client is printed or dumped in JSON mode
  **Then** no credential value appears.

### RF-05 — Session values are secrets

- **Given** a cookie the target sets during a login or a session rotation
  **When** it enters the session jar or the login's before-and-after record of cookies
  **Then** its value is held as a secret.
- **Given** the session checks (weak id, fixation, logout)
  **When** they analyse a session value
  **Then** they read it through the inventoried call (RF-03), and their findings keep carrying names, lengths
  and rules only, as they do today.

### RF-06 — Web API secrets are secrets

- **Given** the Web API's `session_secret`, pinned in the configuration file, in `WEBVIGIL_SESSION_SECRET` or
  generated and stored in the database
  **When** the application loads it
  **Then** it is held as a secret, and only signing and checking a session token read it.
- **Given** a setup, login or password-change request, or the `reset-password` command
  **When** its body or its prompt is validated
  **Then** every password field is held as a secret, and only hashing and verifying read it.
- **Given** the `[web]` table in a file that the scanner also loads
  **When** the scanner validates it
  **Then** the scanner accepts the table and keeps none of its values.

### RF-07 — The report is scrubbed of every secret the scan holds

- **Given** a finished scan
  **When** the result is scrubbed
  **Then** the list of values to hide is collected from the secrets the scan holds (configuration, login,
  session), not assembled by hand, with the same split as today: what the user gave is always hidden, what
  the target issued only when it looks like a session id.
- **Given** a contributor who adds a new secret field to the scan's configuration
  **When** a scan uses it and a page echoes it
  **Then** the report hides it, without any other change.

### Errors and inputs

### RF-08 — An error response never echoes a secret

- **Given** a Web API request whose body fails validation (a password that is too long, a target that is
  refused)
  **When** the API answers `422`
  **Then** the response names the field and the reason, and carries neither the value of a secret field nor
  the target as given.
- **Given** a configuration error, an invalid target, a failed login or a failed request
  **When** the CLI or the Web API reports it
  **Then** the message carries no secret value, as today.

### RF-09 — A credential in a URL is refused

- **Given** a target with userinfo (`https://user:password@host/`, or a user name alone)
  **When** `webvigil scan` validates it
  **Then** the scan does not start, the exit code is `4` (invalid target), and the message says that a
  credential in the URL is not used and points to `--header "Authorization: …"`, without repeating the URL.
- **Given** the same target sent to `POST /api/scans`
  **When** the API validates it
  **Then** it answers `422` under RF-08, and nothing is stored.
- **Given** a URL setting with userinfo (`[auth.login]` `url`, `check_url` and `logout_url`, `[scan] openapi`,
  `[deps] osv_base_url`)
  **When** the configuration is validated
  **Then** it is a configuration error (exit `4`) that names the setting, never its value.
- **Given** a Web API database holding scans whose target was stored with userinfo
  **When** it is migrated to this version
  **Then** each such target is stored without its userinfo, and the scan's findings and report are unchanged.

### RF-10 — Same scan, same report

- **Given** the fixture application scanned with the same configuration (anonymous, with `[auth]` cookies and
  headers, and with the automated login), before and after this spec
  **When** the requests the fixture received and the two JSON reports are compared, leaving out timestamps and
  durations
  **Then** the `Cookie`, credential headers and login body sent are byte for byte the same, and findings,
  severities, check ids, fingerprints and `schema_version` are identical.

### RF-11 — Tests

See the test strategy in the design. The suite must cover:

- the type's contract (RF-01 to RF-03) as unit tests, one parametrized table over every way to turn it into
  text or bytes;
- the reveal inventory (RF-03) as a test over the source;
- a gate that walks the scan's configuration models and the Web API's body and configuration models, and fails
  when a field that holds a credential is a plain string;
- an end-to-end canary: an authenticated scan of the fixture application with known values in a cookie, a
  header, the login password and the session the fixture issues, with logging captured at `DEBUG`, in which no
  spelling of any value appears in the logs, the terminal output, any report format or the warnings, with a
  positive control that the fixture received each value;
- the same canary for the Web API: signing secret and passwords absent from logs, `422` bodies and responses;
- the userinfo refusals (RF-09) and the migration of stored targets.

## Non-functional requirements

### RNF-01 — No new dependency

The type is written in the repository on the standard library and pydantic, which the engine already uses.

### RNF-02 — A minor release

The change fits a minor release under [`docs/stability.md`](../../docs/stability.md): commands, options,
configuration keys, check ids, exit codes, the report schema and fingerprints do not change. Two changes are
listed under **Changed** in the CHANGELOG: the provisional Python API holds secrets where it held strings
(`AuthSection` cookies and headers, `Credentials.password`), and a URL with userinfo is refused (a security
fix, which the stability policy allows in any release).

### RNF-03 — The engine boundary

The type lives in the engine and the Web API imports it; the `import-linter` contract keeps passing.

### RNF-04 — The type checker sees a secret

The type is not a subclass of `str`. Under `mypy --strict`, passing a secret where a string is expected is a
type error, so a new sink that would print the value fails before the tests run.

### RNF-05 — Every step leaves `main` working

The work lands in independent pull requests, each with the full CI green: the type and its gates first, then
the scanner, then the Web API.

### RNF-06 — The suite stays fast and offline, and its guards are proven

No test talks to the real network. The whole suite keeps running in under 2 minutes with coverage, and
per-file line and branch coverage of `src/webvigil` does not drop. Every new test is seen failing once. The
type and every changed guard go through mutation testing in batch: every changed function has a killed mutant,
every surviving mutant is triaged, and the score goes in the pull request.

## Resolved decisions

1. **A credential in a URL is refused, not dropped (decision of 2026-11-24).** Dropping it silently gave an
   anonymous scan to a user who meant to authenticate, and storing it put a password into the Web API's scan
   list. Refusing tells the user, and `--header "Authorization: Basic …"` keeps the same credential possible
   under the existing origin rules.
2. **One project-owned type for the scanner and the Web API.** Both hold credentials, and one contract (RF-01
   to RF-03) with one inventory is easier to review than two. The design records why it is not pydantic's
   `SecretStr`.
3. **The login's username and `extra_fields` stay plain text.** The username is shown on purpose in the
   terminal summary (`as user`), and `extra_fields` are fixed form values such as a tenant or a "remember me"
   box. [`docs/authenticated-scanning.md`](../../docs/authenticated-scanning.md) gains a sentence saying that
   neither is scrubbed, so a secret does not belong in either.
4. **The scrub thresholds stay.** A value under 4 characters would shred the report if replaced, and a value
   the target sets is trusted only when it looks like a session id, so a target cannot blank out findings by
   setting a cookie to a common word.
5. **No new flag.** A cookie or header given on the command line stays visible to the shell history and the
   process list; the `[auth]` table of a configuration file keeps them out of both, and
   [`docs/authenticated-scanning.md`](../../docs/authenticated-scanning.md) gains a sentence saying so. A new
   way to pass them is outside this spec.
