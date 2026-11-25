---
feature: Secret values — one type for every credential and session value, which cannot be printed, logged or serialized by accident
status: done
date: 2026-11-24
related:
  - 007-auth-flows/requirements.md
  - 013-auth-and-api-surface/requirements.md
  - 019-automated-login/design.md
  - 020-session-security/design.md
  - 002-web-api/design.md
origin: conception
---

# 024 — Secret values — design

## Overview of the approach

A new engine module, `core/secrets.py`, defines `Secret`: an immutable, final class that wraps one `str` and
knows its kind (`cookie`, `header`, `password`, `session`, `signing key`) and, for a cookie or a header, its
name. Every way of turning it into text gives a marker. Pickling refuses, and `json.dumps` fails because the
class is not JSON-serializable. The only way to get the value is `reveal()`. A pydantic hook lets a model
declare a secret field. The field validates a plain `str` (with the field's length limits), dumps the object
itself in Python mode, dumps the marker in JSON mode, and appears in OpenAPI as a write-only password string.

Every credential the scanner and the Web API hold is converted to `Secret` where it enters: the CLI options,
the configuration validators, the login prompt, the session jar, the API bodies and the signing secret's
loader. It is revealed only where it is sent or checked. A test walks the source's syntax tree and compares
every `reveal()` call with a declared inventory. A second test walks the models and fails on a credential
field typed `str`. The scrub list comes from `collect_secrets`, a walk that gathers every `Secret` under the
configuration and the login credentials, plus the session's. The kind replaces the hand-built `given` and
`issued` lists.

URLs with userinfo are refused by one predicate, `has_userinfo`, used by `Target.parse` and by the
validators of the URL settings. The Web API answers every `422` without the `input`, so no value goes back.
The targets already stored carry no userinfo, because the Web API has always stored the normalized form
(deviation 17).

### What was checked (2026-11-24, pydantic 2.14.3, Python 3.14, Windows)

A prototype of the type and its pydantic hook confirmed the contract the design relies on. `repr` and `str` of
a model holding secrets show only the marker, and so do logging with `%s`/`%r` and a traceback whose
exception carries a secret in its arguments. `model_dump()` returns the `Secret` object, and validating it
again keeps the value. `model_dump_json()` writes `"[redacted]"`. `model_json_schema()` gives
`{"type": "string", "format": "password", "writeOnly": true}` with the length limits. A wrap validator yields
one error per field (`String should have at most 12 characters`), where a union of "is a `Secret`" and "is a
`str`" yielded two. `json.dumps` raises `Object of type Secret is not JSON serializable`. `pickle.dumps`
raises from `__reduce_ex__`, and `copy.deepcopy` keeps the value through `__deepcopy__`.

## Module layout

```
src/webvigil/core/secrets.py (new)   Secret, SecretKind, secret_field(), collect_secrets(), REDACTED
src/webvigil/core/urls.py            has_userinfo()
src/webvigil/core/target.py          Target.parse refuses userinfo
src/webvigil/core/config.py          AuthSection cookies/headers as list[Secret]; URL settings refuse userinfo;
                                     `web` keeps no values; secret_values and as_header removed
src/webvigil/core/orchestrator.py    scrub list from collect_secrets; Session no longer gets the password
src/webvigil/auth/login.py           Credentials.password: Secret; CookieTransition maps to Secret
src/webvigil/auth/scrub.py           scrub_result(result, secrets: Iterable[Secret]); REDACTED from core.secrets
src/webvigil/http/client.py          cookie header and [auth] headers kept as Secret, revealed per request
src/webvigil/http/session.py         jar values and pending items as Secret; names-only repr
src/webvigil/checks/session/*        values as Secret; ids.py reveals for the analysis
src/webvigil/cli/app.py              the password prompt wraps at once
src/webvigil/api/config.py           WebConfig.session_secret: Secret | None
src/webvigil/api/security.py         token, hashing and verification take Secret
src/webvigil/api/schemas.py          password fields as secret fields
src/webvigil/api/app.py              422 handler without input/ctx/url; app.state.session_secret: Secret
src/webvigil/api/cli.py              reset-password wraps the prompt
tests/unit/test_core_secrets.py (new)       the type's contract table, collect_secrets
tests/unit/test_secret_inventory.py (new)   reveal inventory + credential-field gate
web/openapi.json, web/src/lib/api-types.ts  regenerated (password fields gain format/writeOnly)
```

## Data model

```python
class SecretKind(StrEnum):
    COOKIE = "cookie"          # an [auth] cookie value (the user's)
    HEADER = "header"          # an [auth] header value (the user's)
    PASSWORD = "password"      # the login password, an API password field
    SESSION = "session"        # a value the target issued (jar, login record, session checks)
    SIGNING_KEY = "signing key"  # the Web API's session_secret

@final
class Secret:
    __slots__ = ("_value", "_kind", "_name")
    def __init__(self, value: str, *, kind: SecretKind, name: str | None = None) -> None: ...
    def reveal(self) -> str: ...
    kind: SecretKind            # read-only property
    name: str | None            # read-only property; a cookie or header name, never secret
    given: bool                 # read-only property; kind is not SESSION (what the user gave)
```

| Operation | Result |
|---|---|
| `str`, `format` (any spec), f-string, `%s` | `[redacted]` |
| `repr`, `%r` | `Secret('[redacted]', kind='cookie', name='sid')`: the name goes through `repr`, so a control character in a name the target chose is escaped |
| `len`, `bool` | those of the value |
| `==`, `hash` | between two `Secret`s, by value (`hmac.compare_digest` over the UTF-8 bytes, `surrogatepass`), whatever their kinds; against anything else, `NotImplemented`, so `secret == "x"` is `False` both ways; `hash` of a tagged tuple with the value |
| attribute assignment, deletion, subclassing | `AttributeError` / `TypeError` |
| `pickle`, `copyreg` | `TypeError("a Secret cannot be pickled")` from `__reduce_ex__` |
| `copy.copy`, `copy.deepcopy` | the same object (immutable) |
| `json.dumps` | `TypeError` from the standard encoder |
| iteration, indexing, `in` | `TypeError` (none of the methods exist) |

`REDACTED = "[redacted]"` moves from `auth/scrub.py` to `core/secrets.py` (and `auth.scrub` re-exports it),
so the report's marker and the type's marker are one constant.

`secret_field(kind, *, min_length=None, max_length=None)` returns `Annotated[Secret, _SecretSchema(...)]`:

- **Validation.** A wrap validator passes a `Secret` through unchanged. Anything else goes through
  `str_schema(min_length, max_length)` and is wrapped with the field's kind. The length error is pydantic's own,
  one per field.
- **Serialization.** In Python mode it returns the object; in JSON mode, `REDACTED`.
- **JSON schema.** `{"type": "string", "format": "password", "writeOnly": true}` plus the limits.

The cookie and header entries need their name, which the field-level hook does not know. So
`AuthSection`'s `mode="before"` validators parse `"name=value"` and `"Name: Value"` into
`Secret(value, kind=…, name=…)` themselves, and leave a `Secret` they receive as it is. The checks and the
position-only messages stay what they are today.

## Components

### `Secret` and `secret_field` (`core/secrets.py`)

These are the table above. The module imports only the standard library and `pydantic_core`, so the engine
boundary holds, and the Web API imports it from `webvigil.core.secrets`.

### `collect_secrets` (`core/secrets.py`)

`collect_secrets(*roots: object) -> frozenset[Secret]` walks:

- each pydantic model's field values (`type(model).model_fields`);
- each dataclass's fields;
- the values of a `Mapping`;
- the items of a `list`, `tuple`, `set` or `frozenset`.

It yields every `Secret` it meets. It stops at any other type, so a `str`, an `httpx2` object or a target
`Page` is never entered. A depth cap of 16 is a guard: the configuration is about 4 levels deep. The
orchestrator calls `collect_secrets(self._config, self._credentials) | session.secrets`. A secret field added
anywhere under `ScanConfig` is collected with no other change (RF-07).

### Scan credentials (`core/config.py`, `cli/app.py`, `auth/login.py`)

- **`AuthSection`.**
  - `cookies: list[Secret]` and `headers: list[Secret]`, parsed as described under the data model.
  - `header_pairs` returns `tuple[tuple[str, Secret], ...]`.
  - `as_header` and `secret_values` go. The HTTP client builds the cookie header, and `collect_secrets`
    replaces `secret_values`.
  - `configured` and `has_session` keep their meaning.
- **URL settings.** `[auth.login]` `url`, `check_url` and `logout_url`, `[scan] openapi` and
  `[deps] osv_base_url` get a validator that raises `ValueError("a credential in a URL is not used: …")` when
  `has_userinfo` is true. The location comes from pydantic, and `describe_validation_error` drops the input, so
  the message names the setting only. A relative path or a file path has no authority and passes.
- **`ScanConfig.web`.** A `mode="before"` validator replaces any table with `{}`. The key stays accepted, so a
  shared `webvigil.toml` still loads, and none of its values stay (RF-06).
- **`Credentials`.** `password: Secret`. `__post_init__` wraps a `str` it is given with
  `kind=PASSWORD`, so `Credentials("user", "pw")` keeps working in tests and in Python callers.
  `from_environment` and the CLI prompt build the `Secret` at once.
- **The login body.** `Authenticator._build_body` puts `self._credentials.password.reveal()` into the form
  pairs. This is the inventoried call; the body itself is the request.

### Session values (`http/session.py`, `auth/login.py`, `checks/session/*`)

- **`SessionJar._remember`.** It stores each text form of a value (the readable form and the Latin-1 form) as
  `Secret(form, kind=SESSION, name=cookie.name)`. `values` is `frozenset[Secret]`, and `pending_items()`
  returns `frozenset[tuple[str, Secret]]`. `SessionJar.__repr__` and `Session.__repr__` show the host and
  the cookie names only.
- **The library's storage.** The live and pending `httpx2.Cookies` still hold plain values, because the
  standard cookie rules run on them. `pairs_for` reads them to build the `Cookie` header inside the HTTP layer
  (ADR-6).
- **`Session`.** It loses its `secrets=` argument and `given_secrets`. The password reaches the scrub through
  `collect_secrets(credentials)`, and `Session.secrets` becomes the jar's values.
- **`CookieTransition`.** `pre` and `post` map names to `Secret`. The fixation check compares them with `==`,
  so it needs no reveal.
- **`session_cookies(headers)`** (`checks/session/cookies.py`) returns `(name, Secret)` pairs. `is_jwt`,
  `judge_value` and `judge_samples` take `Secret`, and `ids.py` reveals once per call to analyse it. The
  findings keep carrying names, lengths and rule codes (RF-05).

### HTTP client (`http/client.py`)

- **The cookie header.** `HttpClient.__init__` keeps `_cookie_header: Secret | None`. It joins the cookies
  in the session jar's text form through one inventoried reveal in a small `_static_cookie_header` helper.
- **Per request.** `_send` reveals it once and reveals each `[auth]` header value when it builds that
  request's headers, the second inventoried site.
- **Hop filter.** `_hop_headers` still filters by name only.
- **Wire bytes.** They are the same as today (RF-10).

### Scrub (`auth/scrub.py`)

`scrub_result(result, secrets: Iterable[Secret])` splits by kind:

- **What the user gave** (`given`) is always scrubbed. A `HEADER` secret also contributes its credential
  without the scheme, which is today's `Bearer <token>` rule, moved here from `secret_values`.
- **What the target issued** (`SESSION`) is scrubbed only when `looks_like_session_value`.
- **Unchanged.** The spellings, `MIN_SECRET_LENGTH`, the warnings and the field-by-field walk.
- **The reveal.** `_spellings` is the one inventoried reveal of the module.

### Web API (`api/*`)

- **Configuration.** `WebConfig.session_secret: Secret | None`, as `secret_field(SIGNING_KEY)` with the
  32-byte check moved into the validator on the wrapped value's length. The environment override passes
  through the same validation.
- **The signing secret.** `resolve_session_secret` returns `Secret`: the pinned one, or the stored
  `Setting.value` wrapped, or a new `secrets.token_urlsafe(48)`, written to the database before it is wrapped.
  `app.state.session_secret` is a `Secret`. The `Setting` row keeps the plain value, because the database is
  where it is stored (non-goal: encrypting the database).
- **Tokens and passwords.** `create_token` and `decode_token` take `Secret` and reveal it for `jwt.encode` /
  `jwt.decode`. `hash_password` and `verify_password` take `Secret` and reveal it for Argon2. These four are
  the inventoried sites. `dummy_password_hash` wraps its throwaway value.
- **The API bodies.** `SetupIn.password`, `LoginIn.password`, `PasswordChangeIn.current_password` and
  `new_password` are `secret_field(PASSWORD, …)` with today's limits.
- **`reset-password`.** It wraps the prompt and checks the length with `len()`.
- **The `422` handler.** `app.exception_handler(RequestValidationError)` answers
  `{"detail": [{"type", "loc", "msg"}]}` for every error, without `input`, `ctx` and `url` (ADR-8). The
  dashboard reads only `loc` and `msg` (`web/src/lib/api.ts`).
- **`ScanCreate`.** Its target refusal comes from `Target.parse` (RF-09), whose message never repeats the
  input, so the `422` carries neither the password nor the target.
- **Stored targets.** `scan.target` is `Target.parse(...).entry_url`, which `normalize_url` builds from the
  host and the port, without the userinfo, in every version of the Web API. No stored row carries a
  credential, and no migration runs (deviation 17, which withdraws ADR-9).

### Userinfo (`core/urls.py`, `core/target.py`)

`has_userinfo(url) -> bool` is true when the URL has a scheme and an authority (`urlsplit(url).netloc`) that
contains `@`. That covers `user@`, `user:pass@`, `:pass@` and a bare `@`. An `@` in the path, the query or
the fragment, and a percent-encoded `%40`, are not userinfo.

`Target.parse` raises `InvalidTargetError` before it reads the host, with: "the target URL carries a
credential (`user:password@`), which is not used; send it as a header, for example `--header "Authorization:
Basic …"`". The CLI maps `InvalidTargetError` to exit `4` already.

## Interfaces

```python
# src/webvigil/core/secrets.py
REDACTED: Final = "[redacted]"
class SecretKind(StrEnum): ...
@final
class Secret:
    def __init__(self, value: str, *, kind: SecretKind, name: str | None = None) -> None: ...
    def reveal(self) -> str: ...
    @property
    def kind(self) -> SecretKind: ...
    @property
    def name(self) -> str | None: ...
    @property
    def given(self) -> bool: ...
def secret_field(kind: SecretKind, *, min_length: int | None = None, max_length: int | None = None) -> Any: ...
def collect_secrets(*roots: object) -> frozenset[Secret]: ...

# src/webvigil/core/urls.py
def has_userinfo(url: str) -> bool: ...

# src/webvigil/auth/scrub.py
def scrub_result(result: ScanResult, secrets: Iterable[Secret]) -> ScanResult: ...
```

The `422` body, for every endpoint:

```json
{"detail": [{"type": "string_too_long", "loc": ["body", "password"], "msg": "String should have at most 256 characters"}]}
```

What users see does not change: options, configuration keys, exit codes and the report schema stay the same.
The text of messages may change (`docs/stability.md`), and two messages are new: the userinfo refusal for a
target and for a URL setting.

## ADRs

### ADR-1 — A project-owned `Secret`, not pydantic's `SecretStr`

**Decision.** `core/secrets.py` defines its own final class, with a kind, an optional name and the operations
of the table.

**Alternatives.**

- (a) `pydantic.SecretStr` everywhere.
- (b) `SecretStr` in the models and a wrapper elsewhere.
- (c) Keep `str` and add `repr=False` and more scrub lists.

**Why.** The kind is what the scrub needs to tell what the user gave from what the target issued. Today that
split lives in two hand-built lists, and the kind replaces them (RF-07). The name keeps the cookie and header
names next to their values without a second structure. The class also needs to refuse pickling, to compare
in constant time, and to live in dataclasses and in the session jar, where `SecretStr` brings no benefit.

- (a) and (b) lose the kind and allow pickling; (b) also gives two types to review.
- (c) is the per-call-site discipline this spec replaces.

**Trade-off.** The pydantic hook is ours to maintain: validation, serialization and JSON schema. The contract
test pins each behaviour, so a pydantic upgrade that changes one fails there first.

### ADR-2 — A cookie or header is one `Secret` that carries its name

**Decision.** `AuthSection.cookies` and `headers` are `list[Secret]`. The name is the secret's `name` and is
plain text; the value is the secret.

**Alternatives.**

- (a) A `NamedSecret(name, value)` model per entry.
- (b) The whole `"name=value"` entry as one secret.

**Why.** (a) adds a type that every caller unpacks to reach the same two things. (b) hides the name, which
the HTTP client needs to filter a hop and a message needs to say which cookie. It would also scrub the
`name=` prefix with the value.

**Trade-off.** The Python API shape of `cookies` and `headers` changes: a `Secret`, not a `"name=value"`
string. Inputs are still strings in TOML, on the command line and in Python. It is listed under **Changed**
(RNF-02).

### ADR-3 — The reveal inventory is a syntax-tree test with qualified names

**Decision.** `tests/unit/test_secret_inventory.py` parses every module under `src/webvigil` and collects each
call whose function is an attribute named `reveal`, as `module:qualname` of the enclosing function. It
compares that set with a frozen `ALLOWED_REVEALS` table, which also says why each site needs the value. An
unlisted call fails, and so does a listed site with no call (a stale entry).

**Alternatives.**

- (a) A runtime audit hook that records reveals during the suite.
- (b) Code review only.

**Why.** The syntax tree sees every call, including the ones no test runs. (a) sees only what ran. (b) is the
discipline this spec replaces. Calls are matched by attribute name, so an alias (`r = s.reveal; r()`) would
escape. The test also refuses any `getattr(…, "reveal")` and any reference to `_value` outside
`core/secrets.py`.

**Trade-off.** A legitimate new sink needs a line in the table, with a reason, in the same pull request. That
line is the point: a reviewer sees it.

### ADR-4 — The credential-field gate reads field names, with a declared list and exemptions

**Decision.** The gate imports the engine and Web API modules (the suite runs with every extra) and lists
every pydantic model and dataclass defined there.

- **The rule.** A field fails when its name has a credential word (`password`, `secret`, `token`, `cookie`,
  `cookies`, `credential`, `apikey`/`api_key`) and its annotation has `str` but no `Secret`.
- **Exempt endings.** A name ending in `env`, `field`, `fields`, `hash`, `name`, `names`, `marker`, `url`,
  `secure`, `ttl` or `hours` describes a credential rather than holding one.
- **Declared list.** It adds the fields whose names do not say so (`AuthSection.headers`,
  `CookieTransition.pre`/`post`).
- **Exemption table.** Each other match is listed with its reason: `Location.cookie` and `LocationOut.cookie`
  (a cookie name in a finding) and `StoredMarker.token` (the scanner's own marker, not a credential).
- **Positive controls.** A model defined in the test with `api_token: str` is flagged, and one with
  `api_token: Secret` is not.

**Alternatives.**

- (a) Only a declared list.
- (b) A marker that each model opts into.

**Why.** A declared list and an opt-in marker both miss exactly the new field nobody thought of. Names catch
it.

**Trade-off.** A name that matches without holding a credential needs an exemption line. A dry run over the
models on 2026-11-24 matched 13 fields:

- 7 are the credentials this spec converts;
- 2 are covered by the exempt endings (`User.password_hash`, `CsrfHit.token_fields`);
- 1 holds no string (`HarTally.token_path`, a count);
- 3 need the table.

### ADR-5 — JSON mode writes the marker; the standard JSON encoder and `pickle` fail

**Decision.** A pydantic dump in JSON mode writes `"[redacted]"`. `json.dumps` and `pickle.dumps` raise.

**Alternatives.**

- (a) Raise in pydantic's JSON mode too.
- (b) Write the marker from `json.dumps` through a `default=` hook.

**Why.** A JSON dump of a configuration is what a debug line, a support request or a future endpoint would
do, and a marker keeps that harmless without crashing. The standard encoder cannot be taught a default
globally, and failing is the safe outcome for an unplanned serialization. `pickle` would write the value to
bytes that may reach a disk or another process, so it refuses.

**Trade-off.** A JSON round trip of a model loses its secrets: the reload holds the marker as the value.
Nothing in the project reloads a configuration from JSON, and the contract test pins the behaviour.

### ADR-6 — The session jar's library storage is the boundary

**Decision.** The values inside `httpx2.Cookies` stay plain. Everything the jar exposes is a `Secret`
(`values`, `pending_items`), except `pairs_for`, which builds the `Cookie` header inside the HTTP layer. The
jar has a names-only `repr`.

**Alternatives.**

- (a) Re-implement the cookie rules on `Secret` values.
- (b) Keep the jar's values as plain strings.

**Why.** (a) replaces the standard Domain, Path, `Secure` and expiry rules with our own, which spec 019 chose
not to do. (b) leaves the session values of the login record and the scrub as strings.

**Trade-off.** A library object holds the values, as the request being sent does. Neither is printed, logged
or serialized by the project, and the inventory test lists `pairs_for` as a reading site with its reason.

### ADR-7 — Userinfo is any `@` in the authority, refused before parsing the host

**Decision.** `has_userinfo` checks for `@` in `urlsplit(url).netloc`, and `Target.parse` refuses before it
reads `hostname` or `port`.

**Alternatives.** (a) `parts.username is not None or parts.password is not None`. (b) Strip the userinfo and
warn.

**Why.** (a) misses `https://@host/` and depends on how the parser splits a malformed authority. Refusing
first also keeps a password out of the host and port error paths. (b) was rejected in resolved decision 1.

**Trade-off.** A host name cannot contain `@`, so nothing valid is refused.

### ADR-8 — Every `422` drops `input`, `ctx` and `url`

**Decision.** One handler for `RequestValidationError` keeps `type`, `loc` and `msg` of every error, on
every endpoint.

**Alternatives.** (a) Drop `input` only for secret fields. (b) Replace the messages with a generic one.

**Why.** The value of a body field goes back to the sender, and to any proxy or log in between, so dropping it
everywhere is simpler than telling secret fields apart. It also covers the target as typed. The dashboard uses
`loc` and `msg` only. (b) would lose the field-level messages the forms show.

**Trade-off.** A client that read `input` back from a `422` loses it. The Web API is provisional
(`docs/stability.md`).

### ADR-9 — Stored targets are rewritten; the downgrade does not restore them

> **Withdrawn** in Stage 4: no stored target carries userinfo, so there is nothing to rewrite (deviation 17).

**Decision.** Migration `0003` strips the userinfo from `scan.target` in place, and its `downgrade` is a
no-op.

**Alternatives.** (a) Leave old rows and hide the userinfo when reading. (b) Delete the affected scans.

**Why.** (a) keeps the password in the database file and in its backups. (b) loses scan history for no
reason.

**Trade-off.** A downgrade keeps the stripped targets. The migration docstring says so, and the CHANGELOG
mentions it.

### ADR-10 — One minor release, no milestone

**Decision.** The change goes in a minor release, together with what is already in `[Unreleased]`. The
roadmap row's delivery is `—`.

**Alternatives.** (a) A major release for the Python API shape. (b) A patch release.

**Why.** The command line, configuration, exit codes, report schema and fingerprints do not change. The Python
API and the Web API are provisional, and a security fix may change behaviour in any release
(`docs/stability.md`). The spec delivers no product feature, so it gets no `v0.N` milestone, like `015` and
`023`.

**Trade-off.** A Python caller that read `auth.cookies` as strings has to call `.name` and `.reveal()`. The
CHANGELOG says so under **Changed**.

## Impact on existing code

- **Engine signatures.** `scrub_result`, `Session.__init__`, `SessionJar.values` and `pending_items`,
  `CookieTransition`, `session_cookies`, `is_jwt`, `judge_value` and `judge_samples` change. The tests of
  those units change with them.
- **`AuthSection`.** `as_header` and `secret_values` disappear, and their tests move to `collect_secrets` and
  `scrub_result`.
- **Web API.** `create_token`, `decode_token`, `hash_password`, `verify_password` and
  `resolve_session_secret` take or return `Secret`. Route code passes the body fields through unchanged.
- **OpenAPI.** `web/openapi.json` changes for the four password fields (`format`, `writeOnly`).
  `api-types.ts` is regenerated, and the TypeScript types stay `string`.
- **The `422` body** loses `input` and `ctx` (ADR-8).
- **Not affected.** The JSON report, SARIF, HTML and Markdown, fingerprints, check ids, configuration keys and
  CLI options.
- **Documentation.**
  - [`docs/authenticated-scanning.md`](../../docs/authenticated-scanning.md): the userinfo refusal, the
    username and `extra_fields` are not scrubbed, and command-line values are visible in the shell history
    (resolved decisions 1, 3 and 5).
  - [`docs/writing-checks.md`](../../docs/writing-checks.md): a check that handles a credential receives a
    `Secret`, and a new reveal needs an inventory line.
  - [`docs/web-api.md`](../../docs/web-api.md): the `422` body.
  - `CHANGELOG.md` `[Unreleased]`: the userinfo refusal under **Security**; the Python API and `422` shapes
    under **Changed**.

## Test strategy

The `specs/README.md` rules apply: logic in unit tests, integration attached to the shared scan, a budget of
about one test line per `src/` line.

**`tests/unit/test_core_secrets.py`** holds one parametrized table, one row per way out. Each row asserts that
the value does not appear. Its positive control runs the same way out on the revealed `str` and shows that the
value would appear there.

- **Text.** `str`, `repr`, `format` with `""`/`"s"`/`">40"`, f-string, `%s`/`%r`, `pprint`.
- **Holders.** A `dict`, a `list`, a dataclass and a pydantic model printed.
- **Logging.** At `DEBUG`, through `caplog`, with the secret as an argument and inside `extra`.
- **Exceptions.** An exception with the secret in its arguments, through `traceback.format_exception`.
- **Terminal.** Rich `Console.print` of the secret and of a model, into a recording console.
- **Bytes.**
  - `json.dumps` raises `TypeError` and `pickle.dumps` raises `TypeError`; the positive control is that
    the same holder without the secret serializes.
  - `model_dump_json` writes `"[redacted]"`.
  - A `model_dump` round trip keeps the value, and `copy`/`deepcopy` keep it.

Then:

- **Equality.** Equal, unequal and different kinds; against a `str` both ways; `hash` agreement.
- **Immutability.** Assignment and subclassing refused.
- **Length.** `len`/`bool`.
- **`secret_field`.** Length errors, one per field and without the input; the JSON schema.
- **`collect_secrets`.** A nested model, a dataclass, mappings and sequences. A test model with one more
  secret field is collected with no other change. Depth cap.

**`tests/unit/test_secret_inventory.py`** holds the reveal inventory (ADR-3) and the credential-field gate
(ADR-4), each with its positive control: a throwaway module source with an unlisted `reveal()` is flagged,
and a throwaway model with `api_token: str` is flagged.

**Existing unit tests, adapted.**

- `test_config.py`: cookie and header parsing into named secrets, position-only errors, URL settings with
  userinfo refused per setting, and a file path or relative URL accepted.
- `test_auth_scrub.py`: the kind split, the header scheme rule, and short values with their warning.
- `test_http_session.py`: jar values as `Secret`, names-only `repr`.
- `test_http_client.py` and `test_http_redirect_credentials.py`: the `Cookie` and `[auth]` header bytes sent,
  unchanged (RF-10).
- `test_auth_login.py`: the login body.

**Userinfo.** A table in the `core/urls.py` and target tests:

- refused: `user@`, `user:pass@`, `:pass@`, `@`, with a non-ASCII password;
- accepted, as positive controls: an `@` in the path, the query and the fragment, and `%40` in the path.

`test_cli.py` runs a scan with `https://user:pw@host/`. It exits `4`, and neither `user` nor `pw` appears in
stdout or stderr.

**End-to-end canary, engine.**

- **Where.** The shared `_full` scan already logs in and sends a bearer header. The `scan` fixture gains a
  `DEBUG` log capture stored with the cached result, and `_full` gains one static cookie with a canary value.
  That cookie needs no new scan. The fixture app ignores unknown cookies; this is checked when the scan's
  expected findings stay equal.
- **What it proves.** No spelling of the cookie, the bearer token, the password or the session id the fixture
  issued appears in the captured logs, the warnings, or the JSON, SARIF, HTML and Markdown renderings.
  Spellings means raw, `quote`, `quote_plus`, JSON-escaped and HTML-escaped, each built in the test, not by
  `auth/scrub.py`.
- **Positive control.** The fixture app records, in a new `app.state.auth_log`, the `Authorization` header
  and the canary cookie of each request it receives. The record holds each value, and the login's session
  was confirmed, which shows the password was accepted.
- **The CLI.** One `test_cli.py` test with the same canary through `httpx_mock` checks stdout, stderr and the
  report files.

**End-to-end canary, Web API.**

- **Setup.** Through the test client, with logging captured at `DEBUG`: a pinned canary `session_secret`,
  then setup, login, a password change and a too-long password.
- **What it proves.** No canary in the logs or in any response body. The `422` keeps `loc` and `msg`, which
  is its positive control.
- **Refused target.** `POST /api/scans` with userinfo answers `422`, without the target, and stores no row.
- **Stored form.** `normalize_url` drops the userinfo of a URL that has one, so the stored target would not
  carry it even without the refusal (deviation 17).

**Sabotage, each seen red once.**

- In `core/secrets.py`: make `__str__` return the value, drop `__reduce_ex__`, and make `__eq__` accept a
  `str`.
- Make the JSON serializer return the value.
- Remove a site from `ALLOWED_REVEALS`, and retype `LoginIn.password` to `str`.
- Drop the `HEADER` scheme rule in the scrub, and make `collect_secrets` skip dataclasses.
- Remove the userinfo check from `Target.parse` and from one URL validator.
- Let the `422` handler keep `input`.
- Make `normalize_url` keep the authority as given.

**Mutation in batch** over `core/secrets.py`, `has_userinfo`, the URL validators, the `Target.parse` refusal,
the scrub's kind split, the `422` handler and `resolve_session_secret`. Every changed function has a killed mutant,
every surviving mutant is triaged, and the score goes in the pull request (RNF-06).

**No network.** Every test stays offline: the fixture app in process, `httpx_mock`, and the API's test client.

## Deviations

1. **`secret_field` returns the field's metadata (ADR-1, RNF-04).** It returns a `SecretField`, and a model declares
   `Annotated[Secret, secret_field(kind, …)]`. `mypy` refuses a call used as an annotation, so returning the
   `Annotated` itself would not type-check.
2. **Validation is a chain, not a wrap over `str_schema` (RF-01, RF-08).** The first step wraps a string, or passes a
   `Secret` through. The second checks the length with pydantic's own error types and messages, one error per
   field. The error's `input` is then the `Secret`, so neither `errors()` nor the text of a `ValidationError` carries
   the value. A wrap over `str_schema` reports the raw string as the input.
3. **A bare `Secret` annotation validates (ADR-2).** `list[Secret]`, filled by a `mode="before"` validator, needs a
   schema for the type itself. It accepts only a `Secret`, because it has no kind to wrap a string with, and it shares
   the serializer and the JSON schema of `secret_field`.
4. **`__getstate__` refuses too (RF-02).** The default `object.__getstate__` hands out the slots, value included, to
   any caller. `pickle` still fails from `__reduce_ex__`, and the redundant `__reduce__` was left out.
5. **The inventory also refuses an uncalled `.reveal` (ADR-3).** That covers the alias the ADR names as an escape. It
   refuses the strings `"reveal"` and `"_value"` anywhere, and `_value` as an attribute. A local variable named
   `_value` (`auth/login.py`) is a different name and is not refused.
6. **The field gate's keys and checks (ADR-4).** A field is keyed `module:Class.field`, with the module named without
   the `webvigil.` prefix. Besides a pending entry that holds a `Secret`, the gate fails on an exemption that no
   longer matches and on a declared field that is not found. `StoredMarker` is in `checks/injection/models.py`.
7. **A default shows the marker in the JSON schema (RF-06).** A secret field with a default writes
   `"default": "[redacted]"`, because the default is dumped in JSON mode. The Web API's password fields have no
   default.
8. **The scrub collects the credentials the login used (RF-07).** The orchestrator calls
   `collect_secrets(self._config, authenticator.credentials)`, through a read-only `Authenticator.credentials`, not
   `self._credentials`. A password read from the environment is resolved inside the login step, so
   `self._credentials` is `None` for it, and the scrub would miss it. In Stage 1 the authenticator no longer hands
   the password to `Session`; its `secrets=` argument stays, unused, until Stage 2 removes it.
9. **The scrub's reveal is `_texts`, not `_spellings` (RF-07).** `_texts(secret)` returns the plain texts a secret
   stands for: the value, a header's credential without its scheme, and a session value only when it looks like a
   session id. `_spellings` still works on strings. The short-value warning therefore still counts a header's
   credential without its scheme (`Bearer ab` warns about `ab`), as it did.
10. **A cookie keeps its name and value as written around the `=` (ADR-2, RF-10).** The `Cookie` header joined each
    entry as written, stripped only at its ends, so `sid = v` went out with its spaces. Stripping the name and the
    value would change those bytes. The scrub strips the cookie value, as `secret_values` did. A header's name and
    value are stripped, as `header_pairs` did.
11. **The send-side reveal is in `HttpClient._request_with_retry` (RF-04).** That is the function the design calls
    `_send`. The joined static cookie header is a `COOKIE` secret named `Cookie`.
12. **A non-string cookie or header entry gets the position-only message (RF-08).** For example,
    `invalid cookie #2: expected 'name=value'`. Pydantic's item type error is not used, because the `mode="before"`
    validator parses the list itself.
13. **`pairs_for` has its own list, not an `ALLOWED_REVEALS` line (ADR-6, ADR-3).** It calls no `reveal()`: it reads
    the plain values from `httpx2`'s jar. As an inventory line it would fail as stale. `LIBRARY_READS` in the
    inventory test names it with its reason, and a test checks that each entry is a function of the package that
    calls no reveal.
14. **The weak-id facts are read in `ids.py` (RF-05).** The finding's length, alphabet and estimated bits were
    computed in the scanner from the plain value. `id_facts(Secret)` now gives them, an inventoried reveal beside
    `is_jwt`, `judge_value` and `judge_samples`, so the scanner reveals nothing. `alphabet_of` and `estimated_bits` keep taking a `str`;
    they are the analysers behind the public functions.
15. **`has_userinfo` needs an authority, not a scheme (RF-09, ADR-7).** A scheme-relative `//user:pw@host/` has an
    authority, and a setting such as `[auth.login] check_url` could carry one, so it is refused too. When
    `urlsplit` refuses a value (an unclosed IPv6 bracket, a character that normalizes to a delimiter), the
    authority is split the way `urlsplit` splits it before it checks the host, so a malformed host does not hide
    the credential in front of it, and `Target.parse` gives the userinfo message, not a host error.
16. **A schemeless `user:password@host` keeps its refusal (RF-09).** It reads as the scheme `user:`, so
    `Target.parse` refuses it as an unsupported target before it adds `https://`, as it did before this spec; the
    message repeats nothing of it. The userinfo message uses `...` for the ellipsis, as the other CLI messages
    are ASCII.
17. **No migration of stored targets (RF-09, ADR-9 withdrawn).** `scan.target` has been
    `Target.parse(...).entry_url` since the first version of the Web API, and `normalize_url` builds that URL
    from the host and the port, so the userinfo was never stored. `Target.parse` from that version and from
    the commit before Stage 3 both turn `https://user:pw@example.com/a` into `https://example.com/a`, and no
    other column of a scan holds a URL as given (`options` keeps only numbers, flags and check ids). A
    migration would rewrite rows no version wrote, so RF-09 now states that fact, and a test keeps
    `normalize_url` dropping the userinfo.
18. **The signing secret's least length counts characters (RF-06).** It counted UTF-8 bytes, which needs the
    value. `len()` of the `Secret` gives characters without a reveal, so only signing and checking a token
    read it. The message always said characters; a non-ASCII secret of fewer than 32 characters and 32 bytes
    or more is now refused.

## Implementation notes

- **Stage 0.** The RF-10 baseline was taken on `main` at `dc4e23e` (Python 3.15.2): 3224 tests, 97 % line and branch
  coverage in total, the per-file table, and the three JSON reports of the fixture app. They are kept outside the
  repository. The login scan runs in Active Mode, because a login requires it, with the time-delay detectors off. A
  second run of the cookie-and-header scan and of the login scan gave the same check ids, severities and
  fingerprints, so the Stage 5 comparison has no noise floor in those fields.
- **Stage 1.** The bytes sent did not change: the HTTP client's tests of the `Cookie` and `[auth]` headers, and of
  the credentials kept off a redirect, pass as they were. Four `reveal()` sites entered the inventory: the login
  body, the scrub's `_texts`, the joined `Cookie` header and the request builder. The scan configuration, the
  orchestrator and the HTTP client, printed, show the names and no value.
- **Stage 2.** Four `reveal()` sites entered the inventory, all in the session checks: `is_jwt`, `judge_value`,
  `judge_samples` and `id_facts`. The engine canary reads 2341 log records of the full scan, the request lines
  that `httpx2` logs, besides the four report formats and the warnings. Its static cookie changed no finding of
  the full scan.
- **Stage 3.** Only the tests of invalid-target messages used a target with userinfo, to show that the message
  dropped it. They now use a target whose path, query and fragment carry the canary, and the userinfo cases
  expect the refusal. `ScanCreate` validates through `Target.parse`, so `POST /api/scans` already answers `422`
  to such a target and stores nothing; until Stage 4 drops `input` (ADR-8), that `422` repeats the body to the
  client that sent it. Stage 4 adds the migration of stored targets.
- **Stage 4.** Four `reveal()` sites entered the inventory, all in `api/security.py`: `create_token`,
  `decode_token`, `hash_password` and `verify_password`. `PENDING_CONVERSION` is gone, so a credential field
  typed `str` anywhere in the package fails the gate. The regenerated `openapi.json` gives the four password
  fields `format: password` and `writeOnly`; the TypeScript types stay `string`. The OpenAPI schema of a
  validation error still lists `input` and `ctx` as optional, as FastAPI declares them; the body never sends
  them. The stored-target migration was withdrawn (deviation 17).
- **Stage 5.** The three scans of the fixture app, repeated on `main` at `a38a830` (Python 3.15.2), gave the same
  `schema_version` and the same check ids, severities and fingerprints as the Stage 0 baseline: 28 findings
  anonymous, 29 with the `[auth]` cookie and header, 45 with the login. None of the three secret values appears in
  the reports or in the terminal output, as in the baseline. The CI of that commit is green on every job:
  `quality` on Linux and Windows for Python 3.12 to 3.15, `package`, `docker`, `web` and `compose`.
- **Measurements, Stage 0 to Stage 5.** Tests: 3224 collected (3222 passed, 2 skipped) before, 3415 (3413 passed,
  2 skipped) after. Coverage of `src/webvigil`: 10,193 of 10,386 lines and 2,847 of 2,994 branches before, 10,424
  of 10,616 lines and 2,906 of 3,050 branches after, 97 % in both; no file has more missed lines or partial
  branches than in the baseline, and `core/secrets.py` is fully covered. The suite with coverage takes 99 to
  108 s on a Windows workstation. The reveal inventory holds 12 sites. Mutation, per stage: 117 of 118
  killed (1 equivalent), 119 of 120 (1 equivalent), 96 of 115 against the whole unit suite (the 19 survivors sit in
  session analysers that this spec did not change), 28 of 31 (3 equivalent) and 26 of 26.
