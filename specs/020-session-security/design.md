---
feature: Session-security checks — weak session ids, session fixation, logout that does not invalidate the session
status: done
date: 2026-10-07
related:
  - 020-session-security/requirements.md
  - 019-automated-login/design.md
  - 017-csrf-confirmation/design.md
  - 005-info-disclosure/design.md
origin: conception
---

# 020 — Session-security checks — design

## Overview

One new pass, `SessionScanner`, runs **last** (after the CSRF confirmation, spec 017 ADR-6) and
turns three kinds of observation into `SessionHit`s; three thin checks turn the hits into
findings — the 017 shape (`CsrfScanner` → `csrf_hits` → check), not a new mechanism.

```
Orchestrator.run
  ├─ login (019)  ── Authenticator records the cookie TRANSITION: pre-login / post-login values
  ├─ crawl, fingerprint, probe, injection, stored XSS, envelope, upload, CSRF  (unchanged)
  └─ SessionScanner.run()                                     only if a session.* check is selected
       1. judge the session ids the crawl already saw          local, no request          (weak)
       2. sample N fresh anonymous visits                       GET-only, opt-in          (weak)
       3. compare the cookies across the login + 1 confirming GET                          (fixation)
       4. log out, replay the old cookies                       Active, opt-in, ends session (logout)
         → Observations.session_hits → session.id.weak / session.fixation /
                                       session.logout.not-invalidated
```

Three small additions to the HTTP layer make the observations possible without touching how a
normal request behaves:

- `HttpClient.anonymous()` — a context (a `ContextVar`, like `handshake()` / `quiet()` of 019)
  inside which a request carries **only** the headers the caller passes: no static `[auth]`
  cookie or header, no session jar, no drop detection. Samples are anonymous visits, the
  fixation confirmation and the logout replay send an **explicit** `Cookie` header.
- `Authenticator.transition` — the pre/post-login cookie values of the last committed login.
- `Session.closed` — set after the logout test so no re-login is attempted afterwards.

## Module layout

| File | Change |
|---|---|
| `src/webvigil/checks/session/__init__.py` | **new.** Docstring; no re-exports (importing the package must not load the checks twice). |
| `src/webvigil/checks/session/cookies.py` | **new.** `SESSION_NAME_RE`, `is_session_cookie`, `is_jwt`, `session_cookies(headers)` — the one definition of "a session-looking cookie". `checks/csrf/checks.py` imports it instead of its private copy. |
| `src/webvigil/checks/session/ids.py` | **new.** Pure analysers: `judge_value`, `judge_samples`, `estimated_bits`, `ValueRules`. No I/O. |
| `src/webvigil/checks/session/scanner.py` | **new.** `SessionHit`, `SessionScanner` — the four steps above. |
| `src/webvigil/checks/session/checks.py` | **new.** `WeakSessionIdCheck`, `SessionFixationCheck`, `LogoutNotInvalidatedCheck`, registered. |
| `src/webvigil/checks/registry.py` | the three modules are loaded by `load_plugins` like the other check packages. |
| `src/webvigil/core/findings.py` | `Category.SESSION`. |
| `src/webvigil/core/config.py` | `SessionSection` (`sample_ids`, `sample_count`, `test_logout`), `ScanConfig.session`, `LoginSection.logout_url`. |
| `src/webvigil/core/context.py` | `Observations.session_hits`. |
| `src/webvigil/core/orchestrator.py` | `_scan_session`, the last-pass wiring, the warnings; `_log_in` hands back the `Authenticator`. |
| `src/webvigil/auth/login.py` | `CookieTransition`, `Authenticator.transition`, `Authenticator.reference_url`. |
| `src/webvigil/http/session.py` | `Session.closed` / `close()`, `recover` returns `False` when closed. |
| `src/webvigil/http/client.py` | `anonymous()` and the `_ANON` handling in `_request_with_retry` / `request`. |
| `src/webvigil/cli/app.py`, `cli/_render.py` | `--sample-sessions`, `--test-logout`, `--logout-url`; the summary line. |
| `tests/fixtures/app.py` | the session behaviours in both profiles (see "Fixture app"). |

No new runtime dependency (`math`, `collections`, `http.cookies` from the standard library).

## Data model

### Configuration

```toml
[session]
sample_ids = false        # --sample-sessions: N fresh anonymous GETs of the entry URL
sample_count = 10         # 3..20
test_logout = false       # --test-logout: Active only, needs [auth.login]; ends the session

[auth.login]
logout_url = "https://app.example.com/logout"   # optional; else found in the crawl
```

```python
class SessionSection(_Section):
    sample_ids: bool = False
    sample_count: int = Field(default=10, ge=3, le=20)
    test_logout: bool = False
```

`ScanConfig.session: SessionSection`. `LoginSection.logout_url: str | None = None` (validated like
`check_url`: a URL string; scope is checked when it is used).

### Hits and observations

```python
@dataclass(frozen=True, slots=True)
class SessionHit:
    kind: Literal["weak", "fixation", "logout"]
    name: str                            # the cookie's NAME; never its value
    url: str                             # where it was observed / the endpoint tested
    severity: Severity
    confidence: Confidence
    rule: str                            # which rule fired, in words ("numeric only")
    facts: tuple[tuple[str, str], ...]   # evidence label/content pairs, structural only

class Observations:
    ...
    session_hits: tuple[SessionHit, ...] = ()
```

`facts` is the **only** channel from the scanner to the finding's evidence, and it is built from
numbers and words (`("length", "8")`, `("alphabet", "digits")`, `("estimated bits", "26")`,
`("samples", "10")`). A unit test feeds a secret value through every path and asserts it appears in
no hit (RNF-07).

```python
@dataclass(frozen=True, slots=True)
class CookieTransition:
    pre: Mapping[str, str]    # name -> value after the GET of the login page
    post: Mapping[str, str]   # name -> value after the POST chain, before commit
```

Held in memory on the `Authenticator`, never serialised, never logged. The 019 scrub already hides
every value that entered the jar.

## Components

### `cookies.py` — what a session cookie is

```python
SESSION_NAME_RE = re.compile(
    r"session|sess(?:id)?|sid|auth|jwt|(?:^|[_-])token|connect\.sid|phpsessid|jsessionid",
    re.I,
)
def is_session_cookie(name: str) -> bool
def is_jwt(value: str) -> bool            # three base64url segments, the first decoding to JSON
def session_cookies(headers: httpx.Headers) -> list[tuple[str, str]]   # (name, value) of the
                                                                       # session-looking Set-Cookie
```

The pattern is the CSRF check's, widened by the framework names RF-02 lists; the CSRF check
imports it (a behaviour-neutral change: `test_checks_csrf.py` passes untouched). A JWT-shaped
value is filtered by `session_cookies` itself, so no rule downstream can see one.

### `ids.py` — the analysers (pure)

```python
def judge_value(value: str) -> list[Rule]       # RF-03
def judge_samples(values: Sequence[str]) -> list[Rule]   # RF-04
```

`Rule` is `(code, text, severity)`; the table is the contract:

| Code | Fires when | Severity |
|---|---|---|
| `short` | `len(value) < 16` | MEDIUM |
| `low-entropy` | `estimated_bits(value) < 64` | MEDIUM |
| `numeric` | every character is a digit | HIGH |
| `repeating` | one character repeated, or a 1-4 character block repeated over the whole value | HIGH |
| `timestamp` | 10 or 13 digits and a plausible epoch (2001-01-01 .. 2100-01-01) | HIGH |
| `counter` | an integer under 10^9 (a small number is a counter) | HIGH |
| `duplicates` (samples) | two anonymous visits got the same value | HIGH |
| `sequence` (samples) | the values as integers are strictly monotonic with a near-constant step (max step <= 4 x min step) | HIGH |
| `timestamp-series` (samples) | the values parse as epoch times and increase | HIGH |
| `low-variance` (samples) | at least half the positions hold the same character in every sample (length >= 8) | MEDIUM |

`estimated_bits(value)`: the alphabet is the smallest of digits (10), lower hex (16), upper hex
(16), base36 (36), alphanumeric (62), base64url (64), printable ASCII (95) that contains every
character; bits = `len x log2(size)`. It is the *capacity* of the observed format, deliberately
generous (16 lower-hex characters = 64 bits passes; `short` still fires below 16) so that a
finding means "this cannot be good", never "this is a bit less than ideal". The finding's
severity is the maximum over the fired rules; its confidence is `MEDIUM` for a single value
(`"looks weak"`), `HIGH` for a sample-based rule.

### `scanner.py` — `SessionScanner`

```python
class SessionScanner:
    def __init__(self, http, target, config, pages, forms, *, authenticator: Authenticator | None)
    async def run(self) -> list[SessionHit]
    warnings: list[str]
```

`run()` executes only the steps the configuration and the selected checks ask for, in this
order; a step bug is caught per step and downgraded to a warning, so one broken analyser cannot
cost the others.

**1. Seen ids (`weak`).** For each OK page, `session_cookies(page.headers)`; each *name* is judged
once on its first value. Pure CPU; no request. Runs whenever `session.id.weak` is selected.

**2. Samples (`weak`).** Only with `session.sample_ids`. `sample_count` times, sequentially,
`async with http.anonymous(): await http.get(target.entry_url)`; the session cookies of each
response are collected per name. `judge_value` runs on the first sample of each name,
`judge_samples` on the series. A response that sets no session cookie contributes nothing; a name
seen in fewer than 3 samples is judged by `judge_value` only. If no sample ever set one:
`warnings.append("session sampling: the target issued no session cookie to an anonymous visit")`
and no hit. The seen-id and sample judgements of one name merge into **one** hit (the union of
the rules, one `facts` list), so one weak cookie is one finding.

**3. Fixation (`fixation`).** Needs an `Authenticator` whose login committed. The candidates are
`sorted(pre.keys() & post.keys())` whose name `is_session_cookie`, whose values are not JWTs and
are **equal**; at most 3. For each: the reference page is `authenticator.reference_url`
(`check_url`, else the login's landing page). With a reference and a confirmed login:

```python
header = "; ".join(f"{n}={v}" for n, v in jar.pairs_for(ref, handshake=False) if n != name)
async with http.anonymous():
    response = await http.get(ref, headers={"cookie": header} if header else None)
confirmed = session.looks_dropped(response)      # without it, the session is gone: it authenticates
```

`confirmed` -> a hit with `Confidence.HIGH`; not dropped -> no hit (the cookie is not what
authenticates: a tracking id). No reference, or an unconfirmed login -> a hit with `MEDIUM` and the
fact `("verified", "no")`.

**4. Logout (`logout`).** Needs `session.test_logout`, Active, a login and a reference page.

1. Discover the endpoint: `login.logout_url`; else the first in-scope `<a href>` of an OK crawled
   page whose URL `is_logout` matches (a `selectolax` pass over the page text, document order),
   requested with `GET`; else the first `POST` form of `forms` whose action `is_logout` matches,
   submitted with `urlencode(form_body(form, sentinel=...))` and `Content-Type`
   (the 019 / 017 pattern). None -> warning `session logout test skipped: no logout endpoint
   found`, no request.
2. Check the oracle: `async with http.anonymous(): get(ref)` must **look logged out**
   (`session.looks_dropped`); if the page is public to an anonymous visitor the replay cannot tell
   anything -> warning `...reference page is public...`, skip. (One request, and the only guard
   against a false "still valid" on a landing page that never needed a login.)
3. Snapshot `jar.pairs_for(ref, handshake=False)` as a `Cookie` header **before** logging out.
4. Request the logout endpoint once, through the normal client (the session is live). A `5xx` or
   a transport error -> warning, skip.
5. `session.close()`; then `async with http.anonymous(): get(ref, headers={"cookie": snapshot})`.
   `not looks_dropped(response)` and `status < 400` -> a hit (`MEDIUM`, confidence `HIGH`);
   otherwise nothing.

Total network cost of the logout step: 3 requests (oracle, logout, replay), plus 1 per fixation
candidate (cap 3) and `sample_count` samples.

### The checks

| Id | Mode | Severity | CWE | Reads |
|---|---|---|---|---|
| `session.id.weak` | PASSIVE | MEDIUM (rules raise it to HIGH) | 330, 331, 340 | `session_hits` of kind `weak` |
| `session.fixation` | ACTIVE | MEDIUM | 384 | kind `fixation` |
| `session.logout.not-invalidated` | ACTIVE | MEDIUM | 613 | kind `logout` |

`session.id.weak` is PASSIVE because the passive judgement of cookies already seen is local and
the sampling is `GET`-only and opt-in (spec 005 precedent); the other two are ACTIVE because their
precondition (a login) is. Location: `Location(url=hit.url, cookie=hit.name)`; the dedup key is
`"weak"` / `"fixation"` / `"logout"` — never the value or a hash of it, so a fingerprint is the same on
every run. Evidence is `EvidenceItem(label, content)` straight from `hit.facts`; references are
OWASP WSTG-SESS-01 / -03 / -06 and CWE pages.

### `HttpClient.anonymous()`

```python
_ANON: ContextVar[bool]

@asynccontextmanager
async def anonymous(self) -> AsyncIterator[None]:
    token = _ANON.set(True); quiet = _QUIET.set(True)
    try: yield
    finally: reset both
```

In `_request_with_retry`: when `_ANON.get()` is true, `cookie_header` is `""`, the static
`[auth] headers` are not attached, `session` is treated as `None` (no jar pairs, no absorb); the
caller's own `headers` (an explicit `Cookie`) are sent as given. `request()` skips the drop
detection through `_QUIET`, as `quiet()` does. Without the context nothing changes.

### Orchestrator and CLI

```python
async def _scan_session(self, check_types, http, target, pages, forms, authenticator, warnings)
    -> tuple[SessionHit, ...]
```

Selected iff any `session.*` check is in `check_types`. It builds the `SessionScanner`, runs it
last (after `_scan_csrf`), extends `warnings` from `scanner.warnings`, and catches any exception
into `warnings.append(f"session checks failed: {exc}")` like every pass. The gate warnings are
issued where the opt-in is read: `test_logout` outside Active or without `[auth.login]` ->
`"--test-logout requires --mode active and a login - the logout test did not run"`;
`logout_url` without `test_logout` is harmless and silent.

CLI: `--sample-sessions/--no-sample-sessions`, `--test-logout/--no-test-logout`, `--logout-url`
(merged deep into `[auth.login]` like the 019 flags). The summary gains one line, e.g.
`Session checks: 10 ids sampled, fixation checked, logout tested`, assembled from the result's
warnings-free facts the CLI already has (the config switches and whether a hit kind exists).

## Interfaces

| Surface | Change |
|---|---|
| CLI | `--sample-sessions`, `--test-logout`, `--logout-url TEXT` on `scan`. |
| Config | `[session]` table; `[auth.login] logout_url`. |
| Engine | `Orchestrator` unchanged in signature; `ScanContext.observations.session_hits`. |
| Reports | three new check ids and `Category.SESSION` (JSON, SARIF rules, HTML, Markdown pick them up from the registry). |
| Exit codes | unchanged. |
| Web API / UI | unchanged apart from the catalogue listing three more checks. |

## ADRs

### ADR-1 — One pass, three thin checks (the 017 shape)

**Decision.** `SessionScanner` produces hits; checks only format them.
**Alternatives.** Each check does its own requests in `run()`; three passes.
**Why.** The checks run concurrently and after every pass: a check that sends requests breaks the
"last pass" ordering of the logout test and the per-pass error isolation. Three passes would
triplicate the anonymous-client and warning plumbing. **Trade-off.** One module is the home of
three behaviours; each step is a method with its own try/except.

### ADR-2 — `anonymous()` is a context, not a flag on `request()`

**Decision.** A `ContextVar` context beside `handshake()` and `quiet()`.
**Alternative.** `request(..., anonymous=True)` threaded through the redirect loop and every
wrapper.
**Why.** The same reasons as 019 ADR-3, plus the sampling and replay code stays free of
client-internal arguments. **Trade-off.** Implicit state in one module, tested with a concurrent
task.

### ADR-3 — The transition is recorded by the Authenticator, not re-derived

**Decision.** `CookieTransition` is filled during the handshake, from the jar's pending items after
the page `GET` and after the `POST` chain.
**Alternative.** Make a second anonymous `GET` of the login page and a second login.
**Why.** The handshake already holds both snapshots at no cost; a second login is a second attempt
against a lockout counter, which 019 forbids. **Trade-off.** The fixation verdict depends on the
first login's page being representative of "an attacker's pre-login visit" — it is: it is exactly
the anonymous visit a browser makes.

### ADR-4 — Confirm that the unchanged cookie is what authenticates

**Decision.** One `GET` of the reference page without that cookie.
**Alternative.** Report every unchanged session-looking cookie.
**Why.** Many apps keep an unrelated anonymous id (a load-balancer affinity, an analytics id named
`sessionid`) across login while a different cookie authenticates; the unconfirmed report would be
mostly noise. **Trade-off.** One request per candidate (cap 3); an app that authenticates by a
header *and* a cookie reads as "not required" and is missed (documented).

### ADR-5 — The logout test checks the oracle first

**Decision.** An anonymous `GET` of the reference page must look logged out before the logout is
requested.
**Alternative.** Trust the landing page.
**Why.** A landing page that never needed a login makes "the old cookie still works" always true:
a false finding on every such app. **Trade-off.** One more request; the test is skipped (with a
warning) on a public landing page — set `check_url` to a protected page to run it.

### ADR-6 — Value rules measure capacity, not randomness

**Decision.** `estimated_bits` is the alphabet's capacity; the repeating, counter and timestamp
rules catch structure.
**Alternative.** Shannon entropy of the observed string.
**Why.** Shannon entropy of one short string is noisy: a random 16-hex id measures ~56 bits and
would be flagged although it is exactly the OWASP floor. Capacity cannot under-report, so a
finding is never about a good id. **Trade-off.** A long string drawn from a small *effective*
space (a truncated counter, base64 of a number) can pass the capacity test; the structure rules
and the sampling rules are what catch those.

### ADR-7 — The weak-id check is PASSIVE although it can sample

**Decision.** `mode = PASSIVE`; the sampling is a separate opt-in switch.
**Alternative.** ACTIVE.
**Why.** Judging the cookies already fetched sends nothing; sampling is `GET`-only like the probe
(005). Making the check ACTIVE would hide the free, local judgement from every Passive scan.
**Trade-off.** A Passive scan with `--sample-sessions` sends N extra `GET`s without
`--mode active`; the switch's help says so.

### ADR-8 — Evidence is structural, by construction

**Decision.** `SessionHit.facts` is the only evidence channel and takes only numbers and words.
**Alternative.** Redact values in the check after the fact (as `disclosure/redaction.py` does).
**Why.** A leak prevented by construction cannot be forgotten by the next rule someone adds; the
019 scrub remains the second line, not the first. **Trade-off.** A reviewer sees "rule: numeric
only, length 6" and not the value; the cookie's name and URL are enough to find it.

## Fixture app

Both profiles gain the behaviours the checks need; the 019 `/signin` area is extended, not
rewritten, and the legacy any-cookie gate stays.

| | Insecure | Hardened |
|---|---|---|
| anonymous visit | `session=abc123` on the index (as today) and `GET /signin` sets a **counter** session id `session=1001`, `1002`… | the index sets `__Host-session=<32 random-looking hex>` (a fixed long value: deterministic, 128 bits); `GET /signin` sets an anonymous `__Host-session` of the same form |
| login (`POST /signin`) | **keeps** the anonymous id: it becomes the authenticated session (fixation) | issues a **new** id; the anonymous one is not authenticated |
| `GET /logout` | clears the cookie client-side, **keeps the session valid** server-side | deletes the session server-side (the old cookie reaches `/login`) |
| `/account*` | unchanged gate, now also honouring the logout | same |

The index cookie of the hardened profile changes from `abc123` to a long value so the hardened scan
keeps reporting nothing; the insecure `abc123` is what `session.id.weak` finds without any
sampling. `app.state.logout_log` records each logout request for the tests.

## Request budget

| Step | Requests |
|---|---|
| seen ids | 0 |
| samples | `sample_count` (default 10, max 20) |
| fixation | 1 per candidate (cap 3) |
| logout | 3 (oracle, logout, replay) |

No retry. The injection `request_budget` is not touched (these are separate passes).

## Impact on existing code

- `checks/csrf/checks.py`: imports the shared `SESSION_NAME_RE`; behaviour identical.
- `HttpClient`: one more context; with it unused every existing test passes untouched.
- `Session`: `closed`; a re-login after `close()` returns `False`.
- `Authenticator`: records the transition; a failed login records nothing.
- Registry-driven tests: `test_check_metadata.py` gains three rows (47 -> 50 checks);
  `list-checks` prints three more.
- The hardened fixture's index cookie value changes (above).
- No change to `web/`, `openapi.json`, the DB or the API.

## Risks

| Risk | Mitigation |
|---|---|
| A false fixation on an unrelated unchanged cookie | ADR-4: one confirming `GET`; unconfirmed login -> `MEDIUM` and the fact says so |
| A false "logout not invalidated" on a public landing page | ADR-5: the oracle check, then skip with a warning |
| The logout request has side effects beyond ending the session | opt-in, Active, last pass, one request; it only ever ends the session WebVigil created |
| A cookie value leaking into a finding | ADR-8 by construction; a unit test through every path; the 019 scrub as the second line |
| Weak-id false positives (a legit short id) | `MEDIUM`/`looks weak` wording, structural evidence, the rules are public in the docs |
| The sampling hammers a target | `GET`-only, sequential, <= 20, through the rate limiter, no retry |
| A pass bug costs the scan | per-step try/except, downgraded to a warning |
| `anonymous()` leaks into a concurrent task | a `ContextVar`; tested with two tasks (as 019) |

## Test strategy

Follows [`specs/README.md`, "Testes de uma spec"](../README.md#testes-de-uma-spec).

**Unit** (`tests/unit/`)

- `test_session_ids.py` — tables: value -> rules fired (short, low-entropy, numeric, repeating,
  timestamp, counter, and the passes: 32-hex, 22-char base64url, UUID without dashes); the capacity
  estimator across alphabets; sample series -> rules (duplicates, sequence with steps, timestamp
  series, low variance, a random series that fires nothing).
- `test_session_cookies.py` — name pattern table (hits and misses), JWT skipping, extraction from
  several `Set-Cookie` lines, a malformed header.
- `test_session_scanner.py` — with a `HandlerTransport` site: seen-id judgement and one-hit-per-name
  merging; sampling (no cookie sent, sequential, count, none issued -> warning, fewer than 3
  samples); fixation (changed / unchanged / appeared / cleared, confirmed / not required /
  unconfirmed login / no reference, the cap of 3, a JWT skipped); logout (config URL, link, form,
  none, public landing page skipped, 5xx skipped, still valid -> hit, invalidated -> none, the
  snapshot is taken before and the replay is anonymous); **no value anywhere in any hit**.
- `test_session_checks.py` — hit -> finding: location, cookie, dedup key independent of the value,
  severities, evidence labels; the registry rows.
- `test_http_session.py` / `test_auth_login.py` — `anonymous()` (no static cookie, no static
  header, no jar, explicit `Cookie` kept, concurrent task unaffected); the transition (pre/post,
  failed login records nothing, `reference_url`); `Session.close()` stops re-login.
- `test_config.py` / `test_cli.py` / `test_orchestrator.py` rows — the `[session]` table and its
  ranges, `logout_url`, the three flags, the gate warnings, the pass runs last and only when
  selected, a step failure becomes a warning.
- `test_check_metadata.py` — three rows.
- `test_fixture_session.py` — only the guarantees the integration relies on: the insecure login
  keeps the anonymous id, the hardened rotates it; `/logout` invalidates only in the hardened
  profile; counter ids increase.

**Integration** (`tests/integration/test_scan_fixture_app.py`, shared scans)

- The `_full` scans gain `sample_ids` and `test_logout` (and `logout_url` is *not* set, so the
  discovery from the crawl is exercised). Insecure: `session.id.weak` (the `abc123` index cookie
  and the duplicates), `session.fixation`, `session.logout.not-invalidated`. Hardened: none of
  them (the existing "reports nothing" test covers it).
- Assertions that matter: the three findings carry the cookie name and no value; the logout test
  ran last (the logout request is the final request of the app's log before the replay); the
  sampling requests carried no `Cookie`; the determinism test still passes with the new findings.
- The `session_ttl` scan (019) is untouched; no new scan configuration is expected. If the
  logout test must not share the `_full` scan (it ends the session), it gets one dedicated
  hardened/insecure pair and the design is updated.

**Safety invariants**, each in a test: no value in any report; a Passive scan without
`--sample-sessions` sends nothing new; the logout test needs Active and a login; no derived id is
ever sent; the samples carry no cookie.

## Deviations from the approved requirements

1. `--logout-url` is a CLI flag (the requirements list only the config key `logout_url`); it costs
   one option and mirrors `--login-url`.
2. The summary line is assembled from the config switches (`_session_summary`) rather than from a
   new metadata field; the metadata gains nothing in this spec.
3. **The package imports its checks.** `checks/session/__init__.py` ends with the import of
   `checks.session.checks` and `checks/__init__._load_builtin_checks` lists `session`, like every
   other check package (the design said "no re-exports", which would have left the checks
   unregistered).
4. **The jar refuses a `Secure` cookie set over plain `http`** (`_without_insecure_secure_cookies`
   in `http/session.py`, RFC 6265bis "leave Secure cookies alone"). The fixture's hardened index sets
   `__Host-session=...; Secure` on an `http` target; the stdlib jar accepted it and silently
   replaced the logged-in session cookie with one that is never sent back over `http`, which broke
   the hardened logout and fixation scans (and had been degrading the 019 hardened scans quietly).
   A change to 019 code, with unit tests in `test_session_jar.py`.
5. **The logout step needs the switch twice.** `kinds_for` selects `logout` from the check id; the
   orchestrator drops it unless `[session] test_logout` is on, so selecting the check alone (the
   default in an Active scan) never logs out.
6. **"Last" means last of the passes.** The checks that still run after the pass (the CORS probe, for
   one) make their own unauthenticated requests, so the integration test asserts that the redirect and the
   replay follow the logout and that no re-login does, not that nothing else reaches the app.
7. **Fixture detail.** The hardened index id is `sha256("index-N")[:32]` per visit (a constant one
   is a "duplicates" finding of the sampling) and `GET /signin` gives an anonymous session id in both
   profiles (counter `1001...` in the insecure one, hashed in the hardened one); the insecure login
   keeps it, the hardened login issues a new one.

## Open questions

None blocking.
