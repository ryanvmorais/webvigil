---
feature: Session-security checks — weak session ids, session fixation, logout that does not invalidate the session
status: done
date: 2026-10-07
related:
  - 019-automated-login/requirements.md
  - 019-automated-login/design.md
  - 017-csrf-confirmation/requirements.md
  - 013-auth-and-api-surface/requirements.md
origin: conception
---

# 020 — Session-security checks

## Context and problem

Issue #53. WebVigil tests the *attributes* of a session cookie (`http.cookies.flags`: `Secure`,
`HttpOnly`, `SameSite`, prefixes) and whether a session id leaks in a URL
(`disclosure.session-id-in-url`), but nothing about the **session itself**: whether the id can
be guessed, whether the server accepts an id the attacker chose, whether logging out kills the
session. `docs/authenticated-scanning.md` ("What is deferred") and the coverage table of
`docs/active-injection.md` both list these as blocked on a stateful login. Spec 019 (issue #52)
removed that block: an Active scan can now log in by itself, hold a session and see the cookies
of every hop.

The three classes, and why each one needs a different observation:

| Class | What goes wrong | What has to be observed |
|---|---|---|
| **Weak / predictable id** (CWE-330, 331, 340) | The id is short, low-entropy, numeric, or follows a counter or a timestamp, so it can be guessed or enumerated | The id **values** the target issues: the ones the crawl already saw, plus a few fresh anonymous samples |
| **Session fixation** (CWE-384) | The id an attacker plants in a victim's browser *before* login is still the id *after* login, so the attacker holds an authenticated session | The session cookie **before and after** the login handshake |
| **Session not invalidated on logout** (CWE-613) | The server keeps accepting the old id after the user logged out, so a stolen or cached id stays valid | Whether the **old** id still reaches an authenticated page after the logout request |

**What exists, and what does not.**

- `_SESSION_NAME_RE` (`checks/csrf/checks.py`) already recognises a session-looking cookie by
  name; `parse_set_cookie` (`checks/headers/_parsing.py`) parses a `Set-Cookie` line.
- The `Authenticator` (019) does the pre/post sequence on its own: `GET` of the login page
  (pre-login cookies in the pending jar), the `POST` and its redirect chain (post-login), then
  `commit`. It has the facts for fixation and **no extra request is needed to collect them**.
- `Session` / `SessionJar` hold the live session; `HttpClient.quiet()` fetches a page without
  triggering the re-login logic; the login's landing page and `check_url` are an
  "is this session authenticated?" oracle (019, ADR-6).
- The crawler skips logout links (`is_logout`) and never follows them, so no pass ever calls
  logout today.
- There is no `Category` for session management, and no pass that looks at cookie **values**
  (they are secrets and never reach a report; this spec must keep that true).

### Where it sits

```
 crawl (GET)                      login (019)                  last pass (Active)
 Set-Cookie values seen   ──┐     pre-login cookies ─┐          logout request, then replay
 N fresh anonymous GETs  ───┼─▶ weak-id rules         ├─▶ fixation   the OLD cookies against the
 (opt-in sampling)       ───┘     post-login cookies ─┘   verdict    landing page ─▶ still valid?
        │                                                                │
        └── session.id.weak               session.fixation              └── session.logout.not-invalidated
```

Cookie values are analysed in memory; a finding states **name, length, character classes and an
entropy estimate**, never the value, never a prefix of it.

## Goals

- **`session.id.weak`** — judge the session ids the target issues: from the cookies the crawl
  already saw (no extra request), and, with an opt-in switch, from a handful of **fresh
  anonymous visits** so that a counter, a timestamp or a low-variance id shows up across
  samples.
- **`session.fixation`** — report a session cookie that is the same before and after login,
  using what the 019 handshake already observed, **confirmed** that the unchanged cookie is
  what authenticates (one request) so an unrelated cookie does not raise a false finding.
- **`session.logout.not-invalidated`** — log out, then replay the old session cookies against
  an authenticated page; report if they still work. Opt-in, Active Mode only, last pass.
- **Secrets stay secret**: no cookie value, prefix or hash in any finding, log, warning or
  report; evidence is structural (name, length, alphabet, estimated bits, sample count).
- **Same contract as every check**: a vulnerable and a hardened fixture per check, fingerprints
  stable across runs, registry-listed ids, docs.

## Non-goals

- **Guessing or brute-forcing anyone's session id.** The weak-id check measures the ids the
  target hands **us**; it never tries a derived or neighbouring id against the target.
- **Session timeout / idle expiry**, concurrent-session limits, "remember me" token lifetime.
- **JWT analysis** (signature algorithm, `alg: none`, claims). A JWT-shaped value is skipped by
  the weak-id rules: it is a signed document, not a random id.
- **Cookie attributes** (`Secure`, `HttpOnly`, `SameSite`) — `http.cookies.flags` owns them —
  and **ids in URLs** — `disclosure.session-id-in-url` owns that.
- **Fixation by other means**: a planted id via URL parameter or header, session adoption,
  cross-subdomain cookie tossing. Only the cookie that survives a login is tested.
- **Multi-user and privilege tests**: horizontal / vertical escalation, one account's session
  reaching another's data.
- **Logout CSRF**, and **single sign-out / back-channel logout** across applications.
- **Logins WebVigil cannot do** (spec 019 non-goals): CAPTCHA, MFA, SSO, JSON token logins.
- **Web API / dashboard changes.** Engine and CLI only, as in 006–019.

## Personas

| Persona | Needs from 020 |
|---|---|
| **Security-conscious developer** | To learn from a staging scan that the framework's default session id is fine (or that a hand-rolled one is not), without reading cookie values by hand. |
| **Pentester / consultant** | The three OWASP WSTG session-management findings (WSTG-SESS-01, -03, -06) with the evidence a report needs — the cookie's *name* and why — in one authenticated run. |
| **Application owner worried about disruption** | A promise that WebVigil does not guess ids, that the logout test is opt-in and runs last, and that it only ever ends the session it created itself. |
| **CI pipeline author** | Deterministic findings and a clear skipped-because line when a precondition (a login, a logout endpoint) is missing. |
| **Check author / contributor** | A `SessionScanner` pass and a `Category.SESSION` to extend with the next session check. |

## Functional requirements

### Gates

#### RF-01 — Which switch gates which check

| Check | Needs | Gate |
|---|---|---|
| `session.id.weak` (values already seen) | the crawl | none — passive, no extra request |
| `session.id.weak` (samples) | N fresh anonymous `GET`s | `--sample-sessions` / `[session] sample_ids`, default off; `GET`-only, so allowed in **any** mode (the `--probe` precedent, spec 005) |
| `session.fixation` | a login (019) | none beyond the login: Active Mode, `[auth.login]` configured |
| `session.logout.not-invalidated` | a login, a logout endpoint | `--test-logout` / `[session] test_logout`, default off, **Active Mode only** (it ends the session) |

- **Given** `--test-logout` outside Active Mode, or without a login
  **Then** a scan warning says what it needs and nothing is sent — the behaviour of every
  opt-in used in the wrong mode since 008.
- **Given** none of the switches and no login
  **Then** the scan is byte-for-byte what it is today, plus the passive value rules of RF-03.

#### RF-02 — Which cookies are session ids

- **Given** a cookie
  **Then** it is a session id when its **name** matches the session-looking pattern
  (`session`, `sess`, `sid`, `auth`, `jwt`, `token`, and the framework names `JSESSIONID`,
  `PHPSESSID`, `ASP.NET_SessionId`, `connect.sid`, `laravel_session`…), the same pattern the
  CSRF check uses, moved to one shared place.
- **Given** a value that is JWT-shaped (`xxx.yyy.zzz` base64url with a JSON header)
  **Then** it is skipped by every rule of RF-03 / RF-04 (not a random id).
- **Given** a cookie that is not session-looking
  **Then** no session check looks at it, and no value of it is ever read for a finding.

### Weak session ids

#### RF-03 — Rules on the values already seen

- **Given** the session-id values in the `Set-Cookie` headers of the crawled pages
  **Then** each distinct name is judged once, on its **first** value, by these rules:
  (a) **length** under 16 characters; (b) **estimated entropy** under 64 bits (Shannon entropy
  of the observed characters × length, capped by the alphabet's size — a hex id of 16 chars is
  at most 64 bits, so 16 hex characters is the floor); (c) **purely numeric**; (d) a value that
  **repeats a single character** or a short pattern; (e) a value that looks like a
  **timestamp** (10 or 13 digits in a plausible epoch range) or an **incrementing counter**
  (small integer).
- **Given** a value that breaks (c), (d) or (e), or (a) and (b) together
  **Then** the finding is `HIGH`; a value that breaks only (a) or (b) is `MEDIUM`; confidence
  is `MEDIUM` for a single observation and the rules never claim to *prove* weakness from one
  value (the description says "looks", the evidence says why).
- **Given** a value that passes
  **Then** no finding and no evidence is kept.

#### RF-04 — Sampling fresh ids (`--sample-sessions`)

- **Given** `--sample-sessions` (`[session] sample_ids`, `sample_count` default 10, 3..20)
  **When** the pass runs
  **Then** it sends `sample_count` `GET`s of the entry URL, **each with no cookie and no
  carried state**, through the `HttpClient` (scope guard, rate limiter), and reads the session
  cookie names the responses set.
- **Given** the samples of one cookie name
  **Then**, beyond RF-03 on each value, it reports (a) **duplicates** among samples (two
  anonymous visits sharing an id); (b) a **sequence** — the values, read as integers, strictly
  increasing with a small constant or near-constant step; (c) **low variance** — the same
  characters in the same positions across most samples (an id that is mostly a fixed prefix);
  (d) a **timestamp-ordered** series.
- **Given** a target that sets no session cookie to an anonymous visitor
  **Then** the pass records a `skipped: no session cookie issued anonymously` line, not a
  finding.
- **Given** the samples
  **Then** they are sequential with `sample_count` requests at most, no retry, and the
  summary says how many were taken.

### Session fixation

#### RF-05 — Compare the cookies across the login

- **Given** a login (019) that was verified
  **When** the handshake ran
  **Then** the `Authenticator` has recorded the session-looking cookies the pending jar held
  after the `GET` of the login page (pre-login) and after the `POST` chain (post-login).
- **Given** a session-looking cookie present in both sets with the **same value**
  **Then** it is a fixation candidate (the server did not issue a new id on authentication).
- **Given** a session-looking cookie that **changed** (a new value), appeared only after the
  login, or was cleared
  **Then** it is fine; nothing is reported.
- **Given** the pre-login cookie was set by the login page itself and is the only one
  **Then** it is judged like any other: an app that keeps the anonymous id after login is
  vulnerable by definition.

#### RF-06 — Confirm the cookie is what authenticates

- **Given** a candidate
  **Then** one `GET` of the login's reference page (`check_url`, else the landing page) is
  sent with the live session **minus** that cookie, outside the re-login logic.
- **Given** the page now looks logged out (a `401`, a login redirect, the marker)
  **Then** the cookie is required for authentication: the finding is raised, `HIGH`
  confidence.
- **Given** the page is still authenticated
  **Then** the unchanged cookie is not what authenticates (a tracking id, a CSRF seed) and
  **no finding** is raised.
- **Given** an unconfirmed login (019) or no reference page
  **Then** the finding is raised with `MEDIUM` confidence and the evidence says the
  requirement was not verified.

### Logout does not invalidate

#### RF-07 — Finding the logout

- **Given** `[auth.login] logout_url` (new, optional, in scope)
  **Then** that is the logout endpoint, requested with `GET`.
- **Given** no `logout_url`
  **Then** the pass looks, in the crawled pages, for (a) an in-scope `<a href>` whose URL
  `is_logout` matches, requested with `GET`; (b) a `POST` form whose action `is_logout`
  matches, submitted with `form_body` (its token and defaults, nothing else), via the same
  candidate discipline as 017 / 018 for everything except the logout test itself.
- **Given** several candidates
  **Then** the first in crawl order is used; **given** none
  **Then** a `skipped: no logout endpoint found` line and no request.
- **Given** the endpoint
  **Then** it is requested **once**, with the session, through the `HttpClient`.

#### RF-08 — Replaying the old session

- **Given** the live session cookies, snapshotted just before the logout
  **When** the logout answered (any status below 500)
  **Then** the reference page (`check_url`, else the landing page) is requested **without the
  session jar** and with the **snapshot** as an explicit `Cookie` header, outside the re-login
  logic.
- **Given** the page is still authenticated with the old cookies
  **Then** `session.logout.not-invalidated` is raised: the server kept the session alive.
- **Given** the page looks logged out
  **Then** the logout works; nothing is reported.
- **Given** the logout request itself failed (5xx, transport error) or the reference page
  cannot be told apart
  **Then** a `skipped` / inconclusive line, never a finding.

#### RF-09 — Last pass, and the session ends

- **Given** the logout test is on
  **Then** it is the **last** pass of the scan (after the CSRF confirmation, spec 017
  ADR-6), because it ends the session; the `Session` is marked closed so no re-login is
  attempted for the checks that run afterwards.
- **Given** any later check reads `ctx.pages`
  **Then** it sees the crawl as it was; the logout pass adds no `Page`.

### Findings

#### RF-10 — Shape and identity

- **Given** a new `Category.SESSION`
  **Then** the three checks belong to it: `session.id.weak` (`MEDIUM` / `HIGH`, CWE-330, 331,
  340), `session.fixation` (`MEDIUM`, CWE-384), `session.logout.not-invalidated` (`MEDIUM`,
  CWE-613), each with the WSTG reference, remediation text and a `Confidence`.
- **Given** a finding
  **Then** its location is the URL that set the cookie (weak id), the login URL (fixation) or
  the logout endpoint (logout), its `cookie` field is the **name**, and its dedup key makes the
  fingerprint stable across runs and across different values.
- **Given** the evidence
  **Then** it lists only structural facts (name, length, alphabet classes, estimated bits,
  samples taken, which rule fired, which request confirmed), never a value or part of one.

#### RF-11 — Summary and warnings

- **Given** a pass that ran
  **Then** the scan summary has one line (`Session checks: N ids sampled` / `fixation
  checked` / `logout tested`) and a pass that could not run (no login, no logout endpoint, no
  anonymous session cookie) adds a warning that says why.
- **Given** the reporters
  **Then** they are unchanged apart from the new category and ids.

### Fixture app and tests

#### RF-12 — Vulnerable and hardened endpoints

- **Given** the fixture app
  **Then**, in the insecure profile: an anonymous visit sets a **predictable** session cookie
  (a counter), and the login **keeps** the pre-login cookie value (fixation), and `/logout`
  clears the cookie but the **server keeps the session valid**.
- **Given** the hardened profile
  **Then** ids are long random tokens, the login **issues a new id** and the old one stops
  working, and `/logout` **deletes** the session server-side (the old cookie reaches the login
  page).
- **Given** the existing `/signin` area (019)
  **Then** it is extended, not rewritten; the old any-cookie `/account` behaviour for
  `--cookie` scans stays.

#### RF-13 — Tests, within the suite's budget

Follows [`specs/README.md`, "Testes de uma spec"](../README.md#testes-de-uma-spec).

- **Unit** (the bulk): the value rules (a table of values → rule fired), the entropy
  estimator, the sample analysers (duplicates, sequence, low variance, timestamps), cookie
  selection and JWT skipping, the fixation comparison (changed / unchanged / appeared /
  cleared) and its confirmation, the logout discovery (config, link, form, none) and the
  replay verdict, scrubbing of evidence, config rules.
- **Integration**: attach to the shared scans — the full scan gains `sample_sessions` and
  `test_logout` (and finds all three in the insecure profile, none in the hardened); no new
  scan configuration unless the logout test cannot share one (it ends the session).
- **Safety invariants**, each in a test: no cookie value, prefix or hash in any report; a
  Passive scan sends nothing new without `--sample-sessions`; the logout test never runs
  without Active Mode and a login; the weak-id pass never sends a derived id to the target; the
  samples carry no cookie.
- Budget: about 1.0 test line per source line, the suite near its 10-minute mark.

### Docs

#### RF-14 — Docs

- `docs/authenticated-scanning.md` (or a new `docs/session-security.md`, decided in the
  design): the three checks, the switches, what each proves and cannot prove, the secrets
  rule; the "What is deferred" bullet leaves; `docs/active-injection.md` coverage row.
- `README.md` (roadmap row, flags, the "Authentication" limitation), `CLAUDE.md`
  (architecture paragraph, state line), `specs/README.md` roadmap, the CLI help.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
Code lives in `webvigil.checks.session` plus orchestrator / config / CLI wiring; the entropy
and sequence rules use the standard library (`math`, `collections`). The engine imports nothing
from `webvigil.cli` / `webvigil.api` / `web/`; `import-linter` unchanged.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green. No `web` gate work.

**RNF-03 — Safe by default**
Without a switch the only new behaviour is a local judgement of cookies already fetched.
Sampling is `GET`-only and bounded; the logout test is Active-only, opt-in, last, and ends only
the session WebVigil itself created. Nothing guesses an id.

**RNF-04 — Bounded work**
At most `sample_count` (default 10, max 20) sampling requests, 1 confirmation request per
fixation candidate (cap 3 candidates), 1 logout request and 1 replay. No retry, no loop.

**RNF-05 — Determinism**
Same target → same findings and fingerprints. Dedup keys do not depend on a cookie's value;
the analysers are pure functions of the samples.

**RNF-06 — Scope guard intact**
Every request goes through the `HttpClient`, its scope guard and its rate limiter; no new
host.

**RNF-07 — Secrets**
A cookie value (or a prefix, hash or slice of it) never reaches a finding, evidence item,
warning, log line or report. The session scrub of 019 still applies on top.

**RNF-08 — Python support**
No syntax or API newer than the project's Python floor.

## Resolved decisions

1. **Judge the ids the target gives us, never guess.** Predictability is measured on what we
   were handed; trying a neighbouring id against the target would be an attack, not a scan.
2. **Fixation is a by-product of the login.** The 019 handshake already holds both cookie sets;
   the only extra request is the confirmation that the cookie authenticates, which is what
   separates a real fixation from an unrelated unchanged cookie.
3. **The logout test is last and Active.** It destroys the session the rest of the scan used.
4. **Findings carry structure, not values.** Evidence says why a value looks weak without
   becoming a leak of the value.

## Open questions

1. **Gate of the sampling.** **Proposed:** `--sample-sessions` (default off), allowed in any
   mode because it is `GET`-only like `--probe`. The alternative — Active Mode only — keeps
   Passive free of new requests, at the price of Passive users never getting the sequence
   analysis. The passive single-value rules (RF-03) run either way.
2. **Gate of the fixation check.** **Proposed:** no switch; it runs whenever a login ran and
   costs one `GET`. The alternative — an opt-in flag — is stricter but fixation is the one
   finding the login gives for free.
3. **Gate of the logout test.** **Proposed:** `--test-logout`, default off, Active only
   (RF-01). The alternative — on by default after a login — finds more with no flag but ends
   the session in every authenticated Active scan.
4. **Entropy thresholds.** **Proposed:** under 16 characters or an estimated 64 bits is
   `MEDIUM`; numeric-only, repeating, counter- or timestamp-like is `HIGH` (RF-03). They follow
   OWASP's "at least 64 bits of entropy" guidance; say if you want them stricter (128 bits).
5. **Logout discovery.** **Proposed:** the configured `logout_url`, else the first logout link
   or `POST` form in the crawl, else a `skipped` line (RF-07). The alternative — guessing
   `/logout` — is a probe of paths WebVigil would be inventing.
6. **A new `Category.SESSION`.** **Proposed:** yes — three checks that are about session
   management, not cookie attributes. The alternative — reuse `COOKIES` — avoids touching the
   category table, the registry-driven metadata test and the docs, but mixes two meanings.
7. **Where the docs go.** **Proposed:** a section in `docs/authenticated-scanning.md`
   (the checks need a login, which that page owns). The alternative — a new
   `docs/session-security.md` — suits a page of its own if the section grows past ~80 lines.
