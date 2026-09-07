---
feature: Authenticated scanning (static cookies), CSRF detection, and form-driven crawling
status: done
date: 2026-09-06
related:
  - 001-foundation/requirements.md
  - 002-web-api/requirements.md
  - 003-web-ui/requirements.md
  - 005-info-disclosure/requirements.md
  - 006-active-injection/requirements.md
origin: conception
---

# 007 — Authenticated scanning, CSRF detection, and form-driven crawling

## Context and problem

Specs 001–006 shipped the engine + CLI, the Web API, the dashboard, passive dependency
fingerprinting, information-disclosure probing, and the first Active-Mode injection checks.
**Every scan so far is anonymous.** The crawler starts from the seed URL, follows `<a href>`
links, and never sends a cookie or submits a form. Whatever lives behind a login — a user
dashboard, an account-settings page, an admin panel — is invisible to WebVigil. So is every
page you can only reach *through* a form: a search result, a filtered listing, a wizard step
two.

This is the single biggest coverage gap in the tool. A security-conscious developer's real
question is rarely "is my public marketing page missing a header" — it is "is the
**authenticated** part of my app safe", and the classic authenticated-area bug is **CSRF**:
a state-changing form with no anti-forgery token, submittable from any origin.

007 closes the gap with three tightly-related pieces, all inside the engine's existing
rules (pure library, no new runtime dependency, scope guard unchanged, good-neighbor policy
on every request):

- **Authenticated scanning via static cookies.** `--cookie "name=value"` (repeatable) or
  `[auth] cookies` in the config. The user pastes the session cookie(s) from a browser
  where they are already logged in; WebVigil attaches them to every in-scope request, so
  the crawl and every check see the application as that user.
- **Form-driven crawling.** The crawler learns to submit **safe `GET` forms** (search
  boxes, filters) with their default values and enqueue the resulting URLs, widening the
  discovered surface for every check — passive and active alike. `POST` forms and forms
  that look destructive are never submitted.
- **CSRF detection (passive).** A new `csrf.form.no-token` check reads the `<form>`s parsed
  from crawled bodies and flags every state-changing (`POST`) form that carries no
  anti-CSRF token, weighting the finding by whether the session cookie is `SameSite`-scoped.

An authenticated crawl introduces one genuinely new risk: following an `<a href="/logout">`
or an `<a href="/posts/5/delete">` link now *actually logs out* or *actually deletes*,
where an anonymous scan would have been bounced to a login page. 007 handles this with a
documented **destructive-link avoidance heuristic** (RF-03), the counterpart to spec 006's
form-exclusion heuristic.

### Deferred, on purpose

The original roadmap line for `007` ("scan autenticado (cookie/header/login form), teste de
session/CSRF") is broader than what ships here. These items move to a later spec, for
concrete reasons rather than scope-trimming — settled with Ryan on 2026-09-06:

- **Automated login-form flow** (detect the login form, submit credentials once, capture
  the session cookie, re-login when the session drops). This is a stateful multi-step
  mechanic with its own failure modes (CAPTCHA, MFA, CSRF-on-login, "remember me",
  redirect chains). Static cookies cover the common case — a developer testing their own
  app can always copy a cookie — and are a safe, well-understood building block. The login
  flow rides on top of it in a follow-up.
- **Static auth headers / bearer tokens** (`--header "Authorization: Bearer …"`). A small
  addition, but out of the confirmed v0.7 scope; a natural companion to the login flow
  spec (both are "how do credentials get in").
- **Session-security testing** — session fixation (the id does not rotate on login),
  session not invalidated on logout, weak/predictable session ids. Every one of these
  needs either the login flow (to have a *before* and *after* login) or Active Mode (to
  drive a logout), so they wait for the login-flow spec.
- **Active CSRF confirmation** — replaying a state-changing form with the token removed or
  tampered and checking the server still accepts it. This is an Active-Mode check
  (payload-bearing, state-changing) and belongs with a broader "active session/CSRF" spec.
  007 detects the *absence* of a token by inspection only.
- **`POST` form submission by the crawler**, `multipart`/JSON bodies, parameter mining.
  Out, as in spec 006.

### Where it sits

```
webvigil.http          + static cookies attached to in-scope requests only (never off-scope,
                         never written to any report)                              — RF-01/02

webvigil.crawler       + GET-form discovery and submission during discover()       — RF-05/06
                       + destructive / logout link avoidance (authenticated crawl) — RF-03
                       the Form model (spec 006) moves earlier: parsed during the crawl,
                       not only after it

webvigil.core.context  + ScanContext.forms — the parsed <form> inventory, available to checks — RF-07

webvigil.checks.csrf   new check package  (Category.CSRF, mode = PASSIVE)
       └── csrf.form.no-token   state-changing form, no anti-CSRF token, SameSite-weighted — RF-08

config                 [auth] cookies = ["name=value", …]   ·   [scan] submit_forms = true — RF-10
CLI                    --cookie "name=value"  (repeatable)                                  — RF-10

fixture                tests/fixtures/app.py: a cookie-gated /account area, a token-less POST
                       form, a logout link, a submittable GET search form                  — RF-13
```

The engine still imports nothing from `webvigil.cli`, `webvigil.api`, or `web/`. The
`import-linter` "engine stays independent" contract is unchanged (`webvigil.checks`,
`webvigil.http`, `webvigil.crawler` are already source modules). `csrf.*` findings are
ordinary `Finding`s and flow through spec 001's four reporters and spec 002/003's existing
persistence and dashboard with **no migration, no `openapi.json` regen, no component
change** — the new `CSRF` category surfaces as a string exactly as `INJECTION` did in
spec 006. This is an **engine + CLI** spec.

## Goals

- **Authenticated scanning**: `--cookie "name=value"` (repeatable) and `[auth] cookies`;
  the cookie(s) ride every in-scope request the scan makes (crawl fetches, check probes,
  the injection pass), and **never** leave scope and **never** appear in a report, log
  line, or the scan metadata.
- **Session-safe authenticated crawl**: a documented heuristic keeps the crawler from
  following `logout` / `signout` links (which would kill the session mid-scan) and, when
  the scan is authenticated, from following links and submitting forms that look
  state-changing (`delete`, `remove`, `revoke`, …).
- **Form-driven crawling**: the crawler submits in-scope non-excluded **`GET`** forms with
  their default field values and enqueues the resulting URLs, bounded by `max_pages` and
  deterministic; `POST` forms are never submitted by the crawler.
- **A parsed `<form>` inventory on `ScanContext`** so any check — not just the injection
  pass — can reason about forms.
- **CSRF detection**: `csrf.form.no-token` (`category = CSRF`, `mode = PASSIVE`,
  `cwe = 352`) flags every in-scope state-changing form with no anti-CSRF token; the
  hardened fixture profile yields **zero** `CSRF` findings.
- **CLI surface**: `--cookie`; `list-checks` shows `csrf.*`; the human summary notes an
  authenticated scan (cookie **count**, never values) and the CSRF finding count.
- Docs: a new authenticated-scanning / CSRF section (how to supply cookies, the
  destructive-link heuristic and its limits, form-driven crawling, what the CSRF check
  does and does not prove, why the login flow and session tests are deferred) plus the
  usual architecture / writing-checks / README / CLAUDE / roadmap updates.

## Non-goals

- **Automated login**: detecting a login form, submitting credentials, capturing a session,
  handling CSRF-on-login / MFA / "remember me", re-authenticating when the session drops.
  Deferred (see "Deferred"). 007 takes a cookie the user already has.
- **Auth headers / bearer tokens / API keys.** Deferred. 007 is cookies only.
- **Session-security checks** — fixation, logout invalidation, weak session id, absolute /
  idle session timeout. Deferred (each needs the login flow or Active Mode).
- **Active CSRF confirmation** — resubmitting a form without / with a tampered token.
  Deferred to an Active session/CSRF spec. 007 detects a *missing* token by inspection.
- **`POST` form submission anywhere in the crawler.** The crawler submits `GET` forms only.
  (The Active injection pass still submits `POST` forms it is pointed at — spec 006,
  unchanged.)
- **`multipart/form-data` or JSON request bodies, GraphQL, file uploads.** As spec 006.
- **Parameter mining / brute-forcing hidden parameters or hidden pages.** The crawler
  submits forms the target actually serves; it does not guess.
- **A JavaScript engine / headless browser.** Forms and CSRF tokens are read from served
  HTML text only (spec 001 non-goal, unchanged). A token injected by client-side JS, a
  form built by a framework at runtime, or a SameSite default the browser applies but the
  header does not state — all invisible, and documented as limits.
- **CSRF for `GET` endpoints that change state** (bad design, but 007 only looks at `POST`
  forms), **JSON/`fetch` CSRF**, **clickjacking** (that is `X-Frame-Options`, spec 001),
  **login CSRF**, **CORS-based CSRF** (spec 001's `cors.*`).
- **Any database migration, `openapi.json` regeneration, or new API / UI component.**
  `csrf.*` findings are ordinary `Finding`s (RF-12). The `--cookie` input is CLI +
  config-file only; the Web API does not gain an auth field in v0.7.
- **A new consent / authorization gate.** Supplying your own session cookie to scan your
  own app needs no attestation; the CSRF check is passive. Active Mode is unchanged and
  orthogonal — an authenticated scan can also be `--mode active` and both apply.

## Personas

| Persona | Needs from 007 |
|---|---|
| **Security-conscious developer** | "Scan my app *as a logged-in user*." Copies the `session=` cookie from devtools, runs `webvigil scan https://app.local --cookie "session=…"`, and finally gets findings for the account area — including a MEDIUM `csrf.form.no-token` on the "delete project" form that has no token. |
| **CI pipeline author** | An authenticated scan of a staging deploy using a service-account session cookie from a CI secret, so the nightly scan covers the real app and not just the login page. The cookie value must never reach the SARIF file, the logs, or the archived JSON. |
| **Pentester / consultant** | First-pass authenticated coverage: point the crawler at the app with a client-supplied cookie, let it submit the search and filter forms to expand the map, and get a clean list of every state-changing form missing CSRF protection — with the SameSite context already factored in. |
| **Check author / contributor** | `ScanContext.forms` and `Category.CSRF` as the reference for a check that reasons about forms rather than single responses, and the destructive-heuristic module as the shared "is this safe to touch" helper. |

## Functional requirements

### Authenticated scanning

**RF-01 — Static cookie authentication**
- **Given** `--cookie "name=value"` on the CLI (repeatable) **or** `[auth] cookies =
  ["name=value", …]` in the config, **when** a scan runs, **then** every in-scope HTTP
  request the scan issues (crawl fetches, the CORS/redirect probes, the disclosure probe,
  the injection pass) carries those cookies.
- **Given** both a config `[auth] cookies` list and one or more `--cookie` flags, **then**
  the CLI flags **replace** the config list (consistent with how every other list override
  works — `checks.disabled`); this is documented.
- **Given** a `--cookie` / `cookies` entry with no `=`, an empty name, or a non-string,
  **then** the scan refuses to start with a clear `ConfigError` (**not** a stack trace).
- **Given** no cookie is supplied, **then** the scan is byte-for-byte identical to a v0.6
  scan (anonymous).

**RF-02 — Cookies stay in scope and out of every report**
- **Given** any request whose host is **not** the target host (an `allow_out_of_scope`
  fetch, a redirect target that left scope — which the HTTP layer does not follow anyway),
  **then** the configured cookies are **not** attached to it.
- **Given** any report (JSON, SARIF, HTML, Markdown), any `--format`-less summary line, any
  warning, any `CheckError` message or traceback, or the scan metadata, **then** a cookie
  **value** never appears in it. The CLI summary may state the **number** of cookies
  supplied; nothing more.
- **Given** the scan metadata, **then** it records that the scan was authenticated
  (how — a boolean, a count — is a design decision) **without** storing any cookie name or
  value, and without forcing a Web API migration (RF-12).

**RF-03 — Destructive- and logout-link avoidance**
- **Given** the crawler is about to enqueue a discovered `<a href>` URL **or** submit a
  discovered `GET` form, **when** the URL path or the form action/field names match a
  documented **logout heuristic** (`logout`, `log-out`, `signout`, `sign-out`, `disconnect`),
  **then** it is **skipped** — always, authenticated or not (an anonymous scan gains
  nothing from a logout endpoint either).
- **Given** the scan is **authenticated** (≥1 cookie supplied), **when** a discovered URL
  path or form matches a documented **destructive heuristic** (`delete`, `remove`,
  `destroy`, `drop`, `revoke`, `deactivate`, `disable`, `unsubscribe`, `cancel`, `purge`,
  `reset`, `wipe`), **then** it is **skipped** and the scan records a warning naming the
  count of links it declined to follow.
- **Given** an anonymous scan, **then** the destructive heuristic is **not** applied (an
  anonymous request to `/posts/5/delete` is harmless and usually bounced to login) — only
  the logout heuristic is.
- The heuristic, its keyword list, and its limits (a delete action at `/p/5` with the verb
  only in the HTTP method, a logout named `/session` — not caught) are documented (RF-16).

**RF-04 — Authenticated-session sanity check**
- **Given** an authenticated scan, **when** the seed URL (or a large fraction of crawled
  pages) responds with a redirect to a login-looking URL (`/login`, `/signin`, `/auth`,
  `?next=`) or a login-looking body, **then** the scan records a **warning** ("the supplied
  cookies may be invalid or expired — the target redirected N pages to a login screen"),
  not an error. The scan still completes on whatever it could reach.

### Form-driven crawling

**RF-05 — `GET` form discovery and submission**
- **Given** the pages the crawler fetches, **when** it processes each in-scope HTML page,
  **then** it parses the `<form>` elements out of `page.text` (the spec 006 `Form` model,
  now populated **during** `discover()` rather than only after it — a design decision on
  where the parsing lives) and, for each in-scope `<form method="get">` that is **not**
  excluded (RF-03, and the spec 006 authentication/destruction heuristic), builds the
  submission URL — the form's resolved action plus a query string from the fields' default
  values (text/hidden: the `value`; select: the selected/first `option`; checkbox/radio:
  included only if `checked`; submit/button/image/file/password: omitted) — and enqueues it
  like a discovered link.
- **Given** the same form appears on many pages, **then** its submission URL is enqueued
  **once** (normal crawl `seen` de-dup).
- **Given** `max_pages`, **then** form-submission URLs count against it exactly like
  `<a href>` URLs; the crawl stops at the cap and the ordering is deterministic (links
  before forms on a page, forms in document order).
- **Given** a `<form method="post">` (or `dialog`, or any non-`GET`), **then** the crawler
  **never** submits it. Its inventory is still recorded for the checks (RF-07).

**RF-06 — Form submission is safe by construction**
- Only `GET`. Only in-scope actions. Only default values — **no** payloads, no fuzzing
  (that is the injection pass's job, spec 006, and it already consumes `ScanContext.forms`
  indirectly). The good-neighbor policy (concurrency cap, per-host delay, `timeout_s`) and
  the scope guard apply to every form submission exactly as to a link fetch.
- **Given** `[scan] submit_forms = false`, **then** the crawler does not submit any form
  (the `<a href>` crawl is unchanged); default is `true`. Config-only, no CLI flag.

**RF-07 — The `<form>` inventory is available to checks**
- **Given** any check, **then** `ctx.forms` is the tuple of in-scope `Form`s parsed from
  the crawled pages (de-duplicated on method + action + field-name tuple, as spec 006's
  `extract_forms` already does), populated once by the orchestrator/crawler **before**
  checks run and read-only during the run.
- **Given** the injection pass (spec 006), **then** it consumes the same inventory — the
  orchestrator no longer calls `extract_forms` separately; the mechanics are a design
  decision but the observable behaviour of spec 006 is unchanged.

### CSRF detection

**RF-08 — `csrf.form.no-token`** (`category = CSRF`, `mode = PASSIVE`, `cwe = 352`,
default `MEDIUM`)
- **Given** an in-scope `<form method="post">` from `ctx.forms` that is **not** a login /
  registration / search form (documented exclusion — a pre-session login `POST` is a
  different problem, out of scope per "Non-goals"), **when** the check runs, **then** it
  inspects the form's fields for an **anti-CSRF token**: a field whose name matches
  `csrf`, `xsrf`, `_token`, `authenticity_token`, `__requestverificationtoken`,
  `csrfmiddlewaretoken`, `nonce`, `anti-forgery`, `requesttoken` (case-insensitive,
  substring), typically `type="hidden"` with a non-empty, high-entropy value.
- **Given** the form has **no** such field, **then** a `MEDIUM` finding reports the form's
  action URL, method, and the page it was found on, and lists the field names as evidence.
- **Given** the response that carried the form (or any crawled response for that host) set
  a **session-looking cookie** (`session`, `sess`, `sid`, `auth`, `jwt`, `token` in the
  name) **without** `SameSite=Lax` or `SameSite=Strict`, **then** `confidence = HIGH` (the
  form is genuinely reachable cross-site); **given** the session cookie **is**
  `SameSite=Lax`/`Strict`, **then** `confidence = LOW` and the finding notes that SameSite
  mitigates it; **given** no session cookie is observed at all, **then** `confidence =
  MEDIUM`.
- **Given** a form that **does** carry a recognised token field with a non-trivial value,
  **then** **nothing** is reported.
- **Given** the same form action on several pages, **then** the finding dedups on
  check id + action URL + method (not the page it was found on).

**RF-09 — CSRF false-positive discipline**
- The check fires only on `POST` forms (state-changing by convention), never on `GET`
  forms. It excludes login/registration forms by the documented heuristic. It does not
  fire when a token field is present with a real value.
- **Given** the hardened fixture profile, **then** **zero** `CSRF` findings (its POST forms
  carry a token and its session cookie is `SameSite`).
- Known limits, documented (RF-16): a token injected by client-side JavaScript, a token
  carried in a request header the server sets via a `<meta>` tag + framework JS
  (Rails/Angular pattern), a double-submit-cookie scheme with no form field, or a
  same-site-only app behind an authenticating proxy — all read as "no token" and may be
  false positives; `confidence` and the remediation text call this out.

### CLI

**RF-10 — Surface**
- **Given** `webvigil scan <url> --cookie "a=1" --cookie "b=2"`, **then** both cookies are
  attached to in-scope requests (RF-01).
- **Given** `webvigil list-checks`, **then** `csrf.form.no-token` appears with category
  `CSRF`, mode `passive`, severity `MEDIUM`.
- **Given** `[checks] disabled = ["csrf.form.no-token"]`, **then** the check does not run —
  same mechanism as every other check.
- **Given** `[scan] submit_forms` in the config, **then** it toggles form-driven crawling
  (RF-06); there is **no** CLI flag for it (minimal surface, matches `follow_robots`).
- **Given** the human-readable summary of an authenticated scan, **then** it includes a
  line such as `"Authenticated scan: N cookie(s) supplied"` (count only) and, when any
  `csrf.*` finding is present, `"CSRF: F form(s) without an anti-CSRF token"`. An anonymous
  scan's summary is unchanged.
- **Given** an invalid `--cookie` value (RF-01), **then** the CLI prints a one-line error
  and exits with the usage/operational code, no traceback.

**RF-11 — Exit codes**
- `--fail-on <severity>` treats `csrf.*` findings by severity exactly as today. No new exit
  code; a "cookies may be expired" warning (RF-04) or a "declined N destructive links"
  warning (RF-03) is a warning, not an operational error.

### Reporting

**RF-12 — Reporters and the Web API unchanged in shape**
- **Given** a completed scan, **then** `csrf.*` findings render through the four existing
  reporters with **no new section and no new top-level array**: JSON lists them among
  `findings`; SARIF emits one `rule` per `csrf.*` id used with the form action + method in
  the location; HTML and Markdown group them by severity like any other finding.
- **Given** a `csrf.form.no-token` finding, **then** its `evidence` carries: the form
  (method + action URL + source page), the list of field names, and the session-cookie
  SameSite observation that set the confidence.
- **Given** a scan run through the Web API, **then** `csrf.*` findings persist and are
  returned by `GET /api/scans/{id}` through spec 002's lossless persistence with **no**
  migration and **no** schema change; `GET /api/checks` lists the new check with
  `category: "CSRF"` and the dashboard's data-derived category filter gains `CSRF` with
  **no** component change and **no** `openapi.json` / `api-types.ts` regeneration.
- **Given** the Web API's scan-request schema, **then** it is **unchanged** — v0.7 adds
  **no** `cookies` / auth field to `POST /api/scans` (deferred with the login flow). An
  authenticated scan is a CLI + config-file capability in v0.7.
- **This is stated here so the design phase does not reopen it.** The expectation, to be
  confirmed in design: 007 touches the **engine + CLI only**. If a hardcoded category list
  or enum is found in `webvigil.api` or `web/`, 007 updates that one spot; none is expected
  (spec 006 verified `api/routes/meta.py` returns `category` as `str` and
  `web/src/app/(app)/checks/page.tsx` derives the filter from data).

### Fixture app and tests

**RF-13 — Authenticated + CSRF + form-crawl surface in the fixture** (mirrors spec 001
RF-27, spec 004 RF-19, spec 005 RF-13, spec 006 RF-20)
- **Given** the `tests/fixtures` app's **insecure** profile, **then** it serves, in
  addition to its current surface:
  - `GET /account` — **302 → `/login`** unless the request carries `Cookie: session=abc123`
    (the value the insecure home page already sets); with the cookie, `200` with content
    and links to `/account/settings` and `/logout` and a
    `<form method="post" action="/profile">` **with no CSRF token** (state-changing).
  - `GET /account/settings` — another cookie-gated page, to prove the authenticated crawl
    goes deeper than one hop.
  - `POST /profile` — accepts the update (200); it is the token-less form
    `csrf.form.no-token` must flag.
  - `GET /logout` — clears the session; the crawler must **never** request it.
  - the existing `<form method="get" action="/search"><input name="q"></form>` on the home
    page — the crawler must **submit** it, producing `GET /search?q=` in the request log.
- **Given** the **hardened** profile, **then** the equivalent `/account` area requires the
  `__Host-session` cookie, its `POST /profile` form carries a
  `<input type="hidden" name="csrf_token" value="…">`, and the session cookie is
  `SameSite=Lax` — yielding **zero** `CSRF` findings.

**RF-14 — Integration tests**
- **Given** an **authenticated** scan (`--cookie "session=abc123"`) of the insecure
  profile, **then** `/account` and `/account/settings` are crawled and appear in
  `pages_scanned`; **given** an **anonymous** scan, **then** they are not (they 302 to
  `/login`).
- **Given** any scan, **then** the crawler **submits the `GET` search form** — `GET
  /search?q=…` appears in the fixture's request log — and **never** submits `POST /comment`
  or `POST /login` and **never** requests `/logout`.
- **Given** an authenticated scan, **then** `csrf.form.no-token` fires on `POST /profile`
  with `location.method == "POST"` and the action URL; **given** the hardened profile,
  **then** **zero** `CSRF` findings.
- **Given** any report of an authenticated scan, **then** the string `abc123` (the cookie
  value) appears **nowhere** in the JSON, SARIF, HTML, or Markdown output or in any
  warning — asserted explicitly.
- **Given** an authenticated scan repeated, **then** it is deterministic (same findings,
  same fingerprints, same crawl set).

**RF-15 — Unit tests**
- Cookie parsing: `name=value`, multiple, whitespace, a value containing `=`, the invalid
  cases (no `=`, empty name) → `ConfigError`; CLI-replaces-config precedence.
- `HttpClient`: configured cookies are sent on an in-scope request and **absent** on an
  `allow_out_of_scope=True` request.
- Destructive/logout heuristic: each keyword (`/logout`, `/account/delete`, `?action=remove`,
  a `<form action="/revoke">`), a false-positive guard (`/deleted-items` as a listing page
  is still skipped — documented; `/logout-help` — decision recorded), anonymous vs.
  authenticated application of the destructive set.
- Form-crawl: a `GET` form yields the right submission URL from mixed field types; a `POST`
  form yields none; an excluded (`/login`) form yields none; `submit_forms = false`
  disables it; `max_pages` still caps the crawl.
- `csrf.form.no-token`: token present (each recognised name) → nothing; token absent →
  finding; `SameSite=Lax` session cookie → LOW; no `SameSite` → HIGH; no session cookie →
  MEDIUM; a `GET` form → nothing; a login form → nothing; cross-page dedup.
- The `_render` summary lines (cookie count, CSRF count) and the "cookies may be expired"
  warning.

### Documentation

**RF-16 — Docs**
- A new `docs/authenticated-scanning.md`: supplying cookies (`--cookie`, `[auth] cookies`,
  the CLI-replaces-config rule, where to get a cookie), the privacy guarantee (values never
  leave scope or reach a report), the destructive-/logout-link heuristic **and its limits**,
  form-driven crawling (what gets submitted, what never does), the `csrf.form.no-token`
  check (what it proves, the SameSite weighting, the false-positive limits — JS-injected
  tokens, header-based tokens, double-submit cookies), and why the login flow, auth
  headers, and session-security tests are deferred.
- `docs/architecture.md` (the http / crawler / checks bullets), `docs/writing-checks.md`
  (`ctx.forms` and a note on a form-reasoning check; the destructive heuristic as a shared
  helper), `README.md` (coverage table + an authenticated quick-start line),
  `CLAUDE.md` (architecture summary + `Estado` line), and `specs/README.md` (roadmap row →
  `done`, and a note that the login flow / auth headers / session tests slipped from the
  `007` line to a later spec and why). 007 moves `draft → approved → in progress → done`.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.checks.csrf`, `webvigil.crawler` (form submission, the
heuristic), `webvigil.core.context` (`ScanContext.forms`), and `webvigil.http` (cookie
attachment), plus config additions. It imports nothing from `webvigil.cli`, `webvigil.api`,
or `web/`. Cookie parsing and form-URL building use the standard library
(`http.cookies` / manual `name=value` split, `urllib.parse`); **no runtime dependency is
added**. The `import-linter` contract is unchanged.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy` covering the new
modules. **No** API migration test and **no** `web` gate expected (pending the RF-12
confirmation). The Docker jobs are unchanged.

**RNF-03 — Safe by default**
An anonymous scan is byte-for-byte unchanged. Supplying a cookie changes only *which*
in-scope pages are reachable, not the politeness policy, the scope guard, or the mode gate.
Form-driven crawling issues only in-scope `GET` requests with default values. The
destructive-link heuristic reduces, never increases, what an authenticated crawl touches.

**RNF-04 — Determinism**
Given the same target responses, the crawl set (including submitted-form URLs), the
findings, and the fingerprints are identical across runs; report ordering is stable
(spec 001 RNF-04). Form URLs are built from fields in document order.

**RNF-05 — False-positive discipline**
Per RF-09. `csrf.form.no-token` fires only on non-excluded `POST` forms with no recognised
token field; the hardened fixture yields zero `CSRF` findings; `confidence` reflects the
SameSite context and the documented blind spots.

**RNF-06 — Credential privacy**
Per RF-02. Cookie values are held only in memory for the scan's lifetime, attached only to
in-scope requests, and never written to a report, a log line, a warning, a `CheckError`, or
the scan metadata. Tests assert the value string is absent from every output.

**RNF-07 — Python support**
Runs on CPython 3.12 and 3.13 (the existing CI matrix).

**RNF-08 — Docs**
Per RF-16. The exact scope — cookies not login, passive CSRF not active, `GET` forms not
`POST` — is stated plainly so a user is never surprised.

## Resolved decisions

Settled with Ryan on 2026-09-06:

1. **Authentication mechanism for v0.7:** **static cookies only** — `--cookie "name=value"`
   (repeatable) and `[auth] cookies`. Automated login-form flow, static auth headers /
   bearer tokens, and session-drop re-login are **deferred to a later spec** (they form a
   coherent "how credentials get in / staying logged in" follow-up).
2. **Session / CSRF security scope for v0.7:** **one passive check** — `csrf.form.no-token`
   (state-changing form with no anti-CSRF token, SameSite-weighted). Active CSRF
   confirmation (token-removal replay), session-not-invalidated-on-logout, and session
   fixation / weak-id are **deferred** (each needs Active Mode or the login flow).
3. **Form-driven crawling:** **yes** — the crawler submits safe in-scope **`GET`** forms
   with default values and enqueues the results; `POST` and destructive/auth forms are
   never submitted. This widens coverage for every check, passive and active.
4. **Web API / Web UI:** **no amendment.** `csrf.*` findings are ordinary `Finding`s and
   ride spec 002's persistence + spec 003's findings view; the new `CSRF` category flows
   through as a string. `--cookie` is a CLI + config-file input; `POST /api/scans` gains no
   auth field in v0.7. 007 is an engine + CLI spec. Design confirms; if a single hardcoded
   category spot exists, 007 updates it.

## Resolved during requirements (open questions, settled as proposed)

Approved with Ryan on 2026-09-06 ("aprovado com as propostas"). The design phase elaborates
the mechanics; these answers are fixed.

5. **Form-parsing location (Open question 1):** the **crawler** parses forms from each page
   during `discover()` and returns them alongside the `Page`s; the orchestrator puts them
   on `ScanContext.forms` and hands the same tuple to the injection pass.
   `webvigil.crawler.forms` keeps the `Form` model; `extract_forms` is called from the
   crawl loop (or its logic folds in). The orchestrator no longer calls `extract_forms`
   separately.
6. **Authenticated-scan flag (Open question 2):** a `ScanMetadata.authenticated: bool =
   False` — additive, defaults false, appears in the canonical JSON, not surfaced in the
   SARIF/HTML/MD headers (or shown as a one-liner at most). Design verifies the Web API's
   metadata mapping tolerates the extra field with **no migration**; if it does not, fall
   back to a CLI-summary-only line and no metadata change.
7. **`[auth]` section (Open question 3):** a **new `[auth]` section** with `cookies:
   list[str] = []`. `[active]` stays the attestation-only section for Active Mode — same
   reasoning as spec 006 ADR-4 choosing `[injection]` over `[active]` keys.
8. **Destructive-heuristic scope (Open question 4):** the **logout** subset always; the
   broader **destructive** subset only when the scan is authenticated (RF-03 as written).
   Design may simplify to "always" only if the coverage cost is shown negligible against
   the fixture.
9. **`csrf.form.no-token` inputs (Open question 5):** `ctx.forms` + the crawled responses'
   `Set-Cookie` headers are enough — a pure passive check, no extra request via `ctx.http`.

## Open questions

None. Ready for `/spec design`.
