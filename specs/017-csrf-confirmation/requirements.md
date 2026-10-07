---
feature: Active CSRF confirmation — replay a state-changing form without a valid token (Active Mode)
status: done
date: 2026-10-06
related:
  - 007-auth-flows/requirements.md
  - 008-stored-xss/requirements.md
  - 012-protocol-injection/requirements.md
  - 014-file-upload/requirements.md
origin: conception
---

# 017 — Active CSRF confirmation

## Context and problem

Issue #54 asks for an Active Mode check that **confirms** CSRF instead of inferring it.
Spec 007 shipped `csrf.form.no-token`, a passive check: for every `POST` form that is not a
login / registration / search form it looks for a hidden field whose *name* looks like an
anti-CSRF token, and reports the form when there is none. It never asks the server whether
the token matters. The docs list the confirmation as deferred
([`docs/authenticated-scanning.md`](../../docs/authenticated-scanning.md), "What is
deferred").

**What the passive check gets wrong, in both directions.**

1. **False positives.** A token added by client-side JavaScript, carried in a request
   header (Rails-UJS, Angular, a `<meta>` tag), or implemented as a double-submit cookie
   with no hidden field all read as "no token". The check says so in its own finding text
   and drops to `LOW` confidence behind a `SameSite=Lax` / `Strict` cookie, but a
   developer still cannot tell a real hole from a blind spot.
2. **False negatives.** A form that *has* a `csrf_token` field the server never validates
   is silent. The name matched; nothing proved the token is enforced. This is the more
   dangerous half: it is the exploitable endpoint that looks protected.

**What "accepted" has to mean.** A browser attacker does not send the victim's token. They
submit the victim's own form from another origin, so the request carries the victim's
cookies, a foreign `Origin` / `Referer`, and either no token or a wrong one. The server
protects the victim only if it rejects that request. So the proof is a **three-way
experiment** on one form:

- a **control**: the form submitted the way a legitimate user would, with a fresh valid
  token, from the target's own origin — to learn what "accepted" looks like on this form;
- an **attack replay**: the same submission with the token removed and, separately, with the
  token altered, carrying a foreign `Origin` / `Referer` the way a cross-site form post
  would;
- a **verdict**: the form is confirmed only when the control was accepted *and* an attack
  replay produced an equivalent response. A rejected replay refutes it; anything murky is
  inconclusive and never becomes a finding.

**This is a different kind of Active check.** Every Active detector so far (006–016) sends
a payload into a parameter and reads the response. This one **submits state-changing forms
with their default values** — a control and one or two replays — so it can create a record,
change a setting or send an email on the target, up to three times per form. That is the
`--stored-xss` (008) and `--file-upload` (014) situation, and it gets the same discipline
(see **Open question 1**).

### Where it sits

```
webvigil.checks.csrf                          (Category.CSRF)
       ├── csrf.form.no-token                [007]  passive — no token field seen
       └── csrf.form.token-not-enforced      [017]  ACTIVE  — replay accepted without a valid token

CsrfScanner      new orchestrator pass (webvigil.checks.csrf.scanner), modelled on
                 UploadScanner / EnvelopeScanner: takes the form inventory, runs the
                 control + replays through the shared HttpClient, returns hits
checks.py        + TokenNotEnforcedCheck (id "csrf.form.token-not-enforced")
config / CLI     + one opt-in switch (name in the design)
```

Reuses what 006–014 built, unchanged: `ctx.forms` (the crawler's `<form>` inventory),
`is_auth_form` / `looks_like_search` (and the destructive heuristics of
`webvigil.crawler.safety`), the `HttpClient` (scope guard, concurrency cap, per-host delay,
`[auth]` cookies, `request(headers=…)`), the `webvigil.invalid` sentinel host spec 012
already uses, and the Active-Mode gate. **No new consent mechanism beyond the opt-in.** **No
change to `webvigil.api` or the dashboard** — findings persist and render through the
existing plumbing. The engine imports nothing from `webvigil.cli` / `webvigil.api` /
`web/`; no new runtime dependency.

## Goals

- One new `ACTIVE` check, `csrf.form.token-not-enforced` (`Category.CSRF`, CWE-352), that
  reports a state-changing form only when the server **accepted a cross-site-shaped replay
  without a valid token**, behind `--mode active --authorized-by` and an explicit opt-in.
- A **control / attack-replay / verdict** experiment per candidate form, with the replay
  faithful to a cross-site submission (token removed, token altered, foreign `Origin` and
  `Referer`) so an `Origin`-checking server is not reported as vulnerable.
- A **conservative acceptance oracle**: confirm only when the control was itself an
  acceptance and the replay is equivalent to it; refuse to guess otherwise.
- **Covers both halves of the passive check's error**: a token-less form that really is
  unprotected, and a form with a token field the server ignores.
- **No double reporting** with `csrf.form.no-token` (see **Open question 3**).
- **Safe by construction**: a candidate filter that skips login / registration / search /
  destructive forms, benign field values only, and a hard cap on forms and requests per
  scan.
- **Fixture-app coverage** for both profiles — an enforced token, an ignored token, no token
  at all, an `Origin`-checking form — deterministic and offline.
- **Docs** corrected: the "What is deferred" bullet leaves `docs/authenticated-scanning.md`,
  `docs/active-injection.md` (or the CSRF section) gains the check, plus the usual README /
  CLAUDE / specs-roadmap updates.

## Non-goals

- **Logging in.** The pass uses whatever credentials the scan already carries (`--cookie`,
  `[auth] cookies`). Automated login is issue #52 and a later spec; a session-bound token
  that cannot be obtained without one yields *inconclusive*, not a finding (see **Open
  question 2**).
- **Session-security checks** (fixation, logout invalidation, weak ids) — issue #53.
- **`POST` submission by the crawler** — issue #55. The pass submits only forms already in
  the inventory, and only to confirm them; it does not feed new pages back into the crawl.
- **Other CSRF vectors.** Forms only. No `JSON` / `fetch` endpoints, no `GET`
  state-changing links, no `PUT` / `DELETE` / `PATCH`, no `multipart` bodies, no
  `SameSite` bypass.
- **Testing the `SameSite` attribute itself.** WebVigil's client is not a browser: it
  cannot show whether a browser would attach the cookie. The passive `SameSite` weighting of
  007 stays and still applies (RF-09).
- **Exploitation.** One benign replay proves the server does not check; WebVigil builds no
  attacker page, no auto-submitting HTML, no chained request.
- **Business-logic confirmation.** Whether the accepted submission *did* something harmful
  is the operator's judgment; the finding says the server accepted it.
- **Destructive forms.** A form that looks like it deletes, removes or disables something is
  skipped, not replayed (RF-04).
- **Web API / dashboard changes.** Engine and CLI only, following 006–016.

## Personas

| Persona | Needs from 017 |
|---|---|
| **Security-conscious developer** | "Is my token actually checked?" A finding for the form that accepted the replay, and — through the passive finding being replaced — an end to "no token" alerts for endpoints that reject the replay. |
| **Pentester / consultant** | A fast, honest first pass over every state-changing form of an authenticated session, with the evidence (control vs replay) ready to paste into a report. |
| **CI pipeline author** | A deterministic, bounded check that can run against a disposable staging copy with `--confirm-csrf`, and stay out of the default run. |
| **Check author / contributor** | `CsrfScanner` as the reference for "submit, mutate, compare, refuse to guess" — the control-versus-replay shape. |

## Functional requirements

### Candidate selection

#### RF-01 — Which forms are tested

- **Given** an Active scan with the opt-in on and `csrf.form.token-not-enforced` selected
  **When** the `CsrfScanner` pass runs
  **Then** it considers every form in the inventory that is a `POST` to an in-scope action
  with enctype `application/x-www-form-urlencoded`, and is **not** an auth form
  (`is_auth_form`) or a search form (`looks_like_search`) — the same candidates as the
  passive check, narrowed to the body type the pass can rebuild faithfully.
- **Given** a form with a file input, a `multipart/form-data` or `text/plain` enctype, or a
  non-`POST` method
  **Then** it is skipped; the skip count is reported in the pass summary (RF-08).
- **Given** the same `(method, action, field names)` form on several pages
  **Then** it is tested once.

#### RF-02 — Bounded work

- **Given** a scan with many candidate forms
  **Then** the pass tests at most a fixed number of forms (the cap, set in the design, in
  inventory order) and at most five requests per form; the pass respects the scan's
  politeness settings (concurrency cap, per-host delay) through the shared `HttpClient`.
- **Given** the cap is reached
  **Then** the remaining forms are counted as "not tested (cap)" in the summary, never
  silently dropped.

#### RF-03 — Benign field values only

- **Given** a form field with a default value
  **Then** the pass submits that value unchanged; a field with no default gets a fixed,
  benign sentinel (one that carries a `webvigil` marker so an operator can find and delete
  the test data).
- **Given** the form
  **Then** the pass never submits an injection payload, never mutates a field other than the
  token, and never fills a `password` / `file` field with anything but its default.

#### RF-04 — Destructive and auth-shaped forms are skipped

- **Given** a form whose action or field names or submit-button text match the destructive
  vocabulary of `webvigil.crawler.safety` (`delete`, `remove`, `destroy`, `revoke`,
  `deactivate`, `disable`, `unsubscribe`, `cancel`, `purge`, `wipe`, `logout`, …)
  **Then** the pass does not replay it, whatever its token situation; the skip is counted in
  the summary. A false skip is the conservative error.
- **Given** an auth form (login, registration, password reset)
  **Then** it is excluded for the same reason it is excluded from the passive check.

### The experiment

#### RF-05 — Control

- **Given** a candidate form
  **When** the pass starts its experiment
  **Then** it first fetches the form's **source page** again (`GET form.source_url`) — so the
  token, if any, is fresh — re-parses that one form, and submits it with default values and
  the fresh token as a same-origin `POST` (no foreign headers). The response is the
  **control**.
- **Given** the source page no longer contains the form, or the fetch fails
  **Then** the form is **inconclusive** (RF-08) and the experiment stops there.
- **Given** the control is a rejection — status `4xx`/`5xx`, a redirect back to a login page,
  or a body that matches a rejection marker (CSRF / token / forbidden / expired / invalid /
  session)
  **Then** the form is **inconclusive**: WebVigil could not make the form accept even a valid
  submission (for instance because the token is bound to a session the scan does not hold),
  so there is nothing to compare a replay to.

#### RF-06 — Attack replay

- **Given** the control was accepted
  **When** the form has a token field (`_is_token_field`, the 007 name heuristic)
  **Then** the pass sends two replays, each carrying a **foreign `Origin` and `Referer`**
  (the `webvigil.invalid` sentinel, spec 012): one with the token field **removed**, one with
  its value **altered** (same length, different characters).
- **Given** the form has no token field
  **Then** it sends one replay: the default submission with the foreign `Origin` / `Referer`.
- **Given** a replay
  **Then** it is sent with the same cookies the control used (the scan's configured
  `[auth]` cookies and nothing else — the client already discards what the target sets), and
  the pass honours the scan's rule that a configured credential header is never overwritten.
- **Given** the replay
  **Then** it is a single `POST`, never retried on a `5xx` or a read timeout (a
  non-idempotent request, already the `HttpClient` rule).

#### RF-07 — Verdict

- **Given** the control and a replay
  **When** the replay response is **equivalent** to the control — same status class, same
  redirect target (modulo query), and a body that matches the control after normalising the
  parts that legitimately vary (the token, timestamps, request ids, the echoed sentinel)
  **Then** the form is **confirmed**: the server accepted a cross-site-shaped submission
  without a valid token.
- **Given** the replay is a rejection (RF-05's markers), or differs from the control in status
  class or redirect target
  **Then** the form is **refuted** for that replay; if every replay is refuted the form is
  refuted.
- **Given** the control and replays are all accepted-looking but the bodies differ in a way
  the normalisation cannot explain
  **Then** the form is **inconclusive** — never confirmed on a hunch.
- **Given** any verdict other than confirmed
  **Then** no finding is created from this pass.

#### RF-08 — Pass summary, not noise

- **Given** a completed pass
  **Then** it adds one scan warning with the tallies — `N tested: A confirmed, B refuted,
  C inconclusive, D skipped, E not tested (cap)` — so an operator can see that "no finding"
  means "tested and rejected" rather than "never ran". No warning when the pass did not run.

### Findings

#### RF-09 — `csrf.form.token-not-enforced`

- **Given** the check registry
  **Then** `csrf.form.token-not-enforced` is registered: `category = CSRF`, `mode = ACTIVE`,
  `default_severity = MEDIUM`, `cwe = (352,)`, references to the OWASP CSRF page and the WSTG
  CSRF test.
- **Given** a confirmed form
  **Then** the check emits one finding per form, with `Location(url=form.action,
  method="POST")`, a title naming the action ("POST form to /settings accepted a cross-site
  request without a valid anti-CSRF token"), a description saying what was proved and what was
  not, the remediation (enforce a per-session token, verify `Origin` / `Referer`, set
  `SameSite`), and `EvidenceItem`s for: the form and where it was found, the replay that
  succeeded (token removed / altered / no token field), the control and replay status and
  redirect targets, and whether the scan carried credentials.
- **Given** the finding
  **Then** its confidence weighs the session cookie's `SameSite` exactly as 007 does (`HIGH`
  with no `SameSite`, `LOW` with `Lax` / `Strict`, `MEDIUM` with none observed) — a server
  accepting the replay does not prove a browser would send the cookie — and is capped at
  `MEDIUM` when the scan carried no configured credential (an anonymous form accepting an
  anonymous post is spam surface, not necessarily CSRF).
- **Given** a scan with no confirmed form
  **Then** the check emits nothing.

#### RF-10 — Relationship with `csrf.form.no-token`

- **Given** a form for which the passive check emitted `csrf.form.no-token` and the active
  pass **confirmed** it
  **Then** exactly one finding is reported for that form: the active one (decision in **Open
  question 3**).
- **Given** a form the active pass refuted or left inconclusive
  **Then** the passive finding is unchanged — same id, title, fingerprint, confidence — and
  the active pass adds nothing to it.
- **Given** a form with a token field that the active pass confirmed unenforced
  **Then** it yields one `csrf.form.token-not-enforced` finding, even though the passive
  check was silent about it.
- **Given** a scan without the opt-in
  **Then** `csrf.form.no-token` findings are byte-identical to before 017.

#### RF-11 — Gate, opt-in and suppression

- **Given** a `safe` (passive) scan, or an Active scan without the opt-in
  **Then** the pass does not run, no form is submitted, no request is made on its behalf, and
  `csrf.form.token-not-enforced` produces nothing.
- **Given** the opt-in is on but the scan is not Active
  **Then** the scan is refused at the gate with the same error as any Active request, not
  silently downgraded.
- **Given** `[checks] disabled = ["csrf.form.token-not-enforced"]`
  **Then** the pass does not run.
- **Given** `webvigil list-checks`
  **Then** `csrf.form.token-not-enforced` appears as `CSRF` / `active` / `MEDIUM`.

### Fixture app and tests

#### RF-12 — Vulnerable and hardened forms

- **Given** the fixture's **insecure** profile
  **Then** it exposes at least these `POST` endpoints, linked from the shared link block:
  one with **no token field** that accepts anything; one with a **token field the server
  ignores**; and — present in both profiles — one that **enforces** a token and answers a
  missing or altered token with `403`, and one that **checks `Origin`** and rejects the
  foreign one with `403`.
- **Given** the **hardened** profile
  **Then** the no-token and ignored-token endpoints enforce their token, so the pass
  finds nothing.
- **Given** the endpoints
  **Then** tokens are deterministic per process (no random state a test cannot read), and each
  accepting endpoint's response differs from its rejection in status class.

#### RF-13 — Integration tests

- Active scan of the insecure profile with the opt-in → `csrf.form.token-not-enforced` for
  the no-token and ignored-token forms; none for the enforcing and `Origin`-checking forms;
  the pass summary warning carries the right tallies.
- The same scan **without** the opt-in → no `POST` reaches the new endpoints and no
  `csrf.form.token-not-enforced` finding; `csrf.form.no-token` unchanged.
- Passive scan → nothing new, no crafted request.
- Active scan of the hardened profile with the opt-in → zero `csrf.form.token-not-enforced`.
- A confirmed form yields one finding, not the active one plus the passive one (RF-10).
- Deterministic across repeated runs; within the form and request caps.

#### RF-14 — Unit tests

- Candidate filter: each skip reason (non-`POST`, `multipart`, file input, auth, search,
  destructive, off-scope), and per-form de-duplication.
- Control: rejected control → inconclusive; source page without the form → inconclusive.
- Replay shape: token removed, token altered (same length, different), no-token form (one
  replay), foreign `Origin` / `Referer` present, configured cookies present, nothing else
  added.
- Verdict: equivalent → confirmed; rejection marker → refuted; different status class →
  refuted; unexplained body difference → inconclusive; normalisation of the token, timestamp
  and echoed sentinel.
- Confidence: `SameSite` none / Lax / Strict / unobserved × credentials configured or not.
- Dedup against the passive check (RF-10) and the summary tallies (RF-08).

### Reporting and docs

#### RF-15 — Reporters unchanged

- No reporter gains a field or a section. The finding flows through the same `Check` →
  `Finding` path as every other; a saved canonical JSON re-renders offline exactly as before.

#### RF-16 — Docs

- `docs/authenticated-scanning.md`: the "Active CSRF confirmation" bullet leaves "What is
  deferred"; a new "Active CSRF confirmation" section explains the experiment, the
  opt-in, what is written to the target, the verdicts and the blind spots (RF-17).
- `docs/active-injection.md` (checks table and coverage notes) and the CLI flag reference;
  `README.md` (`v0.17` row, "Scope and limitations"), `CLAUDE.md`, `docs/stack.md` if it
  names the passes, and the `specs/README.md` roadmap row.

#### RF-17 — Documented blind spots

- The docs state, in one place, what the pass cannot see: a token bound to a session the scan
  does not hold, one-time tokens that make the control and the replay differ, multi-step
  forms, forms that always answer `200` with the same page whether or not they succeeded, a
  server that validates `Origin` only when it is present, and everything a real browser
  would add (cookies from `SameSite`, `Sec-Fetch-*`). Each one resolves toward
  *inconclusive* or *no finding*, never toward a false confirmation.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.checks.csrf` (`scanner.py`, additions to `checks.py`) plus the
orchestrator wiring, config and CLI flag. Detection is `re` + the existing HTTP layer; **no
new runtime dependency**. The engine imports nothing from `webvigil.cli` / `webvigil.api` /
`web/`; `import-linter` unchanged.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy` covering the new
module. No `web` gate work.

**RNF-03 — Safe by default**
A passive scan, and an Active scan without the opt-in, is byte-for-byte unchanged and
submits no form. The pass runs only past `--mode active --authorized-by` **and** the opt-in.
It writes to the target (up to three submissions per form); the CLI help, the docs and the
pass summary say so, the way `--stored-xss` and `--file-upload` do.

**RNF-04 — Bounded work**
A cap on forms and a cap of five requests per form, both constants set and justified in the
design. The pass draws on no shared injection budget; it has its own.

**RNF-05 — Determinism and false-positive discipline**
Every confirmation needs an accepted control **and** an equivalent replay; every other
outcome is a non-finding. The hardened profile yields zero findings. Findings and
fingerprints are stable across runs (the fingerprint is the form action, as in 007).

**RNF-06 — Scope guard intact**
Every request, including the foreign-`Origin` replay, goes to an in-scope target URL through
the `HttpClient`. The foreign `Origin` / `Referer` are *header values*, never a request
destination: no new host is contacted.

**RNF-07 — Secrets**
Configured cookies are attached by the client as today and never copied into evidence, logs
or the summary; the evidence records only whether credentials were present.

**RNF-08 — Python support**
No syntax or API newer than the project's Python floor; the CI matrix and `requires-python`
are unchanged.

## Resolved decisions

1. **A control request is required.** Judging a replay by an absolute rule ("`200` means
   accepted") cannot tell success from a validation page that also answers `200`. Comparing
   against a control the scan itself provoked is the only in-band oracle; the cost is one
   extra write per form.
2. **The replay is cross-site-shaped.** It carries a foreign `Origin` and `Referer`, so a
   server that checks them is not reported. Without that, the check would flag exactly the
   defences it is meant to credit.
3. **The token is removed *and* altered.** Servers fail in both ways (presence checked,
   value not; value checked, absence mishandled), and the two replays are cheap.
4. **Refuse to guess.** `confirmed` needs an accepted control and an equivalent replay;
   `refuted` and `inconclusive` both produce no finding. The pass summary keeps "tested and
   rejected" distinguishable from "never ran".
5. **Credentials are the scan's, not the pass's.** No automated login (issue #52), no
   per-experiment cookie jar. A control that fails for want of a session is inconclusive.
6. **Anonymous confirmation is capped at `MEDIUM`.** CSRF needs ambient authority; with no
   configured credential the replay proves the form accepts an anonymous post, which is
   weaker than a hijackable session. The `SameSite` weighting of 007 applies on top.
7. **New check id, `csrf.form.token-not-enforced`.** It covers both "no token" and "token
   ignored", so it is neither a refinement of `csrf.form.no-token` nor a variant of it, and
   it suppresses independently.

## Open questions

1. **Opt-in switch.** Does the pass need its own switch on top of `--mode active
   --authorized-by`? **Proposed: yes** — `--confirm-csrf` / `[injection] csrf_confirm`,
   default off. It writes to the target up to three times per form (008 and 014 gated their
   writes the same way); issue #54 asked only for the Active gate, which would otherwise
   mean every Active scan starts submitting forms, and adding a pass whose default is
   "writes data" to the Active baseline would surprise anyone already running it.
2. **Session-bound tokens.** The `HttpClient` discards what the target sets via
   `Set-Cookie`, so an anonymous scan cannot hold the session a token is bound to, and the
   control is rejected. **Proposed: leave it** — the form is inconclusive, and authenticated
   scans work through `--cookie` today and through automated login (#52) later. The
   alternative is an experiment-scoped cookie jar (fetch the form, keep its `Set-Cookie`,
   replay with it, discard it afterwards): it widens coverage to anonymous session-bound
   forms but breaks the 007 rule that a scan sends exactly what is configured, so it is not
   proposed for 017.
3. **What happens to the passive finding.** **Proposed:** a confirmation *replaces* the
   passive `csrf.form.no-token` finding for the same form (one finding per proof, as 016
   did for `ssti` / `el`); a refutation or an inconclusive result leaves the passive finding
   untouched. The alternative — keeping both, or also deleting the passive finding when the
   replay is refuted — either duplicates the report or turns a "could not tell" into a
   silent suppression of a finding WebVigil cannot actually rule out, so neither is
   proposed.
