---
feature: Active CSRF confirmation — replay a state-changing form without a valid token (Active Mode)
status: done
date: 2026-10-06
related:
  - 017-csrf-confirmation/requirements.md
  - 007-auth-flows/design.md
  - 014-file-upload/design.md
  - 012-protocol-injection/design.md
origin: conception
---

# 017 — Active CSRF confirmation — design

## Overview

017 adds one check, `csrf.form.token-not-enforced`, and one orchestrator pass,
`CsrfScanner`, that feeds it. The pass is modelled on spec 014's `UploadScanner`: it is not a
detector inside the `InjectionScanner`, because it does not fuzz a parameter — it runs a
short, stateful **experiment per form** (fetch → control → attack replays → verdict) and
needs its own caps (ADR-1).

```
Orchestrator.run
  crawl → forms ─┬─ … injection / stored-XSS / envelope / upload passes …
                 └─ _scan_csrf (LAST pass, only Active + opt-in + check selected)
                          │  CsrfScanner(http, target, config, pages, forms).run()
                          ▼
                   Observations.csrf_hits ──► TokenNotEnforcedCheck  → Finding
                                         └──► NoCsrfTokenCheck       skips confirmed forms
```

Per candidate form, at most four requests (cap five), and never more than 20 forms per scan:

```
1. GET  form.source_url                       fresh page → fresh token, re-parse the form
2. POST action  same-origin Origin/Referer     CONTROL   (default values + fresh token)
3. POST action  foreign Origin/Referer         REPLAY A  token field(s) removed
4. POST action  foreign Origin/Referer         REPLAY B  token field(s) altered
                                               (no token field → one replay: default body)
```

The verdict is `confirmed` only when the control was an acceptance and a replay is
equivalent to it. The experiment stops at the first confirmation (fewest writes to the
target), at an inconclusive control, or after both replays are refuted.

## Module layout

```
src/webvigil/checks/csrf/
├── tokens.py       NEW  is_token_field(), is_candidate()   (moved out of checks.py; both the
│                        passive check and the pass use them — no import cycle)
├── scanner.py      NEW  CsrfScanner, CsrfHit, Verdict, _Shape, body normaliser
├── checks.py       + TokenNotEnforcedCheck; NoCsrfTokenCheck skips confirmed forms
└── __init__.py     docstring mentions the pass

src/webvigil/crawler/safety.py   + is_destructive_form(form), is_login_url(url)
src/webvigil/core/config.py      + InjectionSection.csrf_confirm: bool = False
src/webvigil/core/context.py     + Observations.csrf_hits: tuple[CsrfHit, ...]
src/webvigil/core/orchestrator.py+ _scan_csrf, the warning for opt-in outside Active Mode
src/webvigil/cli/app.py          + --confirm-csrf / --no-confirm-csrf
src/webvigil/cli/_render.py      + summary notes (writes happened; confirmed count)
tests/fixtures/app.py            + /panel and four POST routes (both profiles)
```

`webvigil.api` and `web/` are untouched: `csrf_confirm` defaults to `False`, the API never
sets it, and `csrf.form.token-not-enforced` appears in the checks catalogue through the
existing registry listing.

## Data model

```python
type Verdict = Literal["confirmed", "refuted", "inconclusive"]

@dataclass(frozen=True, slots=True)
class CsrfHit:
    """One form the server accepted without a valid token."""
    url: str                    # the form action (finding location, fingerprint)
    source_url: str             # page the form was found on
    replay: str                 # "token removed" | "token altered" | "no token field"
    token_fields: tuple[str, ...]
    control: str                # "POST /newsletter -> 302 -> /panel (200)"
    attack: str                 # same shape, for the replay that was accepted

@dataclass(frozen=True, slots=True)
class _Shape:
    """What one POST answered, reduced to what the verdict compares."""
    first_status: int           # status of the response to the POST itself (history[0])
    final_status: int
    final_path: str             # URL path after redirects, query dropped
    body: str                   # normalised text
    rejected: bool              # status >= 400, login redirect, or a rejection marker
```

No new `Finding` field, no new category, no change to the canonical JSON.

## Components

### Candidate selection (`CsrfScanner._candidates`)

Forms are taken from the inventory in order and de-duplicated on
`(method, action, field names)`. A form is **skipped** (counted, not tested) when any of:

| Skip reason | Predicate |
|---|---|
| not a `POST`, or not urlencoded | `form.method != "POST"` or `form.enctype != "application/x-www-form-urlencoded"` |
| has a file input | any field `type == "file"` |
| auth or search form | `is_auth_form` / `looks_like_search` (via `is_candidate`, shared with the passive check) |
| destructive | `is_destructive_form(form)` — new, below |
| over the cap | already 20 forms tested (counted separately) |

`is_destructive_form` in `crawler/safety.py` flattens the action's path and query, every field
name and the value of every named `submit` / `button` input, replaces `_` and `-` with a
space (so `delete_account` matches — the existing `\b…\b` regex does not see through an
underscore), then applies `_DESTRUCTIVE_RE` and `_LOGOUT_RE`. It does **not** see a `<button>`
element's text: `parse_forms` only collects named `input` / `textarea` / `select` controls, and
extending `Form` is out of scope (a deviation from RF-04's "submit-button text", recorded
below). The error direction is conservative only for named controls; the gap is documented.

### Building the submission (`_build_body`)

The form is rebuilt from the **re-fetched** form's fields, in parser order:

| Field | Value sent |
|---|---|
| `hidden`, `select`, checked `checkbox` / `radio` | its default (so the token travels as served) |
| unchecked `checkbox` / `radio` | omitted, as a browser omits it |
| `password` | its default (usually empty) — never filled |
| `file` | form skipped earlier |
| named `submit` / `button` input | the first one, with its value (a browser sends the clicked button) |
| `text`, `search`, `textarea`, `""` with no default | `wvcsrf<tok><suffix>` |
| `email` with no default | `wvcsrf<tok><suffix>@webvigil.invalid` |
| `url` / `number` / `tel` / `date` with no default | `https://webvigil.invalid/` / `1` / `0` / `2000-01-01` |
| any field with a default | the default, unchanged |

`<tok>` is one `secrets.token_hex(4)` per pass, so an operator can find the test data with
`wvcsrf<tok>`; `<suffix>` is `c` for the control and `r1` / `r2` for the replays so a
uniqueness constraint ("already subscribed") does not make the replay differ from the control
for a reason unrelated to the token.

Token fields (`is_token_field`, the 007 name heuristic) are the **only** thing a replay
changes:

- **removed** — every token field is dropped from the body;
- **altered** — every token field keeps its name and gets `_alter(value)`: each letter and
  digit is shifted to the next one of its class (`a→b … z→a`, `0→1 … 9→0`), other characters
  are kept; a value with no letter or digit becomes `x` repeated to its length (minimum 8).
  Same length, guaranteed different.

### Headers

The control sends what a browser sends from the target's own page:
`Origin: <scheme>://<netloc of the target>` and `Referer: <form.source_url>`. A replay sends
`Origin: https://webvigil.invalid` and `Referer: https://webvigil.invalid/` — the sentinel
spec 012 already puts in `Host` / `X-Forwarded-*`, and a *header value*, never a destination
(RNF-06). `Content-Type` is left to `httpx` (`data=` → urlencoded). Configured `[auth]`
cookies are attached by the client as for every request; a configured header is never
overwritten (the client's existing rule).

### Verdict (`_shape`, `_equivalent`, `_judge`)

`_shape(response)` reduces a `Response` (the client already follows in-scope redirects and
keeps the hops in `history`):

- `first_status` = `history[0].status` when there were redirects, else `status_code` — the
  server's answer to the POST itself;
- `final_status`, `final_path` (query dropped);
- `body` = the normalised text: the pass's sentinel (`wvcsrf<tok>[a-z0-9]{1,2}`), every token
  value the pass saw in the form, hex runs of 16+, ISO-like timestamps and digit runs of 9+
  are removed, whitespace collapsed;
- `rejected` = `first_status >= 400 or final_status >= 400`, **or** `is_login_url(final)`
  when the form is not itself a login page, **or** the body matches `_REJECTION_RE`:

```
csrf | xsrf | cross[- ]site request | forbidden |
(invalid|missing|expired|bad|mismatch\w*)\W+(\w+\W+){0,2}(token|csrf|origin|referer) |
(token|csrf|origin|referer)\W+(\w+\W+){0,2}(invalid|missing|expired|required|mismatch\w*) |
session\W+(\w+\W+){0,2}expired
```

`_equivalent(control, replay)` is true when neither is rejected, `first_status // 100` and
`final_path` match, and the bodies are similar: the word-token lists (`\w+` and single
punctuation marks, capped at 6000 tokens each) have `difflib.SequenceMatcher.ratio() >= 0.95`
and their lengths differ by at most 10 %. Word tokens, not characters, so the cost stays
linear-ish on a large page and a minified one-line HTML is not one giant token.

`_judge(control, replays)`:

- the control is `rejected` → **inconclusive** (no replay is sent);
- any replay `_equivalent` to the control → **confirmed** (the first one wins, and the
  experiment stops there);
- every replay `rejected`, or with a different status class or final path → **refuted**;
- anything else (same class and path, bodies differ) → **inconclusive**.

### Pass summary (RF-08)

`CsrfScanner.warnings` carries one line, appended by the orchestrator:
`CSRF confirmation: 7 forms tested — 2 confirmed, 3 refuted, 2 inconclusive, 4 skipped, 1 not
tested (cap)`. No line when the pass did not run or the inventory had no `POST` form.

### The checks (`checks.py`)

`TokenNotEnforcedCheck` (`id = "csrf.form.token-not-enforced"`, `category = CSRF`, `mode =
ACTIVE`, `default_severity = MEDIUM`, `cwe = (352,)`, the OWASP CSRF page and the WSTG
reference the passive check already uses). It issues no request. One finding per hit:

- `Location(url=hit.url, method="POST")`, `dedup_key = "not-enforced"`;
- title: `POST form to <action> accepted a cross-site request without a valid anti-CSRF token`;
- evidence: `form` (`POST <action> (found on <source_url>)`), `replay` (`token removed` /
  `token altered` / `no token field`), `control` and `attack` (the two shape summaries),
  `credentials` (`session cookies configured` / `none — anonymous replay`);
- confidence — `_CONFIDENCE[samesite]` exactly as the passive check weighs it
  (`_session_samesite(ctx.pages)`), then **capped at `MEDIUM` unless `config.auth.cookies`
  is non-empty** (ADR-5).

`NoCsrfTokenCheck.run` gains one filter: it skips a form whose action is in
`{hit.url for hit in ctx.observations.csrf_hits}` (ADR-4). The check, ids, titles and
fingerprints of every finding it still emits are untouched.

### Orchestrator and CLI wiring

`Orchestrator._scan_csrf` copies `_scan_upload`: no-op unless `scan.mode is ACTIVE`,
`injection.csrf_confirm` is on and `csrf.form.token-not-enforced` is among the selected
checks; a pass exception becomes a warning `CSRF confirmation pass failed: …`. It runs
**after** the upload pass — last — because it is the only pass whose requests change server
state (ADR-6). `run()` adds the warning `CSRF confirmation requires --mode active — the CSRF
pass did not run` when the switch is on outside Active Mode (the existing 008 / 014 pattern;
ADR-7).

`InjectionSection.csrf_confirm: bool = False` sits beside `file_upload`; the CLI option is
`--confirm-csrf/--no-confirm-csrf`, wired through `_build_config` and `_run_scan` like
`file_upload`. `_render.summary` prints, in Active Mode with the pass on, a dim note
(`CSRF confirmation: enabled — each tested form was submitted up to 3 times; test data
marked "wvcsrf" was left on the target`), and a red line `CSRF confirmed: N form(s) accepted a
cross-site replay without a valid token` when any `csrf.form.token-not-enforced` finding
exists. The passive "CSRF: N forms without an anti-CSRF token" line keeps counting only
`csrf.form.no-token`.

## Interfaces

- **CLI:** `webvigil scan <url> --mode active --authorized-by "<who>" --confirm-csrf
  [--cookie "name=value"]`. No new exit code.
- **Config:** `[injection] csrf_confirm = true`.
- **Library:** `webvigil.checks.csrf.scanner.CsrfScanner(http, target, config, pages,
  forms).run() -> list[CsrfHit]`; `.warnings: list[str]`.
- **Check id:** `csrf.form.token-not-enforced`, suppressible through `[checks] disabled`.
- **Web API / OpenAPI:** unchanged.

## ADRs

### ADR-1 — A separate pass, not a detector in the `InjectionScanner`

- **Decision:** `CsrfScanner` is an orchestrator pass with its own caps, run after the other
  passes.
- **Alternatives:** an `InjectionScanner` detector kind (`csrf`) enumerating `POST` points.
- **Why:** the injection pass fans stateless payloads over *injection points* under one shared
  request budget and one baseline per point. This experiment is a sequence on a *form* — fetch,
  submit, mutate, compare — with its own safety filter and its own writes. Forcing it into the
  detector shape would tie it to the injection budget (and re-open the per-point cap that 016
  just measured) for no reuse. `UploadScanner` is the precedent for exactly this shape.
- **Trade-off:** one more pass to wire in the orchestrator, and the form inventory is read
  twice (injection fuzzes it, this confirms it).

### ADR-2 — Judge a replay against a control, with a conservative rejection predicate

- **Decision:** confirm only when the control is not `rejected` and a replay is `_equivalent`
  to it; every uncertain outcome is *refuted* or *inconclusive*, never a finding.
- **Alternatives:** an absolute rule (`2xx`/`3xx` ⇒ accepted); a negative control (a request
  known to be rejected) to calibrate.
- **Why:** an absolute rule cannot tell success from a `200` validation page. A negative
  control needs a request the server is *guaranteed* to reject, which a black-box scanner
  cannot construct without guessing form semantics. The control is the one baseline WebVigil
  can obtain by itself.
- **Trade-off:** one extra state-changing request per form; a form that answers the same page
  whether or not it saved reads as *confirmed* (documented, RF-17), and a form whose control
  changes the state the replay depends on reads as refuted or inconclusive (the safe error).

### ADR-3 — Cross-site-shaped replays, same-origin control

- **Decision:** the control sends the target's own `Origin` / `Referer`; replays send
  `webvigil.invalid`.
- **Alternatives:** send no `Origin` on either; send the foreign `Origin` on every request.
- **Why:** an `httpx` request carries no `Origin` by default, and a server that checks the
  header only when present would accept it — a false confirmation for exactly the defence we
  want to credit. A foreign `Origin` on the *control* would make "token or origin" ambiguous.
- **Trade-off:** a server that requires neither header and accepts the foreign one is
  confirmed, which is correct; a server that checks `Referer` by regex on the host could treat
  `webvigil.invalid` differently from a real attacker's host — immaterial for a deny-list that
  is not the target's own host.

### ADR-4 — The passive check yields to a confirmation, inside the check

- **Decision:** `NoCsrfTokenCheck` skips forms whose action is in `observations.csrf_hits`.
- **Alternatives:** a post-processing step in the orchestrator that drops passive findings; a
  fingerprint collision so `_dedupe` picks one.
- **Why:** checks already read `Observations`; the filter is three lines, local to the passive
  check, order-independent, and leaves the finding model alone. `_dedupe` works on fingerprints
  that include the check id, so it cannot merge two different ids.
- **Trade-off:** the passive check now depends on a field only the Active pass fills; with no
  hits it behaves exactly as in 007 (RF-10).

### ADR-5 — "Credential" for the confidence cap means a configured cookie

- **Decision:** the `MEDIUM` cap lifts only when `config.auth.cookies` is non-empty;
  `--header` alone does not lift it.
- **Alternatives:** any configured credential (cookie or header), as RF-09 reads.
- **Why:** CSRF rides *ambient* authority — the browser attaches the cookie by itself. A
  bearer header is never sent by a cross-site form, so an accepted replay carrying one proves
  nothing about CSRF. A header-only scan is therefore weighed like an anonymous one.
- **Trade-off:** a scan that authenticates by a header **and** needs a cookie for the form is
  capped; the evidence line says which credentials were present so the operator can judge.

### ADR-6 — The pass runs last

- **Decision:** `_scan_csrf` follows `_scan_upload`.
- **Why:** it is the one pass whose requests mutate server state (a control, and up to two
  replays, per form). Running it after the injection, stored-XSS, envelope and upload passes
  means a record it created cannot appear in their baselines.
- **Trade-off:** none worth recording.

### ADR-7 — Opt-in outside Active Mode is a warning, like 008 and 014

- **Decision:** `--confirm-csrf` without `--mode active` adds a warning and the pass does not
  run.
- **Alternatives:** refuse the scan (RF-11's second bullet as written).
- **Why:** `--stored-xss` and `--file-upload` already behave this way and the three flags
  should not disagree; the pass still cannot run without the Active gate, so nothing is sent.
- **Trade-off:** a CI run that forgets `--mode active` succeeds with a warning instead of
  failing. See "Deviations".

### ADR-8 — Word-token similarity for the body comparison

- **Decision:** compare word-token lists with `SequenceMatcher.ratio() >= 0.95` plus a 10 %
  length guard, after normalising the volatile parts.
- **Alternatives:** exact equality after normalisation; character-level `ratio()`; a hash of
  the DOM structure.
- **Why:** exact equality fails on a page that lists the record just created (the control and
  the replay each add a row); character-level `ratio()` is slow on a 100 KB page; a DOM hash
  needs a parser pass and still differs on that new row. A 95 % token match tolerates one row
  and still tells a form page from a "saved" page.
- **Trade-off:** a threshold is a heuristic. It errs toward *inconclusive* (bodies that differ
  more than 5 % with the same status and path never confirm).

## Fixture app

A new page, `/panel`, is linked from the shared link block (so both profiles crawl it) and
carries four `POST` forms. The routes keep the fixture's rules: every response HTML-escapes
what it echoes (no incidental XSS), tokens are one constant per process (`wvfixturetoken`),
and `app.state.csrf_log` records each **accepted** post as `(route, token present, Origin)` so
tests can assert how many writes the pass caused.

| Route | Insecure profile | Hardened profile | Expected |
|---|---|---|---|
| `POST /newsletter` (`email`, `topic`) | **no token field**, accepts anything; `302` → `/panel?saved=newsletter` | token field, `403` without the right token | insecure: **confirmed** (and the passive finding is replaced); hardened: refuted |
| `POST /settings` (`display_name`, `csrf_token`) | token field **ignored**; `200` echoing the name | token enforced (`403`) | insecure: **confirmed**; hardened: refuted |
| `POST /transfer` (`to_account`, `amount`, `csrf_token`) | token enforced (`403` missing or altered) | same | refuted in both |
| `POST /prefs` (`theme`, `csrf_token`) | token ignored, **`Origin` checked** (`403` when it is not the request host) | same | refuted in both |

`/transfer` is excluded from the injection pass by its `_EXCLUDE_FORM_RE` (`transfer`), so the
only new injection load is `/newsletter`, `/settings` and `/prefs`; the budget impact is
re-measured in the task list.

## Request budget

`_MAX_FORMS = 20`, `_PER_FORM_CAP = 5` (counted on requests the pass issues; redirect hops the
client follows inside one `request()` are not counted). Typical form: 4 requests; token-less
form: 3; rejected control: 2. Worst case 100 requests, drawn from no shared injection budget.
The politeness settings (concurrency cap, per-host delay) apply through the client. The two
constants are not config keys: nothing in the issue asks for them, and `[injection]
csrf_confirm` already decides whether the pass exists. If a real site needs more forms, a key
is a one-line follow-up.

## Impact on existing code

- `checks/csrf/checks.py`: `_is_token_field` / `_is_candidate` move to `tokens.py` (public
  names); the passive check imports them. Its findings are unchanged except for the
  `csrf_hits` filter.
- `crawler/safety.py`: two additive predicates; `_DESTRUCTIVE_RE`, `is_auth_form` and the
  crawler's use of them are untouched.
- `core/config.py`, `context.py`, `orchestrator.py`: additive fields and one pass.
- `cli/app.py`, `cli/_render.py`: one option, two summary notes.
- Tests that count registered checks, list the `[injection]` defaults, or count the fixture's
  crawled pages need their numbers updated (page count +1 for `/panel`).
- The fixture's insecure and hardened pages gain a link; no existing route changes.

## Risks

- **It writes to the target.** A control and up to two replays per form create or change
  records. Mitigated by the opt-in, the destructive / auth / search filter, the 20-form cap,
  the stop-at-first-confirmation rule, benign sentinel data marked `wvcsrf<tok>`, and the docs
  saying so. Not mitigated: a benign-looking form that has a real side effect (an email send).
- **Static HTML only.** A token added by JavaScript is absent from the re-fetched form, so
  the control submits without it: a server that enforces the token rejects the control
  (inconclusive); one that does not is confirmed — correctly.
- **Session-bound tokens** (no per-experiment cookie jar): the control is rejected →
  inconclusive; authenticated scans through `--cookie` are the supported path.
- **Rejection heuristics are English-centric.** A localised `403` page without a marker still
  has its status code; a localised `200` rejection page does not, and reads as confirmed only
  when it is also similar to the control — which a rejection page is not.
- **A threshold that is wrong for some site** (ADR-8) fails toward *inconclusive*.

## Test strategy

- **Unit — `test_csrf_scanner.py`** (a `_FakeHttp` recording `GET` / `POST` calls, headers and
  bodies, in the style of `test_upload_scanner.py`): candidate filter, one case per skip
  reason and the de-dup; `_build_body` for each field type and the suffixes; `_alter` (same
  length, always different, no-alphanumeric case); control rejected → inconclusive with no
  replay sent; source page without the form → inconclusive; replay shape (token removed,
  altered, no-token form sends exactly one, foreign `Origin` / `Referer` on replays only,
  same-origin on the control, no body field changed but the token); verdicts (equivalent,
  rejection marker, different status class, different path, unexplained body difference);
  normaliser (sentinel, token, timestamp, hex); stop at the first confirmation; the 20-form
  and 5-request caps; the summary tallies; a scan with no `POST` form emits no warning.
- **Unit — `test_checks_csrf.py`:** `TokenNotEnforcedCheck` finding shape, `SameSite` × cookies
  configured / not (the `MEDIUM` cap), no hits → no findings; `NoCsrfTokenCheck` skips a
  confirmed action and is byte-identical to before with no hits.
- **Unit — `test_safety.py`:** `is_destructive_form` (`delete_account`, `/items/remove`,
  a named submit with `value="Delete"`, a benign form) and `is_login_url`.
- **Unit — `test_config.py` / `test_cli.py`:** `csrf_confirm` default `False`, the TOML key,
  `--confirm-csrf`, the warning outside Active Mode, the summary notes.
- **Orchestrator:** pass skipped in a Passive scan, with the switch off, and with the check
  disabled; a pass exception becomes a warning; `csrf_hits` reaches the context; the pass
  runs after the upload pass.
- **Integration — `test_scan_fixture_app.py`** (the insecure and hardened fixture apps):
  - insecure, Active, `--confirm-csrf` → `csrf.form.token-not-enforced` on `/newsletter` and
    `/settings` only among the new routes (none on `/transfer` or `/prefs`), `/newsletter` has
    **no** `csrf.form.no-token` beside it, the summary warning has the right tallies, and
    `app.state.csrf_log` shows no accepted post that carried a foreign `Origin` for `/prefs`;
  - the same scan **without** the switch → no `POST` to `/newsletter` or `/settings`, and
    `csrf.form.no-token` still fires on `/newsletter`;
  - Passive scan → nothing new, no crafted request;
  - hardened, Active, switch on → zero `csrf.form.token-not-enforced`;
  - repeated runs are identical and stay inside the caps.
- **Gate:** `ruff → black → mypy → lint-imports → pytest` at the end of each stage.

## Deviations from the approved requirements

Each is recorded here so the requirements text stays as approved; the as-built behaviour is
the one below.

1. **RF-11, second bullet.** The opt-in without `--mode active` is a **warning and no pass**,
   not a refused scan — the 008 / 014 precedent (ADR-7).
2. **RF-04, "submit-button text".** Only the *value of a named `submit` / `button` input* is
   matched; a `<button>` element's text is not parsed into `Form` today. Underscore and hyphen
   are normalised so `delete_account` matches.
3. **RF-09, "no configured credential".** The `MEDIUM` cap lifts only for a configured
   **cookie**, not a header (ADR-5).
4. **RF-05.** The control sends explicit same-origin `Origin` / `Referer` (a refinement of
   "no foreign headers"; ADR-3).
5. **RF-06.** The two replays stop at the first confirmation (the requirement says "sends
   two"); fewer writes, same verdict.

## Implementation notes

What changed between this design and the code, and what was measured.

- **Deviations 1-5 above stand as built.** Two refinements of the design text:
  - `_judge` became `_compare` (one replay against the control) plus the loop in `_experiment`,
    which stops at the first confirmation and refutes only when every replay was refuted.
  - `GET` forms are not counted in the tally at all, and "POST forms seen" (which decides whether
    the summary line appears) counts distinct `POST` forms only.
- **The submission is a pre-encoded body, not `data=`.** httpx accepts only a mapping as a form
  body; a list of pairs raises "Attempted to send a sync request with an AsyncClient" at runtime.
  `_submit` sends `content=urlencode(pairs)` with an explicit `Content-Type:
  application/x-www-form-urlencoded`, which also keeps the field order and any repeated name.
- **The sentinel is stripped before the rejection words are searched.** `wvcsrf<token>` contains
  "csrf", so a page that echoed a field read as a rejection page and every control came back
  inconclusive. The suffix is a letter and a digit (`c0` / `r1` / `r2`) so the normaliser can
  remove it exactly.
- **Rejection words are read from the visible text.** The markup of an ordinary page carries a
  hidden `csrf_token` input; `_visible` drops scripts, styles and tags before `_REJECTION_RE`.
- **Fixture.** `/panel` and the four routes are as designed. The hardened profile also wraps its
  older POST routes (`/comment`, `/guestbook`, `/profile`, `/api/xml`) in `_token_enforced`:
  the hardened profile served tokens those routes never checked, and the pass correctly
  confirmed them. The insecure profile's older forms are therefore confirmed too (five forms in
  the manual run); the integration test asserts on `/newsletter`, `/settings` (confirmed) and
  `/transfer`, `/prefs` (not), not on the whole set.
- **Integration budget.** The spec-012 envelope sample went from 20 to 24 (budget 130 to 150) in the
  test config only: the sample takes the entry, then every form action, then the other pages, and
  four new form actions pushed `/reset` and `/resource` out. No injection budget moved.
- **Manual verification** (CLI, fixture served by uvicorn): with `--confirm-csrf`, 7 forms
  tested — 5 confirmed (`/newsletter` by "no token field", `/settings`, `/comment`, `/guestbook`,
  `/api/xml` by "token removed"), 2 refuted (`/transfer`, `/prefs`), 0 inconclusive, 2 skipped
  (login, the multipart upload). Each finding's evidence reads `credentials: none - an anonymous
  replay` and its confidence is MEDIUM (no `--cookie`). Without the switch only the passive
  `csrf.form.no-token` on `/newsletter` remains and no CSRF warning is added.
