# Authenticated scanning, CSRF detection, and form-driven crawling

Spec [`007-auth-flows`](../specs/007-auth-flows/). Three related capabilities: scanning the
target **as a logged-in user** with a cookie you supply, submitting safe `GET` forms during
the crawl to widen coverage, and a passive **CSRF** check over the discovered forms —
plus an opt-in Active confirmation of it (spec 017, below).

## Authenticated scanning

Pass one or more cookies from a browser session where you are already logged in:

```bash
webvigil scan https://app.example.com --cookie "session=<paste from devtools>"
webvigil scan https://app.example.com --cookie "sid=abc" --cookie "csrf=xyz"
```

Or in the config file (a `--cookie` flag replaces this list entirely):

```toml
[auth]
cookies = ["session=abc123"]
```

Each entry is `name=value`. The cookies are attached to every request whose host **is** the
target host, and to no other — an out-of-scope asset or a redirect that leaves scope never
receives them. Under `--scope subdomains` the cookies still go to the entry host only (a
`name=value` string carries no `Domain`, so widening it would be a guess); scan each
subdomain separately if you need that.

**Privacy.** A cookie value is held only in memory for the scan and is never written to a
report, a log line, a warning, or the scan metadata. The JSON report records
`metadata.authenticated: true` (a boolean — no names, no values, no count). The CLI summary
prints the cookie **count** and nothing more.

**Determinism.** WebVigil sends exactly the cookies you configure. It discards anything the
target sets via `Set-Cookie` during the scan, so a run is reproducible and authentication
stays entirely config-driven. (The one exception is a configured automated login, below:
the session cookies it establishes are kept and rotated.)

### Header and bearer authentication

Spec [`013-auth-and-api-surface`](../specs/013-auth-and-api-surface/). Many APIs
authenticate with a bearer token or an API-key header rather than a cookie. Pass any
request header — repeatable — with `--header`:

```bash
webvigil scan https://api.example.com --header "Authorization: Bearer $TOKEN"
webvigil scan https://api.example.com --header "X-API-Key: k1" --header "X-Tenant: acme"
```

Or in the config file (a `--header` flag replaces this list entirely):

```toml
[auth]
headers = ["Authorization: Bearer abc123", "X-Tenant: acme"]
```

Each entry is `Name: Value` (the value may contain `:`). `Host` and `Content-Length` are
rejected — the transport computes them. Headers follow the **exact same rules as cookies**:
attached only to target-host requests, never to an out-of-scope asset or a cross-host
redirect; and a header a check deliberately sets for a request is not overwritten. A
configured header's name and value are never written to a report, a log line, a warning, or
the scan metadata — `metadata.authenticated` is `true` when *either* cookies or headers are
supplied, and the CLI summary prints counts only.

### Automated login — `--login-url` (opt-in)

Spec [`019-automated-login`](../specs/019-automated-login/). A pasted cookie dies in minutes
and cannot be refreshed. With a login configured, WebVigil logs in **itself**, keeps the
session, and logs in again if it drops:

```bash
export WEBVIGIL_LOGIN_PASSWORD='...'          # never a flag: it would land in shell history
webvigil scan https://app.example.com --mode active --authorized-by "Jane / #42" \
  --login-url https://app.example.com/signin --username scanner@example.com
```

```toml
[auth.login]
url = "https://app.example.com/signin"       # in scope
username = "scanner@example.com"
password_env = "WEBVIGIL_LOGIN_PASSWORD"     # the NAME of the variable; a `password` key is an error
# optional, when the guesses are wrong:
username_field = "email"
password_field = "pass"
form_index = 0                                # among the POST forms with a password input
extra_fields = ["tenant=acme"]
logged_in_marker = "Sign out"                 # regex over the body
logged_out_marker = "Please sign in"
check_url = "https://app.example.com/account" # answers differently when logged out
max_relogins = 3                              # 0..10, failed attempts included
```

**It makes a real login request, so it is Active Mode only** (`--mode active
--authorized-by`). Outside Active Mode the scan warns that no login was attempted and goes on
unauthenticated. The password comes from the environment variable (default
`WEBVIGIL_LOGIN_PASSWORD`, or the one `--password-env` / `password_env` names) or, on a
terminal, a no-echo prompt. With neither, the CLI exits with a usage error.

**The handshake.** `GET` the login page; take the form with a password input (the one
`form_index` names when there are several); build the body exactly as a browser would — hidden
fields and CSRF tokens included — with the account in the username field (the nearest text or
e-mail input above the password, unless `username_field` says otherwise); submit it **once**
with the target's `Origin` / `Referer`; follow the in-scope redirect chain. Every `Set-Cookie`
of every hop — the pre-login cookie, the session set on a middle hop, the last one — becomes
the session. The session cookies go to the target host only.

**Verified, not assumed.** A `302` after the `POST` is also what a failed login returns on
many apps, so the result is checked in this order, the first rule that applies deciding: a
`logged_out_marker` in the body fails the login and a `logged_in_marker` confirms it; then
`check_url` fetched with the new session; then a heuristic (the login form is gone **and** a
cookie is new or changed). A login form still on the page fails it. Nothing to go on is
*inconclusive*: the scan continues with a warning and the summary says `not confirmed`. A
**failed** login stops the scan before the crawl with a message that says what was seen (the
URL and status, never a body, a cookie or the password) and exit code **4**, so a pipeline
does not go green on a scan that never authenticated.

**One attempt, ever.** No retry after a `5xx`, a timeout or a "wrong password" answer, and
never another credential: an account lockout is a real harm, and varying the password is
brute force. A login that redirects to another host (SSO, OAuth, SAML), whose form action
leaves scope, or that downgrades an `https` target to `http` fails immediately and the
password goes nowhere.

**Re-login.** A response to a target request means the session dropped when it is a `401`, a
redirect to the login page from a page that is not itself a login page, or a body that
matches `logged_out_marker`. A `403` or a `5xx` is **not** a drop: an injection payload that
draws a block page must not cost a login. A suspicion is confirmed first against `check_url`
or, without one, the page the login landed on (an authenticated page by construction), so an
API that answers `401` for other reasons is not mistaken for an expired session. The re-login is serialised (ten requests that notice the drop wait for one
login) and each retries once, with the new session. A page that bounces to the login even with
a fresh session is learned after one wasted attempt and never signals again. After
`max_relogins` the session is reported lost, a warning says so, and the scan continues with
what it has.

**Privacy.** The password is read once, held in memory, and never written to the config (it is
not a field), a report, a log line, a warning or the metadata. The JSON report gains
`metadata.login: {relogins, session_lost, confirmed}` (`null` without a login) and no username.
If a target reflects the password or a session value into a page, an error or a URL, the final
result is scrubbed of it (`[redacted]`, in the raw, JSON-escaped, percent-encoded and
form-encoded spellings) in findings, locations, warnings and check errors. A value shorter than
four characters is not scrubbed: replacing it would shred the report.

**What it will not do.** CAPTCHA, MFA / TOTP, SSO and delegated logins, forms built by
JavaScript, multi-page logins (the username on one page and the password on the next), JSON /
token logins (`POST /api/login` returning a bearer token), registration or password reset.
For those, keep pasting a cookie or a `--header`. The crawl and the Active passes still skip
login, logout and password forms; the Authenticator is the only thing that logs in.

### Session-safe crawling

An authenticated crawl can *actually* log you out or *actually* delete something, where an
anonymous scan would have been bounced to a login page. WebVigil mitigates this:

- **Logout links are never followed** — on any scan. A URL whose path matches `logout`,
  `log-out`, `logoff`, `signout`, `sign-out`, or `disconnect` is skipped.
- **On an authenticated scan, links that look state-changing are skipped** — `delete`,
  `remove`, `destroy`, `drop`, `revoke`, `deactivate`, `disable`, `unsubscribe`, `cancel`,
  `purge`, `wipe` (word-boundary match on the path or query). The scan records a warning
  with the count.

The heuristic is keyword-based and imperfect. It **misses** a delete action whose verb is
only in the HTTP method (`DELETE /items/5`), a logout at `/session`, or a "password reset"
link. It **over-skips** a benign `/deleted-items` listing. `reset` is deliberately excluded
(`?reset=1` is a common benign filter). If you need one of these paths crawled, the residual
risk of an authenticated scan touching a state-changing `GET` is yours to weigh — you are
the expected operator, scanning your own app.

## Form-driven crawling

The crawler submits safe **`GET`** forms (search boxes, filters) with their default field
values and follows the resulting URLs, just like a discovered link. This surfaces search
results and filtered listings for every check, passive and active.

- **`GET` only by default.** `POST` forms are recorded in the form inventory but not
  submitted unless you opt in to the `POST` phase below. (The Active injection pass submits
  the `POST` forms it targets with payloads — spec 006 — and does not feed the answers back.)
- **Default values only** — no payloads, no fuzzing.
- Login / registration forms and the logout / destructive heuristic above are skipped.
- Submitted-form URLs count against `max_pages` like any other page.

Turn it off with `[scan] submit_forms = false` (there is no CLI flag).

### `POST` forms — `--submit-post-forms` (opt-in)

Spec [`018-post-form-crawl`](../specs/018-post-form-crawl/). A `POST` form is not safe to
open the way a search box is: submitting it **writes to the target** — a record, a message, a
subscription. So the crawler's `POST` phase is **off by default** and runs only in Active Mode
(`--mode active --authorized-by` **and** `--submit-post-forms` / `[scan] submit_post_forms = true`).
Without both, no `POST` leaves the crawler. With the switch on in a Passive scan, the scan warns
that it needs `--mode active` and sends nothing.

```bash
webvigil scan https://staging.example.com --mode active --authorized-by me \
  --cookie "session=<paste from devtools>" --submit-post-forms
```

The phase starts after the `GET` crawl has drained, so a write cannot change a page the crawl is
still reading. It then submits, once each and in order:

- every distinct candidate **form** — `POST`, `application/x-www-form-urlencoded` or
  `multipart/form-data` **without a file input**, and not a login / registration / search /
  logout / destructive-looking form (the same filter as the CSRF confirmation);
- every `POST` **operation** of an `--openapi` import, with the body the importer synthesised —
  JSON, form-urlencoded or none. This is the only source of a JSON body: an HTML form cannot send
  one and WebVigil runs no JavaScript. An operation that looks like authentication or a
  state-changing action is skipped.

Values are the form's own **defaults** — a hidden token travels as served — and a text field
with no default gets a benign `wvcrawl<token>` marker you can search for on the target. Never a
payload, never a file: the injection pass sends payloads and `--file-upload` owns uploads.

Each answer becomes a page: every check that reads the crawled pages sees it (an error page
after a bad submission, a script with no `integrity` on a "thank you" page), and the links and
forms on it are followed by the same BFS, within `max_pages`. After each submission the `GET`
queue is drained again, so a multi-step flow (form → confirmation page → next form) is followed.
A page that is only the answer to a `POST` is never re-requested with `GET` by another pass.

`max_post_submissions` (default 25) caps the writes; a submission also counts as one page against
`max_pages`. A scan with the phase on adds one warning with the tallies (`POST crawl: 6 submitted
— 4 forms, 2 API operations, 5 skipped, 0 not submitted (cap)`). `robots.txt` is honoured, a
`POST` is never retried, and configured cookies and headers are attached as for any request.

What it does **not** do: guess parameters (parameter mining), build JSON for a form-less
endpoint, run a form assembled by JavaScript, send `PUT` / `PATCH` / `DELETE`, log in (issue
#52), or model the hidden state of a wizard across steps. A form that depends on a token bound
to a session the scan does not hold answers an error page; that page is kept and read.

## CSRF detection — `csrf.form.no-token`

A passive check (`Category.CSRF`, `cwe = 352`, default `MEDIUM`). For every discovered
in-scope `<form method="post">` that is not a login / registration / search form, it looks
for an anti-CSRF token field (`csrf`, `xsrf`, `_token`, `authenticity_token`,
`__RequestVerificationToken`, `csrfmiddlewaretoken`, `nonce`, `anti-forgery`,
`requesttoken`). If none is present, it reports the form's action and method.

Confidence is weighted by the session cookie's `SameSite`, read from the crawled responses'
`Set-Cookie` headers:

| Session cookie | Confidence | Why |
|---|---|---|
| no `SameSite` attribute | HIGH | the browser sends it on cross-site requests — the form is genuinely reachable |
| `SameSite=Lax` / `Strict` | LOW | SameSite already mitigates cross-site submission; the finding says so |
| none observed | MEDIUM | the form may be authenticated by other means |

### Blind spots

WebVigil inspects the served HTML only. It reads these as "no token" and may be a false
positive — the finding text and confidence call this out:

- a token injected into the form by client-side JavaScript;
- a token carried in a request **header**, set from a `<meta>` tag by framework JS
  (Rails-UJS, Angular);
- the double-submit-cookie pattern with no hidden field.

## Active CSRF confirmation — `--confirm-csrf` (opt-in)

Spec [`017-csrf-confirmation`](../specs/017-csrf-confirmation/). `csrf.form.no-token` reads
the HTML and guesses from a field *name*: it cannot tell a form with no token from one whose
token JavaScript adds, and it stays silent about a form that *has* a `csrf_token` field the
server never checks. `csrf.form.token-not-enforced` (`Category.CSRF`, CWE-352, default
`MEDIUM`) asks the server instead.

```bash
webvigil scan https://staging.example.com --mode active --authorized-by me \
  --cookie "session=<paste from devtools>" --confirm-csrf
```

It is **opt-in** (`--confirm-csrf` / `[injection] csrf_confirm = true`) on top of
`--mode active --authorized-by`, because it **writes to the target**: up to three
submissions per form (the control and one or two replays), with the form's own default
values and, for a field that has none, a benign `wvcsrf<token>` marker. WebVigil cannot
delete what it submits — the same discipline as `--stored-xss` and `--file-upload`. Point it
at a staging copy.

For each candidate form — a `POST`, urlencoded, with no file input, that is not a login,
registration, search or destructive-looking form — the `CsrfScanner` pass runs one
experiment:

1. **Fetch** the form's page again, so the token is fresh.
2. **Control** — submit the form as a legitimate user would (default values, the fresh
   token, the target's own `Origin` and `Referer`).
3. **Replay** — submit it again the way a cross-site page would: a foreign `Origin` /
   `Referer` (`webvigil.invalid`), with the token **removed**, then with it **altered** (same
   length, different characters). A form with no token field gets one replay, as served.

| Verdict | When | Result |
|---|---|---|
| **confirmed** | the control was accepted and a replay got an equivalent response (same status class, same final path, a body at least 95 % similar) | a finding; the passive finding for that form is replaced |
| **refuted** | every replay was rejected (error status, redirect to a login page, a rejection phrase such as "CSRF token missing"), or answered differently | nothing; the passive finding, if any, stays |
| **inconclusive** | the form could not be fetched, the control itself was rejected, or the bodies differ with the same status and path | nothing |

The foreign `Origin` matters: a server that checks it rejects the replay, so a defence in
depth is credited rather than reported. The pass stops at the first confirming replay, so a
confirmed form is written to twice at most. Each scan with the pass on adds one warning with
the tallies (`CSRF confirmation: 7 forms tested — 2 confirmed, 3 refuted, 2 inconclusive, 4
skipped, 0 not tested (cap)`), so "no finding" can be told apart from "never ran". At most 20
forms are tested per scan, with at most 5 requests each.

Confidence follows the session cookie's `SameSite` exactly as for the passive check, and is
capped at `MEDIUM` unless a session cookie is configured (`--cookie`): a replay with no ambient
credential proves the form takes an anonymous post, not that a logged-in victim can be forced
to make one. A `--header` bearer token does not lift the cap — a cross-site form never sends it.

### What it cannot see

Every item below resolves toward *inconclusive* or *no finding*, never toward a false
confirmation:

- a token bound to a session the scan does not hold (WebVigil sends only the cookies you
  configured and discards what the target sets), so the control is rejected;
- one-time tokens or a form whose control changes the state the replay depends on (a
  "duplicate entry" error reads as a refutation);
- multi-step forms, `multipart` and JSON bodies, and anything that is not a `POST` form;
- a destructive verb only in a `<button>`'s text (the parser keeps named inputs, not button
  text — a named `submit` input's value *is* read);
- a form that answers the same page whether or not it saved: that reads as confirmed;
- a server that validates `Origin` only when it is present, and everything a real browser adds
  (`SameSite` cookie rules, `Sec-Fetch-*`).

## What is deferred

- **Session-security checks** — session fixation, session not invalidated on logout,
  weak/predictable session ids. They build on the automated login (spec 019) and are a spec
  of their own (issue #53).
- **JSON / token logins** (`POST /api/login` returning a bearer token), CAPTCHA, MFA and
  delegated (SSO) logins — the automated login handles form logins only.
- **Parameter mining**, JSON bodies that do not come from an OpenAPI document, and forms
  built by JavaScript — outside the in-band scanner (the `POST` crawl is opt-in, spec 018).
