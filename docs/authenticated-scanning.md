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
stays entirely config-driven.

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

- **`GET` only.** `POST` forms are recorded in the form inventory but never submitted by
  the crawler. (The Active injection pass still submits `POST` forms it targets — spec 006.)
- **Default values only** — no payloads, no fuzzing.
- Login / registration forms and the logout / destructive heuristic above are skipped.
- Submitted-form URLs count against `max_pages` like any other page.

Turn it off with `[scan] submit_forms = false` (there is no CLI flag).

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

- **Automated login** — detecting the login form, submitting credentials, capturing the
  session, re-authenticating when it drops. A stateful multi-step mechanic (CAPTCHA, MFA,
  CSRF-on-login, redirect chains); a follow-up spec. v0.7 takes a cookie you already have.
- **Auth headers / bearer tokens** (`--header "Authorization: Bearer …"`). A companion to
  the login-flow spec.
- **Session-security checks** — session fixation, session not invalidated on logout,
  weak/predictable session ids. Each needs the login flow or Active Mode.
- **`POST` form submission by the crawler**, `multipart`/JSON bodies, parameter mining.
