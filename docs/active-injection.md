# Active injection

Spec [`006-active-injection`](../specs/006-active-injection/). WebVigil's first **Active
Mode** checks: they send crafted input to the target's parameters and forms and watch how
the application handles it.

## Turning it on

Injection checks are `mode = ACTIVE`. They run only with the spec 001 attestation:

```bash
webvigil scan https://staging.example.com --mode active --authorized-by "you / engagement #123"
```

Without `--mode active` nothing here runs and no crafted request is issued. Active Mode
shows a legal-warning banner and records the attestation in every report. It can cause
state changes (a submitted form) — that is inherent to Active Mode.

## What it detects

All of them are detected **in-band** — from the target's own responses. No headless browser,
no out-of-band collaborator.

| Check | Severity | How it is proved |
|---|---|---|
| `injection.xss.reflected` | HIGH | A context-breaking payload comes back in an HTML response with `<`, `>`, `"` intact (not entity- or percent-encoded), in an executable position. |
| `injection.sqli.error-based` | HIGH | A broken quote produces a DBMS parser error (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) that is absent from the baseline. |
| `injection.sqli.boolean-based` | HIGH | A `TRUE` payload keeps the response like the baseline and a `FALSE` payload changes it — reproduced across a confirmation round, after checking the page is stable. |
| `injection.sqli.time-based` | HIGH | An injected `SLEEP(n)` delays the response by ~`n` s while a `SLEEP(0)` control returns fast, and the delay scales with a half-length probe. |
| `injection.traversal.path` | HIGH | A `../` payload returns a known system file — `root:…:0:0:` from `/etc/passwd`, `[fonts]` from `win.ini` — not present in the baseline. |
| `injection.redirect.open` | MEDIUM | An off-site URL injected into the parameter is honoured in the `Location` header (or a `<meta refresh>` / `location.href`). The redirect to the sentinel host is never followed. |
| `injection.xss.stored` | HIGH | A `<wvstored…>` marker submitted through a form (or query parameter) is stored by the app and later rendered with its markup intact on a **different** page — found by a re-crawl. Opt-in; see below. |
| `injection.ssrf.metadata` | CRITICAL | A URL payload in the parameter makes the server fetch the cloud instance metadata service — a provider marker (`AccessKeyId`, `computeMetadata`, `vmId`, …) appears in the response, absent from the baseline. |
| `injection.ssrf.internal` | HIGH | A URL payload reaches a loopback / internal resource (recognizable service banner), reads a local file via `file://`, or an SSRF-shaped connection error names the injected URL — each absent from the baseline. |
| `injection.cmdi.os` | CRITICAL | A shell-metacharacter break plus `echo <marker>=$((a*b))` makes the shell return the *computed* product next to a per-request marker (absent from the baseline), **or** a `sleep`/`ping -n` payload delays the response past a zero-delay control and scales with a half-length probe. This is RCE. |
| `injection.ssti` | HIGH | A polyglot draws a template-engine parse error, then an arithmetic payload (`{{a*b}}`, `${a*b}`, `<%= a*b %>`, …) returns the *evaluated* product glued to a per-request marker, absent from the baseline. The engine is named when identifiable (`{{7*'7'}}` → `7777777` Jinja2, `49` Twig). |
| `injection.crlf` | HIGH | A `%0d%0a`-prefixed payload makes the app write an attacker header line (or, with a double CRLF, a whole body) that the HTTP client parsed back, absent from the baseline. |
| `injection.host-header` | MEDIUM / HIGH | A request with a poisoned `Host` / `X-Forwarded-*` header comes back with the sentinel host in an absolute URL, `Location`, `<base>`, or a canonical tag — absent from the plain-`GET` baseline. HIGH in a reset / redirect context. |
| `injection.xxe` | HIGH | *(opt-in `--xxe`)* A POST body re-sent as XML with an external-entity payload returns a `/etc/passwd` / `win.ini` signature or a named XML-parser error, absent from the baseline. |
| `http.methods.unsafe` | MEDIUM | `TRACE` is enabled and echoes the request (Cross-Site Tracing), or `OPTIONS` advertises `PUT` / `DELETE` / `PATCH` / `CONNECT` on an application route. `Category.HTTP`. |
| `injection.ldap` | HIGH / MEDIUM | A filter-breaking metacharacter draws an LDAP-parser error absent from the baseline (HIGH), or an always-true filter (`*`) widens the result set while an always-false one does not (MEDIUM). |
| `injection.xpath` | HIGH / MEDIUM | An expression-breaking character draws an XPath / XQuery parser error absent from the baseline (HIGH), or a `' or '1'='1` / `' and '1'='2` pair reproduces a two-sided boolean split (MEDIUM). |
| `injection.ssi` | HIGH / MEDIUM | An `<!--#echo var="DATE_LOCAL"-->` / `<!--#printenv-->` / `<esi:vars>` directive is *evaluated* into output absent from the baseline (HIGH), or an undefined-variable marker draws the SSI processor's error string (MEDIUM). Never sends `#exec` / `#include`. |
| `upload.unrestricted` | CRITICAL–MEDIUM | *(opt-in `--file-upload`)* A benign marker file uploaded with a dangerous name / type comes back **executed** (CRITICAL), **served inline** as `text/html` / `image/svg+xml` (HIGH), **written outside the upload directory** by a `../` filename (HIGH), accepted via **`PUT`** and served back (HIGH), or merely stored as a download of a type that should be rejected (MEDIUM). `Category.UPLOAD`. |

Every finding's `location` carries the `method`, `url`, and `param`; its evidence carries
the injection point, the payload sent, and the proof.

## How the pass works

When the scan is Active and at least one `injection.*` check is selected, the orchestrator
runs one bounded `InjectionScanner` pass:

1. **Enumerate injection points** — every query-string parameter on a crawled in-scope URL,
   every fuzzable field of a crawled in-scope `<form>` (GET and POST), and — when
   `--openapi` is set (spec 013) — the query / path parameters and form-urlencoded body
   fields of every declared `GET` / `POST` operation. Forms are parsed from page bodies the
   crawler already fetched; no extra crawl requests. See
   [`api-scanning.md`](api-scanning.md).
2. **Baseline** — one request per point with its original value, shared by every detector.
3. **Fan the detectors** — each enabled detector sends its payloads for that point, drawing
   on one shared **request budget**. Boolean and time-based run confirmation rounds.

Every crafted request goes through the same HTTP layer as a crawl fetch: scope guard,
concurrency cap, per-host delay, timeout. A non-idempotent request (`POST`) is never
retried on a `5xx` or a read timeout — no double-submit.

## Stored XSS — `--stored-xss` (opt-in)

Spec [`008-stored-xss`](../specs/008-stored-xss/). Reflected XSS (above) needs the payload
to bounce back in the *same* response. **Stored XSS** is when the app saves the input and
renders it, unescaped, on a *later* request — a comment thread, a profile page, an activity
feed. Detecting it needs a stateful two-phase pass, and that pass **writes data the target
keeps**, so it has its own opt-in on top of Active Mode:

```bash
webvigil scan https://staging.example.com \
  --mode active --authorized-by "you / engagement #123" --stored-xss
```

or `[injection] stored_xss = true`. **Off by default.** Without `--mode active` the flag
does nothing and the scan warns.

**How the pass works**

1. **Inject.** For every in-scope, non-excluded injection point (POST-form fields first,
   then query parameters — 006's model), submit a small set of marker payloads
   (`<wvstored…>` — an inert custom tag carrying a per-point token). Each marker is
   deliberately persisted by the target.
2. **Re-crawl.** A depth-1 re-crawl from the pages the first crawl found: re-fetch each,
   then follow **one hop** of new links (so a freshly-created `/comments/42` is reached).
3. **Correlate.** A hit needs the marker's `<`/`>` back **verbatim** in an executable
   context, on a page fetched by a re-crawl `GET` (never the submission response — that is
   reflected XSS), that did not already contain the marker before injection. The finding's
   location is the **injection point**; the page(s) it rendered on are in the evidence
   (`Rendered on: …`).

An authenticated scan (`--cookie`) carries its cookies through both phases, so the
high-value behind-login sinks are covered.

**Budget.** Phase A and the re-crawl share the `[injection] request_budget`; the re-crawl
is additionally capped at 120 pages (and by `[scan] max_pages`). Hitting either is a warning.

**Markers are not cleaned up.** WebVigil does not know the target's data model, so it does
not delete the `wvstored…` rows it wrote. Run `--stored-xss` against dev / staging, never a
shared production database.

**Blind spots.** A marker stored but rendered only where the scan cannot reach (an admin
panel, a moderation queue, a staff email); a marker shown only after moderation or a delay;
a marker rendered more than one hop past a known page; a sink that strips unknown tags. DOM
XSS still needs a JavaScript engine (out of scope).

## SSRF — cloud metadata, loopback, `file://`

`injection.ssrf.metadata` and `injection.ssrf.internal` (v0.9) detect Server-Side Request
Forgery **in-band** — from the target's own response, with **no** out-of-band collaborator.
They run in Active Mode like every other injection check; there is **no opt-in flag** and
**no config** (the payloads only read — they write nothing to the target).

The `ssrf` detector puts URL payloads in a parameter and looks for one of four proofs, each
required absent from the point's baseline:

1. a **cloud-metadata marker** — AWS (`AccessKeyId`, `ami-launch-index`), GCP
   (`computeMetadata`, `machineType`), Azure (`vmId`, `resourceGroupName`), AliCloud,
   Kubernetes (a `403 "kind":"Status"`) → `injection.ssrf.metadata`, **CRITICAL** (the
   metadata service usually hands out IAM credentials);
2. a **`file://` read** — `/etc/passwd` or `win.ini` content → `injection.ssrf.internal`;
3. a **recognizable internal service** — a Redis / nginx-status / Docker-API / Elasticsearch
   banner, or an internal admin page title → `injection.ssrf.internal`;
4. an **SSRF-shaped connection error** (or a `502/504` the baseline never returned) that
   **echoes the injected URL** → `injection.ssrf.internal`, MEDIUM confidence — proves the
   parameter reaches a server-side fetcher even when nothing leaked.

Payloads cover the IP/host obfuscations that slip past a naïve block: decimal / hex / octal
encodings of `127.0.0.1` and `169.254.169.254`, `127.1`, `[::1]`, and `user@host`
confusion. A parameter whose **name or value looks like a URL** (`url`, `callback`,
`webhook`, `next`, `image`, …) gets the full payload set and is tested first; any other
parameter gets a short canary set, tested last, only if budget remains.

**Blind SSRF is not covered, and is not on the roadmap.** A parameter that triggers a
server-side request with *no* in-band signal — no reflected body, no error, no status
change — is only detectable with an out-of-band collaborator: a server the scanner hosts,
with a public domain and DNS/HTTP ports, that the target calls back to. That crosses
WebVigil's "the engine talks only to the target" rule and the choice to ship WebVigil as a
repository only, with no hosted service. If you need the blind case, run WebVigil's active
scan alongside your own collaborator (Burp Collaborator, interactsh) and inject its domain
by hand.

## Command injection & SSTI

`injection.cmdi.os` (CRITICAL) and `injection.ssti` (HIGH) (v0.11) detect the two
server-side injection classes that lead straight to remote code execution and are provable
**in-band**. They run in Active Mode like every other injection check.

**OS command injection** has two detector stages:

- **echo** — the payload appends a shell separator (`;`, `|`, `&&`, `` ` ``, `$(…)`, a
  newline, `${IFS}` for space-filtered contexts) plus `echo <marker>=$((a*b))`. A hit needs
  `<marker>=<a*b>` — the *evaluated* product, glued to a per-request marker, absent from the
  baseline. A reflected literal `$((a*b))` is **not** a hit. A Windows `& echo … & set /a`
  variant is reported at MEDIUM confidence.
- **time** — `;sleep <d>`, `` `sleep <d>` ``, `&ping -n <d+1> 127.0.0.1`, `&timeout /t <d>`.
  Confirmed exactly like time-based SQLi: the injected request runs ≥ ~`d` s slower than a
  `sleep 0` control, and a half-delay probe scales. Gated by `[injection] time_based_cmdi`
  (default on) / `--no-time-based-cmdi`.

**SSTI** is a two-stage probe: a polyglot (`${{<%[%'"}}%\`) that draws a template-engine
parse error (Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, ERB), then per-engine
arithmetic payloads (`{{a*b}}`, `${a*b}`, `<%= a*b %>`, `#{a*b}`, `*{a*b}`, `@(a*b)`) whose
computed product must come back glued to the marker. When the engine did not error, a
`{{7*'7'}}` probe identifies it (`7777777` → Jinja2 / Nunjucks, `49` → Twig).

A parameter whose **name** suggests a shell command or a template (`cmd`, `host`, `ping`,
`exec`, `template`, `render`, …) gets the full payload set and is tested first; any other
parameter gets a short canary set from the base order, budget permitting.

**Truly blind command injection is not covered.** A shell command with no output *and* no
timing effect (`; curl http://attacker/`) needs an out-of-band collaborator the scanner
hosts — the same reason blind SSRF is off the roadmap
([`docs/notes/why-not-oast.md`](notes/why-not-oast.md)). The time-based detector is the
in-band substitute; for the rest, pair with your own collaborator.

## Request-envelope injection

`injection.crlf`, `injection.host-header`, `injection.xxe` and `http.methods.unsafe` (v0.12)
test the *request envelope* — the headers the app trusts, the parsers it feeds, the methods
it exposes — rather than a parameter value.

**CRLF injection** (`injection.crlf`, CWE-113) — the detector appends `%0d%0a`-prefixed
payloads to a parameter and checks whether the *response* carries an injected header
(`X-WvInjected: <token>`) that `httpx` parsed back, an injected `Set-Cookie`, or — with a
double CRLF — a whole split body. A payload merely reflected in the page *text* is not a
CRLF hit (that is reflected XSS). Modern servers strip CR/LF from header values, so a real
target can be a false negative even when vulnerable.

**Host-header injection** (`injection.host-header`, CWE-644) — a bounded pass
(`EnvelopeScanner`) re-requests a sample of crawled URLs with `Host` /
`X-Forwarded-Host` / `X-Forwarded-Server` / `X-Host` / `X-Original-Host` set to
`webvigil.invalid`, and flags the sentinel reflected in an absolute URL, `Location`,
`<base href>`, or `<link rel=canonical>` — absent from the plain-`GET` baseline. MEDIUM,
HIGH when the reflection is in a `Location` or a password-reset-looking link. WebVigil never
connects to the sentinel — it is a header value on a request to the in-scope target.

**XXE** (`injection.xxe`, CWE-611) — **opt-in** (`--xxe` / `[injection] xxe`, off by
default because it rewrites the request body). For each POST injection point the detector
re-sends the body as `application/xml` / `text/xml` with an external-entity payload
(`file:///etc/passwd` SYSTEM entity, an in-scope parameter-entity DTD, a bounded
nested-entity payload) and flags a file-content signature (HIGH) or a named XML-parser
error (MEDIUM). **Blind / out-of-band XXE is not covered** — it needs a collaborator, the
same call as blind SSRF.

**HTTP methods** (`http.methods.unsafe`, `Category.HTTP`, CWE-650 / 693) — the
`EnvelopeScanner` sends `OPTIONS` to the URL sample and one `TRACE` per host. `TRACE`
enabled and echoing the request is Cross-Site Tracing (XST); `PUT` / `DELETE` / `PATCH` /
`CONNECT` advertised in `Allow` on a non-static route is a finding (WebVigil does not verify
they are reachable unauthenticated). The pass sends **only** `OPTIONS` and `TRACE` — never
a state-changing verb.

**Not covered:** HTTP request smuggling (needs raw-socket framing control), web-cache-
poisoning *confirmation* (WebVigil flags the reflected unkeyed input, it does not prove the
cache stored the response), and blind XXE.

## LDAP / XPath / SSI injection

`injection.ldap`, `injection.xpath` and `injection.ssi` (v0.14) are three more detectors in
the `InjectionScanner` pass — value injections with the same shape as SQLi (an error
signature plus a differential), for the sinks a reviewer would expect WebVigil to cover.

**LDAP injection** (`injection.ldap`, CWE-90) — an *error probe* appends `)` / `*)(` / `(|`
to break the search filter; a hit needs an LDAP-parser signature
(`javax.naming.directory`, `Bad search filter`, `com.sun.jndi.ldap`, …) absent from the
baseline. A *boolean probe* sends an always-matching filter and an always-failing one; a
hit needs the matching filter to return materially more than the baseline while the failing
one does not. WebVigil parses no LDAP itself.

**XPath / XQuery injection** (`injection.xpath`, CWE-643) — an *error probe* (`'`, `"`, `]`,
`count(//*`) draws an XPath-parser signature (`XPathEvalError`, `org.jaxen`,
`Expression must evaluate to a node-set`, …); a *boolean probe* (`' or '1'='1` vs
`' and '1'='2`) reproduces the classic true-tracks-baseline / false-diverges split. Each of
`ldap` / `xpath` / `ssi` is front-loaded only for parameters whose name is distinctly that
class's (`uid` / `cn` / `dn` for LDAP; `xpath` / `xquery` / `node` for XPath; `include` /
`shtml` / `tpl` for SSI) — on a generic name it still runs, from the shared detector order,
budget permitting.

**SSI / ESI injection** (`injection.ssi`, CWE-97) — the detector injects an
`<!--#echo var="DATE_LOCAL"-->` / `<!--#printenv-->` / `<esi:vars>$(HTTP_HOST)</esi:vars>`
directive and flags the *evaluated* output — a rendered date, an environment dump, the host
— that the baseline did not carry. A directive reflected **verbatim** is not a hit (that is
XSS territory). An undefined-variable marker drawing the SSI processor's error string
(`[an error occurred while processing this directive]`) is a MEDIUM hit. The detector
**never sends `<!--#exec cmd=…-->` or `<!--#include file=…-->`** — command execution and
file inclusion via SSI are `injection.cmdi.os` / `injection.traversal.path` territory, and
sending those would make `ssi` a destructive detector.

**Not covered:** LDAP / XPath / SSI attacks that produce no error and no observable
differential (truly blind), and expression-language injection (SpEL / OGNL) — see
[Coverage boundaries](#coverage-boundaries).

## File upload — `--file-upload` (opt-in)

`upload.unrestricted` (v0.14, `Category.UPLOAD`, CWE-434) tests whether an endpoint stores
an uploaded file and serves it back without validating its type or content. It is **opt-in**
because the pass writes files the target keeps and WebVigil cannot reliably delete — the
same discipline as `--stored-xss`.

```bash
webvigil scan https://staging.example.com --mode active --authorized-by me --file-upload
```

When it is on and `upload.unrestricted` is selected, a `UploadScanner` pass runs after the
injection pass. For every discovered `<form>` with a `type="file"` field (auth- and
destruction-shaped forms excluded) it uploads a small set of **benign marker files**, each
a few hundred inert bytes carrying a `wv<token>` marker:

- **server-side execution** — a `.php` / `.phtml` / `.jsp` / `.asp` file whose body is
  `wv<token>:<?php echo 6*7; ?>`. If it comes back as `wv<token>:42` (the computed product,
  no `<?php` source), the server executed it — **CRITICAL**, remote code execution.
- **client-side execution** — a `.html` / `.svg` file with a `<script>` comment. If it is
  served back inline as `text/html` / `image/svg+xml` with no `Content-Disposition:
  attachment`, script runs in the site origin — **HIGH**, stored XSS via upload.
- **extension / content-type bypass** — the same content under `wv<token>.php.jpg`,
  `wv<token>.pHtml`, `wv<token>.html%00.jpg`, and with an `image/jpeg` part type on an
  `.html` name.
- **filename path traversal** — a part named `../../wv<token>-trav.html`; if it is
  retrievable from the web root (outside every upload directory) — **HIGH**.

An upload is a finding only when the stored file is **retrieved** (from a link in the upload
response, a conventional prefix like `/uploads/` or `/files/`, or the web root for the
traversal case) and one of the outcomes above holds. A file that is stored and retrievable
but served as `application/octet-stream` + `attachment` is a **MEDIUM** "accepts an
arbitrary type" finding.

One more probe: a single **`PUT`** of a benign marker to the entry directory, fetched back
with a `GET`. This is the only state-changing verb WebVigil sends beyond `GET` / `POST`, it
is sent only under `--file-upload`, and the body is inert. (Spec 012's request-envelope pass
deliberately never sent `PUT`; `--file-upload` re-opens it for this one bounded probe.)

**Not covered:** archive extraction (zip-slip), decompression bombs, image-library RCE
(ImageTragick and similar — Nuclei territory, version-specific payloads), antivirus / EDR
evasion, polyglot files, and any upload whose effect is only observable out-of-band
(an uploaded XML that triggers blind XXE, an uploaded file that makes the server fetch a
URL). WebVigil does not clean up the marker files it uploads — they are benign and the
behaviour is documented, like a stored-XSS marker.

## Non-destructive posture

- **`GET` and `POST` only** — with the single exception of the `--file-upload` `PUT` probe
  (one benign marker to the entry directory, only under the opt-in). Never `PATCH`,
  `DELETE`, or `PUT` anywhere else.
- **Forms that look like authentication or destruction are not fuzzed** — the heuristic
  matches `login`, `logout`, `register`, `delete`, `password`, `checkout`, `pay`,
  `transfer`, and similar in the action or field names. It is best-effort: a login form at
  `/session` with generic field names would slip through.
- **Hidden fields and anti-CSRF tokens are submitted with their discovered values**, never
  fuzzed. `file` and `password` inputs are not payload-fuzzed.

## Budget and tuning — `[injection]`

```toml
[injection]
request_budget = 650        # max crafted requests per scan; hitting it is a warning
max_injection_points = 200  # max params / fields tested; excess is a warning
time_based_sqli = true      # --no-time-based-sqli overrides
time_based_cmdi = true      # spec 011: time-delay command-injection payloads; --no-time-based-cmdi overrides
time_based_delay_s = 5      # the D in SLEEP(D) / sleep D; keep below [http] timeout_s
stored_xss = false          # run the two-phase stored-XSS pass; --stored-xss overrides
xxe = false                 # spec 012: re-send POST bodies as XML; --xxe overrides
file_upload = false         # spec 014: upload benign markers through upload forms; --file-upload overrides
upload_budget = 80          # spec 014: total requests the file-upload pass may spend
```

Per point the pass sends at most 38 crafted requests (raised from 30 in v0.11 for the
command-injection / SSTI families and 35 in v0.14 for LDAP / XPath / SSI); the time-based
detectors share a cap of 8 sleep-inducing requests per scan; the stored-XSS re-crawl
fetches at most 120 pages; the file-upload pass has its own `upload_budget`. Hitting any cap
is a scan **warning**, not an error.

Disable any check by id (`[checks] disabled`). Disabling **every** `injection.*` id skips
the pass entirely — no enumeration, no crafted request.

## What it does not do

- **No exploitation.** A confirmed SQLi is proved with one bounded marker; WebVigil does
  not dump the database or read further files.
- **No parameter mining.** It fuzzes parameters the target actually exposes, not guessed
  ones.
- **No WAF evasion.** Payloads are a small static in-repo set with no mutation engine.

### Coverage boundaries

WebVigil's active coverage stops at what is **in-band-provable, without a headless browser,
without an out-of-band collaborator, and without a false-positive-prone oracle** — the line
held since spec 006. What that leaves out, and why:

| Class | Why it is out |
|---|---|
| DOM XSS, client-side prototype pollution | needs a JavaScript engine — out of scope since spec 001. |
| Blind SSRF / XSS / command injection, out-of-band XXE | needs a hosted collaborator (Burp Collaborator, interactsh). Pair WebVigil with your own; see [`docs/notes/why-not-oast.md`](notes/why-not-oast.md). |
| Expression-language injection (SpEL / OGNL / JEXL), `eval()` code injection | deferred (spec 011); the SSTI machinery could be extended but it is a spec-sized surface of its own. |
| NoSQL injection, HTTP parameter pollution | no reliable in-band oracle — high false-positive rate. |
| Remote file inclusion | the blind form needs a collaborator; the in-band form overlaps SSRF / traversal. |
| Session fixation, logout invalidation, weak session id, verb-based auth bypass | needs a stateful login flow WebVigil does not have. |
| HTTP request smuggling, web-cache-poisoning confirmation | needs raw-socket framing control / cache-behaviour analysis. |
| Archive extraction (zip-slip), image-library RCE, AV evasion | destructive, resource-heavy, or Nuclei-style version-specific payloads. |

Everything **in scope** ships: reflected & stored XSS, SQLi (error / boolean / time), path
traversal, open redirect, in-band SSRF, OS command injection, SSTI, CRLF, host-header
injection, in-band XXE (opt-in), HTTP methods, LDAP / XPath / SSI injection, and
unrestricted file upload (opt-in).

## A target to try it on

`docker/target.Dockerfile` packages the test fixture app (an intentionally vulnerable
Starlette app) as a scannable target:

```bash
docker compose --profile targets up target
webvigil scan http://localhost:8080 --mode active --authorized-by me
```

It is not started by `docker compose up`.
