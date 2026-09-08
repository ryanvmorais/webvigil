---
feature: Request-envelope injection — CRLF / response splitting, host-header injection, in-band XXE, HTTP methods (Active Mode)
status: done
date: 2026-09-08
related:
  - 006-active-injection/requirements.md
  - 009-ssrf/requirements.md
  - 011-rce-injection/requirements.md
origin: conception
---

# 012 — Request-envelope injection (CRLF, host header, XXE, HTTP methods)

## Context and problem

Specs 006, 009 and 011 test what the application does with a **parameter value**:
reflected/stored XSS, SQLi, traversal, open redirect, SSRF, command injection,
SSTI. Every one of them puts a payload in a query-string parameter or a form
field and reads the response.

**A whole class of findings a reviewer (and OWASP ZAP / Wapiti) would expect is
about the request *envelope* rather than a parameter value** — the headers the
application trusts, the parsers it feeds untrusted bytes to, and the HTTP methods
it exposes:

- **CRLF injection / HTTP response splitting** — CWE-113. A parameter whose value
  is written into a *response header* (`Location`, `Set-Cookie`, a custom header,
  a `Content-Disposition` filename) without stripping `\r\n` lets an attacker
  inject their own header — or, with a double CRLF, a whole response body. It is
  provable **in-band**: send `%0d%0a`-prefixed payloads and check whether the
  response carries a header (or a body) that the baseline did not.
- **Host-header injection** — CWE-644. An application that builds absolute URLs
  from the `Host` request header (or `X-Forwarded-Host` / `X-Forwarded-Server` /
  `X-Host`) — a password-reset link, a `<base href>`, a `<link rel=canonical>`, a
  redirect — can be pointed at an attacker's domain. Provable **in-band**:
  re-request a page with a sentinel host and check whether the sentinel is
  reflected in an absolute URL, `Location`, or a canonical/base tag, absent from
  the baseline.
- **XML external entity (XXE)** — CWE-611. An endpoint that parses attacker XML
  with an insecure parser resolves `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.
  Provable **in-band** two ways: the entity's expansion (a file's content)
  reflected in the response, or an XML-parser error that names the failed entity
  / external DTD. WebVigil has no XML injection points from crawling, so this is a
  **content-type flip**: re-send a discovered POST body as `application/xml` with
  an XXE payload. It is speculative — most endpoints reject non-form bodies — so
  it is **opt-in**.
- **HTTP methods** — CWE-650 / CWE-16. `OPTIONS` reveals the `Allow` set; `TRACE`
  being enabled is Cross-Site Tracing (XST); `PUT` / `DELETE` / `PATCH` /
  `CONNECT` *advertised* on an application route is worth a finding even before
  proving they are unauthenticated. Provable with a bounded, **non-destructive**
  probe: `OPTIONS` and `TRACE` only — never a state-changing verb.

All four are **in-band, no headless browser, no out-of-band collaborator** — the
same line 011 held. Blind XXE (parameter entities exfiltrating over DNS/HTTP) and
HTTP request smuggling stay out, for the same reasons blind SSRF does.

### Why not blind / smuggling

- **Blind / OAST XXE** — a parameter-entity payload that makes the parser fetch
  `http://attacker/?%file;` needs a hosted collaborator. Same call as blind SSRF
  and blind command injection: not on the roadmap; documented, "pair with your
  own collaborator" (see `docs/notes/why-not-oast.md`).
- **HTTP request smuggling (CL.TE / TE.CL / TE.TE)** — needs raw-socket,
  byte-exact control of the request framing and a front-end/back-end
  desynchronisation to observe. `httpx` normalises the framing; the detection is
  timing- and infrastructure-sensitive and a notorious false-positive generator.
  Explicit non-goal.
- **Web-cache-poisoning *confirmation*** — WebVigil flags a reflected unkeyed
  header (the poisonable input); it does not send a second request to prove the
  cache stored the poisoned response (needs cache-behaviour analysis, often a
  collaborator).

### Where it sits

```
webvigil.checks.injection                        (Category.INJECTION, mode = ACTIVE)
       ├── injection.xss.* / sqli.* / traversal / redirect   [006]
       ├── injection.xss.stored                              [008]
       ├── injection.ssrf.*                                  [009]
       ├── injection.cmdi.os / injection.ssti                [011]
       ├── injection.crlf              [012]  ← `\r\n` in a param → smuggled response
       │                                        header (or split body), baseline-absent
       ├── injection.host-header       [012]  ← sentinel host reflected in an absolute
       │                                        URL / Location / <base> / canonical
       └── injection.xxe               [012]  ← opt-in: POST body re-sent as XML with an
                                                external-entity payload → file content
                                                or a parser error naming the entity

webvigil.checks.http                             (new package — Category.HTTP)
       └── http.methods.unsafe         [012]  ← OPTIONS/TRACE probe: TRACE enabled (XST),
                                                or PUT/DELETE/PATCH/CONNECT advertised

detect/crlf.py   new detector in the 006 InjectionScanner (value injection — fits)
                 the engine's shared budget, baseline, DetectCtx.send
host-header +    a new small orchestrator pass over a sample of discovered URLs, re-
HTTP-methods     requesting with a poisoned Host / an OPTIONS or TRACE method
xxe              a content-type-flip step on 006's POST injection points, opt-in
```

`injection.crlf` reuses the 006 machinery unchanged (it is a parameter-value
injection). `injection.host-header`, `injection.xxe` and `http.methods.unsafe`
need mechanics 006 does not have — a request with a custom `Host`, a request with
a re-typed body, a request with a non-`GET`/`POST` method — all of which the
spec-006 HTTP layer already supports (`HttpClient.request(method, …, headers=…)`).
The engine still imports nothing from `webvigil.cli` / `webvigil.api` / `web/`;
detection is `re` + `httpx.Headers` + the existing HTTP layer; no new runtime
dependency (XML is parsed by the *target*, not WebVigil — WebVigil only sends the
payload and reads the response as text). `import-linter` unchanged.

## Goals

- **`injection.crlf`** (CWE-113) — a new `crlf` detector in the `InjectionScanner`
  pass: for each injection point, send `%0d%0a`-prefixed payloads that try to
  inject a marker response header (`X-WvInjected: <token>`), a marker cookie
  (`Set-Cookie: wv=<token>`), and — with a double CRLF — a marker body. A hit
  needs the injected header / cookie / body in the response and **absent from the
  point's baseline**. Prioritise parameters that commonly land in a header
  (`url`, `redirect`, `next`, `lang`, `locale`, `region`, `country`, `ref`,
  `callback`, `goto`, `return`, `filename`, `download`).
- **`injection.host-header`** (CWE-644) — a new bounded pass that re-requests a
  small sample of discovered in-scope pages (the entry page, any page that
  renders a form, up to a documented cap) with the request `Host` header — and
  the common overrides `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`,
  `X-Original-Host` — set to an off-scope **sentinel** (`webvigil.invalid`). A
  hit needs the sentinel host reflected in the response, absent from the baseline:
  in an absolute `http(s)://webvigil.invalid…` URL in the body, in a `Location`
  header, in `<base href>`, or in `<link rel="canonical">` / `<meta property=
  "og:url">`. WebVigil never *connects* to the sentinel (the scope guard blocks
  it) — the sentinel is a value in a header sent to the in-scope target, exactly
  as in the open-redirect detector.
- **`injection.xxe`** (CWE-611) — an **opt-in** (`[injection] xxe` /
  `--xxe`, default off) content-type-flip step on 006's POST injection points:
  re-send the point's body once as `application/xml` (and once as
  `text/xml`) carrying a small documented set of external-entity payloads —
  a `file:///etc/passwd` / `file:///c:/windows/win.ini` SYSTEM entity
  (error-based + reflected), a parameter-entity that references an external DTD,
  and a "billion laughs"-shaped payload capped to be harmless (a few entities, no
  amplification). A hit needs a `/etc/passwd` / `win.ini` signature (shared with
  the 006 traversal signatures) **or** an XML-parser error naming the entity /
  external DTD (`DOCTYPE is not allowed`, `Entity … not defined`,
  `external entity`, `lxml.etree.XMLSyntaxError`, `SAXParseException`,
  `xmlParseEntityRef`) — each absent from the baseline. Off by default because the
  payload rewrites the request body and most endpoints will 400.
- **`http.methods.unsafe`** (CWE-650, CWE-16) — a new `webvigil.checks.http`
  package and a bounded pass: `OPTIONS` a sample of discovered URLs, parse
  `Allow` / `Public`; send a `TRACE` and check for a `200` that echoes the
  request (XST). Emit one finding when `TRACE` is enabled, one when any of
  `PUT` / `DELETE` / `PATCH` / `CONNECT` is advertised on an application route
  (not a static asset). **Never sends a state-changing verb** — `PUT` etc. are
  reported from the `Allow` header, not by trying them.
- **Gated by the existing Active-Mode attestation** — every 012 check is
  `mode = ACTIVE`, `--mode active --authorized-by`, no new consent gate (the XXE
  opt-in is a *noise/safety* switch on top, like `--stored-xss`, not a second
  legal gate).
- **False-positive discipline** — every signal is confirmed against a baseline;
  CRLF needs the injected header/body *parsed back* by `httpx`, not merely
  reflected in the page text; host-header needs the sentinel in a URL-shaped
  position, not just anywhere; XXE needs a file signature or a parser error, not
  a bare 500; the hardened fixture profile yields **zero** 012 findings.
- **Fixture-app coverage** — the insecure profile gains a CRLF-reflecting
  redirect/language endpoint, a host-header-reflecting "reset link" page, an XML
  endpoint that resolves entities, and a route that advertises `TRACE` + `PUT`;
  the hardened profile serves the safe equivalents. Integration tests assert the
  findings on one profile and zero on the other.
- **Docs** — a "Request-envelope injection" section in `docs/active-injection.md`
  (or a sibling `docs/` page), plus README / CLAUDE / specs-roadmap updates.

## Non-goals

- **Blind / out-of-band XXE** — parameter-entity exfiltration over DNS/HTTP needs
  a hosted collaborator; not on the roadmap, documented like blind SSRF.
- **HTTP request smuggling** (CL.TE / TE.CL / TE.TE, HTTP/2 downgrade) — needs
  raw-socket framing control and a front-end/back-end desync; FP-prone; out.
- **Web-cache-poisoning confirmation** — WebVigil flags the reflected unkeyed
  input; it does not prove the cache stored the poisoned response.
- **Sending `PUT` / `DELETE` / `PATCH` / `CONNECT`** to a target. The methods
  check reads the `Allow` header and sends only `OPTIONS` / `TRACE`.
- **WebDAV / verb-based auth-bypass exploitation** (`X-HTTP-Method-Override`,
  `PROPFIND`, case-tricks like `GeT`). A later candidate; 012 does the common
  `OPTIONS` / `TRACE` case.
- **Full header-injection surface** beyond `Host` and the four `X-Forwarded-*`
  overrides — no `Referer`-as-SQLi, no `User-Agent`-as-XSS sweep (that is a
  header-fuzzing mode, not this spec).
- **SMTP / LDAP / XPath / SSI injection** — separate classes, not scheduled.
- **A JavaScript engine, an OAST collaborator, a new runtime dependency, a
  headless browser** — unchanged since spec 001.
- **Web API / dashboard changes** — engine + CLI only, following 006 / 009 / 011.
- **New crawl fetches for the injection points** — CRLF and XXE reuse 006's
  points; the host-header and methods passes re-request a *sample of URLs the
  crawl already found*, under a documented cap.

## Personas

| Persona | Needs from 012 |
|---|---|
| **Security-conscious developer** | "Does my `?lang=` reflect into a `Set-Cookie`? Does my password-reset email use the `Host` header? Is `TRACE` on?" — a finding that names the parameter / header / method and shows the smuggled header, the reflected sentinel, or the `Allow` line. |
| **Pentester / consultant** | On an authorized engagement, a fast first pass over the request-envelope classes ZAP flags, so the report is not missing CRLF / host-header / XST, with confirmation against a baseline so it is not full of maybes. |
| **CI pipeline author** | A SARIF result when a build introduces a CRLF-reflecting redirect or turns `TRACE` on, so `--fail-on high` / `--fail-on medium` blocks the deploy — no external service in the loop. |
| **Check author / contributor** | `detect/crlf.py` as the reference for "prove a response-header effect in-band", and the host-header / methods passes as the reference for "a bounded per-URL active pass that is not an injection-point detector". |

## Functional requirements

### Detection

**RF-01 — CRLF injection detector** (`injection.crlf`)
- **Given** an Active scan with `injection.crlf` selected, **when** the
  `InjectionScanner` runs, **then** a new `crlf` detector is fanned for each
  injection point alongside the 006/009/011 detectors, drawing on the same shared
  `ActiveBudget` and the point's shared `Baseline`.
- **Given** the detector, **when** it runs for a point, **then** it sends
  `%0d%0a` / `%0d%0a%20` / `%E5%98%8A%E5%98%8D` (unicode-newline) prefixed
  payloads that attempt to inject: a marker header `X-WvInjected: <token>`, a
  marker cookie `Set-Cookie: wv<token>=1`, and a double-CRLF marker body
  `<html>wv<token></html>`.
- **Given** a response, **when** `httpx` has parsed back a header
  `x-wvinjected == <token>` (or a `Set-Cookie` with `wv<token>`) that the
  baseline response did not carry, **then** it emits an `injection.crlf` hit,
  `severity = HIGH`, `confidence = HIGH`, naming the parameter and quoting the
  injected header.
- **Given** the double-CRLF payload and a response whose body **is** the injected
  marker body (a split response) and whose earlier bytes match the app's normal
  headers, **then** it emits an `injection.crlf` hit, `severity = HIGH`,
  `confidence = HIGH`, noting a full response split.
- **Given** the payload string is reflected only in the response **body text**
  (not parsed as a header) or only in a `Location` value that stays on the target
  host, **then** it is **not** a CRLF hit (it may still be an open-redirect or
  XSS hit from another detector).

**RF-02 — CRLF parameter priority**
- **Given** the enumerated injection points, **when** the `crlf` detector order
  is chosen, **then** a point whose name is header-associated (`url`, `redirect`,
  `redirect_uri`, `next`, `return`, `goto`, `dest`, `lang`, `language`, `locale`,
  `region`, `country`, `currency`, `ref`, `referrer`, `callback`, `filename`,
  `file`, `download`, `name`, `title`, `id`) is tested **first** within budget —
  mirroring the 006/009/011 heuristics; other points are tested with a short
  canary set if budget remains.

**RF-03 — Host-header injection pass** (`injection.host-header`)
- **Given** an Active scan with `injection.host-header` selected, **when** the
  orchestrator runs, **then** a new bounded pass re-requests a sample of
  discovered in-scope pages — the entry page, every page carrying a `<form>`, and
  up to a documented cap (default 15) more, de-duplicated by path — once per
  poisoning vector: request `Host: webvigil.invalid`, then
  `X-Forwarded-Host: webvigil.invalid`, `X-Forwarded-Server`, `X-Host`,
  `X-Original-Host` (original `Host` kept).
- **Given** a poisoned response, **when** the sentinel `webvigil.invalid` appears
  — in an absolute `https?://webvigil.invalid` URL in the body, in the `Location`
  header, in `<base href="…webvigil.invalid…">`, or in
  `<link rel="canonical" href="…webvigil.invalid…">` / `<meta property="og:url">`
  — **and** the baseline (unpoisoned) response did **not** contain it, **then**
  it emits an `injection.host-header` hit, `severity = MEDIUM` (`HIGH` when the
  reflection is in a `Location` or a password-reset-looking link), naming the
  header that worked and quoting the reflected line.
- **Given** the pass, **then** every request goes through `ctx.http` with the
  scope guard, concurrency cap, per-host delay and timeout; WebVigil connects
  only to the target host (the sentinel is a header value, never a destination).
- **Given** the request budget (a documented cap, default ~60), **when** it is
  reached, **then** the pass stops and records a warning, not an error.

**RF-04 — In-band XXE step** (`injection.xxe`, opt-in)
- **Given** `[injection] xxe = true` (or `--xxe`) **and** `injection.xxe`
  selected **and** Active Mode, **when** the injection pass runs, **then** for
  each **POST** injection point it re-sends the point's body once as
  `Content-Type: application/xml` and once as `text/xml`, replacing the body with
  a documented external-entity payload set:
  - a SYSTEM entity reading `file:///etc/passwd` / `file:///c:/windows/win.ini`,
    expanded in an element the response echoes (reflected) and in an attribute
    that triggers a parse error (error-based);
  - a parameter-entity payload referencing an external DTD at an **in-scope**
    URL (so the scope guard permits the fetch attempt) whose failure names the
    external DTD;
  - a bounded nested-entity payload (≤ 5 entities, no amplification) to draw a
    "entity expansion" limit error.
- **Given** the response, **when** it contains a `/etc/passwd` (`root:.*?:0:0:`)
  or `win.ini` signature **or** an XML-parser error naming an entity / a DOCTYPE
  / an external reference — each **absent from the baseline** — **then** it emits
  an `injection.xxe` hit, `severity = HIGH`, `confidence = HIGH` for the file
  signature, `MEDIUM` for the parser-error-only case.
- **Given** the endpoint rejects the XML body (a `400`/`415` the baseline never
  returned, no signature), **then** it is **not** a hit.
- **Given** `[injection] xxe` is off (default), **then** no XML body is ever
  sent.

**RF-05 — HTTP-methods pass** (`http.methods.unsafe`)
- **Given** an Active scan with `http.methods.unsafe` selected, **when** the
  orchestrator runs, **then** a bounded pass sends an `OPTIONS` request to a
  sample of discovered in-scope URLs (the entry page + up to a documented cap,
  default 15, de-duplicated by path) and a single `TRACE` request to the entry
  URL.
- **Given** a `TRACE` response that is `200` **and** echoes the request line /
  headers back in its body, **then** it emits an `http.methods.unsafe` hit for
  **Cross-Site Tracing**, `severity = MEDIUM`, `cwe = (693,)`.
- **Given** an `OPTIONS` `Allow` (or `Public`) header that lists any of `PUT`,
  `DELETE`, `PATCH`, `CONNECT` for a URL that is **not** a static asset (by
  content-type / extension), **then** it emits an `http.methods.unsafe` hit
  naming the methods and the URL, `severity = MEDIUM`, `cwe = (650,)`, with a
  note that WebVigil did **not** verify they are unauthenticated.
- **Given** the pass, **then** it sends **only** `OPTIONS` and `TRACE` — never
  `PUT` / `DELETE` / `PATCH` / `CONNECT` / any state-changing verb.

**RF-06 — Hit shape**
- **Given** any 012 hit, **then** it carries `method` / `url` (and `param` for
  `crlf` / `xxe`), the chosen `severity` / `confidence`, a `title` naming what
  was proved, the payload / header / method that worked, and `evidence` of: the
  point (or URL), the payload / poisoned header / method, and the proof (the
  smuggled header, the reflected sentinel line, the leaked file line, the parser
  error, or the `Allow` / `TRACE` echo).

### Checks

**RF-07 — `injection.crlf`**
- Registered — `category = INJECTION`, `mode = ACTIVE`, `default_severity = HIGH`,
  `cwe = (113, 93)`, references to the OWASP CRLF-injection page and the HTTP
  Response Splitting cheat sheet. One finding per hit; description explains that
  the parameter is written into a response header without stripping `\r\n`.

**RF-08 — `injection.host-header`**
- Registered — `category = INJECTION`, `mode = ACTIVE`,
  `default_severity = MEDIUM`, `cwe = (644,)`, references to the PortSwigger
  host-header research and the OWASP host-header page. One finding per hit;
  description explains that the application builds absolute URLs from a
  client-controlled header, enabling password-reset poisoning and cache
  poisoning.

**RF-09 — `injection.xxe`**
- Registered — `category = INJECTION`, `mode = ACTIVE`, `default_severity = HIGH`,
  `cwe = (611, 827)`, references to the OWASP XXE prevention cheat sheet. One
  finding per hit; description explains that an XML parser resolves external
  entities from the request body.

**RF-10 — `http.methods.unsafe`**
- Registered in a new `webvigil.checks.http` package — `category = HTTP` (a new
  `Category` member, or reuse an existing one — design decides), `mode = ACTIVE`,
  `default_severity = MEDIUM`, `cwe = (650, 693, 16)`, references to the OWASP
  testing guide (HTTP methods) and the XST advisory.

**RF-11 — `list-checks` and suppression**
- **Given** `webvigil list-checks`, **then** all four ids appear with their
  category / `active` / default severity.
- **Given** `[checks] disabled = ["injection.crlf"]` (or any id), **then** that
  check does not run; if the only check a pass feeds is disabled, that pass /
  detector does not run at all (no CRLF payloads, no host-header requests, no
  `OPTIONS` / `TRACE`, no XML body) — the 006 ADR-3 / 009 RF-11 gating.

### Config and CLI

**RF-12 — Minimal surface**
- **Given** `[injection]`, **then** it gains `xxe: bool = False` (documented next
  to `stored_xss` as an opt-in that rewrites the request body); the CLI gains
  `--xxe / --no-xxe`.
- **Given** `[injection]`, **then** it may gain caps for the new passes
  (`host_header_sample`, `methods_sample`, or a shared `envelope_budget`) — exact
  keys are an Open question; kept minimal, config-only, no CLI flag.
- **Given** `--fail-on <severity>`, **then** it compares the new findings by
  severity exactly as today; no new exit code.
- **Given** the human-readable Active-scan summary, **then** the injection
  finding / request counters already include the new work; no format change.

### Fixture app and tests

**RF-13 — Vulnerable and hardened surface** (mirrors 006 RF-20 / 009 RF-12 / 011 RF-12)
- The **insecure** profile gains:
  - `GET /set-lang?lang=…` — reflects `lang` into a `Set-Cookie` header without
    stripping `\r\n` (CRLF).
  - `GET /reset` — renders a password-reset link built from the request `Host` /
    `X-Forwarded-Host` header (host-header injection).
  - `POST /api/xml` — parses the request body with an entity-resolving XML
    parser and echoes a field (XXE); for offline determinism it recognises the
    `file://` payloads and returns the fixture's `_ETC_PASSWD` or a canned
    parser error.
  - a route whose handler advertises `TRACE` and `PUT` in its `Allow` header and
    answers `TRACE` with a request echo.
- The **hardened** profile serves the safe equivalents: `lang` whitelisted,
  reset link built from a configured base URL, the XML endpoint disables DTDs
  (`resolve_entities=False`), `TRACE` disabled and `Allow` limited to `GET, POST`.
- Integration: an Active scan of the insecure profile reports `injection.crlf`,
  `injection.host-header`, `http.methods.unsafe`, and — with `--xxe` —
  `injection.xxe`, each with the expected location and evidence; the hardened
  profile reports **zero** 012 findings.

**RF-14 — Integration tests**
- Active scan of the insecure profile → the four checks fire (xxe only with the
  opt-in) with the expected ids / severities / locations.
- Passive scan → none fire, no `OPTIONS` / `TRACE` / poisoned `Host` / XML body
  is sent.
- Active scan of the hardened profile → zero 012 findings.
- Deterministic across repeated runs; stays within every budget.

**RF-15 — Unit tests**
- `crlf` detector: header-parsed-back positive; body-only reflection negative;
  `Set-Cookie` split; double-CRLF body split; baseline suppression; the
  header-name priority list.
- host-header pass: sentinel in `Location` / `<base>` / canonical / absolute URL
  → hit; sentinel absent → no hit; each `X-Forwarded-*` vector; the sample cap
  and the budget warning.
- xxe step: `/etc/passwd` signature → HIGH; parser-error-only → MEDIUM; `400`
  rejection → no hit; `xxe` off → no XML body; both content types tried.
- methods pass: `TRACE` echo → XST hit; `PUT`/`DELETE` in `Allow` on an app route
  → hit; a static asset advertising `OPTIONS, GET, HEAD` → no hit; never sends a
  write verb (asserted via a request spy).

### Reporting

**RF-16 — Reporters unchanged**
- No reporter gains a field or a section. 012 findings flow through the same
  `Finding` path; `CWE-113` / `CWE-644` / `CWE-611` / `CWE-650` ride the existing
  `cwe` field. A saved canonical JSON re-renders offline exactly as before.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.checks.injection` (`detect/crlf.py`, the host-header
and xxe steps) and a new `webvigil.checks.http` package, plus one `[injection]`
field and one CLI flag. Detection is `re` + `httpx.Headers` + the existing HTTP
layer — **WebVigil never parses XML itself**, it sends the payload and reads the
response as text. Nothing imported from `webvigil.cli` / `webvigil.api` / `web/`.
`import-linter` unchanged (add the new `webvigil.checks.http` under the existing
`webvigil.checks` source module).

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy` covering
the new modules. No `web` gate work (engine + CLI only).

**RNF-03 — Safe by default and non-destructive**
A passive scan is byte-for-byte unchanged and issues no crafted request. The 012
passes run only past `--mode active --authorized-by`. The methods pass sends only
`OPTIONS` / `TRACE`. The host-header pass sends only `GET`. The XXE step is
opt-in, sends only `POST`, and writes no persistent data (it re-sends an existing
POST point's body re-typed as XML). CRLF payloads are parameter values. Every
crafted request is in-scope, rate-limited, and bounded by a documented budget.

**RNF-04 — Bounded work**
`crlf` draws on the shared `ActiveBudget` and the per-point cap. The host-header
and methods passes each have a documented URL-sample cap and a request budget;
hitting any cap is a scan warning, never an error. The XXE step sends ≤ ~6
requests per POST point.

**RNF-05 — Determinism and false-positive discipline**
- Given the same target responses, the same findings / evidence / ordering.
- CRLF requires the injected header **parsed back by `httpx`**, not a body-text
  reflection.
- Host-header requires the sentinel in a URL-shaped position, absent from the
  baseline.
- XXE requires a file signature or a named parser error, not a bare `5xx`.
- Methods requires an actual `Allow` entry / a `TRACE` echo.
- The hardened fixture profile yields zero 012 findings.

**RNF-06 — Scope guard intact**
`webvigil.invalid` (host-header sentinel) and the external-DTD URL (XXE) are
values in requests to the **in-scope target**; WebVigil issues no request to an
off-scope host. A `Location` pointing at the sentinel is recorded, not followed
(spec 001 RF-04, unchanged).

**RNF-07 — Python support**
CPython 3.12 and 3.13 (existing CI matrix).

**RNF-08 — Docs**
`docs/active-injection.md` (or a new `docs/request-envelope.md`) gains a section:
the four classes, how each is proved in-band, the Windows caveat where relevant,
and an explicit statement that **blind XXE and request smuggling are not covered
and need a collaborator / raw-socket control**. `README.md` coverage table,
`CLAUDE.md` layer-3 paragraph, and `specs/README.md` roadmap updated; 012 moves
`draft → approved → in progress → done`.

## Resolved decisions

Settled with Ryan on 2026-09-08 (approved the requirements with the proposed resolutions unchanged):

1. **All four ship in 012 (not split).** The four are one theme — the request
   envelope — and share the "re-request / re-shape, don't fuzz a value" idea for
   three of them. *Decided: one spec, 012, with XXE clearly opt-in and
   isolatable so it can be cut late if it proves thin against real targets.*
2. **XXE scope.** In-band only (file-read reflected + error-based + a bounded
   entity-limit error), opt-in `--xxe`, content-type flip on POST points. **Not**
   in 012: blind/OOB XXE, XInclude, XSLT, SVG-upload XXE (that rides 014),
   SOAP-specific payloads. *Decided: as described; if design finds the
   content-type flip is almost always a 400 on realistic targets, XXE moves to
   its own opt-in spec and 012 ships with three checks.*
3. **`http.methods.unsafe` is `mode = ACTIVE`, no extra flag.** `OPTIONS` / `TRACE`
   are safe and idempotent, but sending any non-`GET`/`POST` verb is where the 006
   line drew the boundary. *Decided: Active, no flag — it costs
   almost nothing inside an Active scan and keeps the "crafted verb ⇒ Active"
   rule clean.*
4. **One `http.methods.unsafe` check**, not two (`.trace` + `.dangerous`).
   *Decided: one check, two finding shapes — same
   as `injection.cmdi.os` covering echo + time.*
5. **`Category.HTTP` for the methods check** — a new enum member (a method is not
   a header). *Decided: add `Category.HTTP`; no API/UI change since `category` is
   an opaque string downstream.*
6. **CRLF severity.** HIGH (a full response split is XSS + cache poisoning);
   header-only injection is arguably MEDIUM. *Decided: default HIGH, the
   header-only case still HIGH because `Set-Cookie` injection alone is session
   fixation.*
7. **One shared `EnvelopeScanner` pass** for host-header + methods (both
   re-request a URL sample); `xxe` stays inside the `InjectionScanner`.
   *Decided: one shared pass (both re-request
   a URL sample); `xxe` stays inside the `InjectionScanner` (it is a POST-point
   step). Design confirms.*

## Open questions

None. `design.md` written and approved-pending.
