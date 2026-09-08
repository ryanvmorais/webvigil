---
feature: Unrestricted file upload + residual in-band active checks — LDAP / XPath / SSI injection (Active Mode)
status: done
date: 2026-09-08
related:
  - 006-active-injection/requirements.md
  - 008-stored-xss/requirements.md
  - 011-rce-injection/requirements.md
  - 012-protocol-injection/requirements.md
origin: conception
---

# 014 — File upload and residual in-band active checks

## Context and problem

Specs 006 / 009 / 011 / 012 brought WebVigil to in-band parity with OWASP ZAP /
Wapiti on the injection classes a reviewer would expect: reflected and stored
XSS, SQLi, path traversal, open redirect, SSRF, OS command injection, SSTI, CRLF,
host-header injection, in-band XXE, HTTP methods. The dependency, disclosure and
passive coverage is at parity or ahead.

Two gaps are left in the "active-scan vuln coverage" column, both **in-band, no
headless browser, no out-of-band collaborator** — the line every spec since 006
has held:

1. **Unrestricted file upload** — CWE-434. An endpoint that stores an uploaded
   file and later serves it back, without validating the extension / content
   type / content, lets an attacker upload a web shell (`.php`, `.jsp`, `.aspx`),
   an HTML/SVG file that runs script in the site's origin (stored XSS), or a file
   whose *name* traverses out of the upload directory. It is provable **in-band**:
   upload a **benign** marker file with a dangerous name / type, then fetch it
   back and check whether the server (a) executed it — a `<?php echo 7*7; ?>`
   marker comes back as `49`, not as source — or (b) serves it inline with a
   dangerous `Content-Type` (`text/html`, `image/svg+xml`) rather than as a
   download. WebDAV-style `PUT` of a file is the same class from a different
   verb.
2. **Residual injection detectors** — the injection sinks ZAP / Wapiti fuzz that
   WebVigil's spec-006 pass does not yet cover and that *are* in-band-provable:
   - **LDAP injection** — CWE-90. A parameter spliced into an LDAP search filter.
     Provable in-band: an LDAP-parser error naming the filter, or a
     `*)(uid=*))(|(uid=*` / `*` payload that widens the result set versus the
     baseline.
   - **XPath / XQuery injection** — CWE-643. A parameter spliced into an XPath
     expression over an XML store. Provable in-band: an XPath-parser error, or a
     `' or '1'='1` / `x' or 1=1 or 'x'='y` payload that returns more nodes than
     the baseline.
   - **Server-Side Includes (SSI) / Edge-Side Includes (ESI) injection** —
     CWE-97. A parameter reflected into a page that a server-side include
     processor or an ESI-aware cache/proxy then evaluates. Provable in-band
     (echo): `<!--#echo var="DATE_LOCAL"-->` / `<esi:vars>` expands, and an
     arithmetic-style probe (`<!--#exec cmd="..."-->` is *not* sent — that is
     command injection; the echo/`printenv` form is enough) produces output the
     baseline did not carry.

Everything ZAP / Wapiti do beyond this list needs a browser, a collaborator, or a
stateful login, or is a known false-positive generator — see
[Gap analysis](#gap-analysis-active-checks-in-scope-vs-out) for the full accounting.

### Where it sits

```
webvigil.checks.injection                        (Category.INJECTION, mode = ACTIVE)
       ├── injection.xss.* / sqli.* / traversal / redirect        [006]
       ├── injection.xss.stored                                   [008]
       ├── injection.ssrf.* / cmdi.os / ssti / crlf / xxe         [009/011/012]
       ├── injection.ldap             [014]  ← LDAP-filter error, or a payload that
       │                                       widens the result set, baseline-diffed
       ├── injection.xpath            [014]  ← XPath error, or a payload returning more
       │                                       nodes than the baseline
       └── injection.ssi              [014]  ← an SSI/ESI directive the server evaluates
                                               into output absent from the baseline

webvigil.checks.upload                            (new package — Category.UPLOAD)
       └── upload.unrestricted        [014]  ← a benign marker file, uploaded with a
                                               dangerous name / type, is retrievable
                                               and executed or served inline

UploadScanner   a new orchestrator pass (model of StoredXssScanner / EnvelopeScanner):
                for every discovered file-upload form, and for a PUT probe on the
                entry URL, submit benign marker files and fetch them back. Opt-in
                (--file-upload / [injection] file_upload), because it writes files
                the target keeps.
ldap/xpath/ssi  three new detectors in the existing 006 InjectionScanner pass —
                they reuse the shared ActiveBudget, per-point Baseline and DetectCtx
                unchanged (value injection, exactly like sqli / cmdi).
```

`injection.ldap` / `.xpath` / `.ssi` reuse the 006 machinery with **no** new
mechanics. `upload.unrestricted` needs one mechanic 006 does not have — a
`multipart/form-data` request body, and a bounded `PUT` — which the HTTP layer
gains as a thin passthrough (`HttpClient.request(files=…)`, wrapping `httpx`'s
own `files=`). The engine still imports nothing from `webvigil.cli` /
`webvigil.api` / `web/`; detection is `re` + `httpx` + the existing HTTP layer;
**no new runtime dependency** (WebVigil parses none of LDAP / XPath / XML / SSI
itself — the *target* does; WebVigil sends the payload and reads the response as
text). `import-linter` gains the new `webvigil.checks.upload` package under the
existing `webvigil.checks` layer, no contract change.

## Goals

### Part 1 — Unrestricted file upload

- **`UploadScanner` orchestrator pass** — a new pass modelled on
  `StoredXssScanner` / `EnvelopeScanner`: it runs only when the scan is Active,
  the `upload.unrestricted` check is selected, **and** `[injection] file_upload`
  (or `--file-upload`) is on. Off by default because it writes files the target
  stores and WebVigil cannot reliably delete (same discipline as `--stored-xss`).
- **Upload-form discovery** — the crawler already records `<input type="file">`
  fields (`FormField.type == "file"`). The pass takes every discovered `<form>`
  whose `enctype` is `multipart/form-data` (or that has a file field), excluding
  the auth / destruction-shaped forms the injection package already filters.
- **Benign marker payloads, one family per outcome** — for each upload form the
  pass sends a small set of files, each carrying a unique `wv<token>` marker:
  - **server-side execution** — a file named `wv<token>.php` (and `.phtml`,
    `.php5`, `.jsp`, `.asp`, `.aspx` variants within budget) whose body is
    `wv<token>-<a>x<b>=<!--marker-->` plus `<?php echo <a>*<b>; ?>` /
    `<% out.print(<a>*<b>); %>` — **harmless**: it computes a product, nothing
    else.
  - **client-side execution** — a file named `wv<token>.html` / `.svg` /
    `.xhtml` carrying `<script>/*wv<token>*/</script>` and the marker text —
    harmless unless a victim's browser opens it (documented, like a stored-XSS
    marker).
  - **filter / extension bypass** — the same HTML content under
    `wv<token>.php.jpg`, `wv<token>.pHtml`, `wv<token>.html;.jpg`,
    `wv<token>.html%00.jpg`, and with the multipart part's `Content-Type` set to
    `image/jpeg` while the filename ends `.html` (content-type spoofing).
  - **path traversal in the filename** — a part named
    `../../wv<token>-trav.html` (and `..%2f`, backslash, and leading-`/`
    variants), to land the file outside the upload directory.
- **In-band proof (required)** — an upload is only a finding when the file is
  **retrievable** *and* one of:
  - the retrieved body contains the computed product (`<a>*<b>`) glued to the
    marker and **not** the literal `<?php` / `<%` source → server-side code
    execution, `severity = CRITICAL`, `confidence = HIGH`;
  - the retrieved body is served with `Content-Type: text/html` /
    `application/xhtml+xml` / `image/svg+xml` **and** no
    `Content-Disposition: attachment` → script runs in the site origin (stored
    XSS via upload), `severity = HIGH`, `confidence = HIGH`;
  - the traversal-named file is retrievable at a path **outside** the upload
    directory (e.g. web root) → `severity = HIGH`, `confidence = HIGH`;
  - the file is stored and retrievable but served as
    `application/octet-stream` + `attachment` (no exec, no inline) → the target
    still accepts an arbitrary type it should reject: `severity = MEDIUM`,
    `confidence = MEDIUM`, with a note that WebVigil could not make it execute.
- **Retrieval strategy** — the pass locates the stored file by (in order): a URL
  to `wv<token>` in the upload response body or a `Location` header; the same
  filename under a small set of conventional prefixes derived from the form
  action (`/uploads/`, `/files/`, `/media/`, `/static/uploads/`, the action's
  own directory); for the traversal case, the target's web root and the parent
  of each of those. Every retrieval is a scope-guarded `GET` through `ctx.http`.
- **`PUT` upload probe** — one `PUT wv<token>.txt` (text) and one
  `PUT wv<token>.html` to the entry URL's directory with a marker body, then a
  `GET` of the same URL. A `200`/`201`/`204` followed by a `GET` that returns the
  marker → `upload.unrestricted` (WebDAV/PUT), `severity = HIGH`. This is the
  **only** state-changing verb 014 sends, it is gated behind `--file-upload`, and
  the body is a benign marker (spec 012 declined to send `PUT` at all; 014's
  opt-in re-opens it for this bounded probe — see
  [Resolved decisions](#resolved-decisions)).
- **`upload.unrestricted` check** — a new `webvigil.checks.upload` package,
  `category = Category.UPLOAD` (a new `Category` member — a method is not a
  header, a file is not a parameter), `mode = ACTIVE`,
  `default_severity = HIGH`, `cwe = (434, 646)`, references to the OWASP
  Unrestricted File Upload page and the file-upload cheat sheet. One finding per
  distinct (form, outcome); the finding names the form field, the payload
  filename, the retrieval URL, and quotes the proof (the computed product, the
  `Content-Type` line, or the out-of-directory path).
- **Bounded and safe** — the pass has its own request budget
  (`[injection] upload_budget`, default ~80) and a per-form cap; hitting either is
  a scan warning, not an error. Every request is in-scope, rate-limited. It
  uploads only benign marker files (a PHP `echo`, an HTML `<script>` comment, a
  text marker) — never a real shell, never an executable, never a
  decompression bomb, never a file over a few hundred bytes.

### Part 2 — Residual in-band injection detectors

- **`injection.ldap`** (CWE-90) — a new `ldap` detector in the `InjectionScanner`
  pass, fanned per injection point alongside the 006/009/011/012 detectors on the
  shared budget and baseline:
  - an **error probe** — a single `)` / `*)(` / `(|` payload; a hit needs an
    LDAP-parser error signature in the response, absent from the baseline
    (`LDAPException`, `javax.naming.directory`, `com_err`,
    `Bad search filter`, `Protocol error`, `invalid DN syntax`,
    `ldap_search`, `Search: Bad search filter`, `com.sun.jndi.ldap`);
  - a **boolean probe** — send `*` and `*)(uid=*))(|(uid=*` (always-true filter
    injection) and a `)(!(x=*)` (always-false); a hit needs the always-true
    response to be materially larger / list more records than the baseline
    **and** the always-false response to match or shrink the baseline (the same
    two-sided differential the boolean-SQLi detector uses).
  - `severity = HIGH`, `confidence = HIGH` for the error signature, `MEDIUM` for
    the boolean-only differential.
- **`injection.xpath`** (CWE-643) — a new `xpath` detector, same shape:
  - an **error probe** — `'` / `"` / `]` / `count(//*` ; a hit needs an
    XPath/XQuery error signature absent from the baseline
    (`XPathException`, `XPathEvalError`, `SyntaxError: Invalid expression`,
    `lxml.etree.XPathEvalError`, `System.Xml.XPath`,
    `MS.Internal.Xml`, `org.jaxen`, `Expression must evaluate to a node-set`,
    `xmlXPathEval`, `unterminated string`);
  - a **boolean probe** — `' or '1'='1` / `x' or 1=1 or 'x'='y` (true) versus
    `' and '1'='2` (false); a hit needs the same two-sided differential as LDAP.
  - `severity = HIGH` for the error signature, `MEDIUM` for boolean-only.
- **`injection.ssi`** (CWE-97) — a new `ssi` detector:
  - an **echo probe** — inject `<!--#echo var="DATE_LOCAL"-->`,
    `<!--#printenv-->`, and the ESI equivalents `<esi:vars>$(HTTP_HOST)</esi:vars>`
    / `<!--esi-->` ; a hit needs the *evaluated* output in the response — a
    rendered date/time string, an environment-variable dump, or the host value —
    that the baseline (which reflected the literal directive, or nothing) did not
    carry. The literal directive reflected verbatim is **not** a hit (that is
    XSS-adjacent reflection, caught or not by the `xss` detector).
  - a **marker probe** — `<!--#echo var="wv<token>"-->` where the server's SSI
    processor, on an undefined variable, emits its configured error string
    (`[an error occurred while processing this directive]`) — that string in the
    response, absent from the baseline, is a `MEDIUM` hit (SSI is enabled and
    processing attacker input).
  - `severity = HIGH` for evaluated output, `MEDIUM` for the SSI-error string.
  - **Never sends `<!--#exec cmd=…-->` / `<!--#include file=…-->`** — command
    execution and file inclusion via SSI are covered in spirit by
    `injection.cmdi.os` / `injection.traversal.path`; the `ssi` detector proves
    *SSI evaluation*, not RCE, and stays non-destructive.
- **Parameter priority** — `ldap` front-loads names like `user`, `username`,
  `uid`, `cn`, `dn`, `search`, `filter`, `group`, `ou`, `member`, `mail`;
  `xpath` front-loads `xpath`, `xml`, `query`, `q`, `search`, `node`, `path`,
  `select`, `filter`, `id`, `name`, `user`; `ssi` front-loads `page`, `file`,
  `include`, `tpl`, `template`, `name`, `msg`, `q`, `search`, `q`, `lang`,
  `content`, `body` — mirroring the existing `is_pathlike` / `is_urllike` /
  `is_commandlike` heuristics. Other points get a short canary set if budget
  remains.
- **Detector-order placement** — `ldap` / `xpath` / `ssi` sit near the end of
  `_BASE_ORDER` (like `cmdi` / `ssrf`) so they cannot starve the fast 006
  detectors on a point whose name does not match; `_ordered_kinds` front-loads
  each to position 0 for a point its heuristic matches. `_PER_POINT_REQUEST_CAP`
  and `[injection] request_budget` rise to fit three more small families (exact
  numbers are a design decision — spec 011 raised 30→35 and 500→600).

### Cross-cutting

- **Gated by the existing Active-Mode attestation** — every 014 check is
  `mode = ACTIVE`; `--mode active --authorized-by` is the only legal gate.
  `--file-upload` is a noise/safety switch on top (it writes files), exactly like
  `--stored-xss` and `--xxe` — not a second attestation.
- **False-positive discipline** — every signal is confirmed against a per-point
  baseline (injection) or against the pre-upload state (upload); an upload is
  only a finding when the file is *retrieved*; LDAP/XPath boolean hits need a
  *two-sided* differential; the hardened fixture profile yields **zero** 014
  findings.
- **Fixture-app coverage** — the insecure profile gains a file-upload form + a
  store-and-serve endpoint (no validation, extension-guessed `Content-Type`, a
  fake `.php` "executor" that evaluates the `<?php echo NxM; ?>` marker offline
  for determinism), a `PUT`-accepting path, an LDAP-filter search endpoint, an
  XPath-over-XML endpoint, and an SSI-processing page. The hardened profile
  serves the safe equivalents (extension allow-list + `Content-Disposition:
  attachment` + `application/octet-stream`, `PUT` → 405, parameterised LDAP /
  XPath, SSI disabled). Integration tests assert the findings on one profile and
  zero on the other.
- **Docs** — a "File upload" section in `docs/active-injection.md` (or a sibling
  `docs/file-upload.md`) and an "LDAP / XPath / SSI injection" subsection, plus
  README / CLAUDE / `specs/README.md` roadmap updates. The doc states plainly
  that **archive extraction (zip-slip), image-library RCE, antivirus evasion and
  out-of-band upload triggers are not covered**.

## Non-goals

- **A real web shell, an executable, or any harmful upload.** 014 uploads only
  benign markers (a PHP `echo` of a product, an HTML `<script>` comment, a text
  string), each a few hundred bytes at most.
- **Archive extraction / zip-slip, decompression bombs, quota exhaustion.**
- **Image-parser / media-library RCE** (ImageMagick "ImageTragick", libwebp,
  EXIF-processor CVEs) — needs version-specific payloads, Nuclei territory,
  false-positive-prone.
- **Out-of-band upload triggers** — an uploaded XML that triggers blind XXE, an
  uploaded file that makes the server fetch a URL (blind SSRF via upload). Same
  call as blind SSRF / blind XXE: needs a collaborator, documented, not on the
  roadmap.
- **Antivirus / EDR evasion, polyglot files (GIFAR, PDF+JAR).**
- **Cleaning up uploaded files.** WebVigil cannot reliably delete what it
  uploads; the markers are benign and the behaviour is documented, exactly as
  for `--stored-xss`.
- **NoSQL injection, HTTP parameter pollution, remote file inclusion,
  expression-language injection, `eval()` code injection** — see the
  [gap analysis](#gap-analysis-active-checks-in-scope-vs-out); each is deferred
  for a stated reason (false-positive rate, OAST requirement, or an explicit
  earlier deferral).
- **SSI/ESI *command execution* (`<!--#exec-->`) or *file inclusion*
  (`<!--#include-->`)** — the `ssi` detector proves SSI evaluation with the
  `echo` / `printenv` form only; RCE and LFI via SSI are the `cmdi` / `traversal`
  detectors' territory.
- **Sending any state-changing verb other than the single gated `PUT` upload
  probe.** No `DELETE`, no `PATCH`, no `PUT` to a non-upload path.
- **A JavaScript engine, an OAST collaborator, a new runtime dependency, a
  headless browser** — unchanged since spec 001.
- **Web API / dashboard changes** — engine + CLI only, following 006 / 009 / 011
  / 012.
- **Stateful-login-dependent classes** (session fixation, logout invalidation,
  weak session id, verb-based auth bypass) — still deferred; each needs a login
  flow WebVigil does not have.

## Personas

| Persona | Needs from 014 |
|---|---|
| **Security-conscious developer** | "Can someone upload a `.php` to my avatar endpoint and run it? Does my `?user=` splice into an LDAP filter?" — a finding that names the form field / parameter, shows the uploaded marker coming back executed or inline, or the LDAP/XPath error, and points at the exact remediation. |
| **Pentester / consultant** | On an authorized engagement, a fast first pass over file upload and the LDAP/XPath/SSI sinks ZAP flags, so the report is not missing CWE-434 / CWE-90 / CWE-643, each confirmed in-band so it is not a page of maybes. |
| **CI pipeline author** | A SARIF result when a build ships an upload endpoint that serves `.html` inline or an LDAP-injectable search, so `--fail-on high` blocks the deploy — no external service in the loop. |
| **Check author / contributor** | `UploadScanner` as the reference for "a bounded active pass that writes state and verifies in-band"; `detect/ldap.py` as the reference for "error-signature + two-sided boolean differential in one detector". |

## Functional requirements

### Part 1 — File upload

#### RF-01 — `UploadScanner` pass gate

- **Given** an Active scan, **when** the orchestrator runs, **then** the
  `UploadScanner` pass runs **iff** `upload.unrestricted` is in the selected
  checks **and** `[injection] file_upload` (or `--file-upload`) is `True`.
- **Given** `[injection] file_upload` is `True` but the scan is Passive, **when**
  the scan runs, **then** the pass does not run and a warning records that file
  upload testing requires `--mode active` (mirroring the stored-XSS warning).
- **Given** the pass raises, **when** the orchestrator catches it, **then** it
  becomes a scan warning, not an aborted scan (the `_scan_envelope` /
  `_inject_stored` pattern).

#### RF-02 — Upload-form selection

- **Given** the crawled `<form>` inventory, **when** the pass selects targets,
  **then** it takes every form that has at least one `type="file"` field
  (`enctype` `multipart/form-data`, or forced to it), **excluding** forms the
  injection package's `_EXCLUDE_FORM_RE` already drops (login / register /
  delete / password / checkout …).
- **Given** no upload form was discovered, **when** the pass runs, **then** it
  still runs the `PUT` probe (RF-06) and otherwise records nothing.

#### RF-03 — Benign marker payloads

- **Given** a selected upload form, **when** the pass builds its payloads,
  **then** each payload is a file under a few hundred bytes carrying a unique
  `wv<token>` marker, in these families, tested in this order within budget:
  1. **server-side execution** — `wv<token>.php` with body
     `wv<token>=<?php echo <a>*<b>; ?>` (`<a>`, `<b>` are small random ints); the
     `.phtml` / `.php5` / `.jsp` / `.asp` / `.aspx` variants if budget remains.
  2. **client-side execution** — `wv<token>.html` / `.svg` with a
     `<script>/*wv<token>*/</script>` body and the marker text.
  3. **extension / content-type bypass** — family 2's content under
     `wv<token>.php.jpg`, `wv<token>.pHtml`, `wv<token>.html%00.jpg`, and with
     the multipart part `Content-Type` forced to `image/jpeg`.
  4. **filename path traversal** — a part filename of `../../wv<token>-trav.html`
     and the `..%2f` / backslash / leading-slash variants.
- **Given** a form with non-file fields, **when** the pass submits, **then** each
  non-file field is sent with its discovered default value so the submission is
  well-formed.

#### RF-04 — Retrieval

- **Given** an upload response, **when** the pass looks for the stored file,
  **then** it tries, in order and within budget: a `wv<token>`-containing URL in
  the response body or `Location`; the payload filename under `/uploads/`,
  `/files/`, `/media/`, `/static/uploads/`, and the form action's own directory;
  for the traversal payload, the target web root and the parent directory of
  each of those prefixes.
- **Given** each candidate URL, **when** the pass fetches it, **then** it is a
  scope-guarded `GET` through `ctx.http`; an out-of-scope candidate is skipped,
  never followed.

#### RF-05 — In-band proof and severity

- **Given** a retrieved file whose body contains the computed product `<a>*<b>`
  glued to the `wv<token>` marker **and not** the literal `<?php` / `<%` source,
  **then** it emits `upload.unrestricted`, `severity = CRITICAL`,
  `confidence = HIGH`, title naming server-side code execution.
- **Given** a retrieved file served with `Content-Type` in
  `{text/html, application/xhtml+xml, image/svg+xml}` **and no**
  `Content-Disposition: attachment`, **then** it emits `upload.unrestricted`,
  `severity = HIGH`, `confidence = HIGH`, title naming stored XSS via upload.
- **Given** the traversal-named file retrievable at a path **outside** every
  known upload prefix, **then** it emits `upload.unrestricted`,
  `severity = HIGH`, `confidence = HIGH`, title naming a filename-traversal
  write.
- **Given** a file that is stored and retrievable but served as
  `application/octet-stream` with `Content-Disposition: attachment`, **then** it
  emits `upload.unrestricted`, `severity = MEDIUM`, `confidence = MEDIUM`, title
  noting the target accepts an arbitrary file type but WebVigil could not make it
  execute or render.
- **Given** a file the target rejected (a `4xx` the baseline upload never
  returned, or a file not retrievable by any candidate URL), **then** it is
  **not** a finding.

#### RF-06 — `PUT` upload probe

- **Given** the pass runs (RF-01), **when** it starts, **then** it sends one
  `PUT` of `wv<token>.txt` (a text marker body) and, if that is accepted, one
  `PUT` of `wv<token>.html`, to the entry URL's directory.
- **Given** a `PUT` that returns `200` / `201` / `204` **and** a subsequent
  `GET` of the same URL that returns the marker body, **then** it emits
  `upload.unrestricted`, `severity = HIGH` (`CRITICAL` when the `.html` is served
  as `text/html`), `confidence = HIGH`, title naming WebDAV / `PUT` upload.
- **Given** the pass, **then** `PUT` is the only state-changing verb 014 sends,
  it is sent only under `--file-upload`, only to the entry directory, and only
  with a benign marker body.

#### RF-07 — `upload.unrestricted` check

- Registered in a new `webvigil.checks.upload` package —
  `category = Category.UPLOAD` (new member), `mode = ACTIVE`,
  `default_severity = HIGH`, `cwe = (434, 646)`, references to the OWASP
  Unrestricted File Upload page and the File Upload cheat sheet. It issues **no**
  request — `UploadScanner` has run in the orchestrator and left
  `UploadHit`s on `ctx.observations`; the check filters and renders them. One
  finding per distinct `(form action, field, outcome)` or per `PUT` path;
  `dedup_key` is the field name (or `"PUT"`).

### Part 2 — LDAP / XPath / SSI

#### RF-08 — `injection.ldap` detector

- **Given** an Active scan with `injection.ldap` selected, **when** the
  `InjectionScanner` runs, **then** an `ldap` detector is fanned for each
  injection point on the shared `ActiveBudget` and the point's `Baseline`.
- **Given** the error probe (`)` / `*)(` / `(|`), **when** the response carries
  an LDAP-parser error signature absent from the baseline, **then** it emits an
  `injection.ldap` hit, `severity = HIGH`, `confidence = HIGH`, quoting the
  error.
- **Given** the boolean probe, **when** the always-true filter injection
  (`*)(uid=*))(|(uid=*`, `*`) yields a response materially larger / listing more
  records than the baseline **and** the always-false probe (`)(!(x=*)`) matches
  or shrinks the baseline, **then** it emits an `injection.ldap` hit,
  `severity = MEDIUM` (boolean-only), `confidence = MEDIUM`.
- **Given** only a bare `5xx` with no LDAP signature, or a one-sided size
  change, **then** it is **not** a hit.

#### RF-09 — `injection.xpath` detector

- **Given** `injection.xpath` selected, **when** the pass runs, **then** an
  `xpath` detector is fanned per point, same budget/baseline.
- **Given** the error probe (`'` / `"` / `]` / `count(//*`), **when** the
  response carries an XPath/XQuery error signature absent from the baseline,
  **then** it emits an `injection.xpath` hit, `severity = HIGH`,
  `confidence = HIGH`.
- **Given** the boolean probe (`' or '1'='1` true vs `' and '1'='2` false),
  **when** the two-sided differential holds, **then** it emits an
  `injection.xpath` hit, `severity = MEDIUM`, `confidence = MEDIUM`.
- **Given** a bare `5xx` or a one-sided change, **then** it is **not** a hit.

#### RF-10 — `injection.ssi` detector

- **Given** `injection.ssi` selected, **when** the pass runs, **then** an `ssi`
  detector is fanned per point.
- **Given** the echo probe (`<!--#echo var="DATE_LOCAL"-->`, `<!--#printenv-->`,
  `<esi:vars>$(HTTP_HOST)</esi:vars>`), **when** the response carries the
  *evaluated* output (a rendered date, an env dump, the host) that the baseline
  did not, **then** it emits an `injection.ssi` hit, `severity = HIGH`,
  `confidence = HIGH`.
- **Given** the marker probe (`<!--#echo var="wv<token>"-->`), **when** the
  response carries the SSI processor's undefined-variable error string
  (`[an error occurred while processing this directive]`) absent from the
  baseline, **then** it emits an `injection.ssi` hit, `severity = MEDIUM`,
  `confidence = MEDIUM`.
- **Given** the directive is reflected **verbatim** (not evaluated), **then** it
  is **not** an `injection.ssi` hit.
- **Given** the detector, **then** it never sends `<!--#exec-->` or
  `<!--#include-->`.

#### RF-11 — Detector priority and budget

- **Given** the enumerated points, **when** the `ldap` / `xpath` / `ssi`
  detector order is chosen, **then** a point whose name matches that detector's
  name list (RF, Part 2 goals) is tested first within budget; others get a short
  canary set if budget remains.
- **Given** three new detector families, **when** the design sets the caps,
  **then** `_PER_POINT_REQUEST_CAP` and `[injection] request_budget` rise by a
  documented, fixture-measured amount (spec 011 precedent: 30→35, 500→600).

### Cross-cutting

#### RF-12 — Hit shape

- **Given** any 014 hit, **then** it carries `method` / `url` (and `param` for
  the injection detectors, `field` / filename for upload), the chosen `severity`
  / `confidence`, a `title` naming what was proved, the payload / filename /
  directive that worked, and `evidence` of: the point (or form), the payload,
  and the proof (the leaked product, the `Content-Type` line, the
  out-of-directory path, the LDAP/XPath error, or the evaluated SSI output).

#### RF-13 — `list-checks` and suppression

- **Given** `webvigil list-checks`, **then** `upload.unrestricted`,
  `injection.ldap`, `injection.xpath`, `injection.ssi` all appear with their
  category / `active` / default severity.
- **Given** `[checks] disabled = ["injection.ldap"]` (or any id), **then** that
  check does not run; if the only check a pass / detector feeds is disabled, that
  pass / detector does not run at all — no upload files, no LDAP payloads (the
  006 ADR-3 / 009 RF-11 gating).

#### RF-14 — Config and CLI

- **Given** `[injection]`, **then** it gains `file_upload: bool = False`
  (documented next to `stored_xss` and `xxe` as an opt-in that writes to the
  target) and `upload_budget: int = 80`; the CLI `scan` command gains
  `--file-upload / --no-file-upload`.
- **Given** `[injection] request_budget` / `max_injection_points`, **then** the
  defaults may rise for the three new detector families (config-only, no CLI
  flag), exact values a design decision.
- **Given** `--fail-on <severity>`, **then** it compares the new findings by
  severity exactly as today; no new exit code.
- **Given** the human-readable Active-scan summary, **then** the existing
  injection / crafted-request counters already include the new work; if
  `--file-upload` ran, the summary notes "N file(s) uploaded" the way the
  authenticated-scan line notes cookies (design decides the exact wording).

#### RF-15 — Fixture app

- The **insecure** profile gains:
  - an upload `<form enctype="multipart/form-data">` on the index and a
    `POST /upload` handler that stores `(filename, content_type, body)` with **no
    validation** and returns a link to `/files/<filename>`;
  - a `GET /files/<name>` handler that serves the stored bytes with a
    `Content-Type` guessed from the extension (`.html` → `text/html`, `.svg` →
    `image/svg+xml`, `.php` → executed: the handler evaluates the
    `<?php echo A*B; ?>` marker offline and returns the product), no
    `Content-Disposition`;
  - `PUT /files/<name>` accepted (stores and 201s);
  - `GET /dir?user=…` — splices `user` into an LDAP filter string; a broken
    filter returns a canned `LDAPException: Bad search filter` body, `*` returns
    the full user list, a normal value returns one row;
  - `GET /xdoc?title=…` — runs an XPath built from `title` over a small XML
    catalogue; a broken expression returns a canned
    `lxml.etree.XPathEvalError`, `' or '1'='1` returns every node;
  - `GET /page?tpl=…` — reflects `tpl` into an HTML page and evaluates
    `<!--#echo var="…"-->` / `<!--#printenv-->` directives (offline: a fixed
    date string and a canned env dump), and emits the SSI error string for an
    undefined variable.
- The **hardened** profile serves the safe equivalents: upload allow-lists
  `.png` / `.jpg`, re-serves everything as `application/octet-stream` +
  `Content-Disposition: attachment`, `PUT` → `405`; `/dir` and `/xdoc` use a
  parameterised lookup (payloads return the baseline row set); `/page` HTML-escapes
  `tpl` and never processes SSI.
- The new endpoints are reachable by the crawl (linked from the insecure index,
  like the existing `_INJECTION_LINKS`), taking care not to push the spec-008
  Phase-B re-crawl past `_STORED_REFETCH_CAP` (a design/impl note).

#### RF-16 — Integration tests

- Active scan of the insecure profile with `--file-upload` → `upload.unrestricted`
  (server-exec **and** inline-HTML **and** traversal **and** `PUT` shapes),
  `injection.ldap`, `injection.xpath`, `injection.ssi` all fire with the expected
  ids / severities / locations.
- Active scan **without** `--file-upload` → no upload file is sent, no `PUT`; the
  three injection detectors still fire.
- Passive scan → none fire; no multipart body, no `PUT`, no LDAP/XPath/SSI
  payload is sent.
- Active scan of the hardened profile (with `--file-upload`) → zero 014 findings.
- Deterministic across repeated runs; stays within every budget.

#### RF-17 — Unit tests

- `UploadScanner`: form selection (file field in / auth form out); each payload
  family; retrieval by response URL vs conventional prefix; the four proof
  branches and their severities; the `MEDIUM` "accepted but inert" branch;
  rejection → no hit; budget cap → warning; `PUT` probe positive and negative;
  it uploads only benign markers (asserted on the request spy).
- `ldap` detector: error signature → HIGH; two-sided boolean differential →
  MEDIUM; one-sided change → none; bare `5xx` → none; the name priority list.
- `xpath` detector: the same four cases.
- `ssi` detector: evaluated output → HIGH; SSI-error string → MEDIUM; verbatim
  reflection → none; never sends `#exec` / `#include` (request spy).
- `Category.UPLOAD` is a plain string member (mirrors the spec-013
  `Category.CONTENT` test).
- `HttpClient.request(files=…)` sends a multipart body; `files` and `data` /
  `content` are mutually exclusive.

#### RF-18 — Reporting

- No reporter gains a field or a section. 014 findings flow through the same
  `Finding` path; `CWE-434` / `CWE-90` / `CWE-643` / `CWE-97` ride the existing
  `cwe` field. `Category.UPLOAD` is an opaque string downstream — the API
  `meta.py` route returns `check.category.value`, the dashboard derives its
  filter from the returned list, so no API / UI / `openapi.json` change (the
  spec-012 `HTTP` / spec-013 `CONTENT` precedent). A saved canonical JSON
  re-renders offline exactly as before.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.checks.injection` (`detect/ldap.py`,
`detect/xpath.py`, `detect/ssi.py`) and a new `webvigil.checks.upload` package
(`scanner.py` + `checks.py`), plus one HTTP-layer passthrough (`files=`), two
`[injection]` fields and one CLI flag. Detection is `re` + `httpx` + the existing
HTTP layer — **WebVigil parses none of LDAP / XPath / XML / SSI itself**. Nothing
imported from `webvigil.cli` / `webvigil.api` / `web/`. `import-linter` gains
`webvigil.checks.upload` under the existing `webvigil.checks` layer, no contract
change.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy`
covering the new modules. No `web` gate work (engine + CLI only).

**RNF-03 — Safe by default and non-destructive**
A Passive scan is byte-for-byte unchanged and issues no crafted request. The
LDAP / XPath / SSI detectors run past `--mode active --authorized-by` and send
only parameter values (no `#exec`, no `#include`). The upload pass runs only past
`--mode active --authorized-by` **and** `--file-upload`; it uploads only benign
markers (a PHP `echo`, an HTML `<script>` comment, a text string), each a few
hundred bytes; it sends exactly one kind of state-changing verb (`PUT` of a
marker to the entry directory) and only under the opt-in. Uploaded markers are
left on the target and the behaviour is documented, exactly as for `--stored-xss`.
Every crafted request is in-scope, rate-limited, and bounded by a documented
budget.

**RNF-04 — Bounded work**
The `ldap` / `xpath` / `ssi` detectors draw on the shared `ActiveBudget` and the
per-point cap. The upload pass has its own `[injection] upload_budget` (default
~80) and a per-form cap; hitting either is a scan warning, never an error.

**RNF-05 — Determinism and false-positive discipline**
- Given the same target responses, the same findings / evidence / ordering.
- An upload is a finding only when the file is **retrieved** and executed /
  served inline / landed out of directory; "accepted but inert" is a distinct
  lower severity.
- LDAP / XPath boolean hits need a **two-sided** differential (true widens,
  false does not), like boolean SQLi.
- SSI needs **evaluated** output or the SSI-error string, not a verbatim echo.
- The hardened fixture profile yields zero 014 findings.

**RNF-06 — Scope guard intact**
Every upload, retrieval, `PUT` and injection request goes to the in-scope
target through `ctx.http`. A traversal-named upload is retrieved only from
in-scope paths; an out-of-scope candidate URL is skipped. A `Location` pointing
off-scope is recorded, not followed (spec 001 RF-04, unchanged).

**RNF-07 — Credentials never leak**
`[auth]` cookies and headers (spec 007 / 013) ride the upload / `PUT` / injection
requests through the HTTP layer's existing host-gated attachment, and never
appear in a finding, evidence line, warning, log, or scan metadata (spec 013
RNF-04). The upload pass echoes back only the marker file it sent and the
retrieved file's `Content-Type` / body excerpt.

**RNF-08 — Python support**
CPython 3.12 and 3.13 (existing CI matrix).

**RNF-09 — Docs**
`docs/active-injection.md` (or a new `docs/file-upload.md`) gains the two
sections; the doc states plainly that **zip-slip, image-library RCE, AV evasion
and out-of-band upload triggers are not covered**. `README.md` coverage table,
`CLAUDE.md` layer-3 paragraph, and `specs/README.md` roadmap updated; 014 moves
`planned → draft → approved → in progress → done`.

## Resolved decisions

Answered by Ryan on 2026-09-08 via `/spec` questions:

1. **Scope — file upload *and* a residual sweep, this spec.** 014 covers
   unrestricted file upload **plus** the in-band injection detectors ZAP / Wapiti
   have that WebVigil lacks: LDAP, XPath, SSI. The full accounting is the
   [gap analysis](#gap-analysis-active-checks-in-scope-vs-out) below; the design
   phase may still cut Part 2 down (e.g. drop `ssi` if the fixture shows it is
   thin) the way spec 012 reserved the right to cut XXE.
2. **Upload pass is opt-in `--file-upload` on top of Active Mode.** It writes
   files the target keeps and WebVigil cannot reliably delete — the same
   discipline as `--stored-xss` / `--xxe`. Not a second legal gate.
3. **Filename path traversal is in scope for 014** (`../wv<token>.html` uploaded,
   then fetched from the web root).
4. **`Category.UPLOAD` — a new `Category` member.** Consistent with spec 012's
   `HTTP` and spec 013's `CONTENT`; an opaque string downstream, so no API / UI /
   reporter change.

Confirmed by Ryan on 2026-09-08 ("aprovado com as 6 resoluções propostas"):

5. **The `PUT` upload probe rides Part 1's opt-in.** Spec 012 deliberately never
   sent `PUT`. 014's `--file-upload` already writes files, so a single bounded
   `PUT` of a benign marker to the entry directory is coherent under the same
   switch — and it is the one place WebVigil can prove WebDAV-style upload
   in-band. *Alternative:* leave `PUT` upload out and cover only `multipart`
   forms. *Proposed: in, under `--file-upload`.*
6. **One `upload.unrestricted` check, four finding shapes** (server-exec /
   inline-HTML / traversal / `PUT`), not four check ids — same as
   `injection.cmdi.os` covering echo + time, and `http.methods.unsafe` covering
   TRACE + advertised verbs.
7. **`ssi` proves SSI *evaluation* only** — the `echo` / `printenv` form.
   `<!--#exec-->` (RCE) and `<!--#include-->` (LFI) are the `cmdi` / `traversal`
   detectors' job and stay out of the `ssi` detector to keep it non-destructive.
8. **LDAP / XPath / SSI go in the existing `InjectionScanner` pass**, not a new
   pass — they are value injections with the exact shape of `sqli` (error
   signature + boolean differential). No new orchestrator pass for Part 2.
9. **Expression-language injection (SpEL / OGNL / JEXL), `eval()` code
   injection** — **not** in 014. Spec 011 Resolved decision 4 deferred both; the
   SSTI detector's arithmetic machinery could be extended to EL later, but it is
   its own spec-sized surface (per-framework payloads, FP tuning). *Proposed:
   stays deferred, noted in the gap analysis.*
10. **NoSQL injection, HTTP parameter pollution, remote file inclusion** — **not**
    in 014. NoSQLi and HPP are notorious false-positive generators without a
    strong in-band oracle; RFI's blind form needs a collaborator and its in-band
    form overlaps SSRF / traversal. *Proposed: out, documented in the gap
    analysis; revisit only with a concrete FP-safe detector design.*

## Gap analysis — active checks, in-scope vs out

WebVigil vs OWASP ZAP active-scan rules and Wapiti/Wapiti-ng modules, filtered to
**in-band, no browser, no OAST, low false-positive** — the line held since 006.

| Class | In-band oracle? | Verdict |
|---|---|---|
| Unrestricted file upload (CWE-434) | yes — upload a benign marker, fetch it back, check exec / inline / out-of-dir | **014 Part 1** |
| LDAP injection (CWE-90) | yes — parser error + two-sided boolean result-set differential | **014 Part 2** |
| XPath / XQuery injection (CWE-643) | yes — parser error + two-sided boolean node-set differential | **014 Part 2** |
| SSI / ESI injection (CWE-97) | yes — an `#echo` / `<esi:vars>` directive evaluated into output | **014 Part 2** (evaluation only) |
| Expression-language injection (SpEL/OGNL/JEXL) | yes — arithmetic, like SSTI | **deferred** — spec 011 decision 4; own spec-sized surface |
| `eval()` code injection (PHP/Node) | partial | **deferred** — spec 011 decision 4 |
| NoSQL injection (Mongo/CouchDB) | weak — few reliable error/boolean oracles | **out** — FP-prone without an oracle |
| HTTP parameter pollution | weak | **out** — low signal, FP-prone |
| Remote file inclusion | blind form needs OAST; in-band form ⊆ SSRF/traversal | **out** — covered in spirit / needs collaborator |
| DOM XSS, client-side prototype pollution | needs a JS engine | **out** — non-goal since 001 |
| Session fixation, logout invalidation, weak session id | needs stateful login | **out** — deferred (007 line) |
| Verb-based auth bypass (GET-for-POST, `X-HTTP-Method-Override`) | partial, FP-prone without auth context | **out** — spec 012 "later candidate" |
| Web cache poisoning *confirmation* | needs cache-behaviour analysis / collaborator | **out** — spec 012 non-goal |
| Padding-oracle / crypto attacks | no in-band oracle | **out** |
| Image-library / media-parser RCE (ImageTragick, libwebp) | needs version-specific payloads | **out** — Nuclei territory, FP-prone |
| Blind XXE / XInclude / XSLT via upload | needs OAST | **out** — same call as blind SSRF |
| Zip-slip / archive extraction, decompression bombs | destructive / resource-heavy | **out** — non-goal |
| HTTP request smuggling | needs raw-socket framing | **out** — spec 012 non-goal |

## Open questions

None. Requirements approved 2026-09-08 with all ten resolutions. Two design-phase
latitudes remain, both flagged above: (a) Part 2 may be trimmed if the fixture
shows a detector is thin (spec 012 / XXE precedent); (b) nothing else outstanding.
