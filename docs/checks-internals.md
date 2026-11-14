# Checks internals

Internal reference for contributors and agents, moved out of `CLAUDE.md` so that file stays small (it is loaded into every Claude Code request). For how to write a check, see [writing-checks.md](writing-checks.md).

## Checks and orchestrator steps

**Checks** (`webvigil.checks`) — `PASSIVE`/`ACTIVE` plugins, registered by decorator +
entry points. Contract: `Check.run(ctx: ScanContext) -> list[Finding]`. `webvigil.checks.deps`
(spec 004) passively fingerprints the front end's JS libraries and matches them against a vendored
(offline) Retire.js database; the fingerprint step runs in the `Orchestrator`, not as a check.
`OsvProvider` (spec 010): opt-in online advisory provider (`--osv-online` /
`[deps] osv_online`, default off) — the only place in the engine that talks to a host that is not
the target. An `_osv_lookup` step in the `Orchestrator` (after the fingerprint) sends one
`POST /v1/querybatch` + one `POST /v1/query` per matched package to `api.osv.dev`, normalizes
the result into the native `Advisory` and hands it over through `ScanContext.observations`; the check merges
(`merge_advisories`, dedup by identifier) it with the offline match. A network failure becomes a
warning, not an error. No on-disk cache.
Details in [`docs/dependency-fingerprinting.md`](dependency-fingerprinting.md).
`webvigil.checks.disclosure` (spec 005): two passive checks (stack traces, directory
listing) + an opt-in probing step in the `Orchestrator` (`--probe` / `[disclosure]
probe`, GET-only, no Active gate) that tests a curated catalog of sensitive paths
(`.git`, `.env`, backups, debug endpoints) and feeds six probe-fed checks.
Details in [`docs/information-disclosure.md`](information-disclosure.md).
`webvigil.checks.injection` (spec 006): the first `ACTIVE` checks — reflected XSS,
SQLi (error/boolean/time; the boolean one seeds an empty field with a plausible value and accepts a
status-class split as evidence), path traversal, open redirect. The `Orchestrator` runs an
`InjectionScanner` step (it enumerates injection points from query params + `<form>`s
parsed from the bodies already downloaded — text fields and `<select>`, the latter tested last and never
a target of stored XSS —, a baseline per point, detectors under a shared request
budget); thin checks turn `ctx.observations.injection_hits` into findings.
Gate `--mode active --authorized-by`; GET/POST only; in-band detection (no headless browser,
no OAST collaborator). `[injection]` tunes the budget and time-based detection.
`injection.ssrf.metadata` (CRITICAL) / `injection.ssrf.internal` (HIGH)
(spec 009): **in-band** SSRF — an `ssrf` detector in the same pass that sends URL
payloads and proves the server-side fetch through the target's response (a cloud metadata marker,
a `file://` signature, an internal service banner, or a connection error echoing the URL).
`is_urllike` prioritizes URL-looking params. No flag, no config (the payloads only read).
Blind SSRF is not on the roadmap — it requires a hosted OAST collaborator, which crosses "the engine only
talks to the target" and the repo-only distribution; whoever needs it pairs the scan with their own
external collaborator. `injection.cmdi.os` (CRITICAL) / `injection.ssti` (HIGH) (spec 011):
**in-band** server-side RCE — two new detectors in the same pass. `cmdi` has an
echo stage (shell break + `echo <marker>=$((a*b))` → computed product glued to the
marker, absent from the baseline; in the Windows variant the product must be printed **after** the
marker, as an integer) and a time-based stage (`sleep`/`ping -n`, confirmed
against a delay-0 control, gate `[injection] time_based_cmdi` / `--no-time-based-cmdi`,
default on, sleep sub-budget shared with `sqli-time`). `ssti` does a polyglot →
engine error signature, then per-engine arithmetic payloads → evaluated product
glued to the marker; it identifies the engine (`{{7*'7'}}` → `7777777` Jinja2, `49` Twig).
`is_commandlike` prioritizes params named after a command/template; the stricter `_SHELL_NAMES`
unlocks the full echo set and the time-based stage of `cmdi`. Blind command
injection (no output, no timing) is left out — same reason as blind SSRF.
`_PER_POINT_REQUEST_CAP` went from 30 → 35 and `request_budget` from 500 → 600 (more
detector families per point).
`injection.crlf` (HIGH) / `injection.host-header` (MEDIUM) / `injection.xxe` (HIGH) /
`http.methods.unsafe` (MEDIUM, new `Category.HTTP`) (spec 012): **in-band**
request-envelope injection. `crlf` is a new detector in the `InjectionScanner` (`%0d%0a` payload →
injected header/cookie/body that `httpx` parses back, not text reflection).
`xxe` is an opt-in detector (`[injection] xxe` / `--xxe`, default off, POST points only,
re-sends the body as XML with an external entity → file signature or parser error).
`host-header` + `http.methods.unsafe` come from a new `EnvelopeScanner` pass
(`webvigil.checks.envelope`, modeled on `DisclosureProbe`) that re-requests a sample of crawled URLs
with `Host`/`X-Forwarded-*` = `webvigil.invalid` (sentinel in an absolute URL /
`Location` / `<base>` / canonical) and with `OPTIONS`/`TRACE` (XST, advertised dangerous
verbs). It never sends a destructive verb. Blind XXE and HTTP request smuggling are left out
(collaborator / raw socket). `TRACE` was added to `_IDEMPOTENT`; `HttpClient.request` gained
`content=`.
`injection.xss.stored` (spec 008):
separate `StoredXssScanner` pass
(after the reflected one, opt-in `--stored-xss` / `[injection] stored_xss`, default off —
it writes `<wvstored…>` markers that the target keeps). Phase A injects one marker per injection
point; Phase B does a 1-hop re-crawl (`Crawler.recrawl`) from the frontier of the 1st
crawl and correlates by token. The finding's location = the injection point (stable
fingerprint); the render page(s) go in the evidence. Details in
[`docs/active-injection.md`](active-injection.md).
`webvigil.checks.csrf` (spec 007): passive checks — `csrf.form.no-token` flags a state-changing
`POST` form without an anti-CSRF token, with confidence weighted by the session cookie's `SameSite`
(it also sees the `POST` form that is just a button, which the parser now keeps in the inventory), and
`csrf.form.state-change-over-get` (MEDIUM, CWE-352/650) flags a `GET` form without a token that changes a password or
carries a destructive verb, without ever submitting it. It reads `ScanContext.forms` (the crawler now parses `<form>`s during `discover()`
and submits safe `GET` forms to widen the surface). Authenticated scan with a static
cookie: `--cookie "name=value"` / `[auth] cookies`, attached only to requests to the target host,
never in a report/log/metadata; `webvigil.crawler.safety` guards the crawl against
logout/destructive links. Details in [`docs/authenticated-scanning.md`](authenticated-scanning.md).
`webvigil.checks.content` (spec 013, new `Category.CONTENT`): two passive checks —
`content.sri.missing` (cross-origin subresource without `integrity`, MEDIUM) and `content.mixed`
(`https` page pulling an `http://` subresource, MEDIUM/LOW). `webvigil.checks.disclosure`
gained `disclosure.session-id-in-url` (session token / API key in a URL that the target
produced — link, form action, `Location`; MEDIUM) and `disclosure.private-ip` (RFC-1918 /
loopback / link-local IP in a body; LOW). Header/bearer auth (spec 013): `--header
"Name: Value"` / `[auth] headers`, same discipline as the cookie of 007 (target host only, never
in a report/log/metadata, does not override a header the caller set). OpenAPI import
(spec 013): `--openapi <path|url>` / `[scan] openapi` — `webvigil.crawler.openapi` parses
an OpenAPI 3.x / Swagger 2.0 JSON document (local `$ref`s only, cycle guard), the orchestrator
loads it before the crawl (failure = fatal), the URLs of GET operations become `Crawler` seeds
(`extra_seeds=`), and query/path params + form-urlencoded body fields become
`InjectionPoint`s (`source="openapi"` / `"openapi-path"`) through `enumerate_points`. JSON only,
no fuzzing of JSON body leaves, GET/POST only. Details in
[`docs/api-scanning.md`](api-scanning.md) and
[`docs/content-checks.md`](content-checks.md).
`injection.ldap` (HIGH, CWE-90) / `injection.xpath` (HIGH, CWE-643) / `injection.ssi`
(HIGH, CWE-97) (spec 014): three new detectors in the `InjectionScanner` pass,
in the shape of `sqli` — a parser error signature (LDAP/XPath) or an evaluated `#echo` directive
(SSI), plus a differential (`two_sided_split` from `sqli`, extracted to `detect/_diff.py`;
`wider_then_same` for the LDAP result set). `ssi` only proves evaluation, never `#exec` /
`#include`. `_PER_POINT_REQUEST_CAP` 35→38, `request_budget` 600→650.
`webvigil.checks.upload` (spec 014, new `Category.UPLOAD`): `upload.unrestricted`
(CRITICAL→MEDIUM, CWE-434) from a new `UploadScanner` pass in the orchestrator (modeled on
`EnvelopeScanner`), opt-in `--file-upload` / `[injection] file_upload` (writes files to the
target, no cleanup — the discipline of `--stored-xss`). It uploads benign markers (`<?php echo
6*7;?>`, HTML/SVG `<script>`, extension/content-type spoofing, a `../` name) through each discovered
upload form, fetches them back and proves it in-band: executed, served inline, or written
outside the upload directory. A marker `PUT` probe in the entry directory — the only
destructive verb, only under the opt-in (012 refused `PUT`; 014 reopens it here).
`HttpClient.request` gained `files=` (multipart). The boundaries of active coverage are
documented in [`docs/active-injection.md`](active-injection.md) ("Coverage
boundaries"): `eval()`, NoSQLi, HPP, RFI, DOM XSS, blind/OAST, smuggling and
tests that require a stateful login are left out.
`injection.el` (HIGH, CRITICAL when the type system is reachable; CWE-917) (spec 016):
**in-band** expression-language injection (SpEL / OGNL / JEXL / MVEL / Unified EL), no flag
and no config. The detector lives in `detect/el.py` and runs **together** with `ssti` in a single step
(`ssti+el`, `_merge_el` in the engine) when both checks are selected, so that the same
proof never becomes two findings nor sends the same payload twice; with only `injection.ssti`
selected, the usual `ssti.detect` runs. Proof: a marker glued to the product of `a*b` in
`${}` / `#{}` / `*{}` / `%{}` (OGNL) and in the bare form `'marker'+(a*b)`; the classification comes from the
evidence, never from the delimiter (a pure probe `T(java.lang.Math).abs(-n)` /
`@java.lang.Math@abs(-n)` → CRITICAL; an ambiguous `${}` without EL evidence stays
`injection.ssti`). `is_exprlike` is deliberately narrow (no `q` / `message` / `title`).
`_PER_POINT_REQUEST_CAP` 38 → 42. Details in
[`docs/active-injection.md`](active-injection.md#expression-language-injection).
`csrf.form.token-not-enforced` (MEDIUM, CWE-352) (spec 017): **active** CSRF confirmation,
opt-in `--confirm-csrf` / `[injection] csrf_confirm` (default off — **writes to the target**, up to 3
submissions per form, like `--stored-xss` / `--file-upload`). `CsrfScanner`
(`webvigil.checks.csrf.scanner`) is the **last** pass of the orchestrator: for each candidate form
(urlencoded POST, no file, outside auth/search/destructive; cap of 20 forms × 5 requests) it re-fetches
the page with GET (fresh token), submits the **control** (default values, the target's `Origin`) and then
**replays** with foreign `Origin`/`Referer` (`webvigil.invalid`) and the token removed / altered
(form without a token: one replay). It only **confirms** if the control was accepted and the replay is equivalent
(same status class, same final path, body ≥ 95 % similar); rejected = refuted; the rest =
inconclusive; it never guesses. The confirmation **replaces** the `csrf.form.no-token` of the same form
(the passive check reads `observations.csrf_hits`). Confidence = the `SameSite` of 007, capped at MEDIUM
without `--cookie`. No cookie jar per experiment: a token tied to a session the scan does not have → inconclusive.
Details in [`docs/authenticated-scanning.md`](authenticated-scanning.md#active-csrf-confirmation----confirm-csrf-opt-in).
Crawler with a **POST** phase (spec 018, `v0.18`): opt-in `--submit-post-forms` / `[scan]
submit_post_forms` + `max_post_submissions` (25), **Active Mode only** (default off — **writes to the target**).
It runs **inside** `Crawler.discover()`, after the GET queue empties: it submits once each candidate
form (urlencoded or multipart POST **without** a file, same `is_candidate` /
`is_destructive_form` filter as 017) and each `POST` operation of the `--openapi` (JSON / urlencoded body that 013
already synthesizes; JSON only comes from the OpenAPI), with default values and the `wvcrawl<token>` marker; never a payload,
never a file. Each response becomes a `Page(method="POST")`, and its links/forms feed back into the same BFS
(`_drain`). `Page.fetched_by_get` makes four passes ignore POST pages (the stored-XSS re-crawl, the
GET points of the injection, the envelope sample, the probe folders). `form_body` (in `crawler/forms.py`) is the
body builder shared with 017; `is_candidate` lives in `crawler/safety.py`.
Details in [`docs/authenticated-scanning.md`](authenticated-scanning.md#post-forms----submit-post-forms-opt-in).
Automated login (spec 019, `v0.19`): opt-in `--login-url` + `--username` + `--password-env` /
`[auth.login]`, **Active Mode only** (it is a real POST that creates a session). `webvigil.auth.login.Authenticator`
does the handshake **through the `HttpClient`** (scope guard, rate limiter, redirect loop): GET the page,
pick the form with a password field, build the body with `form_body` (hidden/CSRF), POST **exactly once**
(never a retry, never another credential), follow the chain and **verify** (markers → `check_url` →
heuristic; login form back = failure, nothing conclusive = "not confirmed" with a warning). Failure =
`LoginFailedError`, exit 4, before the crawl. The session is a `webvigil.http.session.Session`: a
`SessionJar` over `httpx.Cookies` (handshake mode accepts every `Set-Cookie` from every hop; live mode only the
rotation of names it already has; target host only) that the `HttpClient` consults — `handshake()` / `quiet()`
are `ContextVar`s (one task's re-login does not leak into the others). Session drop = `401`, a redirect to the
login from a page that is not a login page (learned once, ADR-6), or `logged_out_marker`; **never `403`
or `5xx`** (a blocked payload does not spend a login); `check_url` confirms first. Re-login is serialized
by generation number, 1 retry, cap `max_relogins` (3), then the session is marked "lost" with a warning. The
password is **not a `ScanConfig` field** (it travels as `Credentials`, taken from the env or a prompt; a `password`
key in the TOML is an error); `scrub_result` clears the password, cookies and fixed headers (the `Bearer` token
alone too) and session values (raw, JSON, HTML and percent-encoded upper/lower case spellings)
from the free-text fields at the end of the scan, with or without login, and warns how many fields it changed; a value
emitted by the target is only included if it looks like a session id (`looks_like_session_value`: 8+ chars, 2
classes), and a user secret < 4 chars stays, with a warning. `metadata.login` keeps `relogins` /
`session_lost` / `confirmed`, never the username. With no login configured the client is byte for byte the one from before
(the 007 rule of discarding `Set-Cookie` still holds). Details in
[`docs/authenticated-scanning.md`](authenticated-scanning.md#automated-login----login-url-opt-in).
Session checks (spec 020, `v0.20`, `Category.SESSION`): `session.id.weak` (PASSIVE),
`session.fixation` and `session.logout.not-invalidated` (ACTIVE). A `SessionScanner` pass
(`webvigil.checks.session.scanner`) runs **last** (after the `CsrfScanner`, because the logout
ends the session) and delivers `SessionHit`s with no cookie value at all (`facts` = numbers and words;
ADR-8) in `observations.session_hits`; the three checks only format. Steps: (1) ids the crawl has already seen,
value rules in `checks/session/ids.py` (alphabet capacity, not Shannon: 16 hex = 64 bits
passes; numeric, counter, timestamp and repeated are HIGH); (2) `--sample-sessions` /
`[session] sample_ids`, `sample_count` 3..20: N GETs of the entry URL in `HttpClient.anonymous()` (no
cookie, no static header, no jar), GET-only, valid in any mode, and series rules (duplicates,
sequence, timestamp series, low variance); (3) fixation: `Authenticator.transition` keeps the
cookies before/after the login (for free, no 2nd login), candidate = a session cookie equal in both,
confirmed with 1 GET of the reference page (`check_url` or the landing one) without that cookie; (4)
`--test-logout` / `[session] test_logout` (Active + login only): finds the logout (`logout_url` > 1st link >
1st POST form of the crawl, never guesses `/logout`), checks that the anonymous reference page looks
logged out (oracle), takes the cookie snapshot, performs the logout and re-sends the anonymous snapshot;
`Session.close()` prevents a re-login afterwards. `anonymous()` is a `ContextVar` like
`handshake()`. The jar now refuses a `Secure` cookie coming from an `http` response (like the browser). Details in
[`docs/authenticated-scanning.md`](authenticated-scanning.md#session-security-checks).
HAR import (spec 021, `v0.21`): `--har PATH` / `[scan] har` + `har_max_operations` (150) seed the
crawl and the injection points of SPAs from traffic recorded in the browser or in a proxy. A second
source of seeds next to `--openapi`: `webvigil.crawler.har.load_har` (synchronous, local file, sends
nothing) returns `ApiOperation`s with `source="har"`; the orchestrator does `merge_operations(openapi,
har)` (the OpenAPI wins the tie) and the GET seeds use `ApiOperation.seed_url` (the HAR one carries the
recorded query; the OpenAPI one stays path-only). It only indexes the fields it needs: **it never reads a header
value, cookie or response body** (the "the recording looks authenticated" warning uses only the header name),
a parameter value with a secret-like name or longer than 256 characters becomes `wv`, a JSON body enters only
as a typed shape, multipart enters as urlencoded fields (as in `--openapi`). Scope = `Target.in_scope`
+ the target's scheme; the entry keeps its own origin. It filters out static assets, methods other than GET/POST and
login/destructive paths; a bad file is `HarError` (exit 4), a bad entry is a count in the summary
(`HAR import: N entries read, …`). POST only goes out in the 018 phase (Active + `--submit-post-forms`). The Web API
does not expose the field. Details in [`docs/har-import.md`](har-import.md).
