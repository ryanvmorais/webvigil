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

All four are detected **in-band** — from the target's own responses. No headless browser,
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

Every finding's `location` carries the `method`, `url`, and `param`; its evidence carries
the injection point, the payload sent, and the proof.

## How the pass works

When the scan is Active and at least one `injection.*` check is selected, the orchestrator
runs one bounded `InjectionScanner` pass:

1. **Enumerate injection points** — every query-string parameter on a crawled in-scope URL,
   and every fuzzable field of a crawled in-scope `<form>` (GET and POST). Forms are parsed
   from page bodies the crawler already fetched; no extra crawl requests.
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
is additionally capped at 60 pages (and by `[scan] max_pages`). Hitting either is a warning.

**Markers are not cleaned up.** WebVigil does not know the target's data model, so it does
not delete the `wvstored…` rows it wrote. Run `--stored-xss` against dev / staging, never a
shared production database.

**Blind spots.** A marker stored but rendered only where the scan cannot reach (an admin
panel, a moderation queue, a staff email); a marker shown only after moderation or a delay;
a marker rendered more than one hop past a known page; a sink that strips unknown tags. DOM
XSS still needs a JavaScript engine (out of scope).

## Non-destructive posture

- **`GET` and `POST` only** — never `PUT`, `PATCH`, `DELETE`.
- **Forms that look like authentication or destruction are not fuzzed** — the heuristic
  matches `login`, `logout`, `register`, `delete`, `password`, `checkout`, `pay`,
  `transfer`, and similar in the action or field names. It is best-effort: a login form at
  `/session` with generic field names would slip through.
- **Hidden fields and anti-CSRF tokens are submitted with their discovered values**, never
  fuzzed. `file` and `password` inputs are not payload-fuzzed.

## Budget and tuning — `[injection]`

```toml
[injection]
request_budget = 500        # max crafted requests per scan; hitting it is a warning
max_injection_points = 200  # max params / fields tested; excess is a warning
time_based_sqli = true      # --no-time-based-sqli overrides
time_based_delay_s = 5      # the D in SLEEP(D); keep below [http] timeout_s
stored_xss = false          # run the two-phase stored-XSS pass; --stored-xss overrides
```

Per point the pass sends at most 30 crafted requests; time-based sends at most 8
sleep-inducing requests per scan; the stored-XSS re-crawl fetches at most 60 pages. Hitting
any cap is a scan **warning**, not an error.

Disable any check by id (`[checks] disabled`). Disabling **every** `injection.*` id skips
the pass entirely — no enumeration, no crafted request.

## What it does not do

- **Stored XSS** ships in v0.8 behind `--stored-xss` (see above). **DOM XSS** still needs a
  JavaScript engine (out of scope since spec 001).
- **No SSRF.** Meaningful SSRF detection needs an out-of-band collaborator — a server the
  scanner controls that the target calls back to. WebVigil's engine talks only to the
  target, so SSRF waits for a spec that adds an opt-in collaborator.
- **No OS command injection, XXE, SSTI, or other injection classes** yet.
- **No exploitation.** A confirmed SQLi is proved with one bounded marker; WebVigil does
  not dump the database or read further files.
- **No parameter mining.** It fuzzes parameters the target actually exposes, not guessed
  ones.
- **No WAF evasion.** Payloads are a small static in-repo set with no mutation engine.

## A target to try it on

`docker/target.Dockerfile` packages the test fixture app (an intentionally vulnerable
Starlette app) as a scannable target:

```bash
docker compose --profile targets up target
webvigil scan http://localhost:8080 --mode active --authorized-by me
```

It is not started by `docker compose up`.
