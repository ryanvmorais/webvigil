# Benchmark against known vulnerable applications

WebVigil was run against three applications that are vulnerable on purpose: OWASP DVWA, OWASP
Juice Shop and OWASP WebGoat. This page says what it found, what it missed and why, and what the
run taught us. It is a measurement, not a certification: the applications document their own
weaknesses, so a miss is something we can name, and a hit is something we can check.

> Run on **2026-10-07** at commit [`22d0c3c`](https://github.com/ryanvmorais/webvigil/commit/22d0c3c)
> (the `0.0.0` development version that became `1.0.0`). Every target ran on the maintainer's own
> machine and listened on `127.0.0.1` only. Never point a scanner at a system you do not own or
> are not authorized to test.

## Setup

| | |
|---|---|
| Host | Windows 11, no containers: every target ran as a portable runtime |
| DVWA | 2.5, security level **low**, PHP 8.4.26, MariaDB 11.8.9 |
| Juice Shop | 20.2.0, Node 24 |
| WebGoat | 2026.4, Temurin JDK 25 |
| Configuration | `follow_robots = false`, `max_pages = 120` (see [robots.txt](#robotstxt-and-the-crawl)) |
| Authorization | `--authorized-by "local benchmark on the maintainer's own machine"` |

The five scans:

```bash
# DVWA, the defaults of Active Mode plus a login
WEBVIGIL_LOGIN_PASSWORD=password webvigil scan http://127.0.0.1:4280/ --config bench.toml \
  --mode active --authorized-by "..." --login-url http://127.0.0.1:4280/login.php \
  --username admin --probe --sample-sessions

# DVWA again with every opt-in that writes to the target
... --stored-xss --file-upload --confirm-csrf --submit-post-forms --xxe --test-logout

# Juice Shop, unaided, and seeded with a hand-written OpenAPI document of five public routes
webvigil scan http://127.0.0.1:3000/ --config bench.toml --mode active --authorized-by "..." --probe
... --openapi juice-openapi.json

# WebGoat, logged in with a throw-away account
WEBVIGIL_LOGIN_PASSWORD=... webvigil scan http://127.0.0.1:8080/WebGoat/ --config bench.toml \
  --mode active --authorized-by "..." --login-url http://127.0.0.1:8080/WebGoat/login \
  --username ... --probe --sample-sessions
```

## Results at a glance

| Scan | Pages | Findings | Critical / High / Medium / Low / Info | Time |
|---|---:|---:|---|---:|
| DVWA, Active defaults + login | 52 | 25 | 1 / 6 / 11 / 5 / 2 | 3 min |
| DVWA, every opt-in | 59 | 28 | 2 / 8 / 11 / 5 / 2 | 3.3 min |
| Juice Shop, unaided | 1 | 5 | 0 / 1 / 1 / 1 / 2 | 2 s |
| Juice Shop, seeded with OpenAPI | 22 | 6 | 0 / 2 / 1 / 1 / 2 | 4 min |
| WebGoat, logged in | 1 | 8 | 0 / 1 / 3 / 2 / 2 | 1 s |

The `HIGH` that every scan reports on a `127.0.0.1` target is `tls.https` ("served over HTTP with
no redirect to HTTPS"). It is correct for the rule and noise for a loopback benchmark.

## DVWA

DVWA is the one with the clearest ground truth: one module per weakness.

| DVWA module | Result | Notes |
|---|---|---|
| Command injection | **Found**: `injection.cmdi.os`, CRITICAL | `ip` parameter, proved by a calculated marker |
| SQL injection | **Found**: `injection.sqli.error-based`, HIGH | `id` parameter. Needed the GET-form fix below |
| XSS (reflected) | **Found**: `injection.xss.reflected`, HIGH | `name` |
| XSS (stored) | **Found** with `--stored-xss`: `injection.xss.stored`, HIGH | `txtName`; the same form is also reported as reflected |
| CSP bypass | **Found** as reflected XSS on `include` | The page's weakness is the script include |
| Open redirect | **Found**: `injection.redirect.open`, MEDIUM | |
| File upload | **Found** with `--file-upload`: `upload.unrestricted`, CRITICAL and HIGH | |
| File inclusion | **Found** once `/windows/win.ini` was added ([#117](https://github.com/ryanvmorais/webvigil/pull/117)) | Missed in the run above: see below |
| SQL injection (blind) | **Missed** | See below |
| CSRF | **Missed** in this run; since [#144](https://github.com/ryanvmorais/webvigil/issues/144) reported by `csrf.form.state-change-over-get` | The module changes the password with a `GET` form; `csrf.form.no-token` covers `POST` forms |
| Weak session IDs | **Not detected** | The id is issued by a `POST` button. Cause not investigated |
| Brute force | Out of scope, by policy | WebVigil never guesses credentials |
| XSS (DOM), JavaScript, authorisation bypass, insecure CAPTCHA, cryptography, API | Out of scope | They need a browser or an understanding of the application's logic |

Beyond the modules, the scans also reported things that are true of DVWA and not part of any
module: the security headers it does not send, `PHPSESSID` not renewed at login
(`session.fixation`, low confidence, `verified: no`), PHP deprecation messages on
`/instructions.php` (`disclosure.debug.error-page`), a `Dockerfile` served from the web root
(reported by `disclosure.config.dotenv-exposed`, the probe's check for configuration files), a missing
Subresource Integrity attribute, and six `POST` forms without an anti-CSRF token. The
information-disclosure probe stopped at its 150-request cap (166 candidate paths), as the scan
says in its warnings. With `--confirm-csrf` the seven candidate forms came back inconclusive:
none was confirmed.

**False positives.** None that I could identify. The injection, upload and session findings each
match a documented weakness of DVWA at this level (`session.fixation` is a low-confidence candidate
with `verified: no`), and the disclosure findings were reproduced by hand (the `Dockerfile` is
served; the PHP deprecation notices are on `/instructions.php`). The six `csrf.form.no-token` forms
were not each reviewed; the active confirmation did not confirm any of them. Nobody independent has
counted these results.

### Why blind SQL injection was missed

Measured by hand against the same page, not guessed:

- The form's default value is empty, and an empty `id` matches no row. `' AND '1'='1` and
  `' AND '1'='2` both answer `404 User ID is MISSING`, identical to the baseline: there is no
  differential to detect.
- Even with a value that exists (`id=1`), TRUE answers `200` and FALSE `404`, but the body differs
  by six bytes out of 4.4 KB (similarity 0.998). The boolean detector asks FALSE to fall to 0.90 or
  below, so a short sentence on a large page never qualifies.

Two changes would close it: seed an empty field with a plausible value, and treat a status-class
split as evidence. Both are detector work for a minor release, not a bug.

## Juice Shop

Juice Shop is an Angular single-page application. WebVigil's crawler does not run JavaScript, so
unaided it sees one page (the shell) and reports headers: **it finds nothing in the application
itself.** That is the honest result and the main limitation of the benchmark. A scan like this
now says so: when the entry page looks like a JavaScript application and the crawl found at most
two pages, it warns and points to `--openapi`.

Seeded with an OpenAPI document of five public routes (written by hand, since Juice Shop does not
publish one), it crawled 22 pages and found the intended SQL injection:
`injection.sqli.error-based` on `GET /rest/products/search?q=` (HIGH, SQLite). The server stayed up
for the whole scan; it was polled every 20 seconds.

Two more routes belong in that document and are left out of the final run, because requesting them
**crashes Juice Shop** (below). The weaknesses reachable from the routes that remain were not
reported either:

| Route | Why it was not reported |
|---|---|
| `/rest/track-order/{id}` | NoSQL injection: the `id` is evaluated as JavaScript by the database layer (`$where`). That is `eval()` injection, listed as out of scope in [active-injection.md](active-injection.md) |
| `/ftp` | Answers `403` to anything that is not `.md` or `.pdf` |
| `/rest/admin/application-version`, `/api/Products` | Nothing to report from a plain read |

### Juice Shop crashed twice under an Active scan

Both are bugs of Juice Shop (an uncaught exception ends the process), triggered by input a scanner
is supposed to send. They came from two earlier seeded runs, each of which included one of the
routes below:

1. A request to `/redirect` without a usable `to` throws in `isRedirectAllowed`. The server died
   about 3.5 minutes into the scan.
2. A payload sent to `/rest/products/{id}/reviews` reached the `$where` evaluation as an
   undefined identifier and threw a `ReferenceError`. The server died about 4 minutes into the scan.

Each scan then kept going for about five minutes against a closed port and finished with no
warning, with the same six findings as the clean run (the work that mattered had been done before
the crash). That silence is a defect in WebVigil, not in Juice Shop: see
[what the run taught us](#what-the-run-taught-us). The clean run took 4 minutes, not 9.

## WebGoat

WebGoat 2026.4 logged in (the login ran once and was confirmed) and then crawled **one page**.
As far as we can tell the lessons are loaded by the application's own JavaScript, so there is
little for a crawler that does not run it to follow. It reported a Java error page at `/WebGoat/` (`disclosure.debug.error-page`,
MEDIUM, a true positive), the missing headers and the HTTP-only transport. WebGoat is a poor
benchmark for this kind of scanner; it is listed here so that nobody has to wonder.

## robots.txt and the crawl

DVWA serves `robots.txt` with `Disallow: /`. WebVigil honours `robots.txt` by default, so a scan
with the defaults ends at the entry page. The benchmark turns it off (`follow_robots = false`) for
this one target, which is the owner's own and authorized. The first run did not say why only one
page had been scanned; since [#116](https://github.com/ryanvmorais/webvigil/pull/116) the scan
warns how many URLs `robots.txt` kept out and names the key that turns it off.

## What the run taught us

The benchmark paid for itself before this page was written. Each of these was a defect in
WebVigil that no unit test had caught, and each was fixed with a test:

| Found on | Defect | Fix |
|---|---|---|
| DVWA | A `GET` form's named submit button was dropped from the URL the crawler built, so DVWA's `isset($_GET['Submit'])` guard rejected every request and the SQL injection was invisible | [#114](https://github.com/ryanvmorais/webvigil/pull/114) |
| Juice Shop | `disclosure.vcs.exposed` reported `/ftp/.git/` because a `403` was taken as "the directory exists", but Juice Shop answers `403` to everything under `/ftp/`: a false positive. A control request now rules it out | [#115](https://github.com/ryanvmorais/webvigil/pull/115) |
| DVWA | A scan stopped at the entry page because of `robots.txt` and said nothing | [#116](https://github.com/ryanvmorais/webvigil/pull/116) |
| DVWA | The file-inclusion module was missed because only `/etc/passwd` had an absolute-path payload | [#117](https://github.com/ryanvmorais/webvigil/pull/117) |
| Juice Shop | The server crashed mid-scan and the scan went on against nothing, then finished without a word. It now warns when a large share of the requests got no response | [#118](https://github.com/ryanvmorais/webvigil/pull/118) |

## Limits of this benchmark

- **One run, one host.** Windows, one version of each target, security level *low*. It says nothing
  about a hardened configuration, and the Linux-only payloads (`/etc/passwd`) were not exercised.
- **The Juice Shop result depends on the document that seeded it.** Five routes written by a
  person who knows the application give the scanner knowledge it would not have by itself, and the
  two routes that crash it are not in the final run.
- **No comparison with other scanners.** The numbers are WebVigil's alone. Comparing tools needs the
  same targets, the same configuration and an independent person counting.
- **Single-page applications are the weak spot.** Without a browser, an application that builds its
  pages in JavaScript is almost invisible. Importing an OpenAPI document is the way in today.

## Reproduce it

DVWA, Juice Shop and WebGoat are all distributed by OWASP. Run each bound to `127.0.0.1`, use the
configuration above, and keep `--authorized-by` honest. Do not expose a deliberately vulnerable
application to a network: that is what they are for being exploited.
