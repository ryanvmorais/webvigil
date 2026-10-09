# Benchmark against known vulnerable applications

WebVigil was run against three applications that are vulnerable on purpose: OWASP DVWA, OWASP
Juice Shop and OWASP WebGoat. This page says what it found, what it missed and why, and what the
run taught us. It is a measurement, not a certification: the applications document their own
weaknesses, so a miss is something we can name, and a hit is something we can check.

> Two runs, both by the maintainer, on the maintainer's own machine, against targets reachable from
> that machine only: the [second](#second-run-linux-dvwa-at-three-levels-juice-shop-from-a-recording)
> on **2026-10-09** (Linux containers, DVWA at three levels, Juice Shop from a recording) and the
> [first](#first-run-windows-no-containers-2026-10-07) on **2026-10-07**. Never point a scanner at a
> system you do not own or are not authorized to test.

## Second run: Linux, DVWA at three levels, Juice Shop from a recording

The first run (below) was one machine, one OS and security level *low*. This one repeats it on Linux,
adds DVWA at *medium* and *high*, checks the "looks like a JavaScript application" warning against
Juice Shop's real entry page, and seeds Juice Shop from a browser recording (`--har`, new since 1.0.0)
instead of a hand-written OpenAPI document. It is still the maintainer's own measurement: nobody
independent has counted it, and no other scanner was run.

> Run on **2026-10-09** at commit [`13f6da6`](https://github.com/ryanvmorais/webvigil/commit/13f6da6),
> the `1.0.4` package plus the work that became `1.1.0`. Every target listened on the maintainer's own
> machine only, on a private container network, and the scanner ran in the repository's own `Dockerfile`
> image.

### Setup

| | |
|---|---|
| Host | Windows 11 with Docker Desktop (WSL 2, 8 CPUs, 4 GB); every target and the scanner ran as a Linux container |
| Scanner | `docker build -t webvigil:bench .` at `13f6da6`: Python 3.12.15, Linux 6.18 |
| DVWA | `ghcr.io/digininja/dvwa:latest`, the project's published image built 2026-10-07 from its development branch, PHP 8.5.11, MariaDB 11.8.9; started with `DEFAULT_SECURITY_LEVEL` set to `low`, `medium` or `high` and the database created from `setup.php` |
| Juice Shop | `bkimminich/juice-shop` 20.2.0 |
| WebGoat | `webgoat/webgoat` built 2026-09-17, OpenJDK 25.0.4 |
| Configuration | `follow_robots = false`, `max_pages = 120` |
| Authorization | `--authorized-by "local benchmark on the maintainer's own machine"` |

The scanner reaches a target by a name that has a dot (`dvwa.test`, a network alias): a one-label
Docker service name such as `dvwa` is refused as a target (`could not determine a valid host`). Juice
Shop was scanned at `127.0.0.1:3000` from a container that shares the target's network namespace, so that the
address in the recording is the address the scan uses. The scans:

```bash
# DVWA, per level: Active defaults plus a login, then every opt-in that writes to the target
webvigil scan http://dvwa.test/ --config bench.toml --mode active --authorized-by "..." \
  --login-url http://dvwa.test/login.php --username admin --probe --sample-sessions
... --stored-xss --file-upload --confirm-csrf --submit-post-forms --xxe --test-logout

# Juice Shop, unaided, and seeded with a recording of a read-only walk through the shop
webvigil scan http://juice.test:3000/ --config bench.toml --mode active --authorized-by "..." --probe
webvigil scan http://127.0.0.1:3000/ ... --probe --har juice.har

# WebGoat, logged in with a throw-away account
webvigil scan http://goat.test:8080/WebGoat/ ... --login-url .../WebGoat/login --username ... --probe --sample-sessions
```

### Results at a glance

| Scan | Pages | Findings | Critical / High / Medium / Low / Info | Time |
|---|---:|---:|---|---:|
| DVWA low, Active defaults + login | 55 | 50 | 1 / 9 / 13 / 25 / 2 | 58 s |
| DVWA low, every opt-in | 63 | 56 | 2 / 12 / 13 / 27 / 2 | 63 s |
| DVWA medium, Active defaults + login | 53 | 50 | 1 / 6 / 16 / 25 / 2 | 2.1 min |
| DVWA medium, every opt-in | 64 | 54 | 1 / 8 / 16 / 27 / 2 | 2.2 min |
| DVWA high, Active defaults + login | 55 | 42 | 1 / 4 / 10 / 25 / 2 | 2.7 min |
| DVWA high, every opt-in | 62 | 44 | 0 / 5 / 10 / 27 / 2 | 2.8 min |
| Juice Shop, unaided | 1 | 5 | 0 / 1 / 1 / 1 / 2 | 5 s |
| Juice Shop, seeded with a HAR recording | 17 | 7 | 0 / 2 / 1 / 2 / 2 | 95 s |
| WebGoat, logged in | 1 | 8 | 0 / 1 / 3 / 2 / 2 | 4 s |

The times are not comparable with the first run's: another operating system, containers instead of
portable runtimes, and a scanner that has since gained several passes. The **Low** column is mostly one
check: 21 of the 25 low findings on every DVWA scan are `disclosure.private-ip`, from the translated
`README.*.md` files DVWA serves from its web root (each one contains a private address as an example).
The `HIGH` that each scan reports for a target served over HTTP is `tls.https`, as before.

### DVWA at three levels

| DVWA module | Low | Medium | High |
|---|---|---|---|
| Command injection | Found, CRITICAL | Found | Found in the defaults scan, **not** in the opt-in scan |
| SQL injection | Found, `error-based` | **Missed** | **Missed** |
| SQL injection (blind) | Found, `boolean-based` | **Missed** | **Missed** |
| XSS (reflected) | Found | Found | Found |
| XSS (stored), `--stored-xss` | Found | Found | Found |
| CSP bypass | Found (reflected XSS on `include`) | Found | Not reported |
| Open redirect | Found | Found | Not reported |
| File inclusion | Found (`traversal.path`, `ssrf.internal`) | Found | Found: `ssrf.internal` through a `file://` URL |
| File upload, `--file-upload` | Found, CRITICAL and HIGH | **Missed** | **Missed** |
| CSRF | Found (`csrf.form.state-change-over-get`) | Found | Not reported |
| Weak session IDs, `--submit-post-forms` | Found (`session.id.weak`) | Found | Not reported |
| Brute force, XSS (DOM), JavaScript, authorisation bypass, insecure CAPTCHA, cryptography, API | Out of scope | Out of scope | Out of scope |

Three of the first run's open rows are closed at *low*. Blind SQL injection was closed by
[#143](https://github.com/ryanvmorais/webvigil/issues/143), the CSRF module by
[#144](https://github.com/ryanvmorais/webvigil/issues/144), and the weak session identifier, which the
first run listed as "cause not investigated", is found by `session.id.weak` (spec 020) once
`--submit-post-forms` presses the button that issues it: the id is a counter (one digit, about 3 bits).
`session.fixation` is reported at every level as a low-confidence candidate with `verified: no`
(`PHPSESSID` is the same before and after login), as in the first run. `csrf.form.no-token` reports six to
ten `POST` forms per level; with `--confirm-csrf` every form tested came back inconclusive, none confirmed.
The information-disclosure probe stopped at its 150-request cap on every DVWA scan.

**Why the misses at *medium* happen.** Measured by hand against the same instance:

- *SQL injection, both kinds.* At *medium* the user id is a `<select>` posted by a `POST` form. WebVigil
  puts payloads only in text-like fields (`text`, `search`, `email`, `url`, `tel`, `number`, textarea,
  plus the query parameters of a link) and sends a `<select>` back with its default value, so the
  point is never fuzzed. The endpoint is injectable: an always-true condition appended to the id returns all five
  rows, an always-false one none, and a stray quote makes the database report a syntax error. A browser offers only the
  listed options; a client can send any value, and so can the scanner. This is the cause behind the
  *error-based* miss at *medium*, and probably behind *high* (not checked there).
  [#190](https://github.com/ryanvmorais/webvigil/issues/190) made a `<select>` an injection point (tested
  after the other points, never written to by `--stored-xss`); a new scan of the same instance at *medium*
  with the same options, in the same 2.0 minutes, reports `injection.sqli.error-based` on the id.
- *SQL injection (blind) at medium.* Still missed after #190, for the reason the first run gave for *low*:
  the true and the false condition both answer `200` and differ by one sentence ("exists" against
  "is MISSING") on a page of several kilobytes, and the boolean detector asks the false page to fall below
  0.90 similarity. At *low* the missing row answered `404`, which the status split catches; at *medium* it
  does not.
- *File upload.* *Medium* checks the declared `Content-Type` of the part and nothing else. Uploading by
  hand a file named like the scanner's `.php.jpg`, `.pHtml` and `.html` payloads with the part type
  `image/jpeg` stores all three. The scan stored nothing and reported nothing, and the cause is **not
  found**: the request builder sends the part type as intended, and the *low* scans found the form.

At *high*, the file-inclusion weakness is found by the SSRF detector, not by `traversal.path`: *high* accepts
only names that start with `file`, and the payload `file:///etc/passwd` returns the contents of the
server's file. The command-injection finding at *high* appeared in one scan and not in the other, with
the same target and options; it is a marginal detection there, not a stable one.

**False positives.** None that I could identify in the findings that name a DVWA weakness; the
disclosure findings are true of the files DVWA serves. The `csrf.form.no-token` forms were not each reviewed.
The scan warned on each DVWA run that the login "could not be confirmed (no marker, no `check_url`, and
the page gave no clear answer)" while the session was in fact working: DVWA has no logged-in marker the
heuristic can read; `[auth.login] logged_in_marker` or `check_url` settles it.

### Juice Shop and the JavaScript-app warning

Unaided, the scan crawled **one page** and, on Juice Shop's real entry page, printed the warning the
first run asked for: *the entry page looks like a JavaScript application (almost no content of its own;
scripts build it): WebVigil does not run JavaScript, so it found 1 page(s) and the results cover little of
the application*. The five findings are the same in number and kind as before, all headers and transport.

The second scan used a recording instead of a hand-written document: a headless browser opened the home
page, five client-side routes and three searches, with no login and no form submitted (87 entries in the
file; its one `POST` is the shop's own `socket.io` channel). `--har` read it (`87 entries read, 18 operations seeded (17 GET, 1 POST); ignored: 1 out of
scope, 52 static, 16 duplicate`), the crawl went from 1 page to 17, and the scan found the intended SQL
injection, `injection.sqli.error-based` on `GET /rest/products/search?q=` (HIGH). That is the finding
the OpenAPI-seeded scan of the first run produced, from a file nobody had to write by hand. The server
stayed up for the whole scan. The recording holds no `/redirect` or `track-order` route, the two that
crash Juice Shop, because the walk never requested them.

The scan also warned that the recording "looks authenticated", because the browser sent cookies
(a language and two banner-dismissal flags, no session). The warning is a guess from the presence of a
`Cookie` header; it does not read the values.

### WebGoat

The same as before: logged in (confirmed), **one page** crawled, eight findings, `disclosure.debug.error-page`
on `/WebGoat/` the only one about the application. Session sampling said the target issued no
cookie to an anonymous visit. WebGoat remains a poor benchmark for a scanner that does not run JavaScript.

### What changed since 1.0.0

On the same targets at *low*, the scan reports 50 findings, not 25, and the extra ones are the work done
since: blind SQL injection, the CSRF `GET` form, the weak session identifier, file inclusion through
`ssrf.internal` and `traversal.path`, plus the private-address noise above.
No scan of this run hit a crashed target.

### Limits of the second run

- **One run per configuration, one host.** Linux in a container on a Windows machine, one version of
  each target, DVWA from its development branch. The two *high* scans disagree about one finding.
- **The medium and high rows say what was reported.** A "not reported" is not a claim that the
  weakness exists at that level; only the two misses explained above were measured by hand.
- **Juice Shop depends on the recording.** Its quality is the quality of the walk, and the walk was
  written by someone who knows the shop.
- **No other scanner was run**, so there is still no comparison.

---

## First run: Windows, no containers, 2026-10-07

Run at commit [`22d0c3c`](https://github.com/ryanvmorais/webvigil/commit/22d0c3c) (the `0.0.0`
development version that became `1.0.0`), every target listening on `127.0.0.1` only. What follows is
left as it was measured; the later changes are in the second run above.

### Setup

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

### Results at a glance

| Scan | Pages | Findings | Critical / High / Medium / Low / Info | Time |
|---|---:|---:|---|---:|
| DVWA, Active defaults + login | 52 | 25 | 1 / 6 / 11 / 5 / 2 | 3 min |
| DVWA, every opt-in | 59 | 28 | 2 / 8 / 11 / 5 / 2 | 3.3 min |
| Juice Shop, unaided | 1 | 5 | 0 / 1 / 1 / 1 / 2 | 2 s |
| Juice Shop, seeded with OpenAPI | 22 | 6 | 0 / 2 / 1 / 1 / 2 | 4 min |
| WebGoat, logged in | 1 | 8 | 0 / 1 / 3 / 2 / 2 | 1 s |

The `HIGH` that every scan reports on a `127.0.0.1` target is `tls.https` ("served over HTTP with
no redirect to HTTPS"). It is correct for the rule and noise for a loopback benchmark.

### DVWA

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

#### Why blind SQL injection was missed

Measured by hand against the same page, not guessed:

- The form's default value is empty, and an empty `id` matches no row. `' AND '1'='1` and
  `' AND '1'='2` both answer `404 User ID is MISSING`, identical to the baseline: there is no
  differential to detect.
- Even with a value that exists (`id=1`), TRUE answers `200` and FALSE `404`, but the body differs
  by six bytes out of 4.4 KB (similarity 0.998). The boolean detector asks FALSE to fall to 0.90 or
  below, so a short sentence on a large page never qualifies.

Two changes closed it ([#143](https://github.com/ryanvmorais/webvigil/issues/143)): the detector
seeds an empty field with a plausible value, and treats a status-class split as evidence. Both are
confirmed against the baseline like every other active finding, and a split that rests on the
status alone is reported with `MEDIUM` confidence. Run again against the same DVWA 2.5 at level
*low*, the scan reports `injection.sqli.boolean-based` on the `id` parameter. The table above is the
1.0 run and is left as it was.

### Juice Shop

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

#### Juice Shop crashed twice under an Active scan

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

### WebGoat

WebGoat 2026.4 logged in (the login ran once and was confirmed) and then crawled **one page**.
As far as we can tell the lessons are loaded by the application's own JavaScript, so there is
little for a crawler that does not run it to follow. It reported a Java error page at `/WebGoat/` (`disclosure.debug.error-page`,
MEDIUM, a true positive), the missing headers and the HTTP-only transport. WebGoat is a poor
benchmark for this kind of scanner; it is listed here so that nobody has to wonder.

### robots.txt and the crawl

DVWA serves `robots.txt` with `Disallow: /`. WebVigil honours `robots.txt` by default, so a scan
with the defaults ends at the entry page. The benchmark turns it off (`follow_robots = false`) for
this one target, which is the owner's own and authorized. The first run did not say why only one
page had been scanned; since [#116](https://github.com/ryanvmorais/webvigil/pull/116) the scan
warns how many URLs `robots.txt` kept out and names the key that turns it off.

### What the run taught us

The benchmark paid for itself before this page was written. Each of these was a defect in
WebVigil that no unit test had caught, and each was fixed with a test:

| Found on | Defect | Fix |
|---|---|---|
| DVWA | A `GET` form's named submit button was dropped from the URL the crawler built, so DVWA's `isset($_GET['Submit'])` guard rejected every request and the SQL injection was invisible | [#114](https://github.com/ryanvmorais/webvigil/pull/114) |
| Juice Shop | `disclosure.vcs.exposed` reported `/ftp/.git/` because a `403` was taken as "the directory exists", but Juice Shop answers `403` to everything under `/ftp/`: a false positive. A control request now rules it out | [#115](https://github.com/ryanvmorais/webvigil/pull/115) |
| DVWA | A scan stopped at the entry page because of `robots.txt` and said nothing | [#116](https://github.com/ryanvmorais/webvigil/pull/116) |
| DVWA | The file-inclusion module was missed because only `/etc/passwd` had an absolute-path payload | [#117](https://github.com/ryanvmorais/webvigil/pull/117) |
| Juice Shop | The server crashed mid-scan and the scan went on against nothing, then finished without a word. It now warns when a large share of the requests got no response | [#118](https://github.com/ryanvmorais/webvigil/pull/118) |

### Limits of this benchmark

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

DVWA, Juice Shop and WebGoat are all distributed by OWASP, as container images and as portable
runtimes. The second run's targets are three small Compose files (the image, a published port bound to
`127.0.0.1`, and a network alias with a dot in it), the scanner is `docker build -t webvigil .`, and
each scan is `docker run --network <the target's network> -v "$PWD:/work" webvigil scan ...` with the
configuration above. Keep `--authorized-by` honest. Do not expose a deliberately vulnerable
application to a network: that is what they are for being exploited.
