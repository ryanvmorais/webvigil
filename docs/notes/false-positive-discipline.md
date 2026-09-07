# False-positive discipline in an active scanner

> Design note for [WebVigil](https://github.com/ryanvmorais/webvigil). Background for
> [spec 006 — active injection](../../specs/006-active-injection/design.md) and the
> detectors added in specs 008 and 009.

An active vulnerability scanner sends crafted input to an application and decides, from the
response, whether something is wrong. The failure mode that matters is not missing a bug —
it is reporting one that isn't there. A false "SQL injection — HIGH" costs a developer an
afternoon, and it costs every *other* finding in the report its credibility. After the
second false alarm, the report gets skimmed.

So WebVigil's active detectors are built around one rule: **prove it, or don't report it.**
In practice that rule has three parts.

## 1. The signature must be absent from the baseline

Before any detector runs, WebVigil sends the injection point its *original* value and keeps
the response — status code, body, timing. That is the baseline. A detector's signature only
counts if it appears in the payload response **and** was not already in the baseline.

This sounds obvious and is easy to get wrong. `/etc/passwd` content (`root:...:0:0:`) is a
strong path-traversal signal — unless the page is documentation *about* `/etc/passwd`, in
which case the string is there no matter what you inject. A DBMS error message is a strong
SQL-injection signal — unless the endpoint always 500s with a stack trace. The
baseline-absent check turns "this string is in the response" into "this string is in the
response *because of my payload*."

## 2. A differential signal must reproduce

Some vulnerabilities have no signature — only a difference in behaviour. Boolean-based blind
SQL injection is the classic: you inject `... AND 1=1` and `... AND 1=2`, and if the first
response matches the baseline while the second differs, the parameter is probably in a
`WHERE` clause.

"Probably" is not "prove it." A busy endpoint — one showing a rotating ad, a CSRF token, a
timestamp — differs from itself on every request. So WebVigil's boolean detector does more:

- it checks that the page is *stable* first, by sending the original value twice and
  confirming the two responses are near-identical;
- it requires the TRUE/FALSE split to **reproduce** across a second confirmation round with
  the same payloads.

Time-based blind SQLi gets the same treatment. An injected `SLEEP(5)` that delays the
response by five seconds is suggestive, but a slow endpoint delays every response. So the
detector also sends a `SLEEP(0)` control that must return fast, and a half-length `SLEEP(2)`
probe whose delay must land *near two seconds* — the delay has to scale with what was asked
for. A real time injection is linear in the requested delay; a coincidentally slow endpoint
is not.

## 3. The proof must be in an executable context

A payload coming back in the response is not XSS. It is XSS only if it comes back **verbatim**
— so `<`, `>` and `"` were not entity- or percent-encoded — **and** in a position where a
browser would run it. WebVigil's reflected-XSS detector sends a plain probe first (is the
parameter reflected at all?) and only escalates to context-breaking payloads if it is, then
checks the payload survived intact in an HTML response.

Stored XSS raises the bar again. The marker must render with its markup intact on a
**different page** than the one it was submitted to — found by a re-crawl, not in the
submission's own response. A form that echoes your input back on the same response is
reflected XSS, a different (and differently-remediated) bug; calling it stored would be
wrong.

SSRF is the newest example. An SSRF-shaped connection error — `Connection refused`,
`getaddrinfo failed`, a Python `requests.exceptions` traceback — is a real signal that the
server tried to fetch something. But servers throw those errors for many reasons. So the
error only counts as SSRF if the response **also echoes the injected URL**. "The server
failed to connect, and it told me the URL it failed to connect to, and that URL is the one
I injected" is a server-side fetch of attacker-controlled input. "The server 500'd" is not.

## A concrete near-miss

The first cut of WebVigil's cloud-metadata SSRF signatures matched `iam/security-credentials`
and `instance-identity`. Both are real strings in AWS metadata responses. Both are also
substrings of the *payload URLs*
(`http://169.254.169.254/latest/meta-data/iam/security-credentials/`). An application that
responds `you asked for <url>` would have matched the signature and produced a false
"AWS instance metadata service is reachable — CRITICAL."

The fix was to restrict the signatures to markers that appear in a metadata *response body*
and never in a URL path: `AccessKeyId`, `computeMetadata`, `vmId`, `ami-launch-index`. The
principle — a signature must distinguish "the server fetched this" from "the server echoed
this" — is the same principle as rules 1 through 3, applied to which regexes go in the list.

## What it costs

Proof is not free. A confirmed boolean-based SQL injection is six to eight requests, not
one. Time-based SQLi adds a control and a scaled probe. Some genuinely vulnerable endpoints
that behave strangely — non-deterministic responses, aggressive rate limiting, unusual error
handling — get missed because the confirmation step can't get a clean read.

That is the deliberate trade. WebVigil optimises for *every finding is real* over *every
vulnerability is found*. Where residual uncertainty remains, it is encoded in the finding's
confidence level (`HIGH` / `MEDIUM`) rather than hidden.

The payoff is that a clean run means something, and `--fail-on high` in a CI pipeline is
safe to wire up — because a HIGH finding is not going to flake the build next Tuesday.
