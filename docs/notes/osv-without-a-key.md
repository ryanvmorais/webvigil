# OSV.dev without an API key: adding online data to an offline-first scanner

> Design note for [WebVigil](https://github.com/ryanvmorais/webvigil). Background for
> [spec 010 — OSV.dev online provider](../../specs/010-osv-online/design.md).

WebVigil `v0.4` added passive dependency fingerprinting: it identifies the client-side
JavaScript libraries a site serves, matches each `(library, version)` against a **vendored,
offline** copy of the [Retire.js](https://retirejs.github.io/) database, and reports the
versions with known vulnerabilities.

The vendored database has two structural limits. It goes stale between manual refreshes, so
an advisory published last week for a library the target runs is invisible. And its coverage
is Retire.js's coverage — advisories that exist in the wider ecosystem but were never added
to that particular database are never matched.

`v0.10` adds [OSV.dev](https://osv.dev/) as an opt-in second source. OSV, run by Google and
the OpenSSF, aggregates advisories across ecosystems, covers `npm` (where client-side JS
lives), needs no API key, and has a batch endpoint. Wiring it in came down to a handful of
decisions, almost all of them about defaults and failure modes rather than the happy path.

## Opt-in, because it is egress

Every other WebVigil feature talks only to the target. OSV is the deliberate exception: with
`--osv-online`, the **names and versions** of the detected libraries are sent to
`api.osv.dev`. That is all that leaves the machine — no target URL, no hostname, no cookie,
no finding — and the documentation says so explicitly. It is off by default. A dependency
scan without the flag behaves exactly as it did in `v0.4`.

## Keep the seam synchronous

`v0.4` built an `AdvisoryProvider` protocol with a synchronous method:
`match(name, version) -> list[Advisory]`. The offline provider reads a compiled data
structure; sync is the natural fit.

An online provider needs asynchronous I/O. The tempting move is to make the protocol `async`
— but that ripples into the offline provider (now a pointless `async def`) and the check
that calls it. Instead, the orchestrator runs an **OSV lookup pass** before the checks,
exactly like the existing fingerprint pass: it batch-fetches everything up front and hands
the check a pre-populated `(name, version) -> advisories` map. The check stays a pure,
synchronous transform of its inputs. The async work lives in one place, in the orchestrator,
where the other network passes already are.

## `querybatch` first, then `query`

OSV's `POST /v1/querybatch` takes many `(package, version)` pairs and returns, for each, a
list of vulnerability **IDs** — nothing else. That is the cheap filter. One round trip tells
you *which* of the detected libraries have anything at all, and for a typical scan — a
handful of libraries, none or one vulnerable — the answer is "none" or "one."

Only the packages that came back with an ID get a follow-up `POST /v1/query` for the full
records (summary, severity, affected ranges, references). A completely clean scan makes
exactly **one** OSV request.

## Merge, don't replace

With the flag on, OSV advisories are **combined** with the Retire.js results for the same
detection, not substituted for them. The two lists are coalesced by shared identifier — a
CVE, GHSA, or OSV ID that appears in both — so a library covered by both sources produces
one finding carrying the union of the identifiers and reference links, with the higher of
the two severities.

The offline database stays the floor. OSV can only *add* coverage. A transient OSV failure
can never cost you a match you would have had without the flag.

## CVSS in-tree, no new dependency

GHSA-sourced OSV records carry a qualitative severity string, which maps cleanly
(`MODERATE -> MEDIUM`, and so on). Pure-CVE records often carry only a CVSS vector.

Rather than add a `cvss` library as a dependency, WebVigil computes the CVSS 3.0/3.1 base
score itself — a roughly fifty-line pure function implementing the published formula. It is
deterministic, it is easy to unit-test against the specification's own worked examples, and
it covers the overwhelming majority of `npm` advisories. A vector it can't parse (CVSS v2,
malformed, a future v4-only record) falls back to the same `MEDIUM` default the offline
provider already uses for advisories with no severity — a case the reports already handle.

## Failure is a warning, not an error

OSV unreachable, request timed out, HTTP 429, unparseable response — any of these appends a
single scan warning and the scan continues with the offline results. The exit code is
unaffected. Opting into an online source must not be able to make the scan *worse* than not
opting in; the worst case is that OSV adds nothing this run.

## No persistent cache

Within one scan, a `(library, version)` pair that appears more than once is queried once.
There is no on-disk cache and no cross-scan reuse. A persistent cache would bring TTL,
invalidation, corruption, and concurrency questions to a feature whose entire purpose is
*freshness* — and one `querybatch` plus a few `query` calls per scan is cheap enough that
the trade isn't worth it.

## The broader point

Adding an online data source to an offline-first tool is mostly not about the API call. The
happy path — send request, parse response, map to internal types — is the easy part. The
design is in the answers to "what happens when the service is down, slow, or wrong," "what
does the user give up by opting in," and "can this ever make things worse than leaving it
off." Get those right and the feature is safe to ship on by nobody and useful to everyone
who turns it on.
