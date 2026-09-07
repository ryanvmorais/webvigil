# The OAST problem: why blind SSRF is the one thing WebVigil won't do

> Design note for [WebVigil](https://github.com/ryanvmorais/webvigil). Background for
> [spec 009 — in-band SSRF](../../specs/009-ssrf/design.md), ADR-1.

WebVigil `v0.9` ships SSRF detection. It finds a parameter that makes the server fetch a
URL and reach the cloud instance metadata service (and its IAM credentials), a loopback
admin panel, an internal service, or the filesystem via `file://`. It does this **in-band**
— from the target's own responses — with no external infrastructure.

It stops there. It does not detect *blind* SSRF, and that is not a gap that a future
version will close. This note explains why a capability every serious scanner is "supposed"
to have is one WebVigil deliberately declines.

## What blind SSRF needs

SSRF comes in two flavours. In the non-blind case, something comes back: the fetched
metadata JSON is reflected in the response, or a distinctive connection error names the URL
the server tried to reach, or an internal service's banner shows up where your input went.
WebVigil's `injection.ssrf.metadata` and `injection.ssrf.internal` checks look for exactly
those signals.

In the blind case, nothing comes back. The server makes the request — you can prove it only
if the request lands somewhere you control. That "somewhere" is an **out-of-band
application security testing (OAST) collaborator**: a server with a public domain and DNS
and HTTP listeners that records every callback. You inject `http://<token>.<your-domain>/`,
and later you check whether `<token>` showed up. Burp Suite has Collaborator; ProjectDiscovery
runs `interactsh`.

There is no in-band substitute. If the application fetches your URL and swallows the result
completely, the only witness is the collaborator.

## Why WebVigil won't host one

### It breaks the one invariant the whole engine is built on

Since its first release, WebVigil's scan engine has had a single hard rule: **it talks only
to the target**. The vendored Retire.js vulnerability database is checked into the repo and
matched offline. The information-disclosure probe only requests paths on the target host.
The one online feature — the OSV.dev advisory lookup added in `v0.10` — is a single,
hard-coded, read-only API, off by default, and the documentation states exactly what
leaves the machine.

An OAST collaborator is a different kind of thing entirely. It is a long-running,
internet-facing server that the scanner operates. It is not a client making one request; it
is a service accepting connections from anywhere, indefinitely. Adding it would not bend the
"talks only to the target" rule — it would delete it.

### The infrastructure is exactly what the project chose not to have

WebVigil is distributed as a repository. You clone it, or `pipx install` it, or run the
Docker image. There is no hosted WebVigil, and there never will be — running a public
"scan any URL" service is an attractive nuisance that a solo maintainer should not operate,
and the liability if someone points it at a system they don't own lands on the operator.

A self-hosted OAST collaborator reintroduces every part of that problem. It needs a public
host, a wildcard domain (roughly $10/year plus a VPS), open ports 53, 80 and 443, and
uptime. It is itself an attack surface — a callback relay that a third party can abuse. The
project would be right back to operating an internet-facing service, which is the thing it
decided not to do.

### The free alternative moves the privacy problem, it doesn't solve it

WebVigil could point payloads at a public `interactsh` instance instead of hosting its own.
That is what several tools do. But `interactsh`'s public servers are operated by a third
party, and a blind-SSRF payload that works will cause the target to connect to that third
party — sending it a callback token and, in a real exploitation chain, whatever data the
target exfiltrates. That is a worse privacy posture than the OSV.dev egress, applied to more
sensitive data, with availability nobody guarantees. It would have to be opt-in, loudly, and
even then it is a hard thing to recommend.

### It is the highest-maintenance feature by a wide margin

A working OAST integration is a DNS server, an HTTP listener, a correlation engine that ties
callbacks back to injection points, token minting, a polling API, a deployment story, and —
because the collector is internet-facing — its own security review. For a project
maintained by one person, that is a permanent tax that dwarfs every check in the engine.

### It does not fit the test suite

WebVigil's ~610 tests run offline and deterministically. A real OAST flow is asynchronous
and network-dependent: inject now, callback arrives some seconds later, maybe. Making that
reliable in CI means either mocking the collaborator so thoroughly that the test proves
nothing, or accepting a flaky suite. Neither is acceptable in a tool whose value proposition
is "when it reports something, it's real."

## What honest coverage looks like instead

The in-band checks catch the cases that matter most in practice. Reachable cloud metadata
is the highest-value SSRF outcome — it usually means credential theft — and it reflects
back. Loopback services and `file://` reads reflect back. A server that fetches an
attacker-controlled URL and errors out often echoes the URL in the error, which WebVigil
treats as proof (at MEDIUM confidence) that the parameter reaches a fetcher.

For the genuinely blind case, the documentation says plainly what WebVigil does not do, and
what to do instead: run the active scan alongside your own collaborator — Burp Collaborator
on an engagement, your own `interactsh` — and inject its domain by hand into the parameters
WebVigil flagged as URL-shaped.

A lighter future option exists on paper: a *bring-your-own-collaborator* mode where you pass
`--oast-domain your.instance` and WebVigil fans `http://<token>.your.instance/` payloads
through the injection points, hosting nothing and storing nothing, leaving correlation to
you. It is not planned, but it is the shape any blind-SSRF support would take — the user's
infrastructure, not the project's.

## The broader point

A tool's "won't do" list is a design artifact, not an apology. OWASP ZAP needs a separate
add-on and an external service for OAST. Nuclei needs `interactsh`. Plenty of respected
scanners do no blind detection out of the box. Shipping a feature you cannot operate
responsibly — or one that forces your users into a worse privacy posture than not having it
— is not coverage. It is a liability with a checkbox next to it.

Knowing where a tool should stop is part of designing it.
