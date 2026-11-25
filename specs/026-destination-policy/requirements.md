---
feature: Destination policy — one place decides what each URL may receive, and a public name that resolves only to internal addresses is reported
status: approved
date: 2026-11-25
related:
  - 001-foundation/design.md
  - 019-automated-login/design.md
  - 020-session-security/design.md
  - 023-httpx2-migration/design.md
  - 024-secret-values/requirements.md
origin: conception
---

# 026 — Destination policy

## Context and problem

Every request a scan sends may carry something that belongs to the user: the credentials of the scan (the
`[auth]` cookies and headers, the login password, the session cookies the target issued), a body or a query
built from a page fetched with those credentials, and cookies a pass sends itself. Where each of these may go
is decided in many places:

- **Two rules in `core/target.py`.** `Target.in_scope` says which URLs the scan may request at all (scheme,
  host, port, `--scope subdomains`); `Target.carries_credentials` says which of them may get the credentials
  (the target's origin, plus the `https` upgrade of an `http` target on the default port).
- **The HTTP client applies them in four places of its own:** it attaches the cookies and the `[auth]` headers
  per request, drops a caller's credential headers on a redirect hop, withholds a body or query from a
  redirect, and keeps a `Set-Cookie` only from the target's origin.
- **The session jar has a host rule of its own**, by host name only (no scheme, no port). It agrees with the
  credential rule today only because the client asks the credential rule first.
- **The passes ask the rules themselves or compare host names inline:** the automated login, the session
  tests, the OpenAPI import (its document URL and its `servers` base), the HAR import, the dependency
  fingerprint, the disclosure probe, the upload pass and the crawler's links and forms.
- **The address guard** (`http/addresses.py`) decides which IP addresses each host may use, apart from both
  rules.
- **The OSV lookup** has its own HTTP client, the only destination outside the target.

The destination defects of 1.6.0 ([GHSA-hhpx-9q93-mv55](https://github.com/ryanvmorais/webvigil/security/advisories/GHSA-hhpx-9q93-mv55))
were each fixed at one of these places. A new pass, a new header or a new kind of request would need the same
care again, and nothing would fail if it were missing. Two gaps are open today:

- **A caller's credential header is filtered on redirect hops only.** A pass that sends a `Cookie` or an
  `Authorization` header itself must check the first destination on its own. The session tests do; no other
  pass sends one today, and a new pass that did would send it to any URL in scope.
- **A public name that resolves only to internal addresses is scanned silently.** The address guard keeps a
  scan of a public target off internal addresses, but when the target's own name resolves only to internal
  ones (a stale record, split-horizon DNS, or a record set by whoever controls the name), the scan is treated
  as a scan of an internal target. A scan the user started against a site on the internet then runs, possibly
  in Active Mode and with credentials, against a machine on their own network, and nothing says so.

**This spec puts the answer to "what may this URL receive" in one project-owned policy, makes every sender
ask it, closes the two gaps, and adds a gate that fails when a destination decision is made outside the
policy.** The rules themselves do not change: a scan of the same target sends the same requests.

### Where it sits

```
src/webvigil/core/      the destination policy: scope, credentials, data on redirect, cookies kept
src/webvigil/http/      the client, the session jar and the address guard answer through it
src/webvigil/auth/      the automated login asks it
src/webvigil/checks/    the session, fingerprint, disclosure and upload passes ask it
src/webvigil/crawler/   links, forms, the OpenAPI and HAR imports ask it
tests/                  the shared table of destination cases, the inventory gate, the address warning
```

## Goals

- One project-owned policy answers, for each URL, whether it may be requested, whether it may carry the
  scan's credentials, whether a redirect may replay a body or query to it, and whether its cookies may be kept.
- Every part of the engine that sends, follows, attaches or keeps asks that policy, and a test lists them.
- A credential header a pass sends itself follows the same rule as the client's own, on every request.
- The only destination outside the target is declared, and what it receives is bounded.
- A scan whose public target name resolves only to internal addresses says so, and continues.
- A scan that leaves out the internal addresses of a host that also resolves to public ones says so.
- A scan of the same target sends the same requests and reports the same findings.

## Non-goals

- **Changing the rules.** Which URLs are in scope, which may get the credentials, which redirects are followed
  and how 301/302/303/307/308 treat the method and the body stay as in 1.7.0. The policy moves the rules; it
  does not rewrite them.
- **Refusing a public name that resolves internally.** The scan warns and continues (resolved decision 1);
  there is no flag to refuse it.
- **The address guard for a public target.** A host in scope that resolves only to internal addresses while
  the target resolves to a public one is still not reached, with its warning.
- **A proxy.** A proxy set in the environment receives what the scan sends through it; that is the user's
  configuration.
- **The content of the OSV request.** The packages, versions and ecosystems it sends stay as they are.
- **Failure-injection tests across the scan.** This spec adds only the gate for its own decisions (RF-09).
- **A new flag, configuration key or check.**

## Personas

- **As a developer running an authenticated scan**, I want my cookies, headers and password to reach only
  the origin I gave, whatever pass or redirect sends the request.
- **As someone who scans a site by its public name**, I want to be told when that name points into my own
  network, so that I do not scan a local machine believing it is the site on the internet.
- **As a contributor adding a pass**, I want one call that tells me what a URL may receive, and a test that
  tells me when I decide it myself.

## Functional requirements

### One policy

### RF-01 — One policy answers what each URL may receive

- **Given** a URL and the scan's configuration
  **When** any part of the engine is about to request it, follow a redirect to it, attach a cookie, an
  `Authorization` header or an `[auth]` header to it, replay a body or query to it, or keep a `Set-Cookie`
  from it
  **Then** the answer comes from one project-owned policy, and no other code compares the URL's scheme, host
  or port with the target's.
- **Given** the same URL asked from two places (the HTTP client and a pass, a first request and a redirect
  hop)
  **When** the policy answers
  **Then** both get the same answer.

### RF-02 — The rules do not change

- **Given** one shared table of destination cases (scheme and the `https` upgrade, host case and trailing dot,
  explicit and default ports, the `80`/`443` pair, sibling and parent subdomains under each `--scope`, IP
  literals in both families, a one-label host, a public suffix, a malformed URL, userinfo)
  **When** the policy answers each case
  **Then** every answer equals what `Target.in_scope`, `Target.carries_credentials` and the redirect rules of
  1.7.0 give for it.

### RF-03 — A pass's own credential headers follow the same rule

- **Given** a pass that sends a `Cookie`, an `Authorization` or a configured `[auth]` header itself
  **When** the request, first or after a redirect, goes to a URL that may not carry the credentials
  **Then** the header is dropped, as the client's own credentials are.
- **Given** the same request to a URL that may carry the credentials
  **When** it is sent
  **Then** the header goes as the pass gave it.

### RF-04 — The session jar sends and keeps cookies by the policy

- **Given** session cookies the target issued
  **When** a request goes to a URL the policy says may not carry the credentials (another port, plain `http`
  from an `https` target, a sibling subdomain)
  **Then** no session cookie is sent, whatever the jar's own matching says, and a `Set-Cookie` from it is not
  kept.
- **Given** a URL that may carry the credentials
  **When** the jar chooses which cookies to send
  **Then** the cookie rules of a browser (`Secure`, `Path`, expiry) still apply on top of the policy.

### Destinations outside the target

### RF-05 — The only destination outside the target is declared

- **Given** any scan configuration
  **When** the engine opens a network connection
  **Then** it goes to the target or a host in scope through the address guard, or to `[deps] osv_base_url`
  when the OSV lookup is enabled, and to nothing else.
- **Given** the OSV lookup enabled on an authenticated scan
  **When** it sends its requests
  **Then** they carry no credential, cookie, configured header or URL of the target.

### Addresses

### RF-06 — A public target name that resolves only to internal addresses is reported

- **Given** a target whose host is a name under a top-level domain the Public Suffix List lists
  **When** every address it resolves to is internal (loopback, private, link-local and the other ranges the
  address guard does not treat as public)
  **Then** the scan continues against those addresses as it does today, and the result carries one warning
  that names the host and says it resolved only to internal addresses, in the terminal summary, every report
  format, the Web API and the dashboard.
- **Given** a target that is an IP literal, a one-label name, `localhost`, or a name under a top-level domain
  the Public Suffix List does not list or under a special-use name (`.local`, `.internal`, `.home.arpa` and
  the others the design lists)
  **When** it resolves only to internal addresses
  **Then** no such warning is given.
- **Given** a public target name that resolves to at least one public address
  **When** the scan runs
  **Then** no such warning is given and the address guard behaves as today.

### RF-07 — A host whose internal addresses are left out is reported

- **Given** a target that resolves to a public address, and a host the scan connects to (the target or
  another host in scope) that resolves to both public and internal addresses
  **When** the address guard keeps only the public ones, as it does today
  **Then** the result carries one warning per such host, naming it and saying how many of its addresses were
  left out, in the same outputs as RF-06; past the number of hosts the design sets, one more line says how
  many other hosts had addresses left out.
- **Given** a host that resolves only to public addresses, or a target that resolves to no public address
  **When** the scan runs
  **Then** no such warning is given.

### RF-08 — Same scan, same requests

- **Given** the fixture application scanned with the same configuration (anonymous, with `[auth]` cookies and
  headers, with the automated login and the session tests, and with `--scope subdomains`), before and after
  this spec
  **When** the requests the fixture received and the JSON reports are compared, leaving out timestamps and
  durations
  **Then** the requests are byte for byte the same, and findings, severities, check ids, fingerprints,
  warnings and `schema_version` are identical.

### The gate

### RF-09 — Every destination decision is inventoried

- **Given** the source of `webvigil`
  **When** a test lists every call to the scope and credential rules, every comparison of a URL's host,
  scheme or port with the target's, and every place that opens a connection or builds an HTTP client
  **Then** each one is in the policy, or in a declared inventory with the reason, and a new one outside both
  fails the test.

### RF-10 — Tests

See the test strategy in the design. The suite must cover:

- the shared table of destination cases (RF-02), run against the policy and, while they exist, against the
  1.7.0 rules it replaces;
- a pass's own credential header to a URL that may not carry it, on the first request and on a hop (RF-03),
  with a positive control that the same header reaches the target's origin;
- the session jar against a URL the policy refuses and one it allows (RF-04);
- the OSV requests of an authenticated scan, with a positive control that the target requests of the same
  scan carried the credentials (RF-05);
- the warning of RF-06 for each kind of name, with the resolver stubbed, and a positive control that the
  scan did reach the internal address;
- the warning of RF-07, with a positive control that the scan reached the host's public address;
- the inventory (RF-09) as a test over the source.

## Non-functional requirements

### RNF-01 — No new dependency

The policy is written in the repository on the standard library and the vendored Public Suffix List.

### RNF-02 — A minor release

The change fits a minor release under [`docs/stability.md`](../../docs/stability.md): commands, options,
configuration keys, check ids, exit codes, the report schema and fingerprints do not change. The two new warnings
are listed under **Changed** in the CHANGELOG, and the credential header rule of a pass under **Security**.

### RNF-03 — The engine boundary

The policy lives in the engine and imports nothing from the CLI or the Web API; the `import-linter` contract
keeps passing.

### RNF-04 — No measurable cost on a scan

A full scan of the fixture application takes no measurably longer. The policy answers without a network call;
the address guard still resolves each name once per scan.

### RNF-05 — Every step leaves `main` working

The work lands in independent pull requests, each with the full CI green.

### RNF-06 — The suite stays fast and offline, and its guards are proven

No test talks to the real network or the real resolver. The whole suite keeps running in under 2 minutes with
coverage, and per-file line and branch coverage of `src/webvigil` does not drop. Every new test is seen
failing once. Every changed guard goes through mutation testing in batch: every changed function has a killed
mutant, every surviving mutant is triaged, and the score goes in the pull request.

## Resolved decisions

1. **A public name that resolves only to internal addresses is warned about, and the scan continues
   (decision of 2026-11-23).** Split-horizon DNS and a staging name that points at a local machine are
   legitimate setups, so refusing would break real scans; the warning tells the user before they trust the
   result, and the user who typed the name keeps the choice.
2. **The rules move, they are not rewritten.** Every destination defect so far came from a rule applied in one
   place and missed in another, not from a wrong rule. Keeping the answers of 1.7.0 (RF-02) lets the same table
   of cases prove the move, and leaves any change of a rule to its own spec.
3. **Data from an authenticated page keeps going to its first destination (decision of 2026-11-25).** A form
   fetched with the credentials can post to a sibling subdomain in scope; its body goes there without the
   credentials, as a browser would send it. Only a redirect withholds such data (spec `019`), because the
   destination was chosen after the request left. Withholding it on the first request would change what a
   `--scope subdomains` scan with credentials sends (RF-08) for a destination the user put in scope.
4. **A host that resolves to both public and internal addresses is warned about (decision of 2026-11-25).** The
   address guard keeps using only the public ones; the warning (RF-07) makes an unusual DNS setup visible,
   since the scan otherwise covers fewer addresses than the name has without saying so.
