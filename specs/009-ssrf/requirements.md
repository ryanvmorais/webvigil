---
feature: In-band SSRF detection — cloud metadata, loopback/internal, file:// (Active Mode)
status: done
date: 2026-09-07
related:
  - 001-foundation/requirements.md
  - 006-active-injection/requirements.md
  - 008-stored-xss/requirements.md
origin: conception
---

# 009 — In-band SSRF detection

## Context and problem

Spec 006 shipped the first `ACTIVE` checks. The `InjectionScanner` orchestrator pass
enumerates injection points (query params + fuzzable form fields), baselines each, and fans
per-class detectors under a shared `ActiveBudget`; six thin `injection.*` checks turn the
resulting `InjectionHit`s into findings. 008 added a separate stored-XSS pass on top.

**Server-Side Request Forgery (SSRF) — OWASP A10:2021, CWE-918 — is the one class from the
006 roadmap line still entirely uncovered.** A parameter whose value the server uses to
*make its own outbound request* (a URL fetcher, a webhook tester, a "load image from URL",
a PDF renderer, an XML parser) lets an attacker reach the cloud instance metadata service
(and its IAM credentials), internal-only services, `localhost` admin panels, and the
filesystem via `file://`. It was behind the Capital One breach and is a routine finding on
real applications.

006 deferred SSRF **on purpose** (006 requirements, "Deferred, on purpose"): *reliable*
SSRF detection — especially **blind** SSRF, where the server makes the request but nothing
comes back in the response — needs an **out-of-band (OAST) collaborator**: a server the
scanner hosts that the target calls back to (DNS / HTTP callback). That crosses WebVigil's
standing rule that the engine talks only to the target, needs public DNS/HTTP
infrastructure, and does not fit a free-tier deployment.

**This spec takes the achievable half: in-band, non-blind SSRF.** It detects an
SSRF-capable parameter from the target's *own responses* — a cloud-metadata marker, a
`file://` read signature, internal-resource content it did not return before, or a
distinctive SSRF-shaped connection error — with no collaborator, no new infrastructure, no
cost, and no change to "the engine talks only to the target" (the SSRF payload is just a
*parameter value* sent to the target; whatever the target then connects to is the target's
doing). Blind SSRF — and the semi-blind timing signal — stay deferred to a future
**opt-in** OAST spec, exactly as the online OSV provider was deferred from spec 004 and
shipped later as spec 010.

### Where it sits

```
webvigil.checks.injection                        (Category.INJECTION, mode = ACTIVE)
       ├── injection.xss.reflected      [006]
       ├── injection.sqli.*             [006]
       ├── injection.traversal.path     [006]
       ├── injection.redirect.open      [006]
       ├── injection.xss.stored         [008]
       ├── injection.ssrf.metadata      [009]  ← cloud metadata service reached (CRITICAL)
       └── injection.ssrf.internal      [009]  ← loopback / internal / file:// reached, or a
                                                 server-side fetch of an attacker URL proven
                                                 by an SSRF-shaped error (HIGH)

detect/ssrf.py   new detector: send URL payloads through a point, read the response for a
                 metadata marker | a file:// signature | internal content | an SSRF error
payloads.py      + SSRF_* payload sets and signature regexes (static, in-repo, documented)
engine.py        + "ssrf" in the detector table, _BASE_ORDER, KIND_BY_CHECK_ID; an
                 is_urllike(point) heuristic to test URL-shaped params first (like traversal)
```

Reuses the 006 machinery unchanged: the same `InjectionScanner` pass, the same
`ActiveBudget`, the same `DetectCtx.send`, the same `_InjectionCheck` base. **No new
orchestrator pass** (unlike 008). **No opt-in flag** beyond `--mode active` — SSRF payloads
are *reads*, they write nothing to the target, so there is no persisted-data concern like
stored XSS. **No change to `webvigil.api` or the dashboard** — `injection.ssrf.*` findings
persist and render through the existing plumbing; the new ids surface automatically.

The engine still imports nothing from `webvigil.cli` / `webvigil.api` / `web/`; no new
runtime dependency (detection is `re` + the existing HTTP layer). `import-linter` unchanged.

### Deployment note (context for the roadmap discussion)

This spec was scoped to in-band precisely so it costs **nothing** to run and needs **no**
new machine resources: an SSRF scan is a bounded handful of extra crafted requests inside
the existing Active-Mode budget, I/O-bound like the rest of the engine. It runs identically
from the CLI and from any host that already runs a WebVigil scan. The deferred OAST spec is
the one that would need a public host with DNS/HTTP ports and a domain.

## Goals

- Two new `ACTIVE` checks — `injection.ssrf.metadata` (CRITICAL) and
  `injection.ssrf.internal` (HIGH) — `category = INJECTION`, gated by the existing
  `--mode active --authorized-by`, no new consent mechanism.
- A new `ssrf` detector in the injection engine that, for each injection point, sends a
  small static set of URL payloads and confirms a hit from **one** of:
  1. **cloud metadata signature** in the response (AWS / GCP / Azure / AliCloud markers) —
     absent from the baseline → `injection.ssrf.metadata`;
  2. **`file://` read signature** (`/etc/passwd`, `win.ini`) absent from the baseline →
     `injection.ssrf.internal`;
  3. **internal-resource content** reflected (a loopback / RFC-1918 fetch that returned a
     body the baseline did not) → `injection.ssrf.internal`;
  4. **SSRF-shaped error** — a distinctive connection error naming the attacker URL or an
     unreachable internal host, absent from the baseline (proves the parameter reaches a
     server-side fetcher even when no body leaked) → `injection.ssrf.internal`, MEDIUM
     confidence.
- A **URL-shaped-parameter heuristic** (`is_urllike`) so URL-carrying params
  (`url`, `uri`, `link`, `src`, `dest`, `callback`, `webhook`, `feed`, `proxy`, `image`,
  `next`, `to`, `target`, …, or a value that looks like a URL) are tested first, within the
  shared budget — mirroring 006's `is_pathlike` / `is_redirect_name`.
- Payloads that cover the common **IP/host obfuscations** attackers use to bypass naive
  allow/deny lists: decimal / octal / hex IP encodings of `127.0.0.1`, `127.1`, `[::1]`,
  `0.0.0.0`, `@`-confusion (`http://<target>@169.254.169.254/`), and the bare metadata IP.
- **`file://` scheme** payloads (`file:///etc/passwd`, `file:///c:/windows/win.ini`) —
  detected by a real file-content signature, not just an error.
- **False-positive discipline**: every signature must be absent from the point's baseline;
  metadata hits require a provider-specific token, not just the IP echoed back; a bare
  reflected payload string (the app echoing the parameter without fetching it) is **not** a
  hit.
- **Fixture-app coverage**: the insecure profile gains a URL-fetch endpoint vulnerable to
  SSRF (with the fixture itself standing in for the metadata service and the filesystem so
  the integration test is deterministic and offline); the hardened profile gains the
  allow-listed equivalent. Integration tests assert the finding on one profile and **zero**
  SSRF findings on the other.
- **Docs**: an SSRF section in `docs/active-injection.md` (what it proves, the payloads,
  the metadata targets, why blind SSRF still needs a collaborator and is deferred), plus
  the usual README / CLAUDE / specs-roadmap updates.

## Non-goals

- **Blind / out-of-band SSRF.** No OAST collaborator server, no DNS-callback catcher, no
  use of a third-party interaction server (interactsh & co.). A parameter that triggers a
  server-side request with **no** in-band signal (no reflected body, no error, no timing
  delta) is **not** detected. This is the deliberate scope line; blind SSRF is a future
  opt-in spec (`011-ssrf-oast` or similar), parallel to how spec 010 followed spec 004.
- **Exploitation.** A confirmed SSRF is proved with one read (e.g. the metadata root, or
  `/etc/passwd`); WebVigil does not walk the full metadata tree, extract IAM credentials,
  enumerate internal services, or pivot.
- **A timing / blind-ish probe.** A URL that reaches a server-side fetcher but produces
  **no** in-band signal — no reflected body, no error — is left to the deferred OAST spec.
  009 ships only signals it can prove from the response (Resolved decision 2). No internal
  port scan.
- **Non-HTTP protocol exploitation / smuggling.** No `gopher://` / `dict://` payloads —
  they add error noise without adding detection value that the internal-`http://` payloads
  do not already give (Resolved decision 4). `file://` stays because it yields a real
  content signature.
- **DNS rebinding**, **TOCTOU** on the allow-list, and **IPv6 zone-id tricks** beyond the
  static payload set.
- **New HTTP verbs or a new crawl.** Reuses 006's `GET`/`POST`-only injection points parsed
  from already-crawled bodies.
- **Any opt-in flag.** SSRF payloads write nothing to the target, so `--mode active` is
  sufficient — the same gating as reflected XSS / SQLi / traversal / redirect in 006. No
  `--ssrf` switch, no new `[injection]` field (Resolved decisions 2, 5).
- **Web API / dashboard changes.** Engine + CLI only, following spec 006/008/010.
- **Parameter mining.** Only parameters the target actually exposes are fuzzed.
- **WAF-evasion tuning.** The payload set is small, static, in-repo, no mutation engine —
  same posture as every 006 detector.
- **Header-based SSRF** (`X-Forwarded-For`, `X-Forwarded-Host`, `Referer` used server-side)
  and **SSRF via file upload / XML (XXE)** — separate surfaces, not this spec.

## Personas

| Persona | Needs from 009 |
|---|---|
| **Security-conscious developer** | "Does my 'fetch preview from URL' endpoint let someone hit `169.254.169.254`?" — a finding that names the parameter, the payload that worked, and what leaked. |
| **Pentester / consultant** | On an authorized engagement, a fast in-band SSRF check that flags the obvious cases (metadata, loopback, `file://`) so time goes to the ones that need a collaborator. |
| **CI pipeline author** | A CRITICAL SARIF result when a build exposes the metadata service, so `--fail-on critical` blocks the deploy — with no external service in the loop. |
| **Check author / contributor** | `detect/ssrf.py` as the reference for "prove a server-side effect from in-band signals only". |

## Functional requirements

### Detection

**RF-01 — SSRF detector in the injection pass**
- **Given** an Active scan with `injection.ssrf.metadata` or `injection.ssrf.internal`
  selected, **when** the `InjectionScanner` runs, **then** a new `ssrf` detector is fanned
  for each injection point alongside the 006 detectors, drawing on the same shared
  `ActiveBudget` and the point's shared `Baseline`.
- **Given** the detector, **then** it issues its payloads through `DetectCtx.send` (so the
  scope guard, concurrency cap, per-host delay, timeout, and per-point request cap all
  apply) and stops as soon as `send` returns `None` (budget reached).

**RF-02 — URL-shaped-parameter priority**
- **Given** the enumerated injection points, **when** the detector order is chosen for a
  point, **then** a point whose **name** is URL-associated (`url`, `uri`, `link`, `src`,
  `source`, `dest`, `destination`, `callback`, `webhook`, `feed`, `rss`, `proxy`, `fetch`,
  `load`, `remote`, `image`, `img`, `avatar`, `import`, `upload`, `document`, `target`,
  `to`, `out`, `next`, `continue`, `return`, `redirect_uri`, `site`, `domain`, `host`,
  `path`, `page`, `view`) **or** whose current **value** looks like a URL
  (`^\s*(?:https?:)?//` or contains `://`) is tested by the `ssrf` detector **first**,
  within budget — mirroring 006 RF for `traversal` / `redirect`.
- **Given** a point that matches neither, **then** it is still tested if budget remains, at
  lower priority.

**RF-03 — Cloud metadata detection**
- **Given** the detector sends a cloud-metadata payload — AWS/Azure/DO/OCI
  `http://169.254.169.254/…` (incl. `…/latest/meta-data/iam/security-credentials/` and the
  Azure IMDS `…/metadata/instance?api-version=…` form), GCP
  `http://metadata.google.internal/computeMetadata/v1/…` and
  `http://169.254.169.254/computeMetadata/v1/…`, AliCloud `http://100.100.100.200/…`,
  Kubernetes `https://kubernetes.default.svc/` — plus the obfuscated forms of
  `169.254.169.254` (RF-07) — **when** the response body contains a **provider-specific
  marker** absent from the baseline — e.g. `ami-id`, `instance-id`,
  `iam/security-credentials`, `"AccessKeyId"`, `"Code"\s*:\s*"Success"` (AWS);
  `computeMetadata`, `"machineType"` (GCP); `"azEnvironment"`, `"vmId"`,
  `"resourceGroupName"` (Azure); AliCloud equivalents; `"kind"\s*:\s*"Status"` +
  `"forbidden"` (a Kubernetes API-server 403) — **then** it emits an
  `injection.ssrf.metadata` hit, `severity = CRITICAL`, `confidence = HIGH`.
- **Given** the payload string is merely echoed back without any provider marker, **then**
  it is **not** a hit (the app reflected the parameter, it did not fetch it).

**RF-04 — `file://` read detection**
- **Given** the detector sends a `file://` payload (`file:///etc/passwd`,
  `file:///c:/windows/win.ini`, `file://localhost/etc/passwd`), **when** the response
  contains a `/etc/passwd` (`root:.*?:0:0:`) or `win.ini` (`[fonts]` / `[extensions]`)
  signature absent from the baseline, **then** it emits an `injection.ssrf.internal` hit,
  `severity = HIGH`, `confidence = HIGH`, with a note that a local file was read.
- The `/etc/passwd` / `win.ini` signature set is **shared with** the 006 traversal
  signatures (`payloads.TRAVERSAL_SIGNATURES`) — one source of truth.

**RF-05 — Internal / loopback content detection**
- **Given** the detector sends a loopback / RFC-1918 payload (`http://127.0.0.1/`,
  `http://127.0.0.1:<port>/`, `http://localhost/`, `http://[::1]/`, `http://0.0.0.0/`,
  `http://2130706433/`, `http://0x7f000001/`, `http://0177.0.0.1/`, `http://127.1/`,
  and the bare `http://169.254.169.254/`), **when** the response body differs materially
  from the baseline in a way consistent with a fetched internal resource — a new
  non-trivial body, an HTML `<title>`/server banner absent from the baseline, or a status
  the baseline never returned — **then** it emits an `injection.ssrf.internal` hit,
  `severity = HIGH`, `confidence = MEDIUM` (or HIGH when the fetched content is
  unambiguous, e.g. a recognizable internal-service page).

**RF-06 — SSRF-shaped error detection**
- **Given** the detector sends any SSRF payload, **when** the response contains a
  distinctive **connection error** — `Connection refused`, `No route to host`,
  `Name or service not known`, `getaddrinfo`, `ECONNREFUSED`, `Failed to (connect|resolve)`,
  `certificate verify failed`, `curl: \(\d+\)`,
  `java\.net\.(Connect|UnknownHost|SocketTimeout)Exception`,
  `requests\.exceptions\.\w+`, `urllib\.error`, `ssrf` — **and** that error is absent from
  the baseline **and** the response echoes (a fragment of) the injected URL or the internal
  host, **then** it emits an `injection.ssrf.internal` hit, `severity = HIGH`,
  `confidence = MEDIUM`, titled to make clear it proves a *server-side fetch of an
  attacker-controlled URL* even though no resource body leaked.
- **Given** a generic error with no URL echo and no SSRF-specific wording, **then** it is
  **not** a hit.

**RF-07 — Obfuscation payloads**
- **Given** the payload set, **then** it includes the documented IP/host obfuscations
  (decimal `2130706433`, hex `0x7f000001`, octal `0177.0.0.1`, short `127.1`, IPv6 `[::1]`,
  `@`-confusion `http://<target-host>@169.254.169.254/`, and a fragment trick
  `http://169.254.169.254#@<target-host>/`) so a target that blocks the literal
  `127.0.0.1` / `169.254.169.254` but not an encoded form is still flagged.
- `<target-host>` is substituted by the detector from `DetectCtx.host` (the mechanism
  already exists for the redirect `{host}` payload).

**RF-08 — Hit shape**
- **Given** an SSRF hit, **then** the `InjectionHit` carries `kind = "ssrf-metadata"` or
  `"ssrf-internal"`, the matching `check_id`, `method` / `url` (the injection point base
  URL) / `param`, the chosen `severity` and `confidence`, a `title` naming the parameter
  and what was reached, the `payload` that worked, and `evidence` of: the injection point,
  the payload, and the proof (the metadata marker / file signature / leaked line / error
  text).

### Checks

**RF-09 — `injection.ssrf.metadata`**
- **Given** the check registry, **then** `injection.ssrf.metadata` is registered —
  `category = INJECTION`, `mode = ACTIVE`, `default_severity = CRITICAL`,
  `cwe = (918,)`, references to the OWASP SSRF cheat sheet and the cloud providers'
  metadata-hardening docs.
- **Given** an Active scan, **when** the pass produced a `ssrf-metadata` hit, **then** the
  check emits one finding per hit with the hit's severity/confidence, a `Location`
  carrying `method` / `url` / `param`, and a description explaining that the instance
  metadata service (and likely its IAM credentials) is reachable through this parameter.

**RF-10 — `injection.ssrf.internal`**
- **Given** the check registry, **then** `injection.ssrf.internal` is registered —
  `category = INJECTION`, `mode = ACTIVE`, `default_severity = HIGH`, `cwe = (918,)`,
  references to the OWASP SSRF cheat sheet. (A `file://` read through a server-side fetcher
  is still CWE-918; no separate CWE is added, keeping the shared `_InjectionCheck` body
  untouched.)
- **Given** an Active scan, **when** the pass produced a `ssrf-internal` hit, **then** the
  check emits one finding per hit, with a description matched to the proof (internal
  resource read / local file read / server-side fetch of an attacker URL confirmed by
  error).

**RF-11 — `list-checks` and suppression**
- **Given** `webvigil list-checks`, **then** both ids appear with `INJECTION` / `active` /
  their default severity.
- **Given** `[checks] disabled = ["injection.ssrf.metadata"]` (and/or `…internal`), **then**
  that check does not run; if **both** are disabled the `ssrf` detector does not run at all
  (no SSRF payloads sent) — same gating as every 006 detector.

### Fixture app and tests

**RF-12 — Vulnerable and hardened fetch endpoints**
- **Given** the fixture app's **insecure** profile, **then** it exposes a URL-fetch
  endpoint (e.g. `GET /fetch?url=`) that performs a server-side request to the supplied
  URL and returns the result. For determinism and offline testing, the endpoint itself
  recognises the SSRF payloads: a `169.254.169.254` / `metadata.google.internal` URL
  returns canned metadata JSON with the real provider markers; a `file:///etc/passwd`
  URL returns the fixture's `_ETC_PASSWD`; a loopback URL returns a recognizable internal
  page; an unreachable internal host returns a canned connection error echoing the URL.
- **Given** the **hardened** profile, **then** the same endpoint resolves the URL and
  **rejects** anything that is not on an allow-list of external hosts (400 / a neutral
  error with no upstream body, no signature).
- **Given** an integration Active scan of the insecure profile, **then**
  `injection.ssrf.metadata` and `injection.ssrf.internal` findings are present with the
  expected parameter and evidence; **given** the hardened profile, **then** **zero**
  `injection.ssrf.*` findings (false-positive guard, mirrors 006 RF-27).

**RF-13 — Unit coverage**
- The `ssrf` detector's branches — metadata marker match (per provider), `file://`
  signature, internal content diff, SSRF-error match, "payload echoed but not fetched → no
  hit", baseline suppression, `is_urllike`, and obfuscation-payload `{host}` substitution —
  are unit-tested with crafted responses via a stub `send`, not only through the
  integration scan.

### Reporting

**RF-14 — Reporters unchanged**
- No reporter gains a field or a section. `injection.ssrf.*` findings flow through the same
  `_InjectionCheck` → `Finding` path as every 006 check; `CWE-918` rides the existing `cwe`
  field. A saved canonical JSON re-renders offline exactly as before.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives entirely in `webvigil.checks.injection` (`detect/ssrf.py`, additions to
`payloads.py` / `engine.py` / `checks.py`). **No config change** — no new `[injection]`
field, no CLI flag. Nothing imported from `webvigil.cli` / `webvigil.api` / `web/`; no new
runtime dependency. `import-linter` unchanged.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy` covering the new
modules. No `web` gate work (engine + CLI only).

**RNF-03 — No new egress, no infrastructure, no cost**
The engine still makes outbound requests **only to the target host**. Every SSRF payload is
a *value* placed in a target parameter; whatever the target then connects to is the
target's behaviour, observed in-band. No collaborator server, no third-party service, no
public DNS/HTTP infrastructure, no paid API. Runs on the same machine resources as any
WebVigil scan (I/O-bound, bounded extra requests within the Active-Mode budget).

**RNF-04 — Bounded work**
The `ssrf` detector's requests are drawn from the shared `ActiveBudget` and the per-point
cap (`_PER_POINT_REQUEST_CAP = 30`). The payload set is small and static. Hitting a cap is
a scan warning, never an error.

**RNF-05 — Determinism and false-positive discipline**
- Given the same target responses, the same findings / evidence / ordering across runs.
- Every signature must be **absent from the point's baseline** to count.
- A metadata hit requires a provider-specific token, not the IP or payload echoed.
- The internal-content signal requires a material, resource-shaped difference from the
  baseline — not a one-character diff, not the reflected payload.
- The hardened fixture profile yields zero `injection.ssrf.*` findings.

**RNF-06 — Non-destructive**
SSRF payloads are reads. The detector issues `GET` (and `POST` when the point is a POST
form field), never other verbs, and writes nothing to the target. It does not follow the
target's outbound redirects itself (the scope guard already blocks off-host hops).

**RNF-07 — Python support**
CPython 3.12 and 3.13 (existing CI matrix).

**RNF-08 — Docs**
`docs/active-injection.md` gains an SSRF section: the two checks, the payload categories,
the metadata targets, and an explicit statement that **blind SSRF is not covered and needs
a future opt-in collaborator spec**. The "No SSRF" bullet under "What it does not do"
becomes "in-band SSRF shipped in v0.9; blind SSRF still needs a collaborator".
`README.md` coverage table, `CLAUDE.md` layer-3 injection paragraph, and `specs/README.md`
roadmap updated; 009 moves to `in progress` then `done`.

## Resolved during requirements

Settled with Ryan on 2026-09-07 (Ryan delegated the calls, optimising for "a professional,
defensible tool that builds authority in the topic"):

1. **Two checks.** `injection.ssrf.metadata` (CRITICAL — credential exposure) and
   `injection.ssrf.internal` (HIGH). Mirrors 006's one-check-per-kind; lets
   `--fail-on critical` isolate the metadata case.
2. **No timing / blind-ish probe in 009.** Timing-based SSRF detection is semi-blind,
   environment-sensitive, and hard to test deterministically — it belongs with the deferred
   blind-SSRF toolkit, not here. 009 ships only signals it can prove cleanly from the
   response. This removes the `[injection] ssrf_timing` field and the `--ssrf-timing` flag
   — **009 makes no config or CLI change at all**.
3. **Report the SSRF-shaped-error signal.** An error that names the injected URL / internal
   host and is absent from the baseline is a real finding — it proves the parameter reaches
   a server-side fetcher. `injection.ssrf.internal`, `confidence = MEDIUM`.
4. **`file://` in; no `gopher://` / `dict://`.** `file://` yields a real content signature
   (a HIGH-confidence read). Exotic schemes only add error noise the internal-`http://`
   payloads already cover, and protocol smuggling is a non-goal anyway.
5. **No opt-in flag.** SSRF payloads write nothing to the target, so `--mode active` +
   check selection is the gate — identical to reflected XSS / SQLi / traversal / redirect
   in 006. `--stored-xss` exists only because 008 *persists data*.
6. **Blind / OAST SSRF stays deferred** to a future opt-in spec (candidate `011-ssrf-oast`),
   analogous to spec 010 following spec 004. Recorded in `specs/README.md` at close.
7. **Metadata breadth:** AWS (`…/latest/meta-data/` + `…/iam/security-credentials/`), GCP
   (`metadata.google.internal/computeMetadata/v1/` + the `169.254.169.254` form), Azure IMDS
   (`…/metadata/instance?api-version=…`), AliCloud (`100.100.100.200/…`), **Kubernetes**
   (`https://kubernetes.default.svc/` — 403 `"kind":"Status"` signature), plus the
   obfuscated `169.254.169.254` forms. DigitalOcean / Oracle use `169.254.169.254`, already
   covered.

## Open questions

None. Ready for `/spec design`.
