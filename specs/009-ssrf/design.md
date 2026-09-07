---
feature: In-band SSRF detection — cloud metadata, loopback/internal, file:// (Active Mode)
status: done
date: 2026-09-07
related:
  - 006-active-injection/design.md
  - 008-stored-xss/design.md
origin: conception
---

# 009 — In-band SSRF detection — design

> Design notes: [why blind SSRF is not on the roadmap](../../docs/notes/why-not-oast.md) ·
> [false-positive discipline](../../docs/notes/false-positive-discipline.md).

## Overview

009 adds one detector to the spec-006 injection pass and two thin checks that consume its
hits. Nothing else in the engine moves.

- **`detect/ssrf.py`** — `async def detect(point, baseline, ctx) -> list[InjectionHit]`,
  the sixth entry in `engine._DETECTORS`. For an injection point it sends a small static
  set of URL payloads through `DetectCtx.send` (budgeted, scope-guarded) and returns **one**
  hit as soon as any of four in-band proofs lands:
  1. a **cloud-metadata marker** in the response, absent from the baseline → a
     `ssrf-metadata` hit (`injection.ssrf.metadata`, CRITICAL);
  2. a **`file://` read signature** (`/etc/passwd`, `win.ini`) → `ssrf-internal` (HIGH);
  3. a **recognizable internal-service response** (Redis, nginx status, Docker API, …) →
     `ssrf-internal` (HIGH);
  4. an **SSRF-shaped connection error** (or a `502/504` the baseline never returned) that
     **echoes the injected URL** → `ssrf-internal` (HIGH severity, MEDIUM confidence) —
     proves the parameter reaches a server-side fetcher even when no body leaked.
  Every signature must be **absent from the point's baseline** (`baseline.raw_body`).
- **`points.is_urllike(point)`** — a name/value heuristic; `engine._ordered_kinds` runs the
  `ssrf` detector **first** for a URL-shaped point, exactly as it already front-loads
  `traversal` for path-like names and `redirect` for redirect names.
- **`SsrfMetadataCheck` / `SsrfInternalCheck`** — subclasses of the existing
  `_InjectionCheck`; they only filter `ctx.observations.injection_hits` by `kind`. No new
  base-class code, no per-finding CWE juggling.

**No orchestrator pass** (unlike 008 — the reflected `InjectionScanner` already does
everything). **No config, no CLI flag** (unlike 008/010 — SSRF payloads write nothing to
the target, so `--mode active` + check selection is the whole gate). **No API/UI change.**
The engine still only ever connects to the target host; an SSRF payload is a *value* in a
target parameter and whatever the target then fetches is the target's behaviour, observed
in-band.

```
InjectionScanner.run                                        [006, unchanged]
  enumerate_points → per point: baseline → _ordered_kinds → fan _DETECTORS
        _ordered_kinds now front-loads "ssrf" when is_urllike(point)          [009]
        _DETECTORS["ssrf"] = ssrf.detect                                      [009]
              payload → ctx.send → response
                 _metadata_hit  → ssrf-metadata  (CRITICAL/HIGH)
                 _file_hit      → ssrf-internal   (HIGH/HIGH)
                 _internal_hit  → ssrf-internal   (HIGH/HIGH)
                 _error_hit     → ssrf-internal   (HIGH/MEDIUM)
  → InjectionHit list → ctx.observations.injection_hits
        SsrfMetadataCheck  (kind="ssrf-metadata")  → Finding                  [009]
        SsrfInternalCheck  (kind="ssrf-internal")  → Finding                  [009]
```

## Module layout

| Path | Change | What |
|---|---|---|
| `src/webvigil/checks/injection/detect/ssrf.py` | **new** (~160 lines) | the `detect` coroutine + `_metadata_hit` / `_file_hit` / `_internal_hit` / `_error_hit` + `_snippet` / `_authority`. |
| `src/webvigil/checks/injection/payloads.py` | edit | an SSRF section: `SSRF_METADATA`, `SSRF_FILE`, `SSRF_INTERNAL` payload tuples; `SSRF_METADATA_SIGNATURES`, `SSRF_INTERNAL_SIGNATURES`, `SSRF_ERROR_SIGNATURES` regex tuples. `file://` reuses `TRAVERSAL_SIGNATURES`. |
| `src/webvigil/checks/injection/points.py` | edit | `_URLLIKE_NAMES`, `_URLLIKE_VALUE`, `def is_urllike(point) -> bool`. |
| `src/webvigil/checks/injection/engine.py` | edit | import `ssrf` detector; `_DETECTORS["ssrf"]`; `"ssrf"` into `_BASE_ORDER` (before `sqli-time`); `KIND_BY_CHECK_ID` gains both ids → `"ssrf"`; `_ordered_kinds` gains the `(is_urllike, "ssrf")` front-load. |
| `src/webvigil/checks/injection/checks.py` | edit | `_DESCRIPTION` / `_REMEDIATION` / `_REFERENCES` entries for `"ssrf-metadata"` and `"ssrf-internal"`; `@register class SsrfMetadataCheck` / `SsrfInternalCheck`. |
| `tests/fixtures/app.py` | edit | `/fetch?url=` — insecure (SSRF-able, recognises the payloads for deterministic offline proof) and hardened (allow-list) — plus a link so the crawler finds `?url=`. |
| `tests/unit/test_injection_ssrf.py` | **new** | the detector's branches via a stub `send`. |
| `tests/unit/test_injection_points.py`, `…_engine.py`, `…_orchestrator.py`, `…checks_injection.py`, `…cli.py` | edit | `is_urllike`; `_BASE_ORDER`/`KIND_BY_CHECK_ID`/priority; detector gating; check metadata + finding shape + `_ALL`; `list-checks`. |
| `tests/integration/test_scan_fixture_app.py` | edit | Active scan → `injection.ssrf.*` on insecure, **zero** on hardened, deterministic; page-count fix. |
| `docs/active-injection.md`, `README.md`, `CLAUDE.md`, `specs/README.md` | edit | SSRF section / coverage row / layer-3 paragraph / roadmap. |

Nothing under `src/webvigil/core/`, `src/webvigil/cli/` (beyond a `list-checks` test),
`src/webvigil/api/`, or `web/` changes. `import-linter` contracts unchanged.

## Data model

### `InjectionHit` — reused unchanged

`kind` takes two new string values, `"ssrf-metadata"` and `"ssrf-internal"`. Every other
field is populated as the 006 detectors already do. **No new field** — the CWE stays on the
check class (`(918,)` for both), so `_InjectionCheck.run` is untouched.

### No new value types, no config

`ActiveBudget`, `Baseline`, `DetectCtx`, `InjectionReport` — all as-is. `InjectionSection`
in `core/config.py` — **not touched**.

## Components

### Payloads (`payloads.py`, RF-03..RF-07)

`{host}` is substituted with the target host by the detector, reusing the mechanism the
redirect payloads already use.

```python
# --- SSRF (spec 009) ---------------------------------------------------------------

# Cloud instance-metadata endpoints. A hit needs a provider marker in the body (RF-03),
# never just the address echoed back.
SSRF_METADATA: tuple[str, ...] = (
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://100.100.100.200/latest/meta-data/",
    "https://kubernetes.default.svc/",
    "http://2852039166/latest/meta-data/",              # 169.254.169.254 as decimal
    "http://0xA9FEA9FE/latest/meta-data/",              # …as hex
    "http://{host}@169.254.169.254/latest/meta-data/",  # @-confusion
    "http://169.254.169.254#@{host}/latest/meta-data/", # fragment trick
)

SSRF_FILE: tuple[str, ...] = (
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "file://localhost/etc/passwd",
)

# Loopback / link-local / RFC-1918, plus the encodings that bypass a naïve string block.
SSRF_INTERNAL: tuple[str, ...] = (
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://127.1/",
    "http://2130706433/",       # 127.0.0.1 decimal
    "http://0x7f000001/",       # …hex
    "http://0177.0.0.1/",       # …octal
    "http://{host}@127.0.0.1/",
    "http://169.254.169.254/",  # bare link-local as an internal-reach canary
)

SSRF_METADATA_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS", re.compile(
        r'"AccessKeyId"|"Code"\s*:\s*"Success"|\bami-id\b|instance-identity|'
        r"iam/security-credentials", re.I)),
    ("GCP", re.compile(
        r'computeMetadata|"serviceAccounts"|"machineType"|oauth2/v4/token', re.I)),
    ("Azure", re.compile(r'"azEnvironment"|"vmId"|"resourceGroupName"', re.I)),
    ("AliCloud", re.compile(r'"owner-account-id"|dns-conf/nameservers', re.I)),
    ("Kubernetes", re.compile(
        r'"kind"\s*:\s*"Status"[\s\S]{0,200}"(?:forbidden|Forbidden)"', re.I)),
)

# Distinctive first bytes of common internal services that answer an HTTP GET.
SSRF_INTERNAL_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Redis", re.compile(r"redis_version:|-DENIED Redis|-NOAUTH Authentication", re.I)),
    ("nginx status", re.compile(r"Active connections:\s*\d+|server accepts handled", re.I)),
    ("Docker API", re.compile(r'"ApiVersion"\s*:|"Containers"\s*:\s*\d+', re.I)),
    ("Elasticsearch", re.compile(r'"cluster_name"\s*:|"lucene_version"\s*:', re.I)),
    ("internal HTTP", re.compile(
        r"<title>\s*(?:Index of /|401 Authorization Required|Grafana|Kibana|"
        r"phpMyAdmin|Jenkins)", re.I)),
)

SSRF_ERROR_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(r"Connection refused|No route to host|Network is unreachable|"
               r"Name or service not known|nodename nor servname", re.I),
    re.compile(r"getaddrinfo|ECONNREFUSED|EHOSTUNREACH|ETIMEDOUT|ENETUNREACH", re.I),
    re.compile(r"Failed to (?:connect|resolve|open)|could not resolve host|"
               r"unknown url type|unsupported protocol", re.I),
    re.compile(r"certificate verify failed|CERTIFICATE_VERIFY_FAILED", re.I),
    re.compile(r"curl: \(\d+\)", re.I),
    re.compile(r"java\.net\.(?:Connect|UnknownHost|SocketTimeout|MalformedURL)Exception", re.I),
    re.compile(r"requests\.exceptions\.\w+|urllib3?\.exceptions|aiohttp\.client_exceptions", re.I),
)
```

### `detect/ssrf.py`

```python
_METADATA_ID = "injection.ssrf.metadata"
_INTERNAL_ID = "injection.ssrf.internal"
_GATEWAY_STATUS = frozenset({502, 503, 504})


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    for group in (payloads.SSRF_METADATA, payloads.SSRF_FILE, payloads.SSRF_INTERNAL):
        for template in group:
            payload = template.replace("{host}", ctx.host)
            response = await ctx.send(point, payload)
            if response is None:
                return []                       # budget reached — stop, like every 006 detector
            hit = (
                _metadata_hit(point, baseline, payload, response)
                or _file_hit(point, baseline, payload, response)
                or _internal_hit(point, baseline, payload, response)
                or _error_hit(point, baseline, payload, response)
            )
            if hit is not None:
                return [hit]                     # one hit per point is enough (as traversal/redirect)
    return []
```

- **`_metadata_hit`** — for each `(provider, pattern)` in `SSRF_METADATA_SIGNATURES`:
  `pattern.search(response.text)` and `not pattern.search(baseline.raw_body)` →
  `InjectionHit(kind="ssrf-metadata", check_id=_METADATA_ID, severity=CRITICAL,
  confidence=HIGH, title=f"SSRF to the {provider} instance metadata service via
  '{point.param}'", payload=…, evidence=(point, payload, marker snippet))`.
- **`_file_hit`** — only when `payload.lower().startswith("file:")`; for each pattern in
  `payloads.TRAVERSAL_SIGNATURES` (shared): present, baseline-absent →
  `kind="ssrf-internal"`, `severity=HIGH`, `confidence=HIGH`,
  `title=f"SSRF local file read (file://) via '{point.param}'"`, evidence includes the
  leaked line.
- **`_internal_hit`** — for each `(service, pattern)` in `SSRF_INTERNAL_SIGNATURES`:
  present, baseline-absent → `kind="ssrf-internal"`, `severity=HIGH`, `confidence=HIGH`,
  `title=f"SSRF to an internal service ({service}) via '{point.param}'"`.
- **`_error_hit`** — the weakest, most guarded signal:
  ```python
  authority = _authority(payload)                 # "127.0.0.1", "169.254.169.254", …
  if not authority or authority not in response.text:
      return None                                 # the injected URL must be echoed back
  error = _first_match(payloads.SSRF_ERROR_SIGNATURES, response.text, baseline.raw_body)
  gateway = response.status_code in _GATEWAY_STATUS and response.status_code != baseline.status
  if error is None and not gateway:
      return None
  return InjectionHit(
      kind="ssrf-internal", check_id=_INTERNAL_ID, severity=Severity.HIGH,
      confidence=Confidence.MEDIUM,
      title=f"SSRF — the '{point.param}' parameter is fetched server-side",
      payload=payload,
      evidence=(_point_evidence(point), ("Payload", payload),
                ("Server-side fetch", error or f"HTTP {response.status_code} with the injected URL echoed back")),
  )
  ```
  `_authority(payload)` = the text between `://` and the next `/` (`urlsplit` is unreliable
  for the obfuscated forms), stripped of any `user@`. `_first_match` returns the snippet of
  the first pattern that hits `response.text` and misses `baseline.raw_body`, else `None`.

`_point_evidence` and `_snippet` mirror the helpers in `detect/sqli.py` /
`detect/traversal.py` (a labelled point line; a ≤200-char line around a match index).

### `points.is_urllike` (RF-02)

```python
_URLLIKE_NAMES = frozenset({
    "url", "uri", "u", "link", "src", "source", "href", "dest", "destination",
    "callback", "webhook", "hook", "feed", "rss", "proxy", "fetch", "load", "remote",
    "image", "img", "avatar", "photo", "import", "upload", "document", "file",
    "target", "to", "out", "next", "continue", "return", "redirect", "redirect_uri",
    "site", "domain", "host", "server", "path", "page", "view", "data", "json", "xml",
    "api", "endpoint", "resource", "content", "preview", "open", "download",
})
_URLLIKE_VALUE = re.compile(r"^\s*(?:https?:)?//|\bhttps?://|://|^\s*www\.", re.I)


def is_urllike(point: InjectionPoint) -> bool:
    return point.param.lower() in _URLLIKE_NAMES or bool(_URLLIKE_VALUE.search(point.original))
```

`file` / `path` / `page` overlap `_PATHLIKE_NAMES` on purpose — such a point is tried by
both `traversal` and `ssrf`, within budget (that is already how `traversal` and `redirect`
can both front-load for `next` / `url`).

### `engine.py`

```python
from webvigil.checks.injection.detect import ssrf as ssrf_detect
from webvigil.checks.injection.points import ..., is_urllike

_DETECTORS = { ..., "ssrf": ssrf_detect.detect }
_BASE_ORDER = ("xss", "sqli-error", "sqli-boolean", "traversal", "redirect", "ssrf", "sqli-time")

KIND_BY_CHECK_ID = {
    ...,
    "injection.ssrf.metadata": "ssrf",
    "injection.ssrf.internal": "ssrf",
}
```

`_ordered_kinds` gains one predicate/kind pair:

```python
for predicate, kind in (
    (is_pathlike, "traversal"),
    (is_redirect_name, "redirect"),
    (is_urllike, "ssrf"),
):
    if predicate(point) and kind in kinds:
        kinds.remove(kind)
        kinds.insert(0, kind)
```

Both `injection.ssrf.*` ids mapping to the single `"ssrf"` kind means: the detector runs
when **either** check is selected, and not at all when **both** are disabled (RF-11) —
`selected_kinds` is a `set`, so the duplicate collapses.

### `checks.py`

```python
_DESCRIPTION["ssrf-metadata"] = (
    "A URL supplied in this parameter is fetched by the server, and the request reached the "
    "cloud instance metadata service. That endpoint exposes instance details and, on most "
    "providers, temporary IAM credentials — full account compromise is a common next step."
)
_DESCRIPTION["ssrf-internal"] = (
    "A URL supplied in this parameter is fetched by the server. WebVigil reached a loopback "
    "or internal-only resource (or read a local file via file://, or confirmed the outbound "
    "request from a connection error naming the injected URL). An attacker can pivot to "
    "internal services that trust the application's network position."
)
_REMEDIATION["ssrf-metadata"] = _REMEDIATION["ssrf-internal"] = (
    "Do not fetch user-supplied URLs directly. Resolve the host and reject any address that "
    "is loopback, link-local (169.254.0.0/16), private (RFC 1918), or otherwise internal — "
    "after DNS resolution, and again on every redirect. Allow-list the schemes (https only) "
    "and the destination hosts. On AWS, require IMDSv2 and set the hop limit to 1."
)
_SSRF_REFS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
)
_REFERENCES["ssrf-metadata"] = _REFERENCES["ssrf-internal"] = _SSRF_REFS


@register
class SsrfMetadataCheck(_InjectionCheck):
    id = "injection.ssrf.metadata"
    name = "SSRF — cloud metadata service"
    kind = "ssrf-metadata"
    default_severity = Severity.CRITICAL
    cwe = (918,)
    references = _REFERENCES["ssrf-metadata"]


@register
class SsrfInternalCheck(_InjectionCheck):
    id = "injection.ssrf.internal"
    name = "SSRF — internal resource"
    kind = "ssrf-internal"
    default_severity = Severity.HIGH
    cwe = (918,)
    references = _REFERENCES["ssrf-internal"]
```

### Fixture app (`tests/fixtures/app.py`, RF-12)

**insecure** — a proxy that fetches whatever it is given, standing in for a real
cloud/host environment so the integration test is deterministic and offline:

```python
def _fetch_insecure(request: Request) -> Response:
    raw = request.query_params.get("url", "")
    low = raw.lower()
    if not (low.startswith(("http://", "https://", "file:"))):
        return HTMLResponse(f"<!doctype html><div>preview of {raw}</div>")   # clean baseline
    if "169.254.169.254" in low or "2852039166" in low or "0xa9fea9fe" in low \
       or "metadata.google" in low or "100.100.100.200" in low:
        return PlainTextResponse(
            '{"Code":"Success","LastUpdated":"2026-09-07T00:00:00Z",'
            '"AccessKeyId":"ASIAIOSFODNN7EXAMPLE","Token":"FQoGZ...EXAMPLE"}')
    if low.startswith("file:"):
        return PlainTextResponse(_ETC_PASSWD if "passwd" in low else "file contents")
    if any(t in low for t in ("127.0.0.1", "localhost", "[::1]", "0.0.0.0", "127.1",
                              "2130706433", "0x7f000001", "0177.0.0.1")):
        return PlainTextResponse("redis_version:7.2.4\r\nredis_mode:standalone\r\n")
    return PlainTextResponse(f"failed to fetch {raw}: Connection refused", status_code=502)
```

**hardened** — allow-list, identical neutral rejection for every payload (and the baseline):

```python
def _fetch_hardened(request: Request) -> Response:
    raw = request.query_params.get("url", "")
    if not raw.startswith(("https://cdn.example.com/", "https://api.example.com/")):
        return PlainTextResponse("blocked: destination not on the allow-list", status_code=400)
    return PlainTextResponse("ok")
```

The insecure landing page (or `_LINKS`) gains `<a href="/fetch?url=/preview">preview</a>`
so the crawler discovers the `url` query parameter; `/fetch` is added to both profiles'
`_INJECTION_ROUTES` (GET). `_ETC_PASSWD` already exists (spec 006).

## Interfaces

No external interface. No new CLI option, no config key, no reporter field, no API route.
`webvigil list-checks` gains two rows (`injection.ssrf.metadata | INJECTION | active |
CRITICAL`, `injection.ssrf.internal | INJECTION | active | HIGH`).

## ADRs

### ADR-1 — In-band only; blind SSRF stays deferred

**Decision.** 009 detects SSRF only from the target's own response — a metadata marker, a
`file://` read, an internal-service fingerprint, or an SSRF-shaped error echoing the URL.
No collaborator server, no timing probe.

**Alternatives.** (a) Ship a timing / semi-blind probe now, behind a flag. (b) Use a public
OAST server (interactsh). (c) Wait and do the whole thing — blind included — in one spec.

**Why.** In-band SSRF is the achievable, zero-cost, zero-infrastructure half and covers the
cases that matter most (metadata → credentials, loopback, `file://`). It needs no change to
"the engine talks only to the target". A timing signal is environment-sensitive and hard to
test deterministically; a public OAST server sends callback tokens — and anything the
target exfiltrates — to a third party. Both belong with a future **opt-in** blind-SSRF spec
(`011-ssrf-oast`), the way the online OSV provider followed spec 004 as spec 010. Shipping
only what can be proven cleanly is the right call for a tool meant to be trustworthy.

**Trade-off.** Genuinely blind SSRF (no reflected body, no error, no gateway status) is a
false negative until `011`. The docs say so plainly.

### ADR-2 — One detector, two hit kinds, two checks

**Decision.** A single `ssrf` detector emits `kind="ssrf-metadata"` or `"ssrf-internal"`;
`KIND_BY_CHECK_ID` maps **both** check ids to the one `"ssrf"` detector kind; the two
checks filter by hit kind.

**Alternatives.** (a) Two detectors (`ssrf-metadata`, `ssrf-internal`) in `_DETECTORS`.
(b) One detector, one check (`injection.ssrf.confirmed`) with a per-hit severity.

**Why.** The metadata and internal probes share payloads, baseline handling, and control
flow — splitting the detector would duplicate all of it. Splitting the *check* (a) keeps
one CRITICAL id whose only cause is "the metadata service is reachable", so
`--fail-on critical` isolates the credential-exposure case, and (b) matches 006's
one-check-per-vulnerability-class shape. The 006 engine already tolerates a detector-kind
that differs from the hit kinds it produces — `KIND_BY_CHECK_ID` and `InjectionHit.kind`
are separate concepts.

**Trade-off.** `KIND_BY_CHECK_ID` gains a two-to-one mapping — a small readability cost,
covered by a comment and a test.

### ADR-3 — No new `InjectionHit` field for CWE; both checks are `(918,)`

**Decision.** `injection.ssrf.internal` carries `cwe = (918,)` for every proof, including
the `file://` read. `_InjectionCheck.run` is not touched.

**Alternatives.** Add `InjectionHit.cwe: tuple[int, ...] = ()` and have the shared `run`
apply it, so a `file://` hit could add CWE-73.

**Why.** A `file://` fetch *through a server-side URL fetcher* is squarely CWE-918 (SSRF) —
that is how it is classified in the wild. CWE-73 ("External Control of File Name or Path")
is the path-traversal framing and would read as noise on the loopback/metadata hits that
share the check. Keeping the CWE on the class means zero change to the shared check body —
the single biggest simplicity win of the spec.

**Trade-off.** A reviewer who wants CWE-73 on the `file://` case won't see it. The finding
title and description make the `file://` mechanism explicit regardless.

### ADR-4 — `_error_hit` requires the injected URL echoed back

**Decision.** The error / gateway-status signal only counts when the response also contains
the payload's authority (`127.0.0.1`, `169.254.169.254`, …).

**Alternatives.** Fire on any baseline-absent SSRF-shaped error; fire on any new `5xx`.

**Why.** Applications throw "Connection refused" / `5xx` for many reasons unrelated to the
parameter. Requiring the app to *echo the URL it failed to fetch* ties the error to *this
payload* and turns a vague signal into "the server tried to fetch the attacker's URL" — the
actual definition of SSRF. This is what keeps `injection.ssrf.internal` honest at MEDIUM
confidence rather than a false-positive generator.

**Trade-off.** An app that fetches the URL but does not echo it on error is a miss for this
branch (the metadata / internal-content branches still apply).

### ADR-5 — `is_urllike` front-loads, does not gate

**Decision.** URL-shaped points are tested by `ssrf` **first**; non-URL points are still
tested if budget remains, at normal priority — exactly the `traversal` / `redirect`
pattern.

**Alternatives.** Only run `ssrf` on URL-shaped points.

**Why.** SSRF sinks with an unhelpful parameter name are common (`id`, `q`, `data`). The
per-point cap and the shared budget already bound the cost; skipping non-URL points would
trade real findings for a marginal budget saving.

**Trade-off.** On a huge target the budget may be spent before every non-URL point gets the
`ssrf` payload set — reported as the existing budget warning.

## Impact

- **Backward compatible.** No new default behaviour: `ssrf` runs only in Active Mode with
  `injection.ssrf.metadata` or `injection.ssrf.internal` selected. Passive scans, and
  Active scans that disable both, are byte-for-byte unchanged.
- **Budget.** SSRF adds up to `len(SSRF_METADATA)+len(SSRF_FILE)+len(SSRF_INTERNAL)` ≈ 26
  requests per point *worst case*, bounded by `_PER_POINT_REQUEST_CAP = 30` and the shared
  `request_budget`. The detector returns on the first hit, so a vulnerable point costs far
  less.
- **No config / CLI / API / UI / reporter change.** `list-checks` gains two rows; SARIF/
  JSON/HTML/MD render the new findings through the existing `INJECTION` plumbing.
- **Determinism.** Given the same responses, identical findings / evidence / order.

## Risks

| Risk | Mitigation |
|---|---|
| `_error_hit` false positives | Requires the injected authority echoed **and** a baseline-absent SSRF-specific error or a new `5xx`; MEDIUM confidence; unit-tested against "generic 500, no echo → no hit". |
| Metadata signature over-matching (a page that legitimately contains `"machineType"`) | Signature must be **absent from the baseline**; the payload targets a metadata endpoint; the marker set is specific (`AccessKeyId`, `computeMetadata`, `vmId`). |
| An app that reflects the payload string without fetching it | No provider marker / file signature / internal fingerprint / URL-echoed error ⇒ no hit. Explicit unit test. |
| Obfuscated payloads (`http://2852039166/`) rejected by `httpx` before sending | `httpx` accepts decimal/hex hosts; if a specific form raises, `ctx.send` swallows `RequestFailed` and returns a response-less `None`-safe path (the detector just moves on). Covered by the existing `_send` try/except. |
| SSRF payload makes the scanner itself hit an internal address | It does **not** — the payload is a *value* in a request to the **target**; `ctx.send` builds `(method, point.base_url, params, data)`, so WebVigil only ever connects to the target host. The scope guard is unchanged. |
| Budget starvation for 006 detectors when many URL-shaped points exist | `ssrf` is one slot in `_BASE_ORDER` under the same shared budget as every other detector; hitting the cap is the existing warning, not an error. |

## Testing

| Layer | File | Cases |
|---|---|---|
| unit — detector | `tests/unit/test_injection_ssrf.py` (new) | stub `send` returning canned `Response`s: AWS/GCP/Azure/AliCloud/K8s marker → `ssrf-metadata` CRITICAL; `file:///etc/passwd` → `ssrf-internal` HIGH with the leaked line; Redis/nginx fingerprint → `ssrf-internal` HIGH; error + URL echo → `ssrf-internal` MEDIUM; `502` + URL echo → MEDIUM; generic `500` no echo → no hit; payload echoed, no marker → no hit; signature present in baseline → suppressed; `{host}` substituted from `ctx.host`; detector returns on first hit; `send` → `None` stops it. |
| unit — points | `tests/unit/test_injection_points.py` | `is_urllike` true for `url`/`callback`/`next` names and `http://…` / `//…` values; false for `q` with a plain value. |
| unit — engine | `tests/unit/test_injection_engine.py` | `"ssrf"` in `_BASE_ORDER` and `_DETECTORS`; both ssrf ids in `KIND_BY_CHECK_ID` → `"ssrf"`; `_ordered_kinds` puts `ssrf` first for a `url` point; absent when neither ssrf check selected. |
| unit — checks | `tests/unit/test_checks_injection.py` | add both to `_ALL`; a `ssrf-metadata` hit → one CRITICAL finding, `Location(url, method, param)`, evidence carries the marker; a `ssrf-internal` hit → HIGH; `[]` when no hit; ids/category/mode/severity. |
| unit — orchestrator | `tests/unit/test_injection_orchestrator.py` | Active + `SsrfMetadataCheck` selected → `selected_kinds` contains `"ssrf"`; both disabled → it does not; a raising detector → scan warning not crash (already covered generically). |
| unit — CLI | `tests/unit/test_cli.py` | `list-checks` lists `injection.ssrf.metadata` and `injection.ssrf.internal` with `CRITICAL` / `HIGH`. |
| integration | `tests/integration/test_scan_fixture_app.py` | `_run("insecure", active=True)` → `injection.ssrf.metadata` (param `url`, AWS marker in evidence) **and** `injection.ssrf.internal` present; `_run("hardened", active=True)` → **zero** `injection.ssrf.*`; two runs identical; adjust `pages_scanned` for the new `/fetch` link. |
| quality gate | — | `ruff → black → mypy src → lint-imports → pytest` green at every stage (tasks.md). |

## Open questions

None. Ready for `/spec tasks`.

## Implementation notes

Recorded at close (2026-09-07). What shipped, and where it differed from the design above:

- **`ssrf` runs *last* in `_BASE_ORDER`**, not before `sqli-time`. The 26-payload set was
  starving `sqli-time` (last in `_BASE_ORDER`, first to lose the per-point 30-request cap)
  on a busy point like `id` — an integration test caught it. `_ordered_kinds` still
  front-loads `ssrf` to position 0 for a URL-shaped point, so URL params keep priority;
  non-URL params get `ssrf` only if budget remains, which matches ADR-5's intent.
- **Canary vs. thorough payload split.** `detect()` calls `is_urllike(point)` itself: a
  URL-shaped point gets the full `SSRF_METADATA + SSRF_FILE + SSRF_INTERNAL` set; anything
  else gets `_CANARY` (`SSRF_METADATA[:2] + SSRF_FILE[:1] + SSRF_INTERNAL[:2]` = 5
  payloads). Keeps an obvious sink with an unhelpful name catchable without spending 26
  requests on it. `detect/ssrf.py` imports `is_urllike` from `points` (acyclic).
- **Metadata signatures are body-only.** Dropped `instance-identity` and
  `iam/security-credentials` from the AWS regex — they appear in the *payload URLs*, so an
  app that merely echoes the injected URL would have been a false `ssrf-metadata` hit. Kept
  `AccessKeyId`, `"Code":"Success"`, `InstanceProfileArn`, `ami-launch-index`,
  `block-device-mapping`. Same body-only discipline for GCP / AliCloud.
- **Two fixture endpoints, not one.** One detector returns one hit per point, so a single
  `/fetch` could only ever produce `injection.ssrf.metadata` *or* `injection.ssrf.internal`.
  The insecure profile has `/fetch?url=` (full SSRF, returns canned AWS creds → metadata
  CRITICAL) and `/webhook?callback=` (blocks the metadata IP like many real apps, still
  reaches loopback → internal HIGH). Hardened: both allow-listed, identical `400` for every
  payload → zero findings.
- **No config, no CLI, no `InjectionSection` change** — as designed.
- **pytest:** 587 at spec 010 close → **610** at 009 close (+23). Stage gates: 588 / 600 /
  603 / 606 / 610. `pages_scanned` 10 → 12 (the two new `/fetch` + `/webhook` links). The
  one pre-existing intermittent failure
  (`tests/api/test_scans.py::test_list_pagination_and_status_filter`, timestamp ordering —
  also noted in spec 010) surfaced once in a Stage-4 run and did not recur; unrelated.
- **Manual verification:** an Active scan of the fixture reports `injection.ssrf.metadata`
  (CRITICAL, param `url`, AWS creds in evidence) and `injection.ssrf.internal` (HIGH, param
  `callback`); the hardened profile reports neither; `webvigil list-checks` shows both ids;
  a request capture confirms WebVigil connected only to the target host.
