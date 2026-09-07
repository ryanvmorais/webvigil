---
feature: Stored / persistent XSS — two-phase inject-then-recrawl detection (Active Mode)
status: done
date: 2026-09-07
related:
  - 001-foundation/design.md
  - 006-active-injection/design.md
  - 007-auth-flows/design.md
origin: conception
---

# 008 — Stored / persistent XSS — Design

> Requirements: [`requirements.md`](requirements.md). This document is the *how*.
> Traceability tags (`— RF-NN` / `— RNF-NN`) point back to it.

## Overview

008 adds **one** `ACTIVE` check, `injection.xss.stored`, and a **two-phase pass** behind
it. The shape follows 006 (one orchestrator pass does the network work and leaves
`InjectionHit`s on `ctx.observations`; a thin check turns hits into findings), with one new
ingredient: the pass is **stateful** — it submits, then re-observes.

```
Orchestrator.run()
  ├─ crawl  → pages, forms                                            (spec 007, unchanged)
  ├─ _fingerprint(...)   (spec 004)
  ├─ _probe_disclosure(...)   (spec 005)
  ├─ _inject(...)   (spec 006)   → reflected/sqli/traversal/redirect hits
  ├─ _inject_stored(check_types, http, target, pages, forms, warnings)   NEW   (ADR-1)
  │     └─ StoredXssScanner.run()
  │           A. enumerate_points(pages, forms)        (006 points.py — POST forms first)   — RF-04
  │           B. per point: submit one token-tagged marker set; record token → StoredMarker  — RF-04
  │           C. re-crawl: Crawler.recrawl(frontier, depth 1)  → recrawled pages             — RF-05
  │           D. per recrawled page: match any token verbatim in an executable context       — RF-05, RF-08
  │           E. collect InjectionHit(kind="xss-stored")  + cap warnings
  ├─ ScanContext(observations=Observations(... injection_hits = inject_hits + stored_hits))
  └─ run checks  → injection.xss.stored filters hits by kind == "xss-stored"                  — RF-07
```

The pass runs **only** when `scan.mode is ACTIVE` **and** `injection.xss.stored` is in the
selected set **and** `config.injection.stored_xss` is `True` (ADR-1, ADR-4). A passive scan,
and a plain `--mode active` scan without `--stored-xss`, are byte-for-byte unchanged and
write **no** marker (RF-01, RNF-03).

Everything stays inside the engine's rules: new code in `webvigil.checks.injection` (a
`stored.py` module, marker constants, the check) plus small additive changes to
`webvigil.core.config` (`stored_xss`), `webvigil.core.orchestrator` (`_inject_stored`), and
`webvigil.crawler.crawler` (a `recrawl` method). No new runtime dependency (`re`,
`selectolax`, `secrets`, `urllib.parse`); the `import-linter` contract is unchanged. An
`injection.xss.stored` finding is an ordinary `Finding` and rides spec 001's four reporters
and spec 002/003's persistence and dashboard with **no migration and no `openapi.json`
regen** (RF-12) — 006 already proved the `INJECTION` category flows through as a string and
the reporters render `location.method` / `location.param` / `logicalLocations`.

## Module layout

```
src/webvigil/core/config.py                + InjectionSection.stored_xss: bool = False       — ADR-4, RF-01
src/webvigil/core/orchestrator.py          + _inject_stored() pass (after _inject)            — ADR-1, RF-01

src/webvigil/checks/injection/payloads.py  + STORED_TOKEN_BYTES, STORED_MARKERS              — ADR-5, RNF-06
src/webvigil/checks/injection/points.py    + build_request(point, value)  (extracted)        — ADR-3
src/webvigil/checks/injection/models.py    + StoredMarker, StoredXssReport;
                                           + ActiveBudget.take_recrawl()                      — ADR-6
src/webvigil/checks/injection/engine.py    _build_request → points.build_request  (no behaviour change) — ADR-3
src/webvigil/checks/injection/stored.py    NEW  StoredXssScanner (Phase A + B + detect)       — ADR-1, ADR-2
src/webvigil/checks/injection/checks.py    + _DESCRIPTION/_REMEDIATION/_REFERENCES["xss-stored"]
                                           + @register class StoredXssCheck(_InjectionCheck)  — RF-07

src/webvigil/crawler/crawler.py            + Crawler.recrawl(frontier, *, should_fetch, max_fetches) — ADR-2, RF-05

src/webvigil/cli/app.py                    + --stored-xss / --no-stored-xss                   — RF-10
src/webvigil/cli/_render.py                (no change — the existing injection line counts stored findings) — ADR-7

webvigil.example.toml                      + stored_xss line in [injection]                   — ADR-4
tests/fixtures/app.py                      + guestbook endpoints (insecure) / escaped (hardened) — ADR-8, RF-13
docs/active-injection.md                   + a "Stored XSS" section (or a new docs/stored-xss.md) — RF-16
```

## Components

### Config — `[injection] stored_xss` — ADR-4

```python
class InjectionSection(_Section):
    """Active-injection tuning (spec 006, spec 008). Only consulted on an Active scan."""

    request_budget: int = 500
    max_injection_points: int = 200
    time_based_sqli: bool = True
    time_based_delay_s: int = 5
    stored_xss: bool = False   # spec 008 — opt-in; markers are persisted by design (RNF-06)
```

`stored_xss` defaults **False** (Resolved-during-requirements 2): the stored pass writes
persistent data and needs an explicit extra choice on top of the Active-Mode attestation.
`webvigil.example.toml`'s `[injection]` block gains a commented `stored_xss = false` line
noting the CLI flag and the persisted-marker behaviour.

### Marker payloads — `payloads.py` — ADR-5, RNF-06

```python
# --- stored XSS (spec 008, RF-04) --------------------------------------------------

STORED_TOKEN_BYTES = 6
# {token} is a per-point secrets.token_hex — so a marker found on re-crawl traces back to
# the exact injection point. A hit needs the tag back verbatim (< and > not entity-encoded)
# in an HTML response, on a page other than the one it was submitted to.
STORED_MARKERS: tuple[str, ...] = (
    "<wvstored{token}>",                 # bare tag — did the app render our markup as HTML?
    '"><wvstored{token}>',                # attribute-breaker — same tag, out of a quoted value
)
```

No `alert(`, no `document.cookie`, no `src=`/network reference — the tag is inert in a
browser but unambiguously *rendered as an element* if the app failed to escape it. It
carries `wvstored` + the token, so it is trivially attributable to WebVigil in the target's
data store. Two markers per point is enough: one for element-content context, one for a
quoted-attribute context. (`javascript:`-URL and `<script>` contexts are 006's reflected
territory and rare for stored sinks; skipped to keep the persisted footprint minimal.)

### `build_request` — extracted to `points.py` — ADR-3

006's `engine._build_request(point, value)` becomes `points.build_request(point, value)`
verbatim (same signature, same body — `GET` → pair-list params; `POST` → `dict` body +
kept query). `engine.py` imports it; `stored.py` imports it. No behaviour change; one unit
test moves with it.

### `models.py` additions — ADR-5, ADR-6

```python
@dataclass(frozen=True, slots=True)
class StoredMarker:
    """One marker submitted through one injection point during Phase A."""

    token: str                 # the per-point secrets.token_hex
    point: InjectionPoint
    payloads: tuple[str, ...]   # the concrete STORED_MARKERS strings sent (token substituted)


@dataclass
class StoredXssReport:
    """The output of StoredXssScanner.run()."""

    hits: list[InjectionHit] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    markers_submitted: int = 0
    pages_recrawled: int = 0
```

`ActiveBudget` gains one method (the re-crawl fetches count against `request_budget` but
must *not* be gated by `per_point_limit`, which is a Phase-A concept):

```python
def take_recrawl(self, n: int = 1) -> bool:
    """Reserve n re-crawl fetches against the per-scan limit only (RF-06)."""
    if self.spent + n > self.request_limit:
        return False
    self.spent += n
    return True
```

`InjectionHit` is reused unchanged for `kind = "xss-stored"`.

### `StoredXssScanner` — `stored.py` — ADR-1, ADR-2, ADR-6

```python
_STORED_REFETCH_CAP = 60        # Phase B page budget; validated against the fixture (ADR-6, RF-06)
_CHECK_ID = "injection.xss.stored"


class StoredXssScanner:
    def __init__(
        self,
        http: HttpClient,
        target: Target,
        config: ScanConfig,          # needs [injection] AND [scan].max_pages / submit_forms
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
    ) -> None: ...

    async def run(self) -> StoredXssReport:
        points, warnings = enumerate_points(
            self._pages, self._forms, max_points=self._config.injection.max_injection_points
        )
        budget = ActiveBudget(
            request_limit=self._config.injection.request_budget,
            per_point_limit=_PER_POINT_REQUEST_CAP,     # imported from engine
            time_based_limit=0,
        )
        report = StoredXssReport(warnings=list(warnings))

        # Phase A — inject one token-tagged marker set per point, POST forms first.
        markers: dict[str, StoredMarker] = {}
        for point in _stored_order(points):                       # form points, then query
            if budget.exhausted():
                break
            budget.start_point()
            token = "wv" + secrets.token_hex(payloads.STORED_TOKEN_BYTES)
            sent: list[str] = []
            for template in payloads.STORED_MARKERS:
                payload = template.format(token=token[2:])
                if await self._submit(point, payload, budget) is None:
                    break
                sent.append(payload)
            if sent:
                markers[token] = StoredMarker(token, point, tuple(sent))
        report.markers_submitted = len(markers)
        if not markers:
            return report

        # Phase B — depth-1 re-crawl from the first crawl's frontier.
        frontier = tuple(p.url for p in self._pages if p.ok)
        pre = {normalize_url(p.url): p.text for p in self._pages if p.ok}
        recrawled = await Crawler(self._http, self._target, self._config).recrawl(
            frontier,
            should_fetch=budget.take_recrawl,
            max_fetches=min(_STORED_REFETCH_CAP, max(1, self._config.scan.max_pages)),
        )
        report.pages_recrawled = len(recrawled)
        if budget.exhausted():
            report.warnings.append(
                f"active injection stopped at the {budget.request_limit}-request budget"
            )
        if len(recrawled) >= _STORED_REFETCH_CAP:
            report.warnings.append(
                f"stored-XSS re-crawl stopped at the {_STORED_REFETCH_CAP}-page cap"
            )

        # Phases D/E — correlate.
        report.hits = _detect(markers, recrawled, pre)
        return report

    async def _submit(self, point, payload, budget) -> Response | None:
        if not budget.take():
            return None
        method, url, params, data = build_request(point, payload)
        try:
            return await self._http.request(method, url, params=params or None, data=data, crafted=True)
        except (RequestFailed, OutOfScopeError):
            return None
```

`_stored_order(points)` returns form points (`source == "form"`) first, then query points,
each group in `enumerate_points`'s existing stable order (RF-04).

**Detection** — `_detect(markers, recrawled_pages, pre_bodies) -> list[InjectionHit]`:

```
for token, marker in markers.items():
    render_locations = []                      # (page_url, context) for each executable render
    for page in recrawled_pages:
        if not (page.ok and page.is_html):
            continue
        for payload in marker.payloads:        # the concrete <wvstored…> strings
            if payload not in page.text:
                continue                       # not there, or entity-encoded → skip
            # was it already there before we injected? (only meaningful for a known URL)
            known = pre_bodies.get(normalize_url(page.url))
            if known is not None and payload in known:
                continue
            # render location must differ from where we submitted it (RF-08)
            if normalize_url(page.url) == normalize_url(marker.point.base_url):
                # same URL as the injection point — could be a reflection; only count it
                # if the point was POSTed (a POST action page that now shows stored data)
                if marker.point.method != "POST":
                    continue
            context = xss._context(page.text, payload)      # reuse 006's classifier
            render_locations.append((page.url, context))
            break
    if render_locations:
        yield _stored_hit(marker, render_locations)
```

`_stored_hit` builds one `InjectionHit` per marker (Resolved-during-requirements 9 — first
executable render location + a count):

```python
first_url, first_context = render_locations[0]
extra = len(render_locations) - 1
InjectionHit(
    kind="xss-stored",
    check_id=_CHECK_ID,
    method=marker.point.method,
    url=marker.point.base_url,                 # ← the injection point, NOT the render page (RF-09)
    param=marker.point.param,
    severity=Severity.HIGH,
    confidence=(
        Confidence.HIGH
        if first_context in ("html body", "attribute")
        and normalize_url(first_url) != normalize_url(marker.point.base_url)
        else Confidence.MEDIUM
    ),
    title=(
        f"Stored XSS: the '{marker.point.param}' field of "
        f"{marker.point.method} {marker.point.base_url} renders unescaped on {first_url}"
    ),
    payload=render_locations and marker.payloads[0] or "",
    evidence=(
        ("Injection point", f"{marker.point.method} {marker.point.base_url} — parameter '{marker.point.param}'"),
        ("Marker payload", marker.payloads[0]),
        ("Rendered on", first_url + (f"  (+{extra} more page(s))" if extra else "")),
        ("Reflection context", first_context),
        ("Response snippet", xss._snippet(<the matching page text>, <the matched payload>)),
    ),
)
```

`url = marker.point.base_url` is the key move (ADR-9 / RF-09): the finding's `Location.url`
and thus its **fingerprint** (`check_id` + `location.url` + `location.key` (= param) +
`dedup_key=""`) key on the injection point, so a per-entry render page whose id changes
between runs (`/guestbook/e/7` vs `…/8`) does **not** churn the finding. The render
location(s) live in the evidence.

### `Crawler.recrawl` — `crawler.py` — ADR-2, RF-05

A new method, not a change to `discover()` (006 ADR-3's reasoning — don't churn every
call site). Depth-1 BFS from a supplied frontier:

```python
async def recrawl(
    self,
    frontier: Sequence[str],
    *,
    should_fetch: Callable[[], bool],
    max_fetches: int,
) -> list[Page]:
    """Re-fetch every frontier URL, then follow one hop of *new* in-scope links.

    Reuses the crawl's own scope / logout / destructive-link rules and ``submit_forms``
    handling. ``should_fetch()`` is called before each fetch (the caller's budget guard);
    a False return stops the re-crawl. At most ``max_fetches`` pages.
    """
    seen: set[str] = {normalize_url(u) for u in frontier}
    pages: list[Page] = []
    queue: deque[tuple[str, int]] = deque((normalize_url(u), 0) for u in frontier)
    while queue and len(pages) < max_fetches and should_fetch():
        url, depth = queue.popleft()
        page = await self._fetch(url)
        pages.append(page)
        if depth == 0:                      # only expand one hop past the known frontier
            self._enqueue_links(page, seen, _wrap(queue, depth + 1))
            self._collect_and_enqueue_forms(page, seen, _wrap(queue, depth + 1))
    return pages
```

`_wrap` adapts the existing `_maybe_enqueue`/`_enqueue_links` (which push bare URLs) to push
`(url, depth)` — in practice a tiny `deque` subclass or a helper that `_enqueue_links` calls
through. The logout / destructive / `is_auth_form` skips inside `_maybe_enqueue` and
`_collect_and_enqueue_forms` apply unchanged, so the re-crawl inherits every 007 safety
guarantee (RF-02). Robots/sitemap are **not** re-consulted (the first crawl already
honoured them; the frontier is a subset of what they allowed).

> Implementation note: `_maybe_enqueue` / `_enqueue_links` / `_collect_and_enqueue_forms`
> currently take a `deque[str]`. The cheapest faithful change is to have `recrawl` keep a
> plain `deque[str]` for the one-hop queue and track depth implicitly (frontier fetched
> first from a list, then a single drain of the link queue) rather than threading a depth
> tuple. Either is fine; the tasks pick one.

### `injection.xss.stored` — `checks.py` — RF-07

```python
_DESCRIPTION["xss-stored"] = (
    "A value supplied in this parameter is stored by the application and later rendered in "
    "another page's HTML with its markup intact, in a context where a browser would execute "
    "it. The payload runs for every user who views that page — no phishing link required."
)
_REMEDIATION["xss-stored"] = _REMEDIATION["xss"]        # same fix: context-encode on output
_REFERENCES["xss-stored"] = _REFERENCES["xss"]


@register
class StoredXssCheck(_InjectionCheck):
    id = "injection.xss.stored"
    name = "Stored cross-site scripting"
    kind = "xss-stored"
    default_severity = Severity.HIGH
    cwe = (79, 20)
    references = _REFERENCES["xss-stored"]
```

`_InjectionCheck.run` is reused **verbatim** — it already filters
`ctx.observations.injection_hits` by `kind` and builds a `Finding` with
`Location(url=hit.url, method=hit.method, param=hit.param)` and the hit's evidence.

### Orchestrator wiring — ADR-1

```python
from webvigil.checks.injection.stored import StoredXssScanner

_STORED_CHECK_ID = "injection.xss.stored"

async def run(self, raw_target: str) -> ScanResult:
    ...
        injection_hits = await self._inject(check_types, http, target, pages, forms, warnings)
        stored_hits = await self._inject_stored(check_types, http, target, pages, forms, warnings)
        context = ScanContext(..., observations=Observations(
            detections=detections, probe_hits=probe_hits,
            injection_hits=injection_hits + stored_hits,
        ))
    ...

async def _inject_stored(self, check_types, http, target, pages, forms, warnings) -> tuple[InjectionHit, ...]:
    if self._config.scan.mode is not ScanMode.ACTIVE:
        return ()
    if not self._config.injection.stored_xss:
        return ()
    if not any(c.id == _STORED_CHECK_ID for c in check_types):
        return ()
    try:
        report = await StoredXssScanner(http, target, self._config, pages, forms).run()
    except Exception as exc:                    # a stored-pass bug must not abort the scan
        warnings.append(f"stored-XSS pass failed: {exc or type(exc).__name__}")
        return ()
    warnings.extend(report.warnings)
    return tuple(report.hits)
```

`_STORED_CHECK_ID` is deliberately **not** added to `engine.KIND_BY_CHECK_ID` — that map
drives 006's reflected-detector selection; the stored pass is independent (ADR-1).

The `--stored-xss`-without-`--mode active` warning (RF-01) is emitted in `_select_checks`
(or `run`): if `self._config.injection.stored_xss and self._config.scan.mode is not ACTIVE`,
append `"stored-XSS testing requires --mode active — the stored pass did not run"`.

### CLI — RF-10

```python
# scan(...)
stored_xss: Annotated[bool | None, typer.Option(
    "--stored-xss/--no-stored-xss",
    help="Test for stored/persistent XSS during an Active scan. Submits marker payloads "
         "that the target will store, then re-crawls. Off by default.",
)] = None
```

`_build_config` gains `stored_xss: bool | None`; when not `None` it goes into
`injection_overrides` alongside `time_based_sqli` and is passed to `with_overrides`.
`list-checks` shows the new id automatically. `_render` is **unchanged** — the existing
`"Active injection: N finding(s)"` line already matches `injection.xss.stored` (ADR-7).

## Data model

| Type | Module | Crosses a boundary? |
|---|---|---|
| `StoredMarker` | `checks.injection.models` | No — internal to the stored pass. |
| `StoredXssReport` | `checks.injection.models` | No — returned to `_inject_stored`, unpacked there. |
| `InjectionHit` (`kind="xss-stored"`) | `checks.injection.models` | Yes — onto `ctx.observations.injection_hits` (already `TYPE_CHECKING`-imported in `context.py`) and into `checks.py` at runtime. **No `context.py` change.** |

`ScanResult` is **unchanged** (ADR-7). New `injection.xss.stored` findings; cap warnings in
`warnings`.

## Interfaces

### Check id — RF-07, RF-10

| id | kind | category | mode | default severity | confidence | cwe |
|---|---|---|---|---|---|---|
| `injection.xss.stored` | `xss-stored` | INJECTION | active | HIGH | HIGH / MEDIUM | 79, 20 |

Gated by `--mode active --authorized-by` **and** `--stored-xss` / `[injection] stored_xss`.

### Config — RF-10, ADR-4

| Key | Type | Default | Meaning |
|---|---|---|---|
| `[injection] stored_xss` | bool | `false` | Run the two-phase stored-XSS pass. Writes marker rows the target keeps. `--stored-xss` / `--no-stored-xss` overrides. |

### Internal constants (documented)

| Constant | Value | Meaning |
|---|---|---|
| `STORED_TOKEN_BYTES` | `6` | `secrets.token_hex` length for the per-point marker token. |
| `_STORED_REFETCH_CAP` | `60` (design; validated in impl) | Max pages the Phase B re-crawl fetches. Excess → warning. |
| `_PER_POINT_REQUEST_CAP` | `30` (from 006) | Also bounds Phase A marker submissions per point. |

## ADRs

### ADR-1 — A separate `StoredXssScanner` pass, after `_inject`; the check is a hit-filter

**Decision.** The stored pass is its own module (`stored.py`) and its own orchestrator
method (`_inject_stored`), run **after** `_inject`. `injection.xss.stored` reuses
`_InjectionCheck` and just filters `kind == "xss-stored"`.

**Alternatives.** (a) A `stored()` phase inside `InjectionScanner`. (b) The check itself
drives the two phases.

**Why.** Phase B needs a `Crawler`; `InjectionScanner` holds only an `HttpClient` and would
have to grow a crawl dependency it otherwise never needs (Resolved-during-requirements 5).
A separate pass keeps the reflected engine untouched and the new statefulness isolated. (b)
is the same mistake 006 ADR-1 rejected — the budget and the marker map need a single owner,
not six concurrent checks.

**Trade-off.** Two orchestrator injection methods instead of one; `_inject_stored` repeats
the `mode is ACTIVE` / selected-check guard shape. Acceptable — it mirrors
`_probe_disclosure` / `_inject`.

### ADR-2 — Phase B is a depth-1 re-crawl from the known frontier, not a second `discover()`

**Decision.** `Crawler.recrawl(frontier, …)` re-fetches every URL the first crawl
discovered, then follows **one hop** of new in-scope links, capped at `_STORED_REFETCH_CAP`
and `max_pages`.

**Alternatives.** (a) A verbatim second `Crawler(...).discover()` from the seed. (b)
Re-fetch only the first-crawl page set, no new links.

**Why.** (Resolved-during-requirements 6.) (a) re-pays the full BFS cost and re-parses
robots/sitemap for pages already known; (b) misses the marker that surfaces on a URL the
injection *created* (`/guestbook/e/7`). Depth-1 from the frontier catches the common
"posting a comment adds a link to it" case at roughly `frontier + new links` fetches, and
reuses every existing scope / logout / destructive-skip rule (RF-02).

**Trade-off.** A marker rendered two or more hops beyond a pre-existing page is missed —
documented as a limit (RF-08). Deeper re-crawl is a future knob.

### ADR-3 — Extract `build_request` to `points.py`

`engine._build_request` moves to `points.build_request` unchanged; `engine.py` and
`stored.py` both import it. A pure de-duplication so Phase A builds GET/POST marker requests
exactly as the reflected engine does (kept-query POST forms, `dict` bodies for httpx). One
test moves modules.

### ADR-4 — `stored_xss` on `InjectionSection`, default `False`

Not a new `[stored]` section — the knob is injection tuning and belongs beside
`time_based_sqli` (006 ADR-4's reasoning). Default `False` because the pass writes
persistent data (Resolved-during-requirements 2); `--stored-xss` is the only new CLI flag,
matching `--time-based-sqli`'s pattern exactly.

### ADR-5 — `<wvstored{token}>` markers; two per point; `kind="xss-stored"` reuses `InjectionHit`

**Decision.** A bare distinctive tag plus one attribute-breaker, each carrying a per-point
`secrets.token_hex`. No `alert(`, no script, no network reference.

**Why.** The detector's whole question is "did our markup render as an *element*" — a bare
custom tag answers it unambiguously (`<wvstored…>` present verbatim = rendered as HTML;
`&lt;wvstored…&gt;` = safely escaped). Keeping the payload inert and clearly
WebVigil-branded minimises what 008 leaves in the target's database (RNF-06). Reusing
`InjectionHit` (not a new hit type) means `context.py` and the reporters need **zero**
change.

**Trade-off.** A sink that stores the value but strips unknown tags while keeping
`<script>` would be missed. Rare; a `<script>`-context marker can be added later if real
targets need it.

### ADR-6 — `StoredXssScanner` owns one `ActiveBudget` sized from `request_budget`; `take_recrawl()` for Phase B

**Decision.** The stored pass builds its **own** `ActiveBudget(request_limit=request_budget,
…)` covering Phase A submissions (`take()`, per-point-capped) and Phase B fetches
(`take_recrawl()`, per-scan-limit only). `_STORED_REFETCH_CAP` separately bounds Phase B
page count.

**Alternatives.** Thread the *same* `ActiveBudget` instance through `_inject` and
`_inject_stored` so the reflected and stored passes share one counter.

**Why.** RF-06 requires Phase A and Phase B to share a budget *with each other* and to be
sized by the `request_budget` knob — both satisfied by one `ActiveBudget` inside the pass.
Sharing the *counter* with the reflected pass would mean refactoring `InjectionScanner` to
accept an injected budget (it currently constructs its own) and carefully ordering two
orchestrator methods around a mutable object — cost without a real benefit, since the two
passes run sequentially and the fixture's reflected pass spends ~90/500. `take_recrawl`
exists because `take()` also enforces `per_point_limit`, which would (wrongly) stop the
re-crawl after 30 pages.

**Trade-off.** In the extreme, a scan could spend up to `request_budget` on the reflected
pass *and* up to `request_budget` on the stored pass. Both are bounded and warned; the
combined worst case is documented.

### ADR-7 — No `ScanResult` field; `_render` unchanged

006 ADR-7 again. `injection.xss.stored` findings are counted by the existing
`sum(f.check_id.startswith("injection."))` line. The re-crawl page count and marker count
do **not** enter `ScanResult` — only the RF-06 cap warnings ride `ScanResult.warnings`.
RF-10's parenthetical "Stored XSS: re-crawled P page(s)" summary line is **dropped** for
this reason (it would need a `ScanResult` field); the existing injection-findings line and
the cap warnings cover it.

### ADR-8 — Fixture guestbook: a per-entry page reachable only after a post; state on `app.state`

**Decision.** The insecure profile serves `POST /guestbook` (append `body` to
`app.state.guestbook`, `302 → /guestbook`), `GET /guestbook` (render every entry
**unescaped**, each linking `/guestbook/e/<i>`), and `GET /guestbook/e/<i>` (render entry
`i` unescaped). The home page links `/guestbook`. The hardened profile `html.escape`s on
both render paths.

**Why.** `/guestbook` is in the first crawl (linked from home), so it exercises the
re-fetch half. `/guestbook/e/<i>` is linked **only** from the rendered list, so it is
discoverable **only** by the Phase B one-hop re-crawl **after** a marker has been posted —
this is the case that justifies ADR-2 over "re-fetch the known set only", and RF-14 asserts
the finding's render location is the per-entry page. State lives on `app.state` (like
`app.state.requests`) so every `make_app()` starts clean and the suite is deterministic.

**Trade-off.** One more stateful handler in the fixture. `sqlite3` already set a precedent
(006 ADR-10); an in-memory list is lighter.

### ADR-9 — The finding's `Location.url` is the injection point, not the render page

**Decision.** `InjectionHit.url = marker.point.base_url` (+ `method`, `param`). The render
location(s) go in `evidence` ("Rendered on: …  (+N more page(s))").

**Why.** `compute_fingerprint` hashes `check_id + location.url + location.key + dedup_key`
(`findings.py:98`). A stored marker often renders on a URL whose id varies between runs
(`/guestbook/e/7` → `/guestbook/e/8` after re-runs accumulate rows). Keying the finding on
the **stable** injection point (RF-09) keeps the fingerprint constant across runs and
collapses a multi-page render to one finding. The remediation is at the output-encoding
boundary anyway, which the injection point + "rendered on" evidence pin down precisely.

**Trade-off.** A SARIF/HTML reader sees the *input* location as the primary; the render
page is one line down in the evidence. The `title` names both, so nothing is lost.

## Impact

| Area | Change |
|---|---|
| `webvigil.core.config` | `InjectionSection.stored_xss: bool = False` (one line). |
| `webvigil.core.orchestrator` | `_inject_stored()` + the `stored_hits` merge + the "requires --mode active" warning (~25 lines, parallels `_inject`). |
| `webvigil.core.context` | **none** — `InjectionHit` already imported `TYPE_CHECKING`. |
| `webvigil.checks.injection` | new `stored.py` (~140 lines); `payloads.py` +2 constants; `points.py` gains `build_request` (moved); `models.py` +2 dataclasses +1 `ActiveBudget` method; `checks.py` +1 registered check +3 dict entries; `engine.py` one import line. |
| `webvigil.crawler.crawler` | `recrawl()` (~25 lines); `discover()` unchanged. |
| `webvigil.cli` | one `scan` option; `_build_config` threads it; `_render` unchanged. |
| Reporters JSON/SARIF/HTML/MD | **none** (006's `logicalLocations` already covers `location.param`). |
| `webvigil.api`, `web/` | **none** (RF-12). |
| Alembic / `openapi.json` / `api-types.ts` | **none**. |
| deps | **none**. `import-linter` contract unchanged. |
| Docker | **none** (the target image already packages the insecure profile). |
| Fixture app | guestbook endpoints (insecure) + escaped equivalents (hardened) + `app.state.guestbook`. |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Marker rows pollute a shared/staging DB and are never cleaned up | High (by design) | Default-off opt-in; distinctive `wvstored…` string; the docs state plainly they persist and WebVigil does not remove them (RNF-06). |
| A marker with `<`/`>` trips a downstream WAF/log alarm on the target | Medium | Payload is inert (no `script`, no handler, no URL); bounded; documented. |
| Re-crawl misses a marker rendered >1 hop past a known page | Medium | Documented limit (ADR-2); frontier-seeded depth-1 catches the common case; deeper re-crawl is a future knob. |
| Per-entry render URL varies between runs → fingerprint churn | Medium | `Location.url` = injection point, not render page (ADR-9); asserted in RF-14/RF-15. |
| Stored pass doubles the worst-case request count of an Active scan | Low | Own `ActiveBudget` sized from `request_budget`; `_STORED_REFETCH_CAP`; `max_pages`; every cap warns. Combined worst case documented (ADR-6). |
| False positive: the re-crawl's own GET of a search form echoes the marker | Low | Render-location ≠ injection point (unless POSTed); pre-injection-baseline check; only `<wvstored…>` verbatim in an executable context counts (RF-08). |
| `recrawl` regresses `discover()` by sharing helpers | Low | `recrawl` is additive; `discover()` untouched; the full `test_crawler.py` suite runs unchanged plus new `recrawl` cases. |
| A stored pass exception aborts the scan | Low | `_inject_stored` wraps `run()` in `try/except` → a scan warning, like 006's `_inject`. |

## Testing — RNF-02, RNF-05

### Unit

| File | Covers |
|---|---|
| `tests/unit/test_injection_points.py` (additions) | `build_request` still builds GET pair-lists / POST dict bodies + kept query (moved test). |
| `tests/unit/test_injection_stored.py` (new) | Phase A: form points before query points; `_EXCLUDE_FORM_RE` form → no marker; hidden/CSRF field values preserved in the submitted body; `token → StoredMarker` map; `_PER_POINT_REQUEST_CAP` / `request_budget` gating. Detection: `<wvstored…>` verbatim in body / attribute context → hit; `&lt;wvstored…&gt;` / `text/plain` / HTML-comment → no hit; marker only in the Phase A POST response → no hit; marker in a known page's pre-injection body → no hit; marker on a new URL → hit; multi-page render → one hit + `(+N more)` evidence; hit `url` == injection point (not render page); confidence HIGH vs MEDIUM. |
| `tests/unit/test_crawler.py` (additions) | `recrawl`: re-fetches every frontier URL; follows one hop of a *new* link; does **not** follow a second hop; `should_fetch()` returning False stops it; `max_fetches` caps it; a `/logout` / destructive new link is skipped; `is_auth_form` GET form still not submitted. |
| `tests/unit/test_injection_models.py` (additions) | `ActiveBudget.take_recrawl` decrements `spent`, ignores `per_point_limit`, refuses past `request_limit`. |
| `tests/unit/test_config.py` (additions) | `[injection] stored_xss` round-trips, defaults `False`; `--stored-xss` override beats the file; unknown `[injection]` key still rejected. |
| `tests/unit/test_cli.py` (additions) | `--stored-xss` sets `config.injection.stored_xss = True`; `--no-stored-xss` sets it `False`; `list-checks` shows `injection.xss.stored | INJECTION | active | HIGH`. |
| `tests/unit/test_injection_orchestrator.py` (additions) | `_inject_stored` returns `()` on passive / when `stored_xss` is False / when the check is disabled; wires `stored_hits` onto the context (merged with `injection_hits`); a raising `StoredXssScanner` → scan warning, not a crash; `stored_xss=True` + `--mode passive` → the "requires --mode active" warning. |
| `tests/unit/test_checks_injection.py` (additions) | `StoredXssCheck` turns an `xss-stored` hit into a `HIGH` finding with `location = injection point`, evidence carrying the render location; `[]` when no hit; `list-checks` metadata. |

### Integration — `tests/integration/test_scan_fixture_app.py`

- `test_stored_xss_found_on_the_insecure_guestbook` — Active scan, `stored_xss=True`; assert
  `injection.xss.stored` with `location.param == "body"`, `location.method == "POST"`,
  evidence "Rendered on" naming a `/guestbook…` URL ≠ the injection point.
- `test_stored_xss_render_location_is_the_per_entry_page` — assert the "Rendered on"
  evidence points at `/guestbook/e/<id>` — proving the one-hop re-crawl found a page absent
  from the first crawl.
- `test_stored_xss_not_run_without_the_opt_in` — Active scan, `stored_xss=False`; no
  `injection.xss.stored` finding; the fixture request log shows **no** `POST /guestbook`
  with a `wvstored` body and no second pass over `/guestbook`.
- `test_stored_xss_passive_scan_does_nothing` — passive scan; same assertions.
- `test_hardened_profile_reports_no_stored_xss` — extend the hardened loop with
  `stored_xss=True`; still **zero** `INJECTION` findings.
- `test_authenticated_stored_xss_and_cookie_privacy` — `--cookie` + `stored_xss=True`; a
  marker posted to an `/account`-area form is found on re-crawl; `abc123` appears in no
  report.
- `test_stored_xss_scan_is_deterministic` — two runs; identical findings + fingerprints
  though the guestbook has more rows the second time.

The `scan` fixture's `_run` gains `stored_xss: bool = False` (threaded into the
`ScanConfig` `injection` section).

### Fixture app — RF-13 / ADR-8

Insecure profile adds:
- `_FORMS` (and `_INSECURE_PAGE`) gain `<form method="post" action="/guestbook"><textarea
  name="body"></textarea></form>`; `_LINKS` (or `_INJECTION_LINKS`) gains
  `<a href="/guestbook">guestbook</a>`.
- `POST /guestbook` — `app.state.guestbook.append(body); RedirectResponse("/guestbook", 302)`.
- `GET /guestbook` — `"".join(f'<p><a href="/guestbook/e/{i}">entry {i}</a>: {e}</p>' for i,
  e in enumerate(app.state.guestbook))` in an HTML body (**unescaped `e`**).
- `GET /guestbook/e/{i}` — `HTMLResponse(f"<!doctype html><div>{app.state.guestbook[i]}</div>")`
  (**unescaped**); `404` for a bad index.

Hardened profile: both render paths wrap the entry in `html.escape(...)`. `make_app` sets
`app.state.guestbook = []`.

### Docker target

No change — `tests/fixtures/serve.py` already exposes `make_app("insecure")`; the guestbook
routes come with it.

## Resolved during design

1. **Separate `StoredXssScanner` pass** (ADR-1), after `_inject`, not a phase inside
   `InjectionScanner` — Phase B's `Crawler` dependency stays out of the reflected engine.
2. **Depth-1 re-crawl from the frontier** via `Crawler.recrawl` (ADR-2) — faithful to
   "full coverage from the seed" (Resolved-during-requirements 6) without a second full
   `discover()`.
3. **`build_request` extracted to `points.py`** (ADR-3) — shared by both passes.
4. **`stored_xss` on `InjectionSection`, default `False`** (ADR-4); `--stored-xss` the only
   new flag.
5. **`<wvstored{token}>` markers, two per point, `InjectionHit` reused** (ADR-5) — no
   `context.py` or reporter change.
6. **The stored pass owns its `ActiveBudget`** sized from `request_budget`, with
   `take_recrawl()` for Phase B (ADR-6) — not a counter shared with the reflected pass.
7. **`Location.url` = the injection point, render location in evidence** (ADR-9) — stable
   fingerprint across runs and across a multi-page render.
8. **No `ScanResult` field; `_render` unchanged; RF-10's re-crawl-count line dropped**
   (ADR-7) — the existing injection line + cap warnings cover it. *Flagged for the approval
   gate: this is a small deviation from RF-10 as written.*
9. **`_STORED_REFETCH_CAP = 60`** as the design value (Resolved-during-requirements 7);
   implementation validates it against the fixture's real page count and may adjust with a
   note here.

## Open questions

None. Ready for `/spec tasks`.

## Implementation notes

Landed 2026-09-07, on the design as written.

- **`_STORED_REFETCH_CAP = 60` kept.** The fixture's insecure profile has ~11 first-crawl
  pages; after the 006 reflected pass fuzzes the guestbook form (~30 marker rows), the
  Phase B re-crawl fetches ~11 frontier + ~32 `/guestbook/e/<n>` pages — well under 60 and
  under the default `max_pages = 50` clamp. No cap warning fires in the integration tests.
- **`recrawl` one-hop is a two-list drain, no depth tuple.** Frontier URLs are fetched
  first (and their links + safe GET forms enqueued), then the link queue is drained once
  with no further expansion. `_enqueue_links` / `_collect_and_enqueue_forms` /
  `_maybe_enqueue` are reused unchanged (they still take a `deque[str]`).
- **`_stored_hit` uses `xss._context` / `xss._snippet` from the 006 detector.** Kept
  private (same package); no public rename.
- **The 006 reflected pass runs first and pollutes the sink.** `_inject` fuzzes the same
  POST forms before `_inject_stored`, so the stored marker usually lands at a high entry
  index (`/guestbook/e/30` in manual runs). Harmless — `_detect` matches the `wvstored`
  token, not position, and the finding fingerprints on the injection point. Integration
  tests assert `/guestbook/e/\d+`, not a fixed index.
- **Fixture auth gate relaxed to "any non-empty session cookie".** `_account` /
  `_account_settings` previously required the literal `abc123`; now any value logs in, so a
  distinctive cookie (`UNIQ008SECRET`) can prove both that the authenticated re-crawl
  reaches the behind-login `/profile` → `/account/settings` stored sink **and** that the
  value never reaches a report. Existing spec-007 tests (which pass `session=abc123`) are
  unaffected.
- **`--stored-xss` without `--mode active`** emits `"stored-XSS testing requires --mode
  active — the stored pass did not run"` and exits normally.
- **Web API / UI: zero change confirmed.** `injection.xss.stored` is an ordinary
  `INJECTION` `Finding`; no migration, no `openapi.json` / `api-types.ts` regen, no
  component change (as 006 established). `_render` unchanged — the existing
  `"Active injection: N finding(s)"` line counts stored findings (ADR-7); RF-10's
  re-crawl-count line was dropped.
- **Crawl-count delta:** the hardened anonymous crawl reaches one more page (`/guestbook`),
  9 → 10 in `test_crawler_reaches_the_linked_pages`.
- **pytest:** 501 (spec 007 close) → 536 (+35). `mypy` 95 source files (`stored.py` added).
  `lint-imports` 2 contracts kept. No `web/` change, no Alembic migration.

### Manual verification

`uvicorn tests.fixtures.serve:app` on `:9318`:

- `--mode active --authorized-by impl-check --stored-xss` → `injection.xss.stored` on
  `POST /guestbook` (`body`), rendered on `/guestbook/e/30 (+1 more page(s))`.
- same scan **without** `--stored-xss` → 0 stored findings.
- `--stored-xss --cookie "session=UNIQ008SECRET"` → also `injection.xss.stored` on
  `POST /profile` (`nickname`) rendered on `/account/settings`; the cookie value appears
  nowhere in the JSON report.
- `webvigil list-checks` → `injection.xss.stored | INJECTION | active | HIGH`.
