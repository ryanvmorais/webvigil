---
feature: In-band expression-language injection — SpEL, OGNL, JEXL, MVEL, Unified EL (Active Mode)
status: done
date: 2026-10-06
related:
  - 016-el-injection/requirements.md
  - 011-rce-injection/design.md
  - 009-ssrf/design.md
origin: conception
---

# 016 — In-band expression-language injection — design

## Overview

016 adds one check, `injection.el`, and no new orchestrator pass. The work is a new
detector module, `detect/el.py`, that runs inside the existing `InjectionScanner` pass and
proves evaluation the way 011's `ssti` detector does: a per-request marker glued to the
computed product of two random operands, absent from the baseline.

The one structural problem is RF-05: a point must not be probed twice for the same thing.
`ssti` and `el` overlap on the ambiguous delimiter forms (`${…}`, `#{…}`, `*{…}`) and on the
shared polyglot probe, and each detector draws its own random marker and operands, so two
independent detectors cannot share a response. The design therefore runs **one combined
routine** when both checks are selected (ADR-1), and keeps `ssti` byte-for-byte untouched
when only `injection.ssti` is selected.

```
selected checks              detector entry the scanner runs
injection.ssti only     →    "ssti"      ssti.detect            (unchanged)
injection.el only       →    "el"        el.detect_el           (EL forms only)
both (the default)      →    "ssti+el"   el.detect_combined     (one pass, two hit kinds)
```

The combined routine is a four-step ladder, cheapest first:

1. **Polyglot probe** (shared with `ssti` stage 1): one request; names a template engine
   (`ssti`) or an EL dialect (`el`) from an error signature.
2. **Arithmetic loop** over the delimiter forms, then the bare-expression forms. A hit gives
   the *form* that evaluated.
3. **Classification** of that hit (ADR-2): pure type-access probes name SpEL / OGNL and
   upgrade to CRITICAL; otherwise the evidence decides between `injection.el` (HIGH) and the
   unchanged `injection.ssti`.
4. **Signature-only fallback** when nothing evaluated but an EL error signature appeared:
   an `el` hit at MEDIUM confidence.

## Module layout

```
src/webvigil/checks/injection/
├── payloads.py      + EL_DELIMITERS, EL_AMBIGUOUS_HINTS, EL_BARE_*, EL_*_PROBE,
│                      EL_UNTERMINATED, EL_ERROR_SIGNATURES
├── points.py        + is_exprlike(point)
├── detect/
│   ├── ssti.py      helpers promoted to public (behaviour unchanged): engine_from_error,
│   │                engine_first, identify_engine, build_hit
│   └── el.py        NEW — detect_el, detect_combined, and their shared _run
├── engine.py        + "el" / "ssti+el" in _DETECTORS, "el" in _BASE_ORDER and
│                      KIND_BY_CHECK_ID, the merge step in _ordered_kinds
└── checks.py        + _DESCRIPTION["el"], _REMEDIATION["el"], _REFERENCES["el"],
                       ExpressionLanguageInjectionCheck

tests/fixtures/app.py                 + three simulated EL sinks (insecure) and their
                                        hardened twins, and a stdlib arithmetic evaluator
tests/unit/test_injection_el.py       NEW
tests/unit/test_fixture_el.py         NEW — the fixture evaluator itself
```

No change to `webvigil.core`, `webvigil.cli`, `webvigil.api`, `web/`, the reporters or the
config model (RF-13, resolved decision 2).

## Data model

No new type. `InjectionHit` already carries everything: `kind = "el"`,
`check_id = "injection.el"`, `severity`, `confidence`, `title`, `payload`, `evidence`.

Internal to `detect/el.py`, two frozen dataclasses:

```python
@dataclass(frozen=True, slots=True)
class _Form:
    """One way to wrap an expression so the evaluator might run it."""
    label: str                          # "dollar" | "hash" | "star" | "percent" | "bare" |
                                        # "bare-escape" | the arith_payloads hint (templates)
    category: Literal["template", "ambiguous", "ognl", "bare"]
    wrap: Callable[[InjectionPoint, str, str], str]
    # wrap(point, marker, inner) -> the full value to send, where ``inner`` is the
    # expression text ("6*7", "T(java.lang.Math).abs(-413)", ...)

@dataclass(frozen=True, slots=True)
class _Verdict:
    """What the evidence says about the evaluator."""
    dialect: str                         # "SpEL" | "OGNL" | "JEXL" | "MVEL" | "Unified EL" |
                                         # "unknown"
    type_access: bool                    # a pure static call evaluated
    source: str                          # "type-access probe" | "syntax" | "error signature"
```

`_Form.wrap` is the single seam: the arithmetic stage calls it with `inner = f"{a}*{b}"`, the
identification stage calls it with the type-access expression. Both use the same delimiter,
so a probe is always sent in exactly the form that already evaluated.

## Components

### Payload sets (`payloads.py`)

```python
# (label, open, close) — the EL delimiters. ``${``/``#{``/``*{`` are ambiguous with
# template engines; ``%{`` is OGNL's.
EL_DELIMITERS = (("dollar", "${", "}"), ("hash", "#{", "}"),
                 ("star", "*{", "}"), ("percent", "%{", "}"))

# arith_payloads hints whose delimiter is also an EL delimiter. The combined routine sends
# these once, through EL_DELIMITERS, instead of twice.
EL_AMBIGUOUS_HINTS = frozenset({"Freemarker/EL", "Slim/Pug", "Thymeleaf"})

EL_BARE_WHOLE = "'{marker}'+({inner})"          # the whole value is the expression
EL_BARE_ESCAPE = "'+'{marker}'+({inner})+'"     # appended inside a string literal
EL_SPEL_PROBE = "T(java.lang.Math).abs(-{n})"
EL_OGNL_PROBE = "@java.lang.Math@abs(-{n})"
EL_UNTERMINATED = ("${(", "%{(")
EL_ERROR_SIGNATURES = (
    ("SpEL", re.compile(r"org\.springframework\.expression|Spel(?:Evaluation|Parse)Exception|\bEL\d{4}E\b")),
    ("OGNL", re.compile(r"ognl\.\w*Exception|MethodFailedException|ExpressionSyntaxException")),
    ("JEXL", re.compile(r"org\.apache\.commons\.jexl\d?|JexlException")),
    ("MVEL", re.compile(r"org\.mvel2")),
    ("Unified EL", re.compile(r"(?:javax|jakarta)\.el\.\w*Exception|org\.apache\.el\.|\bELException\b")),
)
```

A unit test guards that every hint in `EL_AMBIGUOUS_HINTS` exists in the output of
`arith_payloads`, so a rename in 011's table cannot silently double the requests.

### `is_exprlike` (`points.py`)

Name set from RF-06 (`expr`, `expression`, `filter`, `sort`, `order`, `where`, `condition`,
`rule`, `formula`, `msg`, `message`, `title`, `el`, `spel`, `ognl`, `eval`, `q`, `query`,
`search`) plus a value shape: the current value already contains `#{`, `${`, `%{` or `T(`.
Same signature and docstring shape as `is_commandlike`.

### Form tables (`el.py`)

`_forms(marker, templates, full)` returns the ordered `_Form` list:

| Mode | Full set (point is `is_commandlike` or `is_exprlike`) | Canary (any other point) |
|---|---|---|
| combined | template-only forms from `arith_payloads` (not in `EL_AMBIGUOUS_HINTS`), then `${` `#{` `*{` `%{` via `EL_DELIMITERS`, then `bare`, `bare-escape` | the first four `arith_payloads` forms, then `#{`, `%{`, `bare` |
| el only | `${` `#{` `*{` `%{`, `bare`, `bare-escape` | `${` `#{` `%{`, `bare` |

The combined canary keeps the four forms `ssti` sends today, so a point `ssti` would have
caught is still caught, and adds exactly three requests (RNF-04).

### The routine (`_run`)

```python
async def _run(point, baseline, ctx, *, templates: bool) -> list[InjectionHit]:
    full = is_commandlike(point) or is_exprlike(point)

    # 1. Shared polyglot probe.
    probe = await ctx.send(point, point.original + payloads.SSTI_POLYGLOT)
    if probe is None:
        return []
    engine = ssti.engine_from_error(probe.text, baseline.raw_body) if templates else None
    el_dialect = _dialect_from_error(probe.text, baseline.raw_body)

    # 2. Arithmetic loop (marker + operands drawn once, as ssti does).
    marker, a, b = ...
    needle = f"{marker}{a * b}"
    for form in _forms(marker, templates=templates, full=full, engine=engine):
        response = await ctx.send(point, form.wrap(point, marker, f"{a}*{b}"))
        if response is None:
            return []
        if needle in response.text and needle not in baseline.raw_body:
            return await _classify(point, baseline, ctx, form, marker, (a, b), engine, el_dialect)

    # 3. Nothing evaluated: look for a signature from an unterminated expression.
    if full and el_dialect is None:
        el_dialect = await _unterminated_probe(point, baseline, ctx)
    return [_signature_hit(point, el_dialect)] if el_dialect else []
```

### Classification (`_classify`, ADR-2)

By the form that evaluated:

| Form category | Evidence | Result |
|---|---|---|
| `template` | — | `ssti` hit, exactly as `ssti.detect` builds it (`engine`, `identify_engine`) |
| `ognl` (`%{}`) | the syntax | dialect OGNL; send the OGNL type probe → CRITICAL if it evaluates, else HIGH |
| `bare`, `bare-escape` | the form is itself an expression | send SpEL then OGNL probes; dialect from the winning probe, else from `el_dialect`, else `unknown`; CRITICAL only on a winning probe, else HIGH |
| `ambiguous` | needs corroboration | send SpEL then OGNL probes (skip OGNL when `el_dialect` is SpEL, and vice versa); a winning probe → `el` CRITICAL; else `el_dialect` known → `el` HIGH; else `ssti` hit, as today (only when `templates`; in el-only mode, no hit) |

A type probe is sent through `form.wrap(point, marker, probe_expr)` with a fresh three-digit
`n` and succeeds when `f"{marker}{n}"` is in the response and not in the baseline. A probe
response that carries an EL signature absent from the baseline names the dialect even though
the probe did not evaluate (a sandboxed `SimpleEvaluationContext` rejecting `T(...)` says so
in its own words): that yields an `el` hit at HIGH.

Severity and confidence, final:

| Proof | Dialect | Severity | Confidence |
|---|---|---|---|
| type-access probe evaluated | SpEL / OGNL | CRITICAL | HIGH |
| `%{}` arithmetic, probe not evaluated | OGNL | HIGH | HIGH |
| ambiguous / bare arithmetic + EL signature (stage 1 or probe error) | per signature | HIGH | HIGH |
| bare arithmetic, no further evidence | unknown | HIGH | HIGH |
| EL signature only, nothing evaluated | per signature | HIGH | MEDIUM |

### Engine wiring (`engine.py`)

- `_DETECTORS` gains `"el": el_detect.detect_el` and `"ssti+el": el_detect.detect_combined`.
- `_BASE_ORDER` gains `"el"` right after `"ssti"`.
- `KIND_BY_CHECK_ID["injection.el"] = "el"` (one-to-one, unlike SSRF: the detector entry is
  chosen by the merge below, not by the check map).
- `_ordered_kinds` front-loads `(is_exprlike, "el")` next to the existing predicates, then
  runs `_merge_el(kinds)`: when both `"ssti"` and `"el"` are present, replace the earlier of
  the two with `"ssti+el"` and drop the other. The result is the list of detector-table keys.

```python
def _merge_el(kinds: list[str]) -> list[str]:
    """Collapse ssti + el into the one combined detector entry (spec 016, ADR-1)."""
    if "ssti" not in kinds or "el" not in kinds:
        return kinds
    at = min(kinds.index("ssti"), kinds.index("el"))  # nothing before ``at`` is either kind
    rest = [k for k in kinds if k not in ("ssti", "el")]
    rest.insert(at, "ssti+el")
    return rest
```

### The check (`checks.py`)

```python
@register
class ExpressionLanguageInjectionCheck(_InjectionCheck):
    """Expression-language injection from the combined ssti / EL detector (spec 016)."""

    id = "injection.el"
    name = "Expression-language injection"
    kind = "el"
    default_severity = Severity.HIGH
    cwe = (917, 94)
    references = _REFERENCES["el"]
```

`_DESCRIPTION["el"]`: the parameter reaches an expression evaluator and an expression
supplied in it was evaluated; with the dialect named in the title. `_REMEDIATION["el"]`:
never evaluate request-derived text as an expression; for Spring use
`SimpleEvaluationContext` (read-only data binding, no `T()`), for Struts keep
`allowStaticMethodAccess` off and upgrade, and treat any parameter reaching `parseExpression`
as code. `_REFERENCES["el"]`: the OWASP Expression Language Injection page, the CWE-917
entry and the Spring SpEL evaluation reference (URLs verified when written, in the
implementation stage).

Hit titles: `Expression-language injection (SpEL) via the 'filter' parameter`, or
`... (expression language, dialect unknown) via ...`. Evidence pairs: `Injection point`,
`Payload`, `Evaluated expression` (`<needle>  (= a * b)`), `Type access` (the probe and its
result, when it ran), `Dialect` (`SpEL — type-access probe` / `OGNL — %{} syntax` /
`JEXL — error signature`), `Error signature` (the matched excerpt, when it contributed).

## Interfaces

No URL, no config key, no CLI flag, no new JSON field (resolved decision 2, RF-13). The
canonical JSON gains findings with `check_id = "injection.el"` and `cwe = [917, 94]`,
already representable. `webvigil list-checks` lists the new id through the registry.

## ADRs

### ADR-1 — One combined detector when both checks are selected

**Decision.** `ssti` and `el` are separate kinds with separate gating, but when both are
selected the scanner runs a single `ssti+el` routine that emits both hit kinds. `ssti`
alone runs the existing, unmodified `ssti.detect`.
**Alternatives.** (a) Two independent detectors; dedupe findings afterwards. (b) A shared
per-point scratchpad on `DetectCtx` that `ssti` writes and `el` reads. (c) Extend
`ssti.detect` in place with flags on `DetectCtx`.
**Why.** (a) sends `${a*b}` and the polyglot twice per point and breaks RF-05's "not sent
twice"; (b) couples two detectors through an untyped dict and an ordering assumption that
silently fails when `ssti` is disabled; (c) edits the one routine RF-05 promises is
unchanged, and puts EL logic in a template module. The combined entry keeps `ssti` alone
provably identical, keeps the EL logic in its own module, and makes the dedup structural:
one proof can only become one hit kind. Precedent: 009 maps two checks onto one detector,
011's `cmdi` runs two stages in one routine.
**Trade-off.** Three entries in the detector table instead of one, a merge step in
`_ordered_kinds`, and a parity obligation: the combined routine's template branch must match
`ssti.detect` (guarded by running the existing `ssti` unit scenarios against both entry
points, RF-12).

### ADR-2 — Classify by evidence, never by the delimiter alone

**Decision.** A delimiter form that evaluates is `injection.el` only when something besides
the arithmetic names an EL dialect (a winning type probe, an EL error signature), or when
the syntax itself is EL-only (`%{}`, the bare string-concatenation form). Otherwise it stays
`injection.ssti`.
**Alternatives.** (a) Treat every `${…}` evaluation as EL. (b) Keep every ambiguous
evaluation as `ssti` and use `el` only for `%{}` and bare forms.
**Why.** `${a*b}` is also Freemarker; labelling it EL would move existing, correct
template findings to the wrong check and break RF-05's "unchanged" guarantee. (b) would make
a SpEL or Unified-EL endpoint reachable only by the two new forms and leave the common
`${}` / `#{}` case reported as "template, engine unknown" — the exact problem the issue
describes.
**Trade-off.** An EL endpoint that evaluates `${}`, rejects both type probes with an
unrecognizable message, and shows no signature stays `injection.ssti`. Acceptable: that is
today's behaviour, not a regression.

### ADR-3 — Type-access probes are pure static calls through the form that already worked

**Decision.** `T(java.lang.Math).abs(-n)` (SpEL) and `@java.lang.Math@abs(-n)` (OGNL), sent
only through the delimiter that just evaluated arithmetic, with a fresh three-digit `n`.
**Alternatives.** (a) `T(java.lang.System).getProperty('java.version')` — richer but reads
the environment. (b) No probe; CRITICAL on any EL hit. (c) A reflection-free syntax-only
fingerprint (SpEL `T(` parses, OGNL `@` parses).
**Why.** `Math.abs` has no side effect, no I/O and no state, and a result glued to a
random marker is unforgeable by reflection; (a) crosses the non-exploitation line in the
requirements; (b) mislabels sandboxed evaluators as RCE; (c) cannot tell "parsed" from
"evaluated", and a parse error response is exactly what the baseline-absent check cannot
prove. The OGNL probe will legitimately fail on modern Struts (static method access off by
default): that hit stays HIGH, which is the accurate severity.
**Trade-off.** At most two extra requests per hit; a payload that names a Java class.

### ADR-4 — `%{}` and the bare form carry their own meaning

**Decision.** An evaluated `%{a*b}` is attributed to OGNL on syntax alone (before any
probe); the bare form `'wv<token>'+(a*b)` is classified as an expression evaluator of
unknown dialect until a probe or signature says otherwise.
**Alternatives.** Require a probe or signature for both.
**Why.** No template engine in the 011 table evaluates `%{}`, and a value that becomes
`wv<token><product>` through string concatenation is, by construction, being evaluated as an
expression. Demanding extra corroboration would drop real Struts hits on hardened static
access.
**Trade-off.** A JavaScript `eval` also satisfies the bare form (resolved decision 6): it is
reported as "expression language (dialect unknown)", and the docs do not claim `eval()`
coverage.

### ADR-5 — The fixture simulates the sink with an `ast` walker

**Decision.** The three insecure routes evaluate nothing through Python's `eval`. A small
walker over `ast.parse(expr, mode="eval")` accepts integer and string constants, unary
minus, `+ - * //`, and one allow-listed call; `+` with a string operand concatenates
(SpEL / OGNL / JEXL semantics). Dialect syntax is normalised first: `T(java.lang.Math).abs(x)`
and `@java.lang.Math@abs(x)` become the allow-listed `abs(x)`, only when that route allows
static calls.
**Alternatives.** (a) Embed a JVM or a Java expression library; (b) Python `eval` with a
restricted namespace; (c) mock at the HTTP layer in unit tests only.
**Why.** A JVM is not a dependency of a Python tool (RNF-01); `eval` in a test fixture is
the thing the check exists to flag, and a restricted namespace is a known-leaky sandbox; (c)
leaves the integration suite without an EL target.
**Trade-off.** The simulation matches the syntax the detector sends, not every corner of the
real evaluators; the unit tests pin the detector against hand-written stubs per dialect, so
the fixture only has to be a faithful-enough target for the end-to-end path (same posture as
006's `SLEEP(n)` and 011's `/ping`).

## Fixture app

Three insecure routes, each linked from the shared link block in both profiles. The
unspecified exact wording of error bodies is simulation, not a claim about a real server.

| Route | Simulates | Evaluates | Type access | Param (exprlike?) | Expected finding |
|---|---|---|---|---|---|
| `GET /report?filter=1` | Spring `parseExpression(filter)` | bare expression only | allowed | `filter` (yes) | `injection.el`, SpEL, CRITICAL |
| `GET /banner?caption=hello` | Struts tag attribute | `%{…}` in the text | allowed | `caption` (no — canary path) | `injection.el`, OGNL, CRITICAL |
| `GET /rule?cond=ok` | SpEL under `SimpleEvaluationContext` | `#{…}` and bare | rejected with `EL1005E` | `cond` (no) | `injection.el`, SpEL, HIGH |

Errors answer `500` with a body starting `org.springframework.expression.spel.SpelParseException: EL1041E: …`
or `ognl.ParseException: …`. The hardened twins escape and echo the value and never
evaluate it, so an Active scan of the hardened profile fuzzes them and finds nothing. The
baseline for `/report?filter=1` evaluates to `1`, so it carries no signature.

Counts that move: the insecure profile gains three injection points and about 3 × (11 to 14)
requests; the integration test's `request_budget = 1200`, `max_pages = 90` and the
"~13 injection points" comment are re-measured in the implementation stage and changed only
if they are not enough (RNF-04).

## Request budget

| Point type | `ssti` today | combined, no hit | extra |
|---|---|---|---|
| canary (not command/expression-shaped) | 1 + 4 = 5 | 1 + 7 = 8 | **+3** |
| full (command- or expression-shaped) | 1 + 8 = 9 | 1 + 11 + 2 (unterminated) = 14 | +5 |
| on a hit | +1 (engine probe) | +1 or +2 (type probes) | ≤ +1 |

`_PER_POINT_REQUEST_CAP` stays 38 and `request_budget` 650 until the integration suite is
measured; they move only with the measurement recorded in `tasks.md`, as 011 and 014 did.
The shared 38-request ceiling is the risk to watch: `el` sits at `ssti`'s position in
`_BASE_ORDER`, ahead of the slow detectors.

## Impact on existing code

- `detect/ssti.py`: four helpers renamed to public names; no logic change; its own tests
  are the guard.
- `engine.py`: two table entries, one order entry, one predicate, `_merge_el`. `ssti` alone
  takes the same code path it takes today.
- `tests/unit/test_injection_engine.py`: `_ordered_kinds` expectations gain the merged entry
  where both checks are selected.
- `tests/unit/test_cli.py`: a `list-checks` assertion for `injection.el`.
- `tests/integration/test_scan_fixture_app.py`: `injection.el` findings per route, the
  hardened guard, the `/greet` unchanged assertion, and a duplicate guard (no `injection.ssti`
  finding for the same point).
- `docs/active-injection.md`, `README.md`, `CLAUDE.md`, `specs/README.md`, and `docs/stack.md`
  when it names the injection detectors.
- Nothing in `web/`: the dashboard renders checks from the API, which reads the registry.

## Risks

| Risk | Mitigation |
|---|---|
| The combined routine drifts from `ssti.detect` on template engines | Parametrize the existing `ssti` unit scenarios over both entry points; assert equal hit tuples. |
| The shared 38-request cap starves later detectors | Canary stays at +3; the full set only on command/expression-shaped points; measured against the fixture before any cap change. |
| A real calculator endpoint is flagged | The proof needs the marker glued to the product through string concatenation; a plain arithmetic evaluator returns the bare product and is not a hit. |
| CRITICAL read as exploitation | The probe is `Math.abs`; evidence says "type access proven", not "exploited"; RNF-03 pins the set of allowed calls and a unit test forbids tokens such as `Runtime`, `ProcessBuilder`, `System`, `Class`, `File`. |
| OGNL syntax attribution is wrong for some app | Only `%{}` evaluating arithmetic through a random marker triggers it; the finding stays HIGH without a probe. |
| Signature regexes are version-specific | Matched against the baseline-absent rule, so a stale pattern fails closed (no finding), never open. |

## Test strategy

**Unit — `tests/unit/test_injection_el.py`** (stubs per dialect, as 011's `_jinja`):

- Stubs: `_spel` (bare + `#{}`/`${}`, `T()` allowed), `_spel_sandboxed` (arithmetic yes,
  `T()` → `EL1005E`), `_ognl` (`%{}` + `@…@`), `_ognl_static_off`, `_freemarker`
  (`${}` only), `_unified_el` (`${}` + `javax.el.ELException` on a bad call), `_jinja`,
  `_reflect` (echoes unevaluated).
- Arithmetic per form; echoed literal and product-without-marker are not hits; baseline
  suppression; the send-returns-`None` stop at every stage.
- Classification table: every row of the Classification and Severity tables above.
- Signature-only: MEDIUM; signature also in baseline → no hit; the unterminated probe only
  on full points.
- **Parity:** the existing `test_injection_ssti` scenarios run against `detect_combined`
  and produce the same `ssti` hits.
- Forbidden-token guard on every probe payload built.
- `EL_AMBIGUOUS_HINTS` ⊆ `arith_payloads` hints; request counts per point type match the
  Request budget table.
- `is_exprlike` name and value classification; `_ordered_kinds` front-loading and
  `_merge_el` for all four selected-set combinations.

**Unit — `tests/unit/test_fixture_el.py`:** the evaluator accepts what it should (arithmetic,
string concatenation, the allow-listed call) and rejects calls, attribute access, names and
comprehensions without ever calling `eval`.

**Check metadata:** id, category, mode, default severity, `cwe == (917, 94)`, references,
`list-checks`, `[checks] disabled` gating (extends `test_checks_injection.py`).

**Integration — `tests/integration/test_scan_fixture_app.py`:** insecure Active → the three
findings with the expected dialect / severity / param / method; no `injection.ssti`
duplicate for those points; `/greet` still `injection.ssti` (Jinja); Passive → none and no
crafted request; hardened Active → zero `injection.el`; determinism across two runs.

## Implementation notes

What changed between this design and the code, and what was measured.

- **Request counts, as built** (nothing evaluating, `_reflect`-style target): combined
  canary 8, combined full 14, EL-only canary 5, EL-only full 9 — the Request budget table,
  confirmed by `test_request_counts_per_point_type`.
- **Per-point cap 38 → 42.** The design said the cap moves only with a measurement. Measured
  on the insecure fixture with every kind selected: `/banner?caption=` (not expression-shaped,
  so the combined entry sits behind xss / sqli / traversal / redirect) found nothing at 38,
  found `injection.el` at 39 and above; `/report?filter=`, `/rule?cond=` and `/greet?name=`
  (all front-loaded) passed at 38. 42 keeps a one-request margin. The full suite, including
  the `sqli-time` tests, passed at 42, so the slow time-based detectors did not start
  draining the shared sleep sub-budget (the 011 concern at 45). `request_budget` unchanged.
- **`_EXPRLIKE_NAMES` is narrower than RF-06 listed.** No `q` / `query` / `search` / `msg` /
  `message` / `title`; `cond` added. The 014 comment in `points.py` records that a
  front-loaded generic name starves the fast detectors, and the measurement above shows how
  tight the cap already is. Those points take the canary path. RF-06 wording is left as
  approved; this is the as-built set.
- **Evidence excerpt is the matched line**, up to 120 characters, not the bare regex match,
  so `EL1005E: Type cannot be found` survives into the finding. A probe's own refusal is
  preferred over the stage-1 signature as the named evidence.
- **Helpers promoted to public** in `ssti.py` (`engine_from_error`, `engine_first`,
  `identify_engine`, `build_hit`, and `CANARY_LIMIT`) — five renames, no logic change; the
  `ssti` tests pass untouched.
- **Fixture.** `/rule` handles `#{…}` only. The three routes HTML-escape text they do not
  evaluate. The insecure profile now crawls 23 pages instead of 20.
- **Manual verification** (CLI, fixture served by uvicorn): three `injection.el` findings
  (OGNL `caption` CRITICAL, SpEL `filter` CRITICAL, SpEL `cond` HIGH), CWE `[917, 94]`,
  `injection.ssti` on `name` still Jinja2 and not duplicated; with `[checks] disabled =
  ["injection.el"]` only the `ssti` finding remains; `list-checks` shows
  `injection.el | INJECTION | active | HIGH`.
