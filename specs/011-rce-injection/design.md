---
feature: In-band RCE injection — OS command injection (echo + time-based) and SSTI (Active Mode)
status: done
date: 2026-09-08
related:
  - 006-active-injection/design.md
  - 009-ssrf/design.md
origin: conception
---

# 011 — In-band RCE injection (command injection, SSTI) — design

> Design notes: [why blind SSRF / OAST is not on the roadmap](../../docs/notes/why-not-oast.md)
> (the same reasoning bounds blind command injection) ·
> [false-positive discipline](../../docs/notes/false-positive-discipline.md).

## Overview

011 adds **two detectors** to the spec-006 injection pass and **two thin checks**
that consume their hits. Nothing else in the engine moves, and the shape is the
one 009 already used for SSRF.

- **`detect/cmdi.py`** — one detector, `kind = "cmdi"`, feeding
  `injection.cmdi.os` (CRITICAL, CWE-78). It runs an **echo** stage always and a
  **time-based** stage when `ctx.time_based_cmdi` is on. The echo stage breaks out
  of the assumed shell context and makes the shell compute `wv<token>=<a*b>`
  (a per-request marker glued to the product of two random operands); a match
  **absent from the baseline** is the proof. The time stage mirrors
  `detect/sqli.py::detect_time` exactly — a `sleep <d>` payload must slow the
  response past a `sleep 0` control and scale with a half-delay confirm.
- **`detect/ssti.py`** — one detector, `kind = "ssti"`, feeding `injection.ssti`
  (HIGH, CWE-1336). Stage 1 sends the polyglot `${{<%[%'"}}%\` and reads the
  response for a template-engine error signature; stage 2 sends per-engine
  arithmetic payloads and looks for `wv<token><a*b>` (marker glued to the
  *computed* product) absent from the baseline; an optional third request
  (`{{7*'7'}}`) identifies the engine.
- **`points.is_commandlike(point)`** — a name heuristic;
  `engine._ordered_kinds` front-loads `cmdi` and `ssti` for a command/template-
  shaped point, exactly as it front-loads `traversal` / `redirect` / `ssrf`.
  Non-command points get a **canary** subset (like 009's `_CANARY`).
- **`OsCommandInjectionCheck` / `TemplateInjectionCheck`** — subclasses of the
  existing `_InjectionCheck`; they only filter `ctx.observations.injection_hits`
  by `kind`. No new base-class code.

**No orchestrator pass** (the reflected `InjectionScanner` already does
everything). **One config field** (`[injection] time_based_cmdi`, default `true`)
and **one CLI flag** (`--time-based-cmdi / --no-time-based-cmdi`), both mirroring
the existing SQLi pair. **No API / UI / reporter change** — the new ids surface
through the existing `INJECTION` plumbing (006/009 established this).

```
InjectionScanner.run                                        [006, unchanged]
  enumerate_points → per point: baseline → _ordered_kinds → fan _DETECTORS
        _ordered_kinds front-loads "cmdi" / "ssti" when is_commandlike(point)   [011]
        _DETECTORS["ssti"] = ssti.detect                                        [011]
        _DETECTORS["cmdi"] = cmdi.detect                                        [011]
              ssti.detect:  polyglot probe → error signature? → arithmetic payloads
                            → "wv<tok><product>" absent from baseline → ssti hit (HIGH)
              cmdi.detect:  echo payloads → "wv<tok>=<product>" absent from baseline
                            → cmdi hit (CRITICAL); then, if ctx.time_based_cmdi,
                            sleep/ping payloads confirmed vs a 0-delay control → cmdi hit
  → InjectionHit list → ctx.observations.injection_hits
        OsCommandInjectionCheck  (kind="cmdi")  → Finding                       [011]
        TemplateInjectionCheck   (kind="ssti")  → Finding                       [011]
```

## Module layout

| Path | Change | What |
|---|---|---|
| `src/webvigil/checks/injection/detect/cmdi.py` | **new** (~150 lines) | `detect` (echo stage + time stage) + `_echo_hit` / `_time_hit` + `_point_evidence` / `_snippet`; `random`/`secrets` for the marker and operands. |
| `src/webvigil/checks/injection/detect/ssti.py` | **new** (~150 lines) | `detect` (polyglot probe → arithmetic → engine id) + `_engine_from_error` / `_identify_engine` / `_arith_payloads`. |
| `src/webvigil/checks/injection/detect/__init__.py` | edit | `DetectCtx` gains `time_based_cmdi: bool` (next to `delay_s`). |
| `src/webvigil/checks/injection/payloads.py` | edit | a command-injection section (`CMDI_ECHO_POSIX`, `CMDI_ECHO_WINDOWS`, `CMDI_TIME`, `CMDI_MARKER_BYTES`) and an SSTI section (`SSTI_POLYGLOT`, `SSTI_ERROR_SIGNATURES`, `SSTI_ENGINE_PROBE`, `SSTI_MARKER_BYTES`; the arithmetic payloads are built by a helper, not a static tuple — brace-escaping). |
| `src/webvigil/checks/injection/points.py` | edit | `_COMMANDLIKE_NAMES`, `def is_commandlike(point) -> bool`. |
| `src/webvigil/checks/injection/engine.py` | edit | import the two detectors + `is_commandlike`; `_DETECTORS["ssti"]` / `["cmdi"]`; `"ssti"` and `"cmdi"` into `_BASE_ORDER`; `KIND_BY_CHECK_ID` gains the two ids; two more `(predicate, kind)` pairs in `_ordered_kinds`; `DetectCtx(..., time_based_cmdi=config.time_based_cmdi)`; the time sub-budget is enabled when `time_based_sqli` **or** `time_based_cmdi`. |
| `src/webvigil/checks/injection/checks.py` | edit | `_DESCRIPTION` / `_REMEDIATION` / `_REFERENCES` for `"cmdi"` and `"ssti"`; `@register class OsCommandInjectionCheck` / `TemplateInjectionCheck`. |
| `src/webvigil/core/config.py` | edit | `InjectionSection.time_based_cmdi: bool = True` + docstring line. |
| `src/webvigil/cli/app.py` | edit | `--time-based-cmdi / --no-time-based-cmdi` option, threaded through `_build_config` like `time_based_sqli`. |
| `tests/fixtures/app.py` | edit | `GET /ping?host=` (insecure: simulated shell — interprets `sleep`/arith payloads; hardened: host regex) and `GET /greet?name=` (insecure: name into Jinja2 template *source*; hardened: name as a *variable*), plus links so the crawler finds `?host=` / `?name=`; both routes in both profiles. |
| `tests/unit/test_injection_cmdi.py` | **new** | the echo + time branches via a stub `send`. |
| `tests/unit/test_injection_ssti.py` | **new** | the polyglot → arithmetic → engine-id branches via a stub `send`. |
| `tests/unit/test_injection_points.py`, `…_engine.py`, `…_orchestrator.py`, `…checks_injection.py`, `…_cli.py`, `…_config.py` | edit | `is_commandlike`; `_BASE_ORDER` / `KIND_BY_CHECK_ID` / priority; `DetectCtx.time_based_cmdi`; detector gating; check metadata + finding shape + `_ALL`; `list-checks`; the config field + CLI flag. |
| `tests/integration/test_scan_fixture_app.py` | edit | Active scan → `injection.cmdi.os` + `injection.ssti` on insecure, **zero** on hardened, deterministic; `pages_scanned` bump for the two new links. |
| `docs/active-injection.md`, `README.md`, `CLAUDE.md`, `specs/README.md` | edit | the new section / coverage rows / layer-3 paragraph / roadmap. |

Nothing under `src/webvigil/core/` beyond the one config field,
`src/webvigil/api/`, or `web/` changes. `import-linter` contracts unchanged
(`webvigil.checks`, `webvigil.http` are already source modules; no new import
direction).

## Data model

### `InjectionHit` — reused unchanged

`kind` takes two new string values, `"cmdi"` and `"ssti"`. Every other field is
populated as the 006/009 detectors already do. **No new field** — the CWE stays
on the check class (`(78, 77)` for `cmdi`, `(1336, 94)` for `ssti`), so
`_InjectionCheck.run` is untouched.

### `DetectCtx` — one new field

```python
@dataclass(frozen=True, slots=True)
class DetectCtx:
    send: Sender
    delay_s: int
    host: str
    time_based_cmdi: bool = True   # [injection] time_based_cmdi — gates cmdi's sleep stage
```

Default `True` keeps every existing construction site and test valid without
edits; `engine.py` passes the real config value.

### `InjectionSection` — one new field

```python
time_based_cmdi: bool = True
```

Documented next to `time_based_sqli`: "Send time-delay OS-command-injection
payloads during an Active scan (slower). On by default."

### `ActiveBudget` — unchanged

The time sub-budget (`_TIME_BASED_SLEEP_CAP = 8`) is now shared by `sqli-time`
and `cmdi`'s time stage. `engine.py` enables it when **either** flag is on:

```python
time_based_limit=_TIME_BASED_SLEEP_CAP if (config.time_based_sqli or config.time_based_cmdi) else 0,
```

## Components

### Payloads (`payloads.py`)

`{marker}` is a per-request `wv` + `secrets.token_hex`; `{a}` / `{b}` are random
two-digit operands (`random.randint(11, 99)`). Like the XSS detector's per-run
token, they make the proof unique but do **not** change which findings are
produced (RNF-05) — `fingerprint` is `check_id` + URL + method + param.

```python
# --- OS command injection (spec 011, RF-02, RF-03) -----------------------------------

CMDI_MARKER_BYTES = 6

# Break out of the assumed shell context, then echo "<marker>=<product>". `$((a*b))` is a
# POSIX arithmetic expansion the shell evaluates — an app that only *reflects* the payload
# sends back the literal "$((a*b))" and is not a hit (ADR-4). A few variants also close a
# quote first, for a value used inside "$var" / '$var'.
CMDI_ECHO_POSIX: tuple[str, ...] = (
    ";echo {marker}=$(({a}*{b}))",
    "|echo {marker}=$(({a}*{b}))",
    "||echo {marker}=$(({a}*{b}))",
    "&&echo {marker}=$(({a}*{b}))",
    "&echo {marker}=$(({a}*{b}))",
    "$(echo {marker}=$(({a}*{b})))",
    "`echo {marker}=$(({a}*{b}))`",
    "%0aecho {marker}=$(({a}*{b}))",
    ";echo${{IFS}}{marker}=$(({a}*{b}))",          # space-filtered contexts
    '";echo {marker}=$(({a}*{b}));#',              # break a double-quoted "$host"
    "';echo {marker}=$(({a}*{b}));#",              # break a single-quoted '$host'
)

# Windows cmd.exe — lower confidence (two-token match, no single self-checking expansion).
CMDI_ECHO_WINDOWS: tuple[str, ...] = (
    "&echo {marker}&set /a {a}*{b}",
    "|echo {marker}&set /a {a}*{b}",
)

# (label, template) — {d} = configured delay, {d1} = d + 1 (ping wants a count). Confirmed
# against a {d}=0 control and a half-delay probe, exactly like SQLI_TIME.
CMDI_TIME: tuple[tuple[str, str], ...] = (
    ("POSIX", ";sleep {d}"),
    ("POSIX", "$(sleep {d})"),
    ("POSIX", "`sleep {d}`"),
    ("POSIX", "|sleep {d}"),
    ("POSIX", "%0asleep {d}"),
    ("Windows", "&ping -n {d1} 127.0.0.1"),
    ("Windows", "&timeout /t {d}"),
)

# --- server-side template injection (spec 011, RF-05, RF-06) -------------------------

SSTI_MARKER_BYTES = 6

# The PortSwigger SSTI polyglot: valid in enough contexts to draw a template parse error
# from most engines without executing anything.
SSTI_POLYGLOT = "${{<%[%'\"}}%\\"

# (engine, pattern) — a parse/render error in the response body, required absent from the
# baseline. Matching one names the engine and picks its arithmetic payload first.
SSTI_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Jinja2", re.compile(r"jinja2\.exceptions|TemplateSyntaxError|TemplateAssertionError", re.I)),
    ("Twig", re.compile(r"Twig\\Error|Twig_Error|Twig\\Environment", re.I)),
    ("Freemarker", re.compile(r"FreeMarker template error|freemarker\.core\.", re.I)),
    ("Velocity", re.compile(r"org\.apache\.velocity|ParseErrorException", re.I)),
    ("Smarty", re.compile(r"Smarty(?:CompilerException|_Compiler_)|Smarty error", re.I)),
    ("Mako", re.compile(r"mako\.exceptions|SyntaxException.*mako", re.I)),
    ("ERB", re.compile(r"\(erb\):\d+|SyntaxError \(\(erb\)", re.I)),
    ("Handlebars", re.compile(r"Handlebars.*Parse error|hbs.*Parse error", re.I)),
)

# String-repetition tell: {{7*'7'}} -> "7777777" (Jinja2/Nunjucks), "49" (Twig).
SSTI_ENGINE_PROBE = "{marker}{{{{7*'7'}}}}"
```

The SSTI arithmetic payloads are built by a helper rather than a `.format` tuple
(the brace-doubling for `{{a*b}}` inside `str.format` is unreadable):

```python
def arith_payloads(marker: str, a: int, b: int) -> tuple[tuple[str, str], ...]:
    """(engine hint, payload) — the marker is glued to the expression so a hit is
    '<marker><product>' in the output, never the product alone (ADR-4)."""
    return (
        ("Jinja2/Twig", f"{marker}{{{{{a}*{b}}}}}"),        # {marker}{{a*b}}
        ("Freemarker/EL", f"{marker}${{{a}*{b}}}"),         # {marker}${a*b}
        ("ERB/EJS", f"{marker}<%= {a}*{b} %>"),
        ("Groovy/Twig", f"{marker}${{{{{a}*{b}}}}}"),       # {marker}${{a*b}}
        ("Thymeleaf", f"{marker}*{{{a}*{b}}}"),             # {marker}*{a*b}
        ("Razor", f"{marker}@({a}*{b})"),
        ("Smarty", f"{marker}{{{a}*{b}}}"),                 # {marker}{a*b}
        ("Slim/Pug", f"{marker}#{{{a}*{b}}}"),              # {marker}#{a*b}
    )
```

### `detect/cmdi.py` (RF-02, RF-03, RF-07)

```python
_CHECK_ID = "injection.cmdi.os"


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    marker = "wv" + secrets.token_hex(payloads.CMDI_MARKER_BYTES)
    a, b = random.randint(11, 99), random.randint(11, 99)
    hit = await _echo(point, baseline, ctx, marker, a, b)
    if hit is None and ctx.time_based_cmdi:
        hit = await _time(point, baseline, ctx)
    return [hit] if hit is not None else []
```

- **`_echo`** — full `CMDI_ECHO_POSIX` for an `is_commandlike` point, else a
  3-payload canary (`;echo …`, `|echo …`, `` `echo …` ``). For each template:
  `payload = point.original + template.format(marker=marker[2:], a=a, b=b)`;
  `response = await ctx.send(point, payload)` (`None` → return `None`). The needle
  is `f"{marker[2:]}={a * b}"`; a hit needs `needle in response.text and needle
  not in baseline.raw_body` →
  `InjectionHit(kind="cmdi", check_id=_CHECK_ID, severity=CRITICAL,
  confidence=HIGH, title=f"OS command injection via the '{point.param}' parameter",
  payload=payload, evidence=(point, payload, ("Command output", snippet)))`.
  After the POSIX set, `CMDI_ECHO_WINDOWS` is tried; a hit there requires
  `marker[2:]` **and** `str(a * b)` both present and baseline-absent →
  `confidence=MEDIUM`.
- **`_time`** — mirrors `sqli.detect_time`: for each `(label, template)` in
  `CMDI_TIME`, send a `{d}=0` / `{d1}=1` control, then a `time_based=True` payload
  at `ctx.delay_s`; require `slow.elapsed_ms - max(control, baseline) >=
  (delay - 1) * 1000`; confirm with a half-delay `time_based=True` probe that
  lands in `[(half-1)*1000, (half+2)*1000]` ms (HIGH), or MEDIUM if the confirm
  request was budget-denied. Hit: `kind="cmdi"`, `severity=CRITICAL`,
  `title=f"OS command injection (time-based, {label}) via '{point.param}'"`,
  evidence carries the control-vs-injected timings.

`_point_evidence` / `_snippet` mirror the helpers in `detect/sqli.py` /
`detect/traversal.py`.

### `detect/ssti.py` (RF-05, RF-06, RF-07)

```python
_CHECK_ID = "injection.ssti"


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    # Stage 1 — polyglot: draw a template error, if any.
    probe = await ctx.send(point, point.original + payloads.SSTI_POLYGLOT)
    if probe is None:
        return []
    engine = _engine_from_error(probe.text, baseline.raw_body)   # str | None

    # Stage 2 — arithmetic: <marker><product> in the output, absent from the baseline.
    marker = "wv" + secrets.token_hex(payloads.SSTI_MARKER_BYTES)
    a, b = random.randint(11, 99), random.randint(11, 99)
    needle = f"{marker[2:]}{a * b}"
    candidates = payloads.arith_payloads(marker[2:], a, b)
    if engine is not None:
        candidates = _engine_first(candidates, engine)
    for _hint, payload in candidates:
        resp = await ctx.send(point, point.original + payload)
        if resp is None:
            break
        if needle in resp.text and needle not in baseline.raw_body:
            engine = engine or await _identify_engine(point, ctx, marker[2:])
            return [_hit(point, engine, point.original + payload, resp, needle)]
    return []
```

- **`_engine_from_error(text, baseline_text)`** — first `(name, pattern)` in
  `SSTI_ERROR_SIGNATURES` matching `text` and not `baseline_text`, else `None`.
- **`_identify_engine(point, ctx, marker)`** — one extra `ctx.send` with
  `SSTI_ENGINE_PROBE` (`{marker}{{7*'7'}}`); `marker + "7777777"` in the response
  → `"Jinja2/Nunjucks"`; `marker + "49"` → `"Twig"`; else `None`. Budget-denied →
  `None` (the finding still stands, engine unnamed).
- **`_hit`** — `InjectionHit(kind="ssti", check_id=_CHECK_ID, severity=HIGH,
  confidence=HIGH, title=f"Server-side template injection ({engine or 'engine
  unknown'}) via the '{point.param}' parameter", payload=…, evidence=(point,
  payload, ("Evaluated expression", f"{needle}  (= {a}*{b})"), optional template
  error snippet))`.

For a non-`is_commandlike` point the detector still runs (SSTI sinks are often
plainly-named `name` / `q`), but stage 2 stops after the first 4 payloads — the
canary rule (ADR-7).

### `points.is_commandlike` (RF-04)

```python
_COMMANDLIKE_NAMES = frozenset({
    "cmd", "command", "exec", "execute", "run", "ping", "host", "hostname", "ip", "addr",
    "domain", "dns", "lookup", "query", "search", "q", "name", "arg", "args", "option",
    "opt", "code", "template", "tpl", "preview", "format", "func", "action", "file", "path",
})


def is_commandlike(point: InjectionPoint) -> bool:
    return point.param.lower() in _COMMANDLIKE_NAMES
```

Name-only — a command-injection or SSTI sink rarely has a telltale *value*
(unlike a URL or a path). `file` / `path` / `search` / `q` overlap
`_PATHLIKE_NAMES` / `_URLLIKE_NAMES` on purpose: such a point is front-loaded for
several detectors, all under the shared per-point cap (already how `next` / `url`
front-load both `traversal` and `redirect`).

### `engine.py`

```python
from webvigil.checks.injection.detect import cmdi as cmdi_detect
from webvigil.checks.injection.detect import ssti as ssti_detect
from webvigil.checks.injection.points import ..., is_commandlike

_DETECTORS = { ..., "ssti": ssti_detect.detect, "cmdi": cmdi_detect.detect }

# ssti/cmdi go near the end: ssti is broad, cmdi carries the time stage — neither should
# starve the fast 006 detectors on a busy point. _ordered_kinds front-loads them for a
# command/template-shaped point.
_BASE_ORDER = (
    "xss", "sqli-error", "sqli-boolean", "traversal", "redirect",
    "ssti", "sqli-time", "cmdi", "ssrf",
)

KIND_BY_CHECK_ID = {
    ...,
    "injection.ssti": "ssti",
    "injection.cmdi.os": "cmdi",
}
```

`_ordered_kinds` gains two pairs:

```python
for predicate, kind in (
    (is_pathlike, "traversal"),
    (is_redirect_name, "redirect"),
    (is_urllike, "ssrf"),
    (is_commandlike, "cmdi"),
    (is_commandlike, "ssti"),
):
    if predicate(point) and kind in kinds:
        kinds.remove(kind)
        kinds.insert(0, kind)
```

`DetectCtx` construction:

```python
self._ctx = DetectCtx(
    send=self._send,
    delay_s=config.time_based_delay_s,
    host=target.host,
    time_based_cmdi=config.time_based_cmdi,
)
```

Both new check ids map one-to-one to a detector kind, so the existing
`selected_kinds` logic is unchanged: the detector runs when its check is
selected, and not at all when it is disabled (RF-10). `cmdi`'s time stage is
gated *inside* the detector by `ctx.time_based_cmdi` (ADR-3), not by dropping a
kind — contrast `sqli-time`, which is its own check id.

### `checks.py`

```python
_CMDI_FIX = (
    "Never pass user input to a shell. Call the program directly with an argument vector "
    "(execve-style: subprocess with a list and shell=False), so there is no shell to inject "
    "into. If a shell is unavoidable, allow-list the input against a strict pattern; escaping "
    "is not enough."
)
_SSTI_FIX = (
    "Never build template source from user input. Pass user values as template *data* "
    "(context variables), not into the template string. Use a sandboxed/logic-less engine "
    "for user-authored templates, and keep the template directory out of user control."
)

_DESCRIPTION["cmdi"] = (
    "A value supplied in this parameter is passed to an operating-system shell. WebVigil "
    "appended a shell command and the server executed it — proved by a computed value in the "
    "response that reflection alone could not produce, or by an attacker-controlled response "
    "delay. This is remote code execution."
)
_DESCRIPTION["ssti"] = (
    "A value supplied in this parameter is concatenated into server-side template source "
    "rather than passed as template data. WebVigil injected a template expression and the "
    "engine evaluated it (an arithmetic expression returned its result). Most template "
    "engines expose enough of the host language to reach remote code execution."
)
_REMEDIATION["cmdi"] = _CMDI_FIX
_REMEDIATION["ssti"] = _SSTI_FIX
_REFERENCES["cmdi"] = (
    f"{_OWASP}/attacks/Command_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
)
_REFERENCES["ssti"] = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
    "https://portswigger.net/research/server-side-template-injection",
)


@register
class OsCommandInjectionCheck(_InjectionCheck):
    """OS command injection from the shell-metacharacter echo or time detector (spec 011)."""

    id = "injection.cmdi.os"
    name = "OS command injection"
    kind = "cmdi"
    default_severity = Severity.CRITICAL
    cwe = (78, 77)
    references = _REFERENCES["cmdi"]


@register
class TemplateInjectionCheck(_InjectionCheck):
    """Server-side template injection from the polyglot + arithmetic detector (spec 011)."""

    id = "injection.ssti"
    name = "Server-side template injection"
    kind = "ssti"
    default_severity = Severity.HIGH
    cwe = (1336, 94)
    references = _REFERENCES["ssti"]
```

### Fixture app (`tests/fixtures/app.py`, RF-12)

**insecure** — a "ping this host" endpoint that shells out, and a greeting that
concatenates into template source. Both *simulate* for deterministic offline CI —
the same trick the 006 fixture uses for `SLEEP(n)`.

```python
import jinja2

_CMDI_SLEEP_RE = re.compile(r"sleep\s+(\d+)|ping\s+-n\s+(\d+)|timeout\s+/t\s+(\d+)", re.I)
_CMDI_ARITH_RE = re.compile(r"(wv[0-9a-f]{6,})=\$\(\((\d+)\*(\d+)\)\)|set /a (\d+)\*(\d+)", re.I)


async def _ping_insecure(request: Request) -> Response:
    raw = request.query_params.get("host", "")
    m = _CMDI_SLEEP_RE.search(raw)
    if m:
        await asyncio.sleep(min(int(next(g for g in m.groups() if g)), 6))
        return PlainTextResponse(f"PING {raw}: 1 packets transmitted")
    m = _CMDI_ARITH_RE.search(raw)
    if m and m.group(1):
        return PlainTextResponse(f"PING\n{m.group(1)}={int(m.group(2)) * int(m.group(3))}\n")
    if m:
        return PlainTextResponse(f"PING\n{int(m.group(4)) * int(m.group(5))}\n")
    return PlainTextResponse(f"PING {raw}: 1 packets transmitted, 0 received")


def _greet_insecure(request: Request) -> Response:
    name = request.query_params.get("name", "")
    try:
        body = jinja2.Template("<!doctype html><p>Hi " + name + "</p>").render()
    except jinja2.exceptions.TemplateError as exc:
        return PlainTextResponse(f"jinja2.exceptions.{type(exc).__name__}: {exc}", status_code=500)
    return HTMLResponse(body)
```

**hardened** — the safe equivalents; every payload (and the baseline) yields a
neutral response:

```python
def _ping_hardened(request: Request) -> Response:
    host = request.query_params.get("host", "")
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):
        return PlainTextResponse("invalid host", status_code=400)
    return PlainTextResponse(f"PING {host}: 1 packets transmitted")


def _greet_hardened(request: Request) -> Response:
    name = request.query_params.get("name", "")
    return HTMLResponse(jinja2.Template("<!doctype html><p>Hi {{ name }}</p>").render(name=name))
```

The shared link block gains `<a href="/ping?host=localhost">ping</a>
<a href="/greet?name=friend">greet</a>`; `/ping` and `/greet` are added to both
profiles' route tuples (GET).

## Interfaces

No external interface beyond:

- **CLI** — `--time-based-cmdi / --no-time-based-cmdi` (default on), threaded like
  `--time-based-sqli`. `webvigil list-checks` gains two rows:
  `injection.cmdi.os | INJECTION | active | CRITICAL` and
  `injection.ssti | INJECTION | active | HIGH`.
- **Config** — `[injection] time_based_cmdi` (bool, default `true`).

No new API route, no reporter field, no `openapi.json` / `api-types.ts` change.

## ADRs

### ADR-1 — In-band only; truly blind command injection stays deferred

**Decision.** 011 detects command injection from the target's own response — an
arithmetic echo, or a measured delay. No collaborator server, no DNS/HTTP
callback catcher.

**Alternatives.** (a) Ship an OAST collaborator (interactsh & co.) for the blind
case now. (b) Wait and do command injection only once an OAST spec exists.

**Why.** The echo and time-based signals cover the cases a developer or a
pentester actually reproduces by hand; they cost nothing and need no
infrastructure. A hosted OAST collaborator crosses "the engine talks only to the
target" and the repo-only distribution — the identical call made for blind SSRF
in spec 009 ([`docs/notes/why-not-oast.md`](../../docs/notes/why-not-oast.md)).
The time-based detector *is* the in-band substitute for the blind case, exactly
as `injection.sqli.time-based` is for blind SQLi.

**Trade-off.** A command injection with no output *and* no timing effect
(`; curl http://x/` on a fire-and-forget path) is a false negative. The docs say
so plainly and point at "pair with your own collaborator".

### ADR-2 — One `cmdi` detector, one `injection.cmdi.os` check (CRITICAL)

**Decision.** A single detector runs the echo stage and the time stage and emits
`kind = "cmdi"`; one check, `injection.cmdi.os`, CWE-78, CRITICAL.

**Alternatives.** (a) Two checks — `injection.cmdi.os` (echo) and
`injection.cmdi.blind` (time) — like the three SQLi ids. (b) Two detector kinds
(`cmdi-echo` / `cmdi-time`) feeding one check, which forces `KIND_BY_CHECK_ID` to
become a one-to-many map.

**Why.** Echo-proved and time-proved command injection are the *same
vulnerability, the same severity, the same fix* — unlike SQLi, where error /
boolean / time are genuinely different techniques with different confidence and a
real reason to disable the slow one independently. Here "disable the slow one" is
`time_based_cmdi`, handled inside the one detector. One check keeps `list-checks`
honest (one row = one vulnerability class) and `KIND_BY_CHECK_ID` one-to-one.

**Trade-off.** A user cannot disable *only* the echo stage (they would disable
the whole check). No real use case for that.

### ADR-3 — `time_based_cmdi` reaches the detector through `DetectCtx`

**Decision.** `DetectCtx` gains a `time_based_cmdi: bool` field; `cmdi.detect`
skips its time stage when it is `False`.

**Alternatives.** Split `cmdi` into `cmdi-echo` / `cmdi-time` kinds and filter the
time kind out of `selected_kinds` when the flag is off — the `sqli-time`
mechanism.

**Why.** `cmdi` is one detector (ADR-2); a `DetectCtx` bool is the minimal seam
and sits naturally next to `delay_s`, which is already the time-stage's only
other input. Default `True` means every existing `DetectCtx(...)` in the tests
keeps working unedited.

**Trade-off.** `DetectCtx` grows one field. It is `frozen`/`slots`; the cost is
one line.

### ADR-4 — Proof is a computed value glued to a per-request marker

**Decision.** A `cmdi` echo hit needs `wv<token>=<a*b>` (the marker and the
*evaluated* product) in the response and absent from the baseline. An `ssti` hit
needs `wv<token><a*b>` (marker glued to the product). `a`, `b` are random per
request.

**Alternatives.** (a) Accept the marker alone (`echo wv<token>`). (b) Accept the
product alone (`49`).

**Why.** The marker alone proves only *reflection* — the app echoed the
parameter. The product alone is a coincidence magnet (a price, an id, a count).
The marker immediately followed by a number that equals `a*b` for operands the
attacker chose this request, and that the baseline did not contain, is only
explicable by the shell / template engine having *evaluated* the expression. This
is the false-positive firewall
([`docs/notes/false-positive-discipline.md`](../../docs/notes/false-positive-discipline.md)).

**Trade-off.** An engine that HTML-encodes the `=`, or splits the marker and the
output across the DOM, is missed. Acceptable — precision over recall for a
CRITICAL finding.

### ADR-5 — SSTI is HIGH, not CRITICAL

**Decision.** `injection.ssti` default severity is HIGH (confidence HIGH on the
arithmetic proof).

**Alternatives.** CRITICAL (SSTI is frequently RCE); per-engine severity
(CRITICAL for Jinja2/Freemarker, HIGH for sandboxed Twig).

**Why.** Matches OWASP ZAP's SSTI rule. The arithmetic proof confirms *expression
evaluation*, not a working RCE gadget — some engines are sandboxed, some
deployments disable dangerous globals. Reserving CRITICAL for `injection.cmdi.os`
and `injection.ssrf.metadata` keeps "CRITICAL = proven code execution or
credential exposure" meaningful. `--fail-on high` still blocks a build on it, and
the description states the RCE potential explicitly.

**Trade-off.** A Jinja2 SSTI (near-certain RCE) is reported HIGH. The finding
title names the engine and the description does not soften the risk.

### ADR-6 — POSIX-primary; Windows via time-based + a MEDIUM-confidence echo

**Decision.** The echo payload set is POSIX-shell-shaped. Windows `cmd` gets two
`& echo … & set /a` variants (reported at MEDIUM confidence) and the
`ping -n` / `timeout` time payloads. No PowerShell.

**Alternatives.** Full parity — `for /f` arithmetic capture on Windows, PowerShell
`$(…)` payloads.

**Why.** Server-side shell-outs are overwhelmingly POSIX; the Windows echo case
lacks a single self-checking expansion like `$((…))`, so its proof is a weaker
two-token match. PowerShell needs different quoting and separators for a small
additional population. The time-based `ping -n` / `timeout` payloads cover
Windows blind command injection at full confidence.

**Trade-off.** A Windows-only, echo-only sink scanned with `--no-time-based-cmdi`
may be missed or reported only at MEDIUM.

### ADR-7 — `cmdi` / `ssti` run late in `_BASE_ORDER`, front-loaded by heuristic

**Decision.** Both sit near the end of `_BASE_ORDER`; `_ordered_kinds` moves them
to position 0 when `is_commandlike(point)`. A non-command point gets a small
canary payload subset, not the full set.

**Alternatives.** Run them in the middle of the order; run the full payload set
on every point.

**Why.** `ssti` is broad (1 probe + up to 8 arithmetic payloads + 1 engine
probe) and `cmdi` carries the sleep stage — on a heavily-parameterised point
either could exhaust the per-point cap before the fast 006 detectors run. This is
exactly the problem 009 hit with `ssrf` and solved the same way (ADR-5 there, and
the `_CANARY` split in the implementation notes).

**Trade-off.** On a huge target the budget may be spent before every non-command
point gets the full `cmdi` / `ssti` set — the existing budget warning covers it.

## Impact

- **Backward compatible.** `cmdi` / `ssti` run only in Active Mode with their
  check selected. Passive scans, and Active scans that disable both, are
  byte-for-byte unchanged. The one new config field and CLI flag both default to
  the pre-existing behaviour's spirit (time-based on, like SQLi).
- **Budget.** Worst case per point: `ssti` ≈ 10 requests, `cmdi` echo ≈ 11
  (POSIX) + 2 (Windows), `cmdi` time ≈ 3 per template × up to 7 templates but
  bounded by the shared 8-sleep sub-budget. The per-point cap
  (`_PER_POINT_REQUEST_CAP = 30`) and `request_budget` (500) bound the total; the
  detectors return on the first hit. **Stage-0 of tasks.md re-measures the
  fixture run and, per Resolved decision 6, bumps `_PER_POINT_REQUEST_CAP` to
  ~40 and `request_budget` to ~600 if a command-shaped point starves the 006
  detectors** — decided with the actual number, recorded in the tasks log.
- **Time sub-budget** is now shared by `sqli-time` and `cmdi` time — still capped
  at 8 sleeps/scan total, still bounded per sleep by `time_based_delay_s`.
- **No API / UI / reporter / migration change.** `list-checks` gains two rows;
  SARIF / JSON / HTML / MD render the new findings through the existing
  `INJECTION` plumbing; CWE-78 / CWE-1336 ride the existing `cwe` field.
- **Determinism.** Given the same responses, identical findings / fingerprints /
  order. The per-request marker and operands vary (like the XSS token); the
  integration test asserts on finding id / param / severity, not evidence bytes.

## Risks

| Risk | Mitigation |
|---|---|
| `cmdi` echo false positive from an app that reflects **and** happens to show a number | The needle is `<marker>=<a*b>` with random `a`, `b`, required absent from the baseline; the literal `$((a*b))` echoed unevaluated is explicitly not a hit. Unit-tested. |
| `ssti` false positive from a page that contains the product coincidentally | The product must be **glued to the marker** (`<marker><product>`), the marker is a per-request `secrets.token_hex`, and the pair must be baseline-absent. Unit-tested with "product present, marker absent → no hit". |
| `cmdi` time false positive on a uniformly slow target | The `{d}=0` control and the half-delay scaling confirm — the exact `sqli.detect_time` logic, already trusted. Unit-tested "uniformly slow → no hit". |
| Time sub-budget starvation between `sqli-time` and `cmdi` time | One shared cap (8), `cmdi` after `sqli-time` in `_BASE_ORDER`; hitting it is the existing warning, not an error. |
| Per-point cap starves the 006 detectors when `cmdi` / `ssti` front-load a busy point | ADR-7 (late base order + canary for non-command points) + the Stage-0 re-measure-and-bump. |
| The SSTI polyglot triggers a `500` that a WAF or error handler turns into a generic page | Stage 2 runs regardless of stage 1 (RF-05) — the arithmetic proof does not depend on the error signature. |
| `jinja2` import in the fixture app | `jinja2` is already a core runtime dependency (the HTML reporter); the fixture lives under `tests/`. No new dependency. |
| A payload separator breaks the fixture's own routing / a real proxy in front of a scan | Payloads are parameter *values*, URL-encoded by `build_request` / httpx; `ctx.send` swallows `RequestFailed` and the detector moves on. |

## Testing

| Layer | File | Cases |
|---|---|---|
| unit — cmdi | `tests/unit/test_injection_cmdi.py` (new) | stub `send`: POSIX echo `<marker>=<product>` present & baseline-absent → `cmdi` CRITICAL/HIGH (per separator); literal `$((a*b))` echoed → no hit; marker alone → no hit; product present in baseline → suppressed; Windows `& set /a` two-token → CRITICAL/MEDIUM; time stage — injected delay past control → CRITICAL/HIGH, uniformly slow → no hit, half-delay scaling, budget-denied confirm → MEDIUM; `ctx.time_based_cmdi=False` → no sleep payload sent; `send` → `None` stops the detector. |
| unit — ssti | `tests/unit/test_injection_ssti.py` (new) | stub `send`: polyglot draws a Jinja2 error → engine recorded; arithmetic `<marker><product>` baseline-absent → `ssti` HIGH; echoed literal `{{a*b}}` → no hit; product without adjacent marker → no hit; `{{7*'7'}}` → `7777777` → engine "Jinja2/Nunjucks"; `49` → "Twig"; no error + arithmetic still fires (stage 2 independent of stage 1); engine-probe budget-denied → finding stands, engine unnamed. |
| unit — points | `tests/unit/test_injection_points.py` | `is_commandlike` true for `cmd` / `host` / `template` / `q`; false for `email`. |
| unit — engine | `tests/unit/test_injection_engine.py` | `"cmdi"` / `"ssti"` in `_BASE_ORDER` and `_DETECTORS`; `KIND_BY_CHECK_ID` maps both ids; `_ordered_kinds` front-loads `cmdi` / `ssti` for a `host` point; absent when neither check selected; the time sub-budget is enabled when only `time_based_cmdi` is on. |
| unit — checks | `tests/unit/test_checks_injection.py` | add both to `_ALL`; a `cmdi` hit → one CRITICAL finding, `Location(url, method, param)`, evidence carries the command output; an `ssti` hit → HIGH; `[]` when no hit; ids / category / mode / severity / cwe. |
| unit — orchestrator | `tests/unit/test_injection_orchestrator.py` | Active + `OsCommandInjectionCheck` selected → `selected_kinds` contains `"cmdi"`; disabled → it does not; `DetectCtx.time_based_cmdi` reflects config. |
| unit — config / CLI | `tests/unit/test_config.py`, `test_cli.py` | `InjectionSection.time_based_cmdi` default `True`, overridable via `[injection]`; `--no-time-based-cmdi` sets it `False`; `list-checks` lists both new ids with `CRITICAL` / `HIGH`. |
| integration | `tests/integration/test_scan_fixture_app.py` | `_run("insecure", active=True)` → `injection.cmdi.os` (param `host`, command output in evidence) **and** `injection.ssti` (param `name`, engine "Jinja2/Nunjucks") present; `_run("hardened", active=True)` → **zero** `injection.cmdi.*` / `injection.ssti`; two runs → identical findings / fingerprints; `pages_scanned` adjusted for `/ping` + `/greet`. |
| quality gate | — | `ruff → black → mypy src → lint-imports → pytest` green at every stage (tasks.md). |

## Open questions

None. Ready for `/spec tasks`.

## Implementation notes

Recorded at close (2026-09-08). What shipped, and where it differed from the
design above:

- **`_COMMANDLIKE_NAMES` grew and a narrower `_SHELL_NAMES` was added.**
  `_COMMANDLIKE_NAMES` (front-loads both detectors) gained `name`, `template`,
  `render`, `view`, `engine`, `preview`, `greeting`, `code`, `eval`, `expr` — the
  parameter names SSTI actually lives in. It deliberately does **not** include the
  stateful-store POST-field names (`body`, `content`, `text`, `subject`): front-
  loading there floods a guestbook / comment store with fuzz entries and pushed
  the spec-008 stored-XSS re-crawl past its page cap (caught by an integration
  test). `points.is_shell_param` (the `_SHELL_NAMES` subset — `cmd`, `host`,
  `exec`, `ping`, `shell`, `ip`, `arg`, …) gates the full `CMDI_ECHO_POSIX` set
  (others get the 3-payload canary) **and** whether `cmdi._time` runs at all.
- **`cmdi._time` is gated on `is_shell_param`, not just `ctx.time_based_cmdi`.** A
  `sleep` payload on a `name` / template sink can only ever waste the shared
  8-sleep sub-budget. This keeps `injection.sqli.time-based` fed on a scan that
  also runs command injection.
- **`_PER_POINT_REQUEST_CAP` went to 35, not 45.** 45 was too generous: it let
  `sqli-time` run on non-time-vulnerable points that the 30-cap had (accidentally)
  stopped before it, and those `sqli-time` runs drained the shared sleep
  sub-budget before the scan reached the one point that needed it. 35 leaves room
  for the front-loaded `ssti` + `cmdi` canary without reopening that door.
  `request_budget` went 500 → 600 (not 700).
- **`_TIME_BASED_SLEEP_CAP` stayed 8.** It is now enabled when `time_based_sqli`
  **or** `time_based_cmdi` is on (`engine.py`), and `cmdi._time`'s `slow` /
  confirm sends draw on it via `time_based=True` exactly like `sqli-time`.
- **`_BASE_ORDER`** = `("xss", "sqli-error", "sqli-boolean", "traversal",
  "redirect", "ssti", "sqli-time", "cmdi", "ssrf")` — `ssti` before `sqli-time`,
  `cmdi` after it, `ssrf` still last.
- **The Windows echo branch gained a `marker in baseline` guard** — without it a
  baseline that already echoed the marker string produced a false MEDIUM hit
  (caught by a unit test).
- **The fixture `/greet` endpoint is both SSTI- and reflected-XSS-vulnerable** on
  the insecure profile (`jinja2.Template("Hi " + name).render()` renders the
  markup too — realistic: template injection implies output injection). The
  hardened `_greet_hardened` needs `jinja2.Template(src, autoescape=True)` —
  Jinja's bare `Template` does **not** autoescape, so `{{ name }}` alone would
  have been a reflected-XSS false positive on the *hardened* profile.
- **`SSTI_ENGINE_PROBE`** is a `%s` template (`"%s{{7*'7'}}"`), not a `.format`
  one — brace-escaping `{{7*'7'}}` through `str.format` is unreadable. The
  stage-2 arithmetic payloads are built by `payloads.arith_payloads(marker, a, b)`
  returning f-strings for the same reason.
- **The integration `scan` fixture's active runs now pass `max_pages = 90`** so
  the stored-XSS re-crawl (`min(_STORED_REFETCH_CAP=60, max_pages)`) has room to
  walk past the extra guestbook entries the wider injection pass creates. Test
  infra only — no product default changed.
- **pytest:** 610 at spec 010/009 close → **639** at 011 close (unit: +9 cmdi,
  +7 ssti, +1 points, +1 config, +2 CLI, +3 engine, +1 checks, +2 orchestrator;
  integration: +4). `pages_scanned` 12 → 14 (the `/ping` + `/greet` links).
- **No API / UI / reporter / migration change** — as designed. `import-linter`
  contracts unchanged.
- **Manual verification:** an Active scan of the fixture reports
  `injection.cmdi.os` (CRITICAL, param `host`, `wv…=<product>` in evidence) and
  `injection.ssti` (HIGH, param `name`, engine "Jinja2/Nunjucks"); the hardened
  profile reports neither; `webvigil list-checks` shows both ids;
  `--no-time-based-cmdi` skips the sleep payloads.
