---
feature: In-band RCE injection — OS command injection (echo + time-based) and SSTI (Active Mode)
status: done
date: 2026-09-08
related:
  - 006-active-injection/requirements.md
  - 009-ssrf/requirements.md
origin: conception
---

# 011 — In-band RCE injection (command injection, SSTI)

## Context and problem

Spec 006 shipped the first `ACTIVE` checks and the machinery they run on: the
`InjectionScanner` orchestrator pass enumerates injection points (query params +
fuzzable form fields), takes one shared `Baseline` per point, and fans per-class
detectors under one shared `ActiveBudget`; thin `injection.*` checks turn the
resulting `InjectionHit`s into findings. 008 (stored XSS) and 009 (in-band SSRF)
extended that pass without changing its shape.

**Two server-side injection classes that lead directly to remote code execution
are still entirely uncovered, and both are detectable in-band:**

- **OS command injection** — OWASP A03:2021, CWE-78. A parameter whose value is
  concatenated into a shell command (`os.system`, `subprocess(..., shell=True)`,
  backticks, `Runtime.exec` with `sh -c`) lets an attacker append their own
  command with a shell metacharacter (`;`, `|`, `&`, `` ` ``, `$(...)`, a
  newline). It is proved **in-band** two ways: an **echo** payload that makes the
  shell compute something the application cannot produce by mere reflection (an
  arithmetic expansion next to a per-request marker), or a **time-based** payload
  (`sleep`, `ping -n`) that delays the response by a chosen number of seconds
  while a zero-delay control returns fast — the same technique WebVigil already
  uses for blind SQLi.
- **Server-side template injection (SSTI)** — CWE-1336 / CWE-94. A parameter
  concatenated into *template source* rather than passed as a template *variable*
  (`Template("Hello " + name).render()`) is evaluated by the engine. Most
  server-side engines (Jinja2, Twig, Freemarker, Velocity, Smarty, ERB) expose
  enough of the host language to reach code execution. It is proved **in-band**
  by a polyglot probe that draws a template error, then an **arithmetic** payload
  (`{{<a>*<b>}}`, `${<a>*<b>}`, `<%= <a>*<b> %>`, …) whose computed product
  appears in the response glued to a per-request marker.

006 explicitly deferred "OS command injection, XXE, SSTI" as never in its line.
This spec takes the two of those three that fit WebVigil's philosophy unchanged —
**in-band, no headless browser, no out-of-band collaborator**. XXE stays deferred
to 012 (protocol/parser injection).

### Why not blind / OAST

A command injection with **no output and no timing signal** (the classic
`; curl http://attacker/`) can only be caught with a hosted OAST collaborator — a
server WebVigil runs, with a public domain and DNS/HTTP ports, that the target
calls back to. That crosses the standing rule that the engine talks only to the
target and the repo-only distribution model (see `docs/notes/why-not-oast.md`,
and the identical call made for blind SSRF in spec 009). 011 ships only the
signals it can prove from the target's own response; the **time-based** detector
is the in-band substitute for the blind case, exactly as `injection.sqli.time-based`
is for blind SQLi. Truly blind command injection stays a documented non-goal.

### Where it sits

```
webvigil.checks.injection                     (Category.INJECTION, mode = ACTIVE)
       ├── injection.xss.reflected      [006]
       ├── injection.sqli.*             [006]
       ├── injection.traversal.path     [006]
       ├── injection.redirect.open      [006]
       ├── injection.xss.stored         [008]
       ├── injection.ssrf.*             [009]
       ├── injection.cmdi.os            [011]  ← shell metacharacter break proved by an
       │                                         arithmetic echo, or by an injected delay
       └── injection.ssti               [011]  ← parameter reaches template source, proved
                                                 by an arithmetic expansion next to a marker

detect/cmdi.py   new detectors: detect_echo (arithmetic + marker) and detect_time
                 (sleep / ping delay, confirmed against a 0-delay control — like sqli)
detect/ssti.py   new detector: polyglot error probe, then per-engine arithmetic payloads;
                 best-effort engine identification (like sqli-error names the DBMS)
payloads.py      + CMDI_* and SSTI_* payload sets and signature regexes (static, in-repo)
engine.py        + "cmdi-echo" / "cmdi-time" / "ssti" in the detector table, _BASE_ORDER,
                 KIND_BY_CHECK_ID; an is_commandlike(point) heuristic (like is_pathlike)
config.py        + [injection] time_based_cmdi (default true), mirroring time_based_sqli
```

Reuses the 006 machinery unchanged: the same `InjectionScanner` pass, the same
`ActiveBudget` (the time-based detector draws on the existing time sub-budget),
the same `DetectCtx.send`, the same `_InjectionCheck` base. **No new orchestrator
pass** (unlike 008). **No new consent mechanism** — command-injection and SSTI
payloads are the reason `--mode active --authorized-by` exists. **No change to
`webvigil.api` or the dashboard** — `injection.cmdi.os` / `injection.ssti`
findings persist and render through the existing plumbing and the new ids surface
automatically (as 006/009 established).

The engine still imports nothing from `webvigil.cli` / `webvigil.api` / `web/`;
detection is `re` + the existing HTTP layer; no new runtime dependency.
`import-linter` unchanged.

## Goals

- Two new `ACTIVE` checks — `injection.cmdi.os` (CRITICAL, CWE-78) and
  `injection.ssti` (HIGH, CWE-1336) — `category = INJECTION`, gated by the
  existing `--mode active --authorized-by`, no new gate.
- A **command-injection echo detector**: for each injection point, break out of
  the assumed shell context with a documented set of separators / substitutions
  (`;`, `\n` / `%0a`, `|`, `||`, `&&`, `&`, `` `…` ``, `$(…)`, `${IFS}` for
  space-filtered contexts) wrapping a command that emits `wv<token>=<a*b>` — a
  per-request marker glued to the product of two random operands. A hit needs
  `wv<token>=<product>` in the response, **absent from the baseline**; the
  literal unevaluated `$((a*b))` echoed back is **not** a hit.
- A **command-injection time detector**: `sleep <d>` / `$(sleep <d>)` /
  `` `sleep <d>` `` (POSIX) and `ping -n <d+1> 127.0.0.1` / `timeout /t <d>`
  (Windows `cmd`), confirmed like `injection.sqli.time-based` — the injected
  request runs ≥ ~`d` s slower than the baseline **and** a `sleep 0` control
  returns fast **and** a second probe with a different `d` scales. Draws on the
  shared time sub-budget; gated by `[injection] time_based_cmdi` (default on),
  mirroring `time_based_sqli`.
- An **SSTI detector**: a stage-1 polyglot probe (`${{<%[%'"}}%\`) that looks for
  a template-engine error signature absent from the baseline (Jinja2
  `jinja2.exceptions` / `TemplateSyntaxError`, Twig `Twig\Error`, Freemarker
  `FreeMarker template error`, Velocity `org.apache.velocity`, Smarty
  `Smarty error`, ERB `(erb):`), then stage-2 per-engine arithmetic payloads
  (`wv<token>{{<a>*<b>}}`, `wv<token>${<a>*<b>}`, `wv<token><%= <a>*<b> %>`,
  `wv<token>#{<a>*<b>}`, `wv<token>${{<a>*<b>}}`, `wv<token>*{<a>*<b>}`,
  `wv<token>@(<a>*<b>)`, `wv<token>{<a>*<b>}`). A hit needs the marker **glued to
  the computed product** (`wv<token><product>`) in the response, absent from the
  baseline.
- **Best-effort engine identification** (like `injection.sqli.error-based` names
  the DBMS): a confirm payload `{{7*'7'}}` → `7777777` ⇒ Jinja2 / Nunjucks;
  `49` ⇒ Twig; `${7*7}`-only evaluation ⇒ Freemarker / Velocity. The engine name
  rides the finding title when known, "unknown engine" otherwise.
- A **command-shaped-parameter heuristic** (`is_commandlike`) so params named
  `cmd`, `exec`, `command`, `run`, `ping`, `host`, `ip`, `domain`, `query`,
  `search`, `name`, `feature`, `option`, `arg`, `code`, `template`, `preview` are
  tested first within budget — mirroring 006's `is_pathlike` / `is_redirect_name`
  / 009's `is_urllike`.
- **False-positive discipline**: every proof must be absent from the point's
  baseline; the echo / SSTI proof needs the marker-plus-computed-value, never a
  reflected literal; the time proof needs the 0-delay control and the scaling
  confirmation. The hardened fixture profile yields **zero** `injection.cmdi.*` /
  `injection.ssti` findings.
- **Fixture-app coverage**: the insecure profile gains a shell-backed endpoint
  and a template-source endpoint; the hardened profile gains the safe
  equivalents. For determinism and offline CI, the shell endpoint *simulates*
  (recognises `sleep N` → `asyncio.sleep(N)`, recognises the arithmetic-echo
  pattern → emits the product) exactly as the 006 fixture simulates `SLEEP(n)`;
  the template endpoint uses a real Jinja2 `Template` (already a runtime
  dependency), so `{{a*b}}` genuinely evaluates with no shell involved.
- **Docs**: a "Command injection & SSTI" section in `docs/active-injection.md`
  (the two techniques, why time-based is the blind fallback, the Windows caveat,
  why truly-blind command injection still needs a collaborator), plus the usual
  README / CLAUDE / specs-roadmap updates.

## Non-goals

- **Truly blind command injection** — a shell command with no output *and* no
  timing signal (`; curl http://x/`, `; nslookup x`). Needs a hosted OAST
  collaborator, which crosses "the engine talks only to the target" and the
  repo-only distribution (identical to the blind-SSRF call in spec 009). The
  time-based detector is the in-band substitute; the rest is a documented
  non-goal, "pair with your own collaborator".
- **Exploitation.** A confirmed command injection is proved with one arithmetic
  echo or one measured delay; a confirmed SSTI with one arithmetic evaluation.
  WebVigil does not read files past the marker, enumerate the environment, drop a
  shell, or walk a template-engine sandbox-escape gadget chain (tplmap
  territory).
- **Client-side / DOM template injection** (AngularJS `{{}}`, Vue, Handlebars in
  the browser). Needs JavaScript execution — out since spec 001, same as DOM XSS.
- **Server-side code injection into a bare language `eval()`** that is not a
  template engine (PHP `eval`, Node `vm`, Ruby `eval`, Python `exec`) and
  **expression-language injection** (Spring SpEL, Struts/OGNL, MVEL). Adjacent
  and arithmetic-detectable, but a distinct surface; candidate for a later spec.
- **XXE / XML external entities.** Deferred to spec 012 (protocol/parser
  injection).
- **LDAP / XPath / NoSQL / SSI / CRLF injection.** Separate classes; CRLF is 012,
  the rest are later candidates.
- **Argument / option injection** (controlling the flags of a fixed binary
  rather than adding a command). Best-effort only through the echo separators; no
  dedicated technique.
- **New HTTP verbs or a new crawl.** Reuses 006's `GET` / `POST` injection points
  parsed from already-crawled bodies.
- **WAF detection / evasion / payload polymorphism.** The payload sets are small,
  static, in-repo, no mutation engine — the posture of every 006/009 detector.
- **Windows-shell parity with POSIX.** The primary target is POSIX shells (the
  dominant server case). Windows `cmd` is covered by the time-based `ping` /
  `timeout` payloads and a lower-confidence `& echo` echo variant; PowerShell-only
  constructs are out (Resolved decision 3).
- **Parameter mining.** Only parameters the target actually exposes are fuzzed.
- **Web API / dashboard changes.** Engine + CLI only, following 006 / 009.

## Personas

| Persona | Needs from 011 |
|---|---|
| **Security-conscious developer** | "Does my `/ping?host=` endpoint shell out? Does my `/greet?name=` template concatenate?" — a CRITICAL / HIGH finding that names the parameter, the payload that worked, and the proof (a computed value the app could not have echoed, or a measured delay). |
| **Pentester / consultant** | On an authorized engagement, a fast in-band first pass over command injection and SSTI across every crawled parameter, with confirmation rounds so the report is not full of maybes, leaving the blind cases for a collaborator. |
| **CI pipeline author** | A CRITICAL SARIF result when a build introduces a shell concatenation, so `--fail-on critical` blocks the deploy — no external service in the loop. |
| **Check author / contributor** | `detect/cmdi.py` as the reference for "prove code execution from an arithmetic side effect" and `detect/ssti.py` for a two-stage probe-then-confirm detector with engine identification. |

## Functional requirements

### Detection

**RF-01 — New detectors in the injection pass**
- **Given** an Active scan with `injection.cmdi.os` and/or `injection.ssti`
  selected, **when** the `InjectionScanner` runs, **then** the `cmdi-echo`,
  `cmdi-time`, and `ssti` detectors are fanned for each injection point alongside
  the 006/009 detectors, drawing on the same shared `ActiveBudget` and the
  point's shared `Baseline`.
- **Given** a detector, **then** it issues its payloads through `DetectCtx.send`
  (scope guard, concurrency cap, per-host delay, timeout, per-point cap all
  apply) and stops as soon as `send` returns `None` (budget reached), like every
  006 detector.
- **Given** every `injection.cmdi.*` / `injection.ssti` check is disabled, **then**
  the corresponding detector kinds do not run and no command-injection / SSTI
  payload is sent (parallel to 006 RF-12 / 009 RF-11).

**RF-02 — Command-injection echo detection** (`injection.cmdi.os`)
- **Given** an injection point, **when** the `cmdi-echo` detector runs, **then**
  it sends, for each documented separator / substitution, a payload that appends
  to the original value a command emitting `wv<token>=$((<a>*<b>))` where
  `<token>` is a per-request `secrets.token_hex` and `<a>`, `<b>` are random
  two-digit operands (so the product is not a hard-coded constant and is unlikely
  to occur naturally).
- **Given** the response contains `wv<token>=<product>` (the marker glued to the
  *computed* product) and the baseline does not, **then** it emits a `cmdi-echo`
  hit — `severity = CRITICAL`, `confidence = HIGH` — naming the parameter and the
  separator that worked.
- **Given** the response contains only `wv<token>` without the computed product,
  **or** the literal unevaluated `$((<a>*<b>))` string, **then** it is **not** a
  hit (the app reflected the payload, it did not run it).
- **Given** the POSIX separators do not fire, **when** budget remains, **then** a
  Windows `cmd` variant (`& echo wv<token> & set /a <a>*<b>`) is tried; a match on
  the marker followed by the product emits a `cmdi-echo` hit at
  `confidence = MEDIUM`.

**RF-03 — Command-injection time-based detection** (`injection.cmdi.os`)
- **Given** `[injection] time_based_cmdi` is on (default) and `injection.cmdi.os`
  is selected, **when** the `cmdi-time` detector runs, **then** it sends a
  delay payload (`;sleep <d>`, `$(sleep <d>)`, `` `sleep <d>` ``, `|sleep <d>`,
  `%0asleep <d>`, and Windows `&ping -n <d+1> 127.0.0.1`, `&timeout /t <d>`) with
  `<d>` = `[injection] time_based_delay_s`, charged against the shared time
  sub-budget (`take_time_based`).
- **Given** the injected request runs ≥ ~`<d>` s slower than the baseline **and**
  a `sleep 0` / `ping -n 1` control returns fast **and** a second probe with a
  different `<d>` scales proportionally, **then** it emits a `cmdi-time` hit —
  `severity = CRITICAL`, `confidence = HIGH` — with the timings in evidence.
- **Given** the target is uniformly slow (baseline and control also take ~`<d>`),
  **then** **nothing** is reported — same discipline as `injection.sqli.time-based`.
- **Given** `[injection] time_based_cmdi` is off, **then** no `sleep` / `ping`
  payload is sent; the echo detector still runs.

**RF-04 — Command-shaped-parameter priority**
- **Given** the enumerated injection points, **when** the detector order is
  chosen for a point, **then** a point whose **name** is command-associated
  (`cmd`, `command`, `exec`, `execute`, `run`, `ping`, `host`, `hostname`, `ip`,
  `addr`, `domain`, `dns`, `lookup`, `query`, `search`, `q`, `name`, `file`,
  `path`, `arg`, `args`, `option`, `opt`, `code`, `template`, `tpl`, `preview`,
  `format`, `func`, `action`) is tested by `cmdi-echo` / `cmdi-time` / `ssti`
  **first** within budget — mirroring 006 / 009.
- **Given** a point that matches neither name nor value shape, **then** it is
  still tested if budget remains, at lower priority (a short canary set rather
  than the full payload list, as 009's SSRF detector does for non-URL points).

**RF-05 — SSTI polyglot probe (stage 1)**
- **Given** an injection point, **when** the `ssti` detector runs, **then** it
  first sends the polyglot `${{<%[%'"}}%\` and checks the response for a
  template-engine **error signature** (documented per engine) absent from the
  baseline.
- **Given** an error signature matches, **then** the engine name is recorded and
  stage 2 runs with that engine's payload first; **given** none matches, **then**
  stage 2 still runs (an engine can inject without erroring on the polyglot),
  budget permitting.

**RF-06 — SSTI arithmetic confirmation (stage 2)**
- **Given** stage 2, **when** it runs, **then** it sends the per-engine
  arithmetic payloads wrapping `<a>*<b>` (random two-digit operands) behind the
  `wv<token>` marker.
- **Given** the response contains `wv<token><product>` (marker glued to the
  *computed* product) absent from the baseline, **then** it emits an `ssti` hit —
  `severity = HIGH`, `confidence = HIGH` — naming the parameter and, when known,
  the engine.
- **Given** a confirm payload `{{7*'7'}}` returns `7777777` (string repetition),
  **then** the engine is reported as Jinja2 / Nunjucks; **given** it returns
  `49`, Twig; the finding title reflects this.
- **Given** the payload is echoed unevaluated (`{{<a>*<b>}}` literally in the
  body) or the product appears without the adjacent marker, **then** it is
  **not** a hit.

**RF-07 — Hit shape**
- **Given** a `cmdi-echo` / `cmdi-time` / `ssti` hit, **then** the `InjectionHit`
  carries `kind` (`"cmdi-echo"` / `"cmdi-time"` / `"ssti"`), the matching
  `check_id`, `method` / `url` (the injection point base URL) / `param`, the
  chosen `severity` and `confidence`, a `title` naming the parameter and what was
  proved, the `payload` that worked, and `evidence` of: the injection point, the
  payload, and the proof (the computed marker line / the baseline-vs-injected
  timings / the template error + the computed product).

### Checks

**RF-08 — `injection.cmdi.os`**
- **Given** the check registry, **then** `injection.cmdi.os` is registered —
  `category = INJECTION`, `mode = ACTIVE`, `default_severity = CRITICAL`,
  `cwe = (78, 77)`, references to the OWASP Command Injection page and cheat
  sheet.
- **Given** an Active scan, **when** the pass produced a `cmdi-echo` **or**
  `cmdi-time` hit, **then** the check emits one finding per hit with the hit's
  severity / confidence, a `Location` carrying `method` / `url` / `param`, and a
  description matched to the proof (arithmetic side effect / injected delay).
- Both detector kinds feed this one check id; the mapping mechanics
  (`KIND_BY_CHECK_ID` currently one-to-one) are a design detail.

**RF-09 — `injection.ssti`**
- **Given** the check registry, **then** `injection.ssti` is registered —
  `category = INJECTION`, `mode = ACTIVE`, `default_severity = HIGH`,
  `cwe = (1336, 94)`, references to the OWASP SSTI page and the PortSwigger SSTI
  research.
- **Given** an Active scan, **when** the pass produced an `ssti` hit, **then**
  the check emits one finding per hit, its description explaining that the
  parameter reaches template source and the engine evaluated an expression, with
  the engine named when identified.

**RF-10 — `list-checks` and suppression**
- **Given** `webvigil list-checks`, **then** `injection.cmdi.os` and
  `injection.ssti` appear with `INJECTION` / `active` / their default severity.
- **Given** `[checks] disabled = ["injection.cmdi.os"]` (and/or
  `"injection.ssti"`), **then** that check does not run; if `injection.cmdi.os`
  is disabled the `cmdi-echo` and `cmdi-time` detectors do not run at all — same
  gating as every 006 detector.

### Config and CLI

**RF-11 — Minimal surface**
- **Given** `[injection]`, **then** it gains `time_based_cmdi: bool = True`,
  documented next to `time_based_sqli`. The shared time sub-budget
  (`_TIME_BASED_SLEEP_CAP`) is enabled when **either** `time_based_sqli` **or**
  `time_based_cmdi` is on.
- **Given** the CLI, **then** it gains `--time-based-cmdi / --no-time-based-cmdi`
  mirroring the existing `--time-based-sqli / --no-time-based-sqli`; no other new
  flag (Open question — this could also be config-only).
- **Given** `--fail-on <severity>`, **then** it compares the new findings by
  severity exactly as today; no new exit code.
- **Given** the human-readable Active-scan summary, **then** the existing
  "F injection finding(s) across P injection points, R crafted requests" line
  already counts the new findings and requests — no format change.

### Fixture app and tests

**RF-12 — Vulnerable and hardened endpoints** (mirrors 006 RF-20 / 009 RF-12)
- **Given** the fixture app's **insecure** profile, **then** it exposes:
  - `GET /ping?host=…` — simulates `os.system(f"ping -c 1 {host}")`: it reflects
    the raw value, and it *interprets* the injection payloads for deterministic
    offline testing — a `sleep <n>` / `ping -n <n>` substring → `await
    asyncio.sleep(n)`; an `echo wv<tok>=$((a*b))` / `set /a a*b` pattern →
    emit `wv<tok>=<product>`; otherwise a canned `PING host` line.
  - `GET /greet?name=…` — renders `jinja2.Template("<p>Hi " + name +
    "</p>").render()` (name concatenated into template source). Real Jinja2, no
    shell, fully deterministic.
- **Given** the **hardened** profile, **then** the same routes are safe:
  `/ping` validates `host` against `^[A-Za-z0-9.\-]+$` (or returns a canned line
  with no interpretation); `/greet` renders `Template("<p>Hi {{ name }}</p>")
  .render(name=name)` (variable, not source). Both profiles link the two routes
  from the shared link block so a hardened Active scan fuzzes them and finds
  nothing.
- **Given** an integration Active scan of the insecure profile, **then**
  `injection.cmdi.os` (from the echo proof, and from the time proof when
  `time_based_cmdi` is on) and `injection.ssti` findings are present with the
  expected parameter, method, and evidence; **given** the hardened profile,
  **then** **zero** `injection.cmdi.*` / `injection.ssti` findings.

**RF-13 — Integration tests**
- Active scan of the insecure profile → the two checks fire with the expected
  ids / severities / `location.param` / `method`.
- Passive scan of the insecure profile → none of them fire and no crafted
  request is issued.
- Active scan of the hardened profile → zero `injection.cmdi.*` / `injection.ssti`
  findings (false-positive guard, mirrors 006 RF-21 / 009 RF-12).
- The scan is deterministic across repeated runs (same findings, same
  fingerprints) and stays within the request budget.

**RF-14 — Unit tests**
- `cmdi-echo`: arithmetic-marker match (per separator); "payload echoed but not
  executed → no hit"; literal `$((a*b))` → no hit; baseline suppression; the
  Windows `& echo … & set /a` variant.
- `cmdi-time`: injected-delay positive; uniformly-slow negative; the `sleep 0`
  control; the different-`d` scaling confirmation; `time_based_cmdi` off → no
  payload.
- `ssti`: stage-1 error signature per engine; stage-2 arithmetic marker
  adjacency; echoed-literal negative; product-without-marker negative; the
  `{{7*'7'}}` engine-identification branch (Jinja2 vs Twig).
- `is_commandlike` name / value classification; the canary vs full-set routing
  for non-command-shaped points.

### Reporting

**RF-15 — Reporters unchanged**
- No reporter gains a field or a section. `injection.cmdi.os` / `injection.ssti`
  findings flow through the same `_InjectionCheck` → `Finding` path as every
  006/009 check; `CWE-78` / `CWE-1336` ride the existing `cwe` field. A saved
  canonical JSON re-renders offline exactly as before.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives entirely in `webvigil.checks.injection` (`detect/cmdi.py`,
`detect/ssti.py`, additions to `payloads.py` / `engine.py` / `points.py` /
`checks.py`) plus one field in `webvigil.core.config` and one flag in
`webvigil.cli`. Detection is `re` + the existing HTTP layer; **no new runtime
dependency** (the fixture's Jinja2 use is a dependency the project already has,
and lives under `tests/`). Nothing imported from `webvigil.cli` / `webvigil.api`
/ `web/` by the engine. `import-linter` unchanged.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy`
covering the new modules. No `web` gate work (engine + CLI only).

**RNF-03 — Safe by default**
A passive scan is byte-for-byte unchanged and issues no crafted request. The new
detectors run only past the `--mode active --authorized-by` gate. Every payload
is a *value* placed in an in-scope target parameter; WebVigil issues only
`GET` / `POST` to the target host and writes nothing persistent. The time-based
payloads are bounded by `time_based_delay_s` (below `timeout_s`) and the shared
time sub-budget.

**RNF-04 — Bounded work**
The `cmdi-echo` / `cmdi-time` / `ssti` requests are drawn from the shared
`ActiveBudget` and the per-point cap (`_PER_POINT_REQUEST_CAP`). The design phase
validates the per-point cap and `request_budget` defaults against the fixture
app's actual request count with the three new detectors added, and may raise them
with rationale (as 006 Resolved decision 9 did). Hitting a cap is a scan warning,
never an error.

**RNF-05 — Determinism and false-positive discipline**
- Given the same target responses, the same findings / evidence / ordering across
  runs. The per-request `token` and random operands guarantee marker uniqueness
  but do not change *which* findings are produced; `fingerprint` is keyed on
  `check_id` + URL + method + parameter, not the payload (006 RNF-04).
- Every proof must be **absent from the point's baseline**.
- The echo / SSTI proof requires the marker glued to a *computed* value, never a
  reflected literal.
- The time proof requires the 0-delay control and the different-`d` scaling
  confirmation.
- The hardened fixture profile yields zero `injection.cmdi.*` / `injection.ssti`
  findings.

**RNF-06 — Non-destructive**
The detectors issue `GET` (and `POST` when the point is a POST form field), never
other verbs, and write nothing to the target. `sleep` / `ping` payloads consume
target CPU/time only for the bounded delay.

**RNF-07 — Python support**
CPython 3.12 and 3.13 (existing CI matrix).

**RNF-08 — Docs**
`docs/active-injection.md` gains a "Command injection & SSTI" section: the two
checks, the echo and time-based techniques, the polyglot-then-arithmetic SSTI
flow, best-effort engine identification, the Windows caveat, and an explicit
statement that **truly blind command injection is not covered and needs a
collaborator** (cross-linking `docs/notes/why-not-oast.md`). The `docs/active-injection.md`
"What it does not do" list, `README.md` coverage table, `CLAUDE.md` layer-3
injection paragraph, and `specs/README.md` roadmap are updated; 011 moves
`draft → approved → in progress → done`.

## Resolved decisions

Settled with Ryan on 2026-09-08 (approved the requirements with the proposed
resolutions unchanged):

1. **One check for command injection, not two.** `injection.cmdi.os` (CRITICAL,
   CWE-78) fed by both the `cmdi-echo` and `cmdi-time` detector kinds — a blind
   time-based command injection is the *same vulnerability at the same severity*
   as an echo-proved one, unlike SQLi where error / boolean / time are genuinely
   different techniques and confidence levels worth separate ids. *Proposed:
   one check.*
2. **SSTI severity = HIGH.** Matches OWASP ZAP's SSTI rule. A confirmed
   arithmetic evaluation in a known-dangerous engine is close to RCE, but the
   default stays HIGH (confidence HIGH) rather than CRITICAL, and the finding
   text makes the RCE potential explicit. *Proposed: HIGH.*
3. **POSIX-primary, Windows via time-based + a low-confidence echo variant.** Full
   Windows-`cmd` echo parity (arithmetic via `set /a` inside `for /f`) adds
   payload noise for a smaller server population; PowerShell is out. Windows
   command injection is still caught by the `ping -n` / `timeout` time-based
   payloads and a `& echo … & set /a` variant reported at MEDIUM confidence.
   *Proposed: as described.*
4. **Server-side code injection into a bare `eval()`** (PHP / Node / Ruby) and
   **expression-language injection** (SpEL / OGNL) are **deferred**, not folded
   into 011. They are arithmetic-detectable and adjacent, but a distinct surface;
   they can be a small follow-up once `injection.ssti` exists. *Proposed: defer.*
5. **`time_based_cmdi` config + `--time-based-cmdi` flag** (default on), mirroring
   the SQLi pair exactly. The alternative is config-only with no CLI flag.
   *Proposed: add the parallel flag.*
6. **`request_budget` / per-point cap.** The design phase measures the fixture
   run with the new detectors added and bumps `_PER_POINT_REQUEST_CAP` (currently
   30) and/or `request_budget` (currently 500) if a command-shaped point would
   otherwise starve — decided with numbers in design, not now.

## Open questions

None. Ready for `/spec design`.
