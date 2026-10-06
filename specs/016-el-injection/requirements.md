---
feature: In-band expression-language injection — SpEL, OGNL, JEXL, MVEL, Unified EL (Active Mode)
status: done
date: 2026-10-06
related:
  - 006-active-injection/requirements.md
  - 011-rce-injection/requirements.md
  - 014-file-upload/requirements.md
origin: conception
---

# 016 — In-band expression-language injection

## Context and problem

Issue #56 asks for expression-language (EL) injection detection: a parameter that is
handed to a Java-world expression evaluator (Spring **SpEL**, Struts **OGNL**, Apache
**JEXL**, **MVEL**, the servlet **Unified EL** behind JSP / JSF) and evaluated server-side.
The docs list it as deferred ("spec-sized surface of its own") since spec 011.

**What WebVigil already does, and what it misses.** Spec 011's `ssti` detector is not
template-engine-specific in how it proves evaluation: stage 2 appends `wv<token>` glued to
an arithmetic expression in eight delimiter forms and needs `wv<token><a*b>` (the
*computed* product) in the response, absent from the baseline. Three of those forms are EL
delimiters — `${a*b}`, `#{a*b}` and `*{a*b}` — so an endpoint that evaluates SpEL / JSP EL
through any of them is **already reported today**, as `injection.ssti` ("engine unknown").
Reading the code, the gaps are:

1. **OGNL's `%{a*b}` form is never sent.** Struts evaluates `%{...}` in tag attributes,
   so a Struts reflection point is invisible to the current payload set.
2. **`#{}` and `*{}` only run on command-shaped parameter names.** A non-command-shaped
   point gets just the first four payloads (`_CANARY_LIMIT = 4`), so a SpEL endpoint on
   `?filter=` or `?msg=` is missed unless the name happens to match.
3. **Bare-expression contexts are not covered.** When the parameter *is* the expression
   (`?expr=3*4`, a search / sort / rule filter handed to `parser.parseExpression()`) there
   is no delimiter to find; the marker has to be built with string concatenation
   (`'wv<token>'+(a*b)`).
4. **No EL error signatures.** `SSTI_ERROR_SIGNATURES` knows Jinja2, Twig, Freemarker,
   Velocity, Smarty, Mako, ERB and Handlebars, but not `SpelEvaluationException`,
   `ognl.OgnlException`, `JexlException`, `org.mvel2`, `javax.el.ELException`.
5. **The finding says the wrong thing.** "Server-side template injection (engine unknown)"
   sends a developer looking for a template; the real problem is an expression evaluator
   that, in SpEL and OGNL, can reach arbitrary static methods — remote code execution
   (CWE-917; the Spring4Shell-class and Struts S2-0xx-class bugs). The remediation is
   different (stop evaluating user input; use a `SimpleEvaluationContext` / OGNL member
   access restrictions), and so is the severity.
6. **Nothing separates "evaluates arithmetic" from "reaches the type system".** The first
   is a sandboxed calculator; the second is RCE. A pure, side-effect-free static call
   (`T(java.lang.Math).abs(-n)` in SpEL, `@java.lang.Math@abs(-n)` in OGNL) tells them apart
   without executing anything harmful.

`eval()` code injection (PHP `eval`, Node `vm`, Ruby / Python `eval`) is the other half of
the deferred row. It is a different surface — the payload syntax depends on the host
language and on whether the value lands in a string literal or a bare expression — and the
issue's proposal is about EL only. See **Open question 1**.

### Where it sits

```
webvigil.checks.injection                     (Category.INJECTION, mode = ACTIVE)
       ├── injection.ssti               [011]  ← parameter reaches template source
       └── injection.el                 [016]  ← parameter reaches an expression evaluator,
                                                 dialect named; CRITICAL when the type
                                                 system is reachable

detect/el.py     new detector: EL delimiters (incl. OGNL %{ } and the bare-expression form),
                 EL error signatures, dialect identification
payloads.py      + EL_* payload sets and signature regexes (static, in-repo)
engine.py        + "el" in the detector table, _BASE_ORDER, KIND_BY_CHECK_ID
points.py        + is_exprlike(point) heuristic (like is_commandlike)
checks.py        + ExpressionLanguageInjectionCheck (id "injection.el")
```

Reuses the 006 machinery unchanged: the same `InjectionScanner` pass, the same
`ActiveBudget`, `Baseline`, `DetectCtx.send` and `_InjectionCheck` base. **No new
orchestrator pass.** **No new consent mechanism** — the payloads are the reason
`--mode active --authorized-by` exists. **No change to `webvigil.api` or the dashboard** —
`injection.el` findings persist and render through the existing plumbing, as
`injection.ssti` did in 011. The engine still imports nothing from `webvigil.cli` /
`webvigil.api` / `web/`; no new runtime dependency.

## Goals

- One new `ACTIVE` check, `injection.el` (HIGH by default, CRITICAL when the type system
  is proved reachable; CWE-917, CWE-94), gated by the existing
  `--mode active --authorized-by`, with no new gate, flag or config key.
- An **EL detector** that proves evaluation **in-band** with the 011 discipline: a
  per-request marker glued to the *computed* product of two random two-digit operands,
  absent from the baseline. Delimiter forms: `${…}`, `#{…}`, `*{…}`, **`%{…}` (OGNL,
  new)**, and the **bare-expression form** `'wv<token>'+(a*b)` (new) for parameters that
  are themselves an expression.
- **EL error signatures** (SpEL, OGNL, JEXL, MVEL, Unified EL) absent from the baseline,
  from the shared polyglot probe plus one unterminated-expression probe, so a point that
  errors without evaluating is still reported, at lower confidence.
- **Dialect identification** by the evidence, never by guessing: a pure static-call probe
  names SpEL and OGNL and upgrades the finding to CRITICAL; an error signature names
  JEXL / MVEL / Unified EL; arithmetic alone is "expression language (dialect unknown)".
- **No double reporting.** The same proof on the same point yields one finding. When the
  EL detector identifies an EL dialect, the finding is `injection.el`; `injection.ssti`
  keeps every behaviour it has today for template engines.
- An **expression-shaped-parameter heuristic** (`is_exprlike`) so parameters named
  `expr`, `expression`, `filter`, `sort`, `order`, `where`, `condition`, `rule`,
  `formula`, `msg`, `message`, `title`, `el`, … are tested first and get the full payload
  set, mirroring 006's `is_pathlike` and 011's `is_commandlike`.
- **False-positive discipline**: every proof absent from the baseline; the literal
  `${a*b}` echoed back is never a hit; the hardened fixture profile yields **zero**
  `injection.el` findings.
- **Fixture-app coverage** for both profiles, deterministic and offline, with no JVM and
  no new dependency (a stdlib `ast`-based arithmetic evaluator simulates the sink, the same
  "fixture simulates the sink" pattern as 006's `SLEEP(n)` and 011's `/ping`).
- **Docs** corrected: the `docs/active-injection.md` coverage table stops listing EL as
  deferred, the checks table and a new "Expression-language injection" section are added,
  plus the usual README / CLAUDE / specs-roadmap updates.

## Non-goals

- **`eval()` code injection** (PHP, Node, Ruby, Python). A distinct surface — see
  **Open question 1**. Until decided, it stays deferred and the docs row says so.
- **Exploitation.** A confirmed EL injection is proved with one arithmetic evaluation and,
  at most, one pure static call. WebVigil does not invoke `Runtime.exec` /
  `ProcessBuilder`, read files, reflect into classes, or walk a sandbox-escape gadget
  chain (that is tplmap / Metasploit territory).
- **Blind EL injection** — an expression whose result never reaches the response. It needs
  an out-of-band collaborator ([`docs/notes/why-not-oast.md`](../../docs/notes/why-not-oast.md)).
- **Non-parameter vectors.** Struts S2-045 arrives through the `Content-Type` header, and
  EL also reaches through other headers and cookies. 016 fuzzes the injection points 006
  already enumerates (query params, `<form>` fields, OpenAPI-seeded parameters) and nothing
  else.
- **Client-side expression injection** (AngularJS `{{…}}`, Vue). Needs JavaScript
  execution — out since spec 001, and already a 011 non-goal.
- **Template engines.** Jinja2, Twig, Freemarker, Velocity, Smarty, ERB and the rest stay
  with `injection.ssti`; 016 does not change which engine names that check reports.
- **WAF detection / evasion / payload polymorphism.** The payload sets are small, static,
  in-repo, with no mutation engine.
- **Web API / dashboard changes.** Engine only, following 006 / 011.

## Personas

| Persona | Needs from 016 |
|---|---|
| **Security-conscious developer** | "Does my Spring / Struts endpoint evaluate what the user types?" A finding that names the parameter, the EL dialect and the proof, and points at the right fix (`SimpleEvaluationContext`, OGNL member access) instead of "template injection". |
| **Pentester / consultant** | A fast in-band first pass over expression-evaluating parameters, with the CRITICAL / HIGH split telling them which hits to take straight to a manual exploit and which are sandboxed calculators. |
| **CI pipeline author** | A CRITICAL SARIF result when a build introduces an expression-evaluating sink, so `--fail-on critical` blocks the deploy with no external service in the loop. |
| **Check author / contributor** | `detect/el.py` as the reference for "prove evaluation, then classify the evaluator from the evidence". |

## Functional requirements

### Detection

#### RF-01 — New detector in the injection pass

- **Given** an Active scan with `injection.el` selected
  **When** the `InjectionScanner` runs
  **Then** the `el` detector is fanned for each injection point alongside the existing
  detectors, drawing on the same shared `ActiveBudget` and the point's shared `Baseline`.
- **Given** the detector
  **Then** it issues every payload through `DetectCtx.send` (scope guard, concurrency
  cap, per-host delay, timeout, per-point cap all apply) and stops as soon as `send`
  returns `None` (budget reached), like every 006 detector.
- **Given** `injection.el` is disabled
  **Then** the `el` detector does not run and no EL payload is sent (parallel to 011
  RF-01).

#### RF-02 — Arithmetic proof across EL delimiters

- **Given** an injection point
  **When** the `el` detector runs its arithmetic stage
  **Then** it appends to the original value `wv<token>` glued to `<a>*<b>` (random
  two-digit operands) wrapped in each EL delimiter form: `${…}`, `#{…}`, `*{…}`, and
  `%{…}` (OGNL).
- **Given** the parameter is itself an expression (no delimiter evaluated)
  **When** the bare-expression stage runs
  **Then** it sends `'wv<token>'+(<a>*<b>)` as the whole value (and a variant with a
  leading quote-close for a value placed inside a string literal), so a SpEL / OGNL /
  JEXL / MVEL evaluator returns `wv<token><product>`.
- **Given** the response contains `wv<token><product>` (the marker glued to the
  *computed* product) and the baseline does not
  **Then** it emits an `el` hit with `confidence = HIGH`, naming the parameter and the
  form that worked.
- **Given** the response echoes the payload unevaluated (the literal `${<a>*<b>}` in the
  body), or contains the product without the adjacent marker
  **Then** it is **not** a hit (the app reflected the payload, it did not run it).

#### RF-03 — Error-signature proof

- **Given** an injection point
  **When** the `el` detector sends the shared SSTI polyglot and an unterminated-expression
  probe (for example `${(` and `%{(`)
  **Then** it checks the responses for an EL error signature absent from the baseline:
  SpEL (`org.springframework.expression`, `SpelEvaluationException`,
  `SpelParseException`, `EL1xxxE` codes), OGNL (`ognl.OgnlException`,
  `ognl.ParseException`, `MethodFailedException`), JEXL (`org.apache.commons.jexl`,
  `JexlException`), MVEL (`org.mvel2`), Unified EL (`javax.el.` / `jakarta.el.`,
  `ELException`).
- **Given** a signature matches but no arithmetic proof follows
  **Then** it emits an `el` hit with `confidence = MEDIUM` (the evaluator is there; it
  rejected the input), `severity = HIGH`.
- **Given** the signature is also present in the baseline
  **Then** it is ignored (a page that always prints an EL stack trace is not a finding
  *about this parameter*).

#### RF-04 — Dialect identification and type-access probe

- **Given** an arithmetic hit in some delimiter form
  **When** the detector runs its identification stage
  **Then** it sends one pure static-call probe in that form — SpEL
  `T(java.lang.Math).abs(-<n>)`, OGNL `@java.lang.Math@abs(-<n>)` — glued to the marker.
- **Given** the SpEL probe returns `wv<token><n>`
  **Then** the dialect is **SpEL**, the type system is reachable, and the hit is upgraded
  to `severity = CRITICAL`. **Given** the OGNL probe does, the same with dialect **OGNL**.
- **Given** neither probe evaluates
  **Then** the hit keeps `severity = HIGH`, and the dialect is the one named by an error
  signature (JEXL, MVEL, Unified EL) when RF-03 matched, otherwise
  "expression language (dialect unknown)".
- **Given** the identification stage
  **Then** it sends no call to `Runtime`, `ProcessBuilder`, `System`, `Class`, `File`, or
  any method with a side effect (RNF-03).

#### RF-05 — Relationship with `injection.ssti`

- **Given** a point where the `el` detector identified an EL dialect
  **Then** exactly one finding is reported for that proof: `injection.el`. The `ssti`
  detector's hit for the same point and the same evaluated form is not also surfaced.
- **Given** a point whose arithmetic evaluated but no EL dialect is identified (for
  example a Freemarker `${a*b}`)
  **Then** `injection.ssti` reports it exactly as it does today; `injection.el` stays
  silent.
- **Given** any scan that produced no EL evidence
  **Then** `injection.ssti` findings are byte-identical to before 016 (same ids, titles,
  fingerprints).
- **Given** both detectors would send the same arithmetic payload at the same point
  **Then** it is not sent twice (a shared request budget is the reason). Whether this is
  one detector or a follow-up stage is a design decision.

#### RF-06 — Expression-shaped-parameter priority

- **Given** the enumerated injection points
  **When** the detector order is chosen for a point
  **Then** a point whose **name** is expression-associated (`expr`, `expression`,
  `filter`, `sort`, `order`, `where`, `condition`, `rule`, `formula`, `msg`, `message`,
  `title`, `el`, `spel`, `ognl`, `eval`, `q`, `query`, `search`) is tested by `el`
  first within budget, with the full payload set, mirroring `is_commandlike`.
- **Given** a point matching neither name nor value shape
  **Then** it is still tested if budget remains, with a short canary set (the delimiter
  forms `ssti` does not already send, and the bare form) rather than the full list.

#### RF-07 — Hit shape

- **Given** an `el` hit
  **Then** the `InjectionHit` carries `kind = "el"`, `check_id = "injection.el"`,
  `method` / `url` (the injection point base URL) / `param`, the `severity` and
  `confidence`, a `title` naming the parameter and the dialect
  ("Expression-language injection (SpEL) via the 'filter' parameter"), the `payload`
  that worked, and `evidence` of: the injection point, the payload, the proof (the
  computed `wv<token><product>`, the type-access result, or the error signature).

### Checks

#### RF-08 — `injection.el`

- **Given** the check registry
  **Then** `injection.el` is registered: `category = INJECTION`, `mode = ACTIVE`,
  `default_severity = HIGH`, `cwe = (917, 94)`, references to the OWASP Expression
  Language Injection page, the CWE-917 entry, and the vendor guidance (Spring
  `SimpleEvaluationContext`).
- **Given** an Active scan whose pass produced an `el` hit
  **Then** the check emits one finding per hit with the hit's severity and confidence, a
  `Location` carrying `method` / `url` / `param`, and a description that says the
  parameter reaches an expression evaluator (naming the dialect when known), why a
  reachable type system means remote code execution, and the fix.

#### RF-09 — `list-checks` and suppression

- **Given** `webvigil list-checks`
  **Then** `injection.el` appears with `INJECTION` / `active` / `HIGH`.
- **Given** `[checks] disabled = ["injection.el"]`
  **Then** the check does not run and the `el` detector sends nothing, same gating as
  every 006 detector.

### Fixture app and tests

#### RF-10 — Vulnerable and hardened endpoints

- **Given** the fixture app's **insecure** profile
  **Then** it exposes at least two endpoints that simulate an EL sink: a **SpEL-style**
  one (evaluates `#{…}` / `${…}` and a bare expression, including
  `T(java.lang.Math).abs(…)`, and answers a malformed expression with a
  `SpelParseException` body) and an **OGNL-style** one (evaluates `%{…}`, including
  `@java.lang.Math@abs(…)`, with an `ognl.OgnlException` body on a parse error). One of the
  parameter names does not match `is_exprlike`, so the canary path is exercised.
- **Given** the simulation
  **Then** it evaluates arithmetic only, through a stdlib `ast` walker that accepts
  integer literals, `+ - * //` and the one allow-listed static call, and rejects
  everything else. Nothing is passed to `eval` / `exec`.
- **Given** the **hardened** profile
  **Then** the same routes never evaluate the value: they treat it as data and escape it
  on output, so an Active scan fuzzes them and finds nothing.
- **Given** both profiles
  **Then** the routes are linked from the shared link block, as every earlier spec did.

#### RF-11 — Integration tests

- Active scan of the insecure profile → `injection.el` fires per endpoint with the
  expected dialect, severity, `location.param` and `method`; no `injection.ssti` duplicate
  for the same proof.
- Passive scan of the insecure profile → no `injection.el` finding and no crafted request.
- Active scan of the hardened profile → zero `injection.el` findings (false-positive
  guard).
- `injection.ssti` findings on the existing `/greet` route are unchanged.
- The scan is deterministic across repeated runs and stays within the request budget.

#### RF-12 — Unit tests

- `el` arithmetic: marker-plus-product match per delimiter form including `%{}`; the bare
  form; "payload echoed but not evaluated → no hit"; product without the marker → no hit;
  baseline suppression.
- `el` error signatures: one case per dialect; signature present in the baseline →
  ignored; signature without arithmetic → MEDIUM confidence.
- Identification: SpEL probe → CRITICAL; OGNL probe → CRITICAL; neither → HIGH with the
  dialect from the signature or "unknown"; the probe never carries a forbidden token
  (RNF-03).
- RF-05: the same proof yields one finding; a Freemarker `${a*b}` stays `injection.ssti`.
- `is_exprlike` name / value classification and canary-vs-full-set routing.

### Reporting and docs

#### RF-13 — Reporters unchanged

- No reporter gains a field or a section. `injection.el` findings flow through the same
  `_InjectionCheck` → `Finding` path; `CWE-917` rides the existing `cwe` field. A saved
  canonical JSON re-renders offline exactly as before.

#### RF-14 — Docs

- `docs/active-injection.md`: the checks table gains `injection.el`; a new
  "Expression-language injection" section explains the proof, the CRITICAL / HIGH split and
  the relationship with `injection.ssti`; the **Coverage boundaries** row for
  "Expression-language injection (SpEL / OGNL / JEXL), `eval()` code injection" is rewritten
  to say EL is covered and `eval()` is not (or is, per Open question 1).
- `README.md` ("Scope and limitations"), `CLAUDE.md`, `docs/stack.md` if it names the
  detectors, and the `specs/README.md` roadmap row are updated.

## Non-functional requirements

**RNF-01 — Engine purity, no new dependency**
New code lives in `webvigil.checks.injection` (`detect/el.py`, additions to `payloads.py`
/ `engine.py` / `points.py` / `checks.py`). Detection is `re` + the existing HTTP layer;
**no new runtime dependency**; the fixture uses only the stdlib. The engine imports nothing
from `webvigil.cli` / `webvigil.api` / `web/`; `import-linter` unchanged.

**RNF-02 — Quality gate**
`ruff → black → mypy (strict) → import-linter → pytest` all green, `mypy` covering the new
module. No `web` gate work.

**RNF-03 — Safe by default and non-destructive**
A passive scan is byte-for-byte unchanged and issues no crafted request. The `el` detector
runs only past the `--mode active --authorized-by` gate. Every payload is a value placed in
an in-scope target parameter. The only expression ever sent is arithmetic and one pure
`Math.abs`-style call: no side effect, no I/O, no process, no reflection.

**RNF-04 — Bounded work**
The full payload set runs only for expression-shaped points; every other point gets a
canary of at most three extra requests. `_PER_POINT_REQUEST_CAP` and `request_budget` rise
only if measured against the fixture (as 011 and 014 did), with the new numbers and the
measurement recorded in `design.md`.

**RNF-05 — Determinism and false-positive discipline**
Every proof is absent from the baseline; the arithmetic and type-access proofs need the
marker glued to the computed value, never a reflected literal. The hardened profile yields
zero `injection.el` findings. Operands and the marker are random per request, but findings
and fingerprints are stable across runs.

**RNF-06 — Scope guard intact**
The detector talks only to the scan target through `DetectCtx.send`; no new host, no
collaborator.

**RNF-07 — Python support**
No syntax or API newer than the project's Python floor; the CI matrix and `requires-python`
are unchanged.

## Resolved decisions

1. **In-band only.** Same line as 006 / 011: no headless browser, no collaborator.
2. **No flag, no config key.** The payload set is tiny, read-only and gated by Active Mode.
   Unlike `time_based_cmdi` there is no slow or body-rewriting stage to opt out of.
3. **The 011 proof discipline is the contract.** Marker glued to the computed product,
   absent from the baseline; a reflected literal is never a hit.
4. **`injection.ssti` is not rewritten.** It keeps its payload set, engine names and
   fingerprints; 016 only takes over a finding when it can name an EL dialect (RF-05).
5. **The fixture simulates the sink.** A JVM is not a test dependency of a Python tool; the
   simulation is an `ast`-restricted arithmetic evaluator, as 006 simulates `SLEEP(n)`.
6. **`eval()` code injection is out of 016** (was Open question 1). It needs per-language
   payload syntax and a string-versus-bare context split, and the issue's proposal is EL
   only. The bare-expression payload `'wv<token>'+(a*b)` may also evaluate under a
   JavaScript `eval`; if it does, the hit is reported as "expression language (dialect
   unknown)" and the docs keep saying `eval()` is not a goal. A later spec can take it.
7. **New check id `injection.el`** (was Open question 2). The remediation, the CWE (917 vs
   1336) and the severity differ, and suppression is independent of `injection.ssti`. The
   cost is the RF-05 dedup, paid in the design.
8. **The type-access probe and the CRITICAL upgrade are in** (was Open question 3). It is
   the only in-band signal that separates a sandboxed calculator from RCE, and it executes
   one pure function; RNF-03 pins it to side-effect-free calls.

## Open questions

None.
