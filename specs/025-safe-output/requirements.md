---
feature: Safe output — redaction, size bounds and control-character neutralization applied in one place for every output
status: approved
date: 2026-11-25
related:
  - 024-secret-values/requirements.md
  - 019-automated-login/design.md
  - 002-web-api/design.md
  - 003-web-ui/design.md
origin: conception
---

# 025 — Safe output

## Context and problem

Text that WebVigil did not write reaches every output: what the scanned site sends (a title, a header value, a
response body quoted as evidence), what a user-supplied file holds (a HAR, an OpenAPI document, a report read
back by `webvigil report`) and the message of an exception. Before it leaves, it needs three treatments:

- **Redaction:** no credential or session value of the scan appears.
- **A size bound:** no single value, and no whole document, grows past a known ceiling.
- **Neutralization:** control, bidirectional and zero-width characters are shown, not acted on, so they cannot
  move a terminal's cursor, forge a log line or make a name read differently from what it holds.

Each treatment exists, but each output applies it on its own:

- **The terminal** has one funnel (`cli/_render.py`), which bounds and neutralizes every message. The commands
  that print a table directly (`list-checks`) do not use it.
- **The server log** of the Web API has no treatment. The scan runner logs every unexpected failure with its
  exception message and traceback, unbounded and with its control characters as they are, and the database
  engine formats statement parameters (finding text) into the message of an error it raises.
- **The reports** are bounded by the result's field types, and each format neutralizes on its own: the HTML and
  Markdown writers call `show_controls` over the whole page, the JSON writer has a regex of its own, and SARIF
  relies on `json.dumps` escaping every non-ASCII character.
- **The database** stores the result as bounded by the model, and the scan's error message is bounded and
  cleaned inline in the runner, outside the field types.
- **The Web API** answers with JSON escaping only, and the `422` body repeats the validation message unbounded.
- **The dashboard** neutralizes the finding fields through `showControls`, a TypeScript mirror of
  `show_controls` that is kept in step only by a comment. The target, the tool version, the `authorized_by`
  text, the check id, the technology name, version and advisories, the filter labels and the page title are
  shown without it.

Two defects follow from the treatments being separate and ordered by accident:

- **The bound runs before the redaction.** Evidence is cut when the finding is built, and the scrub of the
  scan's secrets runs over the finished result. A secret that straddles the cut is no longer whole when the
  scrub looks for it, so its first part stays in the report.
- **`webvigil report` holds the whole file in memory several times.** The file is read whole (up to 256 MiB),
  with a buffer reserved for the limit rather than for the file, and parsed into a full JSON tree before it is
  validated, so the peak is several times the file's size, and more the denser the file is.

Every past defect in this class was fixed at one output, in the releases that added the treatments one by one
(the error-output and availability advisories of 1.6.0,
[GHSA-38gf-jvgw-g2pq](https://github.com/ryanvmorais/webvigil/security/advisories/GHSA-38gf-jvgw-g2pq) and
[GHSA-jh8f-87gj-2mw7](https://github.com/ryanvmorais/webvigil/security/advisories/GHSA-jh8f-87gj-2mw7)). A new
output, a new log line or a new dashboard field would need the same care again, and nothing would fail if it
were missing.

**This spec gives each kind of output one place that applies all three treatments in a fixed order, routes
every output through it, makes the Python and TypeScript neutralization provably the same, bounds the memory of
`webvigil report`, and adds a gate that fails when an output writes text without the treatment.** What a scan
sends and what it finds do not change.

### Where it sits

```
src/webvigil/core/   the one place for the three treatments, and their order (bound after redaction)
src/webvigil/cli/    every command prints through it
src/webvigil/api/    server log, stored error message, 422 body
src/webvigil/reporting/   every format uses it; `webvigil report` reads with bounded memory
web/src/lib/         the TypeScript neutralization, checked against the same cases as the Python one
web/src/             every dashboard field from the API goes through it
tests/               shared test vectors, the sink inventory gate, the log and report canaries
```

## Goals

- One project-owned place applies redaction, the size bound and neutralization, in that order, for each kind
  of output: terminal, log, report, database, API response and dashboard.
- Every output of the CLI, the Web API and the dashboard goes through it, and a test lists the outputs.
- No part of a secret survives a size bound.
- The Web API's server log carries no unbounded, unneutralized or secret-bearing text, and no database
  statement parameter.
- The Python and TypeScript neutralization give the same output for the same input, proven by one shared set
  of cases.
- `webvigil report` reads a file with a peak memory that is a fixed small multiple of its size.
- A scan of the same target sends the same requests and reports the same findings and fingerprints.

## Non-goals

- **Which destinations may receive a credential.** What may be sent to each URL is outside this spec; the
  origin rule (`Target.carries_credentials`) and the redirect rules do not change.
- **Failure-injection tests across the scan.** This spec adds only the gate for its own outputs (RF-09).
- **The scrub thresholds.** A given secret under 4 characters is still not scrubbed (with its warning), and a
  value the target issued is still scrubbed only when it looks like a session id (spec `024`, resolved
  decision 4).
- **The size limits of the fields.** `Name` 1 Ki characters, `Text` 16 Ki, `Url` 64 Ki, evidence 4 Ki and the
  terminal message 4 Ki stay as they are. Only the report file limit changes (resolved decision 4).
- **The report formats and `schema_version`.** A report of the same scan has the same fields; only the text of
  a value that held a partial secret or a raw control character changes.
- **The uvicorn access log.** It records the method, the path and the status, which hold no site text and no
  secret; its format does not change.
- **The redaction inside checks.** The disclosure checks mask secrets of the *site* in what they quote
  (`checks/disclosure/redaction.py`); that is a finding's content, not the output path, and it stays.
- **A new flag, configuration key or check.**

## Personas

- **As a developer reading a report or a CI log**, I want no fragment of my cookie, token or password in it,
  even when the page that echoed it was cut to size.
- **As someone running the Web API**, I want the server log to hold one line per event, bounded, with nothing
  the scanned site wrote acting on my terminal or my log viewer, and no finding text from a failed database
  write.
- **As a user of the dashboard**, I want every name and value the site chose shown as it is, so that a hidden
  character cannot make a target, a technology or a check read differently.
- **As someone triaging a report from another team**, I want `webvigil report` to read a large or hostile file
  without exhausting the machine's memory.
- **As a contributor adding an output**, I want one call that makes text safe for it, and a test that tells me
  when I print text without it.

## Functional requirements

### One place, one order

### RF-01 — One safe-output call per kind of output

- **Given** text bound for the terminal, a log record, a report, the database, an API response or the
  dashboard
  **When** an output writes it
  **Then** it passes through one project-owned call for that kind of output, which applies redaction, then the
  size bound, then neutralization.
- **Given** the same text and the same kind of output
  **When** it is written from two different places (a check error and a warning, the CLI and the Web API)
  **Then** both write the same result.

### RF-02 — No part of a secret survives a size bound

- **Given** a scan that holds a secret and a page that echoes it at the point where a field or a piece of
  evidence is cut to size
  **When** the result is written in any format, stored or shown
  **Then** no prefix or suffix of the secret of 4 characters or more appears, and the value still ends with the
  truncation marker.
- **Given** a value that holds a secret and fits its bound
  **When** it is redacted
  **Then** it reads exactly as it does today.

### Each output

### RF-03 — The terminal

- **Given** any command of the CLI, including `list-checks`, `version` and every error exit
  **When** it prints text that it did not write itself (a check id, a plugin's name, a path, a message from the
  site or a file)
  **Then** the text is bounded and neutralized, and is never read as Rich markup.

### RF-04 — The server log

- **Given** the Web API logging a failure (claiming a scan, a crash, an unexpected error, storing a result)
  **When** the record is formatted
  **Then** its message and its traceback are bounded, their control characters are escaped so the record stays
  on the lines it was given, and the values of the scan's secrets do not appear.
- **Given** a database error raised while storing a result
  **When** it is logged or reported
  **Then** it carries no statement parameter.
- **Given** the engine or a check logging through `logging`
  **When** the application installs the treatment
  **Then** the same rule holds for the `webvigil` loggers, without changing the level or the handlers a user
  configured.

### RF-05 — The reports

- **Given** a result written as JSON, SARIF, HTML or Markdown
  **When** each writer neutralizes the text
  **Then** they use the one call (RF-01), each format's own escaping (JSON strings, Markdown metacharacters,
  HTML entities, SARIF brackets) stays where it is, and the same scan gives the same report as before this spec
  except where RF-02 applies.

### RF-06 — The database and the API

- **Given** a scan's error message, warnings, check errors and findings
  **When** the Web API stores them
  **Then** every free-text column is written through the one call, the scan's error message included.
- **Given** a request whose body fails validation
  **When** the API answers `422`
  **Then** each message is bounded and neutralized, as well as free of the input (spec `024`, RF-08).

### RF-07 — The dashboard

- **Given** any value the API returns that the site, a file or a user chose (target, tool version,
  `authorized_by`, check id, technology name, version and advisories, source URL, filter labels, error and
  toast messages, the page title)
  **When** the dashboard shows it, in the page or in an attribute such as a tooltip or the document title
  **Then** it goes through the TypeScript neutralization.
- **Given** the Python and the TypeScript neutralization
  **When** both run over one shared file of cases (every escaped range, its edges, CRLF, a one-line value,
  surrogates)
  **Then** both give the expected output for every case, and a range added to one and not the other fails a
  test.

### Reading a report back

### RF-08 — `webvigil report` reads with bounded memory

- **Given** a report file of any size up to the limit, valid or not
  **When** `webvigil report` reads it, on the main path or the surrogate fallback
  **Then** it reserves memory for the file's actual size, not for the limit, its peak stays within the
  multiple of the file's size that the design measures, and an invalid file still exits with the same code and
  the same message as today.
- **Given** a report file larger than 64 MiB
  **When** `webvigil report` reads it
  **Then** it is refused with the too-large error, which names the limit.
- **Given** a scan that writes a JSON report larger than 64 MiB
  **When** the file is written
  **Then** the scan warns that `webvigil report` cannot read it back, and the file is still written whole.

### The gate

### RF-09 — Every output is inventoried

- **Given** the source of `webvigil` and of the dashboard
  **When** a test lists every place that writes to the terminal, a logger, a report, the database, an API
  response or the page
  **Then** each one either goes through the one call or is in a declared inventory with the reason (a fixed
  string, a number, an enum), and a new output outside both fails the test.

### RF-10 — Same scan, same report

- **Given** the fixture application scanned with the same configuration (anonymous, with `[auth]` cookies and
  headers, and with the automated login), before and after this spec
  **When** the requests the fixture received and the JSON reports are compared, leaving out timestamps and
  durations
  **Then** the requests are byte for byte the same, and findings, severities, check ids, fingerprints and
  `schema_version` are identical.

### RF-11 — Tests

See the test strategy in the design. The suite must cover:

- the order of the treatments (RF-01, RF-02) as unit tests, with a secret placed at, before and after each cut
  of each bound, and a positive control that the same secret away from the cut is redacted;
- the shared neutralization cases (RF-07), run by `pytest` and by `vitest`;
- the sink inventory (RF-09) as a test over the source;
- a log canary for the Web API: a scan whose failure message and stored text carry a known secret, control
  characters and an oversized value, with logging captured at `DEBUG`, in which no part of the secret, no raw
  control character and no statement parameter appears, with a positive control that the failure was logged;
- the dashboard fields of RF-07 in the component tests;
- a memory measurement of `webvigil report` (RF-08) on a generated file near the limit, on both paths, offline
  and within the suite's time budget, or in a marked test that CI runs.

## Non-functional requirements

### RNF-01 — No new dependency

The treatments are written in the repository on the standard library and pydantic in the engine, and on the
dashboard's existing dependencies.

### RNF-02 — A minor release

The change fits a minor release under [`docs/stability.md`](../../docs/stability.md): commands, options,
configuration keys, check ids, exit codes, the report schema and fingerprints do not change. What changes is
listed under **Changed** or **Fixed** in the CHANGELOG: a partial secret no longer survives a cut, the server
log is bounded and neutralized, the dashboard shows hidden characters in more fields, and `webvigil report`
reads files up to 64 MiB instead of 256 MiB. Lowering a limit that guards against a hostile input is allowed in
a minor release, as the 1.6.0 limits were.

### RNF-03 — The engine boundary

The one call lives in the engine; the CLI and the Web API import it, and the `import-linter` contract keeps
passing. The dashboard keeps talking only to the API.

### RNF-04 — No measurable cost on a scan

A full scan of the fixture application takes no measurably longer, and the redaction of a result stays linear
in its size.

### RNF-05 — Every step leaves `main` working

The work lands in independent pull requests, each with the full CI green.

### RNF-06 — The suite stays fast and offline, and its guards are proven

No test talks to the real network. The whole suite keeps running in under 2 minutes with coverage, and
per-file line and branch coverage of `src/webvigil` does not drop. Every new test is seen failing once. Every
changed guard goes through mutation testing in batch: every changed function has a killed mutant, every
surviving mutant is triaged, and the score goes in the pull request.

## Resolved decisions

1. **Redaction comes before the bound.** Cutting first lets a secret straddle the cut; redacting first never
   does, and the bound then counts the marker, not the secret.
2. **The format's own escaping stays in the format.** JSON string escaping, Markdown and HTML metacharacters and
   SARIF brackets belong to each format; only redaction, the bound and the control-character neutralization move
   to the one place.
3. **The Python and TypeScript neutralization stay two implementations.** The dashboard renders values from the
   API in the browser and needs its own; one file of cases makes them provably the same instead of merging them.
4. **The report file limit drops from 256 MiB to 64 MiB (decision of 2026-11-25).** Measured on the current
   parser, the peak memory of a read grows with how dense the file is, not with the path taken: about 3 times
   the file's size when it holds large values and about 16 times when it holds many small ones, because the
   whole JSON tree is built before validation. A streaming read needs a new dependency or a parser of our own
   (RNF-01), so the file limit is the lever: 64 MiB keeps the worst case near 1 GiB, where 256 MiB allowed
   about 4 GiB. A scan that writes a larger JSON report says so (RF-08).
5. **No ceiling on the number of items in a report (decision of 2026-11-25).** Measured, a ceiling on the
   findings list refuses an oversized file only after the parse, so the peak stays near where it was (1.6 GiB
   instead of 2.4 GiB on the same file). The file limit bounds memory; a ceiling on items would add a rule
   without holding the goal.
