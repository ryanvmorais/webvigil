---
feature: Safe output — redaction, size bounds and control-character neutralization applied in one place for every output
status: in progress
date: 2026-11-25
related:
  - 024-secret-values/requirements.md
  - 019-automated-login/design.md
  - 002-web-api/design.md
  - 003-web-ui/design.md
origin: conception
---

# 025 — Safe output — design

## Overview of the approach

A new engine module, `core/output.py`, owns the three treatments and the order they run in. It names each kind
of output as a `Sink` and gives each one a fixed profile: which bound applies and which neutralization. One
function, `safe_text(value, sink)`, runs the treatments in order: redaction (when the caller has a
`Redactor`), then the bound, then neutralization. The existing primitives (`truncate` and the limits of
`core/bounded.py`, `show_controls` and `replace_surrogates` of `core/text.py`) stay where they are, and the
field types `Name`, `Text` and `Url` become the declared form of the `STORE` profile. Every output in the CLI,
the reporters and the Web API calls `safe_text`, and a syntax-tree test lists every output call in the source.

The scrub of a finished result keeps running once, over the result, as specs `019` and `024` set it up, but its
text replacement moves to `output.Redactor`, which now also recognizes a cut. A fragment of a secret (4
characters or more) next to a cut is redacted too, whether the cut is the field bound's marker, a check's
snippet ellipsis or the edge of a piece of evidence. This closes the straddling case at its source: checks cut
text in several places before any model sees it, so reordering the model's bound alone would not have been
enough (ADR-3).

The Web API's log gets the `LOG` profile through a `logging.Filter` installed on every project logger and on
`uvicorn.error`. The filter rewrites the message and formats the traceback with each exception's text kept on
its own line. Both database engines set `hide_parameters`. `webvigil report` reads the file in chunks up to the
new 64 MiB limit, and the scan warns when the JSON it writes is larger. The dashboard gets one `display`
helper over `showControls`, used for every value the API returns. Python and TypeScript are checked against
one JSON file of cases, and a hostile-payload render test fails if any page shows a raw control character.

### What was checked (2026-11-25, Python 3.15, pydantic 2.14, Windows, peak working set)

`webvigil report` was measured on generated files, as the peak working set above the interpreter's baseline:

| File | Size | Findings | Peak | Ratio |
|---|---|---|---|---|
| 3 KB report | 0.003 MiB | 10 | 297 MiB | — (the limit is reserved up front) |
| Large values (4 KiB evidence each) | 201 MiB | 50 000 | 678 MiB | 3.2× |
| Same, surrogate fallback path | 201 MiB | 50 000 | 686 MiB | 3.2× |
| Minimal findings | 146 MiB | 800 000 | 2 448 MiB | 16.4× |
| Same, surrogate fallback path | 175 MiB | 800 000 | 2 619 MiB | 14.8× |
| Minimal findings, `max_length=50 000` on the list | 146 MiB | refused | 1 589 MiB | 10.9× |

- `handle.read(MAX_REPORT_BYTES + 1)` reserves the whole limit before it reads, so a 3 KB report peaks at
  ~300 MiB.
- Density, not the path taken, drives the peak: pydantic builds the whole JSON tree before it validates, and a
  list ceiling refuses only after that.
- Counting values in the bytes before parsing (stripping strings with a regular expression) took 30 s and
  1.7 GiB on the dense file, so no pre-count is possible without a parser of our own.

These numbers are the grounds for resolved decisions 4 and 5 of the requirements.

## Module layout

```
src/webvigil/core/output.py (new)     Sink, the profiles, safe_text, safe_traceback, Redactor, get_logger
src/webvigil/core/bounded.py          store_text (the STORE step) next to the limits and truncate; the field types call it
src/webvigil/core/text.py             unchanged primitives; the JSON-document escape moves here from the JSON reporter
src/webvigil/auth/scrub.py            the walk over the result stays; text replacement is output.Redactor
src/webvigil/cli/_render.py           _printable is safe_text(TERMINAL); list-checks prints through _render
src/webvigil/cli/app.py               list-checks, the JSON-size warning after writing a report
src/webvigil/reporting/__init__.py    chunked read, MAX_REPORT_BYTES = 64 MiB
src/webvigil/reporting/json_report.py, sarif.py, html.py, markdown.py   neutralize through safe_text
src/webvigil/api/runner.py, security.py   loggers from get_logger; Scan.error through safe_text(STORE)
src/webvigil/api/app.py               422 messages through safe_text(MESSAGE); log filter on uvicorn.error
src/webvigil/api/db.py, migrations/env.py   hide_parameters=True
web/src/lib/text.ts                   display(); the cases file drives its tests
web/src/components/*, web/src/app/**  every API value through display()
tests/data/text-controls-cases.json (new)   the shared neutralization cases
tests/unit/test_output.py (new)       profiles, order, Redactor edges, traceback, log filter
tests/unit/test_output_inventory.py (new)   the sink inventory gate
tests/api/test_log_canary.py (new)    the Web API log canary
web/src/lib/hostile-render.test.tsx (new)   every page rendered from a payload of hostile strings
```

## Data model

No new persisted field and no schema change. `schema_version` stays.

- **`Sink`** (`StrEnum` in `core/output.py`), each member with its profile:

  | Sink | Used by | Bound | Neutralization |
  |---|---|---|---|
  | `TERMINAL` | `cli/_render.py` | 4 Ki characters (`_MESSAGE_MAX_CHARS`) | `show_controls`, `one_line` per call |
  | `LOG` | the log filter | 16 Ki message (`TEXT_MAX_CHARS`), 64 Ki traceback (`URL_MAX_CHARS`) | `show_controls(one_line=True)` per message and per exception line |
  | `MESSAGE` | the `422` body | 1 Ki (`NAME_MAX_CHARS`) | `show_controls(one_line=True)` |
  | `STORE` | the field types, `Scan.error` | the field's limit (`Text` by default) | surrogates replaced; controls kept raw, neutralized where they are shown |
  | `DOCUMENT` | the HTML and Markdown reporters | none (every field is already bounded) | `show_controls` over the whole page |
  | `JSON` | the JSON and SARIF reporters | none | DEL, C1 and the invisible characters as `\uNNNN` in the encoded document |

- **`Redactor`** (`core/output.py`): built from the texts to hide (the strings `scrub._texts` gives). It holds
  every spelling longest first (today's `_Scrubber`), plus two sets for the cut rule: every prefix and every
  suffix of each spelling with at least `MIN_SECRET_LENGTH` (4) characters and shorter than the spelling.
- **`CUT_MARKERS`** (`core/output.py`): `TRUNCATION_MARKER`, the evidence marker, `"…"` and `"..."`, the
  markers the engine and its checks write where they cut text.
- **`MAX_REPORT_BYTES`** (`reporting/__init__.py`): 64 MiB, down from 256 MiB.

## Components

### `safe_text` and the profiles (`core/output.py`)

`safe_text(value, sink, *, one_line=False, limit=None, redactor=None)` applies, in this order: the redactor
when one is given, then `replace_surrogates` and `truncate` with the sink's limit (or `limit`), then the sink's
neutralization. Bounding before neutralizing means an escape is never split by a cut, and the bound counts
what the source held, not its escapes (ADR-2). Every function is pure and idempotent: a value that went
through a profile comes out of it again unchanged, which is what lets a report reload as it was.

`core/bounded.py` keeps the limits, `TRUNCATION_MARKER` and `truncate`, and gains `store_text(value, limit)`:
`replace_surrogates` and then `truncate`, the body of today's `bounded()` validator. The validator calls it, and
the `STORE` profile of `safe_text` calls the same function, so the field types are the declared form of the
`STORE` profile with one implementation (ADR-1). The imports go one way: `core/output.py` imports
`core/bounded.py` and `core/text.py`, and neither imports it back.

### `Redactor` and the cut rule (`core/output.py`, `auth/scrub.py`)

`Redactor.__call__(text, *, cut_edges=False)` first replaces every whole spelling with `REDACTED`, as today.
It then looks at each cut point of the text:

- **Before a cut:** the end of a value cut by `truncate` (just before `TRUNCATION_MARKER` or the evidence
  marker), the position just before any other `CUT_MARKERS` occurrence, and, when `cut_edges` is set, the end
  of the text. If the text just before the point ends with one of the redactor's prefixes, the longest match
  becomes `REDACTED`.
- **After a cut:** the position just after a `CUT_MARKERS` occurrence and, when `cut_edges` is set, the start of
  the text. If the text just after the point starts with one of the suffixes, the longest match becomes
  `REDACTED`.

`cut_edges` is set for evidence content, which checks cut without a marker (`html[:N]`, a line cut from a
body). Titles, descriptions, locations, references, technologies, warnings and check errors are matched at
markers only, so a title that merely ends with the first letters of a password is left alone. The warning that
counts the redacted fields counts these too. `scrub.py` keeps `_texts` (an inventoried reveal of spec `024`),
`looks_like_session_value` and the walk over the result. `_Scrubber` and `_spellings` move to `core/output.py`
unchanged except for the cut rule.

### Terminal (`cli/_render.py`, `cli/app.py`)

`_printable(value, one_line=...)` becomes `safe_text(value, Sink.TERMINAL, one_line=...)`. Every printing
function of `_render` already goes through it, and `_plain` keeps building Rich `Text` objects so that no text
is read as markup. `list-checks` builds its table from `Text` cells made by `_render.cell(...)`, which runs
the `TERMINAL` profile on one line, so a plugin's id or category is shown as written and never parsed as
markup. After `_write_or_print` writes a JSON report, `scan` compares its encoded size with `MAX_REPORT_BYTES`
and, when it is larger, prints a warning through `_render.status`: `webvigil report` reads at most 64 MiB, so
it cannot read this file back. The file is written whole, and the exit code does not change.

### Reports (`reporting/*`)

- **HTML and Markdown** call `safe_text(page, Sink.DOCUMENT)` where they call `show_controls` today. Their own
  escaping (Jinja's autoescape, Markdown and HTML metacharacters, code fences, `&#8203;` in mentions) stays.
- **JSON** calls `safe_text(document, Sink.JSON)`. The regular expression moves from `json_report.py` to
  `core/text.py` as `escape_json_controls`, which the `JSON` profile calls.
- **SARIF** encodes with `ensure_ascii`, so every non-ASCII character is already an escape. It calls the same
  profile, which finds nothing to change, so the two JSON writers share one rule rather than two.
- **Reading back.** `load_result` reads the file in chunks of 1 MiB into a `bytearray` until the end of the
  file or one byte past `MAX_REPORT_BYTES`, and refuses with the too-large error in the second case. It never
  asks for more than one chunk at a time, so memory follows the file's actual size. The parse path (pydantic
  first, the standard parser for an escaped lone surrogate) does not change; both were measured at the same
  peak.

### Server log (`core/output.py`, `api/*`)

`get_logger(name)` returns `logging.getLogger(name)` with `SafeLogFilter` attached once. Every project module
that logs gets its logger from it (today `webvigil.api` in `runner.py` and `security.py`). `create_app`'s
lifespan also attaches the filter, after uvicorn has configured its loggers, to `uvicorn.error` (uvicorn logs
an exception that escapes a request there) and to `httpx2` (the client logs every request's URL at `INFO`).
Third-party loggers are touched only by the Web API, which owns its process; the engine used as a library never
changes another package's logger. The filter changes neither the level nor the handlers.

For each record, `SafeLogFilter.filter`:

1. Renders the message with `record.getMessage()`. If that raises, it leaves the record alone so that
   `logging` reports its own formatting error. Otherwise it sets `record.msg` to
   `safe_text(message, Sink.LOG, one_line=True)` and `record.args` to `()`.
2. When the record has `exc_info`, sets `record.exc_text` to `safe_traceback(exc)`. A formatter uses a
   record's `exc_text` when it is set, so every handler prints the treated traceback.
3. Returns `True`, so no record is dropped.

`safe_traceback(exc)` walks the exception chain as `traceback` does (cause, context unless suppressed, the
members of an exception group). It writes each stack as Python formats it, since frames and source lines come
from the installed code and not from input. Each exception's type, message and notes go through
`show_controls(one_line=True)`, so a message holding a line break, an escape sequence or a bidirectional
override stays on its line and shows what it holds. The whole text is cut to the `LOG` traceback bound.

`make_engine` (`api/db.py`) and the migration engine (`api/migrations/env.py`) pass `hide_parameters=True`, so
an error SQLAlchemy raises names the statement but not its parameters (finding text when a result is stored).

### Database and API (`api/runner.py`, `api/app.py`)

- `_terminate` writes `scan.error = safe_text(error, Sink.STORE)` in place of the inline
  `truncate(replace_surrogates(...))`.
- The rows built in `api/mapping.py` take their values from bounded model fields, which are the `STORE`
  profile (ADR-1); the inventory lists `mapping.py` with that reason.
- `_validation_failed` builds each `detail` entry from `type` (a pydantic constant), `loc` (each string part
  through `safe_text(part, Sink.MESSAGE)`, integers kept) and `msg` (through `safe_text(msg, Sink.MESSAGE)`).
  It still drops `input`, `ctx` and `url` (spec `024`, ADR-8).

### Dashboard (`web/src`)

`display(value, { multiLine } = {})` in `web/src/lib/text.ts` returns `""` for `null` and `undefined` and
otherwise `showControls(value, { oneLine: !multiLine })`. It replaces the direct `showControls` calls and is
added to every value the API returns that the site, a file, a plugin or a user chose:

- the scan list: target;
- the scan page: the heading and the page title (`pageTitle(display(target))`), tool version, `authorized_by`,
  the error message (multi-line);
- the findings table: check id, as well as the fields that use `showControls` today;
- the findings filters: the check id labels;
- the technologies table: name, version, the advisories tooltip, the source URL;
- the checks table: name, id, category;
- `errorMessage` and `fieldErrors` in `web/src/lib/api.ts`, so every toast and field error is covered;
- the report preview's error text.

`showControls` keeps its ranges. `HIDDEN_RANGES` and `INVISIBLE_CHARS` keep their comments, and the cases file
now enforces what the comments only asked for (ADR-7).

## Interfaces

```python
# src/webvigil/core/output.py
class Sink(StrEnum):
    TERMINAL = "terminal"
    LOG = "log"
    MESSAGE = "message"
    STORE = "store"
    DOCUMENT = "document"
    JSON = "json"

CUT_MARKERS: Final[tuple[str, ...]]

def safe_text(
    value: str, sink: Sink, *, one_line: bool = False, limit: int | None = None,
    redactor: Redactor | None = None,
) -> str: ...
def safe_traceback(exc: BaseException) -> str: ...

class Redactor:
    hits: int
    def __init__(self, texts: Iterable[str]) -> None: ...
    @property
    def empty(self) -> bool: ...
    def __call__(self, text: str, *, cut_edges: bool = False) -> str: ...
    def optional(self, text: str | None) -> str | None: ...

class SafeLogFilter(logging.Filter): ...
def get_logger(name: str) -> logging.Logger: ...

# src/webvigil/core/text.py
def escape_json_controls(document: str) -> str: ...

# src/webvigil/reporting/__init__.py
MAX_REPORT_BYTES: Final = 64 * 1024 * 1024
```

```ts
// web/src/lib/text.ts
export function display(value: string | null | undefined, options?: { multiLine?: boolean }): string;
```

`tests/data/text-controls-cases.json` is a list of `{"name", "input", "one_line", "expected"}` objects. The
inputs use JSON escapes, so the file itself holds no raw control character: every range and both of its edges,
the characters just outside each range, tab and line feed in both modes, CRLF, a lone CR, a valid surrogate
pair, an empty string, and text that already holds a literal `\x1b`.

## ADRs

### ADR-1 — One module of profiles; the field types are the `STORE` profile

**Decision.** `core/output.py` defines a `Sink` per kind of output and one `safe_text`. The model field types
keep their names and call the `STORE` profile, rather than every row and column calling `safe_text` again.

**Alternatives.**

- (a) One helper per output (`for_terminal`, `for_log`, …) with no shared order.
- (b) Call `safe_text` at every database write as well as in the types.
- (c) Leave the treatments where they are and add the missing calls.

**Why.** A profile per sink puts each output's rule in one table that a reviewer reads once, and one function
fixes the order for all of them (RF-01). The types are where the result's text is bounded today, and every row
is built from them, so the types are the `STORE` profile applied once. (b) would run it twice on the same text
for nothing. (a) brings back the per-output discipline the spec removes, and (c) is the state that produced the
defects.

**Trade-off.** `core/bounded.py` and `core/output.py` depend on each other's ideas. The limits stay in
`bounded.py`, because the models import them, and `output.py` composes them.

### ADR-2 — Bound before neutralizing, in every profile

**Decision.** `safe_text` cuts the source text and then neutralizes it. The terminal funnel, which today
escapes first and cuts the escaped text, follows the same order.

**Alternatives.** (a) Keep the terminal's escape-then-cut. (b) Neutralize first everywhere.

**Why.** Cutting escaped text can split an escape (`\x1` left from `\x1b`), which shows something the source
did not hold. Cutting the source never splits an escape, and the bound then counts what the site sent, as the
field types already do. One order for every sink is what RF-01 asks for.

**Trade-off.** A printed message can be longer than 4 Ki characters: at most four times longer, when every
character of the source is a control character. The bound still holds; it is on the source, not on the screen.

### ADR-3 — The redaction recognizes cuts, instead of redacting before every cut

**Decision.** The result is still scrubbed once, after the scan. `Redactor` treats every cut point it can
recognize (a cut marker, and the edges of evidence) as the place where a secret may have been split, and
redacts a fragment of 4 or more characters of any spelling found there.

**Alternatives.**

- (a) Redact before the bound: stop cutting fields when findings are built, and cut after the scrub.
- (b) Give checks the scan's redactor (a context variable or a `ScanContext` member), and redact every body
  before a check cuts a snippet out of it.
- (c) Match any fragment of 4 or more characters anywhere in the text.

**Why.** Resolved decision 1 of the requirements says why order matters: cut first, and a secret can straddle
the cut. Text is not cut only by the field types, though. Checks cut snippets out of bodies in several places
(a reflection window, a line around a match, the first bytes of a tag) before a finding exists. (a) fixes the
field bound only. (b) would make every check remember to redact before it cuts, the per-call-site rule this
spec removes, and it would need the session's values while they still change. Recognizing the cut makes the
result safe however the text was cut, which is what RF-02 requires, and keeps the one scrub of specs `019` and
`024`. (c) would blank any title or description that happens to share four letters with a password.

**Trade-off.**

- A fragment of 4 or more characters next to a marker or at an evidence edge that equals the start or the end
  of a secret is redacted even when it is not part of it. This is rare, it errs toward hiding, and the
  redaction warning counts it.
- A fragment of 1 to 3 characters may remain, the same threshold as a whole secret (spec `024`, resolved
  decision 4).
- A cut that leaves no marker in the middle of a longer text is not recognized. No check does that today, and
  `docs/writing-checks.md` says to cut with a marker.

### ADR-4 — The log treatment is a filter on the project's loggers, and tracebacks are rebuilt

**Decision.** `get_logger` attaches `SafeLogFilter`, which rewrites the message and fills `exc_text` with
`safe_traceback`. The Web API also attaches it to `uvicorn.error` and `httpx2`. No formatter, handler or
global record factory is installed.

**Alternatives.**

- (a) A custom `Formatter`, installed on the handlers.
- (b) `logging.setLogRecordFactory`, for every record of the process.
- (c) `show_controls` over the whole formatted traceback.

**Why.**

- The Web API configures no handler: its records go to whatever the operator or uvicorn set up, so a formatter
  would have to replace theirs (a). A filter on the logger travels with the record to every handler.
- (b) would rewrite the records of every library in the process, including an embedder's.
- (c) keeps a line break inside an exception message as a real line, so a message could still print a line
  that looks like a log record of its own. Treating each exception's text as one line, and the frames as
  Python wrote them, keeps the record on the lines it was given (RF-04).

**Trade-off.** A filter on a logger sees only that logger's own records, not its children's. Every module
therefore takes its logger from `get_logger`, and the inventory gate fails on `logging.getLogger` anywhere
else. Other third-party loggers (`h2`, `hpack`, `sqlalchemy`, `alembic`) are not treated: they log protocol
frames and statements, not scan text, and `hide_parameters` keeps the statements' values out (ADR-5). The CLI
attaches nothing to a third-party logger, so a user who turns `httpx2` logging on in an embedding program sees
its records as the library writes them.

### ADR-5 — `hide_parameters` on both database engines

**Decision.** `create_engine(..., hide_parameters=True)` in `make_engine` and in the migration environment.

**Alternatives.** (a) Catch `StatementError` around every write and log a fixed message. (b) Rely on the log
filter's bound and neutralization.

**Why.** The parameters of a failed insert are finding text and, in a user write, a password hash. One engine
setting keeps them out of every message SQLAlchemy builds, wherever the error is raised or logged. (a)
misses a write added later, and (b) would still log the text, only cut and escaped.

**Trade-off.** A failed statement no longer shows its values in the log, which makes a data bug harder to
debug. The statement and the error still say what failed, which is enough for this database.

### ADR-6 — The report reader reads in chunks, up to 64 MiB, and the scan warns about larger files

**Decision.** `load_result` reads 1 MiB at a time into a `bytearray`, and `MAX_REPORT_BYTES` is 64 MiB. After
writing a JSON report larger than the limit, `scan` warns on the terminal.

**Alternatives.** (a) `fstat` and one read of the file's size. (b) A streaming parser. (c) Refuse to write a
JSON report over the limit.

**Why.**

- The chunked read reserves memory for what is there, on a regular file, a pipe or a device alike. (a) trusts a
  size that a pipe does not have and a growing file contradicts.
- (b) needs a dependency or a parser of our own (RNF-01).
- 64 MiB is the limit of the HAR and OpenAPI imports, and keeps the measured worst case near 1 GiB (resolved
  decision 4).
- (c) would lose a scan's result over the size of a file a user may never reload.

**Trade-off.** A JSON report between 64 and 256 MiB that 1.7.0 could reload is now refused. The warning at
scan time tells the user before they need it, and the CHANGELOG says so under **Changed**.

### ADR-7 — One cases file in `tests/data`, read by `pytest` and `vitest`

**Decision.** `tests/data/text-controls-cases.json` holds the cases. A parametrized `pytest` test runs
`show_controls` over every case, and a `vitest` test reads the same file (`../tests/data/…` from `web/`) and
runs `showControls` over every case.

**Alternatives.** (a) Generate the TypeScript ranges from Python. (b) Put the file under `web/`. (c) Merge the
two into one implementation served by the API.

**Why.** The two implementations stay small and readable, and one list of expectations makes a drift fail in
whichever suite runs. `tests/data` already holds shared test data. The dashboard's tests run from a full
checkout, in CI and locally, and the sdist carries neither directory. (a) adds a generator for 9 ranges. (c)
would make the dashboard depend on the API to show text it already holds (requirements, resolved decision 3).

**Trade-off.** The dashboard's test suite reads a file outside `web/`. A `web/`-only copy of the repository
cannot run that one test; it fails with a clear message rather than being skipped.

### ADR-8 — The sink inventory is a syntax-tree test; the dashboard's is a hostile render

**Decision.**

- **Python:** `test_output_inventory.py` parses every module under `src/webvigil` and records every output
  call, as `module:qualname` of the function around it: `print`, `typer.echo`/`secho`, a `.print` or
  `.print_json` on a console, `.write` on `sys.stdout`/`sys.stderr`, `.write_text`/`.write_bytes`,
  `HTTPException`, `JSONResponse`, `session.add`, and `logging.getLogger`. A call whose arguments are all
  literals passes. Every other one must be in `OUTPUT_SINKS`, a mapping from site to reason ("through
  `_render`", "a rendered report", "rows from bounded fields"). An unlisted site fails, and so does a listed
  site with no call left. `logging.getLogger` is allowed only in `core/output.py`.
- **Dashboard:** `hostile-render.test.tsx` builds the API payloads (scan list, scan, findings, technologies,
  checks, an error body) with a helper that sets every string field, at any depth, to a value holding ESC,
  a C1 control, a bidirectional override and a zero-width space. It renders each page and asserts that no
  raw character of those ranges appears in the text, in any attribute or in `document.title`.

**Alternatives.** (a) A source scan of the `.tsx` files for API fields outside `display`. (b) A behavioural
canary for Python too, with no inventory.

**Why.** For Python, the same shape as spec `024`'s reveal inventory (ADR-3 there) gives a reviewer one list
with a reason per output, and fails when a new one appears (RF-09). For the dashboard, a source scan cannot
tell an API value from a constant in JSX. A render driven by the payload types covers every field the API
sends, including a field added later, since the helper fills every string. RF-09's "every place that writes to
the page" is the rendered page itself.

**Trade-off.** The Python gate matches calls by name, so an output through an unusual name (a renamed
console) is missed. The reviewer of `OUTPUT_SINKS` and the canaries cover that. The dashboard gate covers the
pages it renders; a new page needs a line in the test, which the Lighthouse rule for new routes already
requires authors to look at.

### ADR-9 — One minor release, no milestone

**Decision.** The change goes in 1.8.0, a minor release. The roadmap row's delivery is `—`.

**Alternatives.** (a) A patch release. (b) A major release for the lower report limit.

**Why.** Commands, options, configuration keys, check ids, exit codes, the report schema and fingerprints do
not change. A lower limit against hostile input and the security fixes fit a minor release
(`docs/stability.md`), as the 1.6.0 limits did. The spec delivers no product feature, so it gets no `v0.N`
milestone, like `023` and `024`.

**Trade-off.** A user with a JSON report between 64 and 256 MiB has to keep 1.7.0 to reload it, or re-render it
from the scan. The CHANGELOG says so.

## Impact on existing code

- **Engine.**
  - `scrub_result` keeps its signature.
  - `_Scrubber` and `_spellings` move to `core/output.py` and stay private names there (`Redactor` is the new
    public one).
  - `_printable` and the inline escapes of the reporters become calls of `safe_text`.
  - `json_report._RAW_CONTROL_RE` becomes `core/text.escape_json_controls`.
- **`MAX_REPORT_BYTES`** drops to 64 MiB. Its tests, `docs/architecture.md`, the project's agent notes and the
  `report` command's help text change with it.
- **Report text.** A value that held a fragment of a secret next to a cut now shows `[redacted]` there. Nothing
  else in a report changes (RF-10).
- **Terminal.** `list-checks` shows a markup-like id as written, and a message over the bound is cut on its
  source (ADR-2).
- **Web API.** A log record is one line per message and per exception line, with no statement parameters, and
  a `422` message is at most 1 Ki characters. The OpenAPI document does not change.
- **Dashboard.** More fields show hidden characters as escapes. No layout changes.
- **Documentation.**
  - [`docs/writing-checks.md`](../../docs/writing-checks.md): cut a snippet with a marker from `CUT_MARKERS`, and
    log through `get_logger`.
  - [`docs/architecture.md`](../../docs/architecture.md): the sink profiles, and the 64 MiB report limit.
  - [`docs/web-ui.md`](../../docs/web-ui.md): `display()` for every API value.
  - [`docs/web-api.md`](../../docs/web-api.md): the log treatment, and the `422` message bound.
  - `CHANGELOG.md` `[Unreleased]`: the partial-secret redaction and the log treatment under **Security**; the
    report limit and the dashboard fields under **Changed**.

## Test strategy

The `specs/README.md` rules apply: logic in unit tests, integration attached to the shared scan, a budget of
about one test line per `src/` line, the whole suite under 2 minutes, no real network.

**`tests/unit/test_output.py`:**

- **Profiles.** One parametrized table, one row per sink: an input with every kind of control character, an
  oversized value and a surrogate goes in, and the row asserts the bound and the neutralization. Each row's
  positive control is the same input through the primitive alone, which shows the characters that the profile
  removes. Idempotence: each profile applied twice gives the same text.
- **Order (RF-01, ADR-2).** A value whose cut falls on a control character comes out with the escape whole. A
  value holding a secret through `safe_text(..., redactor=...)` shows `[redacted]` and never a fragment.
- **Cut rule (RF-02, ADR-3).** A known secret placed so that each cut splits it at every offset from 1 to its
  length minus 1, under every spelling. The cuts covered are `truncate` of `Name`, `Text` and `Url`,
  `EvidenceItem.of`, and the snippet helpers of `xss`, `cmdi`, `ssrf`, `upload` and `envelope` called with a body
  that holds the secret. The assertion is that no fragment of 4 or more characters remains. Positive controls:
  the same secret away from any cut is redacted whole, a title that ends with the secret's first letters but
  has no marker is left alone, and a fragment of 3 characters at an edge remains. Seen failing by removing the
  cut rule (a fragment remains) and by matching anywhere (the title control fails).
- **Traceback (RF-04).** An exception chain (cause, context, a group with notes) whose messages hold a line
  break, ESC and a bidirectional override. The test counts the lines of `safe_traceback` against the frames and
  exceptions, checks that no raw control character is left, and checks the bound. The positive control is
  `traceback.format_exception` of the same chain, which has the extra lines and the raw characters.
- **Log filter.** Through `caplog` at `DEBUG`: the message with `%s` arguments, a record whose `getMessage`
  raises (left alone, positive control that `logging` reports it), and `exc_info`. The filter keeps level and
  handlers.

**`tests/unit/test_output_inventory.py` (RF-09, ADR-8):** the walk over the source and `OUTPUT_SINKS`, with
positive controls over a throwaway source string (an unlisted `print` fails, a literal-only call passes, a stray
`logging.getLogger` fails). Seen failing by adding a `typer.echo(value)` to a scratch copy of a module.

**Shared cases (RF-07, ADR-7):** `tests/unit/test_text_cases.py` and `web/src/lib/text.test.ts` both run the
file. Seen failing by removing one range from `HIDDEN_RANGES` and, separately, from `INVISIBLE_CHARS`.

**Reports (RF-05, RF-08).**

- The existing reporter tests keep their expected output, which proves the move to `safe_text` changed nothing.
- `load_result` is tested with a file object whose `read` records the sizes asked: no call above 1 MiB.
  Seen failing against today's `read(MAX_REPORT_BYTES + 1)`.
- A file of exactly 64 MiB loads and one byte more is refused. A generated file of 64 MiB is not kept: the
  test writes it into `tmp_path` and removes it.
- **Memory.** A test runs `load_result` in a subprocess on an 8 MiB dense file and on an 8 MiB file of large
  values, reads the peak resident size (`resource.getrusage`, POSIX only, skipped on Windows with that reason)
  and asserts a ratio under 20× and 5× the file's size.
- **Scan warning.** A unit test of the write step with a rendered JSON of 64 MiB plus one byte: the warning is
  printed and the file is written whole. The positive control is one byte smaller, with no warning.

**Web API (RF-04, RF-06).**

- **`tests/api/test_log_canary.py`.** A scan through the orchestrator test seam raises an exception whose
  message holds a known canary value, ESC, a line break and 100 Ki characters. A second scan stores a result
  into a database whose findings table was dropped, so SQLAlchemy raises with the statement and its
  parameters. Logging is captured at `DEBUG` on the root logger. The test asserts that no raw control
  character, no text over the bound and no parameter (the canary) appears, that each record keeps its line
  count, and that the stored `Scan.error` is bounded. The positive controls are that both failures were
  logged (the scan id appears), and that an engine without `hide_parameters` shows the canary in the same
  error (seen failing).
- **`422`.** A body with a 10 Ki-character key and a field whose validator message would hold a control
  character. `msg` and `loc` come back bounded and escaped, without `input`.

**Dashboard (RF-07, ADR-8).** `hostile-render.test.tsx` as described, seen failing by removing `display()` from
the target of the scan list. The existing component tests gain no copies: the hostile render covers the fields.

**Same scan, same report (RF-10).** As in spec `024`: before the first change, the fixture application is
scanned anonymously, with `[auth]` cookies and headers, and with the automated login. The requests the fixture
received and the JSON reports are saved outside the repository, and the same scans are compared when the spec
closes, leaving out timestamps and durations. A difference other than a redacted fragment next to a cut fails
the comparison.

**Mutation (RNF-06).** `core/output.py`, the changed parts of `scrub.py`, `reporting/__init__.py` and the log
filter go through mutation testing in batch at the end of each stage that changes them. Every changed function
has a killed mutant, every survivor is triaged, and the score goes in the pull request.

## Deviations

1. **The prefix and suffix sets are an index (data model, ADR-3).** `Redactor` does not hold every prefix and suffix
   of every spelling: that grows with the square of a secret's length (an 8 KiB header value would take hundreds of
   MiB). It indexes each prefix by its last 4 characters and each suffix by its first 4, and checks a candidate
   against the spelling at the cut. The fragments it finds are the same, and memory grows with the secrets' length.
2. **Idempotence holds for a value that fits its bound (components, ADR-2).** The `STORE`, `DOCUMENT` and `JSON`
   profiles give the same text on a second pass, cut or not. The `TERMINAL`, `LOG` and `MESSAGE` profiles do too,
   except for a value cut at the bound whose escapes make it longer than the bound: a second pass cuts it again. No
   output applies a profile twice, and cutting on the source is what ADR-2 asks for.
3. **`one_line` is a choice of the `TERMINAL` profile only (data model).** `LOG` and `MESSAGE` always escape line
   breaks, and `STORE`, `DOCUMENT` and `JSON` never do, whatever the caller passes.
4. **The evidence marker is `core/bounded.py::EVIDENCE_MARKER` (module layout).** `CUT_MARKERS` names it, and
   `core/output.py` imports only `core/bounded.py`, `core/text.py` and `core/secrets.py`, not the finding model.
   The terminal bound is `core/output.py::TERMINAL_MAX_CHARS`, since the engine cannot import the CLI; Stage 1
   points `_render` at it.
5. **The marker rule acts from Stage 0 (RF-02, tasks).** `scrub.py` uses `Redactor` from Stage 0, so a fragment next
   to a cut marker is redacted in every field from this stage on, and its CHANGELOG line goes in this stage's pull
   request. Stage 1 adds the evidence edges (`cut_edges`).
6. **The traceback's own layout (RF-04, ADR-4).** Each stack is written as Python formats it. The members of an
   exception group follow a `--- sub-exception i of n ---` line instead of Python's box drawing, with Python's
   limits (15 members, 10 levels). Each exception's line is bounded to the `LOG` message bound, and the whole text
   is cut at a line boundary, so the cut never splits an escape.

## Implementation notes

- **Stage 0.** The RF-10 baseline was taken on `main` at `eb66900` (Python 3.15.2, Windows): 3415 tests collected
  (3413 passed, 2 skipped), 97 % line and branch coverage in total, the per-file table, and the three scans of the
  fixture application with the requests it received. They are kept outside the repository. A second run of the
  anonymous scan gave the same requests and the same findings. A second run of the login scan gave the same check
  ids, severities and fingerprints, and 137 of its 941 requests differed, because the command, template and
  expression probes draw random operands: the Stage 4 comparison of the login scan's requests leaves those out.
  Durations: 5.3 s anonymous, 4.9 s with the `[auth]` cookie and header, 29.6 s with the login.
- **Stage 0 mutation.** 155 mutants over `core/output.py`, `store_text`, `EVIDENCE_MARKER` and
  `escape_json_controls`: 144 killed, 5 ended in a timeout (an endless loop the tests detect), and 6 survived as
  equivalent (a short cut that gives the same result, and a guard no input reaches). The first run left 11 other
  survivors at boundaries the tests did not reach: the group width and depth, a fragment that starts the text,
  fragments apart, a run of dots, the longest fragment across two secrets, an exception without a message, and the
  traceback bound. Each now has a test. The last one was a defect: a traceback of exactly the bound was cut, because
  the size counted a line break before the first line.
