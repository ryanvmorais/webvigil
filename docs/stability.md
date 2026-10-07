# Stability and versioning

From `1.0.0` WebVigil follows [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.
This page says what that promises, what it does not, and how a change is announced. Every
release is described in the [changelog](../CHANGELOG.md).

| Release | What it may contain |
|---|---|
| **Patch** (`1.0.x`) | Bug fixes, false-positive and false-negative fixes, documentation. |
| **Minor** (`1.x.0`) | New checks, flags, configuration keys and report fields; detector improvements; tuned defaults (see below); everything backward compatible with the promise on this page. |
| **Major** (`x.0.0`) | A change that breaks something promised below. Always listed under **Breaking** in the changelog. |

## What is stable

Within one major version these do not change in a way that breaks a script, a CI job or a
saved file:

| Surface | The promise |
|---|---|
| **CLI** | Command names (`scan`, `list-checks`, `report`, `version`) and the options in `--help`. A flag is renamed or removed only in a major release; where possible the old name keeps working for a minor release first, with a notice. |
| **Exit codes** | `0` clean · `1` unexpected error · `2` usage error · `3` findings at or above `--fail-on` · `4` operational error (bad target, unreachable host, configuration, a failed login) · `5` Active Mode without `--authorized-by`. |
| **Configuration** | The sections and keys of `webvigil.toml` (see [`webvigil.example.toml`](../webvigil.example.toml)). A key is not renamed or removed within a major version; an unknown key is an error, so a typo never passes silently. |
| **Check ids** | An id such as `http.headers.csp` or `session.fixation` is not renamed or removed within a major version. It is what `[checks] disabled` takes and what a SARIF rule is called. |
| **Safety defaults** | What decides whether something is sent to the target never gets looser: Safe Mode is the default, Active Mode needs `--mode active --authorized-by`, and every opt-in that writes to the target, makes a login request or sends library names to a third party stays off by default. |
| **JSON report** | The canonical report (`--format json`) carries `schema_version`. Within a schema version fields are only **added**: a consumer must ignore keys it does not know. Removing, renaming or retyping a field raises `schema_version` and is a major release. A WebVigil refuses a report whose schema is newer than it understands, with a message that says to upgrade. |
| **SARIF report** | Valid SARIF 2.1.0; a rule id is the check id. |
| **Fingerprints** | A finding's `fingerprint` (the stable identity CI baselines and de-duplication rely on) does not change between releases of one major version, unless the finding is genuinely a different one. |

## What may change in a minor or patch release

- **Detection.** New checks and better detectors can **add findings** to a scan of the same
  target, and false-positive fixes can remove them. A build that must not change between
  releases should pin the version (for example `~=1.0`) and read the changelog before moving.
- **Default severity** of a check. It decides which findings reach `--fail-on`, so it is always
  announced in the changelog, but it is not treated as a breaking change.
- **Tuned defaults**, such as request budgets, page caps and timeouts. These are listed in the
  changelog.
- **Dependencies and supported Python versions.** The minimum Python is `3.12`; a Python
  version that reaches end of life can be dropped in a minor release, with notice.
- **A security fix** may change behaviour in any release if that is what the fix needs.

## What is not covered

These are usable but **provisional**: they can change in a minor release, and the changelog says
so under **Changed**.

- **The Python API.** The package is typed (`py.typed`) and can be imported, but only the
  command line and the files above are the compatibility surface. The names most likely to be
  kept are `webvigil.core.Orchestrator`, `ScanConfig`, `ScanResult`, `Finding`, and
  `webvigil.checks.Check` with `register` (the check contract in
  [writing-checks.md](writing-checks.md)); internals such as the crawler, the HTTP client and
  the injection scanner are not.
- **The Web API (`webvigil-web`) and the dashboard (`web/`).** Their endpoints, the database
  schema and the dashboard are provisional. Database migrations move forward only. The dashboard
  is part of the repository; it is not in the Python package.
- **The text of messages**: warnings, error messages and the terminal summary are meant for
  people, not for parsing. Use the JSON report.
- **Files in `docs/`, `specs/` and `tests/`** describe the project; they are not an interface.

## Deprecations and breaking changes

A feature that is going away is first **deprecated**: it keeps working for at least one minor
release, a warning says what replaces it, and the changelog lists it under **Deprecated**. It is
removed in the next major release and listed under **Breaking**. A breaking change never lands in
a minor or patch release, except a security fix that cannot be done any other way.

## Supported platforms

The test suite runs in CI on Linux with Python 3.12, 3.13 and 3.14. WebVigil is developed and
used on Windows as well; macOS is expected to work but is not tested in CI. A platform-specific
bug is welcome as an [issue](https://github.com/ryanvmorais/webvigil/issues).
