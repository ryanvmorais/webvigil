# Dependency fingerprinting

Spec [`004-deps-fingerprint`](../specs/004-deps-fingerprint/). WebVigil identifies the
client-side JavaScript libraries a target serves and reports the ones running a version with
a known vulnerability.

## What it does

- **Detection.** After the crawl, WebVigil parses each HTML page for `<script>` / `<link>`
  references and inline `<script>` blocks, fetches the **in-scope** resources those pages
  reference, and matches them against the identification rules in a vendored copy of the
  [Retire.js](https://retirejs.github.io/) database. A library is identified from its
  resource **URL**, a **version banner** in the file body, or an exact **file hash**.
- **Matching.** Each detected `(library, version)` is checked against that database's
  advisory ranges. A match becomes a `deps.js.vulnerable-library` finding carrying the
  CVE / GHSA identifiers, a summary, the CWE ids, and the first fixed version.
- **Inventory.** Every detection — vulnerable or not — is recorded on the scan result as a
  *technology inventory*, rendered in the HTML and Markdown reports, stored by the Web API,
  and shown on the dashboard's scan-detail screen.
- **Version undetermined.** A recognised library whose version can't be read produces an
  `INFO` `deps.js.library-detected` finding so the gap in coverage is visible.

## What it does not do

- **No active probing.** WebVigil only fetches resources the target's own pages reference —
  it never guesses paths like `/js/jquery.min.js`. It runs in Safe Mode.
- **No cross-origin fetches.** A script served from a third-party CDN is fingerprinted from
  its URL only; the scope guard blocks the download.
- **No manifests.** WebVigil does not read `package.json` / `requirements.txt` from disk and
  does not consume manifests a target exposes over HTTP (that is spec 005's territory).
- **No online lookups.** Matching is entirely offline against the vendored database. An
  `AdvisoryProvider` seam exists for a future online provider (e.g. OSV.dev).
- **No reachability analysis.** A vulnerable version is reported whether or not the flawed
  code path is actually used.
- **Best effort.** Fetching is capped at 50 distinct in-scope resources per scan; hitting
  the cap adds a scan warning. Minified bundles with their version banner stripped may be
  missed unless an exact file hash matches.

## Turning it off

The pass runs only when a `DEPS` check is selected. Disable **both** ids to skip it entirely
(no extra requests, empty inventory):

```toml
[checks]
disabled = ["deps.js.vulnerable-library", "deps.js.library-detected"]
```

## The vendored database

`src/webvigil/checks/deps/data/retirejs.json` is a normalised copy of the Retire.js
community repository (Apache-2.0, attributed in `NOTICE`).
`src/webvigil/checks/deps/data/PROVENANCE.json` records where it came from and when.

Refresh it with:

```bash
uv run python scripts/update-retirejs-db.py            # fetch, normalise, write both files
uv run python scripts/update-retirejs-db.py --dry-run  # report the delta, write nothing
```

This script is the only part of the project that reaches the Retire.js servers. When the
vendored file is more than 90 days old, `webvigil version` and every scan emit a soft
warning; CI prints it but does not fail.
