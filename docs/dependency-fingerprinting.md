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
- **No online lookups by default.** Matching is offline against the vendored database.
  An opt-in OSV.dev provider (`--osv-online`, see below) adds online coverage on top.
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

## OSV.dev online provider (`--osv-online`)

Spec [`010-osv-online`](../specs/010-osv-online/). The vendored database only advances when
a maintainer refreshes it, and its coverage is Retire.js's coverage. `--osv-online` /
`[deps] osv_online` adds a second advisory source: [OSV.dev](https://osv.dev/) (Google /
OpenSSF), the `npm` ecosystem, no API key.

**It is off by default** — it is the only part of the engine that contacts a host other
than the scan target.

```bash
uv run webvigil scan https://example.com --osv-online
```

```toml
[deps]
osv_online = true
# osv_timeout_s = 10.0
# osv_base_url  = "https://api.osv.dev"
```

- **What is sent.** The names and versions of the client-side libraries the scan detected,
  as `{name, ecosystem: "npm", version}` triples — one `POST /v1/querybatch`, then one
  `POST /v1/query` for each package that had a match. Nothing about the target (no URL,
  hostname, cookie, or finding) ever leaves the machine.
- **How results are used.** OSV advisories are **merged** with the vendored Retire.js
  match for the same detection and de-duplicated by identifier (a shared CVE / GHSA / OSV
  id), so a library covered by both sources yields one finding carrying the union of the
  identifiers and references. OSV never replaces the offline match.
- **On failure.** Any network error, timeout, bad status, or unparseable response is a
  scan **warning**, not an error — the scan still reports the offline results and the exit
  code is unaffected.
- **No cache.** Each opted-in scan queries OSV live (a repeated `(name, version)` within
  one scan is queried once). There is no on-disk cache and no "refresh script".
- **Limitations.** `npm` only (no PyPI / other ecosystems); a few Retire.js library names
  are translated to their npm package name, the rest are used as-is, so an unusual name may
  not match; no reachability analysis (unchanged from the offline match).

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
