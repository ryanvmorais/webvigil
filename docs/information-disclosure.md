# Information disclosure

Spec [`005-info-disclosure`](../specs/005-info-disclosure/). WebVigil detects data a target
leaks by accident: framework error pages, directory listings, and — with an opt-in toggle —
reachable `.git` / `.env` / backup / debug-endpoint paths.

## Two tiers

### Passive (always on)

Runs against the responses the crawler already fetched — **no extra requests**.

- **`disclosure.debug.error-page`** — framework error pages and stack traces (Werkzeug /
  Flask, Django `DEBUG`, Rails, ASP.NET, PHP, Java/JSP, Node/Express). The interactive
  Werkzeug debugger is `HIGH` (it can execute code); a plain stack trace is `MEDIUM`; a lone
  PHP notice is `LOW`.
- **`disclosure.listing.directory-index`** — server-generated directory listings (Apache
  `mod_autoindex`, nginx `autoindex`, Python `http.server`).
- **`disclosure.session-id-in-url`** (`MEDIUM`, CWE-598 — spec 013) — a session identifier
  or credential (`jsessionid`, `phpsessid`, `sid`, `sessionid`, `access_token`, `apikey`,
  …) carried as a query or `;name=value` path parameter in a URL the **target produced** —
  a hyperlink, a form action, or a redirect `Location`. The page's own request URL is not
  inspected (it may be a scanner-crafted `--openapi` seed), and a bare one-time `?token=`
  link (reset / verification) is deliberately excluded. Every session value is redacted
  (`sid=***`), in the evidence and in the finding's location, and so is every copy of it,
  percent-encoded in a URL nested in a parameter; a URL with more than eight session values is
  hidden from its first parameter on.
- **`disclosure.private-ip`** (`LOW`, CWE-200 — spec 013) — an RFC-1918, loopback,
  link-local, or IPv6 unique-local address literal in a response body (an HTML comment, a
  JSON value, an error page). The target's own host is never flagged; at most ten distinct
  addresses are reported per page.

### Probe (opt-in — `--probe` / `[disclosure] probe = true`)

When enabled, the orchestrator runs a bounded probe pass:

1. **Calibrate.** Requests a few random paths to learn the target's "not found" response
   (status, body length, SPA catch-all shell). If it can't calibrate, it warns and falls
   back to content validation only.
2. **Probe a curated catalogue** of well-known sensitive paths under the target origin,
   plus a few derived probes: `<script>.map` for each in-scope script the crawl referenced,
   and the VCS paths re-based under each discovered directory (capped).
3. **Validate.** A response is a hit only if it is not the "not found" page **and** its body
   matches what the path implies — `/.git/config` is a git ini, `/.env` has `KEY=VALUE`
   lines, `/package.json` is a JSON object with `dependencies`, and so on.

Hits become findings from six checks: `disclosure.vcs.exposed` (`HIGH`),
`disclosure.config.dotenv-exposed` (`HIGH`), `disclosure.config.manifest-exposed` (`LOW`),
`disclosure.backup.file-exposed` (`MEDIUM`, `HIGH` for a `.sql` dump),
`disclosure.debug.endpoint-exposed` (`MEDIUM`, `HIGH` for `phpinfo` / `actuator/env`),
`disclosure.sourcemap.exposed` (`MEDIUM`).

Probing sends only in-scope `GET` requests with no payloads and no state-changing calls, and
the good-neighbour policy (concurrency cap, per-host delay, scope guard) applies to every
one. It is **not** gated by Active Mode — but it is **off by default**, because it is
noisier than the default passive scan (~100 extra requests, 404 noise in the target's logs).
When it is on it is the most active thing Safe Mode does.

## Secret redaction

Any body that can carry a credential — `.env`, `/actuator/env`, `.npmrc`, a config backup —
is redacted **before** it becomes part of a finding: keys and structure are kept, values are
masked. The raw secret never reaches the `ScanResult`, a report, or (via the Web API) the
database. A finding proves exposure by shape, not by quoting the secret. Every catalogue entry is
masked: `.env` files mask every value (a quoted value that spans lines is dropped whole),
`.htpasswd` every hash, JSON documents every key whose name holds a secret word in any spelling
(`DB_PASSWORD`, `jwtSecret`, `ConnectionStrings`), and every other body gets the generic masking:
token shapes, the user information of a URL, and the value assigned to a secret-sounding name
(`Password=`, `SECRET_KEY =`, `'db_password' =>`, `define('DB_PASSWORD',`), however short. A
JSON body is parsed for this only up to 256 KiB, and only the first 2,000 characters of its
indented form are built; a longer body gets the generic masking in its first 1 KiB. The JSON key
validator of the catalogue parses a body up to the same 256 KiB, and judges a longer one by its content
patterns alone.

## What it does not do

- **Not a content-discovery scanner.** The catalogue is a small curated list of names that
  are sensitive by definition — not a dirbuster-style wordlist. There is no `--wordlist`.
- **Reads the top of a page only.** The error-page and directory-listing signatures look at the
  first 256 KiB of a body, and every pattern is bounded, so a hostile page cannot keep the scan busy
  in them. A framework error that appears only after that point is not recognised.
- **No active error induction.** It reads error pages the crawl surfaced; it does not send
  malformed input to trigger one (that is spec 006).
- **No `.git` exfiltration.** It reports that `.git/` is reachable; it does not download
  objects or rebuild the tree.
- **No manifest parsing.** An exposed `package.json` is reported as a disclosure finding
  only — it is not fed into the spec 004 dependency inventory.
- **Source maps need `--probe`.** Detection probes `<script>.map`; a `sourceMappingURL`
  comment pointing at a renamed map is not followed.
- **No new API or dashboard surface.** `disclosure.*` findings ride the existing findings
  list and filters.

## Turning it off

The passive checks and the probe pass are ordinary checks — disable any by id:

```toml
[checks]
disabled = ["disclosure.debug.error-page", "disclosure.vcs.exposed"]
```

Disabling **every** probe-fed `disclosure.*` id skips the probe pass entirely, even with
`--probe` (no calibration, no requests). The passive checks still run.

## The catalogue

`src/webvigil/checks/disclosure/data/paths.toml` — hand-curated, versioned in the repo,
grouped by family (`vcs`, `config`, `manifest`, `debug`) with a per-entry content validator,
plus a `[backups]` table expanded into a `basename × suffix` cross-product. It is not
user-extensible; grow it in a commit.
