# Page-content checks

Spec [`013-auth-and-api-surface`](../specs/013-auth-and-api-surface/). Two passive checks
(`Category.CONTENT`) over what a page's HTML tells the browser to load. Both run against the
responses the crawler already fetched — **no extra requests** — and are on by default.

## `content.sri.missing` (`MEDIUM`, CWE-353 / CWE-1104)

Flags a **cross-origin** `<script src>`, `<link rel="stylesheet">`, or
`<link rel="preload"|"modulepreload">` loaded with **no `integrity` attribute** — if that
third party (or the connection to it) is compromised, arbitrary code runs in the page's
context. A separate finding covers a subresource that *has* `integrity` but no
`crossorigin`, where the browser cannot read the response to verify the hash and the check
silently does not run.

A **same-origin** subresource is not flagged — SRI's value is for third-party CDNs. Each
distinct resource URL is reported once, however many pages reference it.

## `content.mixed` (`MEDIUM` / `LOW`, CWE-319)

Flags an `https://` page that references a subresource over plain `http://`. **Active**
content (`script`, `link`, `iframe`, `form`, `object`, `embed`) is `MEDIUM` — the browser
blocks it and the feature breaks. **Passive** content (`img`, `video`, `audio`, `source`)
is `LOW` — it loads over an interceptable channel. A `//host` protocol-relative URL inherits
`https` and is not mixed content; an `http://`-served page is skipped (nothing to
downgrade).
