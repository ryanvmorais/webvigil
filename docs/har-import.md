# Scanning a single-page application from a HAR recording

Spec [`021-har-import`](../specs/021-har-import/). WebVigil's crawler reads HTML and runs no
JavaScript, so a single-page application (SPA) looks to it like one near-empty page: the routes, the
forms and the API calls are all built in the browser. A browser already knows that surface. Walk through
your application once with the network panel open, save the traffic as a **HAR file**, and give it to
WebVigil: the requests you made seed the crawl and the injection pass, the same way an
[`--openapi`](api-scanning.md) description does.

```bash
webvigil scan https://app.example.com --har ./traffic.har
webvigil scan https://app.example.com --har ./traffic.har --openapi ./openapi.json \
  --mode active --authorized-by "Jane / #1234" --submit-post-forms \
  --header "Authorization: Bearer $TOKEN"
```

```toml
[scan]
har = "traffic.har"          # a local file; the CLI flag wins
har_max_operations = 150     # cap on operations seeded from the recording
```

## Recording one

Any tool that writes HAR 1.1 or 1.2 works: Chrome, Edge, Firefox and Safari (network panel, "Save all
as HAR"), Burp Suite, OWASP ZAP and mitmproxy (export the history). Tips:

- **Record a read-only walk.** Browse, search, open pages, and avoid buying, deleting or sending
  anything. Every `GET` in the file is requested again by the crawl, in Passive Mode too, and a `GET`
  that changes state is not recognised as such unless its path looks like it (see below).
- **Use a test account**, and keep the recording to the application you are about to scan. Hosts that
  are not the target are ignored, but the file itself is yours to protect.
- **Export without response bodies** if the browser offers it. WebVigil reads only the requests; a file
  over 64 MiB is refused, and a HAR with every response embedded gets there quickly.

## What it does

The file is read **before the crawl**, locally; the import sends nothing. For every entry that is the
target's own `GET` or `POST` request it keeps an operation:

- a `GET` becomes a **crawl seed** with the query string it was recorded with, because an SPA endpoint
  often answers nothing without its parameters; it is fetched in scope, counted in `pages_scanned`,
  bounded by `max_pages`, and its parameters are **injection points** (`source` `har`);
- a `POST` with a form body (`application/x-www-form-urlencoded`, or the text parts of
  `multipart/form-data`) contributes its fields as injection points; a `POST` with a JSON body
  keeps only the body's **shape** (its keys and the types of its values), which the `POST` crawl phase
  sends. No JSON value is fuzzed (the limit of [`--openapi`](api-scanning.md#limits));
- an operation recorded both in the HAR and in `--openapi` is the OpenAPI one.

A `POST` is never sent by a Passive scan. It goes out only from the `POST` phase of
[`--submit-post-forms`](authenticated-scanning.md#post-forms----submit-post-forms-opt-in) (Active Mode,
off by default, writes to the target), and the injection pass fuzzes it only in Active Mode.

One summary line says what happened, so "no finding" can be told apart from "never imported":

```text
HAR import: 212 entries read, 41 operations seeded (30 GET, 11 POST); ignored: 118 out of scope, 31 static, 14 other method, 6 unsafe, 2 malformed
```

## What is left out, and why

| Entry | Why |
|---|---|
| another host, another scheme, `ws:` / `data:` / extension URLs | the engine talks only to the target; `--scope subdomains` widens the host rule as it does for the crawl |
| images, fonts, stylesheets, scripts, media, source maps | the crawler already finds the scripts a page references and the fingerprint pass reads them |
| `PUT` / `PATCH` / `DELETE` / `OPTIONS` / `HEAD` | the injection pass fuzzes `GET` and `POST` only |
| a path that looks like authentication or a state-changing action (`login`, `logout`, `register`, `password`, `delete`, `checkout`, `pay`, `order`, ...) | a person who recorded a purchase does not make WebVigil place another one |
| an entry with no usable request, URL or parameter name, a URL over 2,048 characters | counted as malformed |

## Secrets in the recording

A HAR often holds a live session. WebVigil never uses it:

- **Headers and cookies are never read**, not `Cookie`, not `Authorization`, not `Set-Cookie`, not
  response bodies. The only thing taken from them is the fact that the recording looks authenticated.
- A query or form parameter whose **name** looks like a secret (`token`, `access_token`, `api_key`,
  `key`, `secret`, `password`, `auth`, `session`, `sid`, `jwt`, `signature`, `otp`, `csrf`, ... whole
  words, any case, with `_` and `-` as breaks) keeps its name, because it is still an injection point,
  and loses its **value**: it becomes `wv`. So does any value over 256 characters.
- A recorded value under a name that is not on that list (`?code=...`) is kept as the baseline. Record
  against a test account.
- The credentials in the URL (`https://user:pass@host`) and the fragment are dropped.

To reach the routes of the logged-in application the scan has to log in **itself**, with `--cookie`,
`--header` or `--login-url` (see [authenticated scanning](authenticated-scanning.md)). When the recording
carries a session and the scan carries none, the scan says so in one warning, without naming a value.

## Limits

- **Routes, not templates.** `/rest/products/42/reviews` is one literal URL; WebVigil does not guess that
  `42` is a parameter.
- **One file.** Merge several recordings with any HAR tool, or record once.
- **JSON values are not fuzzed**, and a recorded GraphQL query becomes the shape `{"query": "wv", ...}`,
  which the server will reject. The route is still seeded.
- **A recorded `multipart/form-data` body is sent urlencoded**, as `--openapi` does.
- **Bounds.** A file over 64 MiB is refused; only the first 20,000 entries are read; at most
  `har_max_operations` (150) operations are seeded; a value is kept up to 256 characters. Past the entry
  or operation limit the scan warns and goes on.
- **A bad file is fatal.** A missing file, a URL, invalid JSON or a document with no `log.entries` stops
  the scan with exit code `4`, because you asked for the import. A file that parses but holds nothing
  usable is a warning.
- **The Web API and the dashboard do not accept a HAR path**: it would be read from the server's disk by
  a remote caller.
