# Scanning an API from its OpenAPI description

Spec [`013-auth-and-api-surface`](../specs/013-auth-and-api-surface/). A JSON API serves no
HTML and has no links, so the crawler finds the entry document and stops. Point WebVigil at
the API's **OpenAPI / Swagger description** and it uses the declared operations to reach
every endpoint and fuzz its parameters.

```bash
webvigil scan https://api.example.com --openapi https://api.example.com/openapi.json
webvigil scan https://api.example.com --openapi ./openapi.json --mode active --authorized-by me
```

```toml
[scan]
openapi = "openapi.json"          # a local path or an in-scope URL
openapi_max_operations = 150      # cap on operations seeded from the import
```

## What it does

The document is loaded **before the crawl**. For every `GET` and `POST` operation it
declares:

- the **operation URL** is added to the crawler as a seed — fetched in scope, counted in
  `pages_scanned`, bounded by `max_pages` — so the passive checks and the injection pass see
  endpoints that nothing links to;
- its **query parameters**, **path parameters** (`/users/{id}`), and
  **`application/x-www-form-urlencoded` body fields** become injection points, tested by the
  same detectors as any crawled parameter (XSS, SQLi, traversal, open redirect, SSRF,
  command injection, SSTI, CRLF, …) under the existing Active-Mode budget;
- a missing parameter value is synthesised deterministically — `example` → `default` →
  first `enum` → a type-based placeholder — so every request is well-formed.

Operations whose path or `operationId` looks like authentication or a state-changing action
(`login`, `logout`, `delete`, `password`, `checkout`, …) are **not** fuzzed, mirroring the
form-exclusion rule.

## Limits

- **JSON only.** `--openapi` reads a `.json` file or a URL returning JSON. A YAML document
  must be converted first (any tool). Adding YAML support would mean a new runtime
  dependency, which WebVigil has avoided since `v0.4`.
- **No leaf-level JSON-body fuzzing.** An `application/json` request body is synthesised and
  sent with the baseline request, but its individual fields are **not** enumerated as
  injection points. A JSON-only `POST` operation with no path parameters therefore
  contributes nothing to fuzz — reach it with a form body, or wait for a follow-up spec.
- **Local `$ref` only.** `#/components/…` / `#/definitions/…` pointers are resolved (cycles
  are broken with a placeholder). A `$ref` to another file or a URL is skipped with a
  warning.
- **`GET` / `POST` only.** A `PUT` / `PATCH` / `DELETE` operation is not exercised — the
  injection engine sends only `GET` and `POST` (a deliberate scope line since `v0.6`).
- **The server host is the scan target.** A `servers[0].url` (or Swagger `host`) that names
  a different host is overridden with the target origin, with a warning — the engine still
  talks only to the target. An out-of-scope `--openapi` URL is refused before any request.
- **A parse failure is fatal.** An unreadable, non-JSON, or non-OpenAPI `--openapi` value
  stops the scan with a message — you asked for the import explicitly. A document that
  parses but declares no usable operations is a warning, and the scan continues with a
  normal crawl.

## Authenticating the API scan

Pair `--openapi` with `--header` for a bearer token or an API key — see
[`authenticated-scanning.md`](authenticated-scanning.md#header-and-bearer-authentication).
The token reaches the target's requests only and never appears in the report.
