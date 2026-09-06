# Writing a check

A check is a plugin that inspects the target through a `ScanContext` and returns zero or
more `Finding` objects. Checks are the unit of coverage in WebVigil; the v0.1 checks under
`src/webvigil/checks/` are the reference implementations.

## The contract

```python
from webvigil.checks.base import Check
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, Finding, Location, Severity


@register
class XContentTypeOptionsCheck(Check):
    id = "http.headers.content-type-options"      # stable, dotted, unique
    name = "X-Content-Type-Options not nosniff"
    category = Category.HEADERS                    # HEADERS | COOKIES | TLS | CORS
    mode = ScanMode.PASSIVE                        # PASSIVE (default) | ACTIVE
    default_severity = Severity.LOW
    cwe = (693,)
    references = ("https://owasp.org/www-project-secure-headers/",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        page = ctx.entry
        if (page.headers.get("x-content-type-options") or "").lower() == "nosniff":
            return []
        return [
            self.finding(
                title="X-Content-Type-Options is not set to nosniff",
                description="Browsers may MIME-sniff the response...",
                remediation="Send 'X-Content-Type-Options: nosniff'.",
                location=Location(url=page.url, header="X-Content-Type-Options"),
                dedup_key="missing",
            )
        ]
```

### Metadata (class attributes)

| Attribute | Purpose |
|---|---|
| `id` | Stable identifier. It appears in reports, `--fail-on` output, and `checks.disabled`. Never change it. |
| `name` | Human-readable title for `list-checks`. |
| `category` | One of `Category`. |
| `mode` | `PASSIVE` runs by default and must be safe against production. `ACTIVE` only runs after the authorization gate. |
| `default_severity` | Used when `self.finding(...)` is called without an explicit `severity`. |
| `cwe`, `references` | Copied onto every finding the check emits. |

### `run(ctx)`

- `ctx.entry` — the `Page` for the seed URL.
- `ctx.pages` — every discovered `Page` (seed first). Iterate these for per-page checks
  (e.g. cookies).
- `ctx.http` — the shared `HttpClient`. Use it for extra requests; it enforces scope,
  rate limiting, and retries. Never build your own client.
- `ctx.target`, `ctx.config` — scope rule and resolved configuration.

Build findings with **`self.finding(...)`** — it fills in `check_id`, `cwe`, `references`,
and the `fingerprint` for you. Pass a short `dedup_key` describing the specific problem
(`"missing"`, `"unsafe-inline"`, `"TLSv1.0"`), so the same issue seen on several pages
collapses to one finding.

An exception raised from `run` is caught by the orchestrator, recorded as a `CheckError`,
and does not abort the scan — but prefer to handle expected failures yourself.

## Registration

- **First-party:** the `@register` decorator plus an import from the relevant
  `webvigil/checks/<category>/__init__.py`.
- **Third-party:** ship a package that declares the entry point and `@register` your
  classes in the imported module:

  ```toml
  [project.entry-points."webvigil.checks"]
  my_pack = "my_pack.checks"
  ```

  `webvigil` calls `load_plugins()` at startup, which imports every such module.

## Testing requirements

Every check ships with unit tests covering:

- a **vulnerable** fixture — the finding is reported, with the expected `id`, `severity`,
  `dedup_key`, and an evidence substring;
- a **hardened** fixture — nothing is reported (false-positive guard).

`tests/support.py` has `make_page` / `make_context` builders. The integration test in
`tests/integration/` additionally asserts that a scan of the hardened fixture app produces
**zero** findings.
