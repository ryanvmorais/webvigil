# Writing a check

> This document is a stub. The check plugin contract is finalized in the
> `001-foundation` spec; this file will be filled in once it lands.

A check is a plugin that inspects the target and returns zero or more `Finding` objects.

```python
from webvigil.checks import Check, register
from webvigil.core import Finding, ScanContext, Severity


@register
class ExampleCheck(Check):
    id = "http.headers.x-content-type-options-missing"
    name = "Missing X-Content-Type-Options header"
    category = "HEADERS"
    mode = "PASSIVE"
    default_severity = Severity.LOW
    cwe = [693]
    references = ["https://owasp.org/www-project-secure-headers/"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        ...
```

## Testing requirements

Every check ships with unit tests covering:

- a **vulnerable** fixture — the finding is reported, with correct severity and evidence;
- a **hardened** fixture — nothing is reported (false-positive guard).
