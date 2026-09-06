"""The six active-injection checks: turn ``InjectionHit``s into findings (RF-08..RF-11).

None of them issues a request — ``engine.InjectionScanner`` (an orchestrator pass) has
already run and left its hits on ``ctx.observations.injection_hits``. Each check filters by
``kind``.
"""

from __future__ import annotations

from typing import ClassVar

from webvigil.checks.base import Check
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, EvidenceItem, Finding, Location, ScanMode, Severity

_OWASP = "https://owasp.org/www-community"

_DESCRIPTION: dict[str, str] = {
    "xss": (
        "A value supplied in this parameter is reflected in the response with its "
        "HTML-significant characters intact, in a context where a browser would execute it. "
        "An attacker can craft a link that runs arbitrary JavaScript in a victim's session."
    ),
    "sqli-error": (
        "A value supplied in this parameter reaches a SQL query unsanitised: a broken quote "
        "produced a database error in the response. The query can likely be rewritten to "
        "read or modify arbitrary data."
    ),
    "sqli-boolean": (
        "A value supplied in this parameter changes the result set of a SQL query in a way "
        "that tracks a true/false condition (blind SQL injection). Data can be extracted one "
        "bit at a time even though the response shows no error."
    ),
    "sqli-time": (
        "A value supplied in this parameter can make the database sleep for a chosen number "
        "of seconds (time-based blind SQL injection). The query is attacker-controlled even "
        "though the response body never changes."
    ),
    "traversal": (
        "A value supplied in this parameter is used to build a filesystem path without "
        "containment: a '../' sequence reached a file outside the intended directory "
        "(a known system file was returned)."
    ),
    "redirect": (
        "A value supplied in this parameter controls the redirect target and an off-site URL "
        "was honoured. Attackers use this for convincing phishing links and, with OAuth-style "
        "flows, for token theft."
    ),
}

_SQLI_FIX = (
    "Use parameterised queries / prepared statements; never build a SQL statement by "
    "concatenating strings. An ORM's query builder is fine as long as raw fragments are "
    "not interpolated."
)

_REMEDIATION: dict[str, str] = {
    "xss": (
        "Context-encode all untrusted output (HTML entity, attribute, JavaScript-string, or "
        "URL encoding as appropriate); prefer a templating engine that auto-escapes. Add a "
        "Content-Security-Policy as defence in depth."
    ),
    "sqli-error": _SQLI_FIX,
    "sqli-boolean": _SQLI_FIX,
    "sqli-time": _SQLI_FIX,
    "traversal": (
        "Resolve the path and confirm it stays within an allow-listed base directory; reject "
        "any input containing path separators or '..'; prefer an opaque id mapped server-side "
        "to a file."
    ),
    "redirect": (
        "Do not redirect to a user-supplied absolute URL. Redirect only to an allow-listed set "
        "of paths, or map an opaque token to a known destination server-side."
    ),
}

_REFERENCES: dict[str, tuple[str, ...]] = {
    "xss": (
        f"{_OWASP}/attacks/xss/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ),
    "sqli-error": (
        f"{_OWASP}/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ),
    "sqli-boolean": (
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ),
    "sqli-time": (
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ),
    "traversal": (f"{_OWASP}/attacks/Path_Traversal",),
    "redirect": (
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    ),
}


class _InjectionCheck(Check):
    """Shared body: filter ``ctx.observations.injection_hits`` for this check's ``kind``."""

    kind: ClassVar[str]
    category = Category.INJECTION
    mode = ScanMode.ACTIVE

    async def run(self, ctx: ScanContext) -> list[Finding]:
        return [
            self.finding(
                title=hit.title,
                description=_DESCRIPTION[self.kind],
                remediation=_REMEDIATION[self.kind],
                severity=hit.severity,
                confidence=hit.confidence,
                location=Location(url=hit.url, method=hit.method, param=hit.param),
                evidence=[EvidenceItem.of(label, content) for label, content in hit.evidence],
            )
            for hit in ctx.observations.injection_hits
            if hit.kind == self.kind
        ]


@register
class ReflectedXssCheck(_InjectionCheck):
    id = "injection.xss.reflected"
    name = "Reflected cross-site scripting"
    kind = "xss"
    default_severity = Severity.HIGH
    cwe = (79, 20)
    references = _REFERENCES["xss"]


@register
class SqliErrorBasedCheck(_InjectionCheck):
    id = "injection.sqli.error-based"
    name = "SQL injection (error-based)"
    kind = "sqli-error"
    default_severity = Severity.HIGH
    cwe = (89, 209)
    references = _REFERENCES["sqli-error"]


@register
class SqliBooleanBasedCheck(_InjectionCheck):
    id = "injection.sqli.boolean-based"
    name = "SQL injection (boolean-based blind)"
    kind = "sqli-boolean"
    default_severity = Severity.HIGH
    cwe = (89,)
    references = _REFERENCES["sqli-boolean"]


@register
class SqliTimeBasedCheck(_InjectionCheck):
    id = "injection.sqli.time-based"
    name = "SQL injection (time-based blind)"
    kind = "sqli-time"
    default_severity = Severity.HIGH
    cwe = (89,)
    references = _REFERENCES["sqli-time"]


@register
class PathTraversalCheck(_InjectionCheck):
    id = "injection.traversal.path"
    name = "Path traversal"
    kind = "traversal"
    default_severity = Severity.HIGH
    cwe = (22, 23)
    references = _REFERENCES["traversal"]


@register
class OpenRedirectCheck(_InjectionCheck):
    id = "injection.redirect.open"
    name = "Open redirect"
    kind = "redirect"
    default_severity = Severity.MEDIUM
    cwe = (601,)
    references = _REFERENCES["redirect"]
