"""
The request-envelope checks: turn ``EnvelopeHit``s into findings (spec 012, RF-08, RF-10).

Neither issues a request — :class:`~webvigil.checks.envelope.scanner.EnvelopeScanner`
(an orchestrator pass) has already run and left its hits on
``ctx.observations.envelope_hits``. Each check filters by ``check_id``.
"""

from __future__ import annotations

from typing import ClassVar

from webvigil.checks.base import Check
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, EvidenceItem, Finding, Location, ScanMode, Severity

_HOST_HEADER_FIX = (
    "Do not build absolute URLs (reset links, redirects, canonical tags) from the request "
    "Host or X-Forwarded-* headers. Use a configured, trusted base URL. Reject requests whose "
    "Host header is not an allow-listed value at the edge."
)
_METHODS_FIX = (
    "Disable TRACE at the web server / framework. Restrict each route to the methods it needs "
    "(GET, POST) and return 405 for the rest. If PUT/DELETE/PATCH are intentional (a REST API), "
    "confirm they enforce authentication and authorization."
)

_DESCRIPTION = {
    "injection.host-header": (
        "The application builds an absolute URL from a client-controlled header (Host or an "
        "X-Forwarded-* variant). An attacker who sets that header can point password-reset "
        "links, redirects, or canonical tags at their own domain — password-reset poisoning "
        "and web-cache poisoning are the common outcomes."
    ),
    "http.methods.unsafe": (
        "The server exposes HTTP methods beyond GET/POST. TRACE enabled is Cross-Site Tracing "
        "(it reflects request headers, defeating HttpOnly). PUT/DELETE/PATCH/CONNECT advertised "
        "on an application route is worth review even before confirming they are unauthenticated."
    ),
}


class _EnvelopeCheck(Check):
    """
    Shared body: filter ``ctx.observations.envelope_hits`` for this check's id.

    Attributes:
        check_key (ClassVar[str]): The ``EnvelopeHit.check_id`` this subclass
            renders; also the key into ``_DESCRIPTION``.
    """

    check_key: ClassVar[str]
    mode = ScanMode.ACTIVE

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads
                ``observations.envelope_hits``.

        Returns:
            list[Finding]: One finding per hit whose ``check_id`` matches.
        """
        fix = _HOST_HEADER_FIX if self.check_key == "injection.host-header" else _METHODS_FIX
        return [
            self.finding(
                title=hit.title,
                description=_DESCRIPTION[self.check_key],
                remediation=fix,
                severity=hit.severity,
                confidence=hit.confidence,
                location=Location(url=hit.url, method=hit.method, param=hit.param),
                dedup_key=hit.param or hit.method,
                evidence=[EvidenceItem.of(label, content) for label, content in hit.evidence],
            )
            for hit in ctx.observations.envelope_hits
            if hit.check_id == self.check_key
        ]


@register
class HostHeaderCheck(_EnvelopeCheck):
    """Host-header injection from the request-envelope pass (spec 012)."""

    id = "injection.host-header"
    name = "Host header injection"
    check_key = "injection.host-header"
    category = Category.INJECTION
    default_severity = Severity.MEDIUM
    cwe = (644,)
    references = (
        "https://portswigger.net/web-security/host-header",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection",
    )


@register
class HttpMethodsCheck(_EnvelopeCheck):
    """Unsafe HTTP methods — TRACE / XST or advertised write verbs (spec 012)."""

    id = "http.methods.unsafe"
    name = "Unsafe HTTP methods enabled"
    check_key = "http.methods.unsafe"
    category = Category.HTTP
    default_severity = Severity.MEDIUM
    cwe = (650, 693, 16)
    references = (
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
        "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
    )
