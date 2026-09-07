"""
Passive check: framework error pages / stack traces in already-crawled responses (RF-01).
"""

from __future__ import annotations

from webvigil.checks.base import Check
from webvigil.checks.disclosure.signatures import match_error
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, Confidence, EvidenceItem, Finding, Location, Severity


@register
class ErrorPageCheck(Check):
    """
    Flags a framework error page or stack trace in an already-crawled response.

    Matches on framework chrome (debugger markup, stack-trace layout), not the
    words "error" / "exception", and reports at most one finding per framework.
    An interactive debugger is HIGH confidence and carries the framework's own
    severity.
    """

    id = "disclosure.debug.error-page"
    name = "Framework error page / stack trace exposed"
    category = Category.DISCLOSURE
    default_severity = Severity.MEDIUM
    cwe = (215, 200)
    references = ("https://owasp.org/www-community/Improper_Error_Handling",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; every OK page body is scanned.

        Returns:
            list[Finding]: One finding per distinct framework whose error
                signature fired.
        """
        findings: list[Finding] = []
        seen: set[str] = set()
        for page in ctx.pages:
            if not page.ok or not page.text:
                continue
            match = match_error(page.text)
            if match is None or match.signature.framework in seen:
                continue
            seen.add(match.signature.framework)
            interactive = match.signature.interactive
            findings.append(
                self.finding(
                    title=(
                        f"{match.signature.framework} interactive debugger exposed"
                        if interactive
                        else f"{match.signature.framework} error page exposed"
                    ),
                    description=(
                        "The application returned a framework "
                        + ("interactive debugger" if interactive else "error page / stack trace")
                        + " to the client. It leaks file paths, source, and component versions"
                        + (
                            ", and the console can execute arbitrary code on the server."
                            if interactive
                            else ", and usually means debug mode is enabled in production."
                        )
                    ),
                    remediation=(
                        "Disable debug mode in production (DEBUG = False, APP_DEBUG=false, "
                        '<customErrors mode="On">, NODE_ENV=production) and return a generic '
                        "error page."
                    ),
                    severity=match.signature.severity,
                    confidence=Confidence.HIGH if interactive else Confidence.MEDIUM,
                    location=Location(url=page.url),
                    dedup_key=match.signature.framework,
                    evidence=[EvidenceItem.of("Marker", match.snippet)],
                )
            )
        return findings
