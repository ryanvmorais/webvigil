"""
Content-Security-Policy check (RF-16).
"""

from __future__ import annotations

from webvigil.checks.base import Check
from webvigil.checks.headers._parsing import header_value, parse_csp, response_headers_evidence
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, Confidence, EvidenceItem, Finding, Location, Severity

_SOURCE_DIRECTIVES = ("script-src", "default-src")


@register
class CspCheck(Check):
    """
    Flags a missing Content-Security-Policy and common policy weaknesses.

    Reports the header's absence, ``'unsafe-inline'`` / ``'unsafe-eval'`` in
    any source list, and a bare ``*`` in ``script-src`` or ``default-src``.
    """

    id = "http.headers.csp"
    name = "Content-Security-Policy weaknesses"
    category = Category.HEADERS
    default_severity = Severity.MEDIUM
    cwe = (693,)
    references = ("https://owasp.org/www-project-secure-headers/#content-security-policy",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; only the entry page is read.

        Returns:
            list[Finding]: One "missing" finding, or one finding per weakness
                found in the present policy.
        """
        page = ctx.entry
        value = header_value(page, "content-security-policy")
        location = Location(url=page.url, header="Content-Security-Policy")

        if value is None:
            return [
                self.finding(
                    title="Content-Security-Policy header is missing",
                    description=(
                        "No Content-Security-Policy header was returned. A CSP is the primary "
                        "defence-in-depth control against cross-site scripting and data injection."
                    ),
                    remediation=(
                        "Add a Content-Security-Policy header. Start from a strict policy such "
                        "as \"default-src 'self'; object-src 'none'; base-uri 'none'\" and loosen "
                        "only as needed."
                    ),
                    location=location,
                    dedup_key="missing",
                    evidence=[response_headers_evidence(page)],
                )
            ]

        directives = parse_csp(value)
        evidence = [EvidenceItem.of("Content-Security-Policy", value)]
        findings: list[Finding] = []

        flat_sources = {token.lower() for tokens in directives.values() for token in tokens}
        if "'unsafe-inline'" in flat_sources:
            findings.append(self._weakness(location, evidence, "unsafe-inline", "'unsafe-inline'"))
        if "'unsafe-eval'" in flat_sources:
            findings.append(self._weakness(location, evidence, "unsafe-eval", "'unsafe-eval'"))

        for directive in _SOURCE_DIRECTIVES:
            if "*" in directives.get(directive, []):
                findings.append(
                    self.finding(
                        title=f"Content-Security-Policy {directive} allows any origin (*)",
                        description=(
                            f"The {directive} directive contains a bare '*', which permits content "
                            "from any origin and defeats most of the policy's value."
                        ),
                        remediation=f"Replace '*' in {directive} with an explicit allow-list.",
                        location=location,
                        severity=Severity.MEDIUM,
                        dedup_key=f"permissive-{directive}",
                        evidence=evidence,
                    )
                )

        return findings

    def _weakness(
        self,
        location: Location,
        evidence: list[EvidenceItem],
        dedup_key: str,
        token: str,
    ) -> Finding:
        """
        Build the finding for an ``'unsafe-inline'`` / ``'unsafe-eval'`` token.

        Args:
            location (Location): The CSP header location.
            evidence (list[EvidenceItem]): The shared policy evidence.
            dedup_key (str): Short key distinguishing the two token cases.
            token (str): The offending token, quoted for display.

        Returns:
            Finding: A MEDIUM-severity finding.
        """
        return self.finding(
            title=f"Content-Security-Policy allows {token}",
            description=(
                f"The policy contains {token}, which lets the page execute inline or dynamically "
                "generated script and largely negates CSP's XSS protection."
            ),
            remediation=(f"Remove {token}. Use nonces or hashes for the scripts you control."),
            location=location,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            dedup_key=dedup_key,
            evidence=evidence,
        )
