"""
Revealing-headers check: server/framework version disclosure (RF-17).
"""

from __future__ import annotations

import re

from webvigil.checks.base import Check
from webvigil.checks.headers._parsing import header_value
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, Confidence, EvidenceItem, Finding, Location, Severity

# Headers that disclose technology/version. ``Server`` is only flagged when it carries a version.
_ALWAYS = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime", "X-Version")
_HAS_DIGIT = re.compile(r"\d")


@register
class RevealingHeadersCheck(Check):
    """
    Flags response headers that disclose the server or framework version.

    ``Server`` is only reported when it carries a digit; a curated set of
    ``X-*`` version headers is reported whenever present.
    """

    id = "http.headers.revealing"
    name = "Server or framework version disclosed in headers"
    category = Category.HEADERS
    default_severity = Severity.LOW
    cwe = (200,)
    references = ("https://owasp.org/www-project-secure-headers/#fingerprinting",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; only the entry page is read.

        Returns:
            list[Finding]: One LOW finding per disclosing header.
        """
        page = ctx.entry
        findings: list[Finding] = []

        server = header_value(page, "server")
        if server and _HAS_DIGIT.search(server):
            findings.append(self._finding(page.url, "Server", server))

        for name in _ALWAYS:
            value = header_value(page, name)
            if value:
                findings.append(self._finding(page.url, name, value))

        return findings

    def _finding(self, url: str, header: str, value: str) -> Finding:
        """
        Build the finding for one disclosing header.

        Args:
            url (str): The page URL.
            header (str): The disclosing header name.
            value (str): Its value.

        Returns:
            Finding: A LOW-severity, HIGH-confidence finding.
        """
        return self.finding(
            title=f"{header} header discloses technology details",
            description=(
                f"The response includes '{header}: {value}', which tells an attacker exactly what "
                "software and version to look up known vulnerabilities for."
            ),
            remediation=(
                f"Remove or generalise the {header} header at the web server or framework level."
            ),
            location=Location(url=url, header=header),
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            dedup_key=header.lower(),
            evidence=[EvidenceItem.of(header, value)],
        )
