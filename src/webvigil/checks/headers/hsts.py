"""
HTTP Strict-Transport-Security check (RF-16).
"""

from __future__ import annotations

import re

from webvigil.checks.base import Check
from webvigil.checks.headers._parsing import header_value, is_https, response_headers_evidence
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, EvidenceItem, Finding, Location, Severity

_MIN_MAX_AGE_SECONDS = 15_552_000  # 180 days
_MAX_AGE_RE = re.compile(r"max-age\s*=\s*\"?(\d+)\"?", re.IGNORECASE)


@register
class HstsCheck(Check):
    """
    Flags a missing HSTS header on an HTTPS site, and a weak one when present.

    Only runs on an HTTPS entry page (the plaintext case belongs to the
    TLS/HTTPS check). Reports absence, a ``max-age`` below 180 days, and a
    missing ``includeSubDomains``.
    """

    id = "http.headers.hsts"
    name = "Strict-Transport-Security weaknesses"
    category = Category.HEADERS
    default_severity = Severity.MEDIUM
    cwe = (319,)
    references = ("https://owasp.org/www-project-secure-headers/#http-strict-transport-security",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; only the entry page is read.

        Returns:
            list[Finding]: Empty for a plaintext page; one "missing" finding, or
                one finding per weakness of a present header.
        """
        page = ctx.entry
        if not is_https(page.url):
            # The site is served over plaintext; the TLS/HTTPS check owns that finding.
            return []

        location = Location(url=page.url, header="Strict-Transport-Security")
        value = header_value(page, "strict-transport-security")
        if value is None:
            return [
                self.finding(
                    title="Strict-Transport-Security header is missing",
                    description=(
                        "The HTTPS response does not send an HSTS header, so a browser can still "
                        "be downgraded to HTTP by an active network attacker on the first visit."
                    ),
                    remediation=(
                        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on "
                        "every HTTPS response."
                    ),
                    location=location,
                    dedup_key="missing",
                    evidence=[response_headers_evidence(page)],
                )
            ]

        evidence = [EvidenceItem.of("Strict-Transport-Security", value)]
        findings: list[Finding] = []
        match = _MAX_AGE_RE.search(value)
        max_age = int(match.group(1)) if match else 0
        if max_age < _MIN_MAX_AGE_SECONDS:
            findings.append(
                self.finding(
                    title="Strict-Transport-Security max-age is too low",
                    description=(
                        f"max-age is {max_age} seconds; a value below {_MIN_MAX_AGE_SECONDS} "
                        "(180 days) leaves a wide downgrade window."
                    ),
                    remediation="Set max-age to at least 31536000 (one year).",
                    location=location,
                    severity=Severity.LOW,
                    dedup_key="low-max-age",
                    evidence=evidence,
                )
            )
        if "includesubdomains" not in value.lower():
            findings.append(
                self.finding(
                    title="Strict-Transport-Security is missing includeSubDomains",
                    description=(
                        "Without includeSubDomains, sub-domains are not covered by HSTS and can be "
                        "used to attack the parent domain's cookies."
                    ),
                    remediation=(
                        "Add the includeSubDomains directive once all sub-domains support HTTPS."
                    ),
                    location=location,
                    severity=Severity.LOW,
                    dedup_key="no-include-subdomains",
                    evidence=evidence,
                )
            )
        return findings
