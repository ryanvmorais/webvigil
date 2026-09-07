"""
Smaller single-header checks: frame options, sniffing, referrer, permissions, isolation.
"""

from __future__ import annotations

from webvigil.checks.base import Check
from webvigil.checks.headers._parsing import header_value, parse_csp, response_headers_evidence
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, Finding, Location, Severity

_LEAKING_REFERRER_POLICIES = {"unsafe-url", "no-referrer-when-downgrade", ""}


@register
class FrameOptionsCheck(Check):
    """
    Flags a page with no clickjacking protection.

    Satisfied by either ``X-Frame-Options`` or a CSP ``frame-ancestors``
    directive; reports only when both are absent.
    """

    id = "http.headers.frame-options"
    name = "Clickjacking protection missing"
    category = Category.HEADERS
    default_severity = Severity.MEDIUM
    cwe = (1021,)
    references = ("https://owasp.org/www-project-secure-headers/#x-frame-options",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; only the entry page is read.

        Returns:
            list[Finding]: One finding when neither control is present, else
                empty.
        """
        page = ctx.entry
        has_xfo = header_value(page, "x-frame-options") is not None
        csp = header_value(page, "content-security-policy") or ""
        has_frame_ancestors = "frame-ancestors" in parse_csp(csp)
        if has_xfo or has_frame_ancestors:
            return []
        return [
            self.finding(
                title="No clickjacking protection (X-Frame-Options / frame-ancestors)",
                description=(
                    "The response sets neither X-Frame-Options nor a Content-Security-Policy "
                    "frame-ancestors directive, so the page can be framed by any site."
                ),
                remediation=(
                    "Send 'X-Frame-Options: DENY' (or SAMEORIGIN) and a CSP "
                    "\"frame-ancestors 'none'\" directive."
                ),
                location=Location(url=page.url, header="X-Frame-Options"),
                dedup_key="missing",
                evidence=[response_headers_evidence(page)],
            )
        ]


@register
class ContentTypeOptionsCheck(Check):
    """Flags a response whose ``X-Content-Type-Options`` is not ``nosniff``."""

    id = "http.headers.content-type-options"
    name = "X-Content-Type-Options not nosniff"
    category = Category.HEADERS
    default_severity = Severity.LOW
    cwe = (693,)
    references = ("https://owasp.org/www-project-secure-headers/#x-content-type-options",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; only the entry page is read.

        Returns:
            list[Finding]: One finding when the header is missing or not
                ``nosniff``, else empty.
        """
        page = ctx.entry
        value = (header_value(page, "x-content-type-options") or "").strip().lower()
        if value == "nosniff":
            return []
        return [
            self.finding(
                title="X-Content-Type-Options is not set to nosniff",
                description=(
                    "Without 'X-Content-Type-Options: nosniff', browsers may MIME-sniff responses "
                    "and treat them as a more dangerous content type than declared."
                ),
                remediation="Send 'X-Content-Type-Options: nosniff' on every response.",
                location=Location(url=page.url, header="X-Content-Type-Options"),
                dedup_key="missing",
                evidence=[response_headers_evidence(page)],
            )
        ]


@register
class ReferrerPolicyCheck(Check):
    """
    Flags a missing ``Referrer-Policy``, or one whose value leaks the full URL cross-origin.
    """

    id = "http.headers.referrer-policy"
    name = "Referrer-Policy missing or leaking"
    category = Category.HEADERS
    default_severity = Severity.LOW
    cwe = (200,)
    references = ("https://owasp.org/www-project-secure-headers/#referrer-policy",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; only the entry page is read.

        Returns:
            list[Finding]: One "missing" or one "leaking" finding, else empty.
        """
        page = ctx.entry
        raw = header_value(page, "referrer-policy")
        if raw is None:
            return [
                self.finding(
                    title="Referrer-Policy header is missing",
                    description=(
                        "No Referrer-Policy is set, so the browser default may send full URLs "
                        "(including paths and query strings) to third-party origins."
                    ),
                    remediation=(
                        "Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."
                    ),
                    location=Location(url=page.url, header="Referrer-Policy"),
                    severity=Severity.LOW,
                    dedup_key="missing",
                    evidence=[response_headers_evidence(page)],
                )
            ]
        if raw.strip().lower() in _LEAKING_REFERRER_POLICIES:
            return [
                self.finding(
                    title=f"Referrer-Policy '{raw.strip()}' leaks referrer data",
                    description=(
                        "This Referrer-Policy value sends the referrer (often including the full "
                        "URL) to cross-origin destinations, at least over HTTPS."
                    ),
                    remediation="Use 'strict-origin-when-cross-origin' or 'no-referrer'.",
                    location=Location(url=page.url, header="Referrer-Policy"),
                    severity=Severity.LOW,
                    dedup_key="leaking",
                    evidence=[response_headers_evidence(page, only=("referrer-policy",))],
                )
            ]
        return []


@register
class PermissionsPolicyCheck(Check):
    """Flags a response with no ``Permissions-Policy`` header (INFO)."""

    id = "http.headers.permissions-policy"
    name = "Permissions-Policy header missing"
    category = Category.HEADERS
    default_severity = Severity.INFO
    references = ("https://owasp.org/www-project-secure-headers/#permissions-policy",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; only the entry page is read.

        Returns:
            list[Finding]: One INFO finding when the header is absent, else
                empty.
        """
        page = ctx.entry
        if header_value(page, "permissions-policy") is not None:
            return []
        return [
            self.finding(
                title="Permissions-Policy header is missing",
                description=(
                    "No Permissions-Policy is set, so powerful browser features (camera, "
                    "geolocation, etc.) are not explicitly restricted for this document."
                ),
                remediation=(
                    "Send a Permissions-Policy that disables features the site does not use, "
                    "e.g. 'geolocation=(), camera=(), microphone=()'."
                ),
                location=Location(url=page.url, header="Permissions-Policy"),
                dedup_key="missing",
                evidence=[response_headers_evidence(page)],
            )
        ]


@register
class CrossOriginIsolationCheck(Check):
    """Flags a response with no ``Cross-Origin-Opener-Policy`` header (INFO)."""

    id = "http.headers.cross-origin-isolation"
    name = "Cross-origin isolation headers missing"
    category = Category.HEADERS
    default_severity = Severity.INFO
    references = ("https://owasp.org/www-project-secure-headers/#cross-origin-opener-policy",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; only the entry page is read.

        Returns:
            list[Finding]: One INFO finding when ``Cross-Origin-Opener-Policy``
                is absent, else empty.
        """
        page = ctx.entry
        if header_value(page, "cross-origin-opener-policy") is not None:
            return []
        return [
            self.finding(
                title="Cross-Origin-Opener-Policy header is missing",
                description=(
                    "Without Cross-Origin-Opener-Policy, the document shares a browsing context "
                    "group with cross-origin openers, widening the impact of some side-channel and "
                    "XS-Leaks attacks."
                ),
                remediation=(
                    "Send 'Cross-Origin-Opener-Policy: same-origin' (and COEP/CORP as needed)."
                ),
                location=Location(url=page.url, header="Cross-Origin-Opener-Policy"),
                dedup_key="coop-missing",
                evidence=[response_headers_evidence(page)],
            )
        ]
