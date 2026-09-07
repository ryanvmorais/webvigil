"""
Passive check: server-generated directory listings in already-crawled responses (RF-02).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from webvigil.checks.base import Check
from webvigil.checks.disclosure.signatures import is_directory_listing
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, Confidence, EvidenceItem, Finding, Location, Severity

_HREF_RE = re.compile(r'href="([^"?]+)"')
_SAMPLE = 12


@register
class DirectoryListingCheck(Check):
    """
    Flags a server-generated directory index in an already-crawled response.

    One finding per listing URL; the evidence samples the first entries.
    """

    id = "disclosure.listing.directory-index"
    name = "Directory listing enabled"
    category = Category.DISCLOSURE
    default_severity = Severity.MEDIUM
    cwe = (548, 200)
    references = ("https://owasp.org/www-community/attacks/Forced_browsing",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; every OK page body is checked.

        Returns:
            list[Finding]: One finding per page that renders a directory index.
        """
        findings: list[Finding] = []
        seen: set[str] = set()
        for page in ctx.pages:
            if not page.ok or not page.text or page.url in seen:
                continue
            if not is_directory_listing(page.text):
                continue
            seen.add(page.url)
            entries = [href for href in _HREF_RE.findall(page.text) if href not in ("../", "/")]
            findings.append(
                self.finding(
                    title=f"Directory listing enabled at {_path_of(page.url)}",
                    description=(
                        "The web server returns an auto-generated index for this directory, "
                        "exposing every file it contains — including ones never linked from "
                        "the application."
                    ),
                    remediation=(
                        "Disable automatic directory indexing (Apache 'Options -Indexes', "
                        "nginx 'autoindex off', or the framework's static handler) and add an "
                        "index file where a landing page is intended."
                    ),
                    location=Location(url=page.url),
                    confidence=Confidence.HIGH,
                    dedup_key=_path_of(page.url),
                    evidence=[EvidenceItem.of("Entries", "\n".join(entries[:_SAMPLE]) or "(none)")],
                )
            )
        return findings


def _path_of(url: str) -> str:
    """
    Args:
        url (str): An absolute URL.

    Returns:
        str: Its path, or ``"/"`` when empty.
    """
    return urlsplit(url).path or "/"
