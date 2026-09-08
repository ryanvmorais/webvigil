"""
The unrestricted-file-upload check: turn ``UploadHit``s into findings (spec 014, RF-07).

It issues no request — :class:`~webvigil.checks.upload.scanner.UploadScanner`
(an orchestrator pass) has already run and left its hits on
``ctx.observations.upload_hits``. One finding per hit; the severity comes from
the hit's outcome (ADR-5).
"""

from __future__ import annotations

from webvigil.checks.base import Check
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, EvidenceItem, Finding, Location, ScanMode, Severity

_UPLOAD_FIX = (
    "Validate uploads by sniffing the content, not the extension or the client Content-Type; "
    "accept only an allow-list of types. Store uploaded files outside the web root (or on a "
    "separate, script-disabled domain), give them a server-generated random name, and serve "
    "them with Content-Disposition: attachment and X-Content-Type-Options: nosniff. Disable "
    "script execution in the upload directory and reject any filename containing a path "
    "separator or '..'. Do not expose a writable PUT / WebDAV method on application routes."
)

_DESCRIPTION = {
    "server-exec": (
        "A file WebVigil uploaded through this form was stored and then executed by the "
        "server — a marker script came back as its computed output, not as source. This is "
        "remote code execution: an attacker uploads a web shell and runs arbitrary commands."
    ),
    "inline-html": (
        "A file WebVigil uploaded through this form is served back inline with an "
        "HTML / SVG content type and no attachment disposition. Script in the uploaded file "
        "runs in the site's origin for anyone who opens that URL — stored XSS via file upload."
    ),
    "traversal": (
        "A file WebVigil uploaded through this form was written outside the intended upload "
        "directory because its name contained a path-traversal sequence. An attacker can "
        "overwrite application files or drop an executable into the web root."
    ),
    "put-upload": (
        "The server accepted an HTTP PUT that created a new file, and served it back. A "
        "misconfigured WebDAV / PUT handler lets an attacker upload a web shell or overwrite "
        "content without going through the application at all."
    ),
    "inert-accept": (
        "This upload endpoint stores files of a type it should reject (an executable / HTML "
        "extension). WebVigil could not make the file execute or render, but accepting the "
        "type at all is the first half of an unrestricted-upload vulnerability."
    ),
}


@register
class UnrestrictedUploadCheck(Check):
    """Unrestricted file upload — a marker file executed, served inline, or written out of place."""

    id = "upload.unrestricted"
    name = "Unrestricted file upload"
    category = Category.UPLOAD
    mode = ScanMode.ACTIVE
    default_severity = Severity.HIGH
    cwe = (434, 646)
    references = (
        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads
                ``observations.upload_hits``.

        Returns:
            list[Finding]: One finding per upload hit.
        """
        return [
            self.finding(
                title=hit.title,
                description=_DESCRIPTION[hit.outcome],
                remediation=_UPLOAD_FIX,
                severity=hit.severity,
                confidence=hit.confidence,
                location=Location(url=hit.url, method=hit.method, param=hit.field),
                dedup_key=f"{hit.field or 'PUT'}:{hit.outcome}",
                evidence=[EvidenceItem.of(label, content) for label, content in hit.evidence],
            )
            for hit in ctx.observations.upload_hits
        ]
