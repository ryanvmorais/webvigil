"""
The six probe-fed disclosure checks (RF-08, RF-10).

Each reads :class:`~webvigil.checks.disclosure.probe.ProbeHit`\\s of its family
from ``ctx.observations.probe_hits`` (filled by the orchestrator's
``DisclosureProbe`` pass) and turns them into findings. They issue no HTTP
themselves.
"""

from __future__ import annotations

from typing import ClassVar

from webvigil.checks.base import Check
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.findings import Category, EvidenceItem, Finding, Location, ScanMode, Severity

_REMEDIATION = {
    "vcs": (
        "Block access to version-control directories at the web server or reverse proxy "
        "(deny '/.git', '/.svn', '/.hg', '/.bzr') and deploy from a build artifact that "
        "does not include them."
    ),
    "config": (
        "Remove the file from the web root and serve secrets from the environment or a "
        "secrets manager. Deny dotfiles and '*.bak' / '*.old' at the web server."
    ),
    "manifest": (
        "Do not serve dependency manifests from the web root. If a build step copies them, "
        "exclude them from the published directory."
    ),
    "backup": (
        "Delete the backup, archive, or dump from the web root and store backups outside "
        "any served directory. Deny editor and archive extensions at the web server."
    ),
    "debug": (
        "Disable the debug or admin endpoint in production, or bind it to an internal "
        "management interface protected by authentication and network controls."
    ),
    "sourcemap": (
        "Do not publish source maps to production, or restrict them to authenticated "
        "internal users. Configure the bundler to omit 'sourceMappingURL' from released "
        "assets."
    ),
}
_REFERENCES = {
    "vcs": ("https://owasp.org/www-community/attacks/Forced_browsing",),
    "config": ("https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",),
    "manifest": ("https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",),
    "backup": ("https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",),
    "debug": ("https://owasp.org/www-community/Improper_Error_Handling",),
    "sourcemap": ("https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",),
}


class _ProbeFedCheck(Check):
    """
    Shared base: turn this check's family of probe hits into findings.

    Attributes:
        family (ClassVar[str]): The probe family this subclass consumes.
    """

    family: ClassVar[str]
    category = Category.DISCLOSURE
    mode = ScanMode.PASSIVE

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan context; reads
                ``observations.probe_hits``.

        Returns:
            list[Finding]: One finding per probe hit whose family matches
                :attr:`family`.
        """
        return [
            self.finding(
                title=f"{hit.title} at {hit.path}",
                description=hit.description,
                remediation=_REMEDIATION[self.family],
                severity=hit.severity,
                confidence=hit.confidence,
                location=Location(url=hit.url),
                dedup_key=hit.path,
                evidence=[
                    EvidenceItem.of("Response", f"HTTP {hit.status} · {hit.content_type}"),
                    EvidenceItem.of("Body (redacted)", hit.redacted_body or "(empty)"),
                ],
            )
            for hit in ctx.observations.probe_hits
            if hit.family == self.family
        ]


@register
class VcsExposedCheck(_ProbeFedCheck):
    """Reachable version-control metadata (``.git``, ``.svn``, ...)."""

    id = "disclosure.vcs.exposed"
    name = "Version-control metadata exposed"
    family = "vcs"
    default_severity = Severity.HIGH
    cwe = (527, 538)
    references = _REFERENCES["vcs"]


@register
class DotenvExposedCheck(_ProbeFedCheck):
    """A reachable configuration or environment file (``.env``, ``config.php``, ...)."""

    id = "disclosure.config.dotenv-exposed"
    name = "Configuration or environment file exposed"
    family = "config"
    default_severity = Severity.HIGH
    cwe = (538, 200)
    references = _REFERENCES["config"]


@register
class ManifestExposedCheck(_ProbeFedCheck):
    """A reachable dependency manifest (``package.json``, ``composer.lock``, ...)."""

    id = "disclosure.config.manifest-exposed"
    name = "Dependency manifest exposed"
    family = "manifest"
    default_severity = Severity.LOW
    cwe = (538,)
    references = _REFERENCES["manifest"]


@register
class BackupFileExposedCheck(_ProbeFedCheck):
    """A reachable backup, archive, or database dump."""

    id = "disclosure.backup.file-exposed"
    name = "Backup or dump file exposed"
    family = "backup"
    default_severity = Severity.MEDIUM
    cwe = (538, 530)
    references = _REFERENCES["backup"]


@register
class DebugEndpointExposedCheck(_ProbeFedCheck):
    """A reachable debug or administrative endpoint (``/debug``, ``/actuator``, ...)."""

    id = "disclosure.debug.endpoint-exposed"
    name = "Debug or administrative endpoint exposed"
    family = "debug"
    default_severity = Severity.MEDIUM
    cwe = (215, 497)
    references = _REFERENCES["debug"]


@register
class SourcemapExposedCheck(_ProbeFedCheck):
    """A reachable JavaScript source map (``*.js.map``)."""

    id = "disclosure.sourcemap.exposed"
    name = "JavaScript source map exposed"
    family = "sourcemap"
    default_severity = Severity.MEDIUM
    cwe = (540, 200)
    references = _REFERENCES["sourcemap"]
