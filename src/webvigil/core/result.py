"""
The result of a scan: metadata, findings, per-check errors, and warnings.

Serialized to JSON this is the canonical report format (RF-21); every other
reporter is a pure function of a :class:`ScanResult`, and ``webvigil report``
reloads one from disk.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from webvigil.core.findings import Finding, ScanMode, Severity
from webvigil.core.target import Scope
from webvigil.core.technology import Technology


class ScanMetadata(BaseModel):
    """
    Everything about a scan except the findings themselves.

    Attributes:
        target (str): The normalized entry URL that was scanned.
        mode (ScanMode): Passive or Active.
        scope (Scope): How wide the crawl was allowed to reach.
        tool_version (str): WebVigil version that produced the result.
        started_at (datetime): When the scan started (UTC).
        finished_at (datetime): When the scan finished (UTC).
        pages_scanned (int): Number of pages the crawler fetched.
        counts (dict[str, int]): Finding count per severity name, including
            zero buckets.
        authorized_by (str | None): Active-Mode authorization attestation, or
            ``None`` for a passive scan.
        authenticated (bool): Records only *that* cookies were supplied for an
            authenticated scan (spec 007) — never a cookie name or value.
    """

    model_config = ConfigDict(frozen=True)

    target: str
    mode: ScanMode
    scope: Scope
    tool_version: str
    started_at: datetime
    finished_at: datetime
    pages_scanned: int
    counts: dict[str, int]
    authorized_by: str | None = None
    authenticated: bool = False


class CheckError(BaseModel):
    """
    A check that raised instead of returning findings.

    Attributes:
        check_id (str): Identifier of the check that failed.
        message (str): The exception message, or its type name when empty.
        traceback (str): Formatted traceback, for the report's error section.
    """

    model_config = ConfigDict(frozen=True)

    check_id: str
    message: str
    traceback: str


class ScanResult(BaseModel):
    """
    The complete outcome of one scan.

    Attributes:
        metadata (ScanMetadata): Everything about the run except the findings.
        findings (tuple[Finding, ...]): The deduplicated findings.
        technologies (tuple[Technology, ...]): Detected client-side libraries.
            Defaults to empty.
        errors (tuple[CheckError, ...]): Checks that raised. Defaults to empty.
        warnings (tuple[str, ...]): Non-fatal notices raised during the scan.
            Defaults to empty.
    """

    model_config = ConfigDict(frozen=True)

    metadata: ScanMetadata
    findings: tuple[Finding, ...]
    technologies: tuple[Technology, ...] = ()
    errors: tuple[CheckError, ...] = ()
    warnings: tuple[str, ...] = ()

    @staticmethod
    def severity_counts(findings: tuple[Finding, ...]) -> dict[str, int]:
        """
        Count findings per severity name, including zero buckets, for report headers.

        Args:
            findings (tuple[Finding, ...]): The findings to tally.

        Returns:
            dict[str, int]: A mapping from every :class:`~webvigil.core.findings.Severity`
                name to its count, so absent severities still show as ``0``.
        """
        counts = {level.name: 0 for level in Severity}
        for finding in findings:
            counts[finding.severity.name] += 1
        return counts
