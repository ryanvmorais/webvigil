"""
Request and response models for the Web API (kept separate from the DB models).

The ``*In`` models validate request bodies; the ``*Out`` models shape
responses, several with a ``from_row`` converter off the DB models.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from webvigil.api.db import Finding as FindingRow
from webvigil.api.db import Scan
from webvigil.core.errors import InvalidTargetError
from webvigil.core.findings import Confidence, ScanMode, Severity
from webvigil.core.target import Scope, Target

# Type alias (PEP 695) for the closed set of ``fail_on`` values.
type FailOn = Literal["none", "info", "low", "medium", "high", "critical"]


class UserOut(BaseModel):
    """The current user, as returned by the auth endpoints."""

    id: int
    username: str
    created_at: datetime


class SetupIn(BaseModel):
    """First-run setup body: the credentials for the single account."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)


class LoginIn(BaseModel):
    """Login body."""

    username: str
    password: str


class PasswordChangeIn(BaseModel):
    """Password-change body: the current password plus the new one."""

    current_password: str
    new_password: str = Field(min_length=8, max_length=256)


class HealthOut(BaseModel):
    """The health endpoint's payload: liveness and the tool version."""

    status: str
    version: str


class CheckOut(BaseModel):
    """One registered check, for the check-catalogue endpoint."""

    id: str
    name: str
    category: str
    mode: str
    default_severity: str
    cwe: list[int]
    references: list[str]


class ScanDefaults(BaseModel):
    """The default scan options, so the UI's new-scan form can pre-fill them."""

    mode: str
    scope: str
    max_pages: int
    delay_ms: int
    follow_robots: bool
    fail_on: str


class ScanCreate(BaseModel):
    """
    New-scan request body.

    Attributes:
        target (str): The URL to scan; validated with
            :meth:`~webvigil.core.target.Target.parse`.
        mode (ScanMode): Passive (default) or Active.
        scope (Scope): Crawl breadth. Defaults to
            :attr:`~webvigil.core.target.Scope.HOST`.
        max_pages (int | None): Crawler page cap; must be > 0 when given.
        delay_ms (int | None): Delay between requests; must be >= 0 when given.
        follow_robots (bool | None): Honour ``robots.txt``.
        authorized_by (str | None): Required for an Active scan.
        fail_on (FailOn | None): Recorded on the scan for later report exit
            codes.
        disabled_checks (list[str]): Check ids to skip. Defaults to empty.
    """

    target: str
    mode: ScanMode = ScanMode.PASSIVE
    scope: Scope = Scope.HOST
    max_pages: int | None = Field(default=None, gt=0)
    delay_ms: int | None = Field(default=None, ge=0)
    follow_robots: bool | None = None
    authorized_by: str | None = None
    fail_on: FailOn | None = None
    disabled_checks: list[str] = []

    @model_validator(mode="after")
    def _check(self) -> ScanCreate:
        """
        Reject an unparseable target, and an Active scan with no ``authorized_by``.

        Returns:
            ScanCreate: ``self`` when valid.

        Raises:
            ValueError: On a bad target or a missing Active-Mode attestation
                (surfaced by FastAPI as a 422).
        """
        try:
            Target.parse(self.target)
        except InvalidTargetError as exc:
            raise ValueError(str(exc)) from exc
        if self.mode is ScanMode.ACTIVE and not (self.authorized_by or "").strip():
            raise ValueError("authorized_by is required for an active scan")
        return self

    def to_options(self) -> dict[str, Any]:
        """
        Returns:
            dict[str, Any]: The non-``None`` extra options, stored verbatim on
                ``Scan.options`` and later merged into the engine config.
        """
        options: dict[str, Any] = {}
        if self.max_pages is not None:
            options["max_pages"] = self.max_pages
        if self.delay_ms is not None:
            options["delay_ms"] = self.delay_ms
        if self.follow_robots is not None:
            options["follow_robots"] = self.follow_robots
        if self.fail_on is not None:
            options["fail_on"] = self.fail_on
        if self.disabled_checks:
            options["disabled_checks"] = self.disabled_checks
        return options


class LocationOut(BaseModel):
    """A finding's location in a response."""

    url: str
    method: str = "GET"
    param: str | None = None
    header: str | None = None
    cookie: str | None = None


class EvidenceOut(BaseModel):
    """One labelled evidence snippet."""

    label: str
    content: str


class FindingOut(BaseModel):
    """One finding in a scan-detail response; severity and confidence as names, not ints."""

    check_id: str
    severity: str
    confidence: str
    title: str
    description: str
    location: LocationOut
    remediation: str
    evidence: list[EvidenceOut]
    cwe: list[int]
    references: list[str]
    fingerprint: str

    @classmethod
    def from_row(cls, row: FindingRow) -> FindingOut:
        """
        Args:
            row (FindingRow): A stored finding.

        Returns:
            FindingOut: The response model, with the severity / confidence
                integers mapped back to their enum names.
        """
        return cls(
            check_id=row.check_id,
            severity=Severity(row.severity).name,
            confidence=Confidence(row.confidence).name,
            title=row.title,
            description=row.description,
            location=LocationOut(**row.location),
            remediation=row.remediation,
            evidence=[EvidenceOut(**item) for item in row.evidence],
            cwe=list(row.cwe),
            references=list(row.references),
            fingerprint=row.fingerprint,
        )


class ScanSummary(BaseModel):
    """A scan as it appears in the list endpoint — identity, status, severity counts."""

    id: int
    target: str
    mode: str
    scope: str
    status: str
    counts: dict[str, int]
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    @classmethod
    def from_row(cls, scan: Scan) -> ScanSummary:
        """
        Args:
            scan (Scan): A stored scan (must have an ``id``).

        Returns:
            ScanSummary: The list-row model.
        """
        assert scan.id is not None
        return cls(
            id=scan.id,
            target=scan.target,
            mode=scan.mode,
            scope=scan.scope,
            status=str(scan.status),
            counts=dict(scan.counts),
            created_at=scan.created_at,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
        )


class TechnologyOut(BaseModel):
    """
    One detected client-side library (spec 004, RF-17). Detail payload only.

    Attributes:
        name (str): Library name.
        version (str | None): Detected version, or ``None``.
        detection (str): How it was found (the ``DetectionMethod`` value).
        source_url (str): URL the detection came from.
        vulnerable (bool): Whether an advisory matched.
        advisories (list[str]): Matching advisory identifiers.
    """

    name: str
    version: str | None
    detection: str
    source_url: str
    vulnerable: bool
    advisories: list[str]


class ScanOut(ScanSummary):
    """
    The full scan-detail response: everything in :class:`ScanSummary` plus the extras.

    Attributes:
        authorized_by (str | None): Active-Mode attestation.
        tool_version (str | None): WebVigil version that ran the scan.
        error (str | None): Failure message, when applicable.
        pages_scanned (int): Pages the crawler fetched.
        options (dict[str, Any]): The request's extra options.
        technologies (list[TechnologyOut]): The detected-technology inventory.
    """

    authorized_by: str | None
    tool_version: str | None
    error: str | None
    pages_scanned: int
    options: dict[str, Any]
    technologies: list[TechnologyOut]

    @classmethod
    def from_row(cls, scan: Scan) -> ScanOut:
        """
        Args:
            scan (Scan): A stored scan.

        Returns:
            ScanOut: The detail model, built on :meth:`ScanSummary.from_row`.
        """
        base = ScanSummary.from_row(scan).model_dump()
        return cls(
            **base,
            authorized_by=scan.authorized_by,
            tool_version=scan.tool_version,
            error=scan.error,
            pages_scanned=scan.pages_scanned,
            options=dict(scan.options),
            technologies=[TechnologyOut(**tech) for tech in (scan.technologies or [])],
        )


class Page[T](BaseModel):
    """
    A cursor-paginated slice of a list response.

    Attributes:
        items (list[T]): The rows on this page.
        next_cursor (str | None): Opaque cursor for the next page, or ``None``
            on the last page.
    """

    items: list[T]
    next_cursor: str | None = None
