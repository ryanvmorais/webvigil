"""Request and response models for the Web API (kept separate from the DB models)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from webvigil.api.db import Finding as FindingRow
from webvigil.api.db import Scan
from webvigil.core.errors import InvalidTargetError
from webvigil.core.findings import Confidence, ScanMode, Severity
from webvigil.core.target import Scope, Target

FailOn = Literal["none", "info", "low", "medium", "high", "critical"]


class UserOut(BaseModel):
    id: int
    username: str
    created_at: datetime


class SetupIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)


class LoginIn(BaseModel):
    username: str
    password: str


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=256)


class HealthOut(BaseModel):
    status: str
    version: str


class CheckOut(BaseModel):
    id: str
    name: str
    category: str
    mode: str
    default_severity: str
    cwe: list[int]
    references: list[str]


class ScanDefaults(BaseModel):
    mode: str
    scope: str
    max_pages: int
    delay_ms: int
    follow_robots: bool
    fail_on: str


class ScanCreate(BaseModel):
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
        try:
            Target.parse(self.target)
        except InvalidTargetError as exc:
            raise ValueError(str(exc)) from exc
        if self.mode is ScanMode.ACTIVE and not (self.authorized_by or "").strip():
            raise ValueError("authorized_by is required for an active scan")
        return self

    def to_options(self) -> dict[str, Any]:
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
    url: str
    method: str = "GET"
    param: str | None = None
    header: str | None = None
    cookie: str | None = None


class EvidenceOut(BaseModel):
    label: str
    content: str


class FindingOut(BaseModel):
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


class ScanOut(ScanSummary):
    authorized_by: str | None
    tool_version: str | None
    error: str | None
    pages_scanned: int
    options: dict[str, Any]

    @classmethod
    def from_row(cls, scan: Scan) -> ScanOut:
        base = ScanSummary.from_row(scan).model_dump()
        return cls(
            **base,
            authorized_by=scan.authorized_by,
            tool_version=scan.tool_version,
            error=scan.error,
            pages_scanned=scan.pages_scanned,
            options=dict(scan.options),
        )


class Page[T](BaseModel):
    items: list[T]
    next_cursor: str | None = None
