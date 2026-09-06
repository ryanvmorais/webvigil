"""The canonical finding model: severities, locations, evidence, and the ``Finding`` itself.

This module is pure data. It must not import any HTTP, crawler, or reporting code.
"""

from __future__ import annotations

import hashlib
from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field

_EVIDENCE_MAX_CHARS = 4096
_FINGERPRINT_CHARS = 16


class Severity(IntEnum):
    """How serious a finding is. Ordered, so ``>=`` comparisons drive ``--fail-on``."""

    INFO = 0
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40

    @classmethod
    def from_name(cls, name: str) -> Severity:
        return cls[name.strip().upper()]


class Confidence(IntEnum):
    """How sure the check is that the finding is real (not a false positive)."""

    LOW = 10
    MEDIUM = 20
    HIGH = 30


class Category(StrEnum):
    """Broad grouping of what a check inspects."""

    HEADERS = "HEADERS"
    COOKIES = "COOKIES"
    TLS = "TLS"
    CORS = "CORS"
    DEPS = "DEPS"
    DISCLOSURE = "DISCLOSURE"
    # Reserved for later specs: INJECTION.


class ScanMode(StrEnum):
    """Safe Mode (default) versus opt-in Active Mode."""

    PASSIVE = "passive"
    ACTIVE = "active"


class Location(BaseModel):
    """Where a finding was observed."""

    model_config = ConfigDict(frozen=True)

    url: str
    method: str = "GET"
    param: str | None = None
    header: str | None = None
    cookie: str | None = None

    @property
    def key(self) -> str:
        """The salient sub-location, used for fingerprinting and stable ordering."""
        return self.param or self.header or self.cookie or ""


class EvidenceItem(BaseModel):
    """One labelled snippet backing a finding (headers, a cookie line, a certificate...)."""

    model_config = ConfigDict(frozen=True)

    label: str
    content: str

    @classmethod
    def of(cls, label: str, content: str) -> EvidenceItem:
        """Build an item, trimming ``content`` to a bounded size."""
        if len(content) > _EVIDENCE_MAX_CHARS:
            content = content[:_EVIDENCE_MAX_CHARS] + "\n...[truncated]"
        return cls(label=label, content=content)


def compute_fingerprint(check_id: str, location: Location, dedup_key: str) -> str:
    """Stable identity of a finding, for deduplication across pages and runs.

    Two findings with the same ``check_id``, URL, sub-location, and ``dedup_key`` collapse
    into one.
    """
    raw = "\n".join([check_id, location.url, location.key, dedup_key])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:_FINGERPRINT_CHARS]


class Finding(BaseModel):
    """A single issue reported by a check."""

    model_config = ConfigDict(frozen=True)

    check_id: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    location: Location
    remediation: str
    evidence: tuple[EvidenceItem, ...] = ()
    cwe: tuple[int, ...] = ()
    references: tuple[str, ...] = ()
    fingerprint: str = Field(min_length=1)
