"""
The canonical finding model: severities, locations, evidence, and the ``Finding`` itself.

This module is pure data. It must not import any HTTP, crawler, or reporting
code — every reporter is a pure function of the objects defined here.
"""

from __future__ import annotations

import hashlib
from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field

_EVIDENCE_MAX_CHARS = 4096
_FINGERPRINT_CHARS = 16


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(IntEnum):
    """
    How serious a finding is.

    Ordered, so ``>=`` comparisons drive ``--fail-on``. The values are spaced
    by ten to leave room for intermediate levels without a renumber.

    Attributes:
        INFO (int): Informational only — no action required.
        LOW (int): Minor issue, low real-world impact.
        MEDIUM (int): Should be fixed, but not urgent.
        HIGH (int): Serious issue, fix promptly.
        CRITICAL (int): Severe issue, fix immediately.
    """

    INFO = 0
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40

    @classmethod
    def from_name(cls, name: str) -> Severity:
        """
        Resolve a severity from its name, case- and whitespace-insensitively.

        Args:
            name (str): A severity name such as ``"high"`` or ``" Critical "``.

        Returns:
            Severity: The matching member.

        Raises:
            KeyError: If ``name`` is not a severity name.
        """
        return cls[name.strip().upper()]


class Confidence(IntEnum):
    """
    How sure the check is that the finding is real (not a false positive).

    Attributes:
        LOW (int): Heuristic match; may need manual confirmation.
        MEDIUM (int): Reproduced once, or a strong single signal.
        HIGH (int): Confirmed, typically by a baseline-absent reproduction.
    """

    LOW = 10
    MEDIUM = 20
    HIGH = 30


class Category(StrEnum):
    """
    Broad grouping of what a check inspects.

    Attributes:
        HEADERS (str): Response security headers.
        COOKIES (str): Cookie attributes and flags.
        TLS (str): Transport security and certificates.
        CORS (str): Cross-origin resource sharing configuration.
        DEPS (str): Client-side dependency versions and advisories.
        DISCLOSURE (str): Information disclosure (stack traces, exposed paths).
        INJECTION (str): Active injection (XSS, SQLi, traversal, redirect, SSRF).
        CSRF (str): Cross-site request forgery protection on forms.
        HTTP (str): HTTP-protocol behaviour not tied to a single response
            header (allowed methods, TRACE / XST).
    """

    HEADERS = "HEADERS"
    COOKIES = "COOKIES"
    TLS = "TLS"
    CORS = "CORS"
    DEPS = "DEPS"
    DISCLOSURE = "DISCLOSURE"
    INJECTION = "INJECTION"
    CSRF = "CSRF"
    HTTP = "HTTP"


class ScanMode(StrEnum):
    """
    Safe Mode (default) versus opt-in Active Mode.

    Attributes:
        PASSIVE (str): Observation only — safe to point at production.
        ACTIVE (str): Sends crafted requests; requires an authorization.
    """

    PASSIVE = "passive"
    ACTIVE = "active"


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


class Location(BaseModel):
    """
    Where a finding was observed.

    Attributes:
        url (str): The URL the finding is anchored to.
        method (str): HTTP method used. Defaults to ``"GET"``.
        param (str | None): Query or form parameter name, when the finding is
            about a specific input.
        header (str | None): Header name, when the finding is about a header.
        cookie (str | None): Cookie name, when the finding is about a cookie.
    """

    model_config = ConfigDict(frozen=True)

    url: str
    method: str = "GET"
    param: str | None = None
    header: str | None = None
    cookie: str | None = None

    @property
    def key(self) -> str:
        """
        The salient sub-location, used for fingerprinting and stable ordering.

        Returns:
            str: The parameter, header, or cookie name — whichever is set — or
                the empty string when the finding is page-level.
        """
        return self.param or self.header or self.cookie or ""


class EvidenceItem(BaseModel):
    """
    One labelled snippet backing a finding (headers, a cookie line, a certificate...).

    Attributes:
        label (str): Short human-readable name for the snippet.
        content (str): The snippet itself, trimmed to a bounded size by
            :meth:`of`.
    """

    model_config = ConfigDict(frozen=True)

    label: str
    content: str

    @classmethod
    def of(cls, label: str, content: str) -> EvidenceItem:
        """
        Build an item, trimming ``content`` to a bounded size.

        Args:
            label (str): Short human-readable name for the snippet.
            content (str): The raw snippet. Anything past
                ``_EVIDENCE_MAX_CHARS`` is dropped and a truncation marker
                appended.

        Returns:
            EvidenceItem: The frozen evidence item.
        """
        if len(content) > _EVIDENCE_MAX_CHARS:
            content = content[:_EVIDENCE_MAX_CHARS] + "\n...[truncated]"
        return cls(label=label, content=content)


def compute_fingerprint(check_id: str, location: Location, dedup_key: str) -> str:
    """
    Stable identity of a finding, for deduplication across pages and runs.

    Two findings with the same ``check_id``, URL, sub-location, and
    ``dedup_key`` collapse into one.

    Args:
        check_id (str): Identifier of the check that produced the finding.
        location (Location): Where the finding was observed; only the URL and
            :attr:`Location.key` participate.
        dedup_key (str): Check-specific string that distinguishes otherwise
            identical findings at the same location.

    Returns:
        str: Hex SHA-256 digest truncated to 16 characters.
    """
    raw = "\n".join([check_id, location.url, location.key, dedup_key])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:_FINGERPRINT_CHARS]


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """
    A single issue reported by a check.

    Attributes:
        check_id (str): Identifier of the check that produced this finding.
        severity (Severity): How serious the issue is.
        confidence (Confidence): How sure the check is that it is real.
        title (str): One-line summary shown in reports.
        description (str): Full explanation of the issue.
        location (Location): Where the issue was observed.
        remediation (str): How to fix it.
        evidence (tuple[EvidenceItem, ...]): Labelled snippets backing the
            finding. Defaults to empty.
        cwe (tuple[int, ...]): Relevant CWE identifiers. Defaults to empty.
        references (tuple[str, ...]): Further-reading URLs. Defaults to empty.
        fingerprint (str): Stable identity from :func:`compute_fingerprint`;
            must be non-empty.
    """

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
