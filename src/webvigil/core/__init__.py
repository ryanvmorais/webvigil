"""
Scan engine: orchestrator, target/scope model, findings, and configuration.

Pure library code. This package must not import FastAPI, SQLModel, Typer, Rich,
or any other UI or persistence concern — the boundary is enforced by
import-linter in CI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from webvigil.core.config import ScanConfig
from webvigil.core.context import Page, ScanContext
from webvigil.core.errors import (
    ActiveModeNotAuthorized,
    ConfigError,
    DuplicateCheckId,
    InvalidTargetError,
    OutOfScopeError,
    RequestFailed,
    WebVigilError,
)
from webvigil.core.findings import (
    Category,
    Confidence,
    EvidenceItem,
    Finding,
    Location,
    ScanMode,
    Severity,
    compute_fingerprint,
)
from webvigil.core.result import CheckError, ScanMetadata, ScanResult
from webvigil.core.target import Scope, Target, normalize_url
from webvigil.core.technology import DetectionMethod, Technology

if TYPE_CHECKING:
    from webvigil.core.orchestrator import Orchestrator

__all__ = [
    "ActiveModeNotAuthorized",
    "Category",
    "CheckError",
    "Confidence",
    "ConfigError",
    "DetectionMethod",
    "DuplicateCheckId",
    "EvidenceItem",
    "Finding",
    "InvalidTargetError",
    "Location",
    "Orchestrator",
    "OutOfScopeError",
    "Page",
    "RequestFailed",
    "ScanConfig",
    "ScanContext",
    "ScanMetadata",
    "ScanMode",
    "ScanResult",
    "Scope",
    "Severity",
    "Target",
    "Technology",
    "WebVigilError",
    "compute_fingerprint",
    "normalize_url",
]


def __getattr__(name: str) -> object:
    """
    Resolve :class:`~webvigil.core.orchestrator.Orchestrator` lazily on first access (PEP 562).

    Importing ``webvigil.core`` must stay cheap. The orchestrator pulls in
    ``webvigil.checks``, ``webvigil.http`` and ``webvigil.crawler``, so it is
    imported only when the name is actually referenced.

    Args:
        name (str): The attribute name requested on the module.

    Returns:
        object: The ``Orchestrator`` class when ``name`` is ``"Orchestrator"``.

    Raises:
        AttributeError: For any other attribute name.
    """
    if name == "Orchestrator":
        from webvigil.core.orchestrator import Orchestrator

        return Orchestrator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
