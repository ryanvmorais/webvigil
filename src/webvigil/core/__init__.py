"""Scan engine: orchestrator, target/scope model, findings, and configuration.

Pure library code — must not import FastAPI, SQLModel, Typer, Rich, or any UI concern.
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

if TYPE_CHECKING:
    from webvigil.core.orchestrator import Orchestrator

__all__ = [
    "ActiveModeNotAuthorized",
    "Category",
    "CheckError",
    "Confidence",
    "ConfigError",
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
    "WebVigilError",
    "compute_fingerprint",
    "normalize_url",
]


def __getattr__(name: str) -> object:
    # Lazy so importing `webvigil.core` does not eagerly pull the orchestrator, which
    # depends on `webvigil.checks` / `webvigil.http` / `webvigil.crawler`.
    if name == "Orchestrator":
        from webvigil.core.orchestrator import Orchestrator

        return Orchestrator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
