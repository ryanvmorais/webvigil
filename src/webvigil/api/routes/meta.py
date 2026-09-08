"""
Health, the check catalogue, and scan-form defaults (RF-20, RF-21, RF-22).
"""

from __future__ import annotations

from fastapi import APIRouter

from webvigil import __version__
from webvigil.api.deps import CurrentUser
from webvigil.api.schemas import CheckOut, HealthOut, ScanDefaults
from webvigil.checks.registry import all_checks, load_plugins
from webvigil.core.config import ScanConfig

router = APIRouter(tags=["meta"])


@router.get("/health")
def health() -> HealthOut:
    """Liveness probe and tool version. The only unauthenticated endpoint besides setup."""
    return HealthOut(status="ok", version=__version__)


@router.get("/checks")
def list_checks(_user: CurrentUser) -> list[CheckOut]:
    """The full check catalogue — the same list as ``webvigil list-checks``, with metadata."""
    load_plugins()
    return [
        CheckOut(
            id=check.id,
            name=check.name,
            category=check.category.value,
            mode=check.mode.value,
            default_severity=check.default_severity.name,
            cwe=list(check.cwe),
            references=list(check.references),
        )
        for check in all_checks()
    ]


@router.get("/config/defaults")
def config_defaults(_user: CurrentUser) -> ScanDefaults:
    """The default scan options, so the UI's new-scan form can pre-fill sensible values."""
    defaults = ScanConfig()
    return ScanDefaults(
        mode=defaults.scan.mode.value,
        scope=defaults.scan.scope.value,
        max_pages=defaults.scan.max_pages,
        delay_ms=defaults.http.delay_ms,
        follow_robots=defaults.scan.follow_robots,
        fail_on=defaults.report.fail_on,
    )
