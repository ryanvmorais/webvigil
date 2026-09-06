"""Process exit codes and the ``--fail-on`` evaluation (RF-25)."""

from __future__ import annotations

from enum import IntEnum

from webvigil.core.findings import Severity
from webvigil.core.result import ScanResult


class ExitCode(IntEnum):
    OK = 0
    INTERNAL = 1
    USAGE = 2
    FINDINGS = 3
    OPERATIONAL = 4
    NOT_AUTHORIZED = 5


def evaluate(result: ScanResult, fail_on: str) -> ExitCode:
    """``FINDINGS`` if any finding is at or above the ``fail_on`` severity, else ``OK``."""
    if fail_on == "none":
        return ExitCode.OK
    threshold = Severity.from_name(fail_on)
    if any(finding.severity >= threshold for finding in result.findings):
        return ExitCode.FINDINGS
    return ExitCode.OK
