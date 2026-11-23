"""Process exit codes and the ``--fail-on`` evaluation (RF-25)."""

from __future__ import annotations

from enum import IntEnum

from webvigil.core.findings import Severity
from webvigil.core.result import ScanResult


class ExitCode(IntEnum):
    """
    The process exit codes the CLI uses.

    Attributes:
        OK (int): Success, no ``--fail-on`` threshold crossed.
        INTERNAL (int): An unexpected error (Typer's default for an unhandled
            exception).
        USAGE (int): Bad command-line usage.
        FINDINGS (int): A finding at or above the ``--fail-on`` severity.
        OPERATIONAL (int): A controlled failure — bad config, unreachable
            target, unreadable report, or a ``--fail-on`` scan left incomplete.
        NOT_AUTHORIZED (int): Active Mode requested without an authorization.
    """

    OK = 0
    INTERNAL = 1
    USAGE = 2
    FINDINGS = 3
    OPERATIONAL = 4
    NOT_AUTHORIZED = 5


def evaluate(result: ScanResult, fail_on: str) -> ExitCode:
    """
    Decide the exit code from the findings and the ``--fail-on`` threshold.

    A gate must not pass on a scan that could not look: below the threshold, an incomplete
    result is an operational failure. A finding at the threshold wins, being the more
    actionable answer.

    Args:
        result (ScanResult): The completed scan.
        fail_on (str): A severity name, or ``"none"`` to never fail.

    Returns:
        ExitCode: ``FINDINGS`` if any finding is at or above the ``fail_on``
            severity, ``OPERATIONAL`` if the scan is incomplete, else ``OK``.
            Always ``OK`` for ``"none"``.
    """
    if fail_on == "none":
        return ExitCode.OK
    threshold = Severity.from_name(fail_on)
    if any(finding.severity >= threshold for finding in result.findings):
        return ExitCode.FINDINGS
    if result.incomplete:
        return ExitCode.OPERATIONAL
    return ExitCode.OK
