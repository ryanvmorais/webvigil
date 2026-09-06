"""Human-facing terminal output — always to stderr, so stdout stays pipeable (RF-24)."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from webvigil.core.findings import Severity
from webvigil.core.result import ScanResult

_console = Console(stderr=True)

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def error(message: str) -> None:
    _console.print(f"error: {message}", style="bold red", markup=False, highlight=False)


def status(message: str) -> None:
    _console.print(message, markup=False, highlight=False)


def banner(authorized_by: str) -> None:
    _console.print(
        "[bold yellow]Active Mode[/] — sending crafted requests. Only scan systems you are "
        f"authorized to test.\nAuthorization on record: [italic]{authorized_by}[/]"
    )


def summary(result: ScanResult) -> None:
    meta = result.metadata
    table = Table(title=f"WebVigil — {meta.target}", title_justify="left")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for severity in reversed(list(Severity)):
        count = meta.counts.get(severity.name, 0)
        style = _SEVERITY_STYLE[severity] if count else "dim"
        table.add_row(f"[{style}]{severity.name}[/]", f"[{style}]{count}[/]")
    _console.print(table)

    for finding in result.findings:
        style = _SEVERITY_STYLE[finding.severity]
        location = finding.location.url
        if finding.location.key:
            location += f" ({finding.location.key})"
        _console.print(
            f"  [{style}]{finding.severity.name:>8}[/]  {finding.title}  [dim]{location}[/]"
        )

    if result.errors:
        _console.print(f"[dim]{len(result.errors)} check(s) errored[/]")
    for warning in result.warnings:
        _console.print(f"[dim]warning: {warning}[/]")
