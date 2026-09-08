"""
Human-facing terminal output — always to stderr, so stdout stays pipeable (RF-24).
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from webvigil.core.findings import ScanMode, Severity
from webvigil.core.result import ScanResult

_console = Console(stderr=True)

# Disclosure checks that are NOT probe-fed "exposed path" findings — excluded from
# the summary's exposed-path count (spec 013 added the last two).
_PASSIVE_DISCLOSURE_IDS = frozenset(
    {
        "disclosure.debug.error-page",
        "disclosure.listing.directory-index",
        "disclosure.session-id-in-url",
        "disclosure.private-ip",
    }
)

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def error(message: str) -> None:
    """
    Print an ``error: <message>`` line to stderr in bold red.

    Args:
        message (str): The error text; printed literally, no Rich markup.
    """
    _console.print(f"error: {message}", style="bold red", markup=False, highlight=False)


def status(message: str) -> None:
    """
    Print a plain status line to stderr.

    Args:
        message (str): The text; printed literally, no Rich markup.
    """
    _console.print(message, markup=False, highlight=False)


def banner(authorized_by: str) -> None:
    """
    Print the Active-Mode warning banner to stderr.

    Args:
        authorized_by (str): The authorization attestation to echo back.
    """
    _console.print(
        "[bold yellow]Active Mode[/] — sending crafted requests. Only scan systems you are "
        f"authorized to test.\nAuthorization on record: [italic]{authorized_by}[/]"
    )


def summary(
    result: ScanResult,
    *,
    cookie_count: int = 0,
    header_count: int = 0,
    osv_online: bool = False,
    file_upload: bool = False,
) -> None:
    """
    Print the human-readable scan summary to stderr.

    A severity-count table, then optional one-liners (detected technologies,
    disclosure, active injection, authenticated scan, CSRF), then one line per
    finding, then error and warning counts.

    Args:
        result (ScanResult): The completed scan.
        cookie_count (int): Number of ``[auth]`` cookies supplied, for the
            authenticated-scan line. Defaults to 0.
        header_count (int): Number of ``[auth]`` headers supplied (spec 013),
            for the authenticated-scan line. Defaults to 0.
        osv_online (bool): Whether the OSV.dev lookup ran, for the advisory-
            sources line. Defaults to ``False``.
        file_upload (bool): Whether the spec-014 file-upload pass ran, for a
            note that files were written to the target. Defaults to ``False``.
    """
    meta = result.metadata
    table = Table(title=f"WebVigil — {meta.target}", title_justify="left")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for severity in reversed(list(Severity)):
        count = meta.counts.get(severity.name, 0)
        style = _SEVERITY_STYLE[severity] if count else "dim"
        table.add_row(f"[{style}]{severity.name}[/]", f"[{style}]{count}[/]")
    _console.print(table)

    if result.technologies:
        vulnerable = sum(1 for tech in result.technologies if tech.vulnerable)
        _console.print(
            f"[dim]Detected {len(result.technologies)} client-side "
            f"librar{'y' if len(result.technologies) == 1 else 'ies'} "
            f"({vulnerable} with known vulnerabilities)[/]"
        )
        if osv_online:
            _console.print("[dim]Advisory sources: offline database + OSV.dev[/]")

    exposed = sum(
        1
        for finding in result.findings
        if finding.check_id.startswith("disclosure.")
        and finding.check_id not in _PASSIVE_DISCLOSURE_IDS
    )
    if exposed:
        _console.print(
            f"[yellow]Information disclosure: {exposed} exposed "
            f"path{'' if exposed == 1 else 's'} found[/]"
        )

    if meta.mode is ScanMode.ACTIVE:
        injected = sum(1 for f in result.findings if f.check_id.startswith("injection."))
        if injected:
            _console.print(
                f"[red]Active injection: {injected} finding{'' if injected == 1 else 's'}[/]"
            )
        if file_upload:
            _console.print(
                "[dim]File-upload testing: enabled — benign marker files were left on the "
                "target[/]"
            )

    if cookie_count or header_count:
        parts: list[str] = []
        if cookie_count:
            parts.append(f"{cookie_count} cookie{'' if cookie_count == 1 else 's'}")
        if header_count:
            parts.append(f"{header_count} header{'' if header_count == 1 else 's'}")
        _console.print(f"[dim]Authenticated scan: {' + '.join(parts)} supplied[/]")
    csrf_forms = sum(1 for f in result.findings if f.check_id == "csrf.form.no-token")
    if csrf_forms:
        _console.print(
            f"[yellow]CSRF: {csrf_forms} form{'' if csrf_forms == 1 else 's'} without an "
            "anti-CSRF token[/]"
        )

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
