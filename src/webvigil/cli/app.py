"""WebVigil CLI entry point: ``scan``, ``list-checks``, ``report``, ``version``."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from webvigil import __version__
from webvigil.checks.registry import all_checks, load_plugins
from webvigil.cli import _render
from webvigil.cli._exit import ExitCode, evaluate
from webvigil.core.config import ScanConfig
from webvigil.core.errors import ActiveModeNotAuthorized, ConfigError, WebVigilError
from webvigil.core.findings import ScanMode
from webvigil.core.orchestrator import Orchestrator
from webvigil.core.result import ScanResult
from webvigil.core.target import Scope
from webvigil.reporting import get_reporter, load_result

app = typer.Typer(
    name="webvigil",
    help="A web application vulnerability scanner for developers. Safe by default.",
    no_args_is_help=True,
    add_completion=False,
)

_FORMATS = ("json", "sarif", "html", "md")
_FAIL_ON = ("none", "info", "low", "medium", "high", "critical")


@app.callback()
def _root() -> None:
    """A web application vulnerability scanner for developers. Safe by default."""


@app.command()
def version() -> None:
    """Print the WebVigil version."""
    typer.echo(f"webvigil {__version__}")


@app.command()
def scan(
    url: Annotated[str, typer.Argument(help="Target URL (https:// assumed if no scheme).")],
    mode: Annotated[ScanMode | None, typer.Option(help="Scan mode.")] = None,
    scope: Annotated[Scope | None, typer.Option(help="How wide to crawl.")] = None,
    output_format: Annotated[
        str | None,
        typer.Option(
            "--format", help=f"Report format ({', '.join(_FORMATS)}).", show_default=False
        ),
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", help="Write the report here.")] = None,
    max_pages: Annotated[int | None, typer.Option(help="Crawler page-count limit.")] = None,
    delay: Annotated[int | None, typer.Option(help="Delay between requests (ms).")] = None,
    authorized_by: Annotated[
        str | None, typer.Option(help="Authorization attestation, required for --mode active.")
    ] = None,
    config: Annotated[Path | None, typer.Option("--config", help="Path to webvigil.toml.")] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(help=f"Exit non-zero on findings >= this severity ({', '.join(_FAIL_ON)})."),
    ] = None,
    verify_tls: Annotated[
        bool, typer.Option("--verify-tls/--insecure", help="Verify the target's TLS certificate.")
    ] = True,
) -> None:
    """Scan a target and report findings."""
    if output_format is not None and output_format not in _FORMATS:
        _render.error(f"unknown --format {output_format!r}; choose from {', '.join(_FORMATS)}")
        raise typer.Exit(ExitCode.USAGE)
    if fail_on is not None and fail_on not in _FAIL_ON:
        _render.error(f"unknown --fail-on {fail_on!r}; choose from {', '.join(_FAIL_ON)}")
        raise typer.Exit(ExitCode.USAGE)

    try:
        cfg = _build_config(
            config=config,
            mode=mode,
            scope=scope,
            max_pages=max_pages,
            delay=delay,
            fail_on=fail_on,
            verify_tls=verify_tls,
            authorized_by=authorized_by,
        )
    except ConfigError as exc:
        _render.error(str(exc))
        raise typer.Exit(ExitCode.OPERATIONAL) from exc

    cfg = _resolve_active_mode(cfg)
    if cfg.scan.mode is ScanMode.ACTIVE and cfg.active is not None:
        _render.banner(cfg.active.authorized_by)

    try:
        result = asyncio.run(Orchestrator(cfg).run(url))
    except ActiveModeNotAuthorized as exc:
        _render.error(str(exc))
        raise typer.Exit(ExitCode.NOT_AUTHORIZED) from exc
    except WebVigilError as exc:
        _render.error(str(exc))
        raise typer.Exit(ExitCode.OPERATIONAL) from exc

    _emit(result, output_format, output)
    raise typer.Exit(int(evaluate(result, cfg.report.fail_on)))


@app.command(name="list-checks")
def list_checks() -> None:
    """List every registered check."""
    load_plugins()
    table = Table(title="WebVigil checks")
    for column in ("id", "category", "mode", "default severity"):
        table.add_column(column)
    for check in all_checks():
        table.add_row(check.id, check.category.value, check.mode.value, check.default_severity.name)
    Console().print(table)


@app.command()
def report(
    scan_json: Annotated[Path, typer.Argument(help="A scan JSON file produced by `scan`.")],
    output_format: Annotated[
        str, typer.Option("--format", help=f"Report format ({', '.join(_FORMATS)}).")
    ],
    output: Annotated[Path | None, typer.Option("--output", help="Write the report here.")] = None,
) -> None:
    """Re-render a saved scan into another format, offline."""
    if output_format not in _FORMATS:
        _render.error(f"unknown --format {output_format!r}; choose from {', '.join(_FORMATS)}")
        raise typer.Exit(ExitCode.USAGE)
    try:
        result = load_result(scan_json)
    except (OSError, ValueError) as exc:
        _render.error(f"could not read {scan_json}: {exc}")
        raise typer.Exit(ExitCode.OPERATIONAL) from exc
    _write_or_print(get_reporter(output_format).render(result), output, output_format)


def _build_config(
    *,
    config: Path | None,
    mode: ScanMode | None,
    scope: Scope | None,
    max_pages: int | None,
    delay: int | None,
    fail_on: str | None,
    verify_tls: bool,
    authorized_by: str | None,
) -> ScanConfig:
    base = ScanConfig.load(config)
    scan_overrides: dict[str, object] = {}
    if mode is not None:
        scan_overrides["mode"] = mode
    if scope is not None:
        scan_overrides["scope"] = scope
    if max_pages is not None:
        scan_overrides["max_pages"] = max_pages

    http_overrides: dict[str, object] = {"verify_tls": verify_tls}
    if delay is not None:
        http_overrides["delay_ms"] = delay

    report_overrides: dict[str, object] = {}
    if fail_on is not None:
        report_overrides["fail_on"] = fail_on

    active_overrides: dict[str, object] = {}
    if authorized_by is not None:
        active_overrides["authorized_by"] = authorized_by

    return base.with_overrides(
        scan=scan_overrides,
        http=http_overrides,
        report=report_overrides,
        active=active_overrides,
    )


def _resolve_active_mode(cfg: ScanConfig) -> ScanConfig:
    if cfg.scan.mode is not ScanMode.ACTIVE:
        return cfg
    if cfg.active is not None and cfg.active.authorized_by.strip():
        return cfg
    if sys.stdin.isatty():
        try:
            answer = typer.prompt("Authorization for Active Mode (name / engagement)").strip()
        except (typer.Abort, EOFError):
            answer = ""
        if answer:
            return cfg.with_overrides(active={"authorized_by": answer})
    _render.error(
        'Active Mode requires --authorized-by "<name / engagement>" '
        "(or an active.authorized_by entry in the config file)."
    )
    raise typer.Exit(ExitCode.NOT_AUTHORIZED)


def _emit(result: ScanResult, output_format: str | None, output: Path | None) -> None:
    if output_format is None:
        _render.summary(result)
        return
    rendered = get_reporter(output_format).render(result)
    if output is not None:
        output.write_text(rendered, "utf-8")
        _render.status(f"wrote {output_format} report to {output}")
        return
    sys.stdout.write(rendered + "\n")
    _render.summary(result)


def _write_or_print(rendered: str, output: Path | None, output_format: str) -> None:
    if output is not None:
        output.write_text(rendered, "utf-8")
        _render.status(f"wrote {output_format} report to {output}")
    else:
        sys.stdout.write(rendered + "\n")


def main() -> None:
    """Console-script entry point (see `project.scripts` in pyproject.toml)."""
    app()


if __name__ == "__main__":
    main()
