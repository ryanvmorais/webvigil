"""
WebVigil CLI entry point: ``scan``, ``list-checks``, ``report``, ``version``.

The command docstrings double as Typer ``--help`` text, so they stay terse; the
private helpers below carry the full Args/Returns sections.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from webvigil import __version__
from webvigil.checks.deps.rules import RetireJsRules
from webvigil.checks.deps.staleness import staleness_warning
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
    for warning in staleness_warning(RetireJsRules.load()):
        _render.status(f"warning: {warning}")


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
    probe: Annotated[
        bool | None,
        typer.Option(
            "--probe/--no-probe",
            help="Probe for well-known exposed paths (.git, .env, backups). Off by default.",
        ),
    ] = None,
    time_based_sqli: Annotated[
        bool | None,
        typer.Option(
            "--time-based-sqli/--no-time-based-sqli",
            help="Send time-delay SQLi payloads during an Active scan (slower). On by default.",
        ),
    ] = None,
    time_based_cmdi: Annotated[
        bool | None,
        typer.Option(
            "--time-based-cmdi/--no-time-based-cmdi",
            help=(
                "Send time-delay OS-command-injection payloads during an Active scan "
                "(slower). On by default."
            ),
        ),
    ] = None,
    stored_xss: Annotated[
        bool | None,
        typer.Option(
            "--stored-xss/--no-stored-xss",
            help=(
                "Test for stored/persistent XSS during an Active scan: submit marker payloads "
                "the target will store, then re-crawl. Off by default."
            ),
        ),
    ] = None,
    xxe: Annotated[
        bool | None,
        typer.Option(
            "--xxe/--no-xxe",
            help=(
                "Test for XXE during an Active scan: re-send each POST body as XML with an "
                "external-entity payload. Off by default (rewrites the request body)."
            ),
        ),
    ] = None,
    cookie: Annotated[
        list[str] | None,
        typer.Option(
            "--cookie",
            help='Send this cookie on in-scope requests ("name=value"). Repeatable.',
        ),
    ] = None,
    header: Annotated[
        list[str] | None,
        typer.Option(
            "--header",
            help='Send this header on in-scope requests ("Name: Value", e.g. a bearer token). '
            "Repeatable.",
        ),
    ] = None,
    openapi: Annotated[
        str | None,
        typer.Option(
            "--openapi",
            help="Seed the scan from an OpenAPI 3.x / Swagger 2.0 JSON document "
            "(a local path or an in-scope URL).",
        ),
    ] = None,
    osv_online: Annotated[
        bool | None,
        typer.Option(
            "--osv-online/--no-osv-online",
            help=(
                "Look up detected libraries against OSV.dev (sends library names + versions "
                "to api.osv.dev). Augments the offline database. Off by default."
            ),
        ),
    ] = None,
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
            probe=probe,
            time_based_sqli=time_based_sqli,
            time_based_cmdi=time_based_cmdi,
            stored_xss=stored_xss,
            xxe=xxe,
            cookie=cookie,
            header=header,
            openapi=openapi,
            osv_online=osv_online,
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

    _emit(
        result,
        output_format,
        output,
        cookie_count=len(cfg.auth.cookies),
        header_count=len(cfg.auth.headers),
        osv_online=cfg.deps.osv_online,
    )
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
    probe: bool | None,
    time_based_sqli: bool | None,
    time_based_cmdi: bool | None,
    stored_xss: bool | None,
    xxe: bool | None,
    cookie: list[str] | None,
    header: list[str] | None,
    openapi: str | None,
    osv_online: bool | None,
) -> ScanConfig:
    """
    Merge the CLI flags onto the loaded config file (or the model defaults).

    Only flags the user actually passed are applied, so an unset flag never
    clobbers a file value. ``verify_tls`` is always applied because its
    ``--verify-tls/--insecure`` pair always has a value.

    Args:
        config (Path | None): Path to a ``webvigil.toml``, or ``None``.
        mode, scope, max_pages, delay, fail_on, authorized_by, probe,
            time_based_sqli, time_based_cmdi, stored_xss, xxe, cookie, header,
            openapi, osv_online: The optional CLI overrides; ``None`` means "not
            passed".
        verify_tls (bool): The resolved TLS-verification flag.

    Returns:
        ScanConfig: The merged, validated configuration.

    Raises:
        ConfigError: If the file is missing / invalid or the merge fails
            validation.
    """
    base = ScanConfig.load(config)
    scan_overrides: dict[str, object] = {}
    if mode is not None:
        scan_overrides["mode"] = mode
    if scope is not None:
        scan_overrides["scope"] = scope
    if max_pages is not None:
        scan_overrides["max_pages"] = max_pages
    if openapi is not None:
        scan_overrides["openapi"] = openapi

    http_overrides: dict[str, object] = {"verify_tls": verify_tls}
    if delay is not None:
        http_overrides["delay_ms"] = delay

    report_overrides: dict[str, object] = {}
    if fail_on is not None:
        report_overrides["fail_on"] = fail_on

    active_overrides: dict[str, object] = {}
    if authorized_by is not None:
        active_overrides["authorized_by"] = authorized_by

    disclosure_overrides: dict[str, object] = {}
    if probe is not None:
        disclosure_overrides["probe"] = probe

    injection_overrides: dict[str, object] = {}
    if time_based_sqli is not None:
        injection_overrides["time_based_sqli"] = time_based_sqli
    if time_based_cmdi is not None:
        injection_overrides["time_based_cmdi"] = time_based_cmdi
    if stored_xss is not None:
        injection_overrides["stored_xss"] = stored_xss
    if xxe is not None:
        injection_overrides["xxe"] = xxe

    auth_overrides: dict[str, object] = {}
    if cookie is not None:
        auth_overrides["cookies"] = cookie
    if header is not None:
        auth_overrides["headers"] = header

    deps_overrides: dict[str, object] = {}
    if osv_online is not None:
        deps_overrides["osv_online"] = osv_online

    return base.with_overrides(
        scan=scan_overrides,
        http=http_overrides,
        report=report_overrides,
        active=active_overrides,
        auth=auth_overrides,
        disclosure=disclosure_overrides,
        injection=injection_overrides,
        deps=deps_overrides,
    )


def _resolve_active_mode(cfg: ScanConfig) -> ScanConfig:
    """
    Ensure an Active scan has an authorization, prompting on a TTY if it does not.

    Args:
        cfg (ScanConfig): The merged config.

    Returns:
        ScanConfig: ``cfg`` unchanged for a Passive scan or one that already
            has an attestation; otherwise a copy with the interactively supplied
            ``authorized_by``.

    Raises:
        typer.Exit: With ``NOT_AUTHORIZED`` when Active Mode has no attestation
            and none could be obtained.
    """
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


def _emit(
    result: ScanResult,
    output_format: str | None,
    output: Path | None,
    *,
    cookie_count: int = 0,
    header_count: int = 0,
    osv_online: bool = False,
) -> None:
    """
    Emit the scan output: the terminal summary, or a rendered report.

    With no ``--format``, prints only the summary. With ``--format`` and
    ``--output``, writes the report to the file and prints a status line. With
    ``--format`` and no ``--output``, writes the report to stdout and the
    summary to stderr.

    Args:
        result (ScanResult): The completed scan.
        output_format (str | None): The report format, or ``None`` for
            summary-only.
        output (Path | None): Where to write the report, or ``None`` for
            stdout.
        cookie_count (int): Cookies supplied, for the summary. Defaults to 0.
        header_count (int): ``[auth]`` headers supplied, for the summary.
            Defaults to 0.
        osv_online (bool): Whether OSV.dev ran, for the summary. Defaults to
            ``False``.
    """
    if output_format is None:
        _render.summary(
            result, cookie_count=cookie_count, header_count=header_count, osv_online=osv_online
        )
        return
    rendered = get_reporter(output_format).render(result)
    if output is not None:
        output.write_text(rendered, "utf-8")
        _render.status(f"wrote {output_format} report to {output}")
        return
    sys.stdout.write(rendered + "\n")
    _render.summary(
        result, cookie_count=cookie_count, header_count=header_count, osv_online=osv_online
    )


def _write_or_print(rendered: str, output: Path | None, output_format: str) -> None:
    """
    Write a rendered report to ``output``, or to stdout when ``output`` is ``None``.

    Args:
        rendered (str): The rendered report text.
        output (Path | None): Destination file, or ``None`` for stdout.
        output_format (str): The format name, for the status line.
    """
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
