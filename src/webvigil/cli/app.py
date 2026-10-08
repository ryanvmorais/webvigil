"""
WebVigil CLI entry point: ``scan``, ``list-checks``, ``report``, ``version``.

The command docstrings double as Typer ``--help`` text, so they stay terse; the
private helpers below carry the full Args/Returns sections.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.measure import Measurement
from rich.table import Table

from webvigil import __version__
from webvigil.auth.login import Credentials
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
# Wide enough that Rich measures a table at its natural size, whatever the terminal is.
_UNBOUNDED_WIDTH = 10_000


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
    file_upload: Annotated[
        bool | None,
        typer.Option(
            "--file-upload/--no-file-upload",
            help=(
                "Test for unrestricted file upload during an Active scan: upload benign marker "
                "files through discovered upload forms and fetch them back. Off by default "
                "(writes files the target keeps)."
            ),
        ),
    ] = None,
    confirm_csrf: Annotated[
        bool | None,
        typer.Option(
            "--confirm-csrf/--no-confirm-csrf",
            help=(
                "Confirm CSRF during an Active scan: submit each state-changing form as a "
                "control and as cross-site replays without a valid token. Off by default "
                "(writes to the target, up to three submissions per form)."
            ),
        ),
    ] = None,
    submit_post_forms: Annotated[
        bool | None,
        typer.Option(
            "--submit-post-forms/--no-submit-post-forms",
            help=(
                "Let the crawler submit candidate POST forms and --openapi POST operations "
                "with benign values during an Active scan, and follow what the answers link "
                "to. Off by default (writes to the target)."
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
    login_url: Annotated[
        str | None,
        typer.Option(
            "--login-url",
            help=(
                "Log in at this in-scope page (a form with a password input) with the "
                "--username account and keep the session, re-logging in if it drops. Makes a "
                "real login request; Active Mode only. One attempt, never a retry."
            ),
        ),
    ] = None,
    username: Annotated[
        str | None,
        typer.Option("--username", help="The account to log in with (needs --login-url)."),
    ] = None,
    password_env: Annotated[
        str | None,
        typer.Option(
            "--password-env",
            help=(
                "Name of the environment variable that holds the login password "
                "(default WEBVIGIL_LOGIN_PASSWORD). Without it set, the password is asked "
                "for on a terminal. There is no --password flag: it would land in your shell "
                "history."
            ),
        ),
    ] = None,
    sample_sessions: Annotated[
        bool | None,
        typer.Option(
            "--sample-sessions/--no-sample-sessions",
            help=(
                "Visit the entry URL a few times with no cookie and judge the session ids the "
                "target issues (duplicates, counters, timestamps). GET-only, so allowed in any "
                "mode. Off by default."
            ),
        ),
    ] = None,
    test_logout: Annotated[
        bool | None,
        typer.Option(
            "--test-logout/--no-test-logout",
            help=(
                "Log out and replay the old session to see whether the server still accepts "
                "it. Ends the session the scan used, so it runs last; Active Mode and a login "
                "only. Off by default."
            ),
        ),
    ] = None,
    logout_url: Annotated[
        str | None,
        typer.Option(
            "--logout-url",
            help="The logout endpoint for --test-logout (else a logout link or form of the crawl).",
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
            file_upload=file_upload,
            confirm_csrf=confirm_csrf,
            submit_post_forms=submit_post_forms,
            cookie=cookie,
            header=header,
            login_url=login_url,
            username=username,
            password_env=password_env,
            logout_url=logout_url,
            sample_sessions=sample_sessions,
            test_logout=test_logout,
            openapi=openapi,
            osv_online=osv_online,
        )
    except ConfigError as exc:
        _render.error(str(exc))
        raise typer.Exit(ExitCode.OPERATIONAL) from exc

    cfg = _resolve_active_mode(cfg)
    if cfg.scan.mode is ScanMode.ACTIVE and cfg.active is not None:
        _render.banner(cfg.active.authorized_by)
    credentials = _resolve_credentials(cfg)

    try:
        result = asyncio.run(Orchestrator(cfg, credentials=credentials).run(url))
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
        login_user=cfg.auth.login.username if cfg.auth.login else None,
        session_checks=_session_summary(cfg),
        osv_online=cfg.deps.osv_online,
        file_upload=cfg.injection.file_upload and cfg.scan.mode is ScanMode.ACTIVE,
        confirm_csrf=cfg.injection.csrf_confirm and cfg.scan.mode is ScanMode.ACTIVE,
        post_crawl=cfg.scan.submit_post_forms and cfg.scan.mode is ScanMode.ACTIVE,
    )
    raise typer.Exit(int(evaluate(result, cfg.report.fail_on)))


@app.command(name="list-checks")
def list_checks() -> None:
    """List every registered check."""
    load_plugins()
    table = Table(title="WebVigil checks")
    # The id is what a user types into ``[checks] disabled``: never wrap or cut a cell, even if the
    # table ends up wider than the terminal (issue #105).
    for column in ("id", "category", "mode", "default severity"):
        table.add_column(column, no_wrap=True, overflow="ignore")
    for check in all_checks():
        table.add_row(check.id, check.category.value, check.mode.value, check.default_severity.name)
    console = Console()
    # Rich crops a table at the terminal width however the columns are set (and `measure` is
    # clamped to it too): measure the table unbounded and, if it is wider than the terminal,
    # render on a console as wide as the table, so a narrow terminal scrolls instead of losing
    # the end of an id.
    unbounded = console.options.update(width=_UNBOUNDED_WIDTH)
    natural = Measurement.get(console, unbounded, table).maximum
    if natural > console.width:
        console = Console(width=natural)
    console.print(table)


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
    file_upload: bool | None,
    confirm_csrf: bool | None,
    submit_post_forms: bool | None,
    cookie: list[str] | None,
    header: list[str] | None,
    login_url: str | None,
    username: str | None,
    password_env: str | None,
    logout_url: str | None,
    sample_sessions: bool | None,
    test_logout: bool | None,
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
            time_based_sqli, time_based_cmdi, stored_xss, xxe, file_upload,
            confirm_csrf, submit_post_forms, cookie, header, login_url, username,
            password_env, logout_url, sample_sessions, test_logout, openapi, osv_online: The
            optional CLI overrides; the three ``login`` flags merge *into* the file's
            ``[auth.login]`` table (spec 019);
            ``None`` means "not passed".
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
    if submit_post_forms is not None:
        scan_overrides["submit_post_forms"] = submit_post_forms

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
    if file_upload is not None:
        injection_overrides["file_upload"] = file_upload
    if confirm_csrf is not None:
        injection_overrides["csrf_confirm"] = confirm_csrf

    auth_overrides: dict[str, object] = {}
    if cookie is not None:
        auth_overrides["cookies"] = cookie
    if header is not None:
        auth_overrides["headers"] = header
    login_overrides: dict[str, object] = {}
    if login_url is not None:
        login_overrides["url"] = login_url
    if username is not None:
        login_overrides["username"] = username
    if password_env is not None:
        login_overrides["password_env"] = password_env
    if logout_url is not None:
        login_overrides["logout_url"] = logout_url
    if login_overrides:
        # with_overrides merges one level deep, so merge the login table here: a flag
        # overrides the file's key and leaves the rest of the file's [auth.login] alone.
        file_login = base.auth.login.model_dump() if base.auth.login else {}
        auth_overrides["login"] = {**file_login, **login_overrides}

    deps_overrides: dict[str, object] = {}
    if osv_online is not None:
        deps_overrides["osv_online"] = osv_online

    session_overrides: dict[str, object] = {}
    if sample_sessions is not None:
        session_overrides["sample_ids"] = sample_sessions
    if test_logout is not None:
        session_overrides["test_logout"] = test_logout

    return base.with_overrides(
        scan=scan_overrides,
        http=http_overrides,
        report=report_overrides,
        active=active_overrides,
        auth=auth_overrides,
        disclosure=disclosure_overrides,
        injection=injection_overrides,
        deps=deps_overrides,
        session=session_overrides,
    )


def _session_summary(cfg: ScanConfig) -> str | None:
    """
    What the session-security pass was asked to do, for the summary (spec 020).

    Args:
        cfg (ScanConfig): The resolved configuration.

    Returns:
        str | None: ``"10 ids sampled, fixation checked, logout tested"`` (only the parts that
            apply), or ``None`` when none does.
    """
    active_login = cfg.scan.mode is ScanMode.ACTIVE and cfg.auth.login is not None
    parts: list[str] = []
    if cfg.session.sample_ids:
        parts.append(f"{cfg.session.sample_count} ids sampled")
    if active_login:
        parts.append("fixation checked")
        if cfg.session.test_logout:
            parts.append("logout tested")
    return ", ".join(parts) or None


def _interactive() -> bool:
    """
    Returns:
        bool: ``True`` when stdin is a terminal, so a prompt can be answered. A seam: tests
            replace it, because ``CliRunner`` has no terminal.
    """
    return sys.stdin.isatty()


def _resolve_credentials(cfg: ScanConfig) -> Credentials | None:
    """
    Get the login password: the environment variable, else a no-echo prompt on a terminal.

    Only an Active scan with ``[auth.login]`` logs in, so only then is a password needed
    (a Passive scan with a login configured warns and sends nothing).

    Args:
        cfg (ScanConfig): The resolved configuration.

    Returns:
        Credentials | None: The account, or ``None`` when no login will run.

    Raises:
        typer.Exit: With the usage code when there is no password and no terminal to ask.
    """
    login = cfg.auth.login
    if login is None or cfg.scan.mode is not ScanMode.ACTIVE:
        return None
    password = os.environ.get(login.password_env, "")
    if not password:
        if not _interactive():
            _render.error(
                f"no password for the login: set the environment variable {login.password_env}"
            )
            raise typer.Exit(ExitCode.USAGE)
        password = typer.prompt(f"Password for {login.username}", hide_input=True)
    return Credentials(username=login.username, password=password)


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
    if _interactive():
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
    login_user: str | None = None,
    session_checks: str | None = None,
    osv_online: bool = False,
    file_upload: bool = False,
    confirm_csrf: bool = False,
    post_crawl: bool = False,
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
        login_user (str | None): The ``[auth.login]`` account, for the summary line.
            Defaults to ``None``.
        session_checks (str | None): What the session-security pass was asked to do (spec
            020), for the summary line. Defaults to ``None``.
        osv_online (bool): Whether OSV.dev ran, for the summary. Defaults to
            ``False``.
        file_upload (bool): Whether the file-upload pass ran, for the summary.
            Defaults to ``False``.
        confirm_csrf (bool): Whether the CSRF confirmation pass ran, for the
            summary. Defaults to ``False``.
        post_crawl (bool): Whether the crawler's POST phase ran, for the
            summary. Defaults to ``False``.
    """
    if output_format is None:
        _render.summary(
            result,
            cookie_count=cookie_count,
            header_count=header_count,
            login_user=login_user,
            session_checks=session_checks,
            osv_online=osv_online,
            file_upload=file_upload,
            confirm_csrf=confirm_csrf,
            post_crawl=post_crawl,
        )
        return
    rendered = get_reporter(output_format).render(result)
    if output is not None:
        output.write_text(rendered, "utf-8")
        _render.status(f"wrote {output_format} report to {output}")
        return
    _write_stdout(rendered)
    _render.summary(
        result,
        cookie_count=cookie_count,
        header_count=header_count,
        login_user=login_user,
        session_checks=session_checks,
        osv_online=osv_online,
        file_upload=file_upload,
        confirm_csrf=confirm_csrf,
        post_crawl=post_crawl,
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
        _write_stdout(rendered)


def _write_stdout(rendered: str) -> None:
    """
    Write a rendered report to stdout as UTF-8, whatever the platform's default encoding.

    On Windows a redirected stdout (``> scan.json``) uses the system code page, so the file came
    out in cp1252 and ``webvigil report`` could not read it back; ``--output`` has always written
    UTF-8. The stream is switched before the first write, which also flushes anything pending.

    Args:
        rendered (str): The rendered report text; a trailing newline is added.
    """
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:  # a replaced stream (a test, an embedder) may not have it
        reconfigure(encoding="utf-8")
    sys.stdout.write(rendered + "\n")


def main() -> None:
    """Console-script entry point (see `project.scripts` in pyproject.toml)."""
    app()


if __name__ == "__main__":
    main()
