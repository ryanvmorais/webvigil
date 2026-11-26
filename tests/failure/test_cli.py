"""
The CLI harness of spec 027 (RF-02 to RF-05, ADR-3): failures before and after a scan.

Each run invokes the real CLI with a configured cookie and bearer token whose values are
credential markers, fails one dependency with a failure marker, and then searches every output:
the standard output and error, the report, the same result re-rendered in the three other
formats, and every log record at ``DEBUG``. No credential may appear in any spelling, a failure's
text may appear only where its kind allows, and the run must end with a documented exit code and
no traceback (RF-02).

Each run also has its positive controls (RF-05): the seam really raised, with its marker in the
text; the searches find the markers where they are known to be; and a run that reached the
target sent it both credentials, while a run that failed before the scan sent nothing.

The scans run the passive profile against the fixture application, over ``httpx2.ASGITransport``,
except the ``resolver`` run: the address guard is installed only on the real transport, so it
scans a name that the patched resolver refuses, and no request leaves the process.
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import httpx2
import pytest
from starlette.applications import Starlette
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from typer.testing import CliRunner, Result

from tests.failure.faults import (
    Fault,
    failing_read,
    failing_render,
    failing_resolver,
    failing_write,
)
from tests.failure.outputs import (
    WIDE_TERMINAL,
    Outputs,
    bad_failure_hits,
    cli_outputs,
    credential_hits,
    every_log_record,
    failure_hits,
    is_output_logger,
)
from tests.failure.table import (
    TARGET,
    Kind,
    credential_marker,
    failure_marker,
    failure_text,
    stage,
)
from tests.fixtures.app import CANARY_COOKIE, make_app
from tests.support import make_finding, make_result
from webvigil.cli import app as app_mod
from webvigil.cli._exit import ExitCode
from webvigil.core import orchestrator as orch_mod
from webvigil.http import client as client_mod
from webvigil.http.client import HttpClient
from webvigil.reporting import get_reporter

runner = CliRunner()

COOKIE: Final = credential_marker("cookie")
BEARER: Final = credential_marker("bearer")
CREDENTIALS: Final = (COOKIE, BEARER)
_CREDENTIAL_FLAGS: Final = (
    "--cookie",
    f"{CANARY_COOKIE}={COOKIE}",
    "--header",
    f"Authorization: Bearer {BEARER}",
)
# The fixture is plain HTTP: the TLS check would open a socket to port 443 of the fixture's name.
_CONFIG: Final = '[checks]\ndisabled = ["tls.https"]\n\n[scan]\nmax_pages = 8\n'
# The exit codes the documentation gives for a scan that ends, well or not (docs/stability.md).
_DOCUMENTED_EXITS: Final = frozenset({ExitCode.OK, ExitCode.FINDINGS, ExitCode.OPERATIONAL})
# A proxy in the environment would be resolved and asked instead of the target.
_PROXY_VARIABLES: Final = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


@dataclass
class Run:
    """
    One CLI run of the harness.

    Attributes:
        result (Result): What the CLI did.
        outputs (Outputs): Everything it showed or wrote.
        fault (Fault): The seam that failed.
        kind (Kind): Its kind of failure.
        app (Starlette | None): The fixture, when the run scanned it.
    """

    result: Result
    outputs: Outputs
    fault: Fault
    kind: Kind
    app: Starlette | None


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """The client still retries a failed request; only the wait between attempts is dropped."""
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)


def echoing(app: ASGIApp) -> ASGIApp:
    """
    Wrap the fixture as a hostile site: every response's ``Server`` header repeats the request's
    ``Cookie`` and ``Authorization``, which the passive checks quote as evidence.

    Args:
        app (ASGIApp): The fixture application.

    Returns:
        ASGIApp: The same application, echoing both credentials.
    """

    async def wrapped(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await app(scope, receive, send)
            return
        echoed = b" ".join(v for k, v in scope["headers"] if k in {b"cookie", b"authorization"})

        async def send_echo(message: Message) -> None:
            if message["type"] == "http.response.start":
                kept = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"server"]
                server = (b"server", b"Echo/1.0 (" + echoed + b")")
                message = {**message, "headers": [*kept, server]}
            await send(message)

        await app(scope, receive, send_echo)

    return wrapped


@pytest.fixture
def fixture_app(monkeypatch: pytest.MonkeyPatch) -> Iterator[Starlette]:
    """
    Point the engine's HTTP client at the fixture application, which echoes the credentials.

    Yields:
        Starlette: The fixture, whose ``state`` records every request it received.
    """
    app = make_app("insecure")
    transport = httpx2.ASGITransport(app=echoing(app))
    monkeypatch.setattr(orch_mod, "HttpClient", functools.partial(HttpClient, transport=transport))
    yield app


@pytest.fixture
def config(tmp_path: Path) -> Path:
    """
    Returns:
        Path: A configuration file for the passive runs.
    """
    path = tmp_path / "webvigil.toml"
    path.write_text(_CONFIG, "utf-8")
    return path


def _marker(name: str) -> tuple[str, Kind]:
    """
    Args:
        name (str): A CLI stage of the table.

    Returns:
        tuple[str, Kind]: The stage's failure marker and its kind.
    """
    row = stage(name)
    assert row.harness == "cli"
    (kind,) = row.kinds
    return failure_marker(name, kind), kind


def _invoke(args: list[str], report: Path, fault: Fault, kind: Kind, app: Starlette | None) -> Run:
    """
    Run the CLI with every log record kept, and collect its outputs.

    Args:
        args (list[str]): The command line.
        report (Path): Where the run writes its JSON report, if it gets that far.
        fault (Fault): The seam the run fails.
        kind (Kind): Its kind of failure.
        app (Starlette | None): The fixture, when the run scans it.

    Returns:
        Run: The run.
    """
    with every_log_record() as logs:
        result = runner.invoke(app_mod.app, args, env=WIDE_TERMINAL)
    return Run(result, cli_outputs(runner, result, report, logs), fault, kind, app)


def _scan_args(report: Path, config: Path | None, *extra: str, target: str = TARGET) -> list[str]:
    """
    Args:
        report (Path): Where the JSON report goes.
        config (Path | None): The configuration file, or ``None``.
        *extra (str): More flags.
        target (str): The URL to scan. Defaults to the fixture's.

    Returns:
        list[str]: A ``scan`` command line with both credentials.
    """
    flags = ["--config", str(config)] if config is not None else []
    return [
        "scan",
        target,
        *flags,
        *_CREDENTIAL_FLAGS,
        "--format",
        "json",
        "--output",
        str(report),
        *extra,
    ]


def _error_lines(result: Result) -> list[str]:
    """
    Args:
        result (Result): A CLI run.

    Returns:
        list[str]: Its ``error:`` lines.
    """
    return [line for line in result.stderr.splitlines() if line.startswith("error:")]


def _check(run: Run, *, reached_target: bool) -> None:
    """
    The assertions every run of the harness makes, with their positive controls.

    Args:
        run (Run): The run.
        reached_target (bool): Whether the run got as far as sending requests to the target.
    """
    result = run.result
    # the run ended as documented: an exit code of the CLI, no traceback
    assert result.exit_code in _DOCUMENTED_EXITS, (result.exit_code, result.exception)
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert "Traceback" not in result.stderr

    # the positive controls of the failure (RF-05): the seam raised, and its text holds the marker
    assert run.fault.raised, "the seam never raised: the run did not reach its stage"
    raised = Outputs()
    for exc in run.fault.raised:
        raised.add("raised", str(exc))
        assert run.fault.marker in str(exc)
    assert failure_hits(raised, {run.fault.marker: run.kind})

    # the searches (RF-03, RF-04)
    assert credential_hits(run.outputs, CREDENTIALS) == []
    assert bad_failure_hits(run.outputs, {run.fault.marker: run.kind}) == []

    # the positive controls of the credentials (RF-05)
    if run.app is None:
        return
    sent = run.app.state.auth_log
    if reached_target:
        assert (f"Bearer {BEARER}", COOKIE) in sent
        wire = Outputs()
        wire.add("wire", repr(sent))
        assert {hit.marker for hit in credential_hits(wire, CREDENTIALS)} == set(CREDENTIALS)
    else:
        assert run.app.state.requests == []


# ---------------------------------------------------------------------------
# The positive controls of the collector
# ---------------------------------------------------------------------------


def test_a_clean_run_has_every_output_and_shows_no_credential(
    tmp_path: Path, config: Path, fixture_app: Starlette
) -> None:
    """
    With no fault, the collector holds the streams, the JSON report and its three re-renders.
    The site echoed both credentials into a header the report quotes, and the scrub removed them:
    the search finds them on the wire and in no output.
    """
    report = tmp_path / "report.json"
    with every_log_record() as logs:
        result = runner.invoke(app_mod.app, _scan_args(report, config), env=WIDE_TERMINAL)
    assert result.exit_code in _DOCUMENTED_EXITS, result.exception
    outputs = cli_outputs(runner, result, report, logs)
    names = {"stdout", "stderr", "report:json", "report:sarif", "report:html", "report:md"}
    assert names <= set(outputs.texts)
    assert all(outputs.texts[f"report:{fmt}"] for fmt in ("json", "sarif", "html", "md"))
    assert "Echo/1.0 (" in outputs.texts["report:json"]  # the echoed header is quoted...
    assert "[redacted]" in outputs.texts["report:json"]  # ...with the credentials taken out
    assert credential_hits(outputs, CREDENTIALS) == []
    wire = Outputs()
    wire.add("wire", repr(fixture_app.state.auth_log))
    assert {hit.marker for hit in credential_hits(wire, CREDENTIALS)} == set(CREDENTIALS)


def test_only_the_projects_loggers_are_an_output() -> None:
    """The engine's, the Web API's and the treated libraries' records are kept; others are not."""
    kept = ("webvigil", "webvigil.http.client", "webvigil.api", "httpx2", "uvicorn.error")
    left = ("httpcore2.connection", "webvigilant", "uvicorn.access", "root")
    assert all(is_output_logger(name) for name in kept)
    assert not any(is_output_logger(name) for name in left)
    with every_log_record() as logs:
        for name in (*kept, *left):
            logging.getLogger(name).debug("record of %s", name)
    assert len(logs.lines) == len(kept) and logs.other == len(left)
    assert all(f"record of {name}" in line for name, line in zip(kept, logs.lines, strict=True))


# ---------------------------------------------------------------------------
# Before the scan
# ---------------------------------------------------------------------------


def test_a_resolver_that_fails_ends_the_scan_in_the_projects_words(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, config: Path
) -> None:
    """
    ``resolver``: the address guard's resolver raises for every name. The scan says the target
    did not answer, with the kind of failure, and exits with ``4``; the resolver's text is nowhere.
    """
    for name in _PROXY_VARIABLES:  # a proxy would be resolved and asked instead of the target
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    marker, kind = _marker("resolver")
    fault = failing_resolver(monkeypatch, marker)
    report = tmp_path / "report.json"
    run = _invoke(_scan_args(report, config), report, fault, kind, None)
    _check(run, reached_target=False)
    assert run.result.exit_code == ExitCode.OPERATIONAL
    assert _error_lines(run.result) == [
        "error: the target did not answer: request to http://demo.test/ failed: ConnectError"
    ]


@pytest.mark.parametrize(
    ("name", "flag"),
    [("config-read", "--config"), ("openapi-read", "--openapi"), ("har-read", "--har")],
)
def test_an_input_file_that_cannot_be_read_is_named_by_its_type(
    name: str,
    flag: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    config: Path,
    fixture_app: Starlette,
) -> None:
    """
    ``config-read``, ``openapi-read``, ``har-read``: the file exists, but reading it raises
    ``OSError``. The scan stops before any request with ``could not read <path>: OSError``.
    """
    marker, kind = _marker(name)
    if flag == "--config":
        source, extra = config, []
    else:
        source = tmp_path / ("api.json" if flag == "--openapi" else "traffic.har")
        source.write_text("{}", "utf-8")
        extra = [flag, str(source)]
    fault = failing_read(monkeypatch, source, marker)
    report = tmp_path / "report.json"
    run = _invoke(_scan_args(report, config, *extra), report, fault, kind, fixture_app)
    _check(run, reached_target=False)
    assert run.result.exit_code == ExitCode.OPERATIONAL
    (line,) = _error_lines(run.result)
    assert line.endswith(": OSError") and "could not read" in line, line


def test_an_openapi_document_that_is_not_json_is_named_by_its_position(
    tmp_path: Path, config: Path, fixture_app: Starlette
) -> None:
    """
    ``openapi-parse``: the document is not JSON. The error names the line and column the parser
    stopped at, in the project's words; no part of the parser's own message appears (RF-04).
    """
    marker, kind = _marker("openapi-parse")
    content = "{\n  " + failure_text(marker)
    document = tmp_path / "api.json"
    document.write_text(content, "utf-8")
    try:
        json.loads(content)
    except json.JSONDecodeError as exc:
        library_message = exc.msg
    fault = Fault(marker, [ValueError(content)])  # the bad document plays the raised failure
    report = tmp_path / "report.json"
    args = _scan_args(report, config, "--openapi", str(document))
    run = _invoke(args, report, fault, kind, fixture_app)
    _check(run, reached_target=False)
    assert run.result.exit_code == ExitCode.OPERATIONAL
    (line,) = _error_lines(run.result)
    assert line.endswith("is not valid JSON (line 2, column 3)"), line
    assert library_message and library_message not in run.result.stderr


# ---------------------------------------------------------------------------
# After the scan
# ---------------------------------------------------------------------------


def test_a_report_that_cannot_be_written_ends_with_one_error_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, config: Path, fixture_app: Starlette
) -> None:
    """
    ``report-write``: writing the report raises ``OSError``. The scan ran; the CLI prints one
    error line, with the path and the type, and exits with ``4``.
    """
    marker, kind = _marker("report-write")
    report = tmp_path / "report.json"
    fault = failing_write(monkeypatch, report, marker)
    run = _invoke(_scan_args(report, config), report, fault, kind, fixture_app)
    _check(run, reached_target=True)
    assert run.result.exit_code == ExitCode.OPERATIONAL
    assert _error_lines(run.result) == [f"error: could not write the report to {report} (OSError)"]
    assert not report.exists()


def test_a_report_that_cannot_be_rendered_ends_with_one_error_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, config: Path, fixture_app: Starlette
) -> None:
    """
    ``report-render``: the JSON reporter raises ``RuntimeError``. The CLI prints one error line,
    with the format and the type, and exits with ``4``.
    """
    marker, kind = _marker("report-render")
    fault = failing_render(monkeypatch, "json", marker)
    report = tmp_path / "report.json"
    run = _invoke(_scan_args(report, config), report, fault, kind, fixture_app)
    _check(run, reached_target=True)
    assert run.result.exit_code == ExitCode.OPERATIONAL
    assert _error_lines(run.result) == ["error: could not render the json report (RuntimeError)"]
    assert not report.exists()


def test_a_saved_report_that_cannot_be_read_is_named_by_its_type(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    ``report-read``: ``webvigil report`` over a file whose read raises ``OSError`` says
    ``could not read <path> (OSError)`` and exits with ``4``.
    """
    marker, kind = _marker("report-read")
    saved = tmp_path / "scan.json"
    saved.write_text(get_reporter("json").render(make_result(make_finding())), "utf-8")
    fault = failing_read(monkeypatch, saved, marker)
    out = tmp_path / "out.md"
    with every_log_record() as logs:
        result = runner.invoke(
            app_mod.app,
            ["report", str(saved), "--format", "md", "--output", str(out)],
            env=WIDE_TERMINAL,
        )
    run = Run(result, cli_outputs(runner, result, out, logs), fault, kind, None)
    _check(run, reached_target=False)
    assert result.exit_code == ExitCode.OPERATIONAL
    assert _error_lines(result) == [f"error: could not read {saved} (OSError)"]


def test_a_rerendered_report_that_cannot_be_written_ends_with_one_error_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    ``report-write`` through ``webvigil report --output``: the saved scan reads, the new file
    cannot be written. One error line, with the path and the type, and exit code ``4``.
    """
    marker, kind = _marker("report-write")
    saved = tmp_path / "scan.json"
    saved.write_text(get_reporter("json").render(make_result(make_finding())), "utf-8")
    out = tmp_path / "out.md"
    fault = failing_write(monkeypatch, out, marker)
    with every_log_record() as logs:
        result = runner.invoke(
            app_mod.app,
            ["report", str(saved), "--format", "md", "--output", str(out)],
            env=WIDE_TERMINAL,
        )
    run = Run(result, cli_outputs(runner, result, out, logs), fault, kind, None)
    _check(run, reached_target=False)
    assert result.exit_code == ExitCode.OPERATIONAL
    assert _error_lines(result) == [f"error: could not write the report to {out} (OSError)"]
    assert not out.exists()


def test_a_saved_report_that_cannot_be_rendered_ends_with_one_error_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    ``report-render`` through ``webvigil report``: the saved scan reads, the Markdown reporter
    raises. One error line, with the format and the type, and exit code ``4``.
    """
    marker, kind = _marker("report-render")
    saved = tmp_path / "scan.json"
    saved.write_text(get_reporter("json").render(make_result(make_finding())), "utf-8")
    fault = failing_render(monkeypatch, "md", marker)
    out = tmp_path / "out.md"
    with every_log_record() as logs:
        result = runner.invoke(
            app_mod.app,
            ["report", str(saved), "--format", "md", "--output", str(out)],
            env=WIDE_TERMINAL,
        )
    run = Run(result, cli_outputs(runner, result, out, logs), fault, kind, None)
    _check(run, reached_target=False)
    assert result.exit_code == ExitCode.OPERATIONAL
    assert _error_lines(result) == ["error: could not render the md report (RuntimeError)"]
    assert not out.exists()
