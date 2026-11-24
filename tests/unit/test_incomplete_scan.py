"""
Incomplete scans: a target that never answered, and a pass or a check that failed.

The orchestrator tests swap the crawler for a stub that returns canned pages and each pass for a
stand-in that raises. The CLI tests drive the real Typer app over a stub orchestrator, and the
one end-to-end test runs the real engine over the in-repository HTTP mock with the retry backoff
at zero, so no request leaves the process.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import httpx2
import pytest
from typer.testing import CliRunner

from tests.http_mock import HttpxMock
from tests.support import make_finding, make_result
from webvigil.auth.scrub import REDACTED, scrub_result
from webvigil.checks.base import Check
from webvigil.checks.csrf.checks import TokenNotEnforcedCheck
from webvigil.checks.deps.check import VulnerableLibraryCheck
from webvigil.checks.disclosure.checks import VcsExposedCheck
from webvigil.checks.envelope.checks import HostHeaderCheck
from webvigil.checks.injection.checks import ReflectedXssCheck, StoredXssCheck
from webvigil.checks.session.checks import WeakSessionIdCheck
from webvigil.checks.upload.checks import UnrestrictedUploadCheck
from webvigil.cli import app as app_mod
from webvigil.cli._exit import ExitCode, evaluate
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page, ScanContext
from webvigil.core.errors import TargetUnreachableError
from webvigil.core.findings import Category, Finding, Severity
from webvigil.core.orchestrator import Orchestrator
from webvigil.core.result import CheckError, ScanResult
from webvigil.core.secrets import Secret, SecretKind
from webvigil.http import client as client_mod
from webvigil.reporting import get_reporter

runner = CliRunner()
_TARGET = "https://example.com/"
_OTHER = "https://example.com/about"
_ACTIVE: dict[str, object] = {"scan": {"mode": "active"}, "active": {"authorized_by": "x"}}
_INCOMPLETE_LINE = (
    "warning: the scan is incomplete because a pass or a check failed: "
    "the report's warnings and errors say which"
)


def _answered(url: str) -> Page:
    """
    Args:
        url (str): The page's URL.

    Returns:
        Page: A blank HTML page that answered with a 200.
    """
    return Page(
        requested_url=url,
        url=url,
        status_code=200,
        headers=httpx2.Headers({"content-type": "text/html"}),
        text="<html></html>",
        elapsed_ms=1.0,
    )


def _one_line(text: str) -> str:
    """
    Args:
        text (str): Terminal output, which Rich wraps at the console width.

    Returns:
        str: ``text`` with every run of whitespace collapsed to one space.
    """
    return " ".join(text.split())


class _Crawler:
    """A crawler that discovers the class-level ``pages`` and finds no forms."""

    forms: tuple[object, ...] = ()
    skipped_destructive = 0
    skipped_by_robots = 0
    limit_warning: str | None = None
    post_summary = None
    pages: ClassVar[list[Page]] = []

    def __init__(self, *_args: object, **_kwargs: object) -> None: ...

    async def discover(self) -> list[Page]:
        return list(type(self).pages)


class _EntrySpy(Check):
    """A check that records the entry page it was given."""

    id = "test.entry-spy"
    name = "entry spy"
    category = Category.HEADERS
    default_severity = Severity.LOW
    entries: ClassVar[list[str]] = []

    async def run(self, ctx: ScanContext) -> list[Finding]:
        type(self).entries.append(ctx.entry.url)
        return []


class _Raises:
    """A stand-in for any scan pass: building it works, running it raises."""

    def __init__(self, *_args: object, **_kwargs: object) -> None: ...

    async def run(self) -> object:
        raise RuntimeError("kaboom")

    async def scan(self, *_args: object) -> object:
        raise RuntimeError("kaboom")


@pytest.fixture
def crawler(monkeypatch: pytest.MonkeyPatch) -> type[_Crawler]:
    """
    Args:
        monkeypatch (pytest.MonkeyPatch): Swaps the orchestrator's crawler.

    Returns:
        type[_Crawler]: The stub, serving one page that answered until a test changes it.
    """
    monkeypatch.setattr(orch_mod, "Crawler", _Crawler)
    monkeypatch.setattr(_Crawler, "pages", [_answered(_TARGET)])
    monkeypatch.setattr(_EntrySpy, "entries", [])
    return _Crawler


# ---------------------------------------------------------------------------
# A target that never answered
# ---------------------------------------------------------------------------


async def test_a_target_that_never_answered_stops_the_scan(crawler: type[_Crawler]) -> None:
    """With no page answered no check runs, so none can report on a response that never came."""
    crawler.pages = [Page.failed(_TARGET, "refused"), Page.failed(_OTHER, "other")]
    with pytest.raises(TargetUnreachableError, match=r"^the target did not answer: refused$"):
        await Orchestrator(ScanConfig(), check_types=[_EntrySpy]).run(_TARGET)
    assert _EntrySpy.entries == []


async def test_the_first_page_that_answered_stands_in_for_a_failed_entry(
    crawler: type[_Crawler],
) -> None:
    """A failed seed next to a page that answered: the checks read the page that answered."""
    crawler.pages = [Page.failed(_TARGET, "refused"), _answered(_OTHER)]
    result = await Orchestrator(ScanConfig(), check_types=[_EntrySpy]).run(_TARGET)
    assert _EntrySpy.entries == [_OTHER]
    assert result.metadata.pages_scanned == 2


async def test_an_answer_with_an_error_status_is_an_answer(crawler: type[_Crawler]) -> None:
    """A 503 came from the target: the scan goes on and the checks read that page."""
    down = Page(
        requested_url=_TARGET,
        url=_TARGET,
        status_code=503,
        headers=httpx2.Headers(),
        text="",
        elapsed_ms=1.0,
    )
    crawler.pages = [down]
    await Orchestrator(ScanConfig(), check_types=[_EntrySpy]).run(_TARGET)
    assert _EntrySpy.entries == [_TARGET]


def test_a_closed_port_exits_operational_and_writes_no_report(
    httpx_mock: HttpxMock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """End to end over the real engine: exit 4, the reason on stderr, no report file."""
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)
    httpx_mock.add_exception(httpx2.ConnectError("connection refused"), is_reusable=True)
    report = tmp_path / "scan.json"

    result = runner.invoke(
        app_mod.app, ["scan", _TARGET, "--format", "json", "--output", str(report)]
    )

    assert result.exit_code == ExitCode.OPERATIONAL
    assert "error: the target did not answer:" in _one_line(result.stderr)
    assert not report.exists()
    assert httpx_mock.get_requests()


# ---------------------------------------------------------------------------
# A pass that failed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pass_name", "raw", "check", "label"),
    [
        ("Fingerprinter", {}, VulnerableLibraryCheck, "dependency fingerprint pass failed"),
        (
            "DisclosureProbe",
            {"disclosure": {"probe": True}},
            VcsExposedCheck,
            "disclosure probe pass failed",
        ),
        ("InjectionScanner", _ACTIVE, ReflectedXssCheck, "active injection pass failed"),
        (
            "StoredXssScanner",
            {**_ACTIVE, "injection": {"stored_xss": True}},
            StoredXssCheck,
            "stored-XSS pass failed",
        ),
        ("EnvelopeScanner", _ACTIVE, HostHeaderCheck, "request-envelope pass failed"),
        (
            "UploadScanner",
            {**_ACTIVE, "injection": {"file_upload": True}},
            UnrestrictedUploadCheck,
            "file-upload pass failed",
        ),
        (
            "CsrfScanner",
            {**_ACTIVE, "injection": {"csrf_confirm": True}},
            TokenNotEnforcedCheck,
            "CSRF confirmation pass failed",
        ),
        ("SessionScanner", {}, WeakSessionIdCheck, "session checks failed"),
    ],
    ids=[
        "fingerprint",
        "disclosure",
        "injection",
        "stored",
        "envelope",
        "upload",
        "csrf",
        "session",
    ],
)
async def test_every_pass_that_raises_marks_the_scan_incomplete(
    crawler: type[_Crawler],
    monkeypatch: pytest.MonkeyPatch,
    pass_name: str,
    raw: dict[str, object],
    check: type[Check],
    label: str,
) -> None:
    """The warning names the pass, and the result knows the scan is incomplete."""
    monkeypatch.setattr(orch_mod, pass_name, _Raises)
    result = await Orchestrator(ScanConfig.model_validate(raw), check_types=[check]).run(_TARGET)
    assert f"{label}: RuntimeError" in result.warnings
    assert result.pass_failed is True
    assert result.incomplete is True


async def test_an_ordinary_warning_does_not_mark_the_scan_incomplete(
    crawler: type[_Crawler],
) -> None:
    """A notice about an opt-in that did not run is not a failure."""
    config = ScanConfig.model_validate({"injection": {"stored_xss": True}})
    result = await Orchestrator(config, check_types=[_EntrySpy]).run(_TARGET)
    assert "stored-XSS testing requires --mode active — the stored pass did not run" in (
        result.warnings
    )
    assert result.pass_failed is False
    assert result.incomplete is False


def test_scrubbing_a_result_keeps_it_incomplete() -> None:
    """A scan with credentials goes through the scrubber, which must not clear the signal."""
    secret = "a-long-configured-secret"
    result = make_result(warnings=[f"session checks failed: {secret}"]).model_copy(
        update={"pass_failed": True}
    )
    scrubbed = scrub_result(result, [Secret(secret, kind=SecretKind.PASSWORD)])
    assert scrubbed.warnings[0] == f"session checks failed: {REDACTED}"
    assert scrubbed.pass_failed is True


def test_the_json_report_keeps_its_shape() -> None:
    """The signal is for the exit code: the canonical report gains no field."""
    result = make_result().model_copy(update={"pass_failed": True})
    assert result.pass_failed is True
    assert "pass_failed" not in json.loads(get_reporter("json").render(result))


# ---------------------------------------------------------------------------
# The exit code
# ---------------------------------------------------------------------------

_CHECK_ERROR = CheckError(check_id="http.headers.csp", message="boom", traceback="trace")


@pytest.mark.parametrize(
    ("severity", "check_failed", "pass_failed", "fail_on", "expected"),
    [
        (None, False, False, "high", ExitCode.OK),
        (None, False, True, "high", ExitCode.OPERATIONAL),
        (None, True, False, "high", ExitCode.OPERATIONAL),
        (Severity.MEDIUM, False, True, "high", ExitCode.OPERATIONAL),
        (Severity.HIGH, False, True, "high", ExitCode.FINDINGS),
        (Severity.HIGH, True, False, "high", ExitCode.FINDINGS),
        (None, False, True, "none", ExitCode.OK),
        (None, True, False, "none", ExitCode.OK),
        (Severity.HIGH, False, True, "none", ExitCode.OK),
    ],
    ids=[
        "complete-passes",
        "pass-failed",
        "check-failed",
        "below-threshold-and-incomplete",
        "finding-wins-over-pass",
        "finding-wins-over-check",
        "none-ignores-pass",
        "none-ignores-check",
        "none-ignores-finding-and-pass",
    ],
)
def test_the_exit_code_of_an_incomplete_scan(
    severity: Severity | None,
    check_failed: bool,
    pass_failed: bool,
    fail_on: str,
    expected: ExitCode,
) -> None:
    """Only a ``--fail-on`` gate fails on an incomplete scan, and a real finding comes first."""
    findings = [make_finding(severity=severity)] if severity is not None else []
    errors = [_CHECK_ERROR] if check_failed else []
    result = make_result(*findings, errors=errors).model_copy(update={"pass_failed": pass_failed})
    assert evaluate(result, fail_on) is expected


class _StubOrchestrator:
    """An orchestrator whose ``run`` returns the class-level ``result``."""

    result: ClassVar[ScanResult] = make_result()

    def __init__(self, _config: object, *, credentials: object = None) -> None: ...

    async def run(self, _url: str) -> ScanResult:
        return type(self).result


@pytest.mark.parametrize(
    ("pass_failed", "fail_on", "code", "warned"),
    [
        (True, "high", ExitCode.OPERATIONAL, True),
        (True, "none", ExitCode.OK, True),
        (False, "high", ExitCode.OK, False),
    ],
    ids=["gate-fails", "no-gate-still-warns", "complete-says-nothing"],
)
def test_a_report_to_a_file_still_says_the_scan_is_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    pass_failed: bool,
    fail_on: str,
    code: ExitCode,
    warned: bool,
) -> None:
    """With ``--output`` no summary is printed: the terminal line is the only sign of it."""
    outcome = make_result().model_copy(update={"pass_failed": pass_failed})
    monkeypatch.setattr(_StubOrchestrator, "result", outcome)
    monkeypatch.setattr(app_mod, "Orchestrator", _StubOrchestrator)
    report = tmp_path / "scan.json"

    result = runner.invoke(
        app_mod.app,
        ["scan", _TARGET, "--format", "json", "--output", str(report), "--fail-on", fail_on],
    )

    assert result.exit_code == code
    assert (_INCOMPLETE_LINE in _one_line(result.stderr)) is warned
    assert json.loads(report.read_text("utf-8"))["findings"] == []
