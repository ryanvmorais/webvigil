"""CLI: output routing, exit codes, active-mode gate, offline re-render — RF-24, RF-25, RF-15."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.support import make_finding, make_result
from webvigil.cli import app as app_mod
from webvigil.cli._exit import ExitCode
from webvigil.core.findings import Severity
from webvigil.core.result import ScanResult

runner = CliRunner()


class _StubOrchestrator:
    result: ScanResult = make_result(make_finding(check_id="http.headers.csp"))

    def __init__(self, config: object) -> None:
        self.config = config

    async def run(self, url: str) -> ScanResult:
        return type(self).result


@pytest.fixture(autouse=True)
def _stub_orchestrator(monkeypatch: pytest.MonkeyPatch) -> None:
    _StubOrchestrator.result = make_result(make_finding(check_id="http.headers.csp"))
    monkeypatch.setattr(app_mod, "Orchestrator", _StubOrchestrator)


def test_no_format_prints_summary_to_stderr_only() -> None:
    result = runner.invoke(app_mod.app, ["scan", "https://example.com"])
    assert result.exit_code == ExitCode.OK
    assert result.stdout == ""
    assert "WebVigil" in result.stderr


def test_format_json_goes_to_stdout() -> None:
    result = runner.invoke(app_mod.app, ["scan", "https://example.com", "--format", "json"])
    assert result.exit_code == ExitCode.OK
    json.loads(result.stdout)  # valid JSON on stdout
    assert "WebVigil" in result.stderr


def test_output_file_leaves_stdout_empty(tmp_path: Path) -> None:
    target = tmp_path / "r.sarif"
    result = runner.invoke(
        app_mod.app,
        ["scan", "https://example.com", "--format", "sarif", "--output", str(target)],
    )
    assert result.exit_code == ExitCode.OK
    assert result.stdout == ""
    assert target.read_text("utf-8").strip().startswith("{")


def test_fail_on_high_with_a_high_finding_exits_findings() -> None:
    _StubOrchestrator.result = make_result(
        make_finding(check_id="tls.https", severity=Severity.HIGH)
    )
    result = runner.invoke(app_mod.app, ["scan", "https://example.com", "--fail-on", "high"])
    assert result.exit_code == ExitCode.FINDINGS


def test_fail_on_none_exits_ok_even_with_findings() -> None:
    result = runner.invoke(app_mod.app, ["scan", "https://example.com", "--fail-on", "none"])
    assert result.exit_code == ExitCode.OK


def test_unknown_format_is_a_usage_error() -> None:
    result = runner.invoke(app_mod.app, ["scan", "https://example.com", "--format", "pdf"])
    assert result.exit_code == ExitCode.USAGE


def test_active_mode_without_authorization_in_non_tty_is_rejected() -> None:
    result = runner.invoke(app_mod.app, ["scan", "https://example.com", "--mode", "active"])
    assert result.exit_code == ExitCode.NOT_AUTHORIZED
    assert "authorized-by" in result.stderr.lower()


def test_active_mode_with_authorization_runs_and_shows_banner() -> None:
    result = runner.invoke(
        app_mod.app,
        ["scan", "https://example.com", "--mode", "active", "--authorized-by", "Jane / #9"],
    )
    assert result.exit_code == ExitCode.OK
    assert "Active Mode" in result.stderr


def test_list_checks_lists_registered_checks() -> None:
    result = runner.invoke(app_mod.app, ["list-checks"])
    assert result.exit_code == 0
    assert "http.headers.csp" in result.stdout


@pytest.mark.parametrize("fmt", ["json", "sarif", "html", "md"])
def test_report_re_renders_offline(tmp_path: Path, fmt: str) -> None:
    scan_json = tmp_path / "scan.json"
    scan_json.write_text(make_result(make_finding()).model_dump_json(), "utf-8")
    result = runner.invoke(app_mod.app, ["report", str(scan_json), "--format", fmt])
    assert result.exit_code == 0
    assert result.stdout.strip()
