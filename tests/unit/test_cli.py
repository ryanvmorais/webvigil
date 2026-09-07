"""CLI: output routing, exit codes, active-mode gate, offline re-render — RF-24, RF-25, RF-15."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.support import make_finding, make_result
from webvigil.cli import app as app_mod
from webvigil.cli._exit import ExitCode
from webvigil.core.findings import ScanMode, Severity
from webvigil.core.result import ScanResult

runner = CliRunner()


class _StubOrchestrator:
    result: ScanResult = make_result(make_finding(check_id="http.headers.csp"))
    last_config: object = None

    def __init__(self, config: object) -> None:
        self.config = config
        type(self).last_config = config

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
    assert "deps.js.vulnerable-library" in result.stdout


def test_scan_summary_reports_detected_libraries() -> None:
    from webvigil.core.technology import DetectionMethod, Technology

    _StubOrchestrator.result = make_result(
        make_finding(check_id="deps.js.vulnerable-library"),
        technologies=(
            Technology(
                name="jquery",
                version="1.12.4",
                detection=DetectionMethod.FILENAME,
                source_url="https://example.com/j.js",
                vulnerable=True,
            ),
        ),
    )
    result = runner.invoke(app_mod.app, ["scan", "https://example.com"])
    assert "Detected 1 client-side library (1 with known vulnerabilities)" in result.stderr


def test_list_checks_lists_the_disclosure_checks() -> None:
    result = runner.invoke(app_mod.app, ["list-checks"])
    assert "disclosure.vcs.exposed" in result.stdout
    assert "disclosure.debug.error-page" in result.stdout
    assert "DISCLOSURE" in result.stdout


def test_probe_flag_enables_the_disclosure_probe_in_the_config() -> None:
    runner.invoke(app_mod.app, ["scan", "https://example.com", "--probe"])
    assert _StubOrchestrator.last_config.disclosure.probe is True  # type: ignore[attr-defined]


def test_no_probe_flag_disables_it_over_a_config_file(tmp_path: Path) -> None:
    cfg = tmp_path / "webvigil.toml"
    cfg.write_text("[disclosure]\nprobe = true\n", "utf-8")
    runner.invoke(app_mod.app, ["scan", "https://example.com", "--config", str(cfg), "--no-probe"])
    assert _StubOrchestrator.last_config.disclosure.probe is False  # type: ignore[attr-defined]


def test_probe_does_not_trip_the_active_mode_gate() -> None:
    result = runner.invoke(app_mod.app, ["scan", "https://example.com", "--probe"])
    assert result.exit_code == 0


def test_scan_summary_reports_exposed_paths() -> None:
    _StubOrchestrator.result = make_result(
        make_finding(check_id="disclosure.vcs.exposed", severity=Severity.HIGH),
        make_finding(check_id="disclosure.debug.error-page", severity=Severity.MEDIUM),
    )
    result = runner.invoke(app_mod.app, ["scan", "https://example.com"])
    assert "Information disclosure: 1 exposed path found" in result.stderr


def test_list_checks_lists_the_injection_checks() -> None:
    result = runner.invoke(app_mod.app, ["list-checks"])
    assert "injection.xss.reflected" in result.stdout
    assert "injection.sqli.time-based" in result.stdout
    assert "injection.xss.stored" in result.stdout
    assert "INJECTION" in result.stdout


def test_no_time_based_sqli_flag_disables_it_over_a_config_file(tmp_path: Path) -> None:
    cfg = tmp_path / "webvigil.toml"
    cfg.write_text("[injection]\ntime_based_sqli = true\n", "utf-8")
    runner.invoke(
        app_mod.app,
        ["scan", "https://example.com", "--config", str(cfg), "--no-time-based-sqli"],
    )
    assert _StubOrchestrator.last_config.injection.time_based_sqli is False  # type: ignore[attr-defined]


def test_stored_xss_flag_enables_it_over_a_config_file(tmp_path: Path) -> None:
    cfg = tmp_path / "webvigil.toml"
    cfg.write_text("[injection]\nstored_xss = false\n", "utf-8")
    runner.invoke(
        app_mod.app,
        ["scan", "https://example.com", "--config", str(cfg), "--stored-xss"],
    )
    assert _StubOrchestrator.last_config.injection.stored_xss is True  # type: ignore[attr-defined]
    runner.invoke(app_mod.app, ["scan", "https://example.com", "--no-stored-xss"])
    assert _StubOrchestrator.last_config.injection.stored_xss is False  # type: ignore[attr-defined]


def test_osv_online_flag_enables_it_over_a_config_file(tmp_path: Path) -> None:
    cfg = tmp_path / "webvigil.toml"
    cfg.write_text("[deps]\nosv_online = false\n", "utf-8")
    runner.invoke(
        app_mod.app,
        ["scan", "https://example.com", "--config", str(cfg), "--osv-online"],
    )
    assert _StubOrchestrator.last_config.deps.osv_online is True  # type: ignore[attr-defined]
    runner.invoke(app_mod.app, ["scan", "https://example.com", "--no-osv-online"])
    assert _StubOrchestrator.last_config.deps.osv_online is False  # type: ignore[attr-defined]


def test_summary_names_osv_as_an_advisory_source_only_when_enabled() -> None:
    from webvigil.core.technology import DetectionMethod, Technology

    tech = Technology(
        name="jquery",
        version="3.4.1",
        detection=DetectionMethod.FILECONTENT,
        source_url="https://example.com/jquery.js",
        vulnerable=True,
    )
    _StubOrchestrator.result = make_result(
        make_finding(check_id="deps.js.vulnerable-library"), technologies=[tech]
    )
    with_osv = runner.invoke(app_mod.app, ["scan", "https://example.com", "--osv-online"])
    assert "Advisory sources: offline database + OSV.dev" in with_osv.stderr

    without = runner.invoke(app_mod.app, ["scan", "https://example.com"])
    assert "OSV.dev" not in without.stderr


def test_active_scan_summary_reports_injection_findings() -> None:
    _StubOrchestrator.result = make_result(
        make_finding(check_id="injection.xss.reflected", severity=Severity.HIGH),
        make_finding(check_id="injection.sqli.error-based", severity=Severity.HIGH),
        mode=ScanMode.ACTIVE,
    )
    result = runner.invoke(
        app_mod.app,
        ["scan", "https://example.com", "--mode", "active", "--authorized-by", "me"],
    )
    assert "Active injection: 2 findings" in result.stderr


# --- spec 007: --cookie, list-checks, summary lines ---


def test_cookie_flags_populate_the_auth_config() -> None:
    runner.invoke(
        app_mod.app,
        ["scan", "https://example.com", "--cookie", "session=abc", "--cookie", "csrf=xyz"],
    )
    assert _StubOrchestrator.last_config.auth.cookies == ["session=abc", "csrf=xyz"]  # type: ignore[attr-defined]


def test_cookie_flags_replace_a_config_file_list(tmp_path: Path) -> None:
    cfg = tmp_path / "webvigil.toml"
    cfg.write_text("[auth]\ncookies = ['from=file']\n", "utf-8")
    runner.invoke(
        app_mod.app,
        ["scan", "https://example.com", "--config", str(cfg), "--cookie", "from=cli"],
    )
    assert _StubOrchestrator.last_config.auth.cookies == ["from=cli"]  # type: ignore[attr-defined]


def test_a_malformed_cookie_is_a_clean_error() -> None:
    result = runner.invoke(app_mod.app, ["scan", "https://example.com", "--cookie", "nope"])
    assert result.exit_code != 0
    assert "invalid cookie" in result.stderr
    assert "Traceback" not in result.stderr


def test_list_checks_lists_the_csrf_check() -> None:
    result = runner.invoke(app_mod.app, ["list-checks"])
    assert "csrf.form.no-token" in result.stdout
    assert "CSRF" in result.stdout


def test_summary_reports_the_authenticated_scan_and_csrf_count() -> None:
    _StubOrchestrator.result = make_result(
        make_finding(check_id="csrf.form.no-token", severity=Severity.MEDIUM),
    )
    result = runner.invoke(app_mod.app, ["scan", "https://example.com", "--cookie", "session=abc"])
    assert "Authenticated scan: 1 cookie supplied" in result.stderr
    assert "CSRF: 1 form without an anti-CSRF token" in result.stderr


def test_version_warns_when_the_advisory_database_is_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        app_mod, "staleness_warning", lambda _rules: ["advisory data is 200 days old"]
    )
    result = runner.invoke(app_mod.app, ["version"])
    assert result.exit_code == 0
    assert "webvigil" in result.stdout
    assert "advisory data is 200 days old" in result.stderr


def test_version_is_quiet_when_the_database_is_fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_mod, "staleness_warning", lambda _rules: [])
    result = runner.invoke(app_mod.app, ["version"])
    assert "warning:" not in result.stderr


@pytest.mark.parametrize("fmt", ["json", "sarif", "html", "md"])
def test_report_re_renders_offline(tmp_path: Path, fmt: str) -> None:
    scan_json = tmp_path / "scan.json"
    scan_json.write_text(make_result(make_finding()).model_dump_json(), "utf-8")
    result = runner.invoke(app_mod.app, ["report", str(scan_json), "--format", fmt])
    assert result.exit_code == 0
    assert result.stdout.strip()
