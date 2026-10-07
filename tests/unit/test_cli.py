"""
CLI: output routing, exit codes, active-mode gate, offline re-render — RF-24, RF-25, RF-15.

The autouse ``_stub_orchestrator`` fixture swaps :class:`Orchestrator` for a stub
that returns a canned :class:`ScanResult` and records the config it was built
with, so the tests drive the real Typer app (via ``CliRunner``) and assert on
exit codes, the stdout/stderr split, the summary lines, and
``_StubOrchestrator.last_config`` — without running a scan. The ``report`` tests
re-render a real result file offline.

Audited under issue #101: the per-spec ``list-checks`` tests became one registry-driven test, the
per-flag "overrides the config file" tests one table, and the per-pass "writes to the target"
summary notes one table; every assertion they made is still made.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.support import make_finding, make_result
from webvigil.checks.registry import all_checks, load_plugins
from webvigil.cli import app as app_mod
from webvigil.cli._exit import ExitCode
from webvigil.core.findings import ScanMode, Severity
from webvigil.core.result import ScanResult
from webvigil.core.technology import DetectionMethod, Technology

runner = CliRunner()
_SCAN = ["scan", "https://example.com"]
_ACTIVE = [*_SCAN, "--mode", "active", "--authorized-by", "me"]


class _StubOrchestrator:
    """A stand-in orchestrator: ``run`` returns the class-level ``result`` and the
    config it was constructed with is recorded on ``last_config`` for assertions."""

    result: ScanResult = make_result(make_finding(check_id="http.headers.csp"))
    last_config: object = None

    def __init__(self, config: object) -> None:
        self.config = config
        type(self).last_config = config

    async def run(self, url: str) -> ScanResult:
        return type(self).result


@pytest.fixture(autouse=True)
def _stub_orchestrator(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap the CLI's ``Orchestrator`` for :class:`_StubOrchestrator` and reset its result."""
    _StubOrchestrator.result = make_result(make_finding(check_id="http.headers.csp"))
    monkeypatch.setattr(app_mod, "Orchestrator", _StubOrchestrator)


def _config() -> object:
    """
    Returns:
        object: The config the last CLI invocation handed to the stub orchestrator.
    """
    return _StubOrchestrator.last_config


# ---------------------------------------------------------------------------
# Output routing and exit codes
# ---------------------------------------------------------------------------


def test_no_format_prints_summary_to_stderr_only() -> None:
    """With no ``--format`` the summary goes to stderr and stdout stays empty."""
    result = runner.invoke(app_mod.app, _SCAN)
    assert result.exit_code == ExitCode.OK
    assert result.stdout == ""
    assert "WebVigil" in result.stderr


def test_format_json_goes_to_stdout() -> None:
    """``--format json`` writes valid JSON to stdout and keeps the summary on stderr."""
    result = runner.invoke(app_mod.app, [*_SCAN, "--format", "json"])
    assert result.exit_code == ExitCode.OK
    json.loads(result.stdout)  # valid JSON on stdout
    assert "WebVigil" in result.stderr


def test_output_file_leaves_stdout_empty(tmp_path: Path) -> None:
    """``--output`` writes the report to the file and leaves stdout empty."""
    target = tmp_path / "r.sarif"
    result = runner.invoke(app_mod.app, [*_SCAN, "--format", "sarif", "--output", str(target)])
    assert result.exit_code == ExitCode.OK
    assert result.stdout == ""
    assert target.read_text("utf-8").strip().startswith("{")


def test_fail_on_controls_the_exit_code() -> None:
    """``--fail-on high`` exits FINDINGS on a HIGH finding; ``--fail-on none`` exits OK."""
    _StubOrchestrator.result = make_result(
        make_finding(check_id="tls.https", severity=Severity.HIGH)
    )
    assert runner.invoke(app_mod.app, [*_SCAN, "--fail-on", "high"]).exit_code == ExitCode.FINDINGS
    assert runner.invoke(app_mod.app, [*_SCAN, "--fail-on", "none"]).exit_code == ExitCode.OK


def test_unknown_format_is_a_usage_error() -> None:
    """An unknown ``--format`` is a USAGE error, not a crash."""
    result = runner.invoke(app_mod.app, [*_SCAN, "--format", "pdf"])
    assert result.exit_code == ExitCode.USAGE


# ---------------------------------------------------------------------------
# The Active-mode gate
# ---------------------------------------------------------------------------


def test_active_mode_without_authorization_in_non_tty_is_rejected() -> None:
    """``--mode active`` with no ``--authorized-by`` in a non-TTY is NOT_AUTHORIZED."""
    result = runner.invoke(app_mod.app, [*_SCAN, "--mode", "active"])
    assert result.exit_code == ExitCode.NOT_AUTHORIZED
    assert "authorized-by" in result.stderr.lower()


def test_active_mode_with_authorization_runs_and_shows_banner() -> None:
    """``--mode active --authorized-by`` runs and prints the Active Mode banner."""
    result = runner.invoke(
        app_mod.app, [*_SCAN, "--mode", "active", "--authorized-by", "Jane / #9"]
    )
    assert result.exit_code == ExitCode.OK
    assert "Active Mode" in result.stderr


# ---------------------------------------------------------------------------
# list-checks
# ---------------------------------------------------------------------------


def test_list_checks_prints_every_registered_check() -> None:
    """``list-checks`` names every registered check, every category and every severity in use."""
    load_plugins()
    checks = list(all_checks())
    # a wide terminal: the longest ids would wrap at the default width of 80 columns
    result = runner.invoke(app_mod.app, ["list-checks"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    assert checks
    missing = [check.id for check in checks if check.id not in result.stdout]
    assert not missing, missing
    for category in {check.category.value for check in checks}:
        assert category in result.stdout, category
    for severity in {check.default_severity.name for check in checks}:
        assert severity in result.stdout, severity
    assert {"active", "passive"} <= {check.mode.value for check in checks}


# ---------------------------------------------------------------------------
# Flags that override the config file
# ---------------------------------------------------------------------------

# (flag, TOML that sets the opposite value, the config attribute path, the value the flag gives)
_FLAG_CASES = [
    ("--probe", "", "disclosure.probe", True),
    ("--no-probe", "[disclosure]\nprobe = true\n", "disclosure.probe", False),
    (
        "--no-time-based-sqli",
        "[injection]\ntime_based_sqli = true\n",
        "injection.time_based_sqli",
        False,
    ),
    (
        "--no-time-based-cmdi",
        "[injection]\ntime_based_cmdi = true\n",
        "injection.time_based_cmdi",
        False,
    ),
    ("--xxe", "[injection]\nxxe = false\n", "injection.xxe", True),
    ("--file-upload", "[injection]\nfile_upload = false\n", "injection.file_upload", True),
    ("--stored-xss", "[injection]\nstored_xss = false\n", "injection.stored_xss", True),
    ("--no-stored-xss", "[injection]\nstored_xss = true\n", "injection.stored_xss", False),
    ("--osv-online", "[deps]\nosv_online = false\n", "deps.osv_online", True),
    ("--no-osv-online", "[deps]\nosv_online = true\n", "deps.osv_online", False),
    ("--confirm-csrf", "[injection]\ncsrf_confirm = false\n", "injection.csrf_confirm", True),
    ("--no-confirm-csrf", "[injection]\ncsrf_confirm = true\n", "injection.csrf_confirm", False),
    ("--submit-post-forms", "[scan]\nsubmit_post_forms = false\n", "scan.submit_post_forms", True),
    (
        "--no-submit-post-forms",
        "[scan]\nsubmit_post_forms = true\n",
        "scan.submit_post_forms",
        False,
    ),
]


def test_flags_override_the_config_file(tmp_path: Path) -> None:
    """Each switch flag wins over the value a config file gives it (both ways when it has two)."""
    cfg = tmp_path / "webvigil.toml"
    for flag, toml, path, expected in _FLAG_CASES:
        cfg.write_text(toml, "utf-8")
        args = [*_SCAN, "--config", str(cfg), flag]
        result = runner.invoke(app_mod.app, args)
        value = _config()
        for part in path.split("."):
            value = getattr(value, part)
        assert value is expected, f"{flag}: {path} is {value!r}, expected {expected!r}"
        if flag == "--probe":
            assert result.exit_code == 0  # GET-only: it does not trip the Active-mode gate


# ---------------------------------------------------------------------------
# The scan summary lines
# ---------------------------------------------------------------------------


def _tech(version: str, method: DetectionMethod) -> Technology:
    """
    Args:
        version (str): The detected jQuery version.
        method (DetectionMethod): How it was detected.

    Returns:
        Technology: A vulnerable jQuery detection.
    """
    return Technology(
        name="jquery",
        version=version,
        detection=method,
        source_url="https://example.com/j.js",
        vulnerable=True,
    )


def test_scan_summary_reports_detected_libraries_and_the_advisory_source() -> None:
    """The summary counts the libraries and names OSV.dev as a source only with ``--osv-online``."""
    _StubOrchestrator.result = make_result(
        make_finding(check_id="deps.js.vulnerable-library"),
        technologies=(_tech("1.12.4", DetectionMethod.FILENAME),),
    )
    with_osv = runner.invoke(app_mod.app, [*_SCAN, "--osv-online"])
    assert "Detected 1 client-side library (1 with known vulnerabilities)" in with_osv.stderr
    assert "Advisory sources: offline database + OSV.dev" in with_osv.stderr
    without = runner.invoke(app_mod.app, _SCAN)
    assert "Detected 1 client-side library" in without.stderr
    assert "OSV.dev" not in without.stderr


def test_scan_summary_counts_exposed_paths_injection_and_csrf_findings() -> None:
    """The summary counts exposed paths, active injection findings and token-less CSRF forms."""
    _StubOrchestrator.result = make_result(
        make_finding(check_id="disclosure.vcs.exposed", severity=Severity.HIGH),
        make_finding(check_id="disclosure.debug.error-page", severity=Severity.MEDIUM),
        make_finding(check_id="injection.xss.reflected", severity=Severity.HIGH),
        make_finding(check_id="injection.sqli.error-based", severity=Severity.HIGH),
        make_finding(check_id="csrf.form.no-token", severity=Severity.MEDIUM),
        mode=ScanMode.ACTIVE,
    )
    result = runner.invoke(app_mod.app, _ACTIVE)
    assert "Information disclosure: 1 exposed path found" in result.stderr
    assert "Active injection: 2 findings" in result.stderr
    assert "CSRF: 1 form without an anti-CSRF token" in result.stderr


# (flag, a finding id, the summary line the flag adds)
_WRITE_NOTES = [
    ("--file-upload", "upload.unrestricted", "File-upload testing: enabled"),
    ("--confirm-csrf", "csrf.form.token-not-enforced", "CSRF confirmation: enabled"),
    ("--submit-post-forms", "injection.xss.reflected", "POST crawl: enabled"),
]


def test_write_pass_notes_appear_only_with_their_flag_in_active_mode() -> None:
    """A pass that writes to the target says so in the summary only when its flag is set."""
    for flag, check_id, note in _WRITE_NOTES:
        _StubOrchestrator.result = make_result(
            make_finding(check_id=check_id, severity=Severity.MEDIUM), mode=ScanMode.ACTIVE
        )
        assert note in runner.invoke(app_mod.app, [*_ACTIVE, flag]).stderr, flag
        assert note not in runner.invoke(app_mod.app, _ACTIVE).stderr, flag
    # the confirmed-CSRF line needs a confirming finding, not the flag
    _StubOrchestrator.result = make_result(
        make_finding(check_id="csrf.form.token-not-enforced", severity=Severity.MEDIUM),
        mode=ScanMode.ACTIVE,
    )
    assert "CSRF confirmed: 1 form accepted" in runner.invoke(app_mod.app, _ACTIVE).stderr


# ---------------------------------------------------------------------------
# --cookie / --header and the authenticated-scan summary (specs 007, 013)
# ---------------------------------------------------------------------------


def test_cookie_and_header_flags_populate_and_replace_the_auth_config(tmp_path: Path) -> None:
    """Repeated flags become the ``auth`` lists, and replace a config-file list entirely."""
    runner.invoke(
        app_mod.app,
        [
            *_SCAN,
            *["--cookie", "session=abc", "--cookie", "csrf=xyz"],
            *["--header", "Authorization: Bearer abc", "--header", "X-API-Key: k"],
        ],
    )
    assert _config().auth.cookies == ["session=abc", "csrf=xyz"]  # type: ignore[attr-defined]
    assert _config().auth.headers == [  # type: ignore[attr-defined]
        "Authorization: Bearer abc",
        "X-API-Key: k",
    ]
    cfg = tmp_path / "webvigil.toml"
    cfg.write_text("[auth]\ncookies = ['from=file']\nheaders = ['X-Old: 1']\n", "utf-8")
    runner.invoke(
        app_mod.app,
        [*_SCAN, "--config", str(cfg), "--cookie", "from=cli", "--header", "X-New: 2"],
    )
    assert _config().auth.cookies == ["from=cli"]  # type: ignore[attr-defined]
    assert _config().auth.headers == ["X-New: 2"]  # type: ignore[attr-defined]


def test_a_malformed_cookie_or_header_is_a_clean_error() -> None:
    """A malformed ``--cookie`` / ``--header`` value is a clean message, not a traceback."""
    for flag, message in (("--cookie", "invalid cookie"), ("--header", "invalid header")):
        result = runner.invoke(app_mod.app, [*_SCAN, flag, "nope"])
        assert result.exit_code != 0, flag
        assert message in result.stderr, flag
        assert "Traceback" not in result.stderr, flag


def test_authenticated_summary_counts_cookies_and_headers_but_never_shows_them() -> None:
    """The authenticated-scan line reports counts only (cookies and ``[auth]`` headers)."""
    both = runner.invoke(
        app_mod.app,
        [*_SCAN, "--cookie", "session=abc", "--header", "Authorization: Bearer secret-xyz"],
    )
    assert "Authenticated scan: 1 cookie + 1 header supplied" in both.stderr
    assert "secret-xyz" not in both.stderr
    cookie_only = runner.invoke(app_mod.app, [*_SCAN, "--cookie", "session=abc"])
    assert "Authenticated scan: 1 cookie supplied" in cookie_only.stderr


# ---------------------------------------------------------------------------
# version staleness and offline report re-render
# ---------------------------------------------------------------------------


def test_version_warns_only_when_the_advisory_database_is_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``version`` prints a staleness warning to stderr when the advisory DB is old, else none."""
    monkeypatch.setattr(
        app_mod, "staleness_warning", lambda _rules: ["advisory data is 200 days old"]
    )
    stale = runner.invoke(app_mod.app, ["version"])
    assert stale.exit_code == 0
    assert "webvigil" in stale.stdout
    assert "advisory data is 200 days old" in stale.stderr
    monkeypatch.setattr(app_mod, "staleness_warning", lambda _rules: [])
    assert "warning:" not in runner.invoke(app_mod.app, ["version"]).stderr


def test_report_re_renders_offline_in_every_format(tmp_path: Path) -> None:
    """``report`` re-renders a saved scan JSON into any format without a network."""
    scan_json = tmp_path / "scan.json"
    scan_json.write_text(make_result(make_finding()).model_dump_json(), "utf-8")
    for fmt in ("json", "sarif", "html", "md"):
        result = runner.invoke(app_mod.app, ["report", str(scan_json), "--format", fmt])
        assert result.exit_code == 0, fmt
        assert result.stdout.strip(), fmt
