"""
The scan harness of spec 027 (RF-01 to RF-05, ADR-1, ADR-2): scans with their stages failing.

Each run invokes the real CLI against the fixture application, over ``httpx2.ASGITransport``, with
the static cookie, the bearer token and the login password as credential markers. The fault
transport fails the requests the plan of ``tests/failure/table.py`` picks, each with the kind the
plan gives its stage in that run. There are two kinds of run:

- **full runs**, one per kind: the integration scan's full configuration (Active Mode, the
  automated login, the session tests, the OpenAPI and HAR imports, the disclosure probe, upload,
  CSRF, stored XSS and the OSV lookup), with every pass the scan goes on after failing at once,
  each with a different kind, so over the runs every one of them gets every kind (ADR-1);
- **runs alone**, one per stage and kind, for the stages whose failure can end the scan (the
  login, the OpenAPI import, the target URL, the crawl) or take away what a later pass needs (the
  OSV lookup, which has nothing to ask when the fingerprint pass failed): only that stage fails,
  in a lighter configuration.

Each run then searches every output (the standard output and error, the JSON report and its three
re-renders, every log record): no credential in any spelling, no session value the fixture issued,
and a failure's text only where its kind may go (RF-03, RF-04). The positive controls (RF-05): the
credentials reached the fixture, every fault the transport applied holds its marker, and every
failing stage got its fault, of its kind.

The runs are kept, so the API harness checks the Web API on the same results without scanning
again (ADR-3).
"""

from __future__ import annotations

import functools
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Final

import httpx2
import pytest
from starlette.applications import Starlette
from typer.testing import CliRunner, Result

from tests.failure.faults import (
    Fault,
    FaultLog,
    FaultTransport,
    attributed,
    failing_osv,
    failing_read,
)
from tests.failure.outputs import (
    WIDE_TERMINAL,
    Outputs,
    bad_failure_hits,
    cli_outputs,
    credential_hits,
    every_log_record,
    failure_hits,
)
from tests.failure.table import (
    ALONE,
    DEPENDENCIES,
    SCAN_RUNS,
    STAGES,
    TARGET,
    TOGETHER,
    Kind,
    Stage,
    credential_marker,
    failure_marker,
    kind_for,
)
from tests.fixtures.app import CANARY_COOKIE, SIGNIN_USER, make_app
from tests.integration.test_scan_fixture_app import _osv_up
from tests.support import spellings
from webvigil.checks import registry
from webvigil.checks.base import Check
from webvigil.checks.deps import _data as deps_data
from webvigil.checks.deps import rules as deps_rules
from webvigil.checks.deps.osv import OsvProvider
from webvigil.checks.disclosure import catalogue
from webvigil.cli import app as app_mod
from webvigil.cli._exit import ExitCode
from webvigil.core import orchestrator as orch_mod
from webvigil.core import suffixes
from webvigil.core.context import ScanContext
from webvigil.core.findings import (
    Category,
    Confidence,
    EvidenceItem,
    Finding,
    Location,
    Severity,
    compute_fingerprint,
)
from webvigil.core.result import ScanResult
from webvigil.http import client as client_mod
from webvigil.http.client import HttpClient
from webvigil.reporting import load_result

runner = CliRunner()

# ---------------------------------------------------------------------------
# The configuration of the runs
# ---------------------------------------------------------------------------


# The three credentials, as markers: each value appears nowhere else, so a match names it.
COOKIE: Final = credential_marker("cookie")
BEARER: Final = credential_marker("bearer")
PASSWORD: Final = credential_marker("password")
CREDENTIALS: Final = (COOKIE, BEARER, PASSWORD)
# The login reads its password from this variable, as a user's scan does: never from the file.
_PASSWORD_ENV: Final = "WV_FAILURE_SUITE_PASSWORD"
# The OpenAPI document is fetched from the fixture, so the import's stage has a request to fail.
_OPENAPI_URL: Final = f"{TARGET}openapi.json"
# The OSV.dev stub's address: the lookup never leaves the process.
_OSV_URL: Final = "http://osv.test"
# What the throwaway check of the ``checks`` stage requests, and its id.
_ECHO_URL: Final = f"{TARGET}failure-suite-echo"
_ECHO_ID: Final = "failure-suite.echo"
# The exit codes the documentation gives for a scan that ends, well or not (docs/stability.md);
# ``1``, an unexpected error, only for a failure that is one.
_DOCUMENTED_EXITS: Final = frozenset({ExitCode.OK, ExitCode.FINDINGS, ExitCode.OPERATIONAL})
_UNEXPECTED: Final = re.compile(r"error: the scan stopped on an unexpected error \((\w+)\)$")

# How each pass of a full run starts the line that names a ``RuntimeError`` its first request
# raised; the line names the type.
_RAISED_SAYS: Final = {
    "fingerprint": "dependency fingerprint pass failed: RuntimeError",
    "probe": "disclosure probe pass failed: RuntimeError",
    "injection": "active injection pass failed: RuntimeError",
    "stored-xss": "stored-XSS pass failed: RuntimeError",
    "envelope": "request-envelope pass failed: RuntimeError",
    "upload": "file-upload pass failed: RuntimeError",
    "csrf": "CSRF confirmation pass failed: RuntimeError",
    "session": "session checks: the ",  # each step of the pass fails on its own
    "checks": f"{_ECHO_ID}: ",
}

# The integration scan's full configuration (tests/integration/test_scan_fixture_app.py), with
# the disclosure probe on so its stage has requests to fail. The TLS check is off: the fixture is
# plain HTTP, and its socket is covered by the socket-based unit tests.
_FULL: Final = """\
[scan]
mode = "active"
max_pages = 90
submit_post_forms = true
openapi = "{openapi}"
har = "{har}"

[active]
authorized_by = "failure-injection suite"

[checks]
disabled = ["tls.https"]

[disclosure]
probe = true

[injection]
stored_xss = true
xxe = true
file_upload = true
csrf_confirm = true
time_based_sqli = false
time_based_cmdi = false
request_budget = 2400
envelope_url_sample = 30
envelope_budget = 180

[auth]
cookies = ["{cookie}"]
headers = ["Authorization: Bearer {bearer}"]

[auth.login]
url = "{target}signin"
username = "{username}"
password_env = "{password_env}"
max_relogins = 10

[session]
sample_ids = true
test_logout = true

[deps]
osv_online = true
osv_base_url = "{osv}"
"""

# The runs alone and the runs of a file: the stages they fail come before the passes, or are
# one pass, so the opt-ins are off and the crawl and the injection are short. The login still
# needs Active Mode.
_LIGHT: Final = """\
[scan]
mode = "active"
max_pages = 3
scope = "{scope}"
openapi = "{openapi}"
har = "{har}"

[active]
authorized_by = "failure-injection suite"

[checks]
disabled = ["tls.https"]

[disclosure]
probe = {probe}

[injection]
time_based_sqli = false
time_based_cmdi = false
request_budget = 40
envelope_budget = 10

[auth]
cookies = ["{cookie}"]
headers = ["Authorization: Bearer {bearer}"]

[auth.login]
url = "{target}signin"
username = "{username}"
password_env = "{password_env}"

[deps]
osv_online = true
osv_base_url = "{osv}"
"""


# ---------------------------------------------------------------------------
# The check of the checks stage
# ---------------------------------------------------------------------------


class _EchoCheck(Check):
    """
    A check that sends one request and quotes the answer, for the ``checks`` stage: the one check
    that sends requests, ``tls.https``, is off against the plain-HTTP fixture.
    """

    id = _ECHO_ID
    name = "failure-suite echo"
    category = Category.HEADERS
    default_severity = Severity.INFO

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): The scan's context; its client sends the request.

        Returns:
            list[Finding]: One finding that quotes the answer's body as evidence.
        """
        response = await ctx.http.get(_ECHO_URL)
        location = Location(url=_ECHO_URL)
        return [
            Finding(
                check_id=self.id,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="The echo answered",
                description="The failure-injection suite's stand-in for a check on the network.",
                location=location,
                remediation="None.",
                evidence=(EvidenceItem.of("body", response.text),),
                fingerprint=compute_fingerprint(self.id, location, "echo"),
            )
        ]


# ---------------------------------------------------------------------------
# A run, and its assertions
# ---------------------------------------------------------------------------


@dataclass
class ScanRun:
    """
    One run of the scan harness.

    Attributes:
        run (int): The run number, which gives each failing stage its kind.
        failing (frozenset[str]): The stages whose requests failed.
        seam (Fault | None): The file the run failed to read, if any.
        result (Result): What the CLI did.
        outputs (Outputs): Everything it showed or wrote.
        log (FaultLog): The faults the plan applied.
        app (Starlette): The fixture, whose ``state`` records what it received.
        scan (ScanResult | None): The JSON report, read back, when one was written.
    """

    run: int
    failing: frozenset[str]
    seam: Fault | None
    result: Result
    outputs: Outputs
    log: FaultLog
    app: Starlette
    scan: ScanResult | None


# The runs, by name, kept for the API harness (ADR-3).
RUNS: dict[str, ScanRun] = {}


def _har(path: Path) -> Path:
    """
    Args:
        path (Path): Where to write the recording.

    Returns:
        Path: A HAR with a GET route and a JSON POST route no page links to.
    """
    entries = [
        {
            "_resourceType": "xhr",
            "request": {"method": "GET", "url": f"{TARGET}spa/items?name=widget", "headers": []},
            "response": {"status": 200},
        },
        {
            "_resourceType": "xhr",
            "request": {
                "method": "POST",
                "url": f"{TARGET}spa/notes",
                "headers": [],
                "postData": {"mimeType": "application/json", "text": '{"text": "note"}'},
            },
            "response": {"status": 200},
        },
    ]
    path.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}), "utf-8")
    return path


def scan_run(
    name: str,
    run: int,
    failing: Iterable[Stage],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    light: bool = False,
    probe: bool = False,
    scope: str = "host",
    seam: Callable[[pytest.MonkeyPatch], Fault] | None = None,
) -> ScanRun:
    """
    Run a scan with the plan of one run, once per test session.

    Args:
        name (str): The run's name, which keeps it for the session.
        run (int): The run number, from 0.
        failing (Iterable[Stage]): The stages whose requests fail.
        monkeypatch (pytest.MonkeyPatch): The caller's patcher.
        tmp_path (Path): A directory for the configuration, the recording and the report.
        light (bool): Whether to scan with the light configuration. Defaults to the full one.
        probe (bool): Whether the light configuration probes for exposed paths. Defaults to
            ``False``.
        scope (str): The light configuration's scope. Defaults to ``"host"``.
        seam (Callable[[pytest.MonkeyPatch], Fault] | None): Fails one more dependency, a file,
            for the whole run. Defaults to none.

    Returns:
        ScanRun: The run.
    """
    if name in RUNS:
        return RUNS[name]
    names = frozenset(row.name for row in failing)
    # the client still retries a failed request; only the wait between attempts is dropped
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)
    monkeypatch.setitem(registry._REGISTRY, _EchoCheck.id, _EchoCheck)
    app = make_app("insecure", password=PASSWORD)
    log = FaultLog()
    transport = FaultTransport(httpx2.ASGITransport(app=app), run, log, names)
    monkeypatch.setattr(orch_mod, "HttpClient", functools.partial(HttpClient, transport=transport))
    osv = failing_osv(httpx2.MockTransport(_osv_up), run, log, names)
    monkeypatch.setattr(orch_mod, "OsvProvider", functools.partial(OsvProvider, transport=osv))
    config = tmp_path / "webvigil.toml"
    config.write_text(
        (_LIGHT if light else _FULL).format(
            openapi=_OPENAPI_URL,
            har=_har(tmp_path / "traffic.har").as_posix(),
            cookie=f"{CANARY_COOKIE}={COOKIE}",
            bearer=BEARER,
            target=TARGET,
            username=SIGNIN_USER,
            password_env=_PASSWORD_ENV,
            osv=_OSV_URL,
            probe=str(probe).lower(),
            scope=scope,
        ),
        "utf-8",
    )
    report = tmp_path / "report.json"
    args = ["scan", TARGET, "--config", str(config), "--format", "json", "--output", str(report)]
    env = {**WIDE_TERMINAL, _PASSWORD_ENV: PASSWORD}
    fault = seam(monkeypatch) if seam is not None else None
    with every_log_record() as records, attributed():
        result = runner.invoke(app_mod.app, args, env=env)
    if seam is not None:
        monkeypatch.undo()  # the file reads again, for the report and its re-renders
    outputs = cli_outputs(runner, result, report, records)
    scan = load_result(report) if report.is_file() else None
    RUNS[name] = ScanRun(run, names, fault, result, outputs, log, app, scan)
    return RUNS[name]


def _session_hits(outputs: Outputs, values: Iterable[str]) -> list[tuple[str, str]]:
    """
    Args:
        outputs (Outputs): A run's outputs.
        values (Iterable[str]): The session values the fixture issued.

    Returns:
        list[tuple[str, str]]: Each output that holds one as a whole token, in any spelling. The
            insecure profile's ids count up (``100001``), so they can turn up inside a random hex
            value of another check; a real leak shows the value on its own.
    """
    return [
        (name, value)
        for value in values
        for form in spellings(value)
        for name, text in outputs.texts.items()
        if re.search(rf"(?<![0-9A-Za-z]){re.escape(form)}(?![0-9A-Za-z])", text)
    ]


def _error_lines(result: Result) -> list[str]:
    """
    Args:
        result (Result): A CLI run.

    Returns:
        list[str]: Its ``error:`` lines.
    """
    return [line for line in result.stderr.splitlines() if line.startswith("error:")]


def _check(outcome: ScanRun, kinds: dict[str, Kind]) -> None:
    """
    The assertions every run of the harness makes, with their positive controls.

    Args:
        outcome (ScanRun): The run.
        kinds (dict[str, Kind]): Each failing stage, with its kind in the run.
    """
    result, log, app = outcome.result, outcome.log, outcome.app

    # the run ended as documented: an exit code of the CLI, no traceback; a scan that stopped
    # says why in one line, and one that finished wrote its report
    exits = set(_DOCUMENTED_EXITS)
    if Kind.RAISES in kinds.values() or outcome.seam is not None:
        exits.add(ExitCode.INTERNAL)  # a failure where nothing expects one is unexpected
    assert result.exit_code in exits, (result.exit_code, result.exception, result.stderr)
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert "Traceback" not in result.stderr
    if result.exit_code in {ExitCode.OPERATIONAL, ExitCode.INTERNAL} and outcome.scan is None:
        assert len(_error_lines(result)) == 1, result.stderr
    else:
        assert outcome.scan is not None, result.stderr
    # an unexpected error, and only one, ends with ``1`` and a line that names its type
    unexpected = [line for line in _error_lines(result) if _UNEXPECTED.match(line)]
    assert (result.exit_code == ExitCode.INTERNAL) == bool(unexpected), result.stderr

    # the positive controls of the failures (RF-05): each fault holds its marker, and every
    # failing stage got one, of its kind for this run
    for fault in log.applied:
        raised = Outputs()
        raised.add("raised", fault.text)
        assert failure_hits(raised, {fault.marker: fault.kind}), fault
    assert log.stages() == set(kinds), sorted(set(kinds) ^ log.stages())
    for name, kind in kinds.items():
        assert log.kinds(name) == {kind}, (name, log.kinds(name))
    markers = {fault.marker: fault.kind for fault in log.applied}
    if outcome.seam is not None:
        assert outcome.seam.raised, "the file was never read: the run did not reach its stage"
        assert all(outcome.seam.marker in str(exc) for exc in outcome.seam.raised)
        markers[outcome.seam.marker] = Kind.FILE_READ

    # the searches (RF-03, RF-04)
    issued = set(app.state.sessions) | app.state.expired
    assert credential_hits(outcome.outputs, CREDENTIALS) == []
    assert _session_hits(outcome.outputs, issued) == []
    assert bad_failure_hits(outcome.outputs, markers) == []

    # the positive controls of the credentials (RF-05): the configured ones reached the fixture
    # whenever a request did
    if app.state.requests:
        assert (f"Bearer {BEARER}", COOKIE) in app.state.auth_log
        wire = Outputs()
        wire.add("wire", repr(app.state.auth_log))
        assert {hit.marker for hit in credential_hits(wire, (COOKIE, BEARER))} == {COOKIE, BEARER}


# ---------------------------------------------------------------------------
# The full runs and the runs alone
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("run", range(SCAN_RUNS))
def test_a_full_scan_with_its_passes_failing_ends_as_documented(
    run: int, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    Every pass the scan goes on after fails, each with its kind of this run. The scan finishes and
    writes its report; each pass's failure is a warning or a check error, and a pass that raised
    says so by type. Nothing else changes: the login confirmed, every credential was sent.
    """
    outcome = scan_run(f"full-{run}", run, TOGETHER, monkeypatch, tmp_path)
    kinds = {row.name: kind_for(run, row) for row in TOGETHER}
    _check(outcome, kinds)
    scan = outcome.scan
    assert scan is not None
    assert outcome.result.exit_code in _DOCUMENTED_EXITS

    # the positive controls of the password and the session: the login worked with the marker
    assert "ok" in outcome.app.state.login_log
    assert scan.metadata.login is not None and scan.metadata.login.confirmed
    assert set(outcome.app.state.sessions) | outcome.app.state.expired

    # the positive control of RF-04 where a failure's text may go: the run that answers the echo
    # with a server error quotes its body in the report, cut and with its controls shown
    if kinds["checks"] is Kind.SERVER_ERROR:
        marker = failure_marker("checks", Kind.SERVER_ERROR)
        quoted = failure_hits(outcome.outputs, {marker: Kind.SERVER_ERROR})
        assert "report:json" in {hit.output for hit in quoted}
        assert all(hit.allowed and not hit.problems for hit in quoted), quoted

    # each pass whose RAISES fault ran says so, by type only
    said = [*scan.warnings, *(f"{error.check_id}: {error.message}" for error in scan.errors)]
    for name, kind in kinds.items():
        if kind is Kind.RAISES:
            says = [line for line in said if line.startswith(_RAISED_SAYS[name])]
            assert any("RuntimeError" in line for line in says), (name, said)


@pytest.mark.parametrize("run", range(SCAN_RUNS))
@pytest.mark.parametrize("row", ALONE, ids=lambda row: row.name)
def test_a_stage_failing_alone_ends_the_scan_as_documented(
    row: Stage, run: int, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    Only this stage fails, with its kind of this run. The scan either goes on, with a warning
    where the stage keeps one, or ends with one error line in the project's words.
    """
    outcome = scan_run(f"{row.name}-{run}", run, (row,), monkeypatch, tmp_path, light=True)
    _check(outcome, {row.name: kind_for(run, row)})


# ---------------------------------------------------------------------------
# A vendored file that cannot be read
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Vendored:
    """
    A data file the engine ships and reads during a scan.

    Attributes:
        key (str): Its read's key in :data:`~tests.failure.table.DEPENDENCIES`.
        package (str): The package that holds it.
        file (str): Its name.
        caches (tuple[Callable[[], None], ...]): The ``cache_clear`` of every cache in front of
            the read, so the run reads it.
        primed (tuple[Callable[[], object], ...]): Reads of the same file that must succeed
            first, so the run fails the one under test.
        probe (bool): Whether the run probes for exposed paths.
        scope (str): The run's scope.
        says (str): How the scan says it: the start of a warning, or of the one error line.
    """

    key: str
    package: str
    file: str
    caches: tuple[Callable[[], None], ...]
    primed: tuple[Callable[[], object], ...] = ()
    probe: bool = False
    scope: str = "host"
    says: str = ""


_VENDORED: Final = (
    _Vendored(
        "webvigil.checks.deps._data:load_raw_db file .read_text",
        "webvigil.checks.deps.data",
        "retirejs.json",
        (deps_data.load_raw_db.cache_clear, deps_rules._load_cached.cache_clear),
        says="dependency fingerprint pass failed: OSError",
    ),
    _Vendored(
        "webvigil.checks.deps._data:load_provenance file .read_text",
        "webvigil.checks.deps.data",
        "PROVENANCE.json",
        (deps_data.load_provenance.cache_clear, deps_rules._load_cached.cache_clear),
        says="dependency fingerprint pass failed: OSError",
    ),
    _Vendored(
        "webvigil.checks.disclosure.catalogue:load_catalogue file .read_text",
        "webvigil.checks.disclosure.data",
        "paths.toml",
        (catalogue.load_catalogue.cache_clear, catalogue.backup_spec.cache_clear),
        probe=True,
        says="disclosure probe pass failed: OSError",
    ),
    _Vendored(
        "webvigil.checks.disclosure.catalogue:backup_spec file .read_text",
        "webvigil.checks.disclosure.data",
        "paths.toml",
        (catalogue.backup_spec.cache_clear,),
        primed=(catalogue.load_catalogue,),
        probe=True,
        says="disclosure probe pass failed: OSError",
    ),
    _Vendored(
        "webvigil.core.suffixes:load_rules file .read_text",
        "webvigil.core.data",
        "public_suffix_list.dat",
        (suffixes.load_rules.cache_clear,),
        scope="subdomains",
        says="error: the scan stopped on an unexpected error (OSError)",
    ),
)


def test_every_vendored_file_of_a_scan_stage_has_a_run() -> None:
    """Each file read :data:`DEPENDENCIES` gives a scan stage is one of the runs below."""
    scan_stages = {row.name for row in STAGES if row.harness == "scan"}
    files = {key for key, name in DEPENDENCIES.items() if " file " in key and name in scan_stages}
    assert files  # the positive control: the table gives the scan stages files
    assert {vendored.key for vendored in _VENDORED} == files


@pytest.mark.parametrize("vendored", _VENDORED, ids=lambda vendored: vendored.key.split(" ")[0])
def test_a_vendored_file_that_cannot_be_read_ends_as_documented(
    vendored: _Vendored, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    Reading a data file the engine ships raises ``OSError``. A pass that needs it says so in its
    own warning, by type, and the scan finishes; the scope's list ends the scan in one error line.
    """
    path = Path(str(resources.files(vendored.package).joinpath(vendored.file)))
    marker = failure_marker(DEPENDENCIES[vendored.key], Kind.FILE_READ)

    def _seam(patcher: pytest.MonkeyPatch) -> Fault:
        for clear in vendored.caches:
            clear()
        for read in vendored.primed:
            read()
        return failing_read(patcher, path, marker)

    try:
        outcome = scan_run(
            f"file-{vendored.key}",
            0,
            (),
            monkeypatch,
            tmp_path,
            light=True,
            probe=vendored.probe,
            scope=vendored.scope,
            seam=_seam,
        )
    finally:
        for clear in vendored.caches:
            clear()  # the next scan reads the real file
    _check(outcome, {})
    said = [*_error_lines(outcome.result)]
    if outcome.scan is not None:
        said += outcome.scan.warnings
    assert any(line.startswith(vendored.says) for line in said), said
