"""
The API harness of spec 027 (RF-02 to RF-05, ADR-3): the Web API storing and serving failed scans.

The Web API never scans again what the scan harness scanned. Each full run of the scan harness
gives its result to a stand-in orchestrator, and the real app, with its real ``ScanRunner``,
stores and serves it: a scan created through ``POST /api/scans``, then the scan, findings,
check-count, list and report routes read, every row of every table dumped and the server log kept.
The API's own failures are injected where they happen: the engine raising an error nothing expects
and one it names, the write of the result and the claim of a queued scan failing in the database,
and the name of a trusted proxy that does not resolve.

The Web API takes no credential for a scan (a target with one is refused), so its credential
markers are the account's password, the signing key of its sessions and the session token the login
issued, besides the scan harness's three, which came in the result. Each run searches every output:
no credential in any spelling, and a failure's text only where its kind may go (RF-03, RF-04). The
positive controls (RF-05): the password and the signing key were used, every fault fired with its
marker, and every failure text the CLI's report quoted reached the API's outputs too.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import jwt
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from tests.failure.faults import (
    Fault,
    failing_claim,
    failing_store,
    raising_orchestrator,
)
from tests.failure.outputs import (
    LogLines,
    Outputs,
    api_outputs,
    bad_failure_hits,
    credential_hits,
    every_log_record,
    failure_hits,
    family,
)
from tests.failure.table import (
    SCAN_RUNS,
    TARGET,
    TOGETHER,
    Kind,
    credential_marker,
    failure_marker,
    failure_text,
)
from tests.failure.test_scan import CREDENTIALS, _session_hits, scan_run
from webvigil.api import client_address as client_address_mod
from webvigil.api import security
from webvigil.api.app import create_app
from webvigil.api.client_address import client_address
from webvigil.api.config import WebConfig
from webvigil.api.db import ScanStatus, make_engine, run_alembic_upgrade
from webvigil.api.runner import INTERNAL_ERROR, OrchestratorFactory
from webvigil.core import ScanConfig, ScanResult, WebVigilError

# The Web API's own credentials, as markers. The signing key is long enough for HS256.
_PASSWORD: Final = credential_marker("account-password")
_SIGNING_KEY: Final = credential_marker("session-signing-key")
_ACCOUNT: Final = {"username": "admin", "password": _PASSWORD}

# The trusted proxy the app names, and the addresses of a request through it.
_PROXY_NAME: Final = "proxy.test"
_PEER: Final = "10.1.2.3"
_FORWARDED: Final = "203.0.113.9"

# The statuses a scan ends in, as the API spells them.
_ENDED: Final = frozenset(
    {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED, ScanStatus.INTERRUPTED}
)
# How long a scan the runner holds may take to end: a stand-in returns at once.
_DEADLINE_S: Final = 10.0


# ---------------------------------------------------------------------------
# The app, and one scan through it
# ---------------------------------------------------------------------------


class _Returning:
    """A stand-in orchestrator that returns a scan harness's result."""

    result: ScanResult

    def __init__(self, _config: ScanConfig) -> None: ...

    async def run(self, _raw_target: str) -> ScanResult:
        """
        Args:
            _raw_target (str): The scan target.

        Returns:
            ScanResult: The result the test set on the class.
        """
        return type(self).result


def _returning(result: ScanResult) -> OrchestratorFactory:
    """
    Args:
        result (ScanResult): What every scan returns.

    Returns:
        OrchestratorFactory: A stand-in orchestrator class that returns it.
    """
    return type("_ReturningOne", (_Returning,), {"result": result})


@dataclass
class _Api:
    """
    One app of the Web API, logged in.

    Attributes:
        client (TestClient): The client, with the session cookie.
        engine (Engine): An engine over the app's database.
        logs (LogLines): Every record kept since the app started.
        session (str): The session token the login issued.
    """

    client: TestClient
    engine: Engine
    logs: LogLines
    session: str

    def scan(self) -> int:
        """
        Create an Active scan of the scan harness's target and wait for the runner to end it.

        Returns:
            int: The scan's id.
        """
        created = self.client.post(
            "/api/scans",
            json={"target": TARGET, "mode": "active", "authorized_by": "the failure suite"},
        )
        assert created.status_code == 201, created.text
        scan_id: int = created.json()["id"]
        deadline = time.monotonic() + _DEADLINE_S
        while time.monotonic() < deadline:
            if self.status(scan_id) in _ENDED:
                return scan_id
            time.sleep(0.01)
        raise AssertionError(f"scan {scan_id} did not end in {_DEADLINE_S} s")

    def status(self, scan_id: int) -> ScanStatus:
        """
        Args:
            scan_id (int): A scan.

        Returns:
            ScanStatus: Its status.
        """
        return ScanStatus(self.client.get(f"/api/scans/{scan_id}").json()["status"])

    def outputs(self, scan_id: int) -> Outputs:
        """
        Args:
            scan_id (int): A scan.

        Returns:
            Outputs: Every output of the scan, as :func:`~tests.failure.outputs.api_outputs`
                collects them.
        """
        return api_outputs(self.client, scan_id, self.engine, self.logs)


@contextmanager
def _api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, factory: OrchestratorFactory
) -> Iterator[_Api]:
    """
    Start an app over a fresh database, through first-run setup and logged in.

    The request comes from :data:`_PEER` and names :data:`_FORWARDED` as its client, so a lookup
    of the trusted proxy's name runs on the login.

    Args:
        tmp_path (Path): A directory for the database.
        monkeypatch (pytest.MonkeyPatch): The test's patcher.
        factory (OrchestratorFactory): What runs each scan.

    Yields:
        _Api: The app, logged in.
    """
    # Argon2 at its lowest cost: the harness checks what the API shows, not how slowly it hashes
    monkeypatch.setattr(
        security, "_hasher", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )
    security.dummy_password_hash.cache_clear()
    config = WebConfig(
        database_path=tmp_path / "webvigil.db",
        session_secret=_SIGNING_KEY,
        allowed_hosts=["testserver"],
        trusted_proxies=[_PROXY_NAME],
    )
    tmp_path.mkdir(parents=True, exist_ok=True)
    run_alembic_upgrade(config)
    engine = make_engine(config)
    app = create_app(config, orchestrator_factory=factory)
    forwarded = {"x-forwarded-for": _FORWARDED}
    try:
        with (
            every_log_record() as logs,
            TestClient(app, client=(_PEER, 50000)) as client,
        ):
            assert client.post("/api/setup", json=_ACCOUNT, headers=forwarded).status_code == 201
            login = client.post("/api/auth/login", json=_ACCOUNT, headers=forwarded)
            assert login.status_code == 204, login.text
            session = next(iter(client.cookies.values()))
            yield _Api(client, engine, logs, session)
    finally:
        engine.dispose()
        security.dummy_password_hash.cache_clear()


def _api_credentials(api: _Api) -> tuple[str, ...]:
    """
    The Web API's credentials, with their positive controls: the password logged in, and the
    session token is the one the marker key signed.

    Args:
        api (_Api): The app.

    Returns:
        tuple[str, ...]: The password, the signing key and the session token.
    """
    claims: dict[str, Any] = jwt.decode(api.session, _SIGNING_KEY, algorithms=["HS256"])
    assert claims["sub"]
    assert api.client.get("/api/auth/me").json()["username"] == _ACCOUNT["username"]
    return (_PASSWORD, _SIGNING_KEY, api.session)


def _check_fault(fault: Fault) -> None:
    """
    The positive control of an injected failure: it fired, with its marker.

    Args:
        fault (Fault): The seam.
    """
    assert fault.raised, "the seam never raised: the run did not reach its stage"
    assert all(fault.marker in str(exc) for exc in fault.raised)


# ---------------------------------------------------------------------------
# The scan harness's results, stored and served
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("run", range(SCAN_RUNS))
def test_a_failed_scan_is_stored_and_served_as_the_cli_showed_it(
    run: int, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    A full run's result, with each pass's failure in it, goes through the runner, the database and
    every route: no credential anywhere, and a failure's text only where the CLI's report has it.
    """
    outcome = scan_run(f"full-{run}", run, TOGETHER, monkeypatch, tmp_path)
    assert outcome.scan is not None
    with _api(tmp_path / "api", monkeypatch, _returning(outcome.scan)) as api:
        scan_id = api.scan()
        assert api.status(scan_id) is ScanStatus.COMPLETED
        outputs = api.outputs(scan_id)
        credentials = (*CREDENTIALS, *_api_credentials(api))

    assert credential_hits(outputs, credentials) == []
    issued = set(outcome.app.state.sessions) | outcome.app.state.expired
    assert _session_hits(outputs, issued) == []
    markers = {fault.marker: fault.kind for fault in outcome.log.applied}
    assert bad_failure_hits(outputs, markers) == []

    # the positive controls: every finding was stored, and every failure text the CLI's report
    # quoted reached the API's outputs too, so the searches above did not pass on nothing
    page = api_body(outputs, "findings")
    assert f'"total":{len(outcome.scan.findings)}' in page
    quoted = {marker for marker in markers if marker in outcome.outputs.texts["report:json"]}
    reached = {hit.marker for hit in failure_hits(outputs, markers)}
    assert quoted <= reached, sorted(quoted - reached)
    if quoted:
        assert {family(hit.output) for hit in failure_hits(outputs, markers)} >= {"db", "report"}


def api_body(outputs: Outputs, route: str) -> str:
    """
    Args:
        outputs (Outputs): A run's outputs.
        route (str): A route's name.

    Returns:
        str: Its body, every page of it.
    """
    return "\n".join(
        text for name, text in outputs.texts.items() if name.split("#")[0] == f"api-body:{route}"
    )


# ---------------------------------------------------------------------------
# The Web API's own failures
# ---------------------------------------------------------------------------


def test_an_engine_error_nothing_expects_is_logged_by_its_type_and_frames(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    The scan fails with ``internal error``, and the server log says where the error was and of
    what type, never what it said: the message of an error nothing expected may quote anything.
    """
    marker = failure_marker("api-engine", Kind.RAISES)
    factory, fault = raising_orchestrator(RuntimeError, marker)
    with _api(tmp_path, monkeypatch, factory) as api:
        scan_id = api.scan()
        outputs = api.outputs(scan_id)
        credentials = _api_credentials(api)

    _check_fault(fault)
    assert f'"error":"{INTERNAL_ERROR}"' in api_body(outputs, "scan")
    assert credential_hits(outputs, credentials) == []
    assert bad_failure_hits(outputs, {marker: Kind.RAISES}) == []
    # the positive control of the log: the failure is there, by type, with its frames
    (line,) = [line for line in api.logs.lines if f"scan {scan_id} failed" in line]
    assert f"ERROR webvigil.api scan {scan_id} failed (RuntimeError)" in line
    assert "Traceback (most recent call last):" in line and "faults.py" in line


def test_an_engine_error_the_engine_names_is_the_scans_error_cut_and_escaped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    A ``WebVigilError``'s message is the project's own, so the scan's ``error`` keeps it, cut at
    the bound of ``Text``, and the API's JSON shows its controls as escapes; it reaches no output
    but the scan's row and the scan and list routes.
    """
    marker = failure_marker("api-engine", Kind.RAISES)
    factory, fault = raising_orchestrator(WebVigilError, marker)
    with _api(tmp_path, monkeypatch, factory) as api:
        scan_id = api.scan()
        assert api.status(scan_id) is ScanStatus.FAILED
        outputs = api.outputs(scan_id)
        credentials = _api_credentials(api)

    _check_fault(fault)
    assert credential_hits(outputs, credentials) == []
    hits = failure_hits(outputs, {marker: Kind.RAISES})
    assert {family(hit.output) for hit in hits} == {"db", "api-body"}, hits
    assert all(not hit.problems for hit in hits), hits
    assert f'"error":"{marker}' in api_body(outputs, "scan")


def test_a_result_the_database_cannot_store_fails_the_scan_and_logs_why(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    The scan fails with ``internal error``; the database's message goes to the server log, the
    operator's, cut and on its lines, and nowhere else.
    """
    outcome = scan_run("full-0", 0, TOGETHER, monkeypatch, tmp_path)
    assert outcome.scan is not None
    marker = failure_marker("api-store", Kind.DB)
    fault = failing_store(monkeypatch, marker)
    with _api(tmp_path / "api", monkeypatch, _returning(outcome.scan)) as api:
        scan_id = api.scan()
        assert api.status(scan_id) is ScanStatus.FAILED
        outputs = api.outputs(scan_id)
        credentials = (*CREDENTIALS, *_api_credentials(api))

    _check_fault(fault)
    assert f'"error":"{INTERNAL_ERROR}"' in api_body(outputs, "scan")
    assert credential_hits(outputs, credentials) == []
    assert bad_failure_hits(outputs, {marker: Kind.DB}) == []
    # the positive control: the database's text is in the log, where it may go
    hits = failure_hits(outputs, {marker: Kind.DB})
    assert {family(hit.output) for hit in hits} == {"server-log"}, hits


def test_a_claim_the_database_fails_is_logged_and_the_queue_goes_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The loop logs the database's message and claims again: the scan still runs to its end."""
    outcome = scan_run("full-0", 0, TOGETHER, monkeypatch, tmp_path)
    assert outcome.scan is not None
    marker = failure_marker("api-claim", Kind.DB)
    fault = failing_claim(monkeypatch, marker)
    with _api(tmp_path / "api", monkeypatch, _returning(outcome.scan)) as api:
        scan_id = api.scan()
        assert api.status(scan_id) is ScanStatus.COMPLETED
        outputs = api.outputs(scan_id)
        credentials = (*CREDENTIALS, *_api_credentials(api))

    _check_fault(fault)
    assert len(fault.raised) == 1
    assert credential_hits(outputs, credentials) == []
    assert bad_failure_hits(outputs, {marker: Kind.DB}) == []
    hits = failure_hits(outputs, {marker: Kind.DB})
    assert {family(hit.output) for hit in hits} == {"server-log"}, hits


def test_a_proxy_name_that_does_not_resolve_trusts_nobody_and_says_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    The lookup of a trusted proxy's name fails on the login: the login still works, the forwarded
    address is not believed, and the resolver's text reaches no output.
    """
    marker = failure_marker("api-proxies", Kind.RESOLVER)
    fault = Fault(marker)
    getaddrinfo = socket.getaddrinfo

    def _getaddrinfo(host: str, *args: Any, **kwargs: Any) -> Any:
        if host == _PROXY_NAME:
            raise fault.fire(socket.gaierror(socket.EAI_NONAME, failure_text(marker)))
        return getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(client_address_mod.socket, "getaddrinfo", _getaddrinfo)
    factory, _ = raising_orchestrator(RuntimeError, failure_marker("api-engine", Kind.RAISES))
    with _api(tmp_path, monkeypatch, factory) as api:
        # ``TestClient.app`` is typed as any ASGI app, which has no ``state``
        trusted = api.client.app.state.trusted_proxies  # type: ignore[attr-defined]
        outputs = Outputs()
        for line in api.logs.lines:
            outputs.add("server-log", line)
        credentials = _api_credentials(api)

    _check_fault(fault)
    assert client_address(_PEER, [_FORWARDED], trusted) == _PEER
    assert credential_hits(outputs, credentials) == []
    assert bad_failure_hits(outputs, {marker: Kind.RESOLVER}) == []
    assert api.logs.lines  # the positive control of the log: the requests were logged
