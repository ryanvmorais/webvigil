"""
The text of a failure and the secret parts of a URL stay out of every output.

A library's exception can quote what it refused or could not parse, and a URL can carry a
credential. Two harmless markers stand for those values. Each failure is forced through the real
engine over the in-repository HTTP mock, with the retry backoff at zero, and read where a user
would meet it: stderr, the JSON report and the Web API. Every test also asserts the failure's
type or exact message, so an output that said nothing could not pass.
"""

from __future__ import annotations

import errno
import functools
import itertools
import json
import os
import ssl
import time
import traceback
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpcore2
import httpx2
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from tests.http_mock import HttpxMock
from webvigil.api import cli as web_cli
from webvigil.api import security
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig
from webvigil.auth.login import Authenticator, Credentials
from webvigil.checks.base import Check
from webvigil.checks.session.checks import WeakSessionIdCheck
from webvigil.checks.session.scanner import SessionHit, SessionScanner
from webvigil.cli import app as app_mod
from webvigil.cli._exit import ExitCode
from webvigil.core import config as config_mod
from webvigil.core.config import LoginSection, ScanConfig
from webvigil.core.context import ScanContext
from webvigil.core.errors import (
    ConfigError,
    HarError,
    InvalidTargetError,
    LoginFailedError,
    OpenApiError,
    OutOfScopeError,
    RequestFailed,
)
from webvigil.core.findings import Category, Finding, Severity
from webvigil.core.orchestrator import Orchestrator, _portable_traceback
from webvigil.core.target import Target
from webvigil.core.urls import HIDDEN_PATH
from webvigil.crawler import openapi as openapi_mod
from webvigil.crawler.har import load_har
from webvigil.crawler.openapi import load_openapi
from webvigil.http import client as client_mod
from webvigil.http.addresses import BlockedAddressError
from webvigil.http.client import HttpClient
from webvigil.http.failures import failure_kind

runner = CliRunner()

_TRANSPORT = "markerTRANSPORT7f3a"
_CREDENTIAL = "markerCREDENTIAL91bc"
_RAW_TEXT = f"refused header value b'{_CREDENTIAL}' near {_TRANSPORT}"
_PATH_PARAMETER = f";sid={_CREDENTIAL}"
_SECRET_URL = (
    f"https://user:{_CREDENTIAL}@example.com/app{_PATH_PARAMETER}"
    f"?token={_CREDENTIAL}#{_CREDENTIAL}"
)
# A target may not carry userinfo (it is refused, spec 024 RF-09); the rest of a URL still can.
_SECRET_TARGET = f"https://example.com/app{_PATH_PARAMETER}?token={_CREDENTIAL}#{_CREDENTIAL}"
_LOGIN_URL = f"https://example.com/login{_PATH_PARAMETER}?next={_CREDENTIAL}"
_OPENAPI_URL = f"https://example.com/openapi.json{_PATH_PARAMETER}?token={_CREDENTIAL}"
_CLEAN_TARGET = "https://example.com/"
_ACTIVE_LOGIN: dict[str, object] = {
    "scan": {"mode": "active"},
    "active": {"authorized_by": "tester"},
    "auth": {"login": {"url": _LOGIN_URL, "username": "tester"}},
}


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero the retry backoff and give the login a password that is itself a marker."""
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)
    monkeypatch.setenv("WEBVIGIL_LOGIN_PASSWORD", _CREDENTIAL)


@pytest.fixture
def _cheap_hashing(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Hash the test account at Argon2's lowest cost, and drop the cheap dummy hash afterwards."""
    monkeypatch.setattr(
        security, "_hasher", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )
    security.dummy_password_hash.cache_clear()
    yield
    security.dummy_password_hash.cache_clear()


def _with_cause(exc: Exception, cause: Exception) -> Exception:
    """
    Args:
        exc (Exception): The outer exception.
        cause (Exception): What caused it.

    Returns:
        Exception: ``exc``, with ``cause`` as its ``__cause__``.
    """
    exc.__cause__ = cause
    return exc


def _squeezed(text: str) -> str:
    """
    Args:
        text (str): Terminal output, which Rich wraps at the console width.

    Returns:
        str: ``text`` with all whitespace removed, so a wrap cannot hide a marker.
    """
    return "".join(text.split())


def _assert_clean(text: str) -> None:
    """
    Args:
        text (str): An output a user would read.

    Raises:
        AssertionError: When a marker is in ``text``.
    """
    squeezed = _squeezed(text)
    assert _TRANSPORT not in squeezed
    assert _CREDENTIAL not in squeezed


def _scan_over_api(
    tmp_path: Path,
    make_orchestrator: Callable[[ScanConfig], Orchestrator],
    target: str,
) -> tuple[dict[str, object], str]:
    """
    Run one scan through the Web API, from the first account to the finished row.

    Args:
        tmp_path (Path): The test's directory, for a throwaway database.
        make_orchestrator (Callable[[ScanConfig], Orchestrator]): Builds the engine for the scan.
        target (str): The scan's target.

    Returns:
        tuple[dict[str, object], str]: The scan's detail response, and its JSON report when the
            scan completed (empty when it failed).
    """
    config = WebConfig(
        database_path=tmp_path / "webvigil.db",
        session_secret="test-session-secret-long-enough-for-hs256",
        allowed_hosts=["testserver"],
    )
    account = {"username": "admin", "password": "password123"}
    with TestClient(create_app(config, orchestrator_factory=make_orchestrator)) as client:
        assert client.post("/api/setup", json=account).status_code == 201
        assert client.post("/api/auth/login", json=account).status_code == 204
        created = client.post("/api/scans", json={"target": target})
        assert created.status_code == 201
        scan_id = created.json()["id"]
        deadline = time.monotonic() + 10
        while (body := client.get(f"/api/scans/{scan_id}").json())["status"] not in (
            "failed",
            "completed",
        ):
            assert time.monotonic() < deadline, body
            time.sleep(0.01)  # the runner works on the app's own loop
        report = ""
        if body["status"] == "completed":
            report = client.get(f"/api/scans/{scan_id}/report").text
    return body, report


# ---------------------------------------------------------------------------
# A failure that stops the scan
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Stop:
    """
    A failure that ends the scan with an error.

    Attributes:
        args (tuple[str, ...]): The CLI options that lead to it.
        config (dict[str, object]): The same options as an engine config.
        message (str): The exact error, with the failure's type as its last word.
    """

    args: tuple[str, ...]
    config: dict[str, object]
    message: str


_STOPS = {
    "target": _Stop(
        (),
        {},
        "the target did not answer: request to https://example.com/app failed: "
        "RemoteProtocolError",
    ),
    "login": _Stop(
        (
            "--mode",
            "active",
            "--authorized-by",
            "tester",
            "--login-url",
            _LOGIN_URL,
            "--username",
            "tester",
        ),
        _ACTIVE_LOGIN,
        "the login request failed: request to https://example.com/login failed: "
        "RemoteProtocolError",
    ),
    "openapi": _Stop(
        ("--openapi", _OPENAPI_URL),
        {"scan": {"openapi": _OPENAPI_URL}},
        "could not fetch https://example.com/openapi.json: request to "
        "https://example.com/openapi.json failed: RemoteProtocolError",
    ),
}


@pytest.mark.parametrize("name", list(_STOPS))
def test_a_failure_that_stops_the_scan_prints_only_its_type(
    name: str, httpx_mock: HttpxMock, tmp_path: Path
) -> None:
    """Exit 4; stderr has the exact error, with neither the library's text nor the URL's secrets."""
    stop = _STOPS[name]
    httpx_mock.add_exception(httpx2.RemoteProtocolError(_RAW_TEXT), is_reusable=True)
    report = tmp_path / "scan.json"

    result = runner.invoke(
        app_mod.app,
        ["scan", _SECRET_TARGET, *stop.args, "--format", "json", "--output", str(report)],
    )

    assert result.exit_code == ExitCode.OPERATIONAL
    assert _squeezed(stop.message) in _squeezed(result.stderr)
    _assert_clean(result.stderr)
    assert not report.exists()
    assert httpx_mock.get_requests()


@pytest.mark.parametrize("name", list(_STOPS))
@pytest.mark.usefixtures("_cheap_hashing")
def test_a_failure_that_stops_the_scan_reaches_the_api_as_its_type(
    name: str, httpx_mock: HttpxMock, tmp_path: Path
) -> None:
    """The stored error, which the Web API serves, is the same exact message."""
    stop = _STOPS[name]
    httpx_mock.add_exception(httpx2.RemoteProtocolError(_RAW_TEXT), is_reusable=True)
    config = ScanConfig.model_validate(stop.config)

    body, _report = _scan_over_api(tmp_path, lambda _config: Orchestrator(config), _SECRET_TARGET)

    assert body["status"] == "failed"
    assert body["error"] == stop.message


# ---------------------------------------------------------------------------
# A failure the scan survives
# ---------------------------------------------------------------------------


class _RaisingCheck(Check):
    """A check whose library call failed, with the raw text on both links of the chain."""

    id = "test.raising"
    name = "raising check"
    category = Category.HEADERS
    default_severity = Severity.LOW

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """
        Args:
            ctx (ScanContext): Unused.

        Returns:
            list[Finding]: Never returns.

        Raises:
            httpx2.LocalProtocolError: Always, chained from a ``ValueError``.
        """
        try:
            raise ValueError(_RAW_TEXT)
        except ValueError as exc:
            raise httpx2.LocalProtocolError(_RAW_TEXT) from exc


async def _failing_step(_self: SessionScanner) -> list[SessionHit]:
    """
    Args:
        _self (SessionScanner): Unused.

    Returns:
        list[SessionHit]: Never returns.

    Raises:
        httpx2.LocalProtocolError: Always.
    """
    raise httpx2.LocalProtocolError(_RAW_TEXT)


@dataclass(frozen=True)
class _Survived:
    """
    A failure that costs a warning or a check error, not the scan.

    Attributes:
        check (type[Check]): The check to run.
        patched (str | None): The ``SessionScanner`` method that fails, if any.
        says (str): The exact text the JSON report must carry.
    """

    check: type[Check]
    patched: str | None
    says: str


_SURVIVED = {
    "session-step": _Survived(
        WeakSessionIdCheck,
        "_weak",
        "session checks: the weak ids step failed: LocalProtocolError",
    ),
    "session-pass": _Survived(
        WeakSessionIdCheck, "run", "session checks failed: LocalProtocolError"
    ),
    "check": _Survived(_RaisingCheck, None, '"message": "LocalProtocolError"'),
}


@pytest.mark.parametrize("name", list(_SURVIVED))
def test_a_failure_the_scan_survives_is_reported_by_its_type(
    name: str, httpx_mock: HttpxMock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The CLI finishes; stderr and the JSON report name the type and hold no marker."""
    case = _SURVIVED[name]
    httpx_mock.add_response(text="<html><body>ok</body></html>", is_reusable=True)
    if case.patched is not None:
        monkeypatch.setattr(SessionScanner, case.patched, _failing_step)
    monkeypatch.setattr(
        app_mod, "Orchestrator", functools.partial(Orchestrator, check_types=[case.check])
    )
    path = tmp_path / "scan.json"

    result = runner.invoke(
        app_mod.app, ["scan", _CLEAN_TARGET, "--format", "json", "--output", str(path)]
    )

    assert result.exit_code == ExitCode.OK
    report = path.read_text("utf-8")
    assert case.says in report
    json.loads(report)  # still a well-formed report
    _assert_clean(result.stderr)
    _assert_clean(report)


@pytest.mark.parametrize("name", list(_SURVIVED))
@pytest.mark.usefixtures("_cheap_hashing")
def test_a_failure_the_scan_survives_reaches_the_api_report_by_its_type(
    name: str, httpx_mock: HttpxMock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The report the Web API renders from its stored rows names the type and holds no marker."""
    case = _SURVIVED[name]
    httpx_mock.add_response(text="<html><body>ok</body></html>", is_reusable=True)
    if case.patched is not None:
        monkeypatch.setattr(SessionScanner, case.patched, _failing_step)

    body, report = _scan_over_api(
        tmp_path,
        lambda _config: Orchestrator(ScanConfig(), check_types=[case.check]),
        _CLEAN_TARGET,
    )

    assert body["status"] == "completed"
    assert case.says in report
    _assert_clean(report)
    _assert_clean(json.dumps(body))


async def test_a_check_error_keeps_the_frames_and_the_chain_without_their_text(
    httpx_mock: HttpxMock,
) -> None:
    """Whoever wrote the check still finds it: the id, both types and the raising frame."""
    httpx_mock.add_response(text="<html></html>", is_reusable=True)

    result = await Orchestrator(ScanConfig(), check_types=[_RaisingCheck]).run(_CLEAN_TARGET)

    error = result.errors[0]
    assert (error.check_id, error.message) == ("test.raising", "LocalProtocolError")
    assert "test_transport_error_text.py" in error.traceback
    assert "ValueError\n" in error.traceback
    assert error.traceback.endswith("LocalProtocolError\n")
    _assert_clean(error.traceback)


async def test_a_check_error_of_the_project_keeps_its_message(httpx_mock: HttpxMock) -> None:
    """A ``WebVigilError`` is written by the project, so it still explains itself."""
    httpx_mock.add_response(text="<html></html>", is_reusable=True)

    class _Refused(_RaisingCheck):
        id = "test.refused"

        async def run(self, ctx: ScanContext) -> list[Finding]:
            raise RequestFailed(_SECRET_URL, "ConnectError")

    result = await Orchestrator(ScanConfig(), check_types=[_Refused]).run(_CLEAN_TARGET)

    assert result.errors[0].message == "request to https://example.com/app failed: ConnectError"


def test_a_group_and_a_looping_chain_are_formatted_without_their_text() -> None:
    """An exception group shows its members' types; a chain that loops still ends."""
    first, second = ValueError(_RAW_TEXT), KeyError(_RAW_TEXT)
    first.__cause__, second.__cause__ = second, first
    group = ExceptionGroup(_RAW_TEXT, [first, TypeError(_RAW_TEXT)])

    text = _portable_traceback(group)

    for name in ("ExceptionGroup", "ValueError", "KeyError", "TypeError"):
        assert text.count(f"{name}\n") == 1, name
    _assert_clean(text)


def test_a_suppressed_context_is_left_out_as_python_leaves_it_out() -> None:
    """``raise ... from None`` means the earlier exception is not part of the story."""
    try:
        try:
            raise KeyError(_RAW_TEXT)
        except KeyError:
            raise ValueError(_RAW_TEXT) from None
    except ValueError as exc:
        text = _portable_traceback(exc)

    assert text.endswith("ValueError\n")
    assert "KeyError" not in text


def test_a_very_long_chain_is_cut_instead_of_failing_the_handler() -> None:
    """Formatting a check's failure must not raise, however long its chain is."""
    head: BaseException = ValueError(_RAW_TEXT)
    for _ in range(5000):
        link = ValueError(_RAW_TEXT)
        link.__cause__ = head
        head = link

    assert _portable_traceback(head).count("ValueError\n") == 16


# ---------------------------------------------------------------------------
# The request error itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        httpx2.ConnectError,
        httpx2.ReadError,
        httpx2.WriteError,
        httpx2.RemoteProtocolError,
        httpx2.LocalProtocolError,
        httpx2.ReadTimeout,
        httpx2.DecodingError,
        httpx2.InvalidURL,
    ],
)
async def test_a_request_failure_carries_the_type_and_a_clean_url(
    failure: type[Exception], httpx_mock: HttpxMock
) -> None:
    """Each way out of the retry loop: exact message, no cause, nothing in a formatted traceback."""
    httpx_mock.add_exception(failure(_RAW_TEXT), is_reusable=True)
    async with HttpClient(Target.parse(_CLEAN_TARGET), ScanConfig()) as http:
        with pytest.raises(RequestFailed) as caught:
            await http.get(_SECRET_URL)

    exc = caught.value
    assert exc.reason == failure.__name__
    assert exc.url == "https://example.com/app"
    assert str(exc) == f"request to https://example.com/app failed: {failure.__name__}"
    assert exc.__cause__ is None
    _assert_clean("".join(traceback.format_exception(exc)))


@pytest.mark.parametrize(
    ("method", "failure", "reason"),
    [
        ("POST", httpx2.ReadError(_RAW_TEXT), "ReadError"),
        (
            "GET",
            _with_cause(httpx2.ConnectError(_RAW_TEXT), BlockedAddressError(_RAW_TEXT)),
            "BlockedAddressError: the host resolves to an address the scan may not reach",
        ),
        (
            "GET",
            client_mod._TotalTimeout("no complete response"),
            "TotalTimeout: no complete response",
        ),
    ],
    ids=["not-retried", "guard", "total-deadline"],
)
async def test_the_other_exits_of_the_retry_loop_chain_nothing(
    method: str, failure: Exception, reason: str, httpx_mock: HttpxMock
) -> None:
    """A request that is not retried leaves through its own ``raise``: each one is clean."""
    httpx_mock.add_exception(failure, is_reusable=True)
    async with HttpClient(Target.parse(_CLEAN_TARGET), ScanConfig()) as http:
        with pytest.raises(RequestFailed) as caught:
            await http.request(method, _SECRET_URL)

    assert caught.value.reason == reason
    assert caught.value.__cause__ is None
    _assert_clean("".join(traceback.format_exception(caught.value)))


def test_an_out_of_scope_error_repeats_no_secret_of_the_url() -> None:
    """The scope guard's error goes to the same outputs as a request failure."""
    exc = OutOfScopeError(_SECRET_URL)
    assert exc.url == "https://example.com/app"
    assert str(exc) == "URL is out of scope: https://example.com/app"


# ---------------------------------------------------------------------------
# Naming the failure
# ---------------------------------------------------------------------------


def _chained(*links: BaseException) -> BaseException:
    """
    Args:
        *links (BaseException): Exceptions, outermost first.

    Returns:
        BaseException: The first one, each link holding the next as its ``__cause__``.
    """
    for outer, inner in itertools.pairwise(links):
        outer.__cause__ = inner
    return links[0]


def test_an_untrusted_certificate_is_named_through_a_suppressed_context() -> None:
    """The TLS layer keeps the certificate error only as a suppressed ``__context__``."""
    certificate = ssl.SSLCertVerificationError(_RAW_TEXT)
    inner = httpcore2.ConnectError(_RAW_TEXT)
    inner.__context__ = certificate
    inner.__suppress_context__ = True
    outer = httpx2.ConnectError(_RAW_TEXT)
    outer.__cause__ = inner

    assert failure_kind(outer) == "SSLCertVerificationError: the TLS certificate is not trusted"


def test_a_guard_refusal_is_named() -> None:
    """The address guard's refusal gets the project's own label, not its text."""
    exc = _chained(httpx2.ConnectError(_RAW_TEXT), BlockedAddressError(_RAW_TEXT))
    assert failure_kind(exc) == (
        "BlockedAddressError: the host resolves to an address the scan may not reach"
    )


def test_a_private_class_loses_its_underscore() -> None:
    """The type is shown as a name a user can read."""

    class _Hidden(Exception):
        pass

    assert failure_kind(_Hidden(_RAW_TEXT)) == "Hidden"


def test_the_chain_walk_stops_at_its_limit_and_on_a_loop() -> None:
    """Past the depth limit the outer type stands; a chain that loops ends the walk."""
    deep = _chained(
        *(httpx2.ConnectError(_RAW_TEXT) for _ in range(8)),
        ssl.SSLCertVerificationError(_RAW_TEXT),
    )
    assert failure_kind(deep) == "ConnectError"
    near = _chained(
        *(httpx2.ConnectError(_RAW_TEXT) for _ in range(7)),
        ssl.SSLCertVerificationError(_RAW_TEXT),
    )
    assert failure_kind(near).startswith("SSLCertVerificationError")

    first, second = httpx2.ReadError(_RAW_TEXT), httpx2.ConnectError(_RAW_TEXT)
    first.__cause__, second.__cause__ = second, first
    assert failure_kind(first) == "ReadError"


# ---------------------------------------------------------------------------
# A target that cannot be parsed
# ---------------------------------------------------------------------------


_USERINFO = (
    "the target URL carries a credential (user:password@), which is not used; send it as a "
    'header, for example --header "Authorization: Basic ..."'
)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (f"user:{_CREDENTIAL}@example.com", "unsupported target (want an http/https URL)"),
        (
            f"https://example.com:{_CREDENTIAL}/",
            "the target URL has an invalid port (want a number from 0 to 65535)",
        ),
        (
            f"https://example.com:99999/?token={_CREDENTIAL}",
            "the target URL has an invalid port (want a number from 0 to 65535)",
        ),
        (
            f"https://[::1/?token={_CREDENTIAL}",
            "could not determine a valid host from the target URL",
        ),
        (
            f"https://exa_mple.com/app{_PATH_PARAMETER}?token={_CREDENTIAL}",
            "could not determine a valid host from https://exa_mple.com/app",
        ),
        (
            f"https:///app?token={_CREDENTIAL}",
            "could not determine a valid host from <unreadable URL>",
        ),
        # a credential is refused before the host is read, whatever is wrong after it
        (f"https://user:{_CREDENTIAL}@example.com:99999/", _USERINFO),
        (f"https://user:{_CREDENTIAL}@[::1/", _USERINFO),
        (f"https://user:{_CREDENTIAL}@exa_mple.com/app?token={_CREDENTIAL}", _USERINFO),
        (f"https://{_CREDENTIAL}@/", _USERINFO),
    ],
)
def test_an_invalid_target_exits_4_without_repeating_the_value(raw: str, message: str) -> None:
    """Same exit code as any bad target, the exact message, and nothing of what was typed."""
    with pytest.raises(InvalidTargetError) as caught:
        Target.parse(raw)
    assert str(caught.value) == message

    result = runner.invoke(app_mod.app, ["scan", raw])

    assert result.exit_code == ExitCode.OPERATIONAL
    assert _squeezed(message) in _squeezed(result.stderr)
    _assert_clean(result.stderr)


def test_a_har_given_as_a_url_is_refused_without_its_secrets() -> None:
    """The refusal names the URL, cut to what a message may repeat."""
    with pytest.raises(HarError) as caught:
        load_har(_SECRET_URL, target=Target.parse(_CLEAN_TARGET), max_operations=10)
    assert str(caught.value) == "--har takes a local file, not a URL: https://example.com/app"


_DEEP_DOCUMENT = "[" * 300 + "]" * 300


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (
            {"status_code": 404},
            "https://example.com/openapi.json returned HTTP 404",
        ),
        (
            {"text": "not json"},
            "https://example.com/openapi.json is not valid JSON (line 1, column 1)",
        ),
        (
            {"text": _DEEP_DOCUMENT},
            "https://example.com/openapi.json is nested too deeply",
        ),
        (
            {"json": {"title": "x"}},
            "https://example.com/openapi.json is not an OpenAPI or Swagger document",
        ),
    ],
    ids=["status", "not-json", "nested", "not-openapi"],
)
async def test_an_openapi_answer_it_cannot_use_is_named_without_the_query(
    answer: dict[str, Any], message: str, httpx_mock: HttpxMock
) -> None:
    """Every message about a fetched document names the URL without its secret parts."""
    httpx_mock.add_response(**answer)
    target = Target.parse(_CLEAN_TARGET)
    async with HttpClient(target, ScanConfig()) as http:
        with pytest.raises(OpenApiError) as caught:
            await load_openapi(_OPENAPI_URL, http=http, target=target, max_operations=10)
    assert str(caught.value) == message


async def test_a_document_too_deep_for_the_parser_is_named_without_the_query(
    httpx_mock: HttpxMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The parser's own recursion limit gives the same message as the nesting limit."""

    def too_deep(_text: str) -> object:
        raise RecursionError

    httpx_mock.add_response(text="{}")
    monkeypatch.setattr(openapi_mod.json, "loads", too_deep)
    target = Target.parse(_CLEAN_TARGET)
    async with HttpClient(target, ScanConfig()) as http:
        with pytest.raises(OpenApiError) as caught:
            await load_openapi(_OPENAPI_URL, http=http, target=target, max_operations=10)
    assert str(caught.value) == "https://example.com/openapi.json is nested too deeply"


async def test_an_openapi_url_out_of_scope_is_named_without_the_query() -> None:
    """Refused before any request, by the same safe name."""
    source = f"https://user:{_CREDENTIAL}@other.example/spec.json?token={_CREDENTIAL}"
    target = Target.parse(_CLEAN_TARGET)
    async with HttpClient(target, ScanConfig()) as http:
        with pytest.raises(OpenApiError) as caught:
            await load_openapi(source, http=http, target=target, max_operations=10)
    assert str(caught.value) == "--openapi URL is out of scope: https://other.example/spec.json"


async def test_an_openapi_local_path_is_still_named_in_full(tmp_path: Path) -> None:
    """A path has no secret parts: the message keeps it, so the user can find the file."""
    path = tmp_path / "spec.json"
    path.write_text("[]", "utf-8")
    target = Target.parse(_CLEAN_TARGET)
    async with HttpClient(target, ScanConfig()) as http:
        with pytest.raises(OpenApiError) as caught:
            await load_openapi(str(path), http=http, target=target, max_operations=10)
    assert str(caught.value) == f"{path} is not an OpenAPI or Swagger document"


_MARKED = f"{_PATH_PARAMETER}?t={_CREDENTIAL}"


def _login_form(action: str, *, method: str = "post") -> str:
    """
    Args:
        action (str): The form's ``action``.
        method (str): The form's method. Defaults to ``post``.

    Returns:
        str: A form with a username and a password input.
    """
    return (
        f'<form method="{method}" action="{action}"><input type="text" name="email">'
        '<input type="password" name="pass"></form>'
    )


_LOGIN_FAILURES: dict[str, tuple[dict[str, tuple[int, str]], str]] = {
    "origin-gate": (
        {"/login": (200, _login_form(f"http://user:{_CREDENTIAL}@example.com/post{_MARKED}"))},
        "the login form action http://example.com/post is not the target origin: "
        "the password stays home",
    ),
    "page-status": (
        {"/login": (404, "<html></html>")},
        "the login page https://example.com/login answered 404",
    ),
    "no-form": (
        {"/login": (200, _login_form(f"/search{_MARKED}", method="get"))},
        "no login form (a POST form with a password input) on https://example.com/login; "
        "forms seen: GET https://example.com/search(email, pass)",
    ),
    "several-forms": (
        {"/login": (200, _login_form(f"/a{_MARKED}") + _login_form(f"/b{_MARKED}"))},
        "2 login forms on https://example.com/login and no form_index: "
        "POST https://example.com/a(email, pass); POST https://example.com/b(email, pass)",
    ),
    "post-status": (
        {"/login": (200, _login_form(f"/post{_MARKED}")), "/post": (500, "")},
        "the login answered 500 at https://example.com/post",
    ),
    "check-url": (
        {
            "/login": (200, _login_form(f"/post{_MARKED}")),
            "/post": (200, "<html>welcome</html>"),
            "/check": (401, ""),
        },
        "check_url https://example.com/check still looks logged out",
    ),
}


@pytest.mark.parametrize("name", list(_LOGIN_FAILURES))
async def test_every_login_message_names_its_url_without_secrets(
    name: str, httpx_mock: HttpxMock
) -> None:
    """Each message the handshake writes about a URL, with the exact text it must show."""
    answers, message = _LOGIN_FAILURES[name]

    def answer(request: httpx2.Request) -> httpx2.Response:
        for prefix, (status, body) in answers.items():
            if request.url.path.startswith(prefix):
                return httpx2.Response(status, headers={"content-type": "text/html"}, text=body)
        raise AssertionError(f"unexpected request to {request.url.path}")

    httpx_mock.add_callback(answer, is_reusable=True)
    target = Target.parse(_CLEAN_TARGET)
    login = LoginSection(
        url=_LOGIN_URL, username="tester", check_url=f"https://example.com/check{_MARKED}"
    )
    async with HttpClient(target, ScanConfig()) as http:
        authenticator = Authenticator(
            http, target, login, Credentials(username="tester", password="not-a-marker")
        )
        http.use_session(authenticator.session)
        with pytest.raises(LoginFailedError) as caught:
            await authenticator.login()

    assert str(caught.value) == message


def test_a_login_gate_message_drops_what_the_url_carries(httpx_mock: HttpxMock) -> None:
    """A login URL on another host is refused by name, without what the URL carried."""
    other = f"https://other.example/login{_PATH_PARAMETER}?next={_CREDENTIAL}#{_CREDENTIAL}"

    result = runner.invoke(
        app_mod.app,
        [
            "scan",
            _CLEAN_TARGET,
            "--mode",
            "active",
            "--authorized-by",
            "tester",
            "--login-url",
            other,
            "--username",
            "tester",
        ],
    )

    assert result.exit_code == ExitCode.OPERATIONAL
    assert _squeezed("https://other.example/login is out of scope") in _squeezed(result.stderr)
    _assert_clean(result.stderr)
    assert httpx_mock.get_requests() == []


_SCHEMELESS = [
    f"user:{_CREDENTIAL}@example.com/doc.json",
    f"example.com/doc.json?token={_CREDENTIAL}",
    f"example.com/doc.json#{_CREDENTIAL}",
    f"example.com/doc;sid={_CREDENTIAL}/x.json",
]


async def _document_error(source: str) -> str:
    """
    Args:
        source (str): The value given to ``--openapi``; a local path, so nothing is sent.

    Returns:
        str: The message of the error it raises.
    """
    target = Target.parse(_CLEAN_TARGET)
    with pytest.raises(OpenApiError) as caught:
        await openapi_mod._fetch_document(
            source, http=HttpClient(target, ScanConfig()), target=target
        )
    _assert_clean("".join(traceback.format_exception(caught.value)))
    return str(caught.value)


def _har_error(source: str) -> str:
    """
    Args:
        source (str): The value given to ``--har``.

    Returns:
        str: The message of the error it raises.
    """
    with pytest.raises(HarError) as caught:
        load_har(source, target=Target.parse(_CLEAN_TARGET), max_operations=10)
    _assert_clean("".join(traceback.format_exception(caught.value)))
    return str(caught.value)


@pytest.mark.parametrize("source", _SCHEMELESS, ids=["userinfo", "query", "fragment", "parameter"])
async def test_a_url_typed_without_its_scheme_is_not_repeated(source: str) -> None:
    """It reads as a missing file, and the message names no part of it."""
    assert await _document_error(source) == f"OpenAPI file not found: {HIDDEN_PATH}"
    assert _har_error(source) == f"HAR file not found: {HIDDEN_PATH}"


async def test_a_plain_missing_file_is_still_named() -> None:
    """The control: a path without a URL delimiter is what the user needs to read."""
    assert await _document_error("missing.json") == "OpenAPI file not found: missing.json"
    assert _har_error("missing.har") == "HAR file not found: missing.har"


async def test_a_file_that_cannot_be_read_names_the_failure_by_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The text of an ``OSError`` quotes the path it was given."""
    document = tmp_path / "plain.json"
    document.write_text("{}", "utf-8")

    def refuse(self: Path, *_args: object, **_kwargs: object) -> str:
        """Fail the way the operating system does, quoting the file name."""
        raise PermissionError(13, "denied", f"{self}{_CREDENTIAL}")

    monkeypatch.setattr(Path, "read_text", refuse)
    monkeypatch.setattr(Path, "read_bytes", refuse)

    assert await _document_error(str(document)) == f"could not read {document}: PermissionError"
    assert _har_error(str(document)) == f"could not read {document}: PermissionError"


@pytest.mark.parametrize(
    "raw",
    [f"{_CREDENTIAL}:pw@example.com/?next=https://other.example/", "ftp://example.com/"],
    ids=["userinfo-read-as-scheme", "real-scheme"],
)
def test_an_unsupported_scheme_is_refused_without_repeating_it(raw: str) -> None:
    """What precedes the first colon can be a user name or a token."""
    with pytest.raises(InvalidTargetError) as caught:
        Target.parse(raw)
    assert str(caught.value) == "unsupported scheme (want an http/https URL)"


async def test_a_path_the_system_refuses_is_not_repeated(monkeypatch: pytest.MonkeyPatch) -> None:
    """A name over the system's limit raises at the first look at the file, quoting itself."""

    def too_long(self: Path) -> bool:
        """Fail the way a POSIX system does on some Python versions."""
        raise OSError(errno.ENAMETOOLONG, "File name too long", str(self))

    monkeypatch.setattr(Path, "is_file", too_long)
    source = _SCHEMELESS[1]

    assert await _document_error(source) == f"could not read {HIDDEN_PATH}: OSError"
    assert _har_error(source) == f"could not read {HIDDEN_PATH}: OSError"


_CONFIG_LOADERS = [ScanConfig.load, WebConfig.load]


@pytest.mark.parametrize("load", _CONFIG_LOADERS, ids=["scan", "web"])
@pytest.mark.parametrize("source", _SCHEMELESS, ids=["userinfo", "query", "fragment", "parameter"])
def test_a_config_value_that_may_be_a_url_is_not_repeated(
    load: Callable[[str], object], source: str
) -> None:
    """The message for a missing config names no part of what was typed."""
    with pytest.raises(ConfigError) as caught:
        load(source)

    assert str(caught.value) == f"config file not found: {HIDDEN_PATH}"


@pytest.mark.parametrize("load", _CONFIG_LOADERS, ids=["scan", "web"])
def test_a_plain_missing_config_is_still_named(load: Callable[[str], object]) -> None:
    """The control: a path without a URL delimiter is what the user needs to read."""
    with pytest.raises(ConfigError) as caught:
        load("missing.toml")

    assert str(caught.value) == "config file not found: missing.toml"


@pytest.mark.parametrize("load", _CONFIG_LOADERS, ids=["scan", "web"])
def test_a_config_path_the_system_refuses_is_a_controlled_error(
    load: Callable[[str], object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first look at the file can raise, quoting the value."""

    def too_long(self: Path) -> bool:
        """Fail the way a POSIX system does on some Python versions."""
        raise OSError(errno.ENAMETOOLONG, "File name too long", str(self))

    monkeypatch.setattr(Path, "is_file", too_long)

    with pytest.raises(ConfigError) as caught:
        load(_SCHEMELESS[1])

    assert str(caught.value) == f"could not read {HIDDEN_PATH}: OSError"
    _assert_clean("".join(traceback.format_exception(caught.value)))  # the chain included


@pytest.mark.parametrize("load", _CONFIG_LOADERS, ids=["scan", "web"])
def test_a_config_that_is_not_utf8_is_a_controlled_error(
    load: Callable[[str], object], tmp_path: Path
) -> None:
    """Bytes that do not decode are named by the failure, never quoted."""
    path = tmp_path / "plain.toml"
    path.write_bytes(b'key = "\xff"\n')

    with pytest.raises(ConfigError) as caught:
        load(str(path))

    assert str(caught.value) == f"could not read {path}: UnicodeDecodeError"


@pytest.mark.parametrize("load", _CONFIG_LOADERS, ids=["scan", "web"])
def test_a_config_nested_too_deeply_is_a_controlled_error(
    load: Callable[[str], object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The TOML parser recurses, so a deep file ends in ``RecursionError``."""
    path = tmp_path / "plain.toml"
    path.write_text("key = 1\n", "utf-8")

    def too_deep(_text: str) -> dict[str, object]:
        """Fail as the parser does on a file nested past the recursion limit."""
        raise RecursionError

    monkeypatch.setattr(config_mod.tomllib, "loads", too_deep)

    with pytest.raises(ConfigError) as caught:
        load(str(path))

    assert str(caught.value) == f"could not read {path}: RecursionError"


@pytest.mark.parametrize(
    ("app", "arguments"),
    [(app_mod.app, ["scan", _CLEAN_TARGET]), (web_cli.app, ["migrate"])],
    ids=["webvigil", "webvigil-web"],
)
def test_an_unreadable_config_exits_4_on_both_command_lines(
    app: Any, arguments: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The option does not refuse the file first, with the usage error's exit code."""
    denied = tmp_path / "plain.toml"
    denied.write_text("", "utf-8")
    real_access = os.access
    real_read = Path.read_text

    def access(path: Any, mode: int, **kwargs: Any) -> bool:
        """Say the file cannot be read, as a permission bit would."""
        return False if Path(path) == denied else real_access(path, mode, **kwargs)

    def read_text(self: Path, *args: Any, **kwargs: Any) -> str:
        """Refuse the file the same way when it is opened."""
        if self == denied:
            raise PermissionError(13, "denied", str(self))
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(os, "access", access)
    monkeypatch.setattr(Path, "read_text", read_text)

    result = runner.invoke(app, [*arguments, "--config", str(denied)])

    assert result.exit_code == ExitCode.OPERATIONAL == 4
    assert "PermissionError" in _squeezed(result.stderr)
