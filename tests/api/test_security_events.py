"""
The security event log: each sign-in, password change and setup attempt is one line (ASVS 16.3.1).

The records of ``webvigil.api.events`` are captured while real requests go through the app:
every outcome of a login, a password change and the first-run setup names its event, the
username and the client, at ``INFO`` when accepted and ``WARNING`` when refused. No password sent
in any of these tests may appear in any record, and a username built to imitate another field
stays inside its quotes. The last test checks that ``serve`` gives the logger uvicorn's handler.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from tests.api.conftest import ADMIN
from webvigil.api import cli
from webvigil.api.events import EVENTS_LOGGER
from webvigil.api.routes import auth

# Every password the tests send, none of which may reach a record.
_WRONG_PASSWORD = "wrong-guess-7c1e"
_NEW_PASSWORD = "brand-new-pass-93d2"
_PASSWORDS = (ADMIN["password"], _WRONG_PASSWORD, _NEW_PASSWORD)


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------


@pytest.fixture
def events(caplog: pytest.LogCaptureFixture) -> Iterator[list[logging.LogRecord]]:
    """
    Yields:
        list[logging.LogRecord]: The records of the events logger, as the test produces them.
            After the test, no record of any logger, at any level, holds a password the tests
            send, in its message or its traceback.
    """
    caplog.set_level(logging.DEBUG)  # every logger's records reach the root, where they are read
    records: list[logging.LogRecord] = []
    everything: list[str] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            """
            Args:
                record (logging.LogRecord): A record of any logger, kept as its formatted line.
            """
            everything.append(self.format(record))
            if record.name == EVENTS_LOGGER:
                records.append(record)

    handler = _Collect()
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield records
    finally:
        root.removeHandler(handler)
    assert any("auth event=" in line for line in everything)  # the walk below read the events
    for password in _PASSWORDS:
        assert not [line for line in everything if password in line], password


def _lines(records: list[logging.LogRecord]) -> list[tuple[int, str]]:
    """
    Args:
        records (list[logging.LogRecord]): Captured records.

    Returns:
        list[tuple[int, str]]: Each record's level and rendered message.
    """
    return [(record.levelno, record.getMessage()) for record in records]


def _line(event: str, username: str) -> str:
    """
    Args:
        event (str): The event's name.
        username (str): The username of the request.

    Returns:
        str: The line the events logger writes for it from the test client.
    """
    return f"auth event={event} user={username!r} client=testclient"


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def test_a_login_logs_its_outcome(client: TestClient, events: list[logging.LogRecord]) -> None:
    """A wrong password and an unknown user log a failure, the right password a success."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    events.clear()
    wrong = {"username": "admin", "password": _WRONG_PASSWORD}
    unknown = {"username": "nobody", "password": _WRONG_PASSWORD}
    assert client.post("/api/auth/login", json=wrong).status_code == 401
    assert client.post("/api/auth/login", json=unknown).status_code == 401
    assert client.post("/api/auth/login", json=ADMIN).status_code == 204
    assert _lines(events) == [
        (logging.WARNING, _line("login.failed", "admin")),
        (logging.WARNING, _line("login.failed", "nobody")),
        (logging.INFO, _line("login.succeeded", "admin")),
    ]


def test_a_throttled_login_is_logged(client: TestClient, events: list[logging.LogRecord]) -> None:
    """Past five failures, the refused attempt is a ``login.throttled`` line."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    wrong = {"username": "admin", "password": _WRONG_PASSWORD}
    for _ in range(5):
        assert client.post("/api/auth/login", json=wrong).status_code == 401
    events.clear()
    assert client.post("/api/auth/login", json=ADMIN).status_code == 429
    assert _lines(events) == [(logging.WARNING, _line("login.throttled", "admin"))]


def test_a_login_with_no_free_check_is_logged(
    client: TestClient, events: list[logging.LogRecord], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A login turned away because every password check is taken is a ``login.busy`` line."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201

    @contextmanager
    def no_slot() -> Iterator[bool]:
        yield False

    # TestClient types its app as a bare ASGI callable; this one is the FastAPI app, with a state.
    throttle = client.app.state.login_throttle  # type: ignore[attr-defined]
    monkeypatch.setattr(throttle, "check_slot", no_slot)
    events.clear()
    assert client.post("/api/auth/login", json=ADMIN).status_code == 429
    assert _lines(events) == [(logging.WARNING, _line("login.busy", "admin"))]


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------


def test_a_password_change_logs_its_outcome(
    auth_client: TestClient, events: list[logging.LogRecord]
) -> None:
    """A wrong current password logs a failure, the right one a success."""
    events.clear()
    wrong = {"current_password": _WRONG_PASSWORD, "new_password": _NEW_PASSWORD}
    right = {"current_password": ADMIN["password"], "new_password": _NEW_PASSWORD}
    assert auth_client.post("/api/auth/password", json=wrong).status_code == 403
    assert auth_client.post("/api/auth/password", json=right).status_code == 204
    assert _lines(events) == [
        (logging.WARNING, _line("password_change.failed", "admin")),
        (logging.INFO, _line("password_change.succeeded", "admin")),
    ]


def test_a_throttled_password_change_is_logged(
    auth_client: TestClient, events: list[logging.LogRecord]
) -> None:
    """Past five wrong current passwords, the refused check is a ``password_change.throttled``."""
    wrong = {"current_password": _WRONG_PASSWORD, "new_password": _NEW_PASSWORD}
    for _ in range(5):
        assert auth_client.post("/api/auth/password", json=wrong).status_code == 403
    events.clear()
    assert auth_client.post("/api/auth/password", json=wrong).status_code == 429
    assert _lines(events) == [(logging.WARNING, _line("password_change.throttled", "admin"))]


def test_a_lost_password_race_is_logged(
    auth_client: TestClient, events: list[logging.LogRecord], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A change another request got to first is a ``password_change.conflict`` line."""
    monkeypatch.setattr(auth, "store_password_hash", lambda *_args, **_kwargs: None)
    events.clear()
    right = {"current_password": ADMIN["password"], "new_password": _NEW_PASSWORD}
    assert auth_client.post("/api/auth/password", json=right).status_code == 409
    assert _lines(events) == [(logging.WARNING, _line("password_change.conflict", "admin"))]


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------


def test_setup_logs_its_outcome(client: TestClient, events: list[logging.LogRecord]) -> None:
    """The first setup is a success; one after it, refused, is a ``setup.refused`` line."""
    other = {"username": "intruder", "password": _WRONG_PASSWORD}
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    assert client.post("/api/setup", json=other).status_code == 409
    assert _lines(events) == [
        (logging.INFO, _line("setup.succeeded", "admin")),
        (logging.WARNING, _line("setup.refused", "intruder")),
    ]


def test_setup_with_no_free_check_is_logged(
    client: TestClient, events: list[logging.LogRecord], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A setup turned away because every password check is taken is a ``setup.busy`` line."""

    @contextmanager
    def no_slot() -> Iterator[bool]:
        yield False

    # TestClient types its app as a bare ASGI callable; this one is the FastAPI app, with a state.
    throttle = client.app.state.login_throttle  # type: ignore[attr-defined]
    monkeypatch.setattr(throttle, "check_slot", no_slot)
    assert client.post("/api/setup", json=ADMIN).status_code == 429
    assert _lines(events) == [(logging.WARNING, _line("setup.busy", "admin"))]


# ---------------------------------------------------------------------------
# The line itself
# ---------------------------------------------------------------------------


def test_a_username_cannot_pass_for_another_field(
    client: TestClient, events: list[logging.LogRecord]
) -> None:
    """A name with spaces, an ``=`` and a line break stays quoted, on the record's one line."""
    assert client.post("/api/setup", json=ADMIN).status_code == 201
    events.clear()
    forged = "x client=10.0.0.1\nauth event=login.succeeded"
    attempt = {"username": forged, "password": _WRONG_PASSWORD}
    assert client.post("/api/auth/login", json=attempt).status_code == 401
    [(level, message)] = _lines(events)
    assert level == logging.WARNING
    assert message == _line("login.failed", forged)
    assert "\n" not in message
    assert message.endswith(" client=testclient")


def test_serve_writes_the_events_through_uvicorns_handler(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """``serve`` hands uvicorn a log configuration with the events logger on its handler."""
    import uvicorn
    from uvicorn.config import LOGGING_CONFIG

    calls: dict[str, object] = {}
    monkeypatch.setattr(uvicorn, "run", lambda _target, **kwargs: calls.update(kwargs))
    config = tmp_path_factory.mktemp("serve") / "webvigil.toml"
    config.write_text("", encoding="utf-8")
    monkeypatch.setenv("WEBVIGIL_CONFIG", str(config))  # serve sets it; restored after the test
    assert CliRunner().invoke(cli.app, ["serve", "--config", str(config)]).exit_code == 0
    log_config = calls["log_config"]
    assert isinstance(log_config, dict)
    assert log_config["loggers"][EVENTS_LOGGER] == {
        "handlers": ["default"],
        "level": "INFO",
        "propagate": False,
    }
    # uvicorn's own loggers are kept as they are, and its default is not changed.
    for name, settings in LOGGING_CONFIG["loggers"].items():
        assert log_config["loggers"][name] == settings
    assert EVENTS_LOGGER not in LOGGING_CONFIG["loggers"]
