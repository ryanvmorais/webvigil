"""
The Web API holds its signing secret and every password as a secret (spec 024, RF-06, RF-08, RF-09).

A pinned canary signing secret and canary passwords go through setup, login, a password change
and too-long passwords, with every log record captured at ``DEBUG``: no spelling of any canary
appears in a log record or a response. Each ``422`` keeps where and why (``type``, ``loc``,
``msg``) and drops ``input``, ``ctx`` and ``url``, on every endpoint. A target with a credential
in it is refused without being repeated, and nothing is stored.

Each test runs on its own copy of the migrated database, through the in-process ``TestClient`` and
the fake orchestrator, so nothing leaves the machine. The spellings searched for are built here,
not by the code under test.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote, quote_plus

import httpx2
import pytest
from fastapi.testclient import TestClient

from tests.api.conftest import FakeOrchestrator
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig

# The canaries: values that no spelling of may reach a log record or a response. The key is long
# enough to be pinned, the passwords long enough for setup, and the last one over the 256 limit.
_SIGNING_KEY = "canary-signing-key-0123456789abcdef"
_PASSWORD = "canary-pass-one"
_NEW_PASSWORD = "canary-pass-two"
_TOO_LONG = "canary-too-long-" + "x" * 256
_CANARIES = (_SIGNING_KEY, _PASSWORD, _NEW_PASSWORD, _TOO_LONG)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _spellings(value: str) -> set[str]:
    """
    Args:
        value (str): A canary.

    Returns:
        set[str]: The forms it could take in a log line or a body: raw, percent-encoded both ways,
            and JSON-escaped, each built here rather than by the code under test.
    """
    return {value, quote(value, safe=""), quote_plus(value), json.dumps(value)[1:-1]}


def _leaks(text: str) -> set[str]:
    """
    Args:
        text (str): Everything the API logged or answered.

    Returns:
        set[str]: The canary spellings found in ``text``.
    """
    return {spelling for value in _CANARIES for spelling in _spellings(value) if spelling in text}


def _everything(response: httpx2.Response) -> str:
    """
    Args:
        response (httpx2.Response): One response.

    Returns:
        str: Its body and every header value, the session cookie included.
    """
    return response.text + "\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.multi_items())


@pytest.fixture
def canary_client(web_config: WebConfig) -> Iterator[TestClient]:
    """
    Yields:
        TestClient: A client for an app whose pinned ``session_secret`` is the canary.
    """
    config = WebConfig(
        database_path=web_config.database_path,
        session_secret=_SIGNING_KEY,
        allowed_hosts=["testserver"],
    )
    with TestClient(create_app(config, orchestrator_factory=FakeOrchestrator)) as client:
        yield client


# ---------------------------------------------------------------------------
# The canary
# ---------------------------------------------------------------------------


def test_the_leak_finder_finds_each_spelling() -> None:
    """Positive control: a canary in any of its spellings is found, and plain text is not."""
    assert _leaks(f"[{quote_plus(_TOO_LONG)}]") and _leaks(f"pw={_PASSWORD}")
    assert not _leaks("[redacted] canary-pass")


def test_no_canary_leaves_the_web_api(
    canary_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """Setup, login, a change and too-long passwords: no canary in a log record or a response."""
    caplog.set_level(logging.DEBUG)
    responses = [
        canary_client.post("/api/setup", json={"username": "admin", "password": _PASSWORD}),
        canary_client.post("/api/auth/login", json={"username": "admin", "password": "wrong-one"}),
        canary_client.post("/api/auth/login", json={"username": "admin", "password": _PASSWORD}),
        canary_client.post(
            "/api/auth/password",
            json={"current_password": _PASSWORD, "new_password": _NEW_PASSWORD},
        ),
        canary_client.get("/api/auth/me"),
        canary_client.post("/api/auth/login", json={"username": "admin", "password": _TOO_LONG}),
        canary_client.post(
            "/api/auth/password",
            json={"current_password": _NEW_PASSWORD, "new_password": _TOO_LONG},
        ),
    ]
    # Positive control: the canary password was accepted, the change took, and the session the
    # canary key signed is valid; the too-long passwords were refused field by field.
    assert [r.status_code for r in responses] == [201, 401, 204, 204, 200, 422, 422]
    assert canary_client.post(
        "/api/auth/login", json={"username": "admin", "password": _NEW_PASSWORD}
    ).is_success
    for refused, field in ((responses[5], "password"), (responses[6], "new_password")):
        (error,) = refused.json()["detail"]
        assert error["loc"] == ["body", field]
        assert "at most 256 characters" in error["msg"]
    assert caplog.records  # the capture saw the requests

    logged = caplog.text + "\n".join(repr(vars(record)) for record in caplog.records)
    answered = "\n".join(_everything(response) for response in responses)
    assert not _leaks(logged), "a canary reached a log record"
    assert not _leaks(answered), "a canary reached a response"


# ---------------------------------------------------------------------------
# The 422 body and the refused target
# ---------------------------------------------------------------------------


def test_every_422_keeps_where_and_why_and_drops_the_input(auth_client: TestClient) -> None:
    """A body, a query and a path error each answer with ``type``, ``loc`` and ``msg`` only."""
    refused = [
        auth_client.post("/api/scans", json={"target": "https://example.com/", "max_pages": 10**6}),
        auth_client.get("/api/scans?limit=0"),
        auth_client.get("/api/scans/0"),
        auth_client.post("/api/auth/login", content=b"{not json", headers={"content-type": "x"}),
    ]
    assert [r.status_code for r in refused] == [422] * 4
    for response in refused:
        detail = response.json()["detail"]
        assert detail, response.text
        for error in detail:
            assert set(error) == {"type", "loc", "msg"}
            assert error["loc"] and error["msg"]
    # The first one would carry ``ctx`` ({"le": ...}) and ``input`` (1000000) by FastAPI's default.
    (too_many,) = refused[0].json()["detail"]
    assert too_many["loc"] == ["body", "max_pages"] and too_many["type"] == "less_than_equal"
    assert "1000000" not in refused[0].text


def test_a_target_with_a_credential_is_refused_and_not_stored(auth_client: TestClient) -> None:
    """The ``422`` names the field and the reason, repeats no part of the URL, and stores no row."""
    response = auth_client.post(
        "/api/scans", json={"target": "https://scan-user:scan-pass@target.example/app"}
    )
    assert response.status_code == 422
    (error,) = response.json()["detail"]
    assert error["loc"] == ["body"] and "carries a credential" in error["msg"]
    for part in ("scan-user", "scan-pass", "target.example"):
        assert part not in response.text
    assert auth_client.get("/api/scans").json()["items"] == []
    # Positive control: the same target without the credential is accepted and listed.
    assert auth_client.post("/api/scans", json={"target": "https://target.example/app"}).is_success
    (stored,) = auth_client.get("/api/scans").json()["items"]
    assert stored["target"] == "https://target.example/app"


def test_the_database_holds_no_canary_but_the_password_hash(
    canary_client: TestClient, web_config: WebConfig
) -> None:
    """The pinned key is never written; the password is stored only as its Argon2 hash."""
    assert canary_client.post(
        "/api/setup", json={"username": "admin", "password": _PASSWORD}
    ).is_success
    stored = Path(web_config.database_path).read_bytes()
    for wal in Path(web_config.database_path).parent.glob("*.db-wal"):
        stored += wal.read_bytes()
    assert b"$argon2" in stored  # positive control: the account was written
    for value in (_SIGNING_KEY, _PASSWORD):
        assert value.encode() not in stored
