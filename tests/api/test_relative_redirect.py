"""
A redirect of the Web API keeps the scheme the client used.

The app runs in process behind ``TestClient``, which plays a client that reached it through a proxy
by sending ``X-Forwarded-Proto``. No address is contacted and redirects are not followed.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.types import Receive, Scope, Send

from webvigil.api.app import create_app
from webvigil.api.config import WebConfig
from webvigil.api.redirects import RelativeRedirectMiddleware, relative_location


def test_a_trailing_slash_redirect_is_relative(web_config: WebConfig) -> None:
    """The ``307`` that would resend a login body names no scheme for the client to follow."""
    with TestClient(create_app(web_config)) as client:
        response = client.post(
            "/api/auth/login/?next=1",
            json={"username": "owner", "password": "not-a-real-password"},
            headers={"x-forwarded-proto": "https"},
            follow_redirects=False,
        )

    assert response.status_code == 307
    assert response.headers["location"] == "/api/auth/login?next=1"


def test_a_response_that_is_not_a_redirect_is_left_alone(web_config: WebConfig) -> None:
    """The control: the middleware touches only a redirect's ``Location``."""
    with TestClient(create_app(web_config)) as client:
        response = client.get("/api/health", follow_redirects=False)

    assert response.status_code == 200
    assert "location" not in response.headers


@pytest.mark.parametrize(("status", "expected"), [(302, "/a"), (201, "http://api.test/a")])
def test_only_a_redirect_has_its_location_rewritten(status: int, expected: str) -> None:
    """A ``201`` may name what it created in ``Location``; only a ``3xx`` is shortened."""

    async def answer(scope: Scope, receive: Receive, send: Send) -> None:
        headers = [(b"location", b"http://api.test/a")]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b""})

    client = TestClient(RelativeRedirectMiddleware(answer), base_url="http://api.test")
    response = client.get("/", follow_redirects=False)
    assert response.status_code == status
    assert response.headers["location"] == expected


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        (b"http://api.test/a", b"/a"),
        (b"http://API.test/a?b=1", b"/a?b=1"),
        (b"https://api.test/a#fragment", b"/a"),
    ],
)
def test_a_location_on_this_server_becomes_relative(location: bytes, expected: bytes) -> None:
    """Scheme, authority and fragment go; the path and the query stay."""
    assert relative_location(location, b"api.test") == expected


@pytest.mark.parametrize(
    "location",
    [
        b"https://other.test/a",
        b"http://api.test//other.test/a",
        b"http://api.test/\\other.test/a",
        b"/already/relative?a=1#top",
        b"http://api.test?a=1",
        b"http://[bad/",
    ],
    ids=["another-host", "double-slash", "backslash", "relative", "no-path", "malformed"],
)
def test_a_location_that_cannot_safely_stand_alone_is_kept(location: bytes) -> None:
    """Shortened, these would read as another host, or there is nothing to shorten."""
    assert relative_location(location, b"api.test") == location
