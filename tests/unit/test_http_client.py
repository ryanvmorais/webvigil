"""
HttpClient: retries, scope guard, and manual redirect handling — RF-05, RF-04, RF-03.

All requests go through ``pytest-httpx``; the autouse ``_no_backoff`` fixture
zeroes the retry sleep so the retry tests are instant. ``http.stats`` is the
observable side channel — retries, blocked-out-of-scope, crafted requests — that
the assertions read.
"""

from __future__ import annotations

import httpx
import pytest

from webvigil.core.config import ScanConfig
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.target import Scope, Target
from webvigil.http import client as client_mod
from webvigil.http.client import HttpClient


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero the retry backoff so retry tests do not actually sleep."""
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)


def _http(
    scope: Scope = Scope.HOST,
    *,
    cookies: list[str] | None = None,
    headers: list[str] | None = None,
) -> HttpClient:
    """
    Args:
        scope (Scope): The target scope. Defaults to ``Scope.HOST``.
        cookies (list[str] | None): Static ``name=value`` cookies to configure.
        headers (list[str] | None): Static ``Name: Value`` ``[auth]`` headers
            to configure (spec 013).

    Returns:
        HttpClient: A client for ``https://example.com`` at ``scope``.
    """
    auth: dict[str, list[str]] = {}
    if cookies:
        auth["cookies"] = cookies
    if headers:
        auth["headers"] = headers
    config = ScanConfig.model_validate({"auth": auth} if auth else {})
    return HttpClient(Target.parse("https://example.com", scope=scope), config)


async def test_retries_then_succeeds(httpx_mock: object) -> None:
    """A 503 then a 200 is one retry and a success; the retry is counted."""
    httpx_mock.add_response(status_code=503)  # type: ignore[attr-defined]
    httpx_mock.add_response(status_code=200, text="ok")  # type: ignore[attr-defined]
    async with _http() as http:
        response = await http.get("https://example.com/")
    assert response.status_code == 200
    assert http.stats.retries == 1


async def test_retries_exhausted_raises_request_failed(httpx_mock: object) -> None:
    """A connect error on every attempt exhausts the two retries and raises ``RequestFailed``."""
    httpx_mock.add_exception(httpx.ConnectError("boom"), is_reusable=True)  # type: ignore[attr-defined]
    async with _http() as http:
        with pytest.raises(RequestFailed):
            await http.get("https://example.com/")
    assert http.stats.retries == 2


async def test_out_of_scope_get_raises_before_any_request(httpx_mock: object) -> None:
    """An off-scope GET is refused by the scope guard before a request goes out."""
    async with _http() as http:
        with pytest.raises(OutOfScopeError):
            await http.get("https://evil.test/")
    assert http.stats.blocked_out_of_scope == 1
    assert http.stats.requests == 0


async def test_in_scope_redirect_is_followed(httpx_mock: object) -> None:
    """An in-scope redirect is followed manually and recorded in ``response.history``."""
    httpx_mock.add_response(  # type: ignore[attr-defined]
        url="https://example.com/a", status_code=301, headers={"location": "/b"}
    )
    httpx_mock.add_response(url="https://example.com/b", status_code=200, text="done")  # type: ignore[attr-defined]
    async with _http() as http:
        response = await http.get("https://example.com/a")
    assert response.status_code == 200
    assert response.url == "https://example.com/b"
    assert len(response.history) == 1
    assert response.history[0].to_url == "https://example.com/b"


async def test_redirect_stops_at_cross_scope_hop(httpx_mock: object) -> None:
    """A redirect that leaves scope is not followed; the hop is flagged on the response."""
    httpx_mock.add_response(  # type: ignore[attr-defined]
        url="https://example.com/",
        status_code=302,
        headers={"location": "https://evil.test/"},
    )
    async with _http() as http:
        response = await http.get("https://example.com/")
    assert response.status_code == 302
    assert response.redirected_out_of_scope is True
    assert response.final_location == "https://evil.test/"


# ---------------------------------------------------------------------------
# Non-GET verbs and the method-aware retry policy (spec 006 ADR-9, RF-15)
# ---------------------------------------------------------------------------


async def test_post_honours_the_scope_guard(httpx_mock: object) -> None:
    """A POST is scope-guarded exactly like a GET."""
    async with _http() as http:
        with pytest.raises(OutOfScopeError):
            await http.request("POST", "https://evil.test/", data={"x": "1"})
    assert http.stats.requests == 0


async def test_post_is_not_retried_on_a_5xx(httpx_mock: object) -> None:
    """A non-idempotent POST is not retried on a 5xx; it counts as a crafted request."""
    httpx_mock.add_response(status_code=503)  # type: ignore[attr-defined]
    async with _http() as http:
        response = await http.request("POST", "https://example.com/f", data={"x": "1"})
    assert response.status_code == 503
    assert http.stats.retries == 0
    assert http.stats.crafted_requests == 1


async def test_post_is_not_retried_on_a_read_timeout(httpx_mock: object) -> None:
    """A read timeout on a POST may mean the request landed, so it is not retried."""
    httpx_mock.add_exception(httpx.ReadTimeout("slow"))  # type: ignore[attr-defined]
    async with _http() as http:
        with pytest.raises(RequestFailed):
            await http.request("POST", "https://example.com/f", data={"x": "1"})
    assert http.stats.retries == 0


async def test_post_is_retried_on_a_pre_send_connect_error(httpx_mock: object) -> None:
    """A pre-send connect error cannot have reached the server, so a POST is retried."""
    httpx_mock.add_exception(httpx.ConnectError("refused"), is_reusable=True)  # type: ignore[attr-defined]
    async with _http() as http:
        with pytest.raises(RequestFailed):
            await http.request("POST", "https://example.com/f", data={"x": "1"})
    assert http.stats.retries == 2


async def test_303_redirect_drops_the_body_and_method(httpx_mock: object) -> None:
    """A 303 turns the follow-up into a bodyless GET."""
    httpx_mock.add_response(  # type: ignore[attr-defined]
        url="https://example.com/a", status_code=303, headers={"location": "/done"}
    )
    httpx_mock.add_response(url="https://example.com/done", status_code=200)  # type: ignore[attr-defined]
    async with _http() as http:
        await http.request("POST", "https://example.com/a", data={"x": "1"})
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert sent[1].method == "GET"
    assert sent[1].read() == b""


async def test_307_redirect_keeps_the_body_and_method(httpx_mock: object) -> None:
    """A 307 replays the same method and body to the new location."""
    httpx_mock.add_response(  # type: ignore[attr-defined]
        url="https://example.com/a", status_code=307, headers={"location": "/b"}
    )
    httpx_mock.add_response(url="https://example.com/b", status_code=200)  # type: ignore[attr-defined]
    async with _http() as http:
        await http.request("POST", "https://example.com/a", data={"x": "1"})
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert sent[1].method == "POST"
    assert sent[1].read() == b"x=1"


# ---------------------------------------------------------------------------
# Static cookies on in-scope requests only (spec 007 RF-01, RF-02, ADR-1)
# ---------------------------------------------------------------------------


async def test_configured_cookie_is_sent_on_a_target_host_request(httpx_mock: object) -> None:
    """Configured cookies are joined and sent on a target-host request."""
    httpx_mock.add_response(status_code=200)  # type: ignore[attr-defined]
    async with _http(cookies=["session=abc123", "csrf=xyz"]) as http:
        await http.get("https://example.com/dashboard")
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert sent[0].headers["cookie"] == "session=abc123; csrf=xyz"


async def test_cookie_is_absent_on_an_out_of_scope_request(httpx_mock: object) -> None:
    """The session cookie is never attached to an out-of-scope request."""
    httpx_mock.add_response(status_code=200)  # type: ignore[attr-defined]
    async with _http(cookies=["session=abc123"]) as http:
        await http.get("https://cdn.other.test/lib.js", allow_out_of_scope=True)
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert "cookie" not in sent[0].headers


async def test_no_cookie_configured_means_no_cookie_header(httpx_mock: object) -> None:
    """With nothing configured there is no ``Cookie`` header at all."""
    httpx_mock.add_response(status_code=200)  # type: ignore[attr-defined]
    async with _http() as http:
        await http.get("https://example.com/")
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert "cookie" not in sent[0].headers


async def test_caller_cookie_header_is_kept_and_the_configured_value_appended(
    httpx_mock: object,
) -> None:
    """A caller-supplied ``Cookie`` header is kept and the configured cookie appended."""
    httpx_mock.add_response(status_code=200)  # type: ignore[attr-defined]
    async with _http(cookies=["session=abc123"]) as http:
        await http.request("GET", "https://example.com/", headers={"cookie": "theme=dark"})
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert sent[0].headers["cookie"] == "theme=dark; session=abc123"


# ---------------------------------------------------------------------------
# Static [auth] headers on in-scope requests only (spec 013 RF-03, RF-04)
# ---------------------------------------------------------------------------


async def test_configured_header_is_sent_on_a_target_host_request(httpx_mock: object) -> None:
    """Configured ``[auth]`` headers reach a target-host request."""
    httpx_mock.add_response(status_code=200)  # type: ignore[attr-defined]
    async with _http(headers=["Authorization: Bearer tkn", "X-Tenant: acme"]) as http:
        await http.get("https://example.com/api/me")
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert sent[0].headers["authorization"] == "Bearer tkn"
    assert sent[0].headers["x-tenant"] == "acme"


async def test_configured_header_is_absent_on_an_out_of_scope_request(httpx_mock: object) -> None:
    """An ``[auth]`` header is never attached to an out-of-scope request."""
    httpx_mock.add_response(status_code=200)  # type: ignore[attr-defined]
    async with _http(headers=["Authorization: Bearer tkn"]) as http:
        await http.get("https://cdn.other.test/lib.js", allow_out_of_scope=True)
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert "authorization" not in sent[0].headers


async def test_caller_header_wins_over_a_configured_auth_header(httpx_mock: object) -> None:
    """A header the caller set for the request is not overwritten by an ``[auth]`` entry."""
    httpx_mock.add_response(status_code=200)  # type: ignore[attr-defined]
    async with _http(headers=["Authorization: Bearer configured"]) as http:
        await http.request(
            "GET", "https://example.com/", headers={"authorization": "Bearer caller"}
        )
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert sent[0].headers["authorization"] == "Bearer caller"
