"""
HttpClient: retries, scope guard, and manual redirect handling — RF-05, RF-04, RF-03.
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
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)


def _http(scope: Scope = Scope.HOST, *, cookies: list[str] | None = None) -> HttpClient:
    config = ScanConfig.model_validate({"auth": {"cookies": cookies}} if cookies else {})
    return HttpClient(Target.parse("https://example.com", scope=scope), config)


async def test_retries_then_succeeds(httpx_mock: object) -> None:
    httpx_mock.add_response(status_code=503)  # type: ignore[attr-defined]
    httpx_mock.add_response(status_code=200, text="ok")  # type: ignore[attr-defined]
    async with _http() as http:
        response = await http.get("https://example.com/")
    assert response.status_code == 200
    assert http.stats.retries == 1


async def test_retries_exhausted_raises_request_failed(httpx_mock: object) -> None:
    httpx_mock.add_exception(httpx.ConnectError("boom"), is_reusable=True)  # type: ignore[attr-defined]
    async with _http() as http:
        with pytest.raises(RequestFailed):
            await http.get("https://example.com/")
    assert http.stats.retries == 2


async def test_out_of_scope_get_raises_before_any_request(httpx_mock: object) -> None:
    async with _http() as http:
        with pytest.raises(OutOfScopeError):
            await http.get("https://evil.test/")
    assert http.stats.blocked_out_of_scope == 1
    assert http.stats.requests == 0


async def test_in_scope_redirect_is_followed(httpx_mock: object) -> None:
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


# --- spec 006: non-GET verbs and the method-aware retry policy (ADR-9, RF-15) ---


async def test_post_honours_the_scope_guard(httpx_mock: object) -> None:
    async with _http() as http:
        with pytest.raises(OutOfScopeError):
            await http.request("POST", "https://evil.test/", data={"x": "1"})
    assert http.stats.requests == 0


async def test_post_is_not_retried_on_a_5xx(httpx_mock: object) -> None:
    httpx_mock.add_response(status_code=503)  # type: ignore[attr-defined]
    async with _http() as http:
        response = await http.request("POST", "https://example.com/f", data={"x": "1"})
    assert response.status_code == 503
    assert http.stats.retries == 0
    assert http.stats.crafted_requests == 1


async def test_post_is_not_retried_on_a_read_timeout(httpx_mock: object) -> None:
    httpx_mock.add_exception(httpx.ReadTimeout("slow"))  # type: ignore[attr-defined]
    async with _http() as http:
        with pytest.raises(RequestFailed):
            await http.request("POST", "https://example.com/f", data={"x": "1"})
    assert http.stats.retries == 0


async def test_post_is_retried_on_a_pre_send_connect_error(httpx_mock: object) -> None:
    httpx_mock.add_exception(httpx.ConnectError("refused"), is_reusable=True)  # type: ignore[attr-defined]
    async with _http() as http:
        with pytest.raises(RequestFailed):
            await http.request("POST", "https://example.com/f", data={"x": "1"})
    assert http.stats.retries == 2


async def test_303_redirect_drops_the_body_and_method(httpx_mock: object) -> None:
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
    httpx_mock.add_response(  # type: ignore[attr-defined]
        url="https://example.com/a", status_code=307, headers={"location": "/b"}
    )
    httpx_mock.add_response(url="https://example.com/b", status_code=200)  # type: ignore[attr-defined]
    async with _http() as http:
        await http.request("POST", "https://example.com/a", data={"x": "1"})
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert sent[1].method == "POST"
    assert sent[1].read() == b"x=1"


# --- spec 007: static cookies on in-scope requests only (RF-01, RF-02, ADR-1) ---


async def test_configured_cookie_is_sent_on_a_target_host_request(httpx_mock: object) -> None:
    httpx_mock.add_response(status_code=200)  # type: ignore[attr-defined]
    async with _http(cookies=["session=abc123", "csrf=xyz"]) as http:
        await http.get("https://example.com/dashboard")
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert sent[0].headers["cookie"] == "session=abc123; csrf=xyz"


async def test_cookie_is_absent_on_an_out_of_scope_request(httpx_mock: object) -> None:
    httpx_mock.add_response(status_code=200)  # type: ignore[attr-defined]
    async with _http(cookies=["session=abc123"]) as http:
        await http.get("https://cdn.other.test/lib.js", allow_out_of_scope=True)
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert "cookie" not in sent[0].headers


async def test_no_cookie_configured_means_no_cookie_header(httpx_mock: object) -> None:
    httpx_mock.add_response(status_code=200)  # type: ignore[attr-defined]
    async with _http() as http:
        await http.get("https://example.com/")
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert "cookie" not in sent[0].headers


async def test_caller_cookie_header_is_kept_and_the_configured_value_appended(
    httpx_mock: object,
) -> None:
    httpx_mock.add_response(status_code=200)  # type: ignore[attr-defined]
    async with _http(cookies=["session=abc123"]) as http:
        await http.request("GET", "https://example.com/", headers={"cookie": "theme=dark"})
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert sent[0].headers["cookie"] == "theme=dark; session=abc123"
