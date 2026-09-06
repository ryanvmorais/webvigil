"""HttpClient: retries, scope guard, and manual redirect handling — RF-05, RF-04, RF-03."""

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


def _http(scope: Scope = Scope.HOST) -> HttpClient:
    return HttpClient(Target.parse("https://example.com", scope=scope), ScanConfig())


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
