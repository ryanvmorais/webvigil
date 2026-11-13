"""
A credential the caller passes itself does not follow a redirect to where credentials may not go.

The session tests send the automated login's cookies as an explicit ``Cookie`` header, and the
client follows in-scope redirects with the caller's headers. The scope can reach another subdomain
(``--scope subdomains``) or the plain ``http`` form of an ``https`` target, where
:meth:`~webvigil.core.target.Target.carries_credentials` says no credential goes. Nothing is mocked
but the network: each test lets the target answer with a redirect and reads what the client sent
on the next hop.
"""

from __future__ import annotations

import httpx
import pytest

from webvigil.core.config import ScanConfig
from webvigil.core.target import Scope, Target
from webvigil.http.client import HttpClient

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)

_START = "https://example.com/account"
_CREDENTIALS = {"cookie": "sid=abc123", "authorization": "Bearer tkn"}


def _client(scope: Scope = Scope.HOST, *, auth_headers: list[str] | None = None) -> HttpClient:
    """
    Args:
        scope (Scope): The target scope. Defaults to ``Scope.HOST``.
        auth_headers (list[str] | None): Configured ``[auth]`` headers, as ``Name: Value``.

    Returns:
        HttpClient: A client for ``https://example.com`` at ``scope``.
    """
    auth = {"headers": auth_headers} if auth_headers else {}
    config = ScanConfig.model_validate({"auth": auth} if auth else {})
    return HttpClient(Target.parse("https://example.com", scope=scope), config)


def _redirect_to(httpx_mock: object, location: str) -> None:
    """
    Answer the start URL with a redirect to ``location``, and ``location`` with a page.

    Args:
        httpx_mock (object): The ``pytest-httpx`` fixture.
        location (str): The redirect target.
    """
    httpx_mock.add_response(  # type: ignore[attr-defined]
        url=_START, status_code=302, headers={"location": location}
    )
    httpx_mock.add_response(url=location, status_code=200, text="ok")  # type: ignore[attr-defined]


def _hop(httpx_mock: object) -> httpx.Request:
    """
    Args:
        httpx_mock (object): The ``pytest-httpx`` fixture.

    Returns:
        httpx.Request: The request the client sent after the redirect.
    """
    sent = httpx_mock.get_requests()  # type: ignore[attr-defined]
    assert len(sent) == 2
    return sent[1]


async def test_a_redirect_to_another_subdomain_drops_the_callers_credentials(
    httpx_mock: object,
) -> None:
    """A sibling subdomain is in scope but gets no caller ``Cookie`` nor ``Authorization``."""
    _redirect_to(httpx_mock, "https://other.example.com/")
    async with _client(Scope.SUBDOMAINS) as http:
        await http.get(_START, headers=dict(_CREDENTIALS))
    hop = _hop(httpx_mock)
    assert "cookie" not in hop.headers
    assert "authorization" not in hop.headers


async def test_a_redirect_down_to_http_drops_the_callers_credentials(httpx_mock: object) -> None:
    """The ``http`` form of an ``https`` target gets no caller credential, even anonymous."""
    _redirect_to(httpx_mock, "http://example.com/login")
    async with _client() as http, http.anonymous():
        await http.get(_START, headers=dict(_CREDENTIALS))
    hop = _hop(httpx_mock)
    assert "cookie" not in hop.headers
    assert "authorization" not in hop.headers


async def test_a_configured_auth_header_passed_by_the_caller_is_dropped_too(
    httpx_mock: object,
) -> None:
    """A header named like a configured ``[auth]`` header is a credential on the hop."""
    _redirect_to(httpx_mock, "https://other.example.com/")
    async with _client(Scope.SUBDOMAINS, auth_headers=["X-Api-Key: k"]) as http:
        await http.get(_START, headers={"X-Api-Key": "k2", "Accept": "text/html"})
    hop = _hop(httpx_mock)
    assert "x-api-key" not in hop.headers
    assert hop.headers["accept"] == "text/html"


async def test_a_redirect_inside_the_target_origin_keeps_the_callers_credentials(
    httpx_mock: object,
) -> None:
    """On the target's own origin the caller's headers go on every hop, as before."""
    _redirect_to(httpx_mock, "https://example.com/home")
    async with _client(Scope.SUBDOMAINS) as http:
        await http.get(_START, headers=dict(_CREDENTIALS))
    hop = _hop(httpx_mock)
    assert hop.headers["cookie"] == "sid=abc123"
    assert hop.headers["authorization"] == "Bearer tkn"
