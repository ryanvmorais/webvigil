"""
A credential the caller passes itself does not follow a redirect to where credentials may not go.

The session tests send the automated login's cookies as an explicit ``Cookie`` header, and the
client follows in-scope redirects with the caller's headers. The scope can reach another subdomain
(``--scope subdomains``) or the plain ``http`` form of an ``https`` target, where
:meth:`~webvigil.core.target.Target.carries_credentials` says no credential goes. Nothing is mocked
but the network: each test lets the target answer with a redirect and reads what the client sent
on the next hop. A ``307`` or ``308`` replays the body and the query parameters too, so the same
rule holds for that data, which may carry a credential.
"""

from __future__ import annotations

from typing import Any

import httpx2
import pytest

from webvigil.core.config import ScanConfig
from webvigil.core.target import Scope, Target
from webvigil.http.client import HttpClient

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)

_START = "https://example.com/account"
_CREDENTIALS = {"cookie": "sid=abc123", "authorization": "Bearer tkn"}


def _client(
    scope: Scope = Scope.HOST,
    *,
    auth_headers: list[str] | None = None,
    base: str = "https://example.com",
) -> HttpClient:
    """
    Args:
        scope (Scope): The target scope. Defaults to ``Scope.HOST``.
        auth_headers (list[str] | None): Configured ``[auth]`` headers, as ``Name: Value``.
        base (str): The target. Defaults to ``https://example.com``.

    Returns:
        HttpClient: A client for ``base`` at ``scope``.
    """
    auth = {"headers": auth_headers} if auth_headers else {}
    config = ScanConfig.model_validate({"auth": auth} if auth else {})
    return HttpClient(Target.parse(base, scope=scope), config)


def _redirect_to(httpx_mock: object, location: str) -> None:
    """
    Answer the start URL with a redirect to ``location``, and ``location`` with a page.

    Args:
        httpx_mock (object): The ``httpx_mock`` fixture.
        location (str): The redirect target.
    """
    httpx_mock.add_response(  # type: ignore[attr-defined]
        url=_START, status_code=302, headers={"location": location}
    )
    httpx_mock.add_response(url=location, status_code=200, text="ok")  # type: ignore[attr-defined]


def _hop(httpx_mock: object) -> httpx2.Request:
    """
    Args:
        httpx_mock (object): The ``httpx_mock`` fixture.

    Returns:
        httpx2.Request: The request the client sent after the redirect.
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


# ---------------------------------------------------------------------------
# A replayed body
# ---------------------------------------------------------------------------

_AUTH = ["X-Api-Key: k"]
_BODY = "marker=1"


def _replay_to(httpx_mock: Any, location: str, status: int = 307, start: str = _START) -> None:
    """
    Answer ``start`` with a redirect that keeps the method, and ``location`` with a page.

    Args:
        httpx_mock (Any): The ``httpx_mock`` fixture.
        location (str): The redirect target.
        status (int): The redirect status. Defaults to ``307``.
        start (str): The URL that redirects. Defaults to the start URL.
    """
    httpx_mock.add_response(url=start, status_code=status, headers={"location": location})
    httpx_mock.add_response(url=location, status_code=200, text="ok")


@pytest.mark.parametrize("status", [307, 308])
@pytest.mark.parametrize("location", ["http://example.com/next", "https://other.example.com/next"])
async def test_a_body_with_credentials_is_not_replayed_where_they_may_not_go(
    httpx_mock: Any, location: str, status: int
) -> None:
    """The redirect stops there and reads as one that left the scope; nothing more is sent."""
    _replay_to(httpx_mock, location, status)
    async with _client(Scope.SUBDOMAINS, auth_headers=_AUTH) as http:
        response = await http.request("POST", _START, content=_BODY)
    assert [str(r.url) for r in httpx_mock.get_requests()] == [_START]
    assert response.redirected_out_of_scope is True
    assert response.final_location == location
    assert response.status_code == status
    assert response.history == ()


@pytest.mark.parametrize(
    "body",
    [
        {"content": _BODY},
        {"data": {"marker": "1"}},
        {"files": {"upload": ("marker.txt", b"marker", "text/plain")}},
    ],
    ids=["content", "data", "files"],
)
async def test_every_kind_of_body_stays_home(httpx_mock: Any, body: dict[str, Any]) -> None:
    """A raw, a form and a multipart body are all held back."""
    _replay_to(httpx_mock, "http://example.com/next")
    async with _client(auth_headers=_AUTH) as http:
        response = await http.request("POST", _START, **body)
    assert len(httpx_mock.get_requests()) == 1
    assert response.redirected_out_of_scope is True


async def test_a_configured_cookie_counts_as_a_credential(httpx_mock: Any) -> None:
    """A scan whose only credential is an ``[auth]`` cookie holds the body back as well."""
    _replay_to(httpx_mock, "http://example.com/next")
    config = ScanConfig.model_validate({"auth": {"cookies": ["sid=marker"]}})
    async with HttpClient(Target.parse("https://example.com", scope=Scope.HOST), config) as http:
        response = await http.request("POST", _START, content=_BODY)
    assert len(httpx_mock.get_requests()) == 1
    assert response.redirected_out_of_scope is True


async def test_a_later_hop_of_the_chain_is_held_back_too(httpx_mock: Any) -> None:
    """A first hop inside the origin is followed; the next one, off it, stops the body."""
    inside = "https://example.com/step"
    outside = "http://example.com/next"
    httpx_mock.add_response(url=_START, status_code=307, headers={"location": inside})
    httpx_mock.add_response(url=inside, status_code=307, headers={"location": outside})
    httpx_mock.add_response(url=outside, status_code=200, text="ok")
    async with _client(auth_headers=_AUTH) as http:
        response = await http.request("POST", _START, content=_BODY)
    sent = httpx_mock.get_requests()
    assert [str(r.url) for r in sent] == [_START, inside]
    assert sent[1].content == _BODY.encode()
    assert response.final_location == outside
    assert len(response.history) == 1


async def test_a_scan_without_credentials_still_replays_its_body(httpx_mock: Any) -> None:
    """With nothing to protect, an in-scope ``307`` is followed with its body, as before."""
    location = "https://other.example.com/next"
    _replay_to(httpx_mock, location)
    async with _client(Scope.SUBDOMAINS) as http:
        response = await http.request("POST", _START, content=_BODY)
    hop = _hop(httpx_mock)
    assert (hop.method, str(hop.url), hop.content) == ("POST", location, _BODY.encode())
    assert response.redirected_out_of_scope is False


@pytest.mark.parametrize(
    ("base", "start", "location"),
    [
        ("https://example.com", _START, "https://example.com/next"),
        ("http://example.com", "http://example.com/account", "https://example.com/account"),
    ],
    ids=["same-origin", "https-upgrade"],
)
async def test_a_body_with_credentials_follows_to_where_they_may_go(
    httpx_mock: Any, base: str, start: str, location: str
) -> None:
    """The target origin and its ``https`` upgrade still get the replayed body."""
    _replay_to(httpx_mock, location, start=start)
    async with _client(auth_headers=_AUTH, base=base) as http:
        response = await http.request("POST", start, content=_BODY)
    hop = _hop(httpx_mock)
    assert (hop.method, str(hop.url), hop.content) == ("POST", location, _BODY.encode())
    assert response.redirected_out_of_scope is False


async def test_a_redirect_that_drops_the_body_is_still_followed(httpx_mock: Any) -> None:
    """A ``302`` becomes a bodyless ``GET``, so no credential travels and the hop goes ahead."""
    location = "http://example.com/next"
    _replay_to(httpx_mock, location, 302)
    async with _client(auth_headers=_AUTH) as http:
        response = await http.request("POST", _START, content=_BODY)
    hop = _hop(httpx_mock)
    assert (hop.method, str(hop.url), hop.content) == ("GET", location, b"")
    assert response.redirected_out_of_scope is False


async def test_a_bodyless_request_with_credentials_is_still_followed(httpx_mock: Any) -> None:
    """A ``307`` on a ``GET`` replays no body: only the headers are filtered."""
    location = "http://example.com/next"
    _replay_to(httpx_mock, location)
    async with _client(auth_headers=_AUTH) as http:
        response = await http.get(_START)
    hop = _hop(httpx_mock)
    assert (hop.method, str(hop.url)) == ("GET", location)
    assert "x-api-key" not in hop.headers
    assert response.redirected_out_of_scope is False


async def test_an_anonymous_request_still_replays_its_body(httpx_mock: Any) -> None:
    """An anonymous request sent no credential, so its body has none to keep home."""
    location = "http://example.com/next"
    _replay_to(httpx_mock, location)
    async with _client(auth_headers=_AUTH) as http, http.anonymous():
        response = await http.request("POST", _START, content=_BODY)
    assert _hop(httpx_mock).content == _BODY.encode()
    assert response.redirected_out_of_scope is False


async def test_a_body_sent_off_the_origin_keeps_following(httpx_mock: Any) -> None:
    """A request to a sibling subdomain carried no credential, so its redirect is followed."""
    start = "https://shop.example.com/cart"
    location = "https://other.example.com/next"
    _replay_to(httpx_mock, location, start=start)
    async with _client(Scope.SUBDOMAINS, auth_headers=_AUTH) as http:
        response = await http.request("POST", start, content=_BODY)
    assert _hop(httpx_mock).content == _BODY.encode()
    assert response.redirected_out_of_scope is False


# ---------------------------------------------------------------------------
# Replayed query parameters
# ---------------------------------------------------------------------------

_START_WITH_QUERY = f"{_START}?marker=1"


@pytest.mark.parametrize("status", [307, 308])
@pytest.mark.parametrize("params", [{"marker": "1"}, [("marker", "1")]], ids=["dict", "pairs"])
@pytest.mark.parametrize("location", ["http://example.com/next", "https://other.example.com/next"])
async def test_query_parameters_with_credentials_are_not_replayed_where_they_may_not_go(
    httpx_mock: Any, location: str, params: Any, status: int
) -> None:
    """A form sent by ``GET`` holds its pairs back like a body: nothing more is sent."""
    _replay_to(httpx_mock, location, status, start=_START_WITH_QUERY)
    async with _client(Scope.SUBDOMAINS, auth_headers=_AUTH) as http:
        response = await http.request("GET", _START, params=params)
    assert [str(r.url) for r in httpx_mock.get_requests()] == [_START_WITH_QUERY]
    assert response.redirected_out_of_scope is True
    assert response.final_location == location
    assert response.status_code == status
    assert response.history == ()


async def test_query_parameters_with_credentials_follow_to_where_they_may_go(
    httpx_mock: Any,
) -> None:
    """The target origin still gets the replayed pairs, so the guard above is not a blanket."""
    location = "https://example.com/next"
    httpx_mock.add_response(url=_START_WITH_QUERY, status_code=307, headers={"location": location})
    httpx_mock.add_response(url=f"{location}?marker=1", status_code=200, text="ok")
    async with _client(auth_headers=_AUTH) as http:
        response = await http.request("GET", _START, params={"marker": "1"})
    assert str(_hop(httpx_mock).url) == f"{location}?marker=1"
    assert response.redirected_out_of_scope is False


async def test_query_parameters_without_credentials_still_follow(httpx_mock: Any) -> None:
    """With nothing to protect, an in-scope ``307`` keeps its pairs, as before."""
    location = "https://other.example.com/next"
    httpx_mock.add_response(url=_START_WITH_QUERY, status_code=307, headers={"location": location})
    httpx_mock.add_response(url=f"{location}?marker=1", status_code=200, text="ok")
    async with _client(Scope.SUBDOMAINS) as http:
        response = await http.request("GET", _START, params={"marker": "1"})
    assert str(_hop(httpx_mock).url) == f"{location}?marker=1"
    assert response.redirected_out_of_scope is False


async def test_a_redirect_that_drops_the_parameters_is_still_followed(httpx_mock: Any) -> None:
    """A ``302`` leaves the pairs behind, so no data travels and the hop goes ahead."""
    location = "http://example.com/next"
    _replay_to(httpx_mock, location, 302, start=_START_WITH_QUERY)
    async with _client(auth_headers=_AUTH) as http:
        response = await http.request("GET", _START, params={"marker": "1"})
    assert str(_hop(httpx_mock).url) == location
    assert response.redirected_out_of_scope is False
