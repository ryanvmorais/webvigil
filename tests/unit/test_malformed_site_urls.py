"""
A URL from the scanned site that cannot be sent costs that URL, never the scan.

The real :class:`HttpClient` and :class:`Crawler` run over an in-process transport, so a URL that
is refused shows up as a request that never arrived. The system resolver is exercised with a stub
of ``socket.getaddrinfo`` that encodes the name as the real one does and performs no lookup.
"""

from __future__ import annotations

import socket
from typing import Any

import httpcore2
import httpx2
import pytest

from tests.support import HandlerTransport
from webvigil.core.config import ScanConfig
from webvigil.core.errors import RequestFailed
from webvigil.core.target import Scope, Target
from webvigil.crawler.crawler import Crawler
from webvigil.http import client as client_mod
from webvigil.http.addresses import system_resolver
from webvigil.http.client import HttpClient

_ORIGIN = "https://example.com"
_LONG_LABEL = "a" * 64
_LONGEST_LABEL = "a" * 63

# Each is in scope under ``--scope subdomains`` and cannot be sent, for a different reason.
_UNSENDABLE = [
    ("empty-label", "https://a..example.com/"),
    ("leading-dot", "https://.example.com/"),
    ("long-label", f"https://{_LONG_LABEL}.example.com/"),
    ("idna-refused", "https://--xn--.example.com/x"),
    ("idna-bad-codepoint", "https://%xn--%00.example.com/x"),
    ("unencodable-path", "https://a.example.com/\ud800"),
    ("unencodable-query", "https://a.example.com/?q=\ud800"),
]


def _site(asked: list[str], page: str = "<html><body>ok</body></html>") -> HandlerTransport:
    """
    Args:
        asked (list[str]): Filled with the URL of every request that arrives.
        page (str): The HTML of every page.

    Returns:
        HandlerTransport: A site that answers ``200`` to anything.
    """

    def answer(request: httpx2.Request) -> httpx2.Response:
        asked.append(str(request.url))
        return httpx2.Response(200, headers={"content-type": "text/html"}, text=page)

    return HandlerTransport(answer)


def _client(transport: httpx2.AsyncBaseTransport) -> HttpClient:
    """
    Args:
        transport (httpx2.AsyncBaseTransport): The site.

    Returns:
        HttpClient: A client for ``example.com`` and its subdomains.
    """
    target = Target.parse(f"{_ORIGIN}/", scope=Scope.SUBDOMAINS)
    return HttpClient(target, ScanConfig(), transport=transport)


@pytest.mark.parametrize("url", [c[1] for c in _UNSENDABLE], ids=[c[0] for c in _UNSENDABLE])
async def test_a_url_that_cannot_be_sent_is_a_controlled_failure(url: str) -> None:
    """Refused once, before any request, and not counted as a target that stopped answering."""
    asked: list[str] = []
    async with _client(_site(asked)) as http:
        with pytest.raises(RequestFailed) as caught:
            await http.get(url)

        assert caught.value.reason == "malformed URL"
        assert asked == []
        assert (http.stats.requests, http.stats.failed, http.stats.retries) == (0, 0, 0)
        await http.get(f"{_ORIGIN}/after")  # the control: the client still sends
        assert asked == [f"{_ORIGIN}/after"]


@pytest.mark.parametrize(
    "url",
    [
        f"https://{_LONGEST_LABEL}.example.com/",
        "https://a-b.example.com/",
        "https://xn--caf-dma.example.com/",
        "https://café.example.com/",
    ],
    ids=["longest-label", "hyphen", "punycode", "unicode-host"],
)
async def test_a_valid_host_is_still_sent(url: str) -> None:
    """The guard's near misses: every one reaches the site."""
    asked: list[str] = []
    async with _client(_site(asked)) as http:
        response = await http.get(url)

    assert response.status_code == 200
    assert len(asked) == 1


def test_one_final_dot_of_a_name_is_not_an_empty_label() -> None:
    """A fully qualified name is valid; a second final dot is an empty label."""
    assert client_mod._is_sendable("https://a.example.com./") is True
    assert client_mod._is_sendable("https://a.example.com../") is False


@pytest.mark.parametrize(
    "url",
    ["https://[::1]/", "https://192.0.2.1/"],
    ids=["ipv6", "ipv4"],
)
async def test_an_ip_literal_is_still_sent(url: str) -> None:
    """An address has no DNS label to refuse."""
    asked: list[str] = []
    target = Target.parse(url)
    async with HttpClient(target, ScanConfig(), transport=_site(asked)) as http:
        await http.get(url)

    assert len(asked) == 1


async def test_a_redirect_to_a_url_that_cannot_be_sent_costs_only_that_url() -> None:
    """The hop is refused with the same failure, after the first request."""
    asked: list[str] = []

    def answer(request: httpx2.Request) -> httpx2.Response:
        asked.append(str(request.url))
        return httpx2.Response(302, headers={"location": "https://a..example.com/"})

    async with _client(HandlerTransport(answer)) as http:
        with pytest.raises(RequestFailed) as caught:
            await http.get(f"{_ORIGIN}/start")

    assert caught.value.reason == "malformed URL"
    assert asked == [f"{_ORIGIN}/start"]


async def test_a_crawl_past_a_link_that_cannot_be_sent_reaches_the_next_one() -> None:
    """A bad subdomain link is one failed page; the link after it is still fetched."""
    asked: list[str] = []
    page = (
        '<html><body><a href="https://a..example.com/bad">bad</a>'
        '<a href="/good">good</a></body></html>'
    )
    target = Target.parse(f"{_ORIGIN}/", scope=Scope.SUBDOMAINS)
    config = ScanConfig().with_overrides(http={"delay_ms": 0})
    async with HttpClient(target, config, transport=_site(asked, page)) as http:
        pages = await Crawler(http, target, config).discover()

    assert f"{_ORIGIN}/good" in asked
    failed = [p for p in pages if not p.ok]
    assert [p.url for p in failed] == ["https://a..example.com/bad"]
    assert failed[0].error == (
        "request to https://a..example.com/bad failed: malformed URL"  # no library text
    )


# ---------------------------------------------------------------------------
# A defect is not taken for a bad URL
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error", [UnicodeError("defect"), ValueError("defect"), KeyError("defect")]
)
async def test_an_error_from_another_step_keeps_propagating(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    """Only the URL's own encoding is a controlled failure: a bug elsewhere stays visible."""

    def broken(*_args: object, **_kwargs: object) -> None:
        raise error

    asked: list[str] = []
    async with _client(_site(asked)) as http:
        monkeypatch.setattr(httpx2.AsyncClient, "build_request", broken)
        with pytest.raises(type(error)) as caught:
            await http.get(f"{_ORIGIN}/page")

    assert caught.value is error
    assert asked == []


def test_a_url_httpx_rejects_by_name_is_left_to_the_request_path() -> None:
    """``InvalidURL`` already has its own failure, which names it."""
    assert client_mod._is_sendable(f"https://example.com/{'a' * 70_000}") is True


async def test_a_url_httpx_rejects_is_reported_by_that_name() -> None:
    """The path the guard leaves alone still ends in a controlled failure."""
    asked: list[str] = []
    async with _client(_site(asked)) as http:
        with pytest.raises(RequestFailed) as caught:
            await http.get(f"{_ORIGIN}/{'a' * 70_000}")

    assert caught.value.reason == "InvalidURL"
    assert asked == []


# ---------------------------------------------------------------------------
# The system resolver
# ---------------------------------------------------------------------------


@pytest.fixture
def lookups(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """
    Replace the system lookup with one that encodes the name and resolves nothing real.

    Args:
        monkeypatch (pytest.MonkeyPatch): The fixture that restores the function.

    Returns:
        list[str]: The names that got past the encoding.
    """
    seen: list[str] = []

    def fake(host: str, port: int, *_args: Any, **_kwargs: Any) -> list[Any]:
        host.encode("idna")  # what the real function does before it asks the resolver
        seen.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return seen


@pytest.mark.parametrize("host", ["a..example.com", ".example.com", f"{_LONG_LABEL}.example.com"])
async def test_the_resolver_turns_an_invalid_name_into_a_connect_error(
    lookups: list[str], host: str
) -> None:
    """A fixed text, with neither the name nor the library's message, and no chained error."""
    with pytest.raises(httpcore2.ConnectError) as caught:
        await system_resolver(host, 443)

    assert str(caught.value) == "the host name is not a valid DNS name"
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
    assert lookups == []


async def test_the_resolver_still_resolves_a_valid_name(lookups: list[str]) -> None:
    """The control: the same stub answers for a name it can encode."""
    assert await system_resolver("a.example.com", 443) == ["192.0.2.1"]
    assert lookups == ["a.example.com"]


async def test_the_resolver_keeps_reporting_a_lookup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A name that does not resolve is still a connect error, chained to its cause."""

    def fail(*_args: Any, **_kwargs: Any) -> list[Any]:
        raise socket.gaierror("no such name")

    monkeypatch.setattr(socket, "getaddrinfo", fail)

    with pytest.raises(httpcore2.ConnectError) as caught:
        await system_resolver("a.example.com", 443)

    assert isinstance(caught.value.__cause__, socket.gaierror)
