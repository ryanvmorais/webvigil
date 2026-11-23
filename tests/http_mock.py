"""
The ``httpx_mock`` fixture: answers the engine's HTTP requests without a socket.

It replaces ``AsyncHTTPTransport.handle_async_request``, so a client built the normal way, with
the address guard installed, reaches this module instead of the network. It implements only what
the suite uses, and its contract is pinned by ``tests/unit/test_http_mock.py``.
"""

from __future__ import annotations

import contextlib
import copy
import inspect
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import httpx2
import pytest

Answer = Callable[[httpx2.Request], httpx2.Response | Awaitable[httpx2.Response | None] | None]
Headers = httpx2.Headers | Mapping[str, str] | Sequence[tuple[str, str]]


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def _params(url: httpx2.URL) -> dict[str, list[str]]:
    """
    Args:
        url (httpx2.URL): The URL to read.

    Returns:
        dict[str, list[str]]: Its query values by name, so the order of the names does not count
            and the order of a repeated name's values does.
    """
    return {name: url.params.get_list(name) for name in url.params}


def _same_url(expected: httpx2.URL, received: httpx2.URL) -> bool:
    """
    Args:
        expected (httpx2.URL): The URL of a registration.
        received (httpx2.URL): The URL of a request.

    Returns:
        bool: Whether they are equal, comparing the query parameters regardless of their order.
    """
    same_params = _params(expected) == _params(received)
    return same_params and expected.copy_with(query=None) == received.copy_with(query=None)


@dataclass
class _Registration:
    """
    One registered answer.

    Attributes:
        answer (Answer): Builds the response, or raises.
        url (httpx2.URL | None): The only URL it answers, or ``None`` for any.
        is_reusable (bool): Whether it may answer again once every match was used.
        uses (int): How many requests it was selected for.
    """

    answer: Answer
    url: httpx2.URL | None
    is_reusable: bool
    uses: int = 0

    def matches(self, request: httpx2.Request) -> bool:
        """
        Args:
            request (httpx2.Request): The request received.

        Returns:
            bool: Whether this registration may answer it.
        """
        return self.url is None or _same_url(self.url, request.url)


def _unread(response: httpx2.Response) -> httpx2.Response:
    """
    Args:
        response (httpx2.Response): A response built by a registration.

    Returns:
        httpx2.Response: The same response, unread, so the client streams it through its body cap.
    """
    response.is_stream_consumed = False
    response.is_closed = False
    if hasattr(response, "_content"):
        del response._content
    return response


# ---------------------------------------------------------------------------
# The mock
# ---------------------------------------------------------------------------


class HttpxMock:
    """Registered answers and the requests received during one test."""

    def __init__(self, *, assert_all_responses_were_requested: bool = True) -> None:
        """
        Args:
            assert_all_responses_were_requested (bool): Whether a registration never used fails
                the test. Defaults to ``True``.
        """
        self._require_all_used = assert_all_responses_were_requested
        self._registrations: list[_Registration] = []
        self._requests: list[httpx2.Request] = []
        self._unmatched: list[httpx2.Request] = []

    def add_response(
        self,
        status_code: int = 200,
        headers: Headers | None = None,
        content: bytes | None = None,
        text: str | None = None,
        json: Any = None,
        url: str | httpx2.URL | None = None,
        is_reusable: bool = False,
    ) -> None:
        """
        Register a response.

        Args:
            status_code (int): The status. Defaults to ``200``.
            headers (Headers | None): The response headers. Defaults to ``None``.
            content (bytes | None): A raw body. Defaults to ``None``.
            text (str | None): A text body. Defaults to ``None``.
            json (Any): A JSON body, copied now. Defaults to ``None``.
            url (str | httpx2.URL | None): The only URL it answers. Defaults to any.
            is_reusable (bool): Whether it may answer again. Defaults to ``False``.
        """
        body = copy.deepcopy(json)

        def respond(_request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(
                status_code=status_code,
                headers=headers,
                json=body,
                content=content,
                text=text,
            )

        self.add_callback(respond, url=url, is_reusable=is_reusable)

    def add_callback(
        self,
        callback: Answer,
        url: str | httpx2.URL | None = None,
        is_reusable: bool = False,
    ) -> None:
        """
        Register a callback that builds the response; returning ``None`` counts as no match.

        Args:
            callback (Answer): Receives the request; it may be a coroutine function.
            url (str | httpx2.URL | None): The only URL it answers. Defaults to any.
            is_reusable (bool): Whether it may answer again. Defaults to ``False``.
        """
        expected = httpx2.URL(url) if isinstance(url, str) else url
        self._registrations.append(_Registration(callback, expected, is_reusable))

    def add_exception(
        self,
        exception: BaseException,
        url: str | httpx2.URL | None = None,
        is_reusable: bool = False,
    ) -> None:
        """
        Register an exception to raise, attaching the request to a ``RequestError``.

        Args:
            exception (BaseException): The exception.
            url (str | httpx2.URL | None): The only URL it answers. Defaults to any.
            is_reusable (bool): Whether it may answer again. Defaults to ``False``.
        """

        def fail(request: httpx2.Request) -> httpx2.Response:
            if isinstance(exception, httpx2.RequestError):
                exception.request = request
            raise exception

        self.add_callback(fail, url=url, is_reusable=is_reusable)

    def get_requests(self) -> list[httpx2.Request]:
        """
        Returns:
            list[httpx2.Request]: Every request received, in order, with its body read.
        """
        return list(self._requests)

    def reset(self) -> None:
        """Forget the requests, the registrations and the unmatched requests."""
        self._requests.clear()
        self._registrations.clear()
        self._unmatched.clear()

    def verify(self) -> None:
        """
        Check the end-of-test rules.

        Raises:
            AssertionError: A registration was never used (unless allowed) or a request had no
                answer.
        """
        if self._require_all_used:
            unused = [str(item.url or "any URL") for item in self._registrations if not item.uses]
            assert not unused, f"Responses registered but never requested: {unused}"
        unmatched = [f"{item.method} {item.url}" for item in self._unmatched]
        assert not unmatched, f"Requests with no registered response: {unmatched}"

    @contextlib.contextmanager
    def patched(self) -> Iterator[HttpxMock]:
        """
        Route the transport to this mock, and verify it on a clean exit.

        Yields:
            HttpxMock: This mock.

        Raises:
            AssertionError: :meth:`verify` failed.
        """

        async def handle(_transport: httpx2.AsyncHTTPTransport, request: httpx2.Request) -> Any:
            return await self._handle(request)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(httpx2.AsyncHTTPTransport, "handle_async_request", handle)
            yield self
        self.verify()

    def _select(self, request: httpx2.Request) -> _Registration | None:
        """
        Args:
            request (httpx2.Request): The request received.

        Returns:
            _Registration | None: The first matching registration not yet used; when all were
                used, the last one if it is reusable; otherwise ``None``.
        """
        matching = [item for item in self._registrations if item.matches(request)]
        chosen = next((item for item in matching if not item.uses), None)
        if chosen is None and matching and matching[-1].is_reusable:
            chosen = matching[-1]
        if chosen is not None:
            chosen.uses += 1
        return chosen

    async def _handle(self, request: httpx2.Request) -> httpx2.Response:
        """
        Args:
            request (httpx2.Request): The request the client sent.

        Returns:
            httpx2.Response: The selected registration's response, unread.

        Raises:
            httpx2.TimeoutException: Nothing answers it, the failure the engine's retry path sees.
        """
        await request.aread()
        self._requests.append(request)
        registration = self._select(request)
        if registration is not None:
            response = registration.answer(request)
            if inspect.isawaitable(response):
                response = await response
            if response is not None:
                return _unread(response)
        self._unmatched.append(request)
        raise httpx2.TimeoutException(
            f"No response registered for {request.method} {request.url}", request=request
        )


@pytest.fixture
def httpx_mock(request: pytest.FixtureRequest) -> Iterator[HttpxMock]:
    """
    Args:
        request (pytest.FixtureRequest): Carries the optional ``httpx_mock`` marker.

    Yields:
        HttpxMock: The mock, active for the whole test and verified at teardown.
    """
    marker = request.node.get_closest_marker("httpx_mock")
    mock = HttpxMock(**marker.kwargs) if marker else HttpxMock()
    with mock.patched():
        yield mock
