"""
The contract of the in-repository HTTP mock (spec 023, RF-10).

The suite trusts this mock in place of a real server, so each rule is pinned here, and each
failure has a passing twin. Requests go through a real ``httpx.AsyncClient``; nothing leaves the
process, because the transport method is replaced for the length of each ``patched()`` block.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest

from tests.http_mock import HttpxMock

_URL = "https://example.com/"
_OTHER = "https://example.com/other"


async def _get(url: str = _URL) -> httpx.Response:
    """
    Args:
        url (str): The URL to request. Defaults to ``_URL``.

    Returns:
        httpx.Response: The answer, read by a client built the normal way.
    """
    async with httpx.AsyncClient() as client:
        return await client.get(url)


async def _send_to_transport() -> httpx.Response:
    """
    Skip the client, which would attach the request to an exception on its own.

    Returns:
        httpx.Response: What the patched transport answers for a ``GET`` of ``_URL``.
    """
    async with httpx.AsyncHTTPTransport() as transport:
        return await transport.handle_async_request(httpx.Request("GET", _URL))


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


async def test_registrations_answer_in_the_order_they_were_added(httpx_mock: HttpxMock) -> None:
    httpx_mock.add_response(text="first")
    httpx_mock.add_response(text="second")

    assert [(await _get()).text, (await _get()).text] == ["first", "second"]


async def test_a_registration_for_another_url_is_skipped(httpx_mock: HttpxMock) -> None:
    httpx_mock.add_response(url=_OTHER, text="other")
    httpx_mock.add_response(url=_URL, text="wanted")

    assert (await _get(_URL)).text == "wanted"
    assert (await _get(_OTHER)).text == "other"


async def test_the_last_reusable_registration_answers_again(httpx_mock: HttpxMock) -> None:
    httpx_mock.add_response(text="once")
    httpx_mock.add_response(text="again", is_reusable=True)

    bodies = [(await _get()).text for _ in range(4)]

    assert bodies == ["once", "again", "again", "again"]


async def test_a_reusable_registration_that_is_not_the_last_does_not_answer_again() -> None:
    mock = HttpxMock()
    mock.add_response(text="reusable", is_reusable=True)
    mock.add_response(text="single")

    with pytest.raises(AssertionError, match="no registered response"), mock.patched():
        assert [(await _get()).text, (await _get()).text] == ["reusable", "single"]
        with pytest.raises(httpx.TimeoutException):
            await _get()


@pytest.mark.parametrize(
    ("registered", "requested"),
    [
        ("https://example.com/?a=1&b=2", "https://example.com/?b=2&a=1"),
        ("https://example.com/?a=1&a=2", "https://example.com/?a=1&a=2"),
    ],
)
async def test_the_url_match_ignores_the_order_of_query_names(
    httpx_mock: HttpxMock, registered: str, requested: str
) -> None:
    httpx_mock.add_response(url=registered, text="hit")

    assert (await _get(requested)).text == "hit"


@pytest.mark.parametrize(
    ("registered", "requested"),
    [
        ("https://example.com/?a=1&a=2", "https://example.com/?a=2&a=1"),
        ("https://example.com/?a=1", "https://example.com/?a=2"),
        ("https://example.com/?a=1", "https://example.com/"),
        ("https://example.com/a", "https://example.com/b"),
    ],
)
async def test_a_different_url_does_not_match(registered: str, requested: str) -> None:
    mock = HttpxMock(assert_all_responses_were_requested=False)
    mock.add_response(url=registered, text="hit")

    with (
        pytest.raises(AssertionError, match="no registered response"),
        mock.patched(),
        pytest.raises(httpx.TimeoutException),
    ):
        await _get(requested)


# ---------------------------------------------------------------------------
# Answers
# ---------------------------------------------------------------------------


async def test_a_response_carries_what_was_registered(httpx_mock: HttpxMock) -> None:
    httpx_mock.add_response(status_code=201, headers={"x-test": "1"}, content=b"body")

    response = await _get()

    assert (response.status_code, response.headers["x-test"], response.content) == (
        201,
        "1",
        b"body",
    )


async def test_a_json_body_is_copied_when_registered(httpx_mock: HttpxMock) -> None:
    payload = {"key": "registered"}
    httpx_mock.add_response(json=payload)
    payload["key"] = "changed later"

    assert (await _get()).json() == {"key": "registered"}


async def test_a_response_is_handed_back_unread(httpx_mock: HttpxMock) -> None:
    httpx_mock.add_response(content=b"streamed body")

    async with (
        httpx.AsyncClient() as client,
        client.stream("GET", _URL) as response,
    ):
        assert not response.is_stream_consumed
        with pytest.raises(httpx.ResponseNotRead):
            _ = response.content
        chunks = [chunk async for chunk in response.aiter_raw()]

    assert b"".join(chunks) == b"streamed body"


async def test_the_same_response_object_can_be_served_twice(httpx_mock: HttpxMock) -> None:
    shared = httpx.Response(200, content=b"shared")
    httpx_mock.add_callback(lambda _request: shared, is_reusable=True)

    assert [(await _get()).content, (await _get()).content] == [b"shared", b"shared"]


async def test_a_callback_receives_the_request(httpx_mock: HttpxMock) -> None:
    def echo(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=str(request.url))

    httpx_mock.add_callback(echo)

    assert (await _get(_OTHER)).text == _OTHER


async def test_an_async_callback_is_awaited(httpx_mock: HttpxMock) -> None:
    async def answer(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="awaited")

    httpx_mock.add_callback(answer)

    assert (await _get()).text == "awaited"


@pytest.mark.parametrize("is_async", [False, True])
async def test_a_callback_returning_none_counts_as_no_match(is_async: bool) -> None:
    async def later(_request: httpx.Request) -> None:
        return None

    mock = HttpxMock()
    mock.add_callback(later if is_async else (lambda _request: None))

    with (
        pytest.raises(AssertionError, match="no registered response"),
        mock.patched(),
        pytest.raises(httpx.TimeoutException),
    ):
        await _get()


async def test_an_exception_is_raised_with_the_request_attached(httpx_mock: HttpxMock) -> None:
    error = httpx.ConnectError("refused")
    httpx_mock.add_exception(error)

    with pytest.raises(httpx.ConnectError) as raised:
        await _send_to_transport()

    assert raised.value is error
    assert raised.value.request.url == _URL


async def test_an_exception_outside_httpx_is_raised_as_is(httpx_mock: HttpxMock) -> None:
    error = ValueError("not a request error")
    httpx_mock.add_exception(error)

    with pytest.raises(ValueError, match="not a request error") as raised:
        await _get()

    assert raised.value is error


# ---------------------------------------------------------------------------
# Recorded requests and reset
# ---------------------------------------------------------------------------


async def test_get_requests_lists_them_in_order_with_the_body_read(httpx_mock: HttpxMock) -> None:
    async def streamed_body() -> AsyncIterator[bytes]:
        yield b"fir"
        yield b"st"

    httpx_mock.add_response(is_reusable=True)

    async with httpx.AsyncClient() as client:
        await client.post(_URL, content=streamed_body())
        await client.post(_OTHER, content=b"second")

    assert [(str(r.url), r.content) for r in httpx_mock.get_requests()] == [
        (_URL, b"first"),
        (_OTHER, b"second"),
    ]


async def test_reset_forgets_requests_registrations_and_unmatched() -> None:
    mock = HttpxMock()
    mock.add_response(url=_URL)
    mock.add_response(url=_OTHER)

    with mock.patched():
        await _get(_URL)
        with pytest.raises(httpx.TimeoutException):
            await _get("https://example.com/unregistered")
        assert len(mock.get_requests()) == 2

        mock.reset()

        assert mock.get_requests() == []
        with pytest.raises(httpx.TimeoutException):
            await _get(_OTHER)  # its registration was still unused, and now it is gone
        mock.reset()  # the exit check passes: the unused and unmatched entries were forgotten


# ---------------------------------------------------------------------------
# End-of-test checks
# ---------------------------------------------------------------------------


async def test_an_unmatched_request_times_out_and_fails_the_test() -> None:
    mock = HttpxMock()

    with (
        pytest.raises(AssertionError, match=r"no registered response.*GET https://example"),
        mock.patched(),
    ):
        with pytest.raises(httpx.TimeoutException) as raised:
            await _send_to_transport()
        assert raised.value.request.url == _URL
        assert len(mock.get_requests()) == 1


async def test_a_matched_request_passes_the_end_of_test_check() -> None:
    mock = HttpxMock()
    mock.add_response()

    with mock.patched():
        await _get()


async def test_an_unused_registration_fails_the_test() -> None:
    mock = HttpxMock()
    mock.add_response(url=_URL)

    with pytest.raises(AssertionError, match="never requested"), mock.patched():
        pass


async def test_an_unused_registration_passes_when_allowed() -> None:
    mock = HttpxMock(assert_all_responses_were_requested=False)
    mock.add_response(url=_URL)

    with mock.patched():
        pass


async def test_an_unmatched_request_fails_even_when_unused_is_allowed() -> None:
    mock = HttpxMock(assert_all_responses_were_requested=False)

    with (
        pytest.raises(AssertionError, match="no registered response"),
        mock.patched(),
        pytest.raises(httpx.TimeoutException),
    ):
        await _get()


@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
def test_the_fixture_reads_the_marker(httpx_mock: HttpxMock) -> None:
    # With the marker ignored, this unused registration errors at this test's teardown.
    httpx_mock.add_response(url=_URL)


@pytest.mark.httpx_mock(unknown_option=True)
def test_the_marker_refuses_an_unknown_option(request: pytest.FixtureRequest) -> None:
    with pytest.raises(TypeError, match="unknown_option"):
        request.getfixturevalue("httpx_mock")


async def test_the_transport_is_restored_after_the_block() -> None:
    original = httpx.AsyncHTTPTransport.handle_async_request
    mock = HttpxMock()

    with mock.patched():
        assert httpx.AsyncHTTPTransport.handle_async_request is not original

    assert httpx.AsyncHTTPTransport.handle_async_request is original
