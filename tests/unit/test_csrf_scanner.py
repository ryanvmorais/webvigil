"""
The active CSRF confirmation pass — spec 017 RF-01..RF-08, RF-14.

``_FakeHttp`` stands in for the ``HttpClient``: ``get`` serves a fixed page (the form's
source page) and ``request`` hands the posted fields and headers to a ``_Server`` callable,
recording every call so the tests can assert exactly what the pass sent — the request
count, the ``Origin`` of the control versus the replays, and that a replay changes nothing
but the token. No network, no fixture app (that is ``test_scan_fixture_app.py``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl

import httpx
import pytest

from tests.support import make_page
from webvigil.checks.csrf import scanner as scanner_module
from webvigil.checks.csrf.scanner import (
    CsrfScanner,
    _alter,
    _build_body,
    _compare,
    _Shape,
)
from webvigil.core.config import ScanConfig
from webvigil.core.errors import RequestFailed
from webvigil.core.target import Target
from webvigil.crawler.forms import Form, parse_forms
from webvigil.http.client import RedirectHop, Response

_TARGET = Target.parse("https://example.com/")
_SOURCE = "https://example.com/"
_TOKEN_FORM = (
    '<form method="post" action="/settings"><input type="hidden" name="csrf_token" '
    'value="tok-abc123"><input name="display_name"></form>'
)
_PLAIN_FORM = '<form method="post" action="/newsletter"><input name="email" type="email"></form>'

type _Server = Callable[[dict[str, str], dict[str, str]], Response]


def _resp(
    text: str = "<p>ok</p>",
    *,
    status: int = 200,
    url: str = _SOURCE,
    history: tuple[RedirectHop, ...] = (),
) -> Response:
    """
    Args:
        text (str): The response body.
        status (int): The final status. Defaults to 200.
        url (str): The final URL. Defaults to the source page.
        history (tuple[RedirectHop, ...]): Redirect hops followed. Defaults to none.

    Returns:
        Response: An HTML response.
    """
    return Response(
        url=url,
        requested_url=url,
        status_code=status,
        headers=httpx.Headers({"content-type": "text/html"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
        history=history,
    )


def _inventory(html: str) -> tuple[Form, ...]:
    """
    Args:
        html (str): The body of the source page.

    Returns:
        tuple[Form, ...]: The forms ``parse_forms`` finds on it, as the crawler would.
    """
    return tuple(parse_forms(make_page(url=_SOURCE, text=html), _TARGET))


class _FakeHttp:
    """Serves the source page on ``get`` and routes every ``request`` through ``server``."""

    def __init__(self, page: str, server: _Server) -> None:
        """
        Args:
            page (str): The HTML served for every ``GET``.
            server (_Server): Called with the posted fields and headers.
        """
        self._page = page
        self._server = server
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict[str, str], dict[str, str]]] = []

    async def get(self, url: str, **_: Any) -> Response:
        """
        Args:
            url (str): The URL requested.
            **_ (Any): Ignored client options.

        Returns:
            Response: The fixed source page.
        """
        self.gets.append(url)
        return _resp(self._page)

    async def request(
        self,
        method: str,
        url: str,
        *,
        content: str | None = None,
        headers: dict[str, str] | None = None,
        crafted: bool = False,
        **_: Any,
    ) -> Response:
        """
        Args:
            method (str): The HTTP method; the pass only ever sends ``POST``.
            url (str): The URL posted to.
            content (str | None): The urlencoded body.
            headers (dict[str, str] | None): The extra headers.
            crafted (bool): Whether the pass marked it as a crafted request.
            **_ (Any): Ignored client options.

        Returns:
            Response: Whatever ``server`` answers.
        """
        assert method == "POST"
        assert crafted is True
        fields = dict(parse_qsl(content or "", keep_blank_values=True))
        self.posts.append((url, fields, dict(headers or {})))
        return self._server(fields, dict(headers or {}))


def _accepting(fields: dict[str, str], headers: dict[str, str]) -> Response:
    """
    Args:
        fields (dict[str, str]): The posted fields.
        headers (dict[str, str]): The request headers.

    Returns:
        Response: ``200 saved`` echoing the first field — a server with no CSRF defence.
    """
    echo = next(iter(fields.values()), "")
    return _resp(f"<h1>Saved</h1><p>thanks {echo}</p>")


def _enforcing(fields: dict[str, str], headers: dict[str, str]) -> Response:
    """
    Args:
        fields (dict[str, str]): The posted fields.
        headers (dict[str, str]): The request headers.

    Returns:
        Response: ``403`` unless ``csrf_token`` is the served value, else ``200``.
    """
    if fields.get("csrf_token") != "tok-abc123":
        return _resp("<p>no</p>", status=403)
    return _accepting(fields, headers)


def _origin_checking(fields: dict[str, str], headers: dict[str, str]) -> Response:
    """
    Args:
        fields (dict[str, str]): The posted fields.
        headers (dict[str, str]): The request headers.

    Returns:
        Response: ``403`` when ``Origin`` is not the target, else ``200`` (token ignored).
    """
    if headers.get("Origin") != "https://example.com":
        return _resp("<p>no</p>", status=403)
    return _accepting(fields, headers)


async def _run(page: str, server: _Server) -> tuple[CsrfScanner, _FakeHttp, list[Any]]:
    """
    Args:
        page (str): The source page HTML (also the form inventory).
        server (_Server): The fake target.

    Returns:
        tuple[CsrfScanner, _FakeHttp, list[Any]]: The scanner after ``run``, its fake
            client, and the hits.
    """
    http = _FakeHttp(page, server)
    scan = CsrfScanner(http, _TARGET, ScanConfig(), (), _inventory(page))  # type: ignore[arg-type]  # fake client
    hits = await scan.run()
    return scan, http, hits


# ---------------------------------------------------------------------------
# Candidate selection (RF-01, RF-02, RF-04)
# ---------------------------------------------------------------------------


def test_candidates_skip_by_reason() -> None:
    """File, multipart, auth, search and destructive forms are skipped; GET is not counted."""
    page = (
        '<form method="get" action="/s"><input name="term"></form>'
        '<form method="post" action="/a" enctype="multipart/form-data"><input name="x"></form>'
        '<form method="post" action="/b"><input type="file" name="f"></form>'
        '<form method="post" action="/login"><input name="user"></form>'
        '<form method="post" action="/search"><input name="q"></form>'
        '<form method="post" action="/items/delete"><input name="id"></form>'
        f"{_PLAIN_FORM}"
    )
    scan = CsrfScanner(None, _TARGET, ScanConfig(), (), _inventory(page))  # type: ignore[arg-type]
    testable, skipped, over_cap, posts = scan._candidates()
    assert [form.action for form in testable] == ["https://example.com/newsletter"]
    assert (skipped, over_cap, posts) == (5, 0, 6)


def test_candidates_deduplicate_the_same_form() -> None:
    """The same ``(method, action, field names)`` on two pages is one candidate."""
    forms = _inventory(_PLAIN_FORM) * 2
    scan = CsrfScanner(None, _TARGET, ScanConfig(), (), forms)  # type: ignore[arg-type]
    testable, _, _, posts = scan._candidates()
    assert len(testable) == 1 and posts == 1


def test_candidates_stop_at_the_form_cap() -> None:
    """Forms past the cap are counted as not tested, never silently dropped."""
    page = "".join(
        f'<form method="post" action="/f{i}"><input name="v"></form>'
        for i in range(scanner_module._MAX_FORMS + 3)
    )
    scan = CsrfScanner(None, _TARGET, ScanConfig(), (), _inventory(page))  # type: ignore[arg-type]
    testable, skipped, over_cap, _ = scan._candidates()
    assert (len(testable), skipped, over_cap) == (scanner_module._MAX_FORMS, 0, 3)


# ---------------------------------------------------------------------------
# Building the submission (RF-03, RF-06)
# ---------------------------------------------------------------------------


def test_build_body_field_table() -> None:
    """Defaults travel, empty text gets the sentinel, typed fallbacks apply, boxes behave."""
    page = (
        '<form method="post" action="/x">'
        '<input type="hidden" name="h" value="keep">'
        '<input name="t"><input type="email" name="e"><input type="url" name="u">'
        '<input type="number" name="n"><input type="password" name="p">'
        '<input type="checkbox" name="on" value="1" checked><input type="checkbox" name="off">'
        '<textarea name="body">typed</textarea>'
        '<input type="submit" name="go" value="Save"><input type="submit" name="other" value="x">'
        "</form>"
    )
    (form,) = _inventory(page)
    assert _build_body(form, sentinel="S") == [
        ("h", "keep"),
        ("t", "S"),
        ("e", "S@webvigil.invalid"),
        ("u", "https://webvigil.invalid/"),
        ("n", "1"),
        ("p", ""),
        ("on", "1"),
        ("go", "Save"),
        ("body", "typed"),  # the parser yields <textarea> after the <input>s
    ]


def test_build_body_changes_only_the_token() -> None:
    """Removing or altering the token leaves every other pair exactly as it was."""
    (form,) = _inventory(_TOKEN_FORM)
    control = _build_body(form, sentinel="S")
    assert control == [("csrf_token", "tok-abc123"), ("display_name", "S")]
    assert _build_body(form, sentinel="S", drop_tokens=True) == [("display_name", "S")]
    assert _build_body(form, sentinel="S", alter_tokens=True) == [
        ("csrf_token", "upl-bcd234"),
        ("display_name", "S"),
    ]


@pytest.mark.parametrize("value", ["tok-abc123", "Zz9", "a", "0", "----", ""])
def test_alter_keeps_the_length_and_always_differs(value: str) -> None:
    """The altered token is never equal to the original and never shorter."""
    altered = _alter(value)
    assert altered != value
    assert len(altered) >= len(value)
    if any(ch.isalnum() for ch in value):
        assert len(altered) == len(value)


# ---------------------------------------------------------------------------
# The experiment (RF-05, RF-06, RF-07)
# ---------------------------------------------------------------------------


async def test_token_ignored_is_confirmed_on_the_first_replay() -> None:
    """A server that ignores the token is confirmed by the removal replay; no further writes."""
    scan, http, hits = await _run(_TOKEN_FORM, _accepting)
    assert [hit.replay for hit in hits] == ["token removed"]
    assert hits[0].url == "https://example.com/settings"
    assert hits[0].token_fields == ("csrf_token",)
    assert len(http.gets) == 1 and len(http.posts) == 2  # fetch + control + one replay
    control, replay = http.posts
    assert control[2]["Origin"] == "https://example.com"
    assert control[2]["Referer"] == _SOURCE
    assert replay[2]["Origin"] == "https://webvigil.invalid"
    assert replay[2]["Referer"] == "https://webvigil.invalid/"
    assert control[2]["Content-Type"] == replay[2]["Content-Type"]
    assert "csrf_token" in control[1] and "csrf_token" not in replay[1]
    assert "1 form tested — 1 confirmed, 0 refuted, 0 inconclusive" in scan.warnings[0]


async def test_value_not_checked_is_confirmed_by_the_altered_replay() -> None:
    """A server that only checks the token's presence is caught by the altered replay."""

    def presence_only(fields: dict[str, str], headers: dict[str, str]) -> Response:
        if "csrf_token" not in fields:
            return _resp("<p>no</p>", status=403)
        return _accepting(fields, headers)

    _, http, hits = await _run(_TOKEN_FORM, presence_only)
    assert [hit.replay for hit in hits] == ["token altered"]
    assert len(http.posts) == 3
    assert http.posts[2][1]["csrf_token"] == "upl-bcd234"


async def test_enforced_token_is_refuted() -> None:
    """A server that rejects both replays is refuted: no hit, both replays were sent."""
    scan, http, hits = await _run(_TOKEN_FORM, _enforcing)
    assert hits == []
    assert len(http.posts) == 3
    assert "0 confirmed, 1 refuted, 0 inconclusive" in scan.warnings[0]


async def test_tokenless_form_gets_one_replay() -> None:
    """A form with no token field is replayed once, as the default body from a foreign origin."""
    _, http, hits = await _run(_PLAIN_FORM, _accepting)
    assert [hit.replay for hit in hits] == ["no token field"]
    assert hits[0].token_fields == ()
    assert len(http.posts) == 2
    assert http.posts[0][1].keys() == http.posts[1][1].keys()


async def test_origin_checking_server_is_refuted() -> None:
    """A token-ignoring server that checks ``Origin`` rejects the replay: not reported."""
    scan, _, hits = await _run(_TOKEN_FORM, _origin_checking)
    assert hits == []
    assert "1 refuted" in scan.warnings[0]


async def test_rejected_control_is_inconclusive_and_sends_no_replay() -> None:
    """When even the valid submission is refused there is nothing to compare a replay to."""
    _, http, hits = await _run(_TOKEN_FORM, lambda f, h: _resp("<p>no</p>", status=403))
    assert hits == []
    assert len(http.posts) == 1


async def test_source_page_without_the_form_is_inconclusive() -> None:
    """If the form is gone from the re-fetched page, no POST is sent."""
    http = _FakeHttp("<p>nothing here</p>", _accepting)
    scan = CsrfScanner(http, _TARGET, ScanConfig(), (), _inventory(_TOKEN_FORM))  # type: ignore[arg-type]
    assert await scan.run() == []
    assert http.posts == []
    assert "1 inconclusive" in scan.warnings[0]


async def test_failed_request_is_inconclusive() -> None:
    """A transport failure on the POST is inconclusive, not an error out of the pass."""

    def boom(fields: dict[str, str], headers: dict[str, str]) -> Response:
        raise RequestFailed(_SOURCE, "connection reset")

    scan, _, hits = await _run(_TOKEN_FORM, boom)
    assert hits == []
    assert "1 inconclusive" in scan.warnings[0]


async def test_a_redirect_after_post_is_described_and_compared() -> None:
    """``POST -> 302 -> /thanks`` for both control and replay confirms, and says so."""
    hop = (RedirectHop("https://example.com/newsletter", "https://example.com/thanks", 302),)

    def redirecting(fields: dict[str, str], headers: dict[str, str]) -> Response:
        return _resp("<h1>Thanks</h1>", url="https://example.com/thanks", history=hop)

    _, _, hits = await _run(_PLAIN_FORM, redirecting)
    assert hits[0].control == "POST /newsletter -> 302 -> /thanks (200)"
    assert hits[0].attack == hits[0].control


async def test_echoed_sentinel_and_token_do_not_make_responses_differ() -> None:
    """Each submission echoes its own sentinel; normalising it keeps the pages equivalent."""

    def echoing(fields: dict[str, str], headers: dict[str, str]) -> Response:
        return _resp(f"<p>hello {fields['display_name']} at 2026-10-06T12:00:01Z</p>")

    _, _, hits = await _run(_TOKEN_FORM, echoing)
    assert len(hits) == 1


async def test_no_post_form_means_no_summary_line() -> None:
    """The tally appears only when the inventory had a POST form."""
    scan, http, hits = await _run(
        '<form method="get" action="/s"><input name="term"></form>', _accepting
    )
    assert (hits, scan.warnings, http.gets, http.posts) == ([], [], [], [])


# ---------------------------------------------------------------------------
# The verdict (RF-07)
# ---------------------------------------------------------------------------


def _shape(
    *,
    first: int = 200,
    final: int = 200,
    path: str = "/x",
    body: str = "saved the thing",
    rejected: bool = False,
) -> _Shape:
    """
    Args:
        first (int): Status of the answer to the POST. Defaults to 200.
        final (int): Final status. Defaults to 200.
        path (str): Final path. Defaults to ``/x``.
        body (str): Normalised body. Defaults to a short sentence.
        rejected (bool): The rejection flag. Defaults to ``False``.

    Returns:
        _Shape: The shape.
    """
    return _Shape(first, final, path, body, rejected)


@pytest.mark.parametrize(
    "replay, verdict",
    [
        (_shape(), "confirmed"),
        (_shape(rejected=True, first=403, final=403), "refuted"),
        (_shape(first=302, final=200), "refuted"),  # different status class
        (_shape(path="/error"), "refuted"),  # different final path
        (
            _shape(body="please fix the highlighted field and try again, nothing was stored"),
            "inconclusive",
        ),
    ],
)
def test_compare_verdicts(replay: _Shape, verdict: str) -> None:
    """Equivalent confirms; rejection or a different class / path refutes; the rest is unsure."""
    assert _compare(_shape(), replay) == verdict


def test_one_extra_row_is_still_the_same_page() -> None:
    """A listing that grew by one row stays above the similarity threshold."""
    rows = " ".join(f"entry number {i} by someone" for i in range(60))
    assert (
        _compare(_shape(body=rows), _shape(body=rows + " entry number 60 by someone"))
        == "confirmed"
    )


async def test_a_hidden_token_input_is_not_a_rejection() -> None:
    """Rejection words are read from the visible text: the markup of a normal page is fine."""
    page = '<p>Saved</p><input type="hidden" name="csrf_token" value="zzz">'
    scan = CsrfScanner(None, _TARGET, ScanConfig(), (), ())  # type: ignore[arg-type]
    assert scan._shape(_resp(page), ()).rejected is False
    assert scan._shape(_resp("<p>CSRF token missing</p>"), ()).rejected is True
    assert scan._shape(_resp("<p>ok</p>", url="https://example.com/login"), ()).rejected is True
