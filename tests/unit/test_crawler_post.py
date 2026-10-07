"""
The crawler's POST phase — spec 018 RF-01..RF-08, RF-14.

``_FakeHttp`` stands in for the ``HttpClient``: ``get`` serves a URL -> body map (a 404 for
anything else, so ``robots.txt`` and the sitemaps are simply absent) and ``request`` records
every ``POST`` with its content, files and headers and answers from a second map, so the tests
assert exactly what the crawler sent, and in which order relative to the ``GET`` crawl. The real
:class:`Crawler` runs on top of it; no network and no fixture app (that is
``test_scan_fixture_app.py``).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl

import httpx
import pytest

from webvigil.core.config import ScanConfig
from webvigil.core.errors import RequestFailed
from webvigil.core.target import Target
from webvigil.crawler.crawler import Crawler
from webvigil.crawler.openapi import ApiOperation
from webvigil.http.client import RedirectHop, Response

_ROOT = "https://example.com/"
_TARGET = Target.parse(_ROOT)


def _resp(
    text: str = "<p>ok</p>",
    *,
    status: int = 200,
    url: str = _ROOT,
    content_type: str = "text/html",
    history: tuple[RedirectHop, ...] = (),
) -> Response:
    """
    Args:
        text (str): The body.
        status (int): The final status. Defaults to 200.
        url (str): The final URL. Defaults to the site root.
        content_type (str): The ``Content-Type``. Defaults to HTML.
        history (tuple[RedirectHop, ...]): Redirect hops followed. Defaults to none.

    Returns:
        Response: A response.
    """
    return Response(
        url=url,
        requested_url=url,
        status_code=status,
        headers=httpx.Headers({"content-type": content_type}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
        history=history,
    )


class _FakeHttp:
    """Serves ``pages`` on ``get``; records every ``request`` and answers from ``answers``."""

    def __init__(self, pages: dict[str, str], answers: dict[str, Response] | None = None) -> None:
        """
        Args:
            pages (dict[str, str]): URL -> HTML for ``GET``.
            answers (dict[str, Response] | None): URL -> the response to a ``POST``;
                anything else answers ``200 ok``.
        """
        self._pages = pages
        self._answers = answers or {}
        self.log: list[tuple[str, str]] = []  # ("GET" | "POST", url), in call order
        self.posts: list[dict[str, Any]] = []

    async def get(self, url: str, **_: Any) -> Response:
        """
        Args:
            url (str): The URL requested.
            **_ (Any): Ignored client options.

        Returns:
            Response: The page, or a ``404`` for an unknown URL.
        """
        self.log.append(("GET", url))
        if url in self._pages:
            return _resp(self._pages[url], url=url)
        return _resp("not found", status=404, url=url)

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        """
        Args:
            method (str): The method; the crawler only ever sends ``POST`` here.
            url (str): The URL posted to.
            **kwargs (Any): ``content`` / ``files`` / ``params`` / ``headers``.

        Returns:
            Response: The configured answer, or ``200 ok``.

        Raises:
            RequestFailed: When the configured answer is the string ``"fail"``.
        """
        assert method == "POST"
        self.log.append(("POST", url))
        self.posts.append({"url": url, **kwargs})
        answer = self._answers.get(url, _resp("<p>ok</p>", url=url))
        if answer is _FAIL:
            raise RequestFailed(url, "connection reset")
        return answer


_FAIL = _resp("fail")


def _config(**scan: Any) -> ScanConfig:
    """
    Args:
        **scan (Any): Overrides for ``[scan]``; the default is an Active scan with the
            POST phase on.

    Returns:
        ScanConfig: The configuration.
    """
    section = {"mode": "active", "submit_post_forms": True, "follow_robots": False, **scan}
    return ScanConfig.model_validate({"scan": section, "active": {"authorized_by": "test"}})


async def _crawl(
    http: _FakeHttp,
    config: ScanConfig | None = None,
    *,
    operations: tuple[ApiOperation, ...] = (),
) -> tuple[Crawler, list[Any]]:
    """
    Args:
        http (_FakeHttp): The fake target.
        config (ScanConfig | None): The configuration. Defaults to :func:`_config`.
        operations (tuple[ApiOperation, ...]): ``POST`` operations of an import.

    Returns:
        tuple[Crawler, list[Any]]: The crawler after ``discover`` and its pages.
    """
    crawler = Crawler(
        http,  # type: ignore[arg-type]  # fake client
        _TARGET,
        config or _config(),
        post_operations=operations,
    )
    return crawler, await crawler.discover()


def _form(action: str, *fields: str, enctype: str = "", method: str = "post") -> str:
    """
    Args:
        action (str): The form action.
        *fields (str): Field names, each a text input.
        enctype (str): The enctype attribute, or none.
        method (str): The method attribute. Defaults to ``post``.

    Returns:
        str: The ``<form>`` HTML.
    """
    inputs = "".join(f'<input name="{name}">' for name in fields)
    attr = f' enctype="{enctype}"' if enctype else ""
    return f'<form method="{method}" action="{action}"{attr}>{inputs}</form>'


def _operation(
    path: str,
    *,
    body_json: str | None = None,
    body_fields: tuple[tuple[str, str], ...] = (),
    query: tuple[tuple[str, str], ...] = (),
    operation_id: str = "",
) -> ApiOperation:
    """
    Args:
        path (str): The operation path.
        body_json (str | None): A synthesised JSON body, or none.
        body_fields (tuple[tuple[str, str], ...]): Synthesised urlencoded fields.
        query (tuple[tuple[str, str], ...]): Synthesised query parameters.
        operation_id (str): The ``operationId``. Defaults to none.

    Returns:
        ApiOperation: A ``POST`` operation.
    """
    return ApiOperation(
        method="POST",
        url=f"https://example.com{path}",
        url_template=f"https://example.com{path}",
        query=query,
        path_params=(),
        body_fields=body_fields,
        body_json=body_json,
        operation_id=operation_id,
    )


def _posted(http: _FakeHttp) -> list[str]:
    """
    Args:
        http (_FakeHttp): The fake target after a crawl.

    Returns:
        list[str]: The paths posted to, in order.
    """
    return [entry["url"].removeprefix("https://example.com") for entry in http.posts]


# ---------------------------------------------------------------------------
# The gate (RF-01)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scan",
    [
        {"mode": "passive"},  # switch on, wrong mode
        {"submit_post_forms": False},  # right mode, switch off
    ],
)
async def test_no_post_is_sent_unless_active_and_opted_in(scan: dict[str, Any]) -> None:
    """A Passive scan, or an Active scan without the switch, never POSTs."""
    http = _FakeHttp({_ROOT: _form("/contact", "msg")})
    crawler, pages = await _crawl(http, _config(**scan))
    assert http.posts == []
    assert crawler.post_summary is None
    assert [page.method for page in pages] == ["GET"]


# ---------------------------------------------------------------------------
# Candidate selection (RF-02, RF-03)
# ---------------------------------------------------------------------------


async def test_only_safe_post_forms_are_submitted_and_skips_are_counted() -> None:
    """File, text/plain, auth, search and destructive forms are skipped; GET is not counted."""
    page = (
        _form("/contact", "msg")
        + _form("/callback", "name", enctype="multipart/form-data")
        + '<form method="post" action="/avatar"><input type="file" name="f"></form>'
        + _form("/plain", "x", enctype="text/plain")
        + _form("/login", "user")
        + _form("/search", "q")
        + _form("/items/delete", "id")
        + _form("/lookup", "term", method="get")
    )
    http = _FakeHttp({_ROOT: page})
    crawler, _ = await _crawl(http)
    assert _posted(http) == ["/contact", "/callback"]
    assert crawler.post_summary is not None
    assert (crawler.post_summary.forms, crawler.post_summary.skipped) == (2, 5)


async def test_the_same_form_on_two_pages_is_submitted_once() -> None:
    """One submission per distinct ``(method, action, field names)``."""
    http = _FakeHttp(
        {
            _ROOT: '<a href="/b">b</a>' + _form("/contact", "msg"),
            f"{_ROOT}b": _form("/contact", "msg"),
        }
    )
    await _crawl(http)
    assert _posted(http) == ["/contact"]


async def test_a_robots_disallowed_action_is_skipped() -> None:
    """``robots.txt`` gates a submission as it gates a fetch."""
    http = _FakeHttp(
        {
            _ROOT: _form("/private/save", "x") + _form("/open/save", "x"),
            f"{_ROOT}robots.txt": "User-agent: *\nDisallow: /private/\n",
        }
    )
    crawler, _ = await _crawl(http, _config(follow_robots=True))
    assert _posted(http) == ["/open/save"]
    assert crawler.post_summary is not None and crawler.post_summary.skipped == 1


async def test_post_operations_follow_the_forms_and_unsafe_ones_are_skipped() -> None:
    """Forms first, then operations in document order; an auth operation is skipped."""
    http = _FakeHttp({_ROOT: _form("/contact", "msg")})
    ops = (_operation("/api/notes"), _operation("/api/session", operation_id="logout"))
    crawler, _ = await _crawl(http, operations=ops)
    assert _posted(http) == ["/contact", "/api/notes"]
    assert crawler.post_summary is not None
    assert (crawler.post_summary.forms, crawler.post_summary.operations) == (1, 1)
    assert crawler.post_summary.skipped == 1


# ---------------------------------------------------------------------------
# Phase order, the answers, the caps (RF-04, RF-06)
# ---------------------------------------------------------------------------


async def test_nothing_is_posted_before_the_get_queue_drains() -> None:
    """Every ``GET`` of the BFS happens before the first ``POST``."""
    http = _FakeHttp(
        {
            _ROOT: '<a href="/a">a</a><a href="/b">b</a>' + _form("/contact", "msg"),
            f"{_ROOT}a": "",
            f"{_ROOT}b": "",
        }
    )
    await _crawl(http)
    first_post = next(i for i, (verb, _) in enumerate(http.log) if verb == "POST")
    gets_after = [url for verb, url in http.log[first_post:] if verb == "GET"]
    assert {f"{_ROOT}a", f"{_ROOT}b"} <= {
        url for verb, url in http.log[:first_post] if verb == "GET"
    }
    assert gets_after == []


async def test_an_answer_is_a_post_page_and_its_links_resume_the_bfs() -> None:
    """The answer is kept as a ``POST`` page; a link on it is fetched and counted."""
    answer = _resp('<h1>Thanks</h1><a href="/status">status</a>', url="https://example.com/contact")
    http = _FakeHttp(
        {_ROOT: _form("/contact", "msg"), f"{_ROOT}status": "<p>status</p>"},
        {"https://example.com/contact": answer},
    )
    _, pages = await _crawl(http)
    assert [(page.url, page.method) for page in pages] == [
        (_ROOT, "GET"),
        ("https://example.com/contact", "POST"),
        (f"{_ROOT}status", "GET"),
    ]
    assert http.log.index(("POST", "https://example.com/contact")) < http.log.index(
        ("GET", f"{_ROOT}status")
    )


async def test_a_form_first_seen_on_an_answer_is_submitted_too() -> None:
    """A multi-step flow: step one's answer carries step two's form."""
    answer = _resp(_form("/step2", "city"), url="https://example.com/step1")
    http = _FakeHttp({_ROOT: _form("/step1", "name")}, {"https://example.com/step1": answer})
    await _crawl(http)
    assert _posted(http) == ["/step1", "/step2"]


async def test_a_redirect_after_post_keeps_the_final_page() -> None:
    """``POST -> 302 -> /received``: the page is the final one and says it was a POST."""
    hop = (RedirectHop("https://example.com/send", "https://example.com/received", 302),)
    answer = _resp("<p>received</p>", url="https://example.com/received", history=hop)
    http = _FakeHttp({_ROOT: _form("/send", "msg")}, {"https://example.com/send": answer})
    _, pages = await _crawl(http)
    assert (pages[1].url, pages[1].method, pages[1].history) == (
        "https://example.com/received",
        "POST",
        hop,
    )


async def test_the_submission_cap_stops_the_phase_and_counts_the_rest() -> None:
    """``max_post_submissions`` bounds the writes; the remainder is reported, not dropped."""
    http = _FakeHttp({_ROOT: _form("/a", "x") + _form("/b", "x") + _form("/c", "x")})
    crawler, _ = await _crawl(http, _config(max_post_submissions=1))
    assert _posted(http) == ["/a"]
    assert crawler.post_summary is not None and crawler.post_summary.over_cap == 2


async def test_max_pages_also_stops_the_phase() -> None:
    """The page cap is shared: with the seed alone filling it, nothing is submitted."""
    http = _FakeHttp({_ROOT: _form("/a", "x") + _form("/b", "x")})
    crawler, pages = await _crawl(http, _config(max_pages=1))
    assert http.posts == [] and len(pages) == 1
    assert crawler.post_summary is not None and crawler.post_summary.over_cap == 2


async def test_a_failed_submission_is_a_failed_post_page_and_counts() -> None:
    """A transport error becomes a failed ``POST`` page; the phase carries on."""
    http = _FakeHttp({_ROOT: _form("/a", "x") + _form("/b", "x")}, {"https://example.com/a": _FAIL})
    crawler, pages = await _crawl(http)
    failed = [page for page in pages if page.method == "POST" and not page.ok]
    assert [page.url for page in failed] == ["https://example.com/a"]
    assert _posted(http) == ["/a", "/b"]
    assert crawler.post_summary is not None and crawler.post_summary.forms == 2


async def test_an_error_answer_is_kept() -> None:
    """A ``500`` answer is a page: the disclosure checks want to read it."""
    answer = _resp("Traceback (most recent call last)", status=500, url="https://example.com/a")
    http = _FakeHttp({_ROOT: _form("/a", "x")}, {"https://example.com/a": answer})
    _, pages = await _crawl(http)
    assert (pages[1].status_code, pages[1].method, pages[1].ok) == (500, "POST", True)


# ---------------------------------------------------------------------------
# The bodies (RF-05)
# ---------------------------------------------------------------------------


async def test_an_urlencoded_form_sends_defaults_and_the_marker() -> None:
    """Defaults and a hidden token travel as served; an empty field gets ``wvcrawl``."""
    page = (
        '<form method="post" action="/contact">'
        '<input type="hidden" name="csrf_token" value="tok">'
        '<input name="msg"><input type="number" name="n"><input type="password" name="p">'
        "</form>"
    )
    http = _FakeHttp({_ROOT: page})
    await _crawl(http)
    (sent,) = http.posts
    assert sent["headers"] == {"Content-Type": "application/x-www-form-urlencoded"}
    fields = dict(parse_qsl(sent["content"], keep_blank_values=True))
    assert fields["csrf_token"] == "tok" and fields["n"] == "1" and fields["p"] == ""
    assert fields["msg"].startswith("wvcrawl") and "files" not in sent


async def test_a_multipart_form_sends_text_parts_and_no_file() -> None:
    """A no-file multipart form goes as ``files`` text parts with no filename."""
    http = _FakeHttp({_ROOT: _form("/cb", "name", "phone", enctype="multipart/form-data")})
    await _crawl(http)
    (sent,) = http.posts
    assert "content" not in sent
    assert [(name, part[0]) for name, part in sent["files"]] == [("name", None), ("phone", None)]
    assert all(str(part[1]).startswith("wvcrawl") for _, part in sent["files"])


@pytest.mark.parametrize(
    "op, content, content_type",
    [
        (_operation("/api/a", body_json='{"text": "x"}'), '{"text": "x"}', "application/json"),
        (
            _operation("/api/b", body_fields=(("k", "v"),)),
            "k=v",
            "application/x-www-form-urlencoded",
        ),
        (_operation("/api/c"), None, None),
    ],
)
async def test_an_api_operation_sends_its_synthesised_body(
    op: ApiOperation, content: str | None, content_type: str | None
) -> None:
    """JSON, urlencoded or no body, each with the matching ``Content-Type``."""
    http = _FakeHttp({_ROOT: "<p>home</p>"})
    await _crawl(http, operations=(op,))
    (sent,) = http.posts
    assert sent["content"] == content
    assert (sent["headers"] or {}).get("Content-Type") == content_type


async def test_an_operation_keeps_its_query_parameters() -> None:
    """The synthesised query goes as ``params``."""
    http = _FakeHttp({_ROOT: "<p>home</p>"})
    await _crawl(http, operations=(_operation("/api/q", query=(("page", "1"),)),))
    assert http.posts[0]["params"] == [("page", "1")]


# ---------------------------------------------------------------------------
# The summary (RF-08)
# ---------------------------------------------------------------------------


async def test_the_summary_line_and_its_absence() -> None:
    """One tally line when something happened; none when the phase had nothing to do."""
    http = _FakeHttp({_ROOT: _form("/contact", "msg") + _form("/login", "u")})
    crawler, _ = await _crawl(http, operations=(_operation("/api/n"),))
    assert crawler.post_summary is not None
    assert crawler.post_summary.warning() == (
        "POST crawl: 2 submitted — 1 form, 1 API operation, 1 skipped, 0 not submitted (cap)"
    )
    empty, _ = await _crawl(_FakeHttp({_ROOT: "<p>no forms</p>"}))
    assert empty.post_summary is not None and empty.post_summary.warning() is None
