"""
The stored-XSS pass: Phase A injection, Phase B re-crawl, and correlation — spec 008.

Two layers. The ``_detect`` tests feed synthetic markers and rendered pages
straight into the correlation function — no HTTP. The end-to-end tests drive the
real :class:`StoredXssScanner` against ``_Guestbook``, a tiny stateful
``httpx_mock`` router that stores a posted ``body`` and renders it back raw on a
per-entry page, so a marker submitted in Phase A really is found by the Phase B
re-crawl.
"""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

from tests.support import make_page
from webvigil.checks.injection import payloads
from webvigil.checks.injection.models import InjectionPoint, StoredMarker
from webvigil.checks.injection.stored import StoredXssScanner, _detect, _stored_order
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.target import Target
from webvigil.crawler.crawler import Crawler
from webvigil.crawler.forms import Form, FormField
from webvigil.http.client import HttpClient

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)

_TARGET = Target.parse("https://example.com/")


# ---------------------------------------------------------------------------
# _detect / _stored_hit — synthetic markers and pages
# ---------------------------------------------------------------------------


def _marker(
    token: str,
    *,
    method: str = "POST",
    base: str = "https://example.com/guestbook",
    param: str = "body",
    payloads: tuple[str, ...] | None = None,
) -> StoredMarker:
    """
    Args:
        token (str): The correlation token embedded in the marker.
        method (str): The injection point's method. Defaults to ``POST``.
        base (str): The injection point's base URL.
        param (str): The injected parameter name.
        payloads (tuple[str, ...] | None): The payload strings; a single
            ``<wvstored{token}>`` if omitted.

    Returns:
        StoredMarker: The marker as Phase A would have recorded it.
    """
    point = InjectionPoint(method, base, param, "", ((param, ""),), source="form")
    return StoredMarker(token, point, payloads or (f"<wvstored{token}>",))


def _rendered(url: str, text: str, *, content_type: str = "text/html") -> Page:
    """
    Args:
        url (str): The page URL.
        text (str): The page body.
        content_type (str): The response content type. Defaults to ``text/html``.

    Returns:
        Page: A page as the Phase B re-crawl would yield it.
    """
    return make_page(url=url, text=text, content_type=content_type)


def test_detect_flags_a_verbatim_marker_on_a_new_page() -> None:
    """A marker rendered verbatim on a page the injection did not touch is a stored hit."""
    marker = _marker("t1")
    page = _rendered("https://example.com/guestbook/e/0", "<html><div><wvstoredt1></div></html>")
    hits = _detect({"t1": marker}, [page], {})
    assert len(hits) == 1
    hit = hits[0]
    assert hit.kind == "xss-stored"
    assert (hit.method, hit.url, hit.param) == ("POST", "https://example.com/guestbook", "body")
    assert "guestbook/e/0" in dict(hit.evidence)["Rendered on"]


def test_detect_ignores_an_escaped_or_plain_text_marker() -> None:
    """An HTML-escaped marker, or one in a ``text/plain`` body, is not exploitable."""
    marker = _marker("t2")
    escaped = _rendered("https://example.com/g/e/0", "<div>&lt;wvstoredt2&gt;</div>")
    plain = _rendered("https://example.com/g/e/1", "<wvstoredt2>", content_type="text/plain")
    assert _detect({"t2": marker}, [escaped, plain], {}) == []


def test_detect_ignores_a_marker_already_in_the_pre_injection_body() -> None:
    """A marker string already present before injection is not attributed to us."""
    marker = _marker("t3")
    page = _rendered("https://example.com/known", "x <wvstoredt3> y")
    assert _detect({"t3": marker}, [page], {"https://example.com/known": "x <wvstoredt3> y"}) == []


def test_detect_a_marker_new_to_a_page_known_before_injection_is_a_hit() -> None:
    """A page the first crawl saw counts once the marker appears on it after the injection."""
    marker = _marker("t9")
    page = _rendered("https://example.com/known", "x <wvstoredt9> y")
    assert len(_detect({"t9": marker}, [page], {"https://example.com/known": "x y"})) == 1


def test_detect_same_url_is_a_hit_only_for_a_posted_point() -> None:
    """A marker echoed on its own URL counts for a POST point but not a GET one (reflection)."""
    get_marker = _marker("t4", method="GET", base="https://example.com/search", param="q")
    get_page = _rendered("https://example.com/search", "<div><wvstoredt4></div>")
    assert _detect({"t4": get_marker}, [get_page], {}) == []

    post_marker = _marker("t5")
    post_page = _rendered("https://example.com/guestbook", "<div><wvstoredt5></div>")
    assert len(_detect({"t5": post_marker}, [post_page], {})) == 1


def test_detect_reports_one_hit_with_a_count_for_a_multi_page_render() -> None:
    """A marker rendered on several pages is one hit whose evidence counts the extras."""
    marker = _marker("t6")
    pages = [
        _rendered("https://example.com/guestbook/e/0", "<div><wvstoredt6></div>"),
        _rendered("https://example.com/guestbook/e/1", "<div><wvstoredt6></div>"),
    ]
    hits = _detect({"t6": marker}, pages, {})
    assert len(hits) == 1
    assert "(+1 more page(s))" in dict(hits[0].evidence)["Rendered on"]


def test_every_stored_marker_carries_the_tag_the_page_scan_looks_for() -> None:
    """``_detect`` finds a page's markers by the ``<wvstored{token}>`` tag alone."""
    for template in payloads.STORED_MARKERS:
        assert "<wvstored{token}>" in template


def test_detect_with_many_markers_and_pages_finds_the_rendered_ones_in_marker_order() -> None:
    """Only the markers a page names are looked up; the hits keep the markers' order."""
    markers = {f"m{i}": _marker(f"m{i}", base=f"https://example.com/form/{i}") for i in range(200)}
    filler = "<p>" + "filler " * 2000 + "</p>"
    pages = [_rendered(f"https://example.com/p/{j}", filler) for j in range(50)]
    pages.append(
        _rendered("https://example.com/p/hit", "<div><wvstoredm123></div><div><wvstoredm7></div>")
    )
    hits = _detect(markers, pages, {})
    assert [hit.url for hit in hits] == [
        "https://example.com/form/7",
        "https://example.com/form/123",
    ]


# ---------------------------------------------------------------------------
# StoredXssScanner end to end — a stateful guestbook router
# ---------------------------------------------------------------------------


class _Guestbook:
    """
    A tiny stateful target: POST /guestbook stores ``body``; /guestbook/e/<i> renders it
    raw; GET /guestbook lists a link per stored entry. Every request is recorded on ``seen``.
    """

    def __init__(self, pages: dict[str, str]) -> None:
        self.pages = pages
        self.store: list[str] = []
        self.seen: list[tuple[str, str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        method, url = request.method, str(request.url)
        body = request.content.decode() if request.content else ""
        self.seen.append((method, url, body))
        html = {"content-type": "text/html; charset=utf-8"}
        if method == "POST" and url == "https://example.com/guestbook":
            self.store.append(parse_qs(body).get("body", [""])[0])
            return httpx.Response(302, headers={"location": "/guestbook"})
        if url == "https://example.com/guestbook":
            links = "".join(f'<a href="/guestbook/e/{i}">e{i}</a>' for i in range(len(self.store)))
            return httpx.Response(200, text=f"<html><body>{links}</body></html>", headers=html)
        if url.startswith("https://example.com/guestbook/e/"):
            entry = self.store[int(url.rsplit("/", 1)[1])]
            return httpx.Response(
                200, text=f"<html><body><div>{entry}</div></body></html>", headers=html
            )
        if url in self.pages:
            return httpx.Response(200, text=self.pages[url], headers=html)
        return httpx.Response(404, text="", headers={"content-type": "text/plain"})


_GB_FORM = Form(
    "POST",
    "https://example.com/guestbook",
    "application/x-www-form-urlencoded",
    (FormField("body", "textarea", ""),),
    "https://example.com/guestbook",
)
_GB_HTML = (
    '<html><body><form method="post" action="/guestbook">'
    '<textarea name="body"></textarea></form></body></html>'
)


async def _run(
    router: _Guestbook,
    pages: tuple[Page, ...],
    forms: tuple[Form, ...],
    httpx_mock: object,
    *,
    config: ScanConfig | None = None,
):
    """
    Run one stored-XSS pass against ``router``.

    Args:
        router (_Guestbook): The stateful response router.
        pages (tuple[Page, ...]): The first-crawl pages the pass starts from.
        forms (tuple[Form, ...]): The parsed forms Phase A submits markers into.
        httpx_mock: The ``httpx_mock`` fixture.
        config (ScanConfig | None): The scan config; a stored-XSS-enabled default
            if omitted.

    Returns:
        StoredXssReport: The pass's report.
    """
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    cfg = config or ScanConfig.model_validate({"injection": {"stored_xss": True}})
    async with HttpClient(_TARGET, cfg) as http:
        return await StoredXssScanner(http, _TARGET, cfg, pages, forms).run()


async def test_marker_is_found_on_the_per_entry_page_after_a_recrawl(httpx_mock: object) -> None:
    """End to end: a marker posted in Phase A is found on ``/guestbook/e/0`` by the re-crawl."""
    seed = '<html><body><a href="/guestbook">gb</a></body></html>'
    gb = _GB_HTML
    router = _Guestbook({"https://example.com/": seed, "https://example.com/guestbook": gb})
    pages = (
        make_page(url="https://example.com/", text=seed),
        make_page(url="https://example.com/guestbook", text=gb),
    )
    report = await _run(router, pages, (_GB_FORM,), httpx_mock)
    assert report.markers_submitted == 1
    assert len(report.hits) == 1
    hit = report.hits[0]
    assert (hit.kind, hit.method, hit.param) == ("xss-stored", "POST", "body")
    assert hit.url == "https://example.com/guestbook"
    assert "guestbook/e/0" in dict(hit.evidence)["Rendered on"]
    assert report.warnings == []  # no budget or page cap was reached


async def test_the_recrawl_charges_the_first_crawl_and_says_when_it_cut(
    httpx_mock: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the first crawl's crawler, the re-crawl spends its allowance and warns when cut."""
    from webvigil.crawler import crawler as crawler_mod

    monkeypatch.setattr(crawler_mod, "_MAX_RETAINED_TEXT_BYTES", 0)
    monkeypatch.setattr(crawler_mod, "_HEAD_CHARS", 10)
    seed = '<html><body><a href="/guestbook">gb</a></body></html>'
    router = _Guestbook({"https://example.com/": seed, "https://example.com/guestbook": _GB_HTML})
    pages = (
        make_page(url="https://example.com/", text=seed),
        make_page(url="https://example.com/guestbook", text=_GB_HTML),
    )
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    cfg = ScanConfig.model_validate({"injection": {"stored_xss": True}})
    async with HttpClient(_TARGET, cfg) as http:
        crawler = Crawler(http, _TARGET, cfg)
        report = await StoredXssScanner(
            http, _TARGET, cfg, pages, (_GB_FORM,), crawler=crawler
        ).run()
    assert crawler._text.spent > 0
    assert any(w.startswith("stored-XSS re-crawl: ") and "page text" in w for w in report.warnings)


async def test_an_escaped_guestbook_yields_no_hit(httpx_mock: object) -> None:
    """A guestbook that HTML-escapes the stored body renders no live marker — no hit."""
    gb = _GB_HTML

    class _Safe(_Guestbook):
        """A ``_Guestbook`` variant that HTML-escapes the entry before rendering it."""

        def __call__(self, request: httpx.Request) -> httpx.Response:
            resp = super().__call__(request)
            if request.method == "GET" and "/guestbook/e/" in str(request.url):
                import html as _html

                i = int(str(request.url).rsplit("/", 1)[1])
                safe = _html.escape(self.store[i])
                return httpx.Response(
                    200,
                    text=f"<html><body><div>{safe}</div></body></html>",
                    headers={"content-type": "text/html"},
                )
            return resp

    router = _Safe({"https://example.com/guestbook": gb})
    pages = (make_page(url="https://example.com/guestbook", text=gb),)
    report = await _run(router, pages, (_GB_FORM,), httpx_mock)
    assert report.markers_submitted == 1
    assert report.hits == []


async def test_form_points_are_submitted_before_query_points(httpx_mock: object) -> None:
    """Phase A submits form points before query points — the first marker request is the POST."""
    seed = _GB_HTML
    router = _Guestbook({"https://example.com/p": seed})
    pages = (
        make_page(url="https://example.com/p?x=1", text=seed),
        make_page(url="https://example.com/guestbook", text=seed),
    )
    await _run(router, pages, (_GB_FORM,), httpx_mock)
    marker_reqs = [m for m, u, b in router.seen if "wvstored" in u or "wvstored" in b]
    assert marker_reqs and marker_reqs[0] == "POST"


async def test_an_excluded_form_gets_no_marker(httpx_mock: object) -> None:
    """A login form is excluded from injection points, so no marker is ever posted to it."""
    login = Form(
        "POST",
        "https://example.com/login",
        "application/x-www-form-urlencoded",
        (FormField("q", "text", ""),),
        "https://example.com/login",
    )
    router = _Guestbook({})
    report = await _run(router, (), (login,), httpx_mock)
    assert report.markers_submitted == 0
    assert not any("wvstored" in b for _, _, b in router.seen)


async def test_request_budget_caps_phase_a(httpx_mock: object) -> None:
    """A tiny request budget bounds how many markers Phase A submits."""
    gb = '<form method="post" action="/guestbook"><textarea name="body"></textarea></form>'
    router = _Guestbook({"https://example.com/guestbook": gb})
    pages = (make_page(url="https://example.com/guestbook", text=gb),)
    cfg = ScanConfig.model_validate({"injection": {"stored_xss": True, "request_budget": 1}})
    report = await _run(router, pages, (_GB_FORM,), httpx_mock, config=cfg)
    assert report.markers_submitted == 1
    assert len([b for _, _, b in router.seen if "wvstored" in b]) == 1


async def test_recrawl_page_cap_warns(httpx_mock: object) -> None:
    """When the Phase B re-crawl hits the page cap it stops and warns."""
    gb = '<form method="post" action="/guestbook"><textarea name="body"></textarea></form>'
    router = _Guestbook(
        {"https://example.com/": "<a href='/x'>x</a>", "https://example.com/guestbook": gb}
    )
    pages = (
        make_page(url="https://example.com/", text="<a href='/x'>x</a>"),
        make_page(url="https://example.com/guestbook", text=gb),
    )
    cfg = ScanConfig.model_validate({"scan": {"max_pages": 1}, "injection": {"stored_xss": True}})
    report = await _run(router, pages, (_GB_FORM,), httpx_mock, config=cfg)
    assert any("1-page cap" in w for w in report.warnings)


def test_the_stored_pass_never_writes_into_a_select() -> None:
    """A ``<select>`` point is left out of the pass that writes markers (issue #190)."""
    text = InjectionPoint("POST", "https://example.com/a", "note", "", (), source="form")
    select = InjectionPoint(
        "POST", "https://example.com/a", "uid", "1", (), source="form", select=True
    )
    query = InjectionPoint("GET", "https://example.com/q", "q", "x", (), source="query")
    assert _stored_order([select, query, text]) == [text, query]


# ---------------------------------------------------------------------------
# _detect: what counts as a render, and how confident it is
# ---------------------------------------------------------------------------


def test_detect_a_get_point_marker_on_another_page_is_a_hit() -> None:
    """Only the GET point's own URL is reflection; any other page that renders it is storage."""
    marker = _marker("g1", method="GET", base="https://example.com/search", param="q")
    page = _rendered("https://example.com/recent", "<div><wvstoredg1></div>")
    (hit,) = _detect({"g1": marker}, [page], {})
    assert (hit.method, hit.url) == ("GET", "https://example.com/search")


def test_detect_compares_the_point_url_in_its_normal_form() -> None:
    """A GET point written with an upper-case host is still the page that reflects it."""
    marker = _marker("g2", method="GET", base="https://EXAMPLE.com:443/search", param="q")
    page = _rendered("https://example.com/search", "<div><wvstoredg2></div>")
    assert _detect({"g2": marker}, [page], {}) == []


def test_detect_needs_the_payload_itself_not_only_its_tag() -> None:
    """A page that dropped the ``">`` before the tag did not render the payload verbatim."""
    marker = _marker("t7", payloads=('"><wvstoredt7>',))
    page = _rendered("https://example.com/guestbook/e/0", "<div><wvstoredt7></div>")
    assert _detect({"t7": marker}, [page], {}) == []
    page = _rendered("https://example.com/guestbook/e/0", '<div>"><wvstoredt7></div>')
    assert len(_detect({"t7": marker}, [page], {})) == 1  # control


def test_detect_a_page_that_carries_both_payloads_is_one_render() -> None:
    """The second payload holds the first: the page counts once, with no extra pages."""
    marker = _marker("t8", payloads=("<wvstoredt8>", '"><wvstoredt8>'))
    page = _rendered("https://example.com/guestbook/e/0", '<div>"><wvstoredt8></div>')
    (hit,) = _detect({"t8": marker}, [page], {})
    assert dict(hit.evidence)["Rendered on"] == "https://example.com/guestbook/e/0"


def test_detect_confidence_follows_the_context_and_the_page() -> None:
    """HIGH off the point in the body or an attribute; MEDIUM in a script or on the point itself."""
    cases = (
        ("https://example.com/e/0", "<div>{m}</div>", "html body", "HIGH"),
        ("https://example.com/e/0", '<input value="{m}">', "attribute", "HIGH"),
        ("https://example.com/e/0", '<script>var x = "{m}";</script>', "script", "MEDIUM"),
        ("https://example.com/guestbook", "<div>{m}</div>", "html body", "MEDIUM"),
    )
    for url, body, context, confidence in cases:
        # the point is written with an upper-case host: only the normal form matches the page
        marker = _marker("c1", base="https://EXAMPLE.com/guestbook")
        (hit,) = _detect({"c1": marker}, [_rendered(url, body.format(m="<wvstoredc1>"))], {})
        assert dict(hit.evidence)["Reflection context"] == context, body
        assert hit.confidence.name == confidence, (url, body)


# ---------------------------------------------------------------------------
# StoredXssScanner: what Phase A sends, and when Phase B runs
# ---------------------------------------------------------------------------


async def test_phase_a_sends_every_marker_of_a_point(httpx_mock: object) -> None:
    """Both marker payloads go to the point, not only the first."""
    router = _Guestbook({"https://example.com/guestbook": _GB_HTML})
    pages = (make_page(url="https://example.com/guestbook", text=_GB_HTML),)
    report = await _run(router, pages, (_GB_FORM,), httpx_mock)
    posted = [b for m, _, b in router.seen if m == "POST"]
    assert len(posted) == len(payloads.STORED_MARKERS) == 2
    assert report.markers_submitted == 1


async def test_a_get_marker_counts_as_an_injection_request(httpx_mock: object) -> None:
    """A GET is idempotent, so only the crafted flag puts a query marker in the counter."""
    pages = (make_page(url="https://example.com/list?page=1", text="<html></html>"),)
    httpx_mock.add_callback(_Guestbook({}), is_reusable=True)  # type: ignore[attr-defined]
    cfg = ScanConfig.model_validate({"injection": {"stored_xss": True}})
    async with HttpClient(_TARGET, cfg) as http:
        report = await StoredXssScanner(http, _TARGET, cfg, pages, ()).run()
        crafted = http.stats.crafted_requests
    assert report.markers_submitted == 1
    assert crafted == len(payloads.STORED_MARKERS)


async def test_a_point_the_budget_refused_gets_no_marker(httpx_mock: object) -> None:
    """With one request, the form gets its first marker; the query point after it gets none."""
    router = _Guestbook({"https://example.com/guestbook": _GB_HTML})
    pages = (
        make_page(url="https://example.com/guestbook", text=_GB_HTML),
        make_page(url="https://example.com/list?page=1", text="<html></html>"),
    )
    cfg = ScanConfig.model_validate({"injection": {"stored_xss": True, "request_budget": 1}})
    report = await _run(router, pages, (_GB_FORM,), httpx_mock, config=cfg)
    assert report.markers_submitted == 1
    assert "active injection stopped at the 1-request budget" in report.warnings
    assert not any("page=" in u and "wvstored" in u for _, u, _ in router.seen)


async def test_no_marker_means_no_recrawl(httpx_mock: object) -> None:
    """With nothing submitted, Phase B does not fetch a single page."""
    login = Form(
        "POST",
        "https://example.com/login",
        "application/x-www-form-urlencoded",
        (FormField("q", "text", ""),),
        "https://example.com/login",
    )
    router = _Guestbook({"https://example.com/login": "<html></html>"})
    pages = (make_page(url="https://example.com/login", text="<html></html>"),)
    report = await _run(router, pages, (login,), httpx_mock)
    assert report.markers_submitted == 0
    assert report.pages_recrawled == 0
    assert router.seen == []


async def test_the_recrawl_frontier_leaves_out_a_page_that_failed(httpx_mock: object) -> None:
    """A first-crawl page with a transport error is not re-fetched; the pages that loaded are."""
    router = _Guestbook({"https://example.com/guestbook": _GB_HTML})
    pages = (
        make_page(url="https://example.com/guestbook", text=_GB_HTML),
        Page.failed("https://example.com/gone", "connection reset"),
    )
    await _run(router, pages, (_GB_FORM,), httpx_mock)
    fetched = {u for m, u, _ in router.seen if m == "GET"}
    assert "https://example.com/guestbook" in fetched  # control
    assert "https://example.com/gone" not in fetched


async def test_the_recrawl_is_capped_at_120_pages_and_at_least_one(
    httpx_mock: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``scan.max_pages`` sizes the re-crawl, between one page and ``_STORED_REFETCH_CAP``."""
    caps: list[int] = []

    async def recrawl(
        self: Crawler, frontier: object, *, should_fetch: object, max_fetches: int
    ) -> list[Page]:
        caps.append(max_fetches)
        return []

    monkeypatch.setattr(Crawler, "recrawl", recrawl)
    pages = (make_page(url="https://example.com/guestbook", text=_GB_HTML),)
    httpx_mock.add_callback(_Guestbook({}), is_reusable=True)  # type: ignore[attr-defined]
    for max_pages in (500, 120, 7, 0):
        cfg = ScanConfig.model_validate(
            {"scan": {"max_pages": max_pages}, "injection": {"stored_xss": True}}
        )
        async with HttpClient(_TARGET, cfg) as http:
            await StoredXssScanner(http, _TARGET, cfg, pages, (_GB_FORM,)).run()
    assert caps == [120, 120, 7, 1]


class _Refusing:
    """An HTTP client stand-in whose marker submissions fail with ``error``."""

    def __init__(self, error: Exception) -> None:
        """
        Args:
            error (Exception): What every request raises.
        """
        self.error = error
        self.calls = 0

    async def request(self, *args: object, **kwargs: object) -> object:
        """
        Raises:
            Exception: The configured error, on every call.
        """
        self.calls += 1
        raise self.error


async def test_a_failed_or_out_of_scope_submission_is_skipped() -> None:
    """A transport error or a redirect out of scope ends that marker set; the pass goes on."""
    from webvigil.core.errors import OutOfScopeError, RequestFailed

    cfg = ScanConfig.model_validate({"injection": {"stored_xss": True}})
    pages = (make_page(url="https://example.com/guestbook", text=_GB_HTML),)
    for error in (
        RequestFailed("https://example.com/guestbook", "reset"),
        OutOfScopeError("https://evil.test/"),
    ):
        http = _Refusing(error)
        # a stand-in: Phase A calls only ``request``, and nothing reaches Phase B
        scanner = StoredXssScanner(http, _TARGET, cfg, pages, (_GB_FORM,))  # type: ignore[arg-type]
        report = await scanner.run()
        assert http.calls == 1, error  # the first marker was tried, the second never was
        assert report.markers_submitted == 0
        assert report.pages_recrawled == 0
