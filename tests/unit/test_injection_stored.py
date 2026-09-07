"""The stored-XSS pass: Phase A injection, Phase B re-crawl, and correlation — spec 008."""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

from tests.support import make_page
from webvigil.checks.injection.models import InjectionPoint, StoredMarker
from webvigil.checks.injection.stored import StoredXssScanner, _detect
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.target import Target
from webvigil.crawler.forms import Form, FormField
from webvigil.http.client import HttpClient

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)

_TARGET = Target.parse("https://example.com/")


# --- _detect / _stored_hit (synthetic markers + pages) ----------------------------


def _marker(
    token: str,
    *,
    method: str = "POST",
    base: str = "https://example.com/guestbook",
    param: str = "body",
    payloads: tuple[str, ...] | None = None,
) -> StoredMarker:
    point = InjectionPoint(method, base, param, "", ((param, ""),), source="form")
    return StoredMarker(token, point, payloads or (f"<wvstored{token}>",))


def _rendered(url: str, text: str, *, content_type: str = "text/html") -> Page:
    return make_page(url=url, text=text, content_type=content_type)


def test_detect_flags_a_verbatim_marker_on_a_new_page() -> None:
    marker = _marker("t1")
    page = _rendered("https://example.com/guestbook/e/0", "<html><div><wvstoredt1></div></html>")
    hits = _detect({"t1": marker}, [page], {})
    assert len(hits) == 1
    hit = hits[0]
    assert hit.kind == "xss-stored"
    assert (hit.method, hit.url, hit.param) == ("POST", "https://example.com/guestbook", "body")
    assert "guestbook/e/0" in dict(hit.evidence)["Rendered on"]


def test_detect_ignores_an_escaped_or_plain_text_marker() -> None:
    marker = _marker("t2")
    escaped = _rendered("https://example.com/g/e/0", "<div>&lt;wvstoredt2&gt;</div>")
    plain = _rendered("https://example.com/g/e/1", "<wvstoredt2>", content_type="text/plain")
    assert _detect({"t2": marker}, [escaped, plain], {}) == []


def test_detect_ignores_a_marker_already_in_the_pre_injection_body() -> None:
    marker = _marker("t3")
    page = _rendered("https://example.com/known", "x <wvstoredt3> y")
    assert _detect({"t3": marker}, [page], {"https://example.com/known": "x <wvstoredt3> y"}) == []


def test_detect_same_url_is_a_hit_only_for_a_posted_point() -> None:
    get_marker = _marker("t4", method="GET", base="https://example.com/search", param="q")
    get_page = _rendered("https://example.com/search", "<div><wvstoredt4></div>")
    assert _detect({"t4": get_marker}, [get_page], {}) == []

    post_marker = _marker("t5")
    post_page = _rendered("https://example.com/guestbook", "<div><wvstoredt5></div>")
    assert len(_detect({"t5": post_marker}, [post_page], {})) == 1


def test_detect_reports_one_hit_with_a_count_for_a_multi_page_render() -> None:
    marker = _marker("t6")
    pages = [
        _rendered("https://example.com/guestbook/e/0", "<div><wvstoredt6></div>"),
        _rendered("https://example.com/guestbook/e/1", "<div><wvstoredt6></div>"),
    ]
    hits = _detect({"t6": marker}, pages, {})
    assert len(hits) == 1
    assert "(+1 more page(s))" in dict(hits[0].evidence)["Rendered on"]


# --- StoredXssScanner end to end (a stateful guestbook router) --------------------


class _Guestbook:
    """A tiny stateful target: POST /guestbook stores `body`; /guestbook/e/<i> renders raw."""

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
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    cfg = config or ScanConfig.model_validate({"injection": {"stored_xss": True}})
    async with HttpClient(_TARGET, cfg) as http:
        return await StoredXssScanner(http, _TARGET, cfg, pages, forms).run()


async def test_marker_is_found_on_the_per_entry_page_after_a_recrawl(httpx_mock: object) -> None:
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


async def test_an_escaped_guestbook_yields_no_hit(httpx_mock: object) -> None:
    gb = _GB_HTML

    class _Safe(_Guestbook):
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
    gb = '<form method="post" action="/guestbook"><textarea name="body"></textarea></form>'
    router = _Guestbook({"https://example.com/guestbook": gb})
    pages = (make_page(url="https://example.com/guestbook", text=gb),)
    cfg = ScanConfig.model_validate({"injection": {"stored_xss": True, "request_budget": 1}})
    report = await _run(router, pages, (_GB_FORM,), httpx_mock, config=cfg)
    assert report.markers_submitted == 1
    assert len([b for _, _, b in router.seen if "wvstored" in b]) == 1


async def test_recrawl_page_cap_warns(httpx_mock: object) -> None:
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
