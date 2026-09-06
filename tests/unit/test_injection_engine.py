"""InjectionScanner: budget, gating, and one shared baseline per point — spec 006 RF-12."""

from __future__ import annotations

from collections.abc import Callable

import httpx

from tests.support import make_page
from webvigil.checks.injection.engine import InjectionScanner
from webvigil.core.config import InjectionSection
from webvigil.core.target import Target
from webvigil.crawler.forms import Form, FormField
from webvigil.http.client import Response

_TARGET = Target.parse("https://example.com/")


class _FakeHttp:
    def __init__(self, render: Callable[[str, dict[str, str]], Response]) -> None:
        self.render = render
        self.calls: list[dict[str, str]] = []

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: object = None,
        data: object = None,
        headers: object = None,
        allow_out_of_scope: bool = False,
        crafted: bool = False,
    ) -> Response:
        merged: dict[str, str] = {}
        merged.update(dict(params or []))  # type: ignore[arg-type]
        merged.update(data or {})  # type: ignore[arg-type]
        self.calls.append(merged)
        return self.render(url, merged)


def _resp(text: str = "<div>static</div>") -> Response:
    return Response(
        url="https://example.com/s",
        requested_url="https://example.com/s",
        status_code=200,
        headers=httpx.Headers({"content-type": "text/html"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _scanner(http: _FakeHttp, *, kinds: set[str], config: InjectionSection | None = None, **kw):
    page = make_page(url="https://example.com/s?q=1")
    return InjectionScanner(
        http,  # type: ignore[arg-type]
        _TARGET,
        config or InjectionSection(),
        (page,),
        (),
        kinds,
        **kw,
    )


async def test_budget_exhaustion_warns_and_stops() -> None:
    http = _FakeHttp(lambda url, p: _resp())
    page1 = make_page(url="https://example.com/a?x=1")
    page2 = make_page(url="https://example.com/b?y=1")
    scanner = InjectionScanner(
        http,  # type: ignore[arg-type]
        _TARGET,
        InjectionSection(request_budget=3),
        (page1, page2),
        (),
        {"xss", "sqli-error"},
    )
    report = await scanner.run()
    assert len(http.calls) == 3
    assert any("stopped at the 3-request budget" in w for w in report.warnings)


async def test_per_point_cap_limits_requests_for_one_point() -> None:
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"sqli-error"}, per_point_limit=2)
    await scanner.run()
    assert len(http.calls) == 2  # baseline + one payload, then the point cap bites


async def test_time_based_sqli_false_drops_the_detector() -> None:
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"sqli-time"}, config=InjectionSection(time_based_sqli=False))
    await scanner.run()
    assert "sqli-time" not in scanner.selected_kinds
    assert all("SLEEP" not in v for call in http.calls for v in call.values())


async def test_only_selected_kinds_run() -> None:
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"xss"})
    await scanner.run()
    # xss sends the plain probe, sees no reflection, stops — no SQL quote payloads
    assert all("'" not in v for call in http.calls for v in call.values())


async def test_one_baseline_per_point_shared_by_all_detectors() -> None:
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"xss", "traversal", "sqli-error"})
    await scanner.run()
    baseline_calls = [c for c in http.calls if c.get("q") == "1"]
    assert len(baseline_calls) == 1


async def test_form_points_are_posted() -> None:
    seen: list[str] = []

    def render(url: str, p: dict[str, str]) -> Response:
        seen.append(url)
        return _resp()

    http = _FakeHttp(render)
    form = Form("POST", "https://example.com/comment", "", (FormField("body", "text", ""),), "x")
    scanner = InjectionScanner(
        http,  # type: ignore[arg-type]
        _TARGET,
        InjectionSection(),
        (),
        (form,),
        {"xss"},
    )
    await scanner.run()
    assert seen and all(u == "https://example.com/comment" for u in seen)
