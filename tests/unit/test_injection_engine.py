"""
InjectionScanner: budget, gating, and one shared baseline per point — spec 006 RF-12.

``_FakeHttp`` stands in for the HTTP client: it records every request's merged
params/body and returns whatever a ``render`` callable produces, so the tests
watch the scanner's request accounting and detector ordering without any real
HTTP. The detectors themselves are covered by the per-technique modules.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from tests.support import make_page
from webvigil.checks.injection.engine import (
    _BASE_ORDER,
    _DETECTORS,
    KIND_BY_CHECK_ID,
    InjectionScanner,
)
from webvigil.checks.injection.models import InjectionPoint
from webvigil.core.config import InjectionSection
from webvigil.core.target import Target
from webvigil.crawler.forms import Form, FormField
from webvigil.http.client import Response

_TARGET = Target.parse("https://example.com/")


class _FakeHttp:
    """A fake HTTP client: every request's merged params + body land on ``calls``,
    and the response comes from the ``render`` callable given at construction."""

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
    """
    Args:
        text (str): The response body. Defaults to a static, non-reflecting page.

    Returns:
        Response: A 200 ``text/html`` response.
    """
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
    """
    Args:
        http (_FakeHttp): The fake HTTP client.
        kinds (set[str]): The detector kinds to select.
        config (InjectionSection | None): The injection config; a default one if omitted.
        **kw: Extra keyword arguments forwarded to :class:`InjectionScanner`.

    Returns:
        InjectionScanner: A scanner over one page with a single ``q=1`` query point.
    """
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


# ---------------------------------------------------------------------------
# Budget, gating, one baseline per point
# ---------------------------------------------------------------------------


async def test_budget_exhaustion_warns_and_stops() -> None:
    """Once the shared request budget is spent the scan stops and warns."""
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
    """The per-point cap bounds the requests spent on a single injection point."""
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"sqli-error"}, per_point_limit=2)
    await scanner.run()
    assert len(http.calls) == 2  # baseline + one payload, then the point cap bites


async def test_time_based_sqli_false_drops_the_detector() -> None:
    """``time_based_sqli=False`` removes the time-based detector before the scan runs."""
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"sqli-time"}, config=InjectionSection(time_based_sqli=False))
    await scanner.run()
    assert "sqli-time" not in scanner.selected_kinds
    assert all("SLEEP" not in v for call in http.calls for v in call.values())


async def test_only_selected_kinds_run() -> None:
    """A scan selecting only ``xss`` sends no SQLi payloads."""
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"xss"})
    await scanner.run()
    # xss sends the plain probe, sees no reflection, stops — no SQL quote payloads
    assert all("'" not in v for call in http.calls for v in call.values())


async def test_one_baseline_per_point_shared_by_all_detectors() -> None:
    """The baseline request for a point is taken once and shared across its detectors."""
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"xss", "traversal", "sqli-error"})
    await scanner.run()
    baseline_calls = [c for c in http.calls if c.get("q") == "1"]
    assert len(baseline_calls) == 1


# ---------------------------------------------------------------------------
# SSRF detector registration and ordering (spec 009)
# ---------------------------------------------------------------------------


def test_ssrf_is_registered_and_maps_both_check_ids() -> None:
    """The ``ssrf`` detector is registered, ordered last, and maps both SSRF check ids."""
    assert "ssrf" in _DETECTORS
    # last in the base order so it never starves the 006 detectors on an unhelpfully-named
    # point; front-loaded by _ordered_kinds for a URL-shaped one.
    assert _BASE_ORDER[-1] == "ssrf"
    assert KIND_BY_CHECK_ID["injection.ssrf.metadata"] == "ssrf"
    assert KIND_BY_CHECK_ID["injection.ssrf.internal"] == "ssrf"


def test_ssrf_is_front_loaded_for_a_url_shaped_point() -> None:
    """For a URL-shaped point ``ssrf`` runs first; for a plain point it does not."""
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"xss", "ssrf", "sqli-error"})
    url_point = InjectionPoint(
        "GET", "https://example.com/fetch", "callback", "x", (("callback", "x"),)
    )
    assert scanner._ordered_kinds(url_point)[0] == "ssrf"
    plain_point = InjectionPoint("GET", "https://example.com/s", "q", "x", (("q", "x"),))
    assert scanner._ordered_kinds(plain_point)[0] != "ssrf"


def test_ssrf_detector_absent_when_no_ssrf_kind_selected() -> None:
    """Without an SSRF kind selected the detector never appears in the order."""
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"xss"})
    point = InjectionPoint("GET", "https://example.com/s", "q", "x", (("q", "x"),))
    assert "ssrf" not in scanner._ordered_kinds(point)


# ---------------------------------------------------------------------------
# Command-injection and SSTI detector registration and ordering (spec 011)
# ---------------------------------------------------------------------------


def test_cmdi_and_ssti_are_registered_and_mapped() -> None:
    """Both new detectors are in the table and each check id maps to its kind."""
    assert "cmdi" in _DETECTORS and "ssti" in _DETECTORS
    assert KIND_BY_CHECK_ID["injection.cmdi.os"] == "cmdi"
    assert KIND_BY_CHECK_ID["injection.ssti"] == "ssti"
    # slow / broad detectors sit near the end, ahead of ssrf.
    assert _BASE_ORDER.index("cmdi") > _BASE_ORDER.index("xss")
    assert _BASE_ORDER.index("ssti") > _BASE_ORDER.index("xss")


def test_cmdi_and_ssti_are_front_loaded_for_a_command_shaped_point() -> None:
    """A ``host`` point front-loads ``cmdi`` / ``ssti``; a plain ``q`` point does not."""
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"xss", "cmdi", "ssti", "sqli-error"})
    host_point = InjectionPoint("GET", "https://example.com/ping", "host", "x", (("host", "x"),))
    assert set(scanner._ordered_kinds(host_point)[:2]) == {"cmdi", "ssti"}
    plain_point = InjectionPoint("GET", "https://example.com/s", "q", "x", (("q", "x"),))
    assert scanner._ordered_kinds(plain_point)[0] not in {"cmdi", "ssti"}


def test_time_sub_budget_is_enabled_by_time_based_cmdi_alone() -> None:
    """With ``time_based_sqli`` off but ``time_based_cmdi`` on, the sleep budget is non-zero."""
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(
        http,
        kinds={"cmdi"},
        config=InjectionSection(time_based_sqli=False, time_based_cmdi=True),
    )
    assert scanner._budget.time_based_limit > 0
    assert scanner._ctx.time_based_cmdi is True


async def test_form_points_are_posted() -> None:
    """A form injection point is exercised with POST requests to the form action."""
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
