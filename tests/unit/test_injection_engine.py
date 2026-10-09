"""
InjectionScanner: budget, gating, and one shared baseline per point — spec 006 RF-12.

``_FakeHttp`` stands in for the HTTP client: it records every request's merged
params/body and returns whatever a ``render`` callable produces, so the tests
watch the scanner's request accounting and detector ordering without any real
HTTP. The detectors themselves are covered by the per-technique modules.

Audited under issue #101: the five per-spec "registered and mapped" tests and the five
"front-loaded" tests were two invariants repeated; they are now one registry-driven wiring test,
one ordering test and one table of front-loading cases (every old assertion is kept).
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
    _merge_el,
)
from webvigil.checks.injection.models import InjectionPoint
from webvigil.checks.registry import all_checks, load_plugins
from webvigil.core.config import InjectionSection
from webvigil.core.findings import Category
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


def _resp(text: str = "<div>static</div>", status: int = 200) -> Response:
    """
    Args:
        text (str): The response body. Defaults to a static, non-reflecting page.
        status (int): The response status. Defaults to 200.

    Returns:
        Response: A ``text/html`` response.
    """
    return Response(
        url="https://example.com/s",
        requested_url="https://example.com/s",
        status_code=status,
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
# Detector wiring, ordering and front-loading (specs 009, 011, 012, 014, 016)
# ---------------------------------------------------------------------------


def test_every_injection_check_is_wired_to_a_registered_detector() -> None:
    """Each scanner-fed injection check maps to a kind the table runs; both SSRF ids share one."""
    load_plugins()
    seen = set()
    for check in all_checks():
        kind = getattr(check, "kind", None)
        # stored XSS is fed by its own pass, not by a detector kind
        if check.category is not Category.INJECTION or kind in (None, "xss-stored"):
            continue
        expected = "ssrf" if kind.startswith("ssrf-") else kind
        assert KIND_BY_CHECK_ID[check.id] == expected, check.id
        assert expected in _DETECTORS, check.id
        seen.add(expected)
    # every detector in the table (but the merged entry) is reached by at least one check
    assert seen == set(_DETECTORS) - {"ssti+el"}
    assert "ssti+el" in _DETECTORS


def test_the_base_order_puts_slow_and_broad_detectors_last() -> None:
    """Fast 006 detectors first; the later families in spec order; ``ssrf`` is always last."""
    order = list(_BASE_ORDER)
    assert order[-1] == "ssrf"  # never starves the others on an unhelpfully-named point
    for kind in ("ssti", "cmdi", "crlf", "ldap", "xpath", "ssi"):
        assert order.index("xss") < order.index(kind) < order.index("ssrf"), kind
    # right after ssti, so it never starves the fast detectors nor sits behind the slow ones
    assert order.index("el") == order.index("ssti") + 1


# (a parameter name, the kinds selected, the kinds that must run first for it) — and a plain
# ``q`` point must get none of them first
_FRONT_LOADED = [
    ("callback", {"xss", "ssrf", "sqli-error"}, {"ssrf"}),
    ("host", {"xss", "cmdi", "ssti", "sqli-error"}, {"cmdi", "ssti"}),
    ("lang", {"xss", "crlf", "sqli-error"}, {"crlf"}),
    ("uid", {"xss", "ldap", "xpath", "ssi", "sqli-error"}, {"ldap"}),
    ("node", {"xss", "ldap", "xpath", "ssi", "sqli-error"}, {"xpath"}),
    ("tpl", {"xss", "ldap", "xpath", "ssi", "sqli-error"}, {"ssi"}),
    ("filter", {"xss", "ssti", "el", "sqli-error"}, {"ssti+el"}),
]


def test_a_matching_parameter_name_front_loads_its_detector() -> None:
    """A URL-, command-, header-, directory-, XPath-, template- or expression-shaped name wins."""
    http = _FakeHttp(lambda url, p: _resp())
    for name, kinds, first in _FRONT_LOADED:
        scanner = _scanner(http, kinds=kinds)
        point = InjectionPoint("GET", "https://example.com/p", name, "x", ((name, "x"),))
        assert set(scanner._ordered_kinds(point)[: len(first)]) == first, name
        plain = InjectionPoint("GET", "https://example.com/s", "q", "x", (("q", "x"),))
        assert not set(scanner._ordered_kinds(plain)[: len(first)]) & first, name


def test_ssrf_detector_absent_when_no_ssrf_kind_selected() -> None:
    """Without an SSRF kind selected the detector never appears in the order."""
    http = _FakeHttp(lambda url, p: _resp())
    scanner = _scanner(http, kinds={"xss"})
    point = InjectionPoint("GET", "https://example.com/s", "q", "x", (("q", "x"),))
    assert "ssrf" not in scanner._ordered_kinds(point)


def test_xxe_kind_is_dropped_unless_the_opt_in_is_on() -> None:
    """``xxe`` runs only when ``[injection] xxe`` is set."""
    http = _FakeHttp(lambda url, p: _resp())
    off = _scanner(http, kinds={"xxe"}, config=InjectionSection())
    assert "xxe" not in off.selected_kinds
    on = _scanner(http, kinds={"xxe"}, config=InjectionSection(xxe=True))
    assert "xxe" in on.selected_kinds


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


async def test_a_get_form_field_that_ships_empty_is_found_by_its_status_split() -> None:
    """A lookup form with an empty ``id`` (issue #143): a seeded TRUE page, a 404 for FALSE."""
    layout = "<html><body>" + "<p>layout</p>" * 300 + "{}</body></html>"

    def render(url: str, p: dict[str, str]) -> Response:
        value = p.get("id", "")
        matches = value.startswith("1") and "'1'='2" not in value and "1=2" not in value
        if matches:
            return _resp(layout.format("<pre>ID: 1 First name: admin</pre>"))
        return _resp(layout.format("<pre>ID: 1 </pre>"), status=404)

    form = Form(
        "GET",
        "https://example.com/vulnerabilities/sqli_blind/",
        "",
        (FormField("id", "text", ""), FormField("Submit", "submit", "Submit")),
        "x",
    )
    scanner = InjectionScanner(
        _FakeHttp(render),  # type: ignore[arg-type]
        _TARGET,
        InjectionSection(),
        (),
        (form,),
        {"sqli-boolean"},
    )
    report = await scanner.run()
    assert [(h.kind, h.param) for h in report.hits] == [("sqli-boolean", "id")]


# ---------------------------------------------------------------------------
# The ssti + el merge (spec 016)
# ---------------------------------------------------------------------------


def test_merge_el_collapses_both_kinds_at_the_earlier_position() -> None:
    """``ssti`` and ``el`` become one ``ssti+el`` entry; any other selection is untouched."""
    assert _merge_el(["xss", "ssti", "el", "crlf"]) == ["xss", "ssti+el", "crlf"]
    assert _merge_el(["el", "xss", "ssti"]) == ["ssti+el", "xss"]  # el was front-loaded
    assert _merge_el(["ssti", "xss", "el"]) == ["ssti+el", "xss"]
    assert _merge_el(["xss", "ssti"]) == ["xss", "ssti"]
    assert _merge_el(["xss", "el"]) == ["xss", "el"]
    assert _merge_el(["xss"]) == ["xss"]


def test_ordered_kinds_runs_the_detector_entry_that_matches_the_selected_checks() -> None:
    """Both checks give one ``ssti+el``; one check gives its own entry; neither gives neither."""
    http = _FakeHttp(lambda url, p: _resp())
    point = InjectionPoint("GET", "https://example.com/s", "q", "x", (("q", "x"),))
    both = _scanner(http, kinds={"xss", "ssti", "el", "sqli-error"})._ordered_kinds(point)
    assert both == ["xss", "sqli-error", "ssti+el"]
    assert _scanner(http, kinds={"xss", "ssti"})._ordered_kinds(point) == ["xss", "ssti"]
    assert _scanner(http, kinds={"xss", "el"})._ordered_kinds(point) == ["xss", "el"]
    assert _scanner(http, kinds={"xss"})._ordered_kinds(point) == ["xss"]
