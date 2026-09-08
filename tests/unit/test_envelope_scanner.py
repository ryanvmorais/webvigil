"""
The request-envelope pass — spec 012 RF-03, RF-05, RF-15.

``_FakeHttp`` records every ``(method, url, headers)`` and returns whatever a
``route`` callable produces. The tests watch the Host-poisoning and OPTIONS /
TRACE probes without any real HTTP — and assert the pass never sends a
state-changing verb.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from tests.support import make_page
from webvigil.checks.envelope.scanner import EnvelopeScanner
from webvigil.core.config import ScanConfig
from webvigil.core.findings import Severity
from webvigil.core.target import Target
from webvigil.crawler.forms import Form, FormField
from webvigil.http.client import Response

_TARGET = Target.parse("https://example.com/")


class _FakeHttp:
    def __init__(self, route: Callable[[str, str, dict[str, str]], Response]) -> None:
        self.route = route
        self.calls: list[tuple[str, str, dict[str, str]]] = []

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: object = None,
        data: object = None,
        content: object = None,
        headers: dict[str, str] | None = None,
        allow_out_of_scope: bool = False,
        crafted: bool = False,
    ) -> Response:
        self.calls.append((method.upper(), url, dict(headers or {})))
        return self.route(method.upper(), url, dict(headers or {}))


def _resp(
    text: str = "ok", *, status: int = 200, headers: dict[str, str] | None = None
) -> Response:
    return Response(
        url="https://example.com/",
        requested_url="https://example.com/",
        status_code=status,
        headers=httpx.Headers(headers or {"content-type": "text/html"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _scanner(http: _FakeHttp, *, pages: tuple = (), forms: tuple = ()) -> EnvelopeScanner:
    return EnvelopeScanner(http, _TARGET, ScanConfig(), pages or (make_page(),), forms)


async def test_sentinel_in_location_is_a_high_host_header_hit() -> None:
    """A poisoned Host reflected in the ``Location`` header is HIGH."""

    def route(method: str, url: str, headers: dict[str, str]) -> Response:
        if headers.get("Host") == "webvigil.invalid":
            return _resp(status=302, headers={"location": "https://webvigil.invalid/next"})
        return _resp()

    http = _FakeHttp(route)
    hits = await _scanner(http).run()
    hh = [h for h in hits if h.check_id == "injection.host-header"]
    assert hh and hh[0].severity is Severity.HIGH
    assert hh[0].param == "Host"


async def test_sentinel_in_a_reset_link_is_high_otherwise_medium() -> None:
    """A sentinel in a plain canonical tag is MEDIUM; in a reset link it is HIGH."""

    def canon(method: str, url: str, headers: dict[str, str]) -> Response:
        if headers.get("X-Forwarded-Host") == "webvigil.invalid":
            return _resp('<link rel="canonical" href="https://webvigil.invalid/">')
        return _resp()

    hits = await _scanner(_FakeHttp(canon)).run()
    hh = [h for h in hits if h.check_id == "injection.host-header"]
    assert hh and hh[0].severity is Severity.MEDIUM
    assert hh[0].param == "X-Forwarded-Host"

    def reset(method: str, url: str, headers: dict[str, str]) -> Response:
        if "webvigil.invalid" in " ".join(headers.values()):
            return _resp(
                'reset your password: <a href="https://webvigil.invalid/r?token=x">here</a>'
            )
        return _resp()

    hits = await _scanner(_FakeHttp(reset)).run()
    hh = [h for h in hits if h.check_id == "injection.host-header"]
    assert hh and hh[0].severity is Severity.HIGH


async def test_sentinel_never_reflected_is_not_a_hit() -> None:
    hits = await _scanner(_FakeHttp(lambda m, u, h: _resp("nothing here"))).run()
    assert not [h for h in hits if h.check_id == "injection.host-header"]


async def test_dangerous_methods_in_allow_on_an_app_route_is_a_hit() -> None:
    """``Allow: GET, PUT, DELETE`` on an HTML route is a methods finding."""

    def route(method: str, url: str, headers: dict[str, str]) -> Response:
        if method == "OPTIONS":
            return _resp(headers={"allow": "GET, POST, PUT, DELETE, OPTIONS"})
        return _resp()

    hits = await _scanner(_FakeHttp(route)).run()
    m = [h for h in hits if h.check_id == "http.methods.unsafe"]
    assert m and "PUT" in m[0].title and "DELETE" in m[0].title


async def test_dangerous_methods_on_a_static_asset_is_not_a_hit() -> None:
    """PUT advertised on a .css file is expected static-host config, not a finding."""
    page = make_page(url="https://example.com/style.css", content_type="text/css")

    def route(method: str, url: str, headers: dict[str, str]) -> Response:
        if method == "OPTIONS":
            return _resp(headers={"allow": "GET, PUT, OPTIONS", "content-type": "text/css"})
        return _resp()

    hits = await _scanner(_FakeHttp(route), pages=(page,)).run()
    assert not [h for h in hits if h.check_id == "http.methods.unsafe"]


async def test_trace_echo_is_an_xst_hit() -> None:
    def route(method: str, url: str, headers: dict[str, str]) -> Response:
        if method == "TRACE":
            token = headers.get("X-Wv-Trace", "")
            return _resp(f"TRACE / HTTP/1.1\r\nX-Wv-Trace: {token}")
        return _resp()

    hits = await _scanner(_FakeHttp(route)).run()
    xst = [h for h in hits if h.check_id == "http.methods.unsafe" and h.method == "TRACE"]
    assert xst and "XST" in xst[0].title


async def test_trace_echo_redacts_a_reflected_auth_header() -> None:
    """A TRACE echo reflecting an Authorization / Cookie header is masked in the evidence."""

    def route(method: str, url: str, headers: dict[str, str]) -> Response:
        if method == "TRACE":
            return _resp(
                "TRACE / HTTP/1.1\r\nauthorization: Bearer wv-secret-xyz\r\ncookie: sid=abc123"
            )
        return _resp()

    hits = await _scanner(_FakeHttp(route)).run()
    xst = next(h for h in hits if h.check_id == "http.methods.unsafe" and h.method == "TRACE")
    blob = " ".join(content for _label, content in xst.evidence)
    assert "wv-secret-xyz" not in blob and "sid=abc123" not in blob
    assert "***redacted***" in blob


async def test_pass_never_sends_a_state_changing_verb() -> None:
    http = _FakeHttp(lambda m, u, h: _resp(headers={"allow": "GET, PUT, DELETE, PATCH, CONNECT"}))
    await _scanner(http).run()
    verbs = {method for method, _, _ in http.calls}
    assert verbs <= {"GET", "OPTIONS", "TRACE"}
    assert not verbs & {"PUT", "DELETE", "PATCH", "CONNECT"}


async def test_budget_cap_warns() -> None:
    pages = tuple(make_page(url=f"https://example.com/p{i}") for i in range(20))
    http = _FakeHttp(lambda m, u, h: _resp())
    scanner = EnvelopeScanner(
        http,
        _TARGET,
        ScanConfig.model_validate({"injection": {"envelope_budget": 5, "envelope_url_sample": 20}}),
        pages,
        (),
    )
    await scanner.run()
    assert any("budget" in w for w in scanner.warnings)


async def test_form_pages_are_sampled() -> None:
    """A form page is in the URL sample — password-reset links live behind forms."""
    form = Form(
        method="post",
        action="https://example.com/account",
        enctype="",
        fields=(FormField(name="x", type="text", value=""),),
        source_url="https://example.com/account",
    )

    def route(method: str, url: str, headers: dict[str, str]) -> Response:
        if "/account" in url and "webvigil.invalid" in " ".join(headers.values()):
            return _resp("<base href='https://webvigil.invalid/'>")
        return _resp()

    hits = await _scanner(_FakeHttp(route), forms=(form,)).run()
    assert [h for h in hits if h.check_id == "injection.host-header"]
