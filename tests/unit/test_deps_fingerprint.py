"""
Fingerprinter: sources, scope handling, and the fetch cap — RF-01..RF-04, RNF-07.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import httpx
import pytest

from webvigil.checks.deps._data import Provenance
from webvigil.checks.deps.fingerprint import Fingerprinter
from webvigil.checks.deps.rules import RetireJsRules
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.target import Target
from webvigil.core.technology import DetectionMethod
from webvigil.http.client import HttpClient

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)

_SEED = "https://example.com/"
_MINI = Path(__file__).parent.parent / "data" / "retirejs-mini.json"
_RULES = RetireJsRules.from_raw(
    json.loads(_MINI.read_text("utf-8")),
    Provenance(source_url="x", retrieved=date(2026, 1, 1), license="Apache-2.0", attribution="t"),
)


def _page(html: str, url: str = _SEED) -> Page:
    return Page(
        requested_url=url,
        url=url,
        status_code=200,
        headers=httpx.Headers({"content-type": "text/html; charset=utf-8"}),
        text=html,
        elapsed_ms=0.0,
    )


async def _run(pages: tuple[Page, ...], router, httpx_mock: object, *, max_fetches: int = 50):
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    config = ScanConfig()
    target = Target.parse(_SEED)
    async with HttpClient(target, config) as http:
        fp = Fingerprinter(http, target, _RULES, max_fetches=max_fetches)
        result = await fp.scan(pages)
        return result, http.stats


def _router(routes: dict[str, tuple[int, str]]):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        status, body = routes.get(str(request.url), (404, ""))
        return httpx.Response(
            status_code=status, text=body, headers={"content-type": "application/javascript"}
        )

    handler.seen = seen  # type: ignore[attr-defined]
    return handler


async def test_detects_library_from_a_fetched_in_scope_filename(httpx_mock: object) -> None:
    html = '<html><body><script src="/static/jquery-1.12.4.min.js"></script></body></html>'
    router = _router({"https://example.com/static/jquery-1.12.4.min.js": (200, "// minified")})
    result, _ = await _run((_page(html),), router, httpx_mock)
    assert ("jquery", "1.12.4", DetectionMethod.FILENAME) in [
        (d.name, d.version, d.method) for d in result.detections
    ]


async def test_detects_library_from_an_inline_banner_without_fetching(httpx_mock: object) -> None:
    html = "<html><body><script>/*! jQuery v3.4.1 */\nwindow.x=1;</script></body></html>"
    router = _router({})
    result, stats = await _run((_page(html),), router, httpx_mock)
    jquery = [d for d in result.detections if d.name == "jquery"]
    assert jquery and jquery[0].version == "3.4.1"
    assert jquery[0].method is DetectionMethod.FILECONTENT
    assert stats.requests == 0


async def test_cross_origin_script_is_identified_from_url_but_not_fetched(
    httpx_mock: object,
) -> None:
    html = (
        '<html><body><script src="https://cdn.example/3.4.1/jquery.min.js"></script></body></html>'
    )
    router = _router({})
    result, stats = await _run((_page(html),), router, httpx_mock)
    assert any(d.name == "jquery" and d.version == "3.4.1" for d in result.detections)
    assert stats.requests == 0
    assert "cdn.example" not in " ".join(router.seen)  # type: ignore[attr-defined]


async def test_fetch_cap_truncates_and_warns(httpx_mock: object) -> None:
    refs = "".join(f'<script src="/s/lib{i}.js"></script>' for i in range(5))
    html = f"<html><body>{refs}</body></html>"
    router = _router({f"https://example.com/s/lib{i}.js": (200, "") for i in range(5)})
    result, stats = await _run((_page(html),), router, httpx_mock, max_fetches=2)
    assert stats.requests == 2
    assert any("stopped at 2 resource fetches" in w for w in result.warnings)


async def test_non_html_and_failed_pages_are_skipped(httpx_mock: object) -> None:
    failed = Page.failed("https://example.com/x", "boom")
    result, _ = await _run((failed,), _router({}), httpx_mock)
    assert result.detections == []
