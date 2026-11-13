"""
Fingerprinter: sources, scope handling, and the fetch cap — RF-01..RF-04, RNF-07.

Resource fetches are stubbed with ``httpx_mock`` (via a small ``_router``); the
rules come from ``tests/data/retirejs-mini.json``. ``http.stats`` is asserted to
prove which cases fetch and which do not.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import httpx
import pytest

from webvigil.checks.deps._data import Provenance
from webvigil.checks.deps.fingerprint import _MAX_INLINE_CHARS, _MAX_RESOURCE_URLS, Fingerprinter
from webvigil.checks.deps.rules import _BODY_MAX, RetireJsRules
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
    """
    Args:
        html (str): The page body.
        url (str): The page URL. Defaults to the seed.

    Returns:
        Page: A 200 HTML page.
    """
    return Page(
        requested_url=url,
        url=url,
        status_code=200,
        headers=httpx.Headers({"content-type": "text/html; charset=utf-8"}),
        text=html,
        elapsed_ms=0.0,
    )


async def _run(pages: tuple[Page, ...], router, httpx_mock: object, *, max_fetches: int = 50):
    """
    Run one fingerprint pass over ``pages`` with resource fetches served by ``router``.

    Args:
        pages (tuple[Page, ...]): The crawled pages.
        router: A handler from :func:`_router`.
        httpx_mock: The ``pytest-httpx`` fixture.
        max_fetches (int): The pass's fetch cap. Defaults to 50.

    Returns:
        tuple: ``(FingerprintResult, HttpStats)``.
    """
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    config = ScanConfig()
    target = Target.parse(_SEED)
    async with HttpClient(target, config) as http:
        fp = Fingerprinter(http, target, _RULES, max_fetches=max_fetches)
        result = await fp.scan(pages)
        return result, http.stats


def _router(routes: dict[str, tuple[int, str]]):
    """
    Build an ``httpx`` callback that serves ``routes`` and records the URLs it saw.

    Args:
        routes (dict[str, tuple[int, str]]): URL -> ``(status, body)``; anything
            else is a 404.

    Returns:
        Callable: The handler, with a ``.seen`` list attribute.
    """
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
    """An in-scope ``<script src>`` is fetched and its filename version is captured."""
    html = '<html><body><script src="/static/jquery-1.12.4.min.js"></script></body></html>'
    router = _router({"https://example.com/static/jquery-1.12.4.min.js": (200, "// minified")})
    result, _ = await _run((_page(html),), router, httpx_mock)
    assert ("jquery", "1.12.4", DetectionMethod.FILENAME) in [
        (d.name, d.version, d.method) for d in result.detections
    ]


async def test_detects_library_from_an_inline_banner_without_fetching(httpx_mock: object) -> None:
    """An inline ``<script>`` banner is matched from the page body — zero requests."""
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
    """A CDN script is matched by its URL only; the out-of-scope host is never requested."""
    html = (
        '<html><body><script src="https://cdn.example/3.4.1/jquery.min.js"></script></body></html>'
    )
    router = _router({})
    result, stats = await _run((_page(html),), router, httpx_mock)
    assert any(d.name == "jquery" and d.version == "3.4.1" for d in result.detections)
    assert stats.requests == 0
    assert "cdn.example" not in " ".join(router.seen)  # type: ignore[attr-defined]


async def test_fetch_cap_truncates_and_warns(httpx_mock: object) -> None:
    """Past ``max_fetches`` in-scope resources, the rest are skipped and a warning is added."""
    refs = "".join(f'<script src="/s/lib{i}.js"></script>' for i in range(5))
    html = f"<html><body>{refs}</body></html>"
    router = _router({f"https://example.com/s/lib{i}.js": (200, "") for i in range(5)})
    result, stats = await _run((_page(html),), router, httpx_mock, max_fetches=2)
    assert stats.requests == 2
    assert any("stopped at 2 resource fetches" in w for w in result.warnings)


async def test_non_html_and_failed_pages_are_skipped(httpx_mock: object) -> None:
    """A failed page contributes no detections and triggers no fetches."""
    failed = Page.failed("https://example.com/x", "boom")
    result, _ = await _run((failed,), _router({}), httpx_mock)
    assert result.detections == []


# ---------------------------------------------------------------------------
# What one scan reads: the pages decide how much they carry, the pass does not follow
# ---------------------------------------------------------------------------


def _spy_identify(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str | None, str | None]]:
    """
    Record every ``identify`` call as ``(url, body)``.

    Args:
        monkeypatch (pytest.MonkeyPatch): The fixture that installs the spy.

    Returns:
        list[tuple[str | None, str | None]]: The calls, filled while the pass runs.
    """
    calls: list[tuple[str | None, str | None]] = []
    real = RetireJsRules.identify

    def spy(self: RetireJsRules, *, url: str | None = None, body: str | None = None) -> list:
        calls.append((url, body))
        return real(self, url=url, body=body)

    monkeypatch.setattr(RetireJsRules, "identify", spy)
    return calls


async def test_an_inline_script_repeated_on_every_page_is_read_once(
    httpx_mock: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same inline script on five pages reaches the matchers once."""
    calls = _spy_identify(monkeypatch)
    html = "<html><body><script>window.app = 1;</script></body></html>"
    pages = tuple(_page(html, f"https://example.com/p{i}") for i in range(5))
    await _run(pages, _router({}), httpx_mock)
    assert [body for _url, body in calls] == ["window.app = 1;"]


async def test_inline_scripts_past_the_scan_budget_are_not_read(
    httpx_mock: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Distinct full-size inline scripts stop at ``_MAX_INLINE_CHARS``, with a warning."""
    calls = _spy_identify(monkeypatch)
    fit = _MAX_INLINE_CHARS // _BODY_MAX
    scripts = "".join(f"<script>{i:08d}{'x' * (_BODY_MAX - 8)}</script>" for i in range(fit + 3))
    result, _ = await _run(
        (_page(f"<html><body>{scripts}</body></html>"),), _router({}), httpx_mock
    )
    assert len(calls) == fit
    assert any("stopped reading inline scripts" in w for w in result.warnings)


async def test_resource_urls_past_the_scan_cap_are_not_examined(
    httpx_mock: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Distinct script URLs stop at ``_MAX_RESOURCE_URLS``, with a warning."""
    calls = _spy_identify(monkeypatch)
    refs = "".join(
        f'<script src="https://cdn.example/s{i}.js"></script>'
        for i in range(_MAX_RESOURCE_URLS + 50)
    )
    result, _ = await _run((_page(f"<html><body>{refs}</body></html>"),), _router({}), httpx_mock)
    assert len(calls) == _MAX_RESOURCE_URLS
    assert any(
        f"stopped at {_MAX_RESOURCE_URLS} distinct resource URLs" in w for w in result.warnings
    )
