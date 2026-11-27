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

import httpx2
import pytest

from webvigil.checks.deps import fingerprint
from webvigil.checks.deps._data import Provenance
from webvigil.checks.deps.fingerprint import _MAX_INLINE_CHARS, _MAX_RESOURCE_URLS, Fingerprinter
from webvigil.checks.deps.rules import _BODY_MAX, RetireJsRules
from webvigil.core.config import ScanConfig
from webvigil.core.context import Detection, Page
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


def _page(html: str, url: str = _SEED, content_type: str = "text/html; charset=utf-8") -> Page:
    """
    Args:
        html (str): The page body.
        url (str): The page URL. Defaults to the seed.
        content_type (str): The page's ``Content-Type``. Defaults to HTML.

    Returns:
        Page: A 200 page.
    """
    return Page(
        requested_url=url,
        url=url,
        status_code=200,
        headers=httpx2.Headers({"content-type": content_type}),
        text=html,
        elapsed_ms=0.0,
    )


async def _run(pages: tuple[Page, ...], router, httpx_mock: object, *, max_fetches: int = 50):
    """
    Run one fingerprint pass over ``pages`` with resource fetches served by ``router``.

    Args:
        pages (tuple[Page, ...]): The crawled pages.
        router: A handler from :func:`_router`.
        httpx_mock: The ``httpx_mock`` fixture.
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
    Build an ``httpx2`` callback that serves ``routes`` and records the URLs it saw.

    Args:
        routes (dict[str, tuple[int, str]]): URL -> ``(status, body)``; anything
            else is a 404.

    Returns:
        Callable: The handler, with a ``.seen`` list attribute.
    """
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(str(request.url))
        status, body = routes.get(str(request.url), (404, ""))
        return httpx2.Response(
            status_code=status, text=body, headers={"content-type": "application/javascript"}
        )

    handler.seen = seen  # type: ignore[attr-defined]
    return handler


async def test_detects_library_from_the_body_of_a_fetched_in_scope_script(
    httpx_mock: object,
) -> None:
    """A script whose name carries no version is fetched, and its banner names the library."""
    html = '<html><body><script src="/static/app.js"></script></body></html>'
    router = _router({"https://example.com/static/app.js": (200, "/*! jQuery v3.4.1 */ x();")})
    result, stats = await _run((_page(html),), router, httpx_mock)
    assert [(d.name, d.version, d.method) for d in result.detections] == [
        ("jquery", "3.4.1", DetectionMethod.FILECONTENT)
    ]
    assert stats.requests == 1


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


async def test_a_failed_page_is_skipped(httpx_mock: object) -> None:
    """A failed page contributes no detections and triggers no fetches."""
    failed = Page.failed("https://example.com/x", "boom")
    result, stats = await _run((failed,), _router({}), httpx_mock)
    assert result.detections == []
    assert stats.requests == 0


async def test_a_page_that_is_not_html_is_not_read_for_scripts(httpx_mock: object) -> None:
    """The same markup served as ``text/plain`` is text, not a page: only the HTML copy counts."""
    html = "<html><body><script>/*! jQuery v3.4.1 */</script></body></html>"
    pages = (
        _page(html, "https://example.com/readme.txt", content_type="text/plain"),
        _page(html.replace("3.4.1", "3.6.0")),
    )
    result, _ = await _run(pages, _router({}), httpx_mock)
    assert [(d.name, d.version) for d in result.detections] == [("jquery", "3.6.0")]


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
    scripts = [f"<script>{i:08d}{'x' * (_BODY_MAX - 8)}</script>" for i in range(fit + 3)]
    # Four scripts a page: each page stays within what the HTML parser reads of one.
    pages = tuple(
        _page(f"<html><body>{''.join(scripts[n : n + 4])}</body></html>", f"{_SEED}p{n}")
        for n in range(0, len(scripts), 4)
    )
    result, _ = await _run(pages, _router({}), httpx_mock)
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


async def test_distinct_library_versions_past_the_scan_cap_are_dropped_with_a_warning(
    httpx_mock: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A page naming more versions than ``_MAX_LIBRARY_VERSIONS`` keeps the first ones found."""
    monkeypatch.setattr(fingerprint, "_MAX_LIBRARY_VERSIONS", 3)
    refs = "".join(
        f'<script src="https://cdn.example/1.0.{i}/jquery.min.js"></script>' for i in range(5)
    )
    result, _ = await _run((_page(f"<html><body>{refs}</body></html>"),), _router({}), httpx_mock)
    assert [d.version for d in result.detections] == ["1.0.0", "1.0.1", "1.0.2"]
    assert "dependency fingerprinting stopped at 3 distinct library versions" in result.warnings


async def test_library_versions_up_to_the_scan_cap_are_all_kept_without_a_warning(
    httpx_mock: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exactly ``_MAX_LIBRARY_VERSIONS`` pairs, one of them found twice, fit the cap."""
    monkeypatch.setattr(fingerprint, "_MAX_LIBRARY_VERSIONS", 3)
    refs = "".join(
        f'<script src="https://cdn.example/1.0.{i}/jquery.min.js"></script>' for i in (0, 1, 2)
    )
    pages = (
        _page(f"<html><body>{refs}</body></html>"),
        _page(f"<html><body>{refs}</body></html>", f"{_SEED}again"),
    )
    result, _ = await _run(pages, _router({}), httpx_mock)
    assert [d.version for d in result.detections] == ["1.0.0", "1.0.1", "1.0.2"]
    assert not any("distinct library versions" in w for w in result.warnings)


async def test_a_stronger_detection_of_a_kept_pair_still_replaces_it_past_the_cap(
    httpx_mock: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cap turns away new pairs only: a pair already kept still takes a stronger method."""
    monkeypatch.setattr(fingerprint, "_MAX_LIBRARY_VERSIONS", 1)
    html = (
        "<html><body>"
        '<script src="https://cdn.example/3.4.1/jquery.min.js"></script>'
        '<script src="https://cdn.example/3.5.0/jquery.min.js"></script>'
        '<script src="/static/jquery-3.4.1.min.js"></script>'
        "</body></html>"
    )
    router = _router({"https://example.com/static/jquery-3.4.1.min.js": (200, "// minified")})
    result, _ = await _run((_page(html),), router, httpx_mock)
    (only,) = result.detections
    assert (only.version, only.method) == ("3.4.1", DetectionMethod.FILENAME)
    assert "dependency fingerprinting stopped at 1 distinct library versions" in result.warnings


def _det(name: str, version: str | None, method: DetectionMethod) -> Detection:
    """
    Args:
        name (str): Library name.
        version (str | None): Detected version, or ``None``.
        method (DetectionMethod): How it was detected.

    Returns:
        Detection: A detection from a synthetic source.
    """
    return Detection(name, version, method, _SEED, f"{name}.js")


def test_a_weaker_or_equal_detection_found_later_does_not_replace_the_kept_one() -> None:
    """The first detection of a pair stays unless a strictly stronger method finds it again."""
    found = fingerprint._Found()
    found.add([_det("jquery", "3.4.1", DetectionMethod.HASH)])
    found.add([_det("jquery", "3.4.1", DetectionMethod.URI)])
    found.add([_det("lodash", "4.17.0", DetectionMethod.FILENAME)])
    found.add([_det("lodash", "4.17.0", DetectionMethod.FILECONTENT)])  # the same rank
    assert [(d.name, d.method) for d in found.winners()] == [
        ("jquery", DetectionMethod.HASH),
        ("lodash", DetectionMethod.FILENAME),
    ]


def test_a_version_less_detection_stays_only_for_a_library_with_no_version() -> None:
    """A library found with and without a version keeps the versioned one; one without, its own."""
    found = fingerprint._Found()
    found.add(
        [
            _det("jquery", None, DetectionMethod.URI),
            _det("jquery", "3.4.1", DetectionMethod.FILENAME),
            _det("lodash", None, DetectionMethod.URI),
        ]
    )
    assert [(d.name, d.version) for d in found.winners()] == [
        ("jquery", "3.4.1"),
        ("lodash", None),
    ]


async def test_a_resource_named_like_a_logout_is_read_by_its_url_only(httpx_mock: object) -> None:
    """A script whose URL names a logout or a destructive verb is never fetched."""
    html = (
        '<html><body><script src="/static/app.js"></script>'
        '<script src="/session/logOut.js"></script>'
        '<link rel="preload" href="/cache/purge_all.js"></body></html>'
    )
    router = _router({"https://example.com/static/app.js": (200, "x();")})
    await _run((_page(html),), router, httpx_mock)
    assert router.seen == ["https://example.com/static/app.js"]  # type: ignore[attr-defined]
