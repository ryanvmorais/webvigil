"""
DisclosureProbe: calibration, validation, derived probes, the cap — RF-04..RF-09, RNF-04.

Every path the probe requests is served by a ``_Router`` (an ``httpx_mock``
callback) that also records the URLs seen — so the "not fetched" assertions are
real. The probe runs against the full shipped catalogue.
"""

from __future__ import annotations

import httpx
import pytest

from webvigil.checks.disclosure import probe as probe_mod
from webvigil.checks.disclosure.catalogue import load_catalogue
from webvigil.checks.disclosure.probe import DisclosureProbe
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.findings import Confidence
from webvigil.core.target import Target
from webvigil.http.client import HttpClient

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)

_SEED = "https://example.com/"
_GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
_ENV = "SECRET_KEY=abcdef\nDB_PASSWORD=hunter2\nDEBUG=1\n"
_PACKAGE_JSON = '{"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "1.0.0"}}'
_SOURCE_MAP = '{"version": 3, "sources": ["app.ts"], "mappings": "AAAA", "sourcesContent": ["x"]}'


def _page(html: str = "", url: str = _SEED, ok: bool = True) -> Page:
    """
    Args:
        html (str): The page body.
        url (str): The page URL. Defaults to the seed.
        ok (bool): ``False`` for a failed page.

    Returns:
        Page: An HTML page (or a failed one).
    """
    return Page(
        requested_url=url,
        url=url,
        status_code=200 if ok else 0,
        headers=httpx.Headers({"content-type": "text/html; charset=utf-8"}),
        text=html,
        elapsed_ms=0.0,
        error=None if ok else "boom",
    )


class _Router:
    """An ``httpx`` callback: serves ``routes`` (URL -> ``(status, body, content_type)``),
    everything else gets ``default``, and every requested URL is appended to ``seen``."""

    def __init__(self, routes: dict[str, tuple[int, str, str]], default: tuple[int, str, str]):
        self.routes = routes
        self.default = default
        self.seen: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.seen.append(url)
        status, body, ctype = self.routes.get(url, self.default)
        return httpx.Response(status_code=status, text=body, headers={"content-type": ctype})


async def _run(router: _Router, pages: tuple[Page, ...], httpx_mock: object):
    """
    Run one disclosure probe against ``router`` over the full catalogue.

    Args:
        router (_Router): The response router.
        pages (tuple[Page, ...]): The crawled pages the probe mines for derived
            targets.
        httpx_mock: The ``pytest-httpx`` fixture.

    Returns:
        ProbeReport: The probe's report.
    """
    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    target = Target.parse(_SEED)
    async with HttpClient(target, ScanConfig()) as http:
        report = await DisclosureProbe(http, target, load_catalogue(), pages).run()
    return report


async def test_validated_git_config_is_a_hit_random_200_is_not(httpx_mock: object) -> None:
    """A path passes only when its body validates: a real ``.git/config`` hits, the 404s do not."""
    router = _Router(
        {"https://example.com/.git/config": (200, _GIT_CONFIG, "text/plain")},
        default=(404, "not found", "text/html"),
    )
    report = await _run(router, (_page(),), httpx_mock)
    hits = {(h.family, h.path) for h in report.hits}
    assert ("vcs", "/.git/config") in hits
    assert all(h.family != "config" for h in report.hits)  # nothing else validated


async def test_spa_catch_all_200_is_not_a_hit_but_a_real_file_is(httpx_mock: object) -> None:
    """An SPA that 200s for every path yields no hits; a real ``package.json`` still validates."""
    shell = "<html><body><div id=app></div></body></html>"
    router = _Router(
        {"https://example.com/package.json": (200, _PACKAGE_JSON, "application/json")},
        default=(200, shell, "text/html"),  # SPA: 200 for everything
    )
    report = await _run(router, (_page(shell),), httpx_mock)
    families = {h.family for h in report.hits}
    assert "manifest" in families
    assert "vcs" not in families  # the .git/config probe got the shell, not an ini


async def test_inconclusive_calibration_warns_and_still_validates(httpx_mock: object) -> None:
    """When calibration cannot settle on a soft-404 shape it warns, but validation still runs."""
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://example.com/.env":
            return httpx.Response(200, text=_ENV, headers={"content-type": "text/plain"})
        counter["n"] += 1
        return httpx.Response(200, text=f"<html>unique {counter['n']} " + "x" * counter["n"] * 40)

    httpx_mock.add_callback(handler, is_reusable=True)  # type: ignore[attr-defined]
    target = Target.parse(_SEED)
    async with HttpClient(target, ScanConfig()) as http:
        report = await DisclosureProbe(http, target, load_catalogue(), (_page(),)).run()
    assert any("could not calibrate" in w for w in report.warnings)
    assert any(h.family == "config" and h.path == "/.env" for h in report.hits)


async def test_request_cap_truncates_and_warns(httpx_mock: object, monkeypatch) -> None:
    """Past the request cap the remaining paths are dropped and a warning is added."""
    monkeypatch.setattr(probe_mod, "_REQUEST_CAP", 5)
    router = _Router({}, default=(404, "nope", "text/html"))
    report = await _run(router, (_page(),), httpx_mock)
    assert report.paths_probed == 5
    assert any("stopped at the 5-request cap" in w for w in report.warnings)


async def test_source_map_probed_for_in_scope_script_only(httpx_mock: object) -> None:
    """``<script>.map`` is probed for in-scope scripts only; the CDN script is left alone."""
    html = (
        '<html><body><script src="/static/app.js"></script>'
        '<script src="https://cdn.example/vendor.js"></script></body></html>'
    )
    router = _Router(
        {"https://example.com/static/app.js.map": (200, _SOURCE_MAP, "application/json")},
        default=(404, "", "text/html"),
    )
    report = await _run(router, (_page(html),), httpx_mock)
    assert any(h.family == "sourcemap" and h.path == "/static/app.js.map" for h in report.hits)
    assert "cdn.example" not in " ".join(router.seen)


async def test_forbidden_git_directory_is_a_medium_confidence_hit(httpx_mock: object) -> None:
    """A ``403`` on ``.git/`` is a hit at MEDIUM confidence, without content validation."""
    router = _Router(
        {"https://example.com/.git/": (403, "<h1>403 Forbidden</h1>", "text/html")},
        default=(404, "", "text/html"),
    )
    report = await _run(router, (_page(),), httpx_mock)
    git_dir = [h for h in report.hits if h.path == "/.git/"]
    assert git_dir and git_dir[0].confidence is Confidence.MEDIUM


async def test_probe_is_deterministic(httpx_mock: object) -> None:
    """Two identical runs produce the same hits in the same order (RNF-04)."""

    def make_router() -> _Router:
        return _Router(
            {"https://example.com/.git/config": (200, _GIT_CONFIG, "text/plain")},
            default=(404, "not found", "text/html"),
        )

    first = await _run(make_router(), (_page(),), httpx_mock)
    second = await _run(make_router(), (_page(),), httpx_mock)
    assert [(h.family, h.path, h.severity) for h in first.hits] == [
        (h.family, h.path, h.severity) for h in second.hits
    ]
