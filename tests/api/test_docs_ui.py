"""
The Swagger UI at ``/docs``: a pinned release, every external file checked by its hash.

Real app through ``TestClient``; nothing reaches the CDN (the page is only rendered, never loaded
in a browser). The page is read with ``selectolax`` and held to an allow-list: every ``src`` and
``href`` is either an empty ``data:`` URL or one of the two pinned files, carrying its
``integrity`` and ``crossorigin="anonymous"``. The same check run on FastAPI's default page is the
positive control: it must flag that page's floating, unchecked files.
"""

from __future__ import annotations

import base64
import re

import pytest
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from selectolax.lexbor import LexborHTMLParser

from tests.api.conftest import FakeOrchestrator
from webvigil.api import docs_ui
from webvigil.api.app import create_app
from webvigil.api.config import WebConfig

_PINNED = {
    docs_ui.SWAGGER_UI_JS_URL: docs_ui.SWAGGER_UI_JS_INTEGRITY,
    docs_ui.SWAGGER_UI_CSS_URL: docs_ui.SWAGGER_UI_CSS_INTEGRITY,
}


def _unpinned(html: str) -> list[str]:
    """
    List every file the page loads that is not pinned and checked.

    Args:
        html (str): The rendered page.

    Returns:
        list[str]: Each ``src`` / ``href`` that is neither ``data:`` nor a pinned file with its
            exact ``integrity`` and ``crossorigin="anonymous"``.
    """
    offenders: list[str] = []
    for node in LexborHTMLParser(html).css("[src], [href]"):
        url = node.attributes.get("src") or node.attributes.get("href") or ""
        if url.startswith("data:"):
            continue
        pinned = (
            url in _PINNED
            and node.attributes.get("integrity") == _PINNED[url]
            and node.attributes.get("crossorigin") == "anonymous"
        )
        if not pinned:
            offenders.append(url)
    return offenders


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def test_docs_loads_only_pinned_files_with_integrity(client: TestClient) -> None:
    """Both Swagger UI files are the pinned ones, with their hash; nothing else is fetched."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    tree = LexborHTMLParser(response.text)
    script = tree.css_first("script[src]")
    stylesheet = tree.css_first('link[rel="stylesheet"]')
    assert script is not None and stylesheet is not None
    assert script.attributes["src"] == docs_ui.SWAGGER_UI_JS_URL
    assert script.attributes["integrity"] == docs_ui.SWAGGER_UI_JS_INTEGRITY
    assert stylesheet.attributes["href"] == docs_ui.SWAGGER_UI_CSS_URL
    assert stylesheet.attributes["integrity"] == docs_ui.SWAGGER_UI_CSS_INTEGRITY
    assert _unpinned(response.text) == []


def test_fastapis_default_page_is_flagged() -> None:
    """Positive control: the allow-list flags the floating, unchecked files of the default page."""
    default = bytes(get_swagger_ui_html(openapi_url="/openapi.json", title="t").body).decode()
    offenders = _unpinned(default)
    assert "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js" in offenders
    assert "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" in offenders
    assert "https://fastapi.tiangolo.com/img/favicon.png" in offenders


def test_docs_reads_the_openapi_document_of_this_app(client: TestClient) -> None:
    """The page points at the app's own OpenAPI document, which is served."""
    page = client.get("/docs").text
    assert "url: '/openapi.json'" in page
    assert client.get("/openapi.json").status_code == 200


def test_docs_reads_the_openapi_document_under_the_root_path(web_config: WebConfig) -> None:
    """Behind a proxy that mounts the API on a prefix, the page asks for the prefixed document."""
    app = create_app(web_config, orchestrator_factory=FakeOrchestrator)
    with TestClient(app, root_path="/webvigil") as prefixed:
        page = prefixed.get("/docs").text
    assert "url: '/webvigil/openapi.json'" in page


def test_redoc_is_off(client: TestClient) -> None:
    """ReDoc is not served; the Swagger UI in the same app is (so the 404 is not a broken app)."""
    assert client.get("/redoc").status_code == 404
    assert client.get("/docs").status_code == 200


def test_the_docs_routes_stay_out_of_the_openapi_document(client: TestClient) -> None:
    """The documentation page is not an API operation."""
    paths = client.get("/openapi.json").json()["paths"]
    assert "/docs" not in paths
    assert [path for path in paths if not path.startswith("/api/")] == []


# ---------------------------------------------------------------------------
# The pin
# ---------------------------------------------------------------------------


def test_the_pin_is_an_exact_release() -> None:
    """A floating version (``@5``, ``@latest``) would let the CDN change the file under the hash."""
    assert re.fullmatch(r"\d+\.\d+\.\d+", docs_ui.SWAGGER_UI_VERSION)
    for url in _PINNED:
        assert url.startswith(
            f"https://cdn.jsdelivr.net/npm/swagger-ui-dist@{docs_ui.SWAGGER_UI_VERSION}/"
        )


@pytest.mark.parametrize("integrity", sorted(_PINNED.values()))
def test_each_integrity_is_a_sha384_digest(integrity: str) -> None:
    """The value is ``sha384-`` and the base64 of 48 bytes, the form browsers check."""
    prefix, _, digest = integrity.partition("-")
    assert prefix == "sha384"
    assert len(base64.b64decode(digest, validate=True)) == 48


def test_a_page_without_the_pinned_tag_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    """If FastAPI renders the tags differently, the page is refused, not served unchecked."""
    monkeypatch.setattr(
        docs_ui, "get_swagger_ui_html", lambda **_: HTMLResponse("<html><body></body></html>")
    )
    with pytest.raises(RuntimeError, match="no single"):
        docs_ui.swagger_ui_html("/openapi.json", "t")
