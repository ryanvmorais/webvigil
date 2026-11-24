"""
The Swagger UI page at ``/docs``, loaded from a pinned release with Subresource Integrity.

FastAPI's own ``/docs`` points at ``swagger-ui-dist@5`` on jsDelivr: a floating version, with no
``integrity`` attribute, so the page runs whatever script the CDN serves under that name, on the
API's own origin. This module serves the same page from an exact release, with the SHA-384 of each
file in the tag (the browser refuses a file that does not match) and ``crossorigin="anonymous"``,
so the request carries no cookie. The favicon, which FastAPI loads from its own site, is an empty
``data:`` URL: the page makes no third-party request beyond the two pinned files.

``scripts/update-swagger-ui.py`` moves the pin: it reads the release from the npm registry, hashes
the files of the published package, checks that jsDelivr serves the same bytes and rewrites the
constants below. ReDoc (``/redoc``) is turned off in :func:`webvigil.api.app.create_app`; this
page is the API's only documentation UI.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse

# The pinned release and the SHA-384 of each file, in the form the ``integrity`` attribute takes.
# Rewritten by ``scripts/update-swagger-ui.py``; edit them by hand only together.
SWAGGER_UI_VERSION = "5.35.0"
SWAGGER_UI_JS_INTEGRITY = "sha384-gjRm0bEPMeTmMh5jT2cHccIwCUZSTd8YC+j0d0sXw0MdGEfScduGpSyF3ZSSLkX9"
SWAGGER_UI_CSS_INTEGRITY = "sha384-WlYgdmXYOOBWL5apwjDEZwN+U3HmXSSu5R6V5aGxEcf7z+KuRNwBhoxKVN1i3D5I"

_CDN = f"https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}"
SWAGGER_UI_JS_URL = f"{_CDN}/swagger-ui-bundle.js"
SWAGGER_UI_CSS_URL = f"{_CDN}/swagger-ui.css"
# An empty icon: without one the browser asks for ``/favicon.ico``, and FastAPI's default is an
# image on its own site.
_FAVICON_URL = "data:,"

DOCS_PATH = "/docs"


def _with_integrity(html: str, attribute: str, url: str, integrity: str) -> str:
    """
    Add ``integrity`` and ``crossorigin`` to the one tag that loads ``url``.

    Args:
        html (str): The page FastAPI rendered.
        attribute (str): The attribute that holds the URL (``src`` or ``href``).
        url (str): The pinned URL the tag loads.
        integrity (str): The ``integrity`` value of that file.

    Returns:
        str: The page, with the two attributes right after the URL.

    Raises:
        RuntimeError: When the tag is not found exactly once, so a FastAPI release that renders
            the page differently fails loudly instead of serving a tag without integrity.
    """
    tag = f'{attribute}="{url}"'
    if html.count(tag) != 1:
        raise RuntimeError(f"the Swagger UI page has no single {tag} to pin")
    return html.replace(tag, f'{tag} integrity="{integrity}" crossorigin="anonymous"')


def swagger_ui_html(openapi_url: str, title: str) -> HTMLResponse:
    """
    Render the Swagger UI page with every external file pinned and checked.

    Args:
        openapi_url (str): Where the page reads the OpenAPI document from.
        title (str): The page title.

    Returns:
        HTMLResponse: FastAPI's Swagger UI page, loading the pinned release with integrity.
    """
    page = get_swagger_ui_html(
        openapi_url=openapi_url,
        title=title,
        swagger_js_url=SWAGGER_UI_JS_URL,
        swagger_css_url=SWAGGER_UI_CSS_URL,
        swagger_favicon_url=_FAVICON_URL,
    )
    html = bytes(page.body).decode()
    html = _with_integrity(html, "src", SWAGGER_UI_JS_URL, SWAGGER_UI_JS_INTEGRITY)
    html = _with_integrity(html, "href", SWAGGER_UI_CSS_URL, SWAGGER_UI_CSS_INTEGRITY)
    return HTMLResponse(html)


def install_docs(app: FastAPI) -> None:
    """
    Serve the pinned Swagger UI at ``/docs``, in place of FastAPI's own.

    The app must be built with ``docs_url=None``; the OpenAPI URL is resolved under the request's
    ``root_path``, as FastAPI does, so the page works behind a proxy that mounts the API on a
    prefix.

    Args:
        app (FastAPI): The application to add the route to.
    """
    title = f"{app.title} - Swagger UI"
    openapi_path = app.openapi_url or "/openapi.json"

    async def docs(request: Request) -> HTMLResponse:
        """The interactive API documentation (Swagger UI)."""
        root_path = str(request.scope.get("root_path", "")).rstrip("/")
        return swagger_ui_html(root_path + openapi_path, title)

    app.add_route(DOCS_PATH, docs, include_in_schema=False)
