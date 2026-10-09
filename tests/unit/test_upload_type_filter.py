"""
The file-upload pass against servers that filter by part type — spec 014, issue #194.

``test_upload_scanner.py`` covers the pass over a store-and-serve stand-in; this file adds the
servers that reject most of what the pass sends.

Every server is a ``_Server`` (an ``httpx_mock`` callback) that parses the multipart request,
decides what to store, and serves stored files back from ``/files/``; it counts the requests so
the tests can say how many were spent. The scanner runs for real over the real HTTP client.
Nothing else is faked: the point is how the pass spends its per-form cap on a server that
rejects most of what it sends.
"""

from __future__ import annotations

import re

import httpx
import pytest

from webvigil.checks.upload.scanner import UploadScanner
from webvigil.core.config import ScanConfig
from webvigil.core.target import Target
from webvigil.crawler.forms import Form, FormField
from webvigil.http.client import HttpClient

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)

_ORIGIN = "https://example.com"
_ACTION = f"{_ORIGIN}/up"
_PART = re.compile(
    rb'filename="(?P<name>[^"]*)"\r\nContent-Type: (?P<type>[^\r\n]+)\r\n\r\n(?P<body>.*?)\r\n--',
    re.S,
)
_PHP = re.compile(rb"(?P<marker>wv[0-9a-f]+):<\?php echo (?P<a>\d+)\*(?P<b>\d+); \?>")


class _Server:
    """A stand-in upload endpoint: ``accept`` decides by part type, ``echo`` names the file."""

    def __init__(self, accept: frozenset[str] | None, *, echo: bool) -> None:
        """
        Args:
            accept (frozenset[str] | None): The part types it stores, or ``None`` for all.
            echo (bool): Whether the answer to a stored upload names the file. ``False`` makes
                every answer the same, stored or not.
        """
        self.accept = accept
        self.echo = echo
        self.files: dict[str, bytes] = {}
        self.posts = 0
        self.gets = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/up":
            self.posts += 1
            part = _PART.search(request.content + b"\r\n--")
            if part is None:
                return httpx.Response(400, text="bad")
            ctype = part["type"].decode()
            name = part["name"].decode()
            if self.accept is not None and ctype not in self.accept:
                return httpx.Response(200, text="<p>Your file was not uploaded.</p>")
            self.files[name] = part["body"]
            text = f"<pre>../files/{name} uploaded</pre>" if self.echo else "<p>Thanks.</p>"
            return httpx.Response(200, text=text)
        if request.method == "GET" and path.startswith("/files/"):
            self.gets += 1
            body = self.files.get(path.removeprefix("/files/"))
            if body is None:
                return httpx.Response(404, text="not found")
            php = _PHP.search(body)
            if php is not None:  # a .php file is executed, whatever it was declared as
                product = int(php["a"]) * int(php["b"])
                return httpx.Response(200, text=f"{php['marker'].decode()}:{product}")
            return httpx.Response(200, text=body.decode(), headers={"content-type": "text/html"})
        self.gets += request.method == "GET"
        return httpx.Response(404, text="not found")


def _form() -> Form:
    """
    Returns:
        Form: A DVWA-shaped upload form: a hidden size, the file, and the submit button.
    """
    return Form(
        method="POST",
        action=_ACTION,
        enctype="multipart/form-data",
        fields=(
            FormField("MAX_FILE_SIZE", "hidden", "100000"),
            FormField("uploaded", "file", ""),
            FormField("Upload", "submit", "Upload"),
        ),
        source_url=_ACTION,
    )


async def _run(server: _Server, httpx_mock: object) -> tuple[UploadScanner, list]:
    """
    Run the pass over ``server``.

    Args:
        server (_Server): The endpoint under test.
        httpx_mock: The ``pytest-httpx`` fixture.

    Returns:
        tuple[UploadScanner, list]: The scanner (for its counters) and its hits.
    """
    httpx_mock.add_callback(server, is_reusable=True)  # type: ignore[attr-defined]
    target = Target.parse(_ORIGIN)
    config = ScanConfig()
    async with HttpClient(target, config) as http:
        scanner = UploadScanner(http, target, config, (), (_form(),))
        hits = await scanner.run()
    return scanner, hits


async def test_a_server_that_filters_by_part_type_is_reached_past_the_rejections(
    httpx_mock: object,
) -> None:
    """A ``.php`` declared as ``image/jpeg`` is stored and run; rejected files cost one POST."""
    server = _Server(frozenset({"image/jpeg", "image/png"}), echo=True)
    scanner, hits = await _run(server, httpx_mock)
    outcomes = {hit.outcome for hit in hits}
    assert "server-exec" in outcomes
    assert any(hit.payload_name.endswith(".php") for hit in hits if hit.outcome == "server-exec")
    # Before #194 each rejected file cost a dozen look-ups and the cap ended the pass early.
    assert server.posts <= 14
    assert not any("upload file-upload pass stopped" in w for w in scanner.warnings)


async def test_a_server_that_answers_every_upload_alike_and_stores_none_is_not_chased(
    httpx_mock: object,
) -> None:
    """Identical answers and a benign file that never comes back: one look-up round, no hit."""
    server = _Server(frozenset(), echo=False)
    _, hits = await _run(server, httpx_mock)
    assert hits == []
    # one round of look-ups for the benign file, plus the pass's PUT probe, not one per payload
    assert server.gets <= 16


async def test_a_server_that_answers_every_upload_alike_but_stores_them_is_still_probed(
    httpx_mock: object,
) -> None:
    """The same answer for everything is no proof of rejection: the stored files are fetched."""
    server = _Server(None, echo=False)
    _, hits = await _run(server, httpx_mock)
    assert {hit.outcome for hit in hits} >= {"server-exec"}
