"""
The file-upload pass — spec 014 RF-01..RF-06, RF-17.

``_Store`` is a tiny stand-in for a store-and-serve upload endpoint; ``_FakeHttp``
routes ``POST`` / ``GET`` / ``PUT`` through it and records every call so the
tests can assert the pass uploads only benign markers and never sends ``DELETE``
/ ``PATCH``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from tests.support import make_page
from webvigil.checks.upload.scanner import UploadScanner
from webvigil.core.config import ScanConfig
from webvigil.core.findings import Severity
from webvigil.core.target import Target
from webvigil.crawler.forms import Form, FormField
from webvigil.http.client import Response

_TARGET = Target.parse("https://example.com/")
_UPLOAD_FORM = Form(
    method="POST",
    action="https://example.com/upload",
    enctype="multipart/form-data",
    fields=(FormField("caption", "text", "hi"), FormField("avatar", "file", "")),
    source_url="https://example.com/",
)
_LOGIN_FORM = Form(
    method="POST",
    action="https://example.com/login",
    enctype="multipart/form-data",
    fields=(FormField("photo", "file", ""),),
    source_url="https://example.com/",
)


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


_GUESS = {
    ".php": "php",
    ".phtml": "php",
    ".jsp": "jsp",
    ".html": "text/html",
    ".svg": "image/svg+xml",
    ".jpg": "image/jpeg",
    ".txt": "text/plain",
}


def _guess(name: str) -> str:
    for ext, ctype in _GUESS.items():
        if name.lower().endswith(ext):
            return ctype
    return "application/octet-stream"


def _run_php(body: bytes) -> str:
    """Fake a PHP / JSP interpreter: collapse ``marker:<?php echo A*B; ?>`` to ``marker:AB``."""
    import re as _re

    text = body.decode()
    m = _re.search(r"echo (\d+)\*(\d+)|print\((\d+)\*(\d+)\)", text)
    if not m:
        return text
    nums = [int(x) for x in m.groups() if x]
    return text.split(":", 1)[0] + ":" + str(nums[0] * nums[1])


@dataclass
class _Store:
    """A store-and-serve upload endpoint. A ``../`` filename writes to the web root."""

    execute_php: bool = True
    inline: bool = True
    reject_dangerous: bool = False
    sanitize_names: bool = False
    under_files: dict[str, bytes] = field(default_factory=dict)
    at_root: dict[str, bytes] = field(default_factory=dict)

    def upload(self, filename: str, body: bytes) -> Response:
        name = filename.rsplit("/", 1)[-1].split("%00")[0]
        dangerous = not name.lower().endswith((".txt", ".jpg"))
        if self.reject_dangerous and dangerous:
            return _resp("rejected", status=400)
        traversal = "../" in filename or "..%2f" in filename.lower()
        if traversal and self.sanitize_names:
            self.under_files[name] = body  # the ../ was stripped
            return _resp(f'<a href="/files/{name}">saved</a>')
        if traversal:
            self.at_root[name] = body
            return _resp("saved (no link)")
        self.under_files[name] = body
        return _resp(f'<a href="/files/{name}">saved</a>')

    def serve(self, path: str) -> Response:
        from urllib.parse import urlsplit as _split

        just_path = _split(path).path
        name = just_path.rsplit("/", 1)[-1]
        directory = just_path.rsplit("/", 1)[0] + "/"
        if directory == "/files/":
            body = self.under_files.get(name)
        elif directory == "/":
            body = self.at_root.get(name)
        else:
            body = None
        if body is None:
            return _resp("not found", status=404)
        ctype = _guess(name)
        if ctype in ("php", "jsp"):
            if self.execute_php:
                return _resp(_run_php(body), headers={"content-type": "text/html"})
            return _resp(body.decode(), headers={"content-type": "application/octet-stream"})
        if not self.inline:
            return _resp(
                body.decode(),
                headers={
                    "content-type": "application/octet-stream",
                    "content-disposition": "attachment",
                },
            )
        return _resp(body.decode(), headers={"content-type": ctype})


class _FakeHttp:
    def __init__(self, store: _Store, *, put_ok: bool = False) -> None:
        self._store = store
        self._put_ok = put_ok
        self.calls: list[tuple[str, str, bytes]] = []

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: object = None,
        data: object = None,
        content: bytes | None = None,
        files: dict[str, tuple[str, bytes, str]] | None = None,
        headers: dict[str, str] | None = None,
        allow_out_of_scope: bool = False,
        crafted: bool = False,
    ) -> Response:
        method = method.upper()
        payload = b""
        if files:
            payload = next(iter(files.values()))[1]
        elif content:
            payload = content
        self.calls.append((method, url, payload))
        if method == "POST" and files:
            return self._store.upload(next(iter(files.values()))[0], payload)
        if method == "GET":
            return self._store.serve(url)
        if method == "PUT":
            if not self._put_ok:
                return _resp("method not allowed", status=405)
            self._store.at_root[url.rsplit("/", 1)[-1]] = payload
            return _resp("created", status=201)
        return _resp()


def _scanner(http: _FakeHttp, *, forms: tuple[Form, ...] = (_UPLOAD_FORM,), budget: int = 80):
    cfg = ScanConfig.model_validate({"injection": {"upload_budget": budget}})
    return UploadScanner(http, _TARGET, cfg, (make_page(),), forms)


async def test_only_forms_with_a_file_field_that_are_not_auth_shaped_are_probed() -> None:
    """The upload form is selected; the login form is dropped."""
    http = _FakeHttp(_Store())
    scanner = _scanner(http, forms=(_UPLOAD_FORM, _LOGIN_FORM))
    await scanner.run()
    posted = {url for method, url, _ in http.calls if method == "POST"}
    assert any(url.endswith("/upload") for url in posted)
    assert not any(url.endswith("/login") for _, url, _ in http.calls)


async def test_server_side_execution_is_a_critical_hit() -> None:
    """A .php marker returned as its computed product is CRITICAL / server-exec."""
    hits = await _scanner(_FakeHttp(_Store(execute_php=True))).run()
    exec_hits = [h for h in hits if h.outcome == "server-exec"]
    assert exec_hits and exec_hits[0].severity is Severity.CRITICAL


async def test_inline_html_upload_is_a_high_hit() -> None:
    """An .html marker served back as text/html with no attachment is HIGH / inline-html."""
    hits = await _scanner(_FakeHttp(_Store(execute_php=False, inline=True))).run()
    assert any(h.outcome == "inline-html" and h.severity is Severity.HIGH for h in hits)


async def test_filename_traversal_is_a_high_hit() -> None:
    """A ``../../`` marker retrievable from the web root is HIGH / traversal."""
    store = _Store(execute_php=False, inline=True)
    hits = await _scanner(_FakeHttp(store)).run()
    assert any(h.outcome == "traversal" and h.severity is Severity.HIGH for h in hits)


async def test_inert_accept_is_a_medium_hit_when_nothing_stronger_fires() -> None:
    """A stored-but-download-only file (names sanitised) is MEDIUM / inert-accept."""
    store = _Store(execute_php=False, inline=False, sanitize_names=True)
    hits = await _scanner(_FakeHttp(store)).run()
    assert hits and all(h.severity is Severity.MEDIUM for h in hits)
    assert {h.outcome for h in hits} == {"inert-accept"}


async def test_rejected_dangerous_types_produce_no_hit() -> None:
    """An endpoint that 400s every dangerous type yields nothing."""
    store = _Store(reject_dangerous=True)
    assert await _scanner(_FakeHttp(store)).run() == []


async def test_budget_cap_records_a_warning() -> None:
    """A tiny budget stops the pass with a warning, not an error."""
    scanner = _scanner(_FakeHttp(_Store()), budget=3)
    await scanner.run()
    assert any("budget" in w for w in scanner.warnings)


async def test_put_probe_positive_and_negative() -> None:
    """PUT accepted + served back is a hit; PUT 405 is silent."""
    ok = await _scanner(_FakeHttp(_Store(), put_ok=True)).run()
    assert any(h.outcome == "put-upload" and h.method == "PUT" for h in ok)
    no = await _scanner(_FakeHttp(_Store(), put_ok=False)).run()
    assert not any(h.outcome == "put-upload" for h in no)


async def test_pass_uploads_only_benign_markers_and_no_write_verbs() -> None:
    """Every payload is inert; the only state-changing verb is the gated PUT."""
    http = _FakeHttp(_Store(), put_ok=True)
    await _scanner(http).run()
    methods = {method for method, _, _ in http.calls}
    assert methods <= {"POST", "GET", "PUT"}
    for _, _, payload in http.calls:
        text = payload.decode("utf-8", "replace").lower()
        assert "rm -rf" not in text
        assert "system(" not in text
        assert "eval(" not in text
        assert len(payload) < 400
