"""
Path-traversal detector — spec 006 RF-10, RF-13.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from webvigil.checks.injection.detect import DetectCtx, normalize_body, traversal
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.http.client import Response

_POINT = InjectionPoint(
    "GET", "https://example.com/download", "file", "notes.txt", (("file", "notes.txt"),)
)
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
_WININI = "; for 16-bit app support\n[fonts]\n[extensions]\n"


def _resp(text: str) -> Response:
    return Response(
        url="https://example.com/download",
        requested_url="https://example.com/download",
        status_code=200,
        headers=httpx.Headers({"content-type": "text/plain"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _baseline(body: str = "notes") -> Baseline:
    return Baseline(200, body, normalize_body(body), len(body), 1.0)


def _ctx(render: Callable[[str], Response]) -> DetectCtx:
    async def send(point: InjectionPoint, value: str, *, time_based: bool = False) -> Response:
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com")


async def test_etc_passwd_disclosure_is_a_hit() -> None:
    hits = await traversal.detect(
        _POINT, _baseline(), _ctx(lambda v: _resp(_PASSWD if "etc/passwd" in v else "notes"))
    )
    assert len(hits) == 1 and hits[0].kind == "traversal"
    assert "root:x:0:0" in hits[0].evidence[2][1]


async def test_win_ini_disclosure_is_a_hit() -> None:
    hits = await traversal.detect(
        _POINT, _baseline(), _ctx(lambda v: _resp(_WININI if "win.ini" in v.lower() else "notes"))
    )
    assert len(hits) == 1


async def test_signature_already_in_the_baseline_is_not_a_hit() -> None:
    hits = await traversal.detect(_POINT, _baseline(_PASSWD), _ctx(lambda v: _resp(_PASSWD)))
    assert hits == []


async def test_payload_echoed_without_the_file_is_not_a_hit() -> None:
    hits = await traversal.detect(
        _POINT, _baseline(), _ctx(lambda v: _resp(f"File not found: {v}"))
    )
    assert hits == []
