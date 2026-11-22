"""
Path-traversal detector — spec 006 RF-10, RF-13.

Pure detector unit: ``_ctx`` wraps a ``render`` callable as the scanner's
``send``, so each test decides what the target returns for a given payload and
no HTTP is issued. ``_PASSWD`` / ``_WININI`` are the real file signatures the
detector looks for.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx, normalize_body, traversal
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.http.client import Response

_POINT = InjectionPoint(
    "GET", "https://example.com/download", "file", "notes.txt", (("file", "notes.txt"),)
)
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
_WININI = "; for 16-bit app support\n[fonts]\n[extensions]\n"


def _resp(text: str) -> Response:
    """
    Args:
        text (str): The response body.

    Returns:
        Response: A 200 ``text/plain`` response carrying ``text``.
    """
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
    """
    Args:
        body (str): The pre-injection response body.

    Returns:
        Baseline: The baseline the detector diffs each payload against.
    """
    return Baseline(200, body, normalize_body(body), len(body), 1.0)


def _ctx(render: Callable[[str], Response | None], *, seen: list[str] | None = None) -> DetectCtx:
    """
    Args:
        render (Callable[[str], Response | None]): Maps an injected value to the response
            the target would return, or ``None`` to model a denied request.
        seen (list[str] | None): When given, every value sent is appended to it.

    Returns:
        DetectCtx: A detector context whose ``send`` calls ``render``.
    """

    async def send(
        point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None:
        if seen is not None:
            seen.append(value)
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com")


async def test_etc_passwd_disclosure_is_a_hit() -> None:
    """A payload that pulls back ``/etc/passwd`` content is a hit, with the line as evidence."""
    hits = await traversal.detect(
        _POINT, _baseline(), _ctx(lambda v: _resp(_PASSWD if "etc/passwd" in v else "notes"))
    )
    assert len(hits) == 1 and hits[0].kind == "traversal"
    assert "root:x:0:0" in hits[0].evidence[2][1]


async def test_win_ini_disclosure_is_a_hit() -> None:
    """The Windows ``win.ini`` signature is recognised too."""
    hits = await traversal.detect(
        _POINT, _baseline(), _ctx(lambda v: _resp(_WININI if "win.ini" in v.lower() else "notes"))
    )
    assert len(hits) == 1


async def test_absolute_windows_path_is_tried_when_relative_ones_do_not_reach_the_root() -> None:
    """An app deep in the tree never reaches the drive root with ``../``; the absolute path does."""
    hits = await traversal.detect(
        _POINT,
        _baseline(),
        _ctx(lambda v: _resp(_WININI if v == "/windows/win.ini" else "notes")),
    )
    assert len(hits) == 1 and hits[0].payload == "/windows/win.ini"


async def test_signature_already_in_the_baseline_is_not_a_hit() -> None:
    """A file signature already present in the baseline body does not count."""
    hits = await traversal.detect(_POINT, _baseline(_PASSWD), _ctx(lambda v: _resp(_PASSWD)))
    assert hits == []


async def test_payload_echoed_without_the_file_is_not_a_hit() -> None:
    """The payload string bouncing back in an error message is not disclosure."""
    hits = await traversal.detect(
        _POINT, _baseline(), _ctx(lambda v: _resp(f"File not found: {v}"))
    )
    assert hits == []


async def test_a_denied_request_stops_the_detector() -> None:
    """A ``None`` from ``send`` on a later payload ends the loop: nothing is sent after it."""
    seen: list[str] = []
    hits = await traversal.detect(
        _POINT,
        _baseline(),
        _ctx(lambda v: None if len(seen) == 2 else _resp("notes"), seen=seen),
    )
    assert hits == []
    assert seen == list(payloads.TRAVERSAL[:2])


async def test_the_evidence_is_the_one_line_that_holds_the_signature() -> None:
    """The lines before and after the match stay out of the evidence."""
    body = "<pre>listing\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/bin/false</pre>"
    (hit,) = await traversal.detect(_POINT, _baseline(), _ctx(lambda v: _resp(body)))
    assert dict(hit.evidence)["Leaked content"] == "root:x:0:0:root:/root:/bin/bash"


async def test_a_signature_on_the_last_line_keeps_its_last_character() -> None:
    """With no newline after the match, the line runs to the end of the body."""
    body = "listing\nroot:x:0:0:root"
    (hit,) = await traversal.detect(_POINT, _baseline(), _ctx(lambda v: _resp(body)))
    assert dict(hit.evidence)["Leaked content"] == "root:x:0:0:root"


def test_the_evidence_line_is_cut_at_200_characters() -> None:
    """A line of exactly 200 characters is whole; one more is cut there and marked."""
    line = "root:x:0:0:" + "a" * 189
    assert len(line) == 200
    assert traversal._line_around(line, 0) == line
    assert traversal._line_around(line + "b", 0) == line + "…"
