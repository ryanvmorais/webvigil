"""
In-band XXE detector — spec 012 RF-04, RF-15.

Pure detector unit: ``_ctx`` wraps a ``render`` callable that also records the
``content_type`` each send used, so a test can prove the content-type flip
happened. ``_PASSWD`` is the real ``/etc/passwd`` signature the file-read proof
matches on.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx2

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx, normalize_body, xxe
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_POST = InjectionPoint(
    "POST", "https://example.com/api/xml", "data", "{}", (("data", "{}"),), source="form"
)
_GET = InjectionPoint("GET", "https://example.com/x", "q", "1", (("q", "1"),))

_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _resp(text: str, *, status: int = 200) -> Response:
    return Response(
        url="https://example.com/api/xml",
        requested_url="https://example.com/api/xml",
        status_code=status,
        headers=httpx2.Headers({"content-type": "text/plain"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _baseline(body: str = "ok") -> Baseline:
    return Baseline(200, body, normalize_body(body), len(body), 1.0)


def _ctx(
    render: Callable[[str], Response | None], *, seen_ct: list[str] | None = None
) -> DetectCtx:
    async def send(
        point: InjectionPoint,
        value: str,
        *,
        time_based: bool = False,
        content_type: str | None = None,
    ) -> Response | None:
        if seen_ct is not None and content_type is not None:
            seen_ct.append(content_type)
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com", self_url="https://example.com")


async def test_file_read_signature_is_a_high_hit() -> None:
    """A ``file:///etc/passwd`` payload that returns the file content is HIGH / HIGH."""
    hits = await xxe.detect(
        _POST, _baseline(), _ctx(lambda v: _resp(_PASSWD if "etc/passwd" in v else "ok"))
    )
    assert len(hits) == 1
    hit = hits[0]
    assert hit.kind == "xxe"
    assert hit.check_id == "injection.xxe"
    assert hit.severity is Severity.HIGH
    assert hit.confidence is Confidence.HIGH
    assert "local file read" in hit.title


async def test_parser_error_only_is_a_medium_hit() -> None:
    """An XML-parser error naming the entity, with no file content, is HIGH / MEDIUM."""
    hits = await xxe.detect(
        _POST,
        _baseline(),
        _ctx(lambda v: _resp("lxml.etree.XMLSyntaxError: Entity 'xxe' not defined", status=500)),
    )
    assert len(hits) == 1
    assert hits[0].severity is Severity.HIGH
    assert hits[0].confidence is Confidence.MEDIUM


async def test_plain_400_rejection_is_not_a_hit() -> None:
    """An endpoint that rejects the XML body with no signature is not a hit."""
    hits = await xxe.detect(_POST, _baseline(), _ctx(lambda v: _resp("bad request", status=400)))
    assert hits == []


async def test_get_point_is_skipped() -> None:
    """The content-type flip is POST-only."""
    hits = await xxe.detect(_GET, _baseline(), _ctx(lambda v: _resp(_PASSWD)))
    assert hits == []


async def test_both_content_types_are_tried() -> None:
    """Each content type gets the file payload once per file and each other payload once."""
    seen_ct: list[str] = []
    await xxe.detect(_POST, _baseline(), _ctx(lambda v: _resp("ok"), seen_ct=seen_ct))
    per_type = len(payloads.XXE_FILES) + len(payloads.XXE_PAYLOADS) - 1
    assert per_type == 4
    assert seen_ct == ["application/xml"] * per_type + ["text/xml"] * per_type


async def test_signature_already_in_the_baseline_is_suppressed() -> None:
    """A ``root:...:0:0:`` line already in the baseline body is not a new finding."""
    hits = await xxe.detect(_POST, _baseline(_PASSWD), _ctx(lambda v: _resp(_PASSWD)))
    assert hits == []


async def test_a_denied_request_stops_the_detector() -> None:
    """A ``None`` from ``send`` on a later payload ends the loops: nothing is sent after it."""
    seen_ct: list[str] = []
    hits = await xxe.detect(
        _POST,
        _baseline(),
        _ctx(lambda v: None if len(seen_ct) == 2 else _resp("ok"), seen_ct=seen_ct),
    )
    assert hits == []
    assert len(seen_ct) == 2


async def test_the_evidence_is_the_one_line_that_holds_the_proof() -> None:
    """The lines around the parser error stay out; a proof on the last line keeps its end."""
    error = "lxml.etree.XMLSyntaxError: Entity 'xxe' not defined"
    for body in (f"<pre>trace\n{error}\n  at line 1</pre>", f"trace\n{error}"):
        (hit,) = await xxe.detect(_POST, _baseline(), _ctx(lambda v, b=body: _resp(b)))
        assert dict(hit.evidence)["Xml parser error"] == error, body


def test_the_evidence_line_is_cut_at_200_characters() -> None:
    """A line of exactly 200 characters is whole; one more is cut there and marked."""
    line = "ExpatError" + "x" * 190
    assert len(line) == 200
    assert xxe._first_match(payloads.XXE_ERROR_SIGNATURES, line, "") == line
    assert xxe._first_match(payloads.XXE_ERROR_SIGNATURES, line + "y", "") == line + "…"
