"""
In-band SSRF detector — spec 009 RF-01..RF-08, RF-13.

Pure detector unit: ``_ctx`` wraps a ``render`` callable as the scanner's
``send``, so each test decides what the target's response would echo for a given
payload — a cloud-metadata marker, a ``file://`` read, an internal service
banner, or a connection error quoting the URL — and no HTTP is issued.
``_AWS_CREDS`` / ``_REDIS`` / ``_PASSWD`` are the real signatures the detector
proves a server-side fetch by.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx2

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx, normalize_body, ssrf
from webvigil.checks.injection.models import Baseline, InjectionPoint
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_POINT = InjectionPoint(
    "GET", "https://example.com/fetch", "url", "/preview", (("url", "/preview"),)
)

_AWS_CREDS = '{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","Token":"FQoGZ...EXAMPLE"}'
_REDIS = "redis_version:7.2.4\r\nredis_mode:standalone\r\n"
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _resp(text: str, *, status: int = 200) -> Response:
    """
    Args:
        text (str): The response body.
        status (int): The status code. Defaults to 200.

    Returns:
        Response: A ``text/plain`` response carrying ``text``.
    """
    return Response(
        url="https://example.com/fetch",
        requested_url="https://example.com/fetch",
        status_code=status,
        headers=httpx2.Headers({"content-type": "text/plain"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _baseline(body: str = "preview of /preview") -> Baseline:
    """
    Args:
        body (str): The pre-injection response body — a marker already here is
            suppressed rather than reported.

    Returns:
        Baseline: The baseline each payload's response is compared against.
    """
    return Baseline(200, body, normalize_body(body), len(body), 1.0)


def _ctx(render: Callable[[str], Response | None], *, host: str = "example.com") -> DetectCtx:
    """
    Args:
        render (Callable[[str], Response | None]): Maps an injected value to the
            target's response, or ``None`` to model a denied request.
        host (str): The target host, substituted into ``user@host`` payloads.

    Returns:
        DetectCtx: A detector context whose ``send`` calls ``render``.
    """

    async def send(
        point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None:
        return render(value)

    return DetectCtx(send=send, delay_s=5, host=host)


async def test_aws_metadata_marker_is_a_critical_hit() -> None:
    """An AWS credential blob in the response is a CRITICAL, HIGH-confidence hit."""
    hits = await ssrf.detect(
        _POINT,
        _baseline(),
        _ctx(lambda v: _resp(_AWS_CREDS if "169.254.169.254" in v else "preview")),
    )
    assert len(hits) == 1
    hit = hits[0]
    assert hit.kind == "ssrf-metadata"
    assert hit.check_id == "injection.ssrf.metadata"
    assert hit.severity is Severity.CRITICAL
    assert hit.confidence is Confidence.HIGH
    assert "AWS" in hit.title
    assert "AccessKeyId" in hit.evidence[2][1]


async def test_each_metadata_provider_marker_is_detected() -> None:
    """GCP, Azure, AliCloud and Kubernetes metadata markers are each recognised and named."""
    cases = {
        "GCP": '{"machineType":"projects/1/machineTypes/e2-small","serviceAccounts":{}}',
        "Azure": '{"azEnvironment":"AzurePublicCloud","vmId":"abc","resourceGroupName":"rg"}',
        "AliCloud": '{"owner-account-id":"12345","region-id":"cn-hangzhou"}',
        "Kubernetes": '{"kind":"Status","status":"Failure","reason":"Forbidden","code":403}',
    }
    for provider, body in cases.items():
        hits = await ssrf.detect(_POINT, _baseline(), _ctx(lambda v, b=body: _resp(b)))
        assert hits and hits[0].kind == "ssrf-metadata", provider
        assert provider in hits[0].title, provider


async def test_file_scheme_read_is_a_high_hit() -> None:
    """A ``file://`` payload that returns ``/etc/passwd`` content is a HIGH ssrf-internal hit."""
    hits = await ssrf.detect(
        _POINT,
        _baseline(),
        _ctx(lambda v: _resp(_PASSWD if v.lower().startswith("file:") else "preview")),
    )
    assert len(hits) == 1
    assert hits[0].kind == "ssrf-internal"
    assert hits[0].severity is Severity.HIGH
    assert hits[0].confidence is Confidence.HIGH
    assert "file://" in hits[0].title
    assert "root:x:0:0" in hits[0].evidence[2][1]


async def test_internal_service_fingerprint_is_a_high_hit() -> None:
    """A loopback payload that returns a Redis banner is a HIGH ssrf-internal hit."""

    def render(value: str) -> Response:
        if any(t in value for t in ("127.0.0.1", "localhost", "[::1]")):
            return _resp(_REDIS)
        return _resp("preview")

    hits = await ssrf.detect(_POINT, _baseline(), _ctx(render))
    assert len(hits) == 1
    assert hits[0].kind == "ssrf-internal"
    assert "Redis" in hits[0].title


async def test_ssrf_error_that_echoes_the_url_is_a_medium_hit() -> None:
    """A "connection refused" error quoting our URL proves a server-side fetch (MEDIUM)."""

    def render(value: str) -> Response:
        if value.startswith(("http://", "https://")):
            return _resp(f"failed to fetch {value}: Connection refused", status=200)
        return _resp("preview")

    hits = await ssrf.detect(_POINT, _baseline(), _ctx(render))
    assert len(hits) == 1
    assert hits[0].kind == "ssrf-internal"
    assert hits[0].confidence is Confidence.MEDIUM
    assert "fetched server-side" in hits[0].title


async def test_gateway_status_that_echoes_the_url_is_a_medium_hit() -> None:
    """A 5xx gateway response quoting our URL is a MEDIUM hit too."""

    def render(value: str) -> Response:
        if value.startswith("http://"):
            return _resp(f"upstream error for {value}", status=502)
        return _resp("preview")

    hits = await ssrf.detect(_POINT, _baseline(), _ctx(render))
    assert hits and hits[0].confidence is Confidence.MEDIUM


async def test_generic_500_without_the_url_echoed_is_not_a_hit() -> None:
    """A bare 500 that does not quote our URL is not attributable to us."""
    hits = await ssrf.detect(
        _POINT, _baseline(), _ctx(lambda v: _resp("Internal Server Error", status=500))
    )
    assert hits == []


async def test_payload_echoed_without_any_marker_is_not_a_hit() -> None:
    """The payload merely reflected back, with no marker, is not a hit."""
    hits = await ssrf.detect(_POINT, _baseline(), _ctx(lambda v: _resp(f"you asked for {v}")))
    assert hits == []


async def test_marker_already_in_the_baseline_is_suppressed() -> None:
    """A marker present in the baseline body is not reported as a new finding."""
    hits = await ssrf.detect(_POINT, _baseline(_AWS_CREDS), _ctx(lambda v: _resp(_AWS_CREDS)))
    assert hits == []


async def test_host_is_substituted_into_the_payload() -> None:
    """The ``user@host`` bypass payloads carry the real target host."""
    seen: list[str] = []

    def render(value: str) -> Response:
        seen.append(value)
        return _resp("preview")

    await ssrf.detect(_POINT, _baseline(), _ctx(render, host="victim.test"))
    assert any("victim.test@169.254.169.254" in p for p in seen)
    assert any("victim.test@127.0.0.1" in p for p in seen)


async def test_detector_stops_when_send_returns_none() -> None:
    """When ``send`` returns ``None`` (budget denied) the detector stops there."""
    calls = 0

    def render(value: str) -> Response | None:
        nonlocal calls
        calls += 1
        return None if calls >= 3 else _resp("preview")

    hits = await ssrf.detect(_POINT, _baseline(), _ctx(render))
    assert hits == []
    assert calls == 3  # stopped at the first None


async def test_first_hit_wins_and_stops_the_scan() -> None:
    """Once a payload hits, the detector reports it and sends nothing more."""
    seen: list[str] = []

    def render(value: str) -> Response:
        seen.append(value)
        return _resp(_AWS_CREDS)  # every payload "hits" — the first must win

    hits = await ssrf.detect(_POINT, _baseline(), _ctx(render))
    assert len(hits) == 1
    assert len(seen) == 1


_NOTE = InjectionPoint("GET", "https://example.com/fetch", "note", "hi", (("note", "hi"),))


def _recording(seen: list[str], body: str = "preview") -> Callable[[str], Response]:
    """
    Args:
        seen (list[str]): Every value sent is appended to it.
        body (str): What the target answers to every value.

    Returns:
        Callable[[str], Response]: A render function that records the values.
    """

    def render(value: str) -> Response:
        seen.append(value)
        return _resp(body)

    return render


def _full_set() -> list[str]:
    """
    Returns:
        list[str]: Every payload a URL-shaped point gets, in order, before ``{host}`` is filled.
    """
    return [*payloads.SSRF_METADATA, *payloads.SSRF_FILE, *payloads.SSRF_INTERNAL]


async def test_a_point_that_does_not_look_like_a_url_gets_only_the_canary() -> None:
    """Two metadata, one ``file://`` and two loopback payloads, and nothing else."""
    seen: list[str] = []
    assert await ssrf.detect(_NOTE, _baseline(), _ctx(_recording(seen))) == []
    assert seen == [
        payloads.SSRF_METADATA[0],
        payloads.SSRF_METADATA[1],
        payloads.SSRF_FILE[0],
        payloads.SSRF_INTERNAL[0],
        payloads.SSRF_INTERNAL[1],
    ]


async def test_a_url_shaped_point_gets_every_payload() -> None:
    """The full set, in order, with the target host in the ``user@host`` slots."""
    seen: list[str] = []
    assert await ssrf.detect(_POINT, _baseline(), _ctx(_recording(seen))) == []
    assert seen == [t.replace("{host}", "example.com") for t in _full_set()]


async def test_an_ipv6_target_skips_the_payloads_with_the_host_as_userinfo() -> None:
    """A host that cannot be userinfo leaves out the ``{host}@`` payloads, never sending None."""
    seen: list[str] = []
    assert await ssrf.detect(_POINT, _baseline(), _ctx(_recording(seen), host="[::1]")) == []
    assert seen == [t.replace("{host}", "[::1]") for t in _full_set() if "{host}@" not in t]
    assert len(seen) == len(_full_set()) - 2


async def test_a_file_signature_answering_a_non_file_payload_is_not_a_file_read() -> None:
    """The ``file://`` proof counts only for a ``file:`` payload."""

    def render(value: str) -> Response:
        return _resp("preview" if value.lower().startswith("file:") else _PASSWD)

    assert await ssrf.detect(_POINT, _baseline(), _ctx(render)) == []


async def test_each_proof_already_in_the_baseline_is_suppressed() -> None:
    """The file, service and error proofs each need to be absent from the baseline."""

    def file_read(value: str) -> Response:
        return _resp(_PASSWD if value.lower().startswith("file:") else "preview")

    def redis(value: str) -> Response:
        return _resp(_REDIS if "127.0.0.1" in value else "preview")

    def refused(value: str) -> Response:
        return _resp(f"failed to fetch {value}: Connection refused")

    for render, baseline in (
        (file_read, _PASSWD),
        (redis, _REDIS),
        (refused, "Connection refused"),
    ):
        assert await ssrf.detect(_POINT, _baseline(), _ctx(render)), render.__name__  # control
        assert await ssrf.detect(_POINT, _baseline(baseline), _ctx(render)) == [], render.__name__


async def test_an_error_that_does_not_echo_the_injected_url_is_not_a_hit() -> None:
    """A connection error that names no URL of ours is not tied to the payload (ADR-4)."""
    hits = await ssrf.detect(_POINT, _baseline(), _ctx(lambda v: _resp("Connection refused")))
    assert hits == []


async def test_a_file_payload_has_no_host_to_echo_for_the_error_proof() -> None:
    """``file:///...`` has an empty authority, so an error after it proves nothing."""

    def render(value: str) -> Response:
        if value.startswith("file:///"):
            return _resp(f"{value}: Connection refused")
        return _resp("preview")

    assert await ssrf.detect(_POINT, _baseline(), _ctx(render)) == []


async def test_each_gateway_status_that_echoes_the_url_is_a_hit() -> None:
    """502, 503 and 504 are each a gateway error; a status the baseline also had is not new."""
    for status in (502, 503, 504):

        def render(value: str, code: int = status) -> Response:
            return _resp(f"upstream error for {value}", status=code)

        hits = await ssrf.detect(_POINT, _baseline(), _ctx(render))
        assert hits and hits[0].confidence is Confidence.MEDIUM, status
        same = Baseline(status, "preview", "preview", 7, 1.0)
        assert await ssrf.detect(_POINT, same, _ctx(render)) == [], status


def test_the_authority_is_the_host_the_server_connects_to() -> None:
    """``user@`` and a ``#@host`` fragment are not the host the request goes to."""
    assert ssrf._authority("http://example.com@127.0.0.1/") == "127.0.0.1"
    assert ssrf._authority("http://169.254.169.254#@example.com/latest/") == "169.254.169.254"
    assert ssrf._authority("http://127.0.0.1:8080/x") == "127.0.0.1:8080"


async def test_the_evidence_is_the_one_line_that_holds_the_marker() -> None:
    """The lines around the match stay out of the evidence; the last line keeps its end."""
    body = f"<pre>start\n{_AWS_CREDS}\nend</pre>"
    (hit,) = await ssrf.detect(_POINT, _baseline(), _ctx(lambda v: _resp(body)))
    assert hit.evidence[2][1] == _AWS_CREDS
    (hit,) = await ssrf.detect(_POINT, _baseline(), _ctx(lambda v: _resp("start\n" + _AWS_CREDS)))
    assert hit.evidence[2][1] == _AWS_CREDS


def test_the_evidence_line_is_cut_at_200_characters() -> None:
    """A line of exactly 200 characters is whole; one more is cut there and marked."""
    line = "x" * 200
    assert ssrf._snippet(line, 0) == line
    assert ssrf._snippet(line + "y", 0) == line + "…"
