"""
In-band SSRF detector — spec 009 RF-01..RF-08, RF-13.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

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
    return Response(
        url="https://example.com/fetch",
        requested_url="https://example.com/fetch",
        status_code=status,
        headers=httpx.Headers({"content-type": "text/plain"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _baseline(body: str = "preview of /preview") -> Baseline:
    return Baseline(200, body, normalize_body(body), len(body), 1.0)


def _ctx(render: Callable[[str], Response | None], *, host: str = "example.com") -> DetectCtx:
    async def send(
        point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None:
        return render(value)

    return DetectCtx(send=send, delay_s=5, host=host)


async def test_aws_metadata_marker_is_a_critical_hit() -> None:
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
    def render(value: str) -> Response:
        if any(t in value for t in ("127.0.0.1", "localhost", "[::1]")):
            return _resp(_REDIS)
        return _resp("preview")

    hits = await ssrf.detect(_POINT, _baseline(), _ctx(render))
    assert len(hits) == 1
    assert hits[0].kind == "ssrf-internal"
    assert "Redis" in hits[0].title


async def test_ssrf_error_that_echoes_the_url_is_a_medium_hit() -> None:
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
    def render(value: str) -> Response:
        if value.startswith("http://"):
            return _resp(f"upstream error for {value}", status=502)
        return _resp("preview")

    hits = await ssrf.detect(_POINT, _baseline(), _ctx(render))
    assert hits and hits[0].confidence is Confidence.MEDIUM


async def test_generic_500_without_the_url_echoed_is_not_a_hit() -> None:
    hits = await ssrf.detect(
        _POINT, _baseline(), _ctx(lambda v: _resp("Internal Server Error", status=500))
    )
    assert hits == []


async def test_payload_echoed_without_any_marker_is_not_a_hit() -> None:
    hits = await ssrf.detect(_POINT, _baseline(), _ctx(lambda v: _resp(f"you asked for {v}")))
    assert hits == []


async def test_marker_already_in_the_baseline_is_suppressed() -> None:
    hits = await ssrf.detect(_POINT, _baseline(_AWS_CREDS), _ctx(lambda v: _resp(_AWS_CREDS)))
    assert hits == []


async def test_host_is_substituted_into_the_payload() -> None:
    seen: list[str] = []

    def render(value: str) -> Response:
        seen.append(value)
        return _resp("preview")

    await ssrf.detect(_POINT, _baseline(), _ctx(render, host="victim.test"))
    assert any("victim.test@169.254.169.254" in p for p in seen)
    assert any("victim.test@127.0.0.1" in p for p in seen)


async def test_detector_stops_when_send_returns_none() -> None:
    calls = 0

    def render(value: str) -> Response | None:
        nonlocal calls
        calls += 1
        return None if calls >= 3 else _resp("preview")

    hits = await ssrf.detect(_POINT, _baseline(), _ctx(render))
    assert hits == []
    assert calls == 3  # stopped at the first None


async def test_first_hit_wins_and_stops_the_scan() -> None:
    seen: list[str] = []

    def render(value: str) -> Response:
        seen.append(value)
        return _resp(_AWS_CREDS)  # every payload "hits" — the first must win

    hits = await ssrf.detect(_POINT, _baseline(), _ctx(render))
    assert len(hits) == 1
    assert len(seen) == 1
