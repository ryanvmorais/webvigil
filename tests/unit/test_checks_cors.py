"""
CORS check: reflective origin, wildcard+credentials, null — RF-20.

Each case stubs the target's response headers with ``httpx_mock`` and runs the
check through a real :class:`~webvigil.http.client.HttpClient` (the check sends
one extra ``Origin`` request).
"""

from __future__ import annotations

import pytest

from tests.support import make_context, make_page
from webvigil.checks.cors.check import CorsCheck
from webvigil.core.config import ScanConfig
from webvigil.core.findings import Severity
from webvigil.core.target import Target
from webvigil.http.client import HttpClient

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)

_URL = "https://example.com/"


async def _run(response_headers: dict[str, str], httpx_mock: object) -> list:
    """
    Run the CORS check against a target that replies with ``response_headers``.

    Args:
        response_headers (dict[str, str]): Headers to return for the check's
            probe request.
        httpx_mock: The ``pytest-httpx`` fixture.

    Returns:
        list: The findings the check produced.
    """
    httpx_mock.add_response(url=_URL, headers=response_headers, text="ok")  # type: ignore[attr-defined]
    async with HttpClient(Target.parse(_URL), ScanConfig()) as http:
        ctx = make_context(make_page(url=_URL), http=http)
        return await CorsCheck().run(ctx)


async def test_reflective_origin_with_credentials_is_high(httpx_mock: object) -> None:
    """Echoing the probe Origin back with ``credentials: true`` is a HIGH finding."""
    findings = await _run(
        {
            "access-control-allow-origin": "https://webvigil-cors-probe.example",
            "access-control-allow-credentials": "true",
        },
        httpx_mock,
    )
    assert findings and findings[0].severity is Severity.HIGH
    assert findings[0].fingerprint


async def test_wildcard_with_credentials(httpx_mock: object) -> None:
    """``*`` plus credentials — a broken CORS setup — is reported even though browsers reject it."""
    findings = await _run(
        {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"},
        httpx_mock,
    )
    assert findings and "combined with credentials" in findings[0].title


async def test_null_origin(httpx_mock: object) -> None:
    """An allowed ``null`` origin is reachable from sandboxed iframes and is flagged."""
    findings = await _run({"access-control-allow-origin": "null"}, httpx_mock)
    assert findings and "null" in findings[0].title.lower()


async def test_safe_cors_is_silent(httpx_mock: object) -> None:
    """A fixed allow-listed origin, or no CORS headers at all, produces nothing."""
    assert await _run({"access-control-allow-origin": "https://trusted.example"}, httpx_mock) == []
    assert await _run({}, httpx_mock) == []
