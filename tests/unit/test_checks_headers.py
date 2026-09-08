"""
Header checks: vulnerable fixture reports, hardened fixture is silent — RF-16, RF-17.
"""

from __future__ import annotations

import pytest

from tests.support import hardened_headers, make_context, make_page
from webvigil.checks.headers.csp import CspCheck
from webvigil.checks.headers.hsts import HstsCheck
from webvigil.checks.headers.misc import (
    ContentTypeOptionsCheck,
    CrossOriginIsolationCheck,
    FrameOptionsCheck,
    PermissionsPolicyCheck,
    ReferrerPolicyCheck,
)
from webvigil.checks.headers.revealing import RevealingHeadersCheck
from webvigil.core.findings import Severity

_ALL_HEADER_CHECKS = [
    CspCheck,
    HstsCheck,
    FrameOptionsCheck,
    ContentTypeOptionsCheck,
    ReferrerPolicyCheck,
    PermissionsPolicyCheck,
    CrossOriginIsolationCheck,
    RevealingHeadersCheck,
]


@pytest.mark.parametrize("check_cls", _ALL_HEADER_CHECKS)
async def test_hardened_response_produces_no_findings(check_cls: type) -> None:
    ctx = make_context(make_page(headers=hardened_headers(), text="<html></html>"))
    assert await check_cls().run(ctx) == []


async def test_csp_missing() -> None:
    ctx = make_context(make_page(headers={}))
    findings = await CspCheck().run(ctx)
    assert [f.fingerprint for f in findings]
    assert findings[0].severity is Severity.MEDIUM
    assert "missing" in findings[0].title.lower()


async def test_csp_unsafe_inline_is_flagged() -> None:
    ctx = make_context(
        make_page(headers={"content-security-policy": "script-src 'self' 'unsafe-inline'"})
    )
    keys = {f.title for f in await CspCheck().run(ctx)}
    assert any("unsafe-inline" in title for title in keys)


async def test_hsts_missing_on_https_only() -> None:
    https = await HstsCheck().run(make_context(make_page(headers={})))
    assert https and https[0].severity is Severity.MEDIUM

    http_ctx = make_context(make_page(url="http://example.com/", headers={}))
    assert await HstsCheck().run(http_ctx) == []  # TLS check owns HTTP-only sites


async def test_hsts_weaknesses() -> None:
    ctx = make_context(make_page(headers={"strict-transport-security": "max-age=100"}))
    keys = {f.title for f in await HstsCheck().run(ctx)}
    assert any("max-age" in k for k in keys)
    assert any("includeSubDomains" in k for k in keys)


async def test_frame_options_missing_but_ok_with_frame_ancestors() -> None:
    assert await FrameOptionsCheck().run(make_context(make_page(headers={})))
    ok = make_context(make_page(headers={"content-security-policy": "frame-ancestors 'none'"}))
    assert await FrameOptionsCheck().run(ok) == []


async def test_content_type_options() -> None:
    assert await ContentTypeOptionsCheck().run(make_context(make_page(headers={})))
    ok = make_context(make_page(headers={"x-content-type-options": "nosniff"}))
    assert await ContentTypeOptionsCheck().run(ok) == []


async def test_referrer_policy_missing_and_leaking() -> None:
    assert await ReferrerPolicyCheck().run(make_context(make_page(headers={})))
    leaking = make_context(make_page(headers={"referrer-policy": "unsafe-url"}))
    findings = await ReferrerPolicyCheck().run(leaking)
    assert findings and "leaks" in findings[0].title


async def test_revealing_headers() -> None:
    ctx = make_context(
        make_page(headers={"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/8.1.2"})
    )
    keys = {f.location.header for f in await RevealingHeadersCheck().run(ctx)}
    assert keys == {"Server", "X-Powered-By"}

    quiet = make_context(make_page(headers={"server": "cloudflare"}))
    assert await RevealingHeadersCheck().run(quiet) == []
