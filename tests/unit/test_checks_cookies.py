"""
Cookie-flag check: vulnerable and hardened fixtures — RF-18.
"""

from __future__ import annotations

from tests.support import make_context, make_page
from webvigil.checks.cookies.flags import CookieFlagsCheck
from webvigil.core.findings import Severity


async def _run(*set_cookies: str, url: str = "https://example.com/") -> list:
    page = make_page(url=url, set_cookies=set_cookies)
    return await CookieFlagsCheck().run(make_context(page))


async def test_insecure_session_cookie_is_flagged() -> None:
    findings = await _run("session=abc; Path=/")
    keys = {f.fingerprint: f for f in findings}
    titles = {f.title for f in findings}
    assert any("Secure" in t for t in titles)
    assert any("HttpOnly" in t for t in titles)
    assert any("SameSite" in t for t in titles)
    assert all(f.location.cookie == "session" for f in keys.values())


async def test_hardened_cookie_produces_no_findings() -> None:
    findings = await _run("__Host-session=abc; Secure; HttpOnly; Path=/; SameSite=Lax")
    assert findings == []


async def test_host_prefix_violation() -> None:
    findings = await _run("__Host-session=abc; Secure; HttpOnly; Path=/app; SameSite=Lax")
    assert any("__Host-" in f.title for f in findings)


async def test_samesite_none_without_secure() -> None:
    findings = await _run("t=1; HttpOnly; SameSite=None; Path=/")
    assert any("SameSite=None" in f.title for f in findings)
    assert any(f.severity is Severity.MEDIUM for f in findings)


async def test_http_site_does_not_require_secure() -> None:
    findings = await _run("t=1; HttpOnly; SameSite=Lax; Path=/", url="http://example.com/")
    assert findings == []
