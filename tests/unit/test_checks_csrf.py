"""csrf.form.no-token — a state-changing form with no anti-CSRF token — spec 007 RF-08/09."""

from __future__ import annotations

import pytest

from tests.support import make_context, make_page
from webvigil.checks.csrf.checks import NoCsrfTokenCheck
from webvigil.core.findings import Confidence
from webvigil.crawler.forms import Form, FormField


def _form(
    *fields: str,
    method: str = "POST",
    action: str = "https://example.com/profile",
    types: dict[str, str] | None = None,
) -> Form:
    types = types or {}
    return Form(
        method=method,
        action=action,
        enctype="application/x-www-form-urlencoded",
        fields=tuple(FormField(name=n, type=types.get(n, "text"), value="") for n in fields),
        source_url="https://example.com/account",
    )


async def _run(forms: list[Form], *, set_cookies: list[str] | None = None):
    page = make_page(url="https://example.com/account", set_cookies=set_cookies or [])
    ctx = make_context(page, forms=forms)
    return await NoCsrfTokenCheck().run(ctx)


async def test_a_tokenless_post_form_is_flagged() -> None:
    findings = await _run([_form("nickname", "bio")])
    assert len(findings) == 1
    assert findings[0].check_id == "csrf.form.no-token"
    assert findings[0].location.method == "POST"
    assert findings[0].location.url == "https://example.com/profile"
    assert "nickname, bio" in findings[0].evidence[1].content


@pytest.mark.parametrize(
    "token_name",
    [
        "csrf_token",
        "authenticity_token",
        "__RequestVerificationToken",
        "csrfmiddlewaretoken",
        "_token",
    ],
)
async def test_a_recognised_token_field_suppresses_the_finding(token_name: str) -> None:
    assert await _run([_form("nickname", token_name)]) == []


async def test_a_get_form_is_never_flagged() -> None:
    assert await _run([_form("q", method="GET", action="https://example.com/search")]) == []


async def test_a_login_form_is_excluded() -> None:
    form = _form("username", "password", action="https://example.com/login")
    assert await _run([form]) == []


async def test_confidence_is_high_without_samesite() -> None:
    findings = await _run([_form("x")], set_cookies=["session=abc; Path=/"])
    assert findings[0].confidence is Confidence.HIGH


async def test_confidence_is_low_with_samesite_lax() -> None:
    findings = await _run([_form("x")], set_cookies=["session=abc; Path=/; SameSite=Lax"])
    assert findings[0].confidence is Confidence.LOW


async def test_confidence_is_medium_without_a_session_cookie() -> None:
    findings = await _run([_form("x")], set_cookies=["theme=dark; Path=/"])
    assert findings[0].confidence is Confidence.MEDIUM


async def test_the_same_action_seen_twice_shares_a_fingerprint() -> None:
    # ctx.forms is crawler-deduped, but if the same action reaches the check twice the
    # findings collapse in the orchestrator's fingerprint dedup.
    form = _form("x")
    other = Form(
        method="POST",
        action="https://example.com/profile",
        enctype="application/x-www-form-urlencoded",
        fields=(FormField(name="x", type="text", value=""),),
        source_url="https://example.com/account/settings",
    )
    findings = await _run([form, other])
    assert len({f.fingerprint for f in findings}) == 1
