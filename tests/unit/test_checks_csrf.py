"""
csrf.form.no-token — a state-changing form with no anti-CSRF token — spec 007 RF-08/09.

Forms are built by hand with ``_form`` and handed to the check via
``ScanContext.forms``; ``_run`` also supplies the crawl's ``Set-Cookie`` headers,
which weight the confidence.
"""

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
    """
    Build a :class:`~webvigil.crawler.forms.Form` with the named fields.

    Args:
        *fields (str): Field names; each is a ``text`` input unless overridden.
        method (str): Form method. Defaults to ``"POST"``.
        action (str): Absolute form action.
        types (dict[str, str] | None): Per-field type overrides.

    Returns:
        Form: The assembled form.
    """
    types = types or {}
    return Form(
        method=method,
        action=action,
        enctype="application/x-www-form-urlencoded",
        fields=tuple(FormField(name=n, type=types.get(n, "text"), value="") for n in fields),
        source_url="https://example.com/account",
    )


async def _run(forms: list[Form], *, set_cookies: list[str] | None = None):
    """
    Run the CSRF check over ``forms`` with the given crawl cookies.

    Args:
        forms (list[Form]): The form inventory.
        set_cookies (list[str] | None): Raw ``Set-Cookie`` values seen on the
            crawl, which set the session-cookie ``SameSite``.

    Returns:
        list: The findings the check produced.
    """
    page = make_page(url="https://example.com/account", set_cookies=set_cookies or [])
    ctx = make_context(page, forms=forms)
    return await NoCsrfTokenCheck().run(ctx)


# ---------------------------------------------------------------------------
# Which forms are flagged
# ---------------------------------------------------------------------------


async def test_a_tokenless_post_form_is_flagged() -> None:
    """A POST form with no token field yields one finding located at its action."""
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
    """A field matching any known anti-CSRF token name clears the form."""
    assert await _run([_form("nickname", token_name)]) == []


async def test_a_get_form_is_never_flagged() -> None:
    """Only state-changing (POST) forms are CSRF targets."""
    assert await _run([_form("q", method="GET", action="https://example.com/search")]) == []


async def test_a_login_form_is_excluded() -> None:
    """A login form has no session to protect yet, so it is not a target."""
    form = _form("username", "password", action="https://example.com/login")
    assert await _run([form]) == []


# ---------------------------------------------------------------------------
# Confidence weighting by the session cookie's SameSite
# ---------------------------------------------------------------------------


async def test_confidence_is_high_without_samesite() -> None:
    """A session cookie with no ``SameSite`` leaves the form fully exploitable."""
    findings = await _run([_form("x")], set_cookies=["session=abc; Path=/"])
    assert findings[0].confidence is Confidence.HIGH


async def test_confidence_is_low_with_samesite_lax() -> None:
    """``SameSite=Lax`` on the session cookie makes the finding barely exploitable."""
    findings = await _run([_form("x")], set_cookies=["session=abc; Path=/; SameSite=Lax"])
    assert findings[0].confidence is Confidence.LOW


async def test_confidence_is_medium_without_a_session_cookie() -> None:
    """With no session cookie observed the check cannot judge exploitability — MEDIUM."""
    findings = await _run([_form("x")], set_cookies=["theme=dark; Path=/"])
    assert findings[0].confidence is Confidence.MEDIUM


async def test_the_same_action_seen_twice_shares_a_fingerprint() -> None:
    """Two forms with the same action collapse to one finding in the fingerprint dedup."""
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
