"""
csrf.form.no-token (spec 007 RF-08/09), csrf.form.token-not-enforced (spec 017 RF-09/10) and
csrf.form.state-change-over-get (issue #144).

Forms are built by hand with ``_form`` and handed to the check via
``ScanContext.forms``; ``_run`` also supplies the crawl's ``Set-Cookie`` headers,
which weight the confidence. The active check issues no request: ``_hit`` builds the
``CsrfHit`` the ``CsrfScanner`` pass would leave on ``Observations.csrf_hits``.
"""

from __future__ import annotations

import pytest

from tests.support import make_context, make_page
from webvigil.checks.csrf.checks import (
    GetStateChangeCheck,
    NoCsrfTokenCheck,
    TokenNotEnforcedCheck,
)
from webvigil.checks.csrf.scanner import CsrfHit
from webvigil.core.config import ScanConfig
from webvigil.core.context import Observations
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


async def test_a_button_only_post_form_is_flagged() -> None:
    """A POST form that is only a button ("Generate") changes state with no token (#145)."""
    form = Form(
        method="POST",
        action="https://example.com/vulnerabilities/weak_id/",
        enctype="application/x-www-form-urlencoded",
        fields=(),
        source_url="https://example.com/account",
        labels=("Generate",),
    )
    findings = await _run([form])
    assert len(findings) == 1
    assert findings[0].evidence[1].content == "(none)"


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


# ---------------------------------------------------------------------------
# csrf.form.token-not-enforced — the active check (spec 017)
# ---------------------------------------------------------------------------

_ACTION = "https://example.com/profile"


def _hit(url: str = _ACTION, replay: str = "token removed") -> CsrfHit:
    """
    Args:
        url (str): The form action the pass confirmed.
        replay (str): The replay that was accepted. Defaults to ``token removed``.

    Returns:
        CsrfHit: A hit as the confirmation pass would record it.
    """
    return CsrfHit(
        url=url,
        source_url="https://example.com/account",
        replay=replay,
        token_fields=("csrf_token",),
        control="POST /profile -> 200",
        attack="POST /profile -> 200",
    )


async def _run_active(
    hits: tuple[CsrfHit, ...],
    *,
    cookies: list[str] | None = None,
    set_cookies: list[str] | None = None,
):
    """
    Args:
        hits (tuple[CsrfHit, ...]): The pass's confirmed forms.
        cookies (list[str] | None): ``[auth] cookies`` configured for the scan.
        set_cookies (list[str] | None): Raw ``Set-Cookie`` values seen on the crawl.

    Returns:
        list: The findings the active check produced.
    """
    page = make_page(url="https://example.com/account", set_cookies=set_cookies or [])
    config = ScanConfig.model_validate({"auth": {"cookies": cookies or []}})
    ctx = make_context(
        page, config=config, observations=Observations(csrf_hits=hits), forms=[_form("x")]
    )
    return await TokenNotEnforcedCheck().run(ctx)


async def test_a_confirmed_form_becomes_one_finding() -> None:
    """One hit is one finding at the form's action, with the proof in the evidence."""
    findings = await _run_active((_hit(),), cookies=["session=abc"])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.location.url == _ACTION and finding.location.method == "POST"
    assert "accepted a cross-site request" in finding.title
    labels = {item.label: item.content for item in finding.evidence}
    assert labels["replay"] == "token removed"
    assert labels["control"] == "POST /profile -> 200"
    assert labels["credentials"] == "session cookies configured"


async def test_no_hits_means_no_findings() -> None:
    """With nothing confirmed (or the pass off) the check emits nothing."""
    assert await _run_active(()) == []


@pytest.mark.parametrize(
    "set_cookies, cookies, expected",
    [
        (["session=a; Path=/"], ["session=a"], Confidence.HIGH),
        (["session=a; Path=/"], [], Confidence.MEDIUM),  # anonymous replay: capped
        (["session=a; Path=/; SameSite=Lax"], ["session=a"], Confidence.LOW),
        (["session=a; Path=/; SameSite=Lax"], [], Confidence.LOW),
        ([], ["session=a"], Confidence.MEDIUM),
    ],
)
async def test_confidence_follows_samesite_and_is_capped_without_a_cookie(
    set_cookies: list[str], cookies: list[str], expected: Confidence
) -> None:
    """The 007 SameSite weighting applies; with no configured cookie it never exceeds MEDIUM."""
    findings = await _run_active((_hit(),), cookies=cookies, set_cookies=set_cookies)
    assert findings[0].confidence is expected


async def test_a_confirmation_replaces_the_passive_finding_for_the_same_action() -> None:
    """The passive check skips a form the active pass confirmed — one proof, one finding."""
    page = make_page(url="https://example.com/account")
    forms = [_form("nickname"), _form("bio", action="https://example.com/other")]
    ctx = make_context(page, forms=forms, observations=Observations(csrf_hits=(_hit(),)))
    findings = await NoCsrfTokenCheck().run(ctx)
    assert [f.location.url for f in findings] == ["https://example.com/other"]


async def test_the_passive_check_is_unchanged_without_hits() -> None:
    """With no confirmation the passive finding is exactly what 007 emitted."""
    findings = await _run([_form("nickname")])
    assert len(findings) == 1 and findings[0].check_id == "csrf.form.no-token"


# ---------------------------------------------------------------------------
# A GET form that changes state (issue #144)
# ---------------------------------------------------------------------------

_PASSWORD_CHANGE = {"password_new": "password", "password_conf": "password", "Change": "submit"}


async def _run_get(forms: list[Form], *, set_cookies: list[str] | None = None):
    """
    Args:
        forms (list[Form]): The form inventory.
        set_cookies (list[str] | None): Raw ``Set-Cookie`` values seen on the crawl.

    Returns:
        list: The findings ``csrf.form.state-change-over-get`` produced.
    """
    page = make_page(url="https://example.com/account", set_cookies=set_cookies or [])
    return await GetStateChangeCheck().run(make_context(page, forms=forms))


def _change_form() -> Form:
    """
    Returns:
        Form: A DVWA-shaped GET password-change form.
    """
    return _form(
        *_PASSWORD_CHANGE,
        method="GET",
        action="https://example.com/csrf/",
        types=_PASSWORD_CHANGE,
    )


async def test_a_password_change_over_get_is_flagged() -> None:
    """The DVWA module: one finding at the form action, with the reason in the evidence."""
    (finding,) = await _run_get([_change_form()])
    assert finding.check_id == "csrf.form.state-change-over-get"
    assert finding.location.method == "GET"
    assert finding.location.url == "https://example.com/csrf/"
    evidence = {e.label: e.content for e in finding.evidence}
    assert evidence["why"] == "password change"
    assert evidence["fields"] == "password_new, password_conf, Change"
    assert "password fields" in finding.description


async def test_a_destructive_verb_over_get_is_flagged() -> None:
    """A GET form whose action names a destructive operation."""
    form = _form("id", method="GET", action="https://example.com/items/delete")
    (finding,) = await _run_get([form])
    assert {e.label: e.content for e in finding.evidence}["why"] == "destructive verb"


async def test_a_token_field_suppresses_the_get_finding() -> None:
    """A GET form that carries an anti-CSRF token is not reported."""
    form = _form(
        *_PASSWORD_CHANGE,
        "user_token",
        method="GET",
        action="https://example.com/csrf/",
        types=_PASSWORD_CHANGE,
    )
    assert await _run_get([form]) == []


async def test_search_login_and_post_forms_are_not_get_findings() -> None:
    """The other form kinds are left to their own checks, or to none."""
    forms = [
        _form("q", method="GET", action="https://example.com/search"),
        _form(
            "username",
            "password",
            method="GET",
            action="https://example.com/login",
            types={"password": "password"},
        ),
        _form(*_PASSWORD_CHANGE, action="https://example.com/csrf/", types=_PASSWORD_CHANGE),
    ]
    assert await _run_get(forms) == []


async def test_the_get_check_does_not_touch_the_post_check() -> None:
    """The GET form is not reported by ``csrf.form.no-token`` either: it reads POST forms only."""
    assert await _run([_change_form()]) == []


@pytest.mark.parametrize(
    "set_cookies, expected",
    [
        (["session=abc; Path=/"], Confidence.MEDIUM),
        (["session=abc; Path=/; SameSite=Lax"], Confidence.MEDIUM),
        (["session=abc; Path=/; SameSite=Strict"], Confidence.LOW),
        (["theme=dark; Path=/"], Confidence.LOW),
    ],
)
async def test_get_confidence_follows_samesite_and_lax_does_not_lower_it(
    set_cookies: list[str], expected: Confidence
) -> None:
    """Lax rides a top-level GET navigation, so only Strict (or no cookie evidence) is LOW."""
    (finding,) = await _run_get([_change_form()], set_cookies=set_cookies)
    assert finding.confidence is expected
