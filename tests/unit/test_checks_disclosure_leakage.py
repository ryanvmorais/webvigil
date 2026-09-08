"""
``disclosure.session-id-in-url`` and ``disclosure.private-ip`` — spec 013 RF-13, RF-14.

Pure over synthetic pages built with :func:`make_page` (and one hand-built
:class:`Page` for the redirect case). No HTTP is issued.
"""

from __future__ import annotations

import httpx

from tests.support import make_context, make_page
from webvigil.checks.disclosure.leakage import PrivateIpInBodyCheck, SessionIdInUrlCheck
from webvigil.core.context import Page
from webvigil.core.findings import Category, ScanMode


async def _session_titles(page: Page) -> list[str]:
    """
    Args:
        page (Page): The page under test.

    Returns:
        list[str]: The ``SessionIdInUrlCheck`` finding titles.
    """
    ctx = make_context(page, target_url="https://app.example/")
    return [f.title for f in await SessionIdInUrlCheck().run(ctx)]


# ---------------------------------------------------------------------------
# disclosure.session-id-in-url
# ---------------------------------------------------------------------------


def test_session_check_metadata() -> None:
    """Passive, ``Category.DISCLOSURE``, CWE-598."""
    assert SessionIdInUrlCheck.category is Category.DISCLOSURE
    assert SessionIdInUrlCheck.mode is ScanMode.PASSIVE
    assert SessionIdInUrlCheck.cwe == (598,)


async def test_jsessionid_in_a_link_is_flagged_with_the_value_redacted() -> None:
    """A ``;jsessionid=`` path parameter in an ``<a href>`` is flagged, value masked."""
    page = make_page(
        url="https://app.example/home",
        text='<a href="/dashboard;jsessionid=SECRET123">go</a>',
    )
    findings = await SessionIdInUrlCheck().run(
        make_context(page, target_url="https://app.example/")
    )
    assert len(findings) == 1
    blob = " ".join(e.content for e in findings[0].evidence)
    assert "SECRET123" not in blob
    assert "jsessionid=***" in blob


async def test_access_token_in_a_form_action_and_a_redirect_location() -> None:
    """A ``?access_token=`` in a form action and in a redirect ``Location`` are both flagged."""
    form_page = make_page(
        url="https://app.example/a",
        text='<form action="https://app.example/cb?access_token=abc123"></form>',
    )
    redirect_page = Page(
        requested_url="https://app.example/login",
        url="https://app.example/login",
        status_code=302,
        headers=httpx.Headers({"content-type": "text/html"}),
        text="",
        elapsed_ms=1.0,
        final_location="https://other.example/next?sid=zzz",
    )
    ctx = make_context(
        form_page, pages=[form_page, redirect_page], target_url="https://app.example/"
    )
    keys = {f.title for f in await SessionIdInUrlCheck().run(ctx)}
    assert keys == {
        "Session identifier 'access_token' carried in a URL",
        "Session identifier 'sid' carried in a URL",
    }


async def test_a_url_the_scanner_crafted_is_not_flagged() -> None:
    """The page's own request URL (which may be an --openapi seed) is not inspected."""
    page = make_page(url="https://app.example/api/thing?sid=wvcrafted", text="<p>ok</p>")
    assert await _session_titles(page) == []


async def test_a_bare_reset_token_in_a_link_is_not_flagged() -> None:
    """A one-time ``?token=`` link (a reset / verification link) is deliberately not flagged."""
    page = make_page(
        url="https://app.example/mail",
        text='<a href="/reset/confirm?token=abc123">reset</a>',
    )
    assert await _session_titles(page) == []


# ---------------------------------------------------------------------------
# disclosure.private-ip
# ---------------------------------------------------------------------------


async def _ip_addresses(body: str, *, target: str = "https://app.example/") -> list[str]:
    """
    Args:
        body (str): The response body.
        target (str): The scan target URL. Defaults to a hostname target.

    Returns:
        list[str]: The addresses ``PrivateIpInBodyCheck`` reported (from the
            ``address`` evidence item).
    """
    page = make_page(url=target, text=body)
    ctx = make_context(page, target_url=target)
    findings = await PrivateIpInBodyCheck().run(ctx)
    return [next(e.content for e in f.evidence if e.label == "address") for f in findings]


async def test_each_private_range_matches_and_public_addresses_do_not() -> None:
    """RFC-1918, loopback, link-local, and ``::1`` match; a public address does not."""
    body = "10.1.2.3 172.20.0.1 192.168.1.1 127.0.0.1 169.254.0.5 ::1 and 203.0.113.9"
    found = set(await _ip_addresses(body))
    assert found == {"10.1.2.3", "172.20.0.1", "192.168.1.1", "127.0.0.1", "169.254.0.5", "::1"}


async def test_a_three_octet_version_string_is_not_a_match() -> None:
    """``10.20.30`` (three octets) is not a dotted quad and is not flagged."""
    assert await _ip_addresses("app version 10.20.30 built today") == []


async def test_the_targets_own_host_is_not_flagged() -> None:
    """Scanning ``http://10.0.0.5/`` does not report ``10.0.0.5`` from its own body."""
    assert await _ip_addresses("bound to 10.0.0.5 ok", target="http://10.0.0.5/") == []


async def test_more_than_the_cap_is_truncated_with_a_note() -> None:
    """15 distinct private addresses → 10 findings and a note on the last one."""
    body = " ".join(f"10.0.0.{n}" for n in range(1, 16))
    page = make_page(url="https://app.example/dump", text=body)
    findings = await PrivateIpInBodyCheck().run(
        make_context(page, target_url="https://app.example/")
    )
    assert len(findings) == 10
    assert any(e.label == "note" and "15 distinct" in e.content for e in findings[-1].evidence)
