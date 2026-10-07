"""
The fixture's CSRF routes — spec 017 RF-12.

Pure unit of ``tests/fixtures/app.py``: ``/panel`` and its four POST routes are driven through
``httpx.ASGITransport`` with no scan, so a regression in what each route accepts or refuses
cannot hide behind the integration test (which would then fail for the wrong reason). The app is
built per test, so ``app.state.csrf_log`` starts empty.
"""

from __future__ import annotations

import httpx
import pytest
from starlette.applications import Starlette

from tests.fixtures.app import _CSRF_TOKEN, make_app

_BASE = "http://example.com"


def _client(app: Starlette) -> httpx.AsyncClient:
    """
    Args:
        app (Starlette): The fixture app.

    Returns:
        httpx.AsyncClient: A client wired to ``app`` in-process.
    """
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=_BASE)


async def _post(
    app: Starlette, path: str, data: dict[str, str], headers: dict[str, str] | None = None
) -> httpx.Response:
    """
    Args:
        app (Starlette): The fixture app.
        path (str): The route to post to.
        data (dict[str, str]): The urlencoded fields.
        headers (dict[str, str] | None): Extra request headers.

    Returns:
        httpx.Response: The response, redirects not followed.
    """
    async with _client(app) as client:
        return await client.post(path, data=data, headers=headers)


@pytest.mark.parametrize("profile", ["insecure", "hardened"])
async def test_panel_lists_four_post_forms(profile: str) -> None:
    """Both profiles serve ``/panel`` with the four forms (and link it from the index)."""
    app = make_app(profile)
    async with _client(app) as client:
        panel = (await client.get("/panel")).text
        index = (await client.get("/")).text
    for action in ("/newsletter", "/settings", "/transfer", "/prefs"):
        assert f'action="{action}"' in panel
    assert 'href="/panel"' in index


async def test_insecure_newsletter_has_no_token_field_and_accepts_anything() -> None:
    """The insecure ``/newsletter`` form has no token and redirects after any post."""
    app = make_app("insecure")
    async with _client(app) as client:
        assert "csrf_token" not in (await client.get("/panel")).text.split("/settings")[0]
    response = await _post(app, "/newsletter", {"email": "a@b.test"})
    assert (response.status_code, response.headers["location"]) == (302, "/panel?saved=newsletter")
    assert app.state.csrf_log == [("newsletter", True, "", "a@b.test")]


async def test_insecure_settings_ignores_the_token_and_escapes_the_echo() -> None:
    """``/settings`` has a token field the server never reads, and escapes what it echoes."""
    app = make_app("insecure")
    response = await _post(app, "/settings", {"csrf_token": "wrong", "display_name": "<b>x</b>"})
    assert response.status_code == 200
    assert "&lt;b&gt;x&lt;/b&gt;" in response.text and "<b>" not in response.text
    no_token = await _post(app, "/settings", {"display_name": "y"})
    assert no_token.status_code == 200


@pytest.mark.parametrize("profile", ["insecure", "hardened"])
async def test_transfer_enforces_the_token(profile: str) -> None:
    """``/transfer`` accepts only the served token: missing, altered and wrong are ``403``."""
    app = make_app(profile)
    good = await _post(app, "/transfer", {"csrf_token": _CSRF_TOKEN, "to_account": "42"})
    assert good.status_code == 200
    for fields in ({"to_account": "42"}, {"csrf_token": "x" + _CSRF_TOKEN, "to_account": "42"}):
        assert (await _post(app, "/transfer", fields)).status_code == 403
    assert [entry[1] for entry in app.state.csrf_log] == [True, False, False]


@pytest.mark.parametrize("profile", ["insecure", "hardened"])
async def test_prefs_ignores_the_token_but_checks_a_foreign_origin(profile: str) -> None:
    """``/prefs`` refuses a foreign ``Origin``; the same-origin and no-Origin posts pass."""
    app = make_app(profile)
    same = await _post(app, "/prefs", {"theme": "dark"}, {"Origin": "http://example.com"})
    none = await _post(app, "/prefs", {"theme": "dark"})
    foreign = await _post(app, "/prefs", {"theme": "dark"}, {"Origin": "https://webvigil.invalid"})
    assert (same.status_code, none.status_code, foreign.status_code) == (200, 200, 403)


async def test_hardened_newsletter_and_settings_enforce_the_token() -> None:
    """The hardened profile gives ``/newsletter`` a token field and enforces it on both routes."""
    app = make_app("hardened")
    async with _client(app) as client:
        assert "csrf_token" in (await client.get("/panel")).text.split("/settings")[0]
    assert (await _post(app, "/newsletter", {"email": "a@b.test"})).status_code == 403
    assert (await _post(app, "/settings", {"display_name": "y"})).status_code == 403
    ok = await _post(app, "/settings", {"csrf_token": _CSRF_TOKEN, "display_name": "y"})
    assert ok.status_code == 200


async def test_the_log_is_reset_per_app() -> None:
    """A fresh app starts with an empty ``csrf_log`` so a test counts only its own writes."""
    first = make_app("insecure")
    await _post(first, "/settings", {"display_name": "y"})
    assert make_app("insecure").state.csrf_log == []
