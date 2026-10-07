"""
The fixture's POST-crawl routes — spec 018 RF-12.

Pure unit of ``tests/fixtures/app.py``: ``/support`` and its POST routes are driven through
``httpx.ASGITransport`` with no crawl, so a regression in what a route answers cannot hide behind
the integration test. Each test builds its own app, so ``app.state.post_log`` starts empty. Every
post carries the form's token: the hardened profile refuses a post without it.

Audited under issue #101: the page-content test and the log-reset test were dropped — the
integration scans prove the forms are reached and every test here builds a fresh app and asserts the
log exactly.
"""

from __future__ import annotations

import httpx
import pytest
from starlette.applications import Starlette

from tests.fixtures.app import _SUPPORT_TOKEN, make_app

_BASE = "http://example.com"
_TOKEN = {"csrf_token": _SUPPORT_TOKEN}


def _client(app: Starlette) -> httpx.AsyncClient:
    """
    Args:
        app (Starlette): The fixture app.

    Returns:
        httpx.AsyncClient: A client wired to ``app`` in-process.
    """
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=_BASE)


@pytest.mark.parametrize("profile", ["insecure", "hardened"])
async def test_the_answer_pages_are_not_linked_from_any_get_page(profile: str) -> None:
    """``/support/status`` and ``/support/received`` exist; only a POST answer points at them."""
    app = make_app(profile)
    async with _client(app) as client:
        assert (await client.get("/support/status")).status_code == 200
        assert (await client.get("/support/received")).status_code == 200
        for path in ("/", "/support", "/panel", "/about"):
            body = (await client.get(path)).text
            assert "/support/status" not in body and "/support/received" not in body


@pytest.mark.parametrize("profile", ["insecure", "hardened"])
async def test_ticket_answers_a_page_with_a_new_link_and_logs_the_post(profile: str) -> None:
    """The ticket answer links ``/support/status``; the post is logged as urlencoded."""
    app = make_app(profile)
    data = {**_TOKEN, "subject": "hi", "message": "x"}
    async with _client(app) as client:
        response = await client.post("/support/ticket", data=data)
    assert response.status_code == 200 and 'href="/support/status"' in response.text
    assert app.state.post_log == [("ticket", "application/x-www-form-urlencoded", data)]


@pytest.mark.parametrize("profile", ["insecure", "hardened"])
async def test_callback_redirects_and_parses_a_multipart_body(profile: str) -> None:
    """A text-only multipart post redirects to ``/support/received`` and is logged as multipart."""
    app = make_app(profile)
    fields = {**_TOKEN, "name": "Ada", "phone": "42"}
    async with _client(app) as client:
        response = await client.post(
            "/support/callback", files=[(name, (None, value)) for name, value in fields.items()]
        )
    assert (response.status_code, response.headers["location"]) == (302, "/support/received")
    assert app.state.post_log == [("callback", "multipart/form-data", fields)]


async def test_insecure_feedback_answers_a_stack_trace_script_and_cookie() -> None:
    """The insecure error page has a traceback, an SRI-less script and a bare cookie."""
    app = make_app("insecure")
    async with _client(app) as client:
        response = await client.post("/support/feedback", data={"format": "xml", "rating": "1"})
    assert response.status_code == 500
    assert "Traceback (most recent call last)" in response.text
    assert 'src="https://cdn.example.com/widget.js"' in response.text
    assert "integrity" not in response.text
    assert response.headers["set-cookie"] == "ticket=abc123; Path=/"


async def test_hardened_feedback_answers_a_plain_400() -> None:
    """The hardened profile gives no trace and sets no cookie."""
    app = make_app("hardened")
    async with _client(app) as client:
        response = await client.post(
            "/support/feedback", data={**_TOKEN, "format": "xml", "rating": "1"}
        )
    assert (response.status_code, response.text) == (400, "Bad request")
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize("profile", ["insecure", "hardened"])
async def test_a_feedback_without_the_xml_format_is_fine(profile: str) -> None:
    """The error depends on the hidden ``format`` default the crawler submits as served."""
    app = make_app(profile)
    async with _client(app) as client:
        response = await client.post(
            "/support/feedback", data={**_TOKEN, "format": "json", "rating": "1"}
        )
    assert response.status_code == 200


@pytest.mark.parametrize("profile", ["insecure", "hardened"])
async def test_api_notes_takes_json_and_logs_it(profile: str) -> None:
    """``POST /api/notes`` answers JSON and records the body and its content type."""
    app = make_app(profile)
    async with _client(app) as client:
        response = await client.post("/api/notes", json={"text": "hello"})
    assert response.json() == {"ok": True}
    assert app.state.post_log == [("notes", "application/json", {"text": "hello"})]


@pytest.mark.parametrize("path", ["/support/ticket", "/support/feedback"])
async def test_the_hardened_profile_enforces_the_token_the_insecure_one_ignores(path: str) -> None:
    """Without the served token the hardened form answers ``403``; the insecure one accepts."""
    async with _client(make_app("hardened")) as client:
        assert (await client.post(path, data={"format": "json"})).status_code == 403
    async with _client(make_app("insecure")) as client:
        assert (await client.post(path, data={"format": "json"})).status_code == 200
