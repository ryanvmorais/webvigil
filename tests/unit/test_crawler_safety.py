"""Link / form safety heuristics — spec 007 RF-03, ADR-5."""

from __future__ import annotations

import pytest

from webvigil.crawler.forms import Form, FormField
from webvigil.crawler.safety import is_auth_form, is_destructive, is_logout, looks_like_search


def _form(action: str, *names: str, method: str = "POST") -> Form:
    return Form(
        method=method,
        action=action,
        enctype="application/x-www-form-urlencoded",
        fields=tuple(FormField(name=n, type="text", value="") for n in names),
        source_url="https://example.com/",
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/logout",
        "https://example.com/account/log-out",
        "https://example.com/session?do=signout",
        "https://example.com/disconnect",
        "https://example.com/user/logoff",
    ],
)
def test_is_logout_matches_logout_endpoints(url: str) -> None:
    assert is_logout(url) is True


@pytest.mark.parametrize(
    "url",
    ["https://example.com/login", "https://example.com/blog/post", "https://example.com/about"],
)
def test_is_logout_leaves_ordinary_urls_alone(url: str) -> None:
    assert is_logout(url) is False


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/posts/5/delete",
        "https://example.com/items?action=remove",
        "https://example.com/account/deactivate",
        "https://example.com/api/keys/1/revoke",
        "https://example.com/newsletter/unsubscribe",
    ],
)
def test_is_destructive_matches_state_changing_urls(url: str) -> None:
    assert is_destructive(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/deleted-items",  # word-boundary: "deleted" != "delete"
        "https://example.com/undeletable",
        "https://example.com/reset-password",  # "reset" deliberately not in the set
        "https://example.com/products",
    ],
)
def test_is_destructive_respects_word_boundaries(url: str) -> None:
    assert is_destructive(url) is False


def test_is_auth_form_matches_login_and_registration() -> None:
    assert is_auth_form(_form("/login", "username", "password")) is True
    assert is_auth_form(_form("/users", "email", "password", "password_confirm")) is True
    assert is_auth_form(_form("/register", "email")) is True
    assert is_auth_form(_form("/comment", "body")) is False


def test_looks_like_search_matches_search_forms() -> None:
    assert looks_like_search(_form("/search", "q", method="GET")) is True
    assert looks_like_search(_form("/products", "query", method="GET")) is True
    assert looks_like_search(_form("/catalog", "q", method="GET")) is True
    assert looks_like_search(_form("/profile", "nickname")) is False
