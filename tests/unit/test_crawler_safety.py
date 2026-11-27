"""
Link / form safety heuristics — spec 007 RF-03, ADR-5.

Pure string / form predicates: each test is a table of URLs (or built forms)
that must or must not trip a heuristic, with the word-boundary edge cases called
out inline.
"""

from __future__ import annotations

import pytest

from webvigil.crawler.forms import Form, FormField
from webvigil.crawler.openapi import ApiOperation
from webvigil.crawler.safety import (
    is_auth_form,
    is_candidate,
    is_destructive,
    is_login_url,
    is_logout,
    is_unsafe_api_operation,
    is_unsafe_form,
    is_unsafe_operation,
    is_unsafe_url,
    looks_like_search,
    state_change_signal,
)


def _form(action: str, *names: str, method: str = "POST") -> Form:
    """
    Args:
        action (str): The form action URL.
        *names (str): The field names, all rendered as text inputs.
        method (str): The form method. Defaults to ``POST``.

    Returns:
        Form: The assembled form.
    """
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
    """The logout/sign-out/disconnect URL vocabulary is matched."""
    assert is_logout(url) is True


@pytest.mark.parametrize(
    "url",
    ["https://example.com/login", "https://example.com/blog/post", "https://example.com/about"],
)
def test_is_logout_leaves_ordinary_urls_alone(url: str) -> None:
    """A login page or an ordinary content URL is not a logout."""
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
    """Delete / remove / deactivate / revoke / unsubscribe URLs are flagged destructive."""
    assert is_destructive(url) is True


@pytest.mark.parametrize(
    "verb",
    [
        "delete",
        "remove",
        "destroy",
        "drop",
        "revoke",
        "deactivate",
        "disable",
        "unsubscribe",
        "cancel",
        "purge",
        "wipe",
    ],
)
def test_every_destructive_verb_is_recognised(verb: str) -> None:
    """Each word of the vocabulary, alone in a path segment, marks the URL destructive."""
    assert is_destructive(f"https://example.com/items/5/{verb}") is True


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
    """Names like "deleted-items" / "undeletable" / "reset-password" must not trip the check."""
    assert is_destructive(url) is False


def test_is_auth_form_matches_login_and_registration() -> None:
    """A login or registration form is recognised by its action and its field names."""
    assert is_auth_form(_form("/login", "username", "password")) is True
    assert is_auth_form(_form("/users", "email", "password", "password_confirm")) is True
    assert is_auth_form(_form("/register", "email")) is True
    assert is_auth_form(_form("/comment", "body")) is False


@pytest.mark.parametrize("word", ["search", "query", "find", "filter"])
def test_every_search_word_in_the_action_marks_a_search_form(word: str) -> None:
    """Each word of the search vocabulary is enough, with an ordinary field name."""
    assert looks_like_search(_form(f"/{word}", "term", method="GET")) is True
    assert looks_like_search(_form("/catalog", "term", method="GET")) is False


def test_looks_like_search_matches_search_forms() -> None:
    """A GET form named ``q`` / ``query`` on a search-ish action looks like search."""
    assert looks_like_search(_form("/search", "q", method="GET")) is True
    assert looks_like_search(_form("/products", "query", method="GET")) is True
    assert looks_like_search(_form("/catalog", "q", method="GET")) is True
    assert looks_like_search(_form("/profile", "nickname")) is False


# ---------------------------------------------------------------------------
# Destructive forms and login URLs (spec 017 RF-04)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "action, names",
    [
        ("https://example.com/items/remove", ("id",)),
        ("https://example.com/account", ("delete_account",)),
        ("https://example.com/account", ("do-purge",)),
        ("https://example.com/logout", ("next",)),
        ("https://example.com/x?action=revoke", ("id",)),
    ],
)
def test_destructive_form_matches_action_and_field_names(
    action: str, names: tuple[str, ...]
) -> None:
    """A destructive verb in the path, the query or a field name (``_`` / ``-`` are breaks)."""
    assert is_unsafe_form(_form(action, *names)) is True


def test_destructive_form_reads_a_named_submit_value() -> None:
    """``<input type=submit name=op value=Delete>`` marks an otherwise neutral form."""
    form = Form(
        method="POST",
        action="https://example.com/items/5",
        enctype="application/x-www-form-urlencoded",
        fields=(
            FormField(name="id", type="hidden", value="5"),
            FormField(name="op", type="submit", value="Delete"),
        ),
        source_url="https://example.com/",
    )
    assert is_unsafe_form(form) is True


@pytest.mark.parametrize(
    "labels, destructive",
    [
        (("Delete account",), True),  # a <button> element's text, no named control at all
        (("Save", "Remove item"), True),
        (("Log out",), True),  # the logout vocabulary counts too
        (("Generate",), False),
        (("Deleted items",), False),  # the word boundary holds
    ],
)
def test_destructive_form_reads_the_button_labels(
    labels: tuple[str, ...], destructive: bool
) -> None:
    """The visible label of a button, named or not, marks a form destructive (issue #145)."""
    form = Form(
        method="POST",
        action="https://example.com/account",
        enctype="application/x-www-form-urlencoded",
        fields=(),
        source_url="https://example.com/",
        labels=labels,
    )
    assert is_unsafe_form(form) is destructive


@pytest.mark.parametrize(
    "action, names",
    [
        ("https://example.com/newsletter", ("email", "topic")),
        ("https://example.com/settings", ("display_name",)),
        ("https://example.com/deleted-items", ("page",)),  # the delete word boundary holds
    ],
)
def test_destructive_form_leaves_benign_forms_alone(action: str, names: tuple[str, ...]) -> None:
    """Benign forms, including a near-miss word, are not destructive."""
    assert is_unsafe_form(_form(action, *names)) is False


def test_login_url() -> None:
    """A login / sign-in path is a login URL; an ordinary page is not."""
    assert is_login_url("https://example.com/login?next=/x") is True
    assert is_login_url("https://example.com/users/sign-in") is True
    assert is_login_url("https://example.com/panel") is False
    assert is_login_url("https://example.com/panel?next=/login") is False  # the path, not the query


# ---------------------------------------------------------------------------
# GET forms that change state (issue #144)
# ---------------------------------------------------------------------------


def _typed_form(action: str, *fields: tuple[str, str], method: str = "GET") -> Form:
    """
    Args:
        action (str): The form action URL.
        *fields (tuple[str, str]): ``(name, type)`` pairs, in order.
        method (str): The form method. Defaults to ``GET``.

    Returns:
        Form: The assembled form.
    """
    return Form(
        method=method,
        action=action,
        enctype="application/x-www-form-urlencoded",
        fields=tuple(FormField(name=n, type=t, value="") for n, t in fields),
        source_url="https://example.com/",
    )


def test_a_password_change_form_over_get_is_a_state_change() -> None:
    """The DVWA shape: a new password and its confirmation on a GET form."""
    form = _typed_form(
        "https://example.com/vulnerabilities/csrf/",
        ("password_new", "password"),
        ("password_conf", "password"),
        ("Change", "submit"),
    )
    assert state_change_signal(form) == "password change"


def test_one_password_field_named_like_a_change_is_a_state_change() -> None:
    """A single ``new_password`` input is half of a change; a plain ``password`` is a login."""
    action = "https://example.com/account"
    assert state_change_signal(_typed_form(action, ("new_password", "password"))) == (
        "password change"
    )
    assert state_change_signal(_typed_form(action, ("password", "password"))) is None


def test_two_password_fields_over_get_are_a_state_change_whatever_their_names() -> None:
    """Two password inputs are a change even when neither name says so."""
    form = _typed_form("https://example.com/account", ("pw1", "password"), ("pw2", "password"))
    assert state_change_signal(form) == "password change"


@pytest.mark.parametrize(
    "name",
    [
        "new_password",
        "password_conf",
        "repeat_password",
        "retype_password",
        "current_password",
        "old_password",
    ],
)
def test_every_change_word_in_one_password_name_is_a_state_change(name: str) -> None:
    """A single password input named like the new, confirmed or current one is half a change."""
    assert state_change_signal(_typed_form("https://example.com/account", (name, "password"))) == (
        "password change"
    )


def test_a_search_form_is_never_a_state_change() -> None:
    """A search over ``GET`` with a destructive-looking filter name stays a search."""
    form = _typed_form(
        "https://example.com/search", ("q", "text"), ("remove_duplicates", "checkbox")
    )
    assert state_change_signal(form) is None
    assert state_change_signal(
        _typed_form("https://example.com/items", ("remove_duplicates", "checkbox"))
    ) == (
        "destructive verb"
    )  # the control: the same field off a search form


def test_a_destructive_verb_over_get_is_a_state_change() -> None:
    """A destructive verb in the action path, a field name or a submit label."""
    assert (
        state_change_signal(_typed_form("https://example.com/items/delete", ("id", "text")))
        == "destructive verb"
    )
    assert (
        state_change_signal(_typed_form("https://example.com/items", ("remove_item", "text")))
        == "destructive verb"
    )


@pytest.mark.parametrize(
    "form",
    [
        _typed_form("https://example.com/search", ("q", "text")),
        _typed_form("https://example.com/products", ("filter", "text")),
        _typed_form("https://example.com/login", ("username", "text"), ("password", "password")),
        _typed_form(
            "https://example.com/sign-up",
            ("password", "password"),
            ("password_confirm", "password"),
        ),
        _typed_form("https://example.com/logout", ("next", "hidden")),
        _typed_form("https://example.com/deleted-items", ("page", "text")),
        _typed_form("https://example.com/newsletter", ("email", "text")),
        _typed_form(
            "https://example.com/account/password",
            ("password_new", "password"),
            ("password_conf", "password"),
            method="POST",
        ),
    ],
)
def test_forms_that_do_not_change_state_over_get_are_left_alone(form: Form) -> None:
    """Search, login, registration, logout, a near-miss word, a plain form and any POST."""
    assert state_change_signal(form) is None


# ---------------------------------------------------------------------------
# Form candidates and unsafe operations (specs 017 / 018)
# ---------------------------------------------------------------------------


def test_is_candidate_is_a_post_that_is_not_auth_or_search() -> None:
    """A state-changing POST form is a candidate; GET, login and search forms are not."""
    assert is_candidate(_form("https://example.com/newsletter", "email")) is True
    assert is_candidate(_form("https://example.com/newsletter", "email", method="GET")) is False
    assert is_candidate(_form("https://example.com/login", "user")) is False
    assert is_candidate(_form("https://example.com/search", "q")) is False


def _operation(path: str, operation_id: str = "") -> ApiOperation:
    """
    Args:
        path (str): The operation path.
        operation_id (str): The ``operationId``. Defaults to none.

    Returns:
        ApiOperation: A bodiless ``POST`` operation.
    """
    return ApiOperation(
        method="POST",
        url=f"https://example.com{path}",
        url_template=f"https://example.com{path}",
        query=(),
        path_params=(),
        body_fields=(),
        body_json=None,
        operation_id=operation_id,
    )


@pytest.mark.parametrize(
    "path, operation_id",
    [
        ("/auth/login", ""),
        ("/api/accounts", "delete_account"),
        ("/orders/remove", ""),
        ("/api/session", "logoutUser"),
        ("/users/password", "reset-password"),
    ],
)
def test_unsafe_operations_are_recognised(path: str, operation_id: str) -> None:
    """Auth, logout and destructive paths or operation ids are left alone."""
    assert is_unsafe_api_operation(_operation(path, operation_id)) is True


@pytest.mark.parametrize(
    "path, operation_id",
    [("/api/notes", "create_note"), ("/api/tickets", "openTicket"), ("/api/deleted-items", "")],
)
def test_benign_operations_are_not_unsafe(path: str, operation_id: str) -> None:
    """Ordinary create operations — and a near-miss word — pass."""
    assert is_unsafe_api_operation(_operation(path, operation_id)) is False


# ---------------------------------------------------------------------------
# Spellings: underscores, camelCase, percent-encoding (one gate per kind of send)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/account/delete_account",
        "https://example.com/account/deleteAccount",
        "https://example.com/account/DeleteAccount",
        "https://example.com/api/XMLDelete",
        "https://example.com/items/5/%64elete",  # %64 is "d"
        "https://example.com/items/5/%2564elete",  # encoded twice
        "https://example.com/items?do=removeItem",
        "https://example.com/session/logOut",
        "https://example.com/session/log%6Fut",
        "https://example.com/sign_out",
    ],
)
def test_the_url_gate_reads_every_spelling_of_a_word(url: str) -> None:
    """``_``, a ``camelCase`` boundary and percent-encoding do not hide a logout or a verb."""
    assert is_unsafe_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/deleted-items",
        "https://example.com/undeletable",
        "https://example.com/payload",
        "https://example.com/model/remover",
        "https://example.com/orders?order=asc",  # a transaction word only counts on a form
        "https://example.com/list?reset=1",
        "https://example.com/blog/%70ost",
    ],
)
def test_the_url_gate_leaves_near_misses_alone(url: str) -> None:
    """A word that only contains a verb, or a sort / filter link, is still followed."""
    assert is_unsafe_url(url) is False


@pytest.mark.parametrize(
    "action, names",
    [
        ("https://example.com/account", ("deleteAccount",)),
        ("https://example.com/items/%72emove", ("id",)),
        ("https://example.com/login", ("user",)),
        ("https://example.com/profile", ("newPassword",)),
        ("https://example.com/cart/checkout", ("card",)),
        ("https://example.com/bank", ("transfer_amount",)),
        ("https://example.com/shop", ("order",)),
        ("https://example.com/prefs/reset", ("all",)),
        ("https://example.com/pay", ("amount",)),
    ],
)
def test_the_form_gate_refuses_auth_logout_verbs_and_transactions(
    action: str, names: tuple[str, ...]
) -> None:
    """Every vocabulary a pass used to keep apart is in the one form gate."""
    assert is_unsafe_form(_form(action, *names)) is True


@pytest.mark.parametrize(
    "action, names",
    [
        ("https://example.com/comment", ("body",)),
        ("https://example.com/settings", ("displayName",)),
        ("https://example.com/payload", ("data",)),
        ("https://example.com/orders/history", ("page",)),
    ],
)
def test_the_form_gate_passes_ordinary_forms(action: str, names: tuple[str, ...]) -> None:
    """A comment, a settings form and a near-miss word are submitted."""
    assert is_unsafe_form(_form(action, *names)) is False


@pytest.mark.parametrize(
    "path, operation_id",
    [
        ("/api/users/{id}", "deleteUser"),
        ("/api/orders", "createOrder"),
        ("/api/cart/checkout", ""),
        ("/api/session", "signOut"),
        ("/api/items/%64elete", ""),
    ],
)
def test_the_operation_gate_reads_camel_case_operation_ids(path: str, operation_id: str) -> None:
    """The ``operationId`` style most OpenAPI documents use is read word by word."""
    assert is_unsafe_operation(path, operation_id) is True


@pytest.mark.parametrize(
    "path, operation_id",
    [("/api/users/{id}", "getUser"), ("/api/items", "listItems"), ("/api/payloads", "")],
)
def test_the_operation_gate_passes_reads(path: str, operation_id: str) -> None:
    """A read operation is imported."""
    assert is_unsafe_operation(path, operation_id) is False
