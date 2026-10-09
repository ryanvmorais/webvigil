"""
Keyword heuristics for "is this safe for the crawler to touch" (spec 007, RF-03).

Shared by the crawler (which link / GET-form does it skip) and the ``csrf.*``
checks (which form is a login / search form and therefore not a CSRF target).
Spec 006's ``injection/points.py`` keeps its own ``_EXCLUDE_FORM_RE`` for now —
unifying the three overlapping keyword sets is a follow-up (design ADR-8).

Every predicate is a substring / word-boundary match on a URL path+query or on
a form's action + field names. They are deliberately conservative and
imperfect; the limits are documented in ``docs/authenticated-scanning.md``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from webvigil.crawler.forms import Form

if TYPE_CHECKING:
    from webvigil.crawler.openapi import ApiOperation

# Follow-me-and-the-session-dies. Skipped on every crawl — authenticated or not (an
# anonymous scan gains nothing from a logout endpoint either).
_LOGOUT_RE = re.compile(
    r"log[\s_-]?out|log[\s_-]?off|sign[\s_-]?out|(?:^|/)disconnect(?:$|/|\?)", re.I
)
# Looks state-changing. Skipped only on an authenticated crawl (RF-03). ``reset`` is
# intentionally absent — ``?reset=1`` is a common benign filter; "password reset" links
# are a documented gap.
_DESTRUCTIVE_RE = re.compile(
    r"\b(?:delete|remove|destroy|drop|revoke|deactivate|disable|unsubscribe|cancel|purge|wipe)\b",
    re.I,
)
# A login / registration form: no session to protect yet, so not a CSRF target, and not a
# form the crawler should submit.
_AUTH_FORM_RE = re.compile(
    r"log[\s_-]?in|sign[\s_-]?in|sign[\s_-]?up|register|/auth(?:$|/|\b)|password|passwd", re.I
)
# A search / filter form: the canonical *safe* GET form (the crawler submits it), but not a
# meaningful CSRF target.
_SEARCH_FORM_RE = re.compile(r"\b(?:search|query|find|filter)\b", re.I)

# A login / registration page, by its action path: a password field there is a credential being
# sent to establish a session, not one being changed inside it.
_AUTH_ACTION_RE = re.compile(
    r"log[\s_-]?in|sign[\s_-]?in|sign[\s_-]?up|register|/auth(?:$|/|\b)", re.I
)
# A password field that is half of a change: the new password, its confirmation, the old one.
_PASSWORD_CHANGE_RE = re.compile(r"new|conf|repeat|retype|current|old", re.I)


def _path_and_query(url: str) -> str:
    """
    Args:
        url (str): An absolute URL.

    Returns:
        str: ``"<path>?<query>"``, the haystack the URL predicates match on.
    """
    parts = urlsplit(url)
    return f"{parts.path}?{parts.query}"


def is_logout(url: str) -> bool:
    """
    Args:
        url (str): The absolute URL to test.

    Returns:
        bool: ``True`` when ``url`` looks like a logout endpoint. Skipped on
            every crawl, authenticated or not.
    """
    return bool(_LOGOUT_RE.search(_path_and_query(url)))


def is_destructive(url: str) -> bool:
    """
    Args:
        url (str): The absolute URL to test.

    Returns:
        bool: ``True`` when ``url`` looks state-changing. Skipped only on an
            authenticated crawl (RF-03).
    """
    return bool(_DESTRUCTIVE_RE.search(_path_and_query(url)))


def _form_haystack(form: Form) -> str:
    """
    Args:
        form (Form): The form to flatten.

    Returns:
        str: The form action followed by every field name, the haystack the
            form predicates match on.
    """
    return form.action + " " + " ".join(field.name for field in form.fields)


def is_auth_form(form: Form) -> bool:
    """
    Args:
        form (Form): The form to classify.

    Returns:
        bool: ``True`` when ``form`` is a login or registration form — no
            session to protect yet, so not a CSRF target and not one the
            crawler should submit.
    """
    return bool(_AUTH_FORM_RE.search(_form_haystack(form)))


def looks_like_search(form: Form) -> bool:
    """
    Args:
        form (Form): The form to classify.

    Returns:
        bool: ``True`` when ``form`` is a search / filter form — the canonical
            safe GET form, but not a meaningful CSRF target.
    """
    haystack = _form_haystack(form)
    return bool(_SEARCH_FORM_RE.search(haystack)) or any(
        field.name.lower() == "q" for field in form.fields
    )


def is_login_url(url: str) -> bool:
    """
    Args:
        url (str): The absolute URL to test.

    Returns:
        bool: ``True`` when the URL path looks like a login / registration
            page — where a rejected, session-less submission usually lands.
    """
    return bool(_AUTH_FORM_RE.search(urlsplit(url).path))


def _verb_haystack(form: Form) -> str:
    """
    Args:
        form (Form): The form to flatten.

    Returns:
        str: The action's path and query, the field names and the value of every named
            ``submit`` / ``button`` input, with ``_`` and ``-`` as word breaks — what the
            destructive vocabulary is matched on.
    """
    parts = [_path_and_query(form.action)]
    parts += [field.name for field in form.fields]
    parts += [field.value for field in form.fields if field.type in ("submit", "button")]
    return re.sub(r"[_-]", " ", " ".join(parts))


def is_destructive_form(form: Form) -> bool:
    """
    Args:
        form (Form): The form to classify.

    Returns:
        bool: ``True`` when the form looks destructive or like a logout — the
            action's path and query, a field name, or the value of a named
            ``submit`` / ``button`` input matches the destructive vocabulary.
            ``_`` and ``-`` count as word breaks (``delete_account`` matches,
            which ``\bdelete\b`` alone would miss). A ``<button>`` element's text
            is not parsed into :class:`Form`, so a destructive verb only there is
            not seen — the gap is documented in ``docs/authenticated-scanning.md``.
    """
    haystack = _verb_haystack(form)
    return bool(_DESTRUCTIVE_RE.search(haystack) or _LOGOUT_RE.search(haystack))


def state_change_signal(form: Form) -> str | None:
    """
    Why a ``GET`` form looks like it changes state, for the ``csrf.form.state-change-over-get``
    check (issue #144). Neither signal is a guess about a free-text field: both are structural.

    Args:
        form (Form): The form to classify.

    Returns:
        str | None: ``"password change"`` when the form has two ``password`` inputs, or one named
            like the new / confirmed / old password, and its action is not a login or
            registration page; ``"destructive verb"`` when the action's path, a field name or a
            submit label carries a destructive verb (``delete``, ``remove``, ...); otherwise
            ``None``. A ``POST`` form, a search form and a logout form are always ``None``
            (a logout is a nuisance, not a state change worth the finding).
    """
    if form.method != "GET" or looks_like_search(form):
        return None
    if _DESTRUCTIVE_RE.search(_verb_haystack(form)):
        return "destructive verb"
    if _AUTH_ACTION_RE.search(urlsplit(form.action).path):
        return None
    passwords = [field for field in form.fields if field.type == "password"]
    if len(passwords) >= 2 or any(_PASSWORD_CHANGE_RE.search(f.name) for f in passwords):
        return "password change"
    return None


def is_candidate(form: Form) -> bool:
    """
    Args:
        form (Form): A parsed form.

    Returns:
        bool: ``True`` when the form is a ``POST`` that is neither an auth form
            nor a search form — a meaningful CSRF target and a form a state-changing
            pass (spec 017 CSRF confirmation, spec 018 POST crawl) may consider.
    """
    return form.method == "POST" and not is_auth_form(form) and not looks_like_search(form)


def looks_unsafe_operation(op: ApiOperation) -> bool:
    """
    Args:
        op (ApiOperation): An imported OpenAPI operation.

    Returns:
        bool: ``True`` when the operation's path or ``operationId`` looks like
            authentication, a logout, or a state-changing action (``login``,
            ``delete_account``, ``/orders/remove``) — the vocabulary the injection
            pass already uses to leave such operations alone. ``_`` and ``-`` count
            as word breaks.
    """
    haystack = re.sub(r"[_-]", " ", f"{urlsplit(op.url_template).path} {op.operation_id}")
    return bool(
        _DESTRUCTIVE_RE.search(haystack)
        or _LOGOUT_RE.search(haystack)
        or _AUTH_FORM_RE.search(haystack)
    )


__all__ = [
    "is_auth_form",
    "is_candidate",
    "is_destructive",
    "is_destructive_form",
    "is_login_url",
    "is_logout",
    "looks_like_search",
    "looks_unsafe_operation",
    "state_change_signal",
]
