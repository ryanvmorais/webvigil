"""
Keyword heuristics for "is this safe for the scan to send" (spec 007, RF-03).

Every pass that sends a request it did not take from a fixed catalogue asks one of three
gates first, so a logout or a state-changing action is left alone the same way everywhere:

* :func:`is_unsafe_url` — a ``GET`` of a URL found on a page: a crawled link, a sampled
  form action (``envelope.*``), a script or stylesheet (dependency fingerprinting), a source
  map (``disclosure.*``);
* :func:`is_unsafe_form` — a form the scan submits: the crawler (``GET`` and ``POST``), the
  CSRF confirmation, active injection, the file-upload pass;
* :func:`is_unsafe_operation` — an imported operation (OpenAPI, HAR) and the crawler's
  ``POST`` phase over it.

The ``csrf.*`` checks also read the classifiers here (which form is a login / search form
and therefore not a CSRF target).

Every predicate reads the text after :func:`_words` has percent-decoded it and split ``_``,
``camelCase`` and ``PascalCase`` into words. A link must name a verb as a whole word
(``/deleted-items`` is followed); a form or an operation is refused when a long verb appears
anywhere in a name (``deleteall``, ``purchases``), as the injection and import filters did
before there was one gate. They are deliberately conservative and imperfect; the limits are
documented in ``docs/authenticated-scanning.md`` and ``docs/active-injection.md``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

from webvigil.crawler.forms import Form

if TYPE_CHECKING:
    from webvigil.crawler.openapi import ApiOperation

# A lower-case letter or digit followed by a capital, or a capital followed by a capitalised
# word (``XMLDelete``): a word break in ``deleteAccount`` and ``XMLDelete``.
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
# A value encoded twice (``%2564elete``) is still read: some frameworks decode a path twice.
_DECODE_ROUNDS = 2

# Follow-me-and-the-session-dies. Skipped on every crawl — authenticated or not (an
# anonymous scan gains nothing from a logout endpoint either).
_LOGOUT_RE = re.compile(
    r"log[\s_-]?out|log[\s_-]?off|sign[\s_-]?out|(?:^|/)disconnect(?:$|/|\?)", re.I
)
# Looks state-changing. Skipped on every crawl (RF-03). ``reset`` is
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
# A destructive verb or a transaction in a form or an operation, inside a longer name too
# (``deleteall``, ``unsubscribed``, ``purchases``): a benign form skipped costs coverage, a
# destructive one submitted costs the target's data. ``drop``, ``reset``, ``pay`` and ``order``
# sit inside common benign names (``dropdown``, ``payload``, ``ordering``), so they stay whole
# words. A link that names a transaction is still followed (``?order=asc`` sorts, ``?reset=1``
# clears a filter).
_ACTION_VERB_RE = re.compile(
    r"delete|remove|destroy|revoke|deactivate|disable|unsubscribe|cancel|purge|wipe|"
    r"checkout|purchase|transfer|\b(?:drop|reset|pay|order)\b",
    re.I,
)
# What a form or an operation must not name: a logout, a login or a registration, a destructive
# verb or a transaction.
_UNSAFE_ACTION_RES = (_LOGOUT_RE, _AUTH_FORM_RE, _ACTION_VERB_RE)
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


def _decoded(text: str) -> str:
    """
    Args:
        text (str): A URL path and query, field names, button labels or an ``operationId``.

    Returns:
        str: ``text`` percent-decoded, at most twice.
    """
    for _ in range(_DECODE_ROUNDS):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return text


def _words(text: str) -> str:
    """
    Args:
        text (str): A URL path and query, field names, button labels or an ``operationId``.

    Returns:
        str: ``text`` percent-decoded (at most twice), with ``_`` and every ``camelCase`` /
            ``PascalCase`` boundary turned into a space, so ``delete_account``,
            ``deleteAccount`` and ``%64elete`` all read as the word ``delete``.
    """
    return _CAMEL_RE.sub(" ", _decoded(text)).replace("_", " ")


def _names_unsafe_action(text: str) -> bool:
    """
    Args:
        text (str): The text of a form or an operation, not yet decoded.

    Returns:
        bool: Whether it names a logout, a login or a registration, a destructive verb or a
            transaction (:data:`_UNSAFE_ACTION_RES`). The text is read decoded and as words,
            so a verb a ``camelCase`` boundary cuts in two (``unSubscribe``) still counts.
    """
    haystack = f"{_decoded(text)} {_words(text)}"
    return any(pattern.search(haystack) for pattern in _UNSAFE_ACTION_RES)


def is_logout(url: str) -> bool:
    """
    Args:
        url (str): The absolute URL to test.

    Returns:
        bool: ``True`` when ``url`` looks like a logout endpoint. Skipped on
            every crawl, authenticated or not.
    """
    return bool(_LOGOUT_RE.search(_words(_path_and_query(url))))


def is_destructive(url: str) -> bool:
    """
    Args:
        url (str): The absolute URL to test.

    Returns:
        bool: ``True`` when ``url`` looks state-changing. Skipped on every crawl
            (RF-03).
    """
    return bool(_DESTRUCTIVE_RE.search(_words(_path_and_query(url))))


def is_unsafe_url(url: str) -> bool:
    """
    The gate of every ``GET`` the scan sends to a URL it found on a page.

    Args:
        url (str): The absolute URL to test.

    Returns:
        bool: ``True`` when ``url`` looks like a logout or a state-changing action: the
            request is not sent.
    """
    return is_logout(url) or is_destructive(url)


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


def _verb_parts(form: Form) -> list[str]:
    """
    Args:
        form (Form): The form to flatten.

    Returns:
        list[str]: The action's path and query, the field names and the value of every named
            ``submit`` / ``button`` input — what the destructive vocabulary is matched on.
    """
    parts = [_path_and_query(form.action)]
    parts += [field.name for field in form.fields]
    parts += [field.value for field in form.fields if field.type in ("submit", "button")]
    return parts


def is_unsafe_form(form: Form) -> bool:
    """
    The gate of every form the scan submits.

    Args:
        form (Form): The form to classify.

    Returns:
        bool: ``True`` when the form looks like a logout, a destructive action, a login or a
            registration, or a transaction (``checkout``, ``pay``, ``order``, ``transfer``,
            ``reset``): the action's path and query, a field name, the value of a named
            ``submit`` / ``button`` input or the label of any button names one
            (:func:`_names_unsafe_action`). The form is not submitted.
    """
    # The labels are read here and not in ``_verb_parts``: a ``GET`` form's button
    # ("Remove filters") must not widen ``state_change_signal`` (issue #144).
    return _names_unsafe_action(" ".join([*_verb_parts(form), *form.labels]))


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
    if _DESTRUCTIVE_RE.search(_words(" ".join(_verb_parts(form)))):
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


def is_unsafe_operation(path: str, operation_id: str = "") -> bool:
    """
    The gate of every imported operation (OpenAPI, HAR): the import leaves it out and the
    crawler's ``POST`` phase does not submit it.

    Args:
        path (str): The operation's path (a template such as ``/users/{id}`` or a URL).
        operation_id (str): Its ``operationId``, when the document gives one. Defaults to
            empty.

    Returns:
        bool: ``True`` when the path or the ``operationId`` names what :func:`is_unsafe_form`
            refuses (``login``, ``deleteUser``, ``/orders/remove``, ``checkout``), read as
            :func:`_names_unsafe_action` reads it.
    """
    return _names_unsafe_action(f"{urlsplit(path).path} {operation_id}")


def is_unsafe_api_operation(op: ApiOperation) -> bool:
    """
    Args:
        op (ApiOperation): An imported operation.

    Returns:
        bool: :func:`is_unsafe_operation` of its URL template and ``operationId``.
    """
    return is_unsafe_operation(op.url_template, op.operation_id)


__all__ = [
    "is_auth_form",
    "is_candidate",
    "is_destructive",
    "is_login_url",
    "is_logout",
    "is_unsafe_api_operation",
    "is_unsafe_form",
    "is_unsafe_operation",
    "is_unsafe_url",
    "looks_like_search",
    "state_change_signal",
]
