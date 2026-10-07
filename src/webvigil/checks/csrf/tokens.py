"""
What counts as an anti-CSRF token field and as a CSRF-relevant form (spec 007, spec 017).

Shared by the passive ``csrf.form.no-token`` check and the active
:class:`~webvigil.checks.csrf.scanner.CsrfScanner` pass, so both agree on which
forms are candidates and which field is the token. Pure functions over the parsed
``<form>`` model; no request, no state.
"""

from __future__ import annotations

import re

from webvigil.crawler.forms import Form, FormField
from webvigil.crawler.safety import is_auth_form, looks_like_search

_TOKEN_NAME_RE = re.compile(
    r"csrf|xsrf|_token|authenticity_token|__requestverificationtoken|csrfmiddlewaretoken|"
    r"nonce|anti[\s_-]?forgery|request[\s_-]?token",
    re.I,
)


def is_token_field(field: FormField) -> bool:
    """
    Args:
        field (FormField): A form control.

    Returns:
        bool: ``True`` when the field name matches a known anti-CSRF token name.
    """
    return bool(_TOKEN_NAME_RE.search(field.name))


def is_candidate(form: Form) -> bool:
    """
    Args:
        form (Form): A parsed form.

    Returns:
        bool: ``True`` when the form is a ``POST`` that is neither an auth form
            nor a search form — i.e. a meaningful CSRF target.
    """
    return form.method == "POST" and not is_auth_form(form) and not looks_like_search(form)
