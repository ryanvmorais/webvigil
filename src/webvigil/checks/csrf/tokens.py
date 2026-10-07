"""
What counts as an anti-CSRF token field and as a CSRF-relevant form (spec 007, spec 017).

Shared by the passive ``csrf.form.no-token`` check and the active
:class:`~webvigil.checks.csrf.scanner.CsrfScanner` pass, so both agree on which
forms are candidates and which field is the token. Pure functions over the parsed
``<form>`` model; no request, no state.
"""

from __future__ import annotations

import re

from webvigil.crawler.forms import FormField
from webvigil.crawler.safety import is_candidate

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


# ``is_candidate`` lives in ``webvigil.crawler.safety`` since spec 018 (the crawler must not
# import from ``checks``); re-exported so the passive check and the 017 pass keep their imports.
__all__ = ["is_candidate", "is_token_field"]
