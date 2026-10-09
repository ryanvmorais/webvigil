"""
The one URL predicate the engine and the reporters share: is this safe to turn into a link.

A finding's ``references`` come from the checks, except the ones the opt-in OSV lookup copies from
an advisory record, which a third-party database wrote. Autoescaping keeps such a value from
breaking out of an attribute; it does not stop a ``javascript:`` or ``data:`` URL from being a
link, so the value is checked where it enters (``checks.deps.osv``) and again where it is
rendered (the HTML report; the dashboard has the same check in ``web/src/lib/links.ts``).
"""

from __future__ import annotations

from urllib.parse import urlsplit

_LINK_SCHEMES = frozenset({"http", "https"})


def is_http_url(value: str) -> bool:
    """
    Args:
        value (str): A reference URL, as a check or an advisory gave it.

    Returns:
        bool: ``True`` when ``value`` is an absolute ``http`` or ``https`` URL with a host and
            carries no whitespace or control character. Browsers drop tabs and newlines inside a
            URL, so ``"java<TAB>script:..."`` must not slip through by looking like something else.
    """
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme.lower() in _LINK_SCHEMES and bool(parts.netloc)
