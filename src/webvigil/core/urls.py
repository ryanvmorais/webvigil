"""
URL helpers the engine and the reporters share: is this safe to turn into a link, and where does
a link the scanned site wrote lead.

A finding's ``references`` come from the checks, except the ones the opt-in OSV lookup copies from
an advisory record, which a third-party database wrote. Autoescaping keeps such a value from
breaking out of an attribute; it does not stop a ``javascript:`` or ``data:`` URL from being a
link, so the value is checked where it enters (``checks.deps.osv``) and again where it is
rendered (the HTML report; the dashboard has the same check in ``web/src/lib/links.ts``).

A link on a scanned page is written by the site, so it can be malformed in ways that make the
standard library raise: an unclosed IPv6 bracket (``http://[::1``) fails ``urljoin`` itself, and a
port past 65535 fails the first ``.port``. :func:`resolve_url` turns either into ``None``, so one
bad link costs that link and not the crawl, the check or the pass that met it.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from webvigil.core.text import INVISIBLE_CHARS

_LINK_SCHEMES = frozenset({"http", "https"})
# A bidirectional or invisible character makes a link read as another address than the one it
# opens, and the reporters would show it as an escape inside the ``href``.
_INVISIBLE_RE = re.compile(f"[{INVISIBLE_CHARS}]")


def is_http_url(value: str) -> bool:
    """
    Args:
        value (str): A reference URL, as a check or an advisory gave it.

    Returns:
        bool: ``True`` when ``value`` is an absolute ``http`` or ``https`` URL with a host and
            carries no whitespace, control, bidirectional or invisible character. Browsers drop
            tabs and newlines inside a URL, so ``"java<TAB>script:..."`` must not slip through by
            looking like something else.
    """
    if any(ch.isspace() or ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in value):
        return False
    if _INVISIBLE_RE.search(value):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme.lower() in _LINK_SCHEMES and bool(parts.netloc)


def resolve_url(base: str, ref: str) -> str | None:
    """
    Resolve ``ref`` against ``base`` as a browser follows a link, or give up on a malformed one.

    Args:
        base (str): The URL of the page or response the reference came from.
        ref (str): The reference as the site wrote it (``href``, ``src``, ``action``,
            ``Location``).

    Returns:
        str | None: The absolute URL, or ``None`` when ``ref`` (or the result) cannot be parsed:
            a malformed bracketed host, or a port that is not a number in ``0..65535``.
    """
    try:
        url = urljoin(base, ref)
        _ = urlsplit(url).port  # parsed lazily: a bad port raises only here
    except ValueError:
        return None
    return url
