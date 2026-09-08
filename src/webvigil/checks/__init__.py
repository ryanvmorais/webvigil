"""
Check plugins.

Each check subclasses :class:`~webvigil.checks.base.Check`, declares its
metadata, and implements ``async run(ctx) -> list[Finding]``. Checks are
registered with the ``@register`` decorator and, for third parties, discovered
via the ``webvigil.checks`` entry points.
"""

from __future__ import annotations

from webvigil.checks.base import Check
from webvigil.checks.registry import (
    all_checks,
    iter_checks,
    load_plugins,
    register,
    unknown_check_ids,
)

__all__ = [
    "Check",
    "all_checks",
    "iter_checks",
    "load_plugins",
    "register",
    "unknown_check_ids",
]


def _load_builtin_checks() -> None:
    """Import the built-in check packages so their ``@register`` calls run at import time."""
    from webvigil.checks import (  # noqa: F401
        content,
        cookies,
        cors,
        csrf,
        deps,
        disclosure,
        envelope,
        headers,
        injection,
        tls,
        upload,
    )


_load_builtin_checks()
