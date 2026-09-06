"""The scope guard: the single place that decides whether a URL may be requested."""

from __future__ import annotations

from webvigil.core.errors import OutOfScopeError
from webvigil.core.target import Target


class ScopeGuard:
    """Wraps a :class:`Target`'s scope rule with a raising and a boolean check."""

    def __init__(self, target: Target) -> None:
        self._target = target

    def allows(self, url: str) -> bool:
        return self._target.in_scope(url)

    def check(self, url: str) -> None:
        """Raise :class:`OutOfScopeError` if ``url`` is outside the target scope."""
        if not self._target.in_scope(url):
            raise OutOfScopeError(url)
