"""
The scope guard: the single place that decides whether a URL may be requested.

Both the HTTP client and the crawler consult a :class:`ScopeGuard` before every
fetch, so ``--scope`` is enforced in exactly one implementation.
"""

from __future__ import annotations

from webvigil.core.errors import OutOfScopeError
from webvigil.core.target import Target


class ScopeGuard:
    """
    Wraps a :class:`~webvigil.core.target.Target`'s scope rule.

    Offers a boolean check (:meth:`allows`) for callers that branch on scope
    and a raising check (:meth:`check`) for callers that must not proceed.
    """

    def __init__(self, target: Target) -> None:
        """
        Args:
            target (Target): The target whose scope rule this guard enforces.
        """
        self._target = target

    def allows(self, url: str) -> bool:
        """
        Args:
            url (str): The absolute URL to test.

        Returns:
            bool: ``True`` when ``url`` is within the target scope.
        """
        return self._target.in_scope(url)

    def check(self, url: str) -> None:
        """
        Raise if ``url`` is outside the target scope.

        Args:
            url (str): The absolute URL to test.

        Raises:
            OutOfScopeError: When ``url`` is outside the target scope.
        """
        if not self._target.in_scope(url):
            raise OutOfScopeError(url)
