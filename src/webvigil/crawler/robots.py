"""
robots.txt handling for the crawler (RF-07).

``robots.txt`` gates crawler *discovery* only — checks are never robots-gated.
It is also where we look for ``Sitemap:`` directives.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.robotparser import RobotFileParser

from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.http.client import HttpClient


@dataclass(frozen=True, slots=True)
class Robots:
    """
    A parsed robots.txt, or a permissive stand-in when there is none.

    Attributes:
        sitemaps (tuple[str, ...]): ``Sitemap:`` URLs declared in the file.
    """

    _rules: RobotFileParser | None
    sitemaps: tuple[str, ...]

    def can_fetch(self, user_agent: str, url: str) -> bool:
        """
        Args:
            user_agent (str): The crawler's ``User-Agent`` string.
            url (str): The absolute URL the crawler wants to fetch.

        Returns:
            bool: ``True`` when the rules allow it, or always when there is no
                ``robots.txt``.
        """
        if self._rules is None:
            return True
        return self._rules.can_fetch(user_agent, url)

    @classmethod
    def allow_all(cls) -> Robots:
        """
        Returns:
            Robots: A permissive instance with no rules and no sitemaps.
        """
        return cls(_rules=None, sitemaps=())


async def load(http: HttpClient, origin: str, user_agent: str) -> Robots:
    """
    Fetch and parse ``<origin>/robots.txt``; any failure yields a permissive result.

    Args:
        http (HttpClient): The shared HTTP client.
        origin (str): The target origin (scheme + host + port).
        user_agent (str): The crawler's ``User-Agent`` string (unused here, kept
            for symmetry with :meth:`Robots.can_fetch`).

    Returns:
        Robots: The parsed rules, or :meth:`Robots.allow_all` when the file is
            missing, empty, non-200, or unreachable.
    """
    try:
        response = await http.get(f"{origin}/robots.txt")
    except (RequestFailed, OutOfScopeError):
        return Robots.allow_all()
    if response.status_code != 200 or not response.text.strip():
        return Robots.allow_all()

    parser = RobotFileParser()
    parser.parse(response.text.splitlines())
    sitemaps = parser.site_maps() or []
    return Robots(_rules=parser, sitemaps=tuple(sitemaps))
