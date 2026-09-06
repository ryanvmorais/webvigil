"""robots.txt handling for the crawler (RF-07).

``robots.txt`` gates crawler *discovery* only — checks are never robots-gated. It is also
where we look for ``Sitemap:`` directives.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.robotparser import RobotFileParser

from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.http.client import HttpClient


@dataclass(frozen=True, slots=True)
class Robots:
    """A parsed robots.txt, or a permissive stand-in when there is none."""

    _rules: RobotFileParser | None
    sitemaps: tuple[str, ...]

    def can_fetch(self, user_agent: str, url: str) -> bool:
        if self._rules is None:
            return True
        return self._rules.can_fetch(user_agent, url)

    @classmethod
    def allow_all(cls) -> Robots:
        return cls(_rules=None, sitemaps=())


async def load(http: HttpClient, origin: str, user_agent: str) -> Robots:
    """Fetch and parse ``<origin>/robots.txt``; any failure yields a permissive result."""
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
