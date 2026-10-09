"""
Best-effort sitemap.xml parsing (RF-07).

A missing or malformed sitemap is never an error — it just yields no extra seed
URLs. ``xml.etree`` does not expand external entities, and ``expat`` stops an entity
expansion that grows out of proportion, so untrusted sitemap XML is safe to parse.

The sitemaps come from the scanned site, so how many are read and how many URLs are taken from them
is bounded (:data:`MAX_SITEMAPS`, :data:`MAX_URLS`).
"""

from __future__ import annotations

from xml.etree import ElementTree

from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.http.client import HttpClient

# Sitemaps a scan reads: the ones robots.txt declares plus the conventional one. A site that
# declares more is asking for requests the scan does not budget for.
MAX_SITEMAPS = 20
# URLs a scan takes from all its sitemaps together; the crawl fetches at most ``max_pages`` of
# them, so the rest would only fill memory.
MAX_URLS = 10_000


def parse(text: str, *, limit: int = MAX_URLS) -> list[str]:
    """
    Return every ``<loc>`` URL in a sitemap or sitemap index.

    Args:
        text (str): The raw XML body.
        limit (int): The most URLs to return. Defaults to :data:`MAX_URLS`.

    Returns:
        list[str]: The trimmed ``<loc>`` values (at most ``limit``), or ``[]`` when the
            body will not parse.
    """
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return []
    locations: list[str] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "loc" and element.text and element.text.strip():
            locations.append(element.text.strip())
            if len(locations) >= limit:
                break
    return locations


async def fetch(http: HttpClient, url: str, *, limit: int = MAX_URLS) -> list[str]:
    """
    Fetch and parse one sitemap URL.

    Args:
        http (HttpClient): The shared HTTP client.
        url (str): The sitemap URL to fetch.
        limit (int): The most URLs to return. Defaults to :data:`MAX_URLS`.

    Returns:
        list[str]: The ``<loc>`` URLs (at most ``limit``), or ``[]`` on any non-200 response
            or transport failure.
    """
    try:
        response = await http.get(url)
    except (RequestFailed, OutOfScopeError):
        return []
    if response.status_code != 200:
        return []
    return parse(response.text, limit=limit)
