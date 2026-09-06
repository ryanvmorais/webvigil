"""Best-effort sitemap.xml parsing (RF-07).

A missing or malformed sitemap is never an error — it just yields no extra seed URLs.
``xml.etree`` does not expand external entities, so untrusted sitemap XML is safe to parse.
"""

from __future__ import annotations

from xml.etree import ElementTree

from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.http.client import HttpClient


def parse(text: str) -> list[str]:
    """Return every ``<loc>`` URL in a sitemap or sitemap index; ``[]`` if it will not parse."""
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return []
    locations: list[str] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "loc" and element.text and element.text.strip():
            locations.append(element.text.strip())
    return locations


async def fetch(http: HttpClient, url: str) -> list[str]:
    """Fetch and parse one sitemap URL; any failure yields ``[]``."""
    try:
        response = await http.get(url)
    except (RequestFailed, OutOfScopeError):
        return []
    if response.status_code != 200:
        return []
    return parse(response.text)
