"""
Lightweight in-scope page discovery.

BFS from the seed URL over ``<a href>`` links and sitemap seeds, GET only, no
JavaScript, bounded by ``max_pages``. Also builds the ``<form>`` inventory the
injection and CSRF work depends on.
"""

from __future__ import annotations

from webvigil.crawler.crawler import Crawler
from webvigil.crawler.robots import Robots

__all__ = ["Crawler", "Robots"]
