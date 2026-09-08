"""
Page-content checks (spec 013): what a page's HTML tells the browser to load.

Two passive checks, both pure functions of ``ctx.pages`` — they issue no HTTP:
``content.sri.missing`` (a cross-origin subresource with no Subresource
Integrity) and ``content.mixed`` (an HTTPS page pulling a resource over
``http://``).
"""

from __future__ import annotations

from webvigil.checks.content import checks  # noqa: F401  — registers the checks on import
