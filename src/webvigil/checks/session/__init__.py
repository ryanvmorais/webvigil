"""
Session-security checks (spec 020, ``Category.SESSION``).

Weak or predictable session ids, session fixation, and a logout that does not invalidate the
session. ``cookies`` is the one definition of a session-looking cookie, ``ids`` the pure
analysers, ``scanner`` the pass that turns observations into hits, and ``checks`` the three
registered checks that turn hits into findings.
"""

from __future__ import annotations

from webvigil.checks.session import checks as checks

__all__ = ["checks"]
