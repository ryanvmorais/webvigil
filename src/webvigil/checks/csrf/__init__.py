"""Cross-site request forgery checks (spec 007, ``Category.CSRF``).

One passive check, :mod:`checks`. It reads the parsed ``<form>`` inventory on
``ScanContext.forms`` and the crawled responses' ``Set-Cookie`` headers — no extra request
— and flags every state-changing (``POST``) form that carries no anti-CSRF token, weighting
the finding by the session cookie's ``SameSite``.

Importing this package registers the check.
"""

from __future__ import annotations

from webvigil.checks.csrf import checks  # noqa: F401
