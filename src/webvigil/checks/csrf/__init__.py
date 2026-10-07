"""
Cross-site request forgery checks (spec 007, ``Category.CSRF``).

A passive check, ``csrf.form.no-token`` (:mod:`checks`): it reads the parsed
``<form>`` inventory on ``ScanContext.forms`` and the crawled responses'
``Set-Cookie`` headers — no extra request — and flags every state-changing
(``POST``) form that carries no anti-CSRF token, weighting the finding by the
session cookie's ``SameSite``.

An active one, ``csrf.form.token-not-enforced`` (spec 017): the opt-in
:class:`~webvigil.checks.csrf.scanner.CsrfScanner` pass replays each candidate
form without a valid token and from a foreign origin, and the check reports the
forms the server accepted. It writes to the target (``--confirm-csrf``).

Importing this package registers both checks.
"""

from __future__ import annotations

from webvigil.checks.csrf import checks  # noqa: F401
