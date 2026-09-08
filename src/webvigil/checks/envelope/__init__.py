"""
Request-envelope checks (spec 012, ``Category.INJECTION`` and ``Category.HTTP``).

:class:`~webvigil.checks.envelope.scanner.EnvelopeScanner` runs as an
orchestrator pass in Active Mode when a check it feeds is selected: it
re-requests a bounded sample of crawled URLs with a poisoned ``Host`` /
``X-Forwarded-*`` header and with ``OPTIONS`` / ``TRACE``. The checks in
:mod:`checks` turn its ``EnvelopeHit``\\s into findings.

Importing this package registers every check.
"""

from __future__ import annotations

from webvigil.checks.envelope import checks  # noqa: F401  (registers host-header + methods)
