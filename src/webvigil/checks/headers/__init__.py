"""Security-header and revealing-header checks (RF-16, RF-17).

Importing this package registers every header check.
"""

from __future__ import annotations

from webvigil.checks.headers import csp, hsts, misc, revealing  # noqa: F401
