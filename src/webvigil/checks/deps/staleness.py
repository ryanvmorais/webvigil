"""A soft warning when the vendored advisory database is old (spec 004, RF-22).

Not a gate — it rides ``ScanResult.warnings`` and ``webvigil version`` so the age is
visible; refreshing the file (``scripts/update-retirejs-db.py``) is a maintainer action.
"""

from __future__ import annotations

from datetime import date

from webvigil.checks.deps.rules import RetireJsRules

STALE_AFTER_DAYS = 90


def staleness_warning(rules: RetireJsRules, *, today: date | None = None) -> list[str]:
    age = ((today or date.today()) - rules.provenance.retrieved).days
    if age > STALE_AFTER_DAYS:
        return [
            f"dependency advisory data is {age} days old; "
            "run scripts/update-retirejs-db.py to refresh it"
        ]
    return []
