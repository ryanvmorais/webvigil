"""
Information-disclosure checks (spec 005, ``Category.DISCLOSURE``).

Two tiers:

* **Passive** — :mod:`errors` and :mod:`listing` read the responses the crawler already
  fetched. They always run (unless disabled).
* **Probe** — :class:`~webvigil.checks.disclosure.probe.DisclosureProbe` runs as an
  orchestrator pass when ``[disclosure] probe`` is on and at least one probe-fed check is
  selected; the checks in :mod:`checks` turn its ``ProbeHit``\\s into findings.

Importing this package registers every check.
"""

from __future__ import annotations

from webvigil.checks.disclosure import checks, errors, listing  # noqa: F401
