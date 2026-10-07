"""
The technology inventory: Observations dedup/order — RF-12, RF-14.

The ``ScanResult`` JSON round-trip of the inventory (``vulnerable`` flag included) is asserted by
``test_reporters_technologies.py::test_json_round_trips_the_inventory`` (issue #101: the model-level
test here made the same assertion).
"""

from __future__ import annotations

from webvigil.core.context import Detection, Observations
from webvigil.core.technology import DetectionMethod, Technology


def _tech(
    name: str, version: str | None, *, method: DetectionMethod = DetectionMethod.FILENAME
) -> Technology:
    """
    Args:
        name (str): Library name.
        version (str | None): Detected version, or ``None``.
        method (DetectionMethod): How it was detected. Defaults to
            ``FILENAME``.

    Returns:
        Technology: An inventory entry with a synthetic source URL.
    """
    return Technology(
        name=name, version=version, detection=method, source_url=f"https://x/{name}.js"
    )


def test_observations_dedup_on_name_and_version() -> None:
    """One entry per (name, version), first write wins, sorted by name then version."""
    obs = Observations()
    obs.add_technology(_tech("jquery", "1.12.4"))
    obs.add_technology(_tech("jquery", "1.12.4", method=DetectionMethod.URI))  # ignored
    obs.add_technology(_tech("jquery", "3.6.0"))
    obs.add_technology(_tech("bootstrap", None))

    got = obs.technologies
    assert [(t.name, t.version) for t in got] == [
        ("bootstrap", None),
        ("jquery", "1.12.4"),
        ("jquery", "3.6.0"),
    ]
    assert got[1].detection is DetectionMethod.FILENAME  # first write wins


def test_observations_warnings_accumulate() -> None:
    """``add_warning`` appends in call order."""
    obs = Observations()
    obs.add_warning("one")
    obs.add_warning("two")
    assert obs.warnings == ["one", "two"]


def test_detection_is_frozen_and_hashable() -> None:
    """``Detection`` is a frozen, hashable dataclass."""
    d = Detection(
        "jquery", "1.12.4", DetectionMethod.FILENAME, "https://x/jquery.js", "jquery-1.12.4.min.js"
    )
    assert {d, d} == {d}
