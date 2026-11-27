"""
The technology inventory: Observations dedup/order — RF-12, RF-14.

The ``ScanResult`` JSON round-trip of the inventory (``vulnerable`` flag included) is asserted by
``test_reporters_technologies.py::test_json_round_trips_the_inventory`` (issue #101: the model-level
test here made the same assertion).
"""

from __future__ import annotations

import dataclasses

import pytest

from webvigil.core import context
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


def test_detection_is_frozen_and_hashable_by_value() -> None:
    """``Detection`` is frozen, and two equal detections are one set member (the dedup needs it)."""
    fields = ("jquery", "1.12.4", DetectionMethod.FILENAME, "https://x/jquery.js", "jquery.min.js")
    d = Detection(*fields)
    assert {d, Detection(*fields)} == {d}
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.version = "9.9.9"  # type: ignore[misc]  # writing to a frozen field is the point


def test_the_inventory_past_its_cap_turns_new_entries_away_and_warns_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Up to ``TECHNOLOGIES_CAP`` entries stay; the first one turned away queues one warning."""
    monkeypatch.setattr(context, "TECHNOLOGIES_CAP", 2)
    obs = Observations()
    for version in ("1.0.0", "1.0.1", "1.0.2", "1.0.3"):
        obs.add_technology(_tech("jquery", version))
    obs.add_technology(_tech("jquery", "1.0.0"))  # a pair already kept is not turned away
    assert [t.version for t in obs.technologies] == ["1.0.0", "1.0.1"]
    assert obs.warnings == ["the technology inventory stopped at 2 entries"]


def test_the_inventory_up_to_its_cap_keeps_every_entry_without_a_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """As many entries as the cap, one of them added twice, fit with no warning."""
    monkeypatch.setattr(context, "TECHNOLOGIES_CAP", 2)
    obs = Observations()
    for version in ("1.0.0", "1.0.1", "1.0.1"):
        obs.add_technology(_tech("jquery", version))
    assert [t.version for t in obs.technologies] == ["1.0.0", "1.0.1"]
    assert obs.warnings == []
