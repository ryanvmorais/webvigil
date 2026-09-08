"""
Check registration, discovery, and selection — RF-09, RF-11.

The autouse ``_isolate_registry`` fixture snapshots and restores the module-level
``_REGISTRY`` so each test starts from an empty registry and the real checks are
put back afterwards. ``_make_check`` builds throwaway :class:`Check` subclasses to
register.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from webvigil.checks import registry
from webvigil.checks.base import Check
from webvigil.core.errors import DuplicateCheckId, WebVigilError
from webvigil.core.findings import Category, ScanMode, Severity


@pytest.fixture(autouse=True)
def _isolate_registry() -> Iterator[None]:
    """Clear the global registry for the test and restore the real checks afterwards."""
    saved = dict(registry._REGISTRY)
    saved_loaded = registry._plugins_loaded
    registry._REGISTRY.clear()
    registry._plugins_loaded = False
    yield
    registry._REGISTRY.clear()
    registry._REGISTRY.update(saved)
    registry._plugins_loaded = saved_loaded


def _make_check(check_id: str | None = "x.y", *, mode: ScanMode = ScanMode.PASSIVE) -> type[Check]:
    """
    Args:
        check_id (str | None): The check id to assign, or ``None`` to leave it unset
            (to test the missing-metadata path).
        mode (ScanMode): The check's mode. Defaults to ``PASSIVE``.

    Returns:
        type[Check]: A fresh, unregistered :class:`Check` subclass.
    """

    class _C(Check):
        name = "A check"
        category = Category.HEADERS
        default_severity = Severity.LOW

        async def run(self, ctx: object) -> list[object]:
            return []

    if check_id is not None:
        _C.id = check_id
    _C.mode = mode
    return _C


def test_register_adds_to_the_registry() -> None:
    """A registered check is returned by ``all_checks``."""
    cls = registry.register(_make_check("http.headers.demo"))
    assert registry.all_checks() == [cls]


def test_register_rejects_missing_metadata() -> None:
    """A check with no id is rejected at registration."""
    with pytest.raises(WebVigilError, match="metadata"):
        registry.register(_make_check(check_id=None))


def test_duplicate_id_raises() -> None:
    """Registering two different classes under one id raises :class:`DuplicateCheckId`."""
    registry.register(_make_check("dup.id"))
    with pytest.raises(DuplicateCheckId, match=r"dup\.id"):
        registry.register(_make_check("dup.id"))


def test_re_registering_the_same_class_is_a_no_op() -> None:
    """Registering the exact same class twice is idempotent, not an error."""
    cls = _make_check("same.class")
    registry.register(cls)
    registry.register(cls)
    assert registry.all_checks() == [cls]


def test_iter_checks_filters_by_mode() -> None:
    """``iter_checks`` returns PASSIVE checks in Passive mode and both sets in Active mode."""
    passive = registry.register(_make_check("a.passive", mode=ScanMode.PASSIVE))
    active = registry.register(_make_check("b.active", mode=ScanMode.ACTIVE))

    assert registry.iter_checks(mode=ScanMode.PASSIVE) == [passive]
    assert registry.iter_checks(mode=ScanMode.ACTIVE) == [passive, active]


def test_iter_checks_honors_disabled_and_reports_unknown_ids() -> None:
    """``disabled`` drops a check; ``unknown_check_ids`` names ids that matched nothing."""
    registry.register(_make_check("keep.me"))
    registry.register(_make_check("drop.me"))

    assert registry.iter_checks(mode=ScanMode.PASSIVE, disabled=["drop.me"]) == [
        registry._REGISTRY["keep.me"]
    ]
    assert registry.unknown_check_ids(["drop.me", "ghost"]) == ["ghost"]


def test_load_plugins_discovers_entry_point_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """``load_plugins`` loads ``webvigil.checks`` entry points once, idempotently."""

    def _plugin() -> type[Check]:
        return registry.register(_make_check("plugin.check"))

    class _FakeEntryPoint:
        def load(self) -> type[Check]:
            return _plugin()

    monkeypatch.setattr(
        registry,
        "entry_points",
        lambda group: [_FakeEntryPoint()] if group == "webvigil.checks" else [],
    )

    registry.load_plugins()
    registry.load_plugins()  # idempotent

    assert "plugin.check" in registry._REGISTRY
