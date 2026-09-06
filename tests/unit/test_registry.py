"""Check registration, discovery, and selection — RF-09, RF-11."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from webvigil.checks import registry
from webvigil.checks.base import Check
from webvigil.core.errors import DuplicateCheckId, WebVigilError
from webvigil.core.findings import Category, ScanMode, Severity


@pytest.fixture(autouse=True)
def _isolate_registry() -> Iterator[None]:
    saved = dict(registry._REGISTRY)
    saved_loaded = registry._plugins_loaded
    registry._REGISTRY.clear()
    registry._plugins_loaded = False
    yield
    registry._REGISTRY.clear()
    registry._REGISTRY.update(saved)
    registry._plugins_loaded = saved_loaded


def _make_check(check_id: str | None = "x.y", *, mode: ScanMode = ScanMode.PASSIVE) -> type[Check]:
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
    cls = registry.register(_make_check("http.headers.demo"))
    assert registry.all_checks() == [cls]


def test_register_rejects_missing_metadata() -> None:
    with pytest.raises(WebVigilError, match="metadata"):
        registry.register(_make_check(check_id=None))


def test_duplicate_id_raises() -> None:
    registry.register(_make_check("dup.id"))
    with pytest.raises(DuplicateCheckId, match=r"dup\.id"):
        registry.register(_make_check("dup.id"))


def test_re_registering_the_same_class_is_a_no_op() -> None:
    cls = _make_check("same.class")
    registry.register(cls)
    registry.register(cls)
    assert registry.all_checks() == [cls]


def test_iter_checks_filters_by_mode() -> None:
    passive = registry.register(_make_check("a.passive", mode=ScanMode.PASSIVE))
    active = registry.register(_make_check("b.active", mode=ScanMode.ACTIVE))

    assert registry.iter_checks(mode=ScanMode.PASSIVE) == [passive]
    assert registry.iter_checks(mode=ScanMode.ACTIVE) == [passive, active]


def test_iter_checks_honors_disabled_and_reports_unknown_ids() -> None:
    registry.register(_make_check("keep.me"))
    registry.register(_make_check("drop.me"))

    assert registry.iter_checks(mode=ScanMode.PASSIVE, disabled=["drop.me"]) == [
        registry._REGISTRY["keep.me"]
    ]
    assert registry.unknown_check_ids(["drop.me", "ghost"]) == ["ghost"]


def test_load_plugins_discovers_entry_point_checks(monkeypatch: pytest.MonkeyPatch) -> None:
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
