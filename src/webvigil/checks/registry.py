"""
Check registration and discovery (RF-09).

Built-in checks register with ``@register`` at import time. Third-party checks
are found through the ``webvigil.checks`` entry-point group.
"""

from __future__ import annotations

from collections.abc import Sequence
from importlib.metadata import entry_points

from webvigil.checks.base import Check
from webvigil.core.errors import DuplicateCheckId, WebVigilError
from webvigil.core.findings import ScanMode

_REGISTRY: dict[str, type[Check]] = {}
_REQUIRED_METADATA = ("id", "name", "category", "default_severity")
_ENTRY_POINT_GROUP = "webvigil.checks"

_plugins_loaded = False


def register(check_cls: type[Check]) -> type[Check]:
    """
    Class decorator: validate metadata and add the check to the registry.

    Args:
        check_cls (type[Check]): The check class being registered.

    Returns:
        type[Check]: ``check_cls`` unchanged, so the decorator is transparent.

    Raises:
        WebVigilError: If a required metadata attribute is missing or empty.
        DuplicateCheckId: If another class is already registered under the same
            ``id``.
    """
    for attribute in _REQUIRED_METADATA:
        if getattr(check_cls, attribute, None) in (None, ""):
            raise WebVigilError(
                f"{check_cls.__name__} is missing required check metadata: {attribute!r}"
            )
    check_id = check_cls.id
    existing = _REGISTRY.get(check_id)
    if existing is not None and existing is not check_cls:
        raise DuplicateCheckId(
            f"check id {check_id!r} is registered by both "
            f"{existing.__module__}.{existing.__name__} and "
            f"{check_cls.__module__}.{check_cls.__name__}"
        )
    _REGISTRY[check_id] = check_cls
    return check_cls


def load_plugins() -> None:
    """
    Import every package registered under the ``webvigil.checks`` entry-point group.

    Idempotent: the discovery scan runs at most once per process.
    """
    global _plugins_loaded
    if _plugins_loaded:
        return
    for entry_point in entry_points(group=_ENTRY_POINT_GROUP):
        entry_point.load()
    _plugins_loaded = True


def all_checks() -> list[type[Check]]:
    """
    Returns:
        list[type[Check]]: Every registered check, ordered by ``id``.
    """
    return sorted(_REGISTRY.values(), key=lambda check: check.id)


def unknown_check_ids(disabled: Sequence[str]) -> list[str]:
    """
    Args:
        disabled (Sequence[str]): Check ids from the ``[checks] disabled`` list.

    Returns:
        list[str]: The subset that does not match any registered check id,
            sorted.
    """
    return sorted(set(disabled) - set(_REGISTRY))


def iter_checks(*, mode: ScanMode, disabled: Sequence[str] = ()) -> list[type[Check]]:
    """
    Select the checks eligible for a run.

    Args:
        mode (ScanMode): The scan mode; an Active-only check is excluded from a
            Passive run.
        disabled (Sequence[str]): Check ids to exclude. Defaults to empty.

    Returns:
        list[type[Check]]: The eligible checks, ordered by ``id``.
    """
    blocked = set(disabled)
    return [
        check
        for check in all_checks()
        if check.id not in blocked and _mode_allows(mode, check.mode)
    ]


def _mode_allows(run_mode: ScanMode, check_mode: ScanMode) -> bool:
    """
    Args:
        run_mode (ScanMode): The mode the scan is running in.
        check_mode (ScanMode): The check's minimum mode.

    Returns:
        bool: ``True`` when a Passive check (always) or an Active check in an
            Active run.
    """
    if check_mode is ScanMode.PASSIVE:
        return True
    return run_mode is ScanMode.ACTIVE
