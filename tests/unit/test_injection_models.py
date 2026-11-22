"""
``ActiveBudget`` accounting — spec 006 (take / take_time_based) and spec 008 (take_recrawl).

Plain object under test: every request the active passes make is drawn from one
``ActiveBudget``, which enforces a per-scan ceiling, a per-point cap, and a
separate time-based sub-budget. The re-crawl of spec 008 draws from the same
scan ceiling but ignores the per-point cap.
"""

from __future__ import annotations

from webvigil.checks.injection.models import ActiveBudget


def _budget(**kw: int) -> ActiveBudget:
    """
    Args:
        **kw (int): Overrides for any of the three limits.

    Returns:
        ActiveBudget: A budget of 10 requests, 3 per point, 2 time-based.
    """
    limits = {"request_limit": 10, "per_point_limit": 3, "time_based_limit": 2, **kw}
    return ActiveBudget(**limits)


def test_take_respects_both_the_scan_and_per_point_caps() -> None:
    """``take`` grants up to the per-point cap, then refuses until the next point starts."""
    budget = _budget()
    budget.start_point()
    assert budget.take() and budget.take() and budget.take()
    assert not budget.take()  # per-point cap of 3 reached
    budget.start_point()
    assert budget.take()  # a new point resets point_spent


def test_take_recrawl_ignores_the_per_point_cap() -> None:
    """``take_recrawl`` runs past the per-point cap but still stops at the scan ceiling."""
    budget = _budget()
    budget.start_point()
    budget.take()  # point_spent == 1
    # take_recrawl keeps going well past per_point_limit (3)...
    assert all(budget.take_recrawl() for _ in range(9))
    assert budget.spent == 10
    # ...but stops at request_limit
    assert not budget.take_recrawl()


def test_take_recrawl_refuses_a_batch_that_would_overshoot() -> None:
    """A batched ``take_recrawl`` is all-or-nothing: a batch that would overshoot is refused."""
    budget = _budget()
    assert budget.take_recrawl(9)
    assert not budget.take_recrawl(2)
    assert budget.spent == 9


def test_take_time_based_stops_at_exactly_the_time_cap() -> None:
    """Two sleep requests are granted, the third is refused, and the general budget is unharmed."""
    budget = _budget(per_point_limit=10)
    budget.start_point()
    assert budget.take_time_based() and budget.take_time_based()
    assert not budget.take_time_based()
    assert (budget.time_based_spent, budget.spent) == (2, 2)
    assert budget.take()  # the general budget still has room


def test_take_time_based_also_needs_room_in_the_general_caps() -> None:
    """A full point refuses a sleep request too, and the refused one is not counted."""
    budget = _budget()
    budget.start_point()
    assert budget.take() and budget.take() and budget.take()  # per-point cap of 3 reached
    assert not budget.take_time_based()
    assert (budget.time_based_spent, budget.spent) == (0, 3)
