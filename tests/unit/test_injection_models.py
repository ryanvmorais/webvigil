"""
``ActiveBudget`` accounting — spec 006 (take / take_time_based) and spec 008 (take_recrawl).
"""

from __future__ import annotations

from webvigil.checks.injection.models import ActiveBudget


def _budget(**kw: int) -> ActiveBudget:
    return ActiveBudget(request_limit=10, per_point_limit=3, time_based_limit=2, **kw)


def test_take_respects_both_the_scan_and_per_point_caps() -> None:
    budget = _budget()
    budget.start_point()
    assert budget.take() and budget.take() and budget.take()
    assert not budget.take()  # per-point cap of 3 reached
    budget.start_point()
    assert budget.take()  # a new point resets point_spent


def test_take_recrawl_ignores_the_per_point_cap() -> None:
    budget = _budget()
    budget.start_point()
    budget.take()  # point_spent == 1
    # take_recrawl keeps going well past per_point_limit (3)...
    assert all(budget.take_recrawl() for _ in range(9))
    assert budget.spent == 10
    # ...but stops at request_limit
    assert not budget.take_recrawl()


def test_take_recrawl_refuses_a_batch_that_would_overshoot() -> None:
    budget = _budget()
    assert budget.take_recrawl(9)
    assert not budget.take_recrawl(2)
    assert budget.spent == 9
