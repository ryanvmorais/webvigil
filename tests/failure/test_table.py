"""
The table check of spec 027 (RF-02, RF-06): the failure table keeps up with the code.

- Every pass ``Orchestrator.run`` calls, and the crawl, is a stage's seam, read from the syntax
  tree of ``run``; a throwaway class with one more pass, or a pass renamed, is the positive
  control.
- Every seam of the table names something that exists.
- Every network client, file operation and database statement of the two inventories is a key of
  :data:`~tests.failure.table.DEPENDENCIES` with a stage, and every key is one of them.
- The fault plan is fixed and gives every stage every one of its kinds.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import itertools
import textwrap
from collections.abc import Mapping
from typing import Final

from tests.failure.table import (
    DEPENDENCIES,
    HOSTILE,
    PAD_CHAR,
    SCAN_RUNS,
    STAGE_NAMES,
    STAGES,
    TARGET,
    Kind,
    _bucket,
    credential_marker,
    failure_marker,
    failure_text,
    fault_for,
    kind_for,
    stage,
)
from tests.unit.test_destination_inventory import CONNECTIONS
from tests.unit.test_sensitive_point_inventory import SENSITIVE_POINTS
from webvigil.core import orchestrator as orch_mod
from webvigil.core.bounded import TEXT_MAX_CHARS
from webvigil.core.orchestrator import Orchestrator
from webvigil.core.target import Target
from webvigil.crawler.crawler import Crawler

# The calls of ``Orchestrator.run`` on ``self`` that are not passes, with the reason.
NOT_PASSES: Final[Mapping[str, str]] = {
    "_enforce_active_gate": "checks the configuration before any request; raises a project error",
    "_select_checks": "reads the check registry and the configuration; no dependency",
}

# The classes a short seam (``Class.method``) names.
_SEAM_CLASSES: Final[Mapping[str, type]] = {
    "Orchestrator": Orchestrator,
    "Crawler": Crawler,
    "Target": Target,
}

# ---------------------------------------------------------------------------
# Every pass has a row (RF-06)
# ---------------------------------------------------------------------------


def passes_of(source: str, class_name: str = "Orchestrator") -> set[str]:
    """
    Read the passes a scan's ``run`` calls.

    Args:
        source (str): A module's source.
        class_name (str): The class whose ``run`` is read. Defaults to ``"Orchestrator"``.

    Returns:
        set[str]: ``<class_name>.<method>`` for every call of a method on ``self`` in ``run``,
            except :data:`NOT_PASSES`, and ``Crawler.discover`` for a call of ``discover``.
    """
    tree = ast.parse(source)
    run = next(
        node
        for cls in ast.walk(tree)
        if isinstance(cls, ast.ClassDef) and cls.name == class_name
        for node in cls.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "run"
    )
    found: set[str] = set()
    for node in ast.walk(run):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        owner, name = node.func.value, node.func.attr
        if name == "discover":
            found.add("Crawler.discover")
        elif isinstance(owner, ast.Name) and owner.id == "self" and name not in NOT_PASSES:
            found.add(f"{class_name}.{name}")
    return found


def unlisted(passes: set[str]) -> set[str]:
    """
    Args:
        passes (set[str]): What :func:`passes_of` read.

    Returns:
        set[str]: The passes no stage names as its seam.
    """
    return passes - {row.seam for row in STAGES}


def stale(passes: set[str], class_name: str = "Orchestrator") -> set[str]:
    """
    Args:
        passes (set[str]): What :func:`passes_of` read.
        class_name (str): The class that was read. Defaults to ``"Orchestrator"``.

    Returns:
        set[str]: The seams on that class (and the crawl) that ``run`` no longer calls.
    """
    seams = {
        row.seam
        for row in STAGES
        if row.seam.startswith(f"{class_name}.") or row.seam == "Crawler.discover"
    }
    return seams - passes


def test_every_pass_of_the_scan_is_a_stage() -> None:
    """Every pass ``Orchestrator.run`` calls, and the crawl, is the seam of a row, and back."""
    passes = passes_of(inspect.getsource(orch_mod))
    # the positive control: the reading found the passes, not an empty set that passes anything
    assert {"Orchestrator._fingerprint", "Orchestrator._scan_session", "Crawler.discover"} <= passes
    assert unlisted(passes) == set()
    assert stale(passes) == set()


_THROWAWAY: Final = textwrap.dedent("""
    class Orchestrator:
        async def run(self, raw_target):
            self._enforce_active_gate()
            await self._log_in(http, target, warnings)
            pages = await crawler.discover()
            await self._fingerprint(pages)
            await self._brand_new_pass(pages)
            self._load_har(target, warnings)
    """)


def test_a_pass_with_no_row_is_named() -> None:
    """The positive control: a throwaway ``run`` with a pass the table lacks names that pass."""
    passes = passes_of(_THROWAWAY)
    assert unlisted(passes) == {"Orchestrator._brand_new_pass"}
    assert "Orchestrator._enforce_active_gate" not in passes


def test_a_renamed_pass_is_named_on_both_sides() -> None:
    """A pass renamed in a throwaway class: the new name has no row, and the old row is stale."""
    renamed = _THROWAWAY.replace("_fingerprint", "_fingerprint_v2").replace(
        "_brand_new_pass", "_log_in"
    )
    passes = passes_of(renamed)
    assert unlisted(passes) == {"Orchestrator._fingerprint_v2"}
    assert "Orchestrator._fingerprint" in stale(passes)


def _resolve(seam: str) -> object:
    """
    Args:
        seam (str): A stage's seam.

    Returns:
        object: What it names.

    Raises:
        AttributeError: If it names nothing.
    """
    head, _, rest = seam.partition(".")
    if head in _SEAM_CLASSES:
        return getattr(_SEAM_CLASSES[head], rest)
    parts = seam.split(".")
    for cut in range(len(parts) - 1, 0, -1):
        try:
            found: object = importlib.import_module(".".join(parts[:cut]))
        except ModuleNotFoundError:
            continue
        for name in parts[cut:]:
            found = getattr(found, name)
        return found
    raise AttributeError(seam)


def test_every_seam_names_something_that_exists() -> None:
    """A seam that a refactor renamed fails here, before a harness wraps nothing."""
    for row in STAGES:
        assert _resolve(row.seam) is not None, row


def test_the_rows_are_unique_and_well_formed() -> None:
    """One row per name; a scan stage gets the six network kinds, every other one a single kind."""
    assert len(STAGE_NAMES) == len(STAGES)
    for row in STAGES:
        assert row.kinds, row
        assert len(set(row.kinds)) == len(row.kinds), row
        if row.harness == "scan":
            assert len(row.kinds) == SCAN_RUNS, row


# ---------------------------------------------------------------------------
# Every dependency has a row (RF-06)
# ---------------------------------------------------------------------------


def dependency_keys() -> set[str]:
    """
    Returns:
        set[str]: Every entry of ``CONNECTIONS`` (spec 026) and every ``file`` and ``sql`` point
            of the sensitive-point inventory.
    """
    points = {key for key in SENSITIVE_POINTS if key.split(" ")[1] in {"file", "sql"}}
    return set(CONNECTIONS) | points


def test_every_dependency_has_a_stage() -> None:
    """Every connection, file and statement is a key, every key is one, and each names a row."""
    keys = dependency_keys()
    # the positive control: the inventories gave the three families
    assert any(" sql " in key for key in keys) and any(" file " in key for key in keys)
    assert "webvigil.http.client:HttpClient.__aenter__" in keys
    assert keys - set(DEPENDENCIES) == set(), "a dependency with no row"
    assert set(DEPENDENCIES) - keys == set(), "a row for a dependency that is gone"
    assert set(DEPENDENCIES.values()) <= STAGE_NAMES


# ---------------------------------------------------------------------------
# The plan is fixed (RF-02, ADR-1)
# ---------------------------------------------------------------------------

_URLS: Final = (*(f"http://demo.test/page/{n}" for n in range(64)), TARGET)


def test_the_plan_gives_the_same_answer_twice() -> None:
    """The same arguments give the same kind, so a run fails the same requests every time."""
    grid = list(itertools.product(range(SCAN_RUNS), STAGES, range(3), _URLS, range(3)))
    first = [fault_for(*args) for args in grid]
    assert first == [fault_for(*args) for args in grid]
    assert any(kind is not None for kind in first) and None in first  # the plan does both


def test_the_runs_give_every_stage_every_kind_and_neighbours_differ() -> None:
    """
    Over the scan runs, every stage gets each of its kinds once; in one run two neighbouring
    scan stages never get the same kind, so a warning names one cause.
    """
    scan = [row for row in STAGES if row.harness == "scan"]
    for row in STAGES:
        runs = range(len(row.kinds))
        assert sorted(kind_for(run, row) for run in runs) == sorted(row.kinds), row
    for run in range(SCAN_RUNS):
        for before, after in itertools.pairwise(scan):
            assert kind_for(run, before) != kind_for(run, after), (run, before.name, after.name)


def test_the_first_request_fails_once_and_a_bucket_fails_for_good() -> None:
    """The first request fails on its first attempt only; a URL in bucket 0, on every attempt."""
    crawl = stage("crawl")
    passing = next(url for url in _URLS if _bucket(url) != 0)
    failing = next(url for url in _URLS if _bucket(url) == 0)
    run = next(r for r in range(SCAN_RUNS) if kind_for(r, crawl) is not Kind.RAISES)
    kind = kind_for(run, crawl)
    assert fault_for(run, crawl, 0, passing, 0) is kind
    assert fault_for(run, crawl, 0, passing, 1) is None  # the retry goes through
    assert fault_for(run, crawl, 5, passing, 0) is None
    assert [fault_for(run, crawl, 5, failing, attempt) for attempt in range(3)] == [kind] * 3


def test_raises_happens_once_and_the_target_is_kept_outside_its_stage() -> None:
    """``RAISES`` fails the first request only; the target URL fails for good in ``target`` only."""
    crawl = stage("crawl")
    raising = next(r for r in range(SCAN_RUNS) if kind_for(r, crawl) is Kind.RAISES)
    failing = next(url for url in _URLS if _bucket(url) == 0)
    assert fault_for(raising, crawl, 0, failing, 0) is Kind.RAISES
    assert fault_for(raising, crawl, 1, failing, 0) is None
    target_row = stage("target")
    run = next(r for r in range(SCAN_RUNS) if kind_for(r, crawl) is not Kind.RAISES)
    assert fault_for(run, crawl, 3, TARGET, 0) is None
    expected = kind_for(run, target_row) if _bucket(TARGET) == 0 else None
    assert fault_for(run, target_row, 3, TARGET, 0) is expected


# ---------------------------------------------------------------------------
# The markers (RF-01)
# ---------------------------------------------------------------------------


def test_the_markers_are_distinct_and_carry_the_hostile_text() -> None:
    """Each marker names where it came from; a failure's text adds the controls and the padding."""
    failures = {failure_marker(row.name, kind) for row in STAGES for kind in row.kinds}
    assert len(failures) == sum(len(row.kinds) for row in STAGES)
    assert failure_marker("crawl", Kind.RESET).startswith("wv-fail-crawl-reset-")
    assert credential_marker("cookie") != credential_marker("bearer")
    text = failure_text(failure_marker("crawl", Kind.RESET))
    for char in (chr(0x1B), "\r\n", chr(0x202E), chr(0x200B)):
        assert char in HOSTILE
    assert text.count(PAD_CHAR) > TEXT_MAX_CHARS
