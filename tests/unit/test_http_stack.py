"""
No engine module imports the previous HTTP stack (spec 023, RF-01).

The source is read with ``ast`` and nothing is imported, so the guard also holds in an
environment where the old packages happen to be installed next to the new ones.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import webvigil

# The installed package's own folder, so the guard reads what the suite actually runs.
_PACKAGE = Path(webvigil.__file__).parent
# What RF-01 forbids: the engine's previous client and its transport.
_OLD_STACK = frozenset({"httpx", "httpcore"})


def _imported_packages(source: str) -> set[str]:
    """
    Args:
        source (str): Python source.

    Returns:
        set[str]: The top-level package of every absolute import, at any depth of the module.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.partition(".")[0])
    return found


def _imports_of(relative: str) -> set[str]:
    """
    Args:
        relative (str): A module path inside the package.

    Returns:
        set[str]: The packages that module imports.
    """
    return _imported_packages((_PACKAGE / relative).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The guard over the real tree, and its control
# ---------------------------------------------------------------------------


def test_no_engine_module_imports_the_previous_stack() -> None:
    """Every module of the package is read, and none names ``httpx`` or ``httpcore``."""
    modules = sorted(_PACKAGE.rglob("*.py"))
    assert _PACKAGE / "http" / "client.py" in modules
    offenders = {
        path.relative_to(_PACKAGE).as_posix(): found
        for path in modules
        if (found := _imported_packages(path.read_text(encoding="utf-8")) & _OLD_STACK)
    }
    assert offenders == {}


@pytest.mark.parametrize(
    ("relative", "package"),
    [("http/client.py", "httpx2"), ("http/addresses.py", "httpcore2")],
)
def test_the_walker_reads_the_imports_of_a_real_module(relative: str, package: str) -> None:
    """The control of the guard above: on the real tree it does see the current stack."""
    assert package in _imports_of(relative)


# ---------------------------------------------------------------------------
# What the walker flags and what it leaves alone
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "import httpx",
        "import httpcore",
        "import httpx as client",
        "import httpx._config",
        "import os, httpcore",
        "from httpx import AsyncClient",
        "from httpcore._models import URL",
        "def lazy():\n    import httpx",
    ],
)
def test_the_walker_flags_every_form_of_the_import(source: str) -> None:
    """Aliased, dotted, combined, ``from`` and function-level imports are all seen."""
    assert _imported_packages(source) & _OLD_STACK


@pytest.mark.parametrize(
    "source",
    [
        "import httpx2",
        "from httpcore2 import URL",
        "from .httpx import helper",
        "text = 'import httpx'",
    ],
)
def test_the_walker_leaves_near_misses_alone(source: str) -> None:
    """The new packages, a relative module and a string are not the previous stack."""
    assert not _imported_packages(source) & _OLD_STACK
