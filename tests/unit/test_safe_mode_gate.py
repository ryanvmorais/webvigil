"""
Every pass that sends a request asks the one gate of ``crawler/safety.py`` first.

A logout or a state-changing action is left alone the same way by every pass only while no
pass keeps a filter of its own, or none. The table below names each module that sends a
request to the target and the gate it calls (``is_unsafe_url``, ``is_unsafe_form``,
``is_unsafe_operation`` / ``is_unsafe_api_operation``), or why it needs none. A new sending
module fails here until it is in the table.
"""

from __future__ import annotations

import re
from pathlib import Path

import webvigil

_SRC = Path(webvigil.__file__).parent
_SENDS = re.compile(r"\b_?(?:http|client)\.(?:get|post|request|send|stream)\(")

# The module that sends, or builds what another module sends -> the gates it calls.
GATED: dict[str, tuple[str, ...]] = {
    "crawler/crawler.py": ("is_unsafe_url", "is_unsafe_form", "is_unsafe_api_operation"),
    "crawler/openapi.py": ("is_unsafe_operation",),
    "crawler/har.py": ("is_unsafe_api_operation",),
    "checks/csrf/scanner.py": ("is_unsafe_form",),
    "checks/injection/points.py": ("is_unsafe_form",),
    "checks/upload/scanner.py": ("is_unsafe_form",),
    "checks/envelope/scanner.py": ("is_unsafe_url", "is_unsafe_form"),
    "checks/deps/fingerprint.py": ("is_unsafe_url",),
    "checks/disclosure/probe.py": ("is_unsafe_url",),
}

# A module that sends with no gate of its own -> why.
EXEMPT: dict[str, str] = {
    "auth/login.py": "the login the configuration names, and the page it lands on",
    "checks/cors/check.py": "the entry URL, which the person scanning chose",
    "checks/deps/osv.py": "the OSV API, not the target",
    "checks/injection/engine.py": "the points of checks/injection/points.py, gated there",
    "checks/injection/stored.py": "the points of points.py and pages the crawler fetched",
    "checks/session/scanner.py": "the opt-in logout test requests a logout on purpose",
    "crawler/robots.py": "robots.txt at the origin",
    "crawler/sitemap.py": "the sitemaps robots.txt names, at the origin",
}

# A vocabulary of its own outside safety.py: the shape the removed per-pass filters had.
_OWN_VOCABULARY = re.compile(r"log\[\\s_-\]\?out|delete\|remove")


def _relative(path: Path) -> str:
    """
    Args:
        path (Path): A module under ``src/webvigil``.

    Returns:
        str: Its path relative to the package, with ``/``.
    """
    return path.relative_to(_SRC).as_posix()


def _modules() -> dict[str, str]:
    """
    Returns:
        dict[str, str]: The source of every module of the package, by relative path.
    """
    return {_relative(path): path.read_text(encoding="utf-8") for path in _SRC.rglob("*.py")}


def test_every_sending_module_is_gated_or_exempt() -> None:
    """A module that sends a request is in one table, and every table row still sends or builds."""
    sources = _modules()
    senders = {name for name, source in sources.items() if _SENDS.search(source)}
    assert "crawler/crawler.py" in senders  # control: the pattern sees a real sender
    assert senders - GATED.keys() - EXEMPT.keys() == set()
    assert EXEMPT.keys() <= senders
    assert not GATED.keys() & EXEMPT.keys()


def test_every_gated_module_calls_its_gates() -> None:
    """The gate is called, not only imported: ``name(`` appears in the module's own code."""
    sources = _modules()
    for module, gates in GATED.items():
        for gate in gates:
            assert re.search(rf"\b{gate}\(", sources[module]), (module, gate)


def test_no_module_but_safety_keeps_a_vocabulary_of_its_own() -> None:
    """The words live in one place, so every pass refuses the same actions."""
    sources = _modules()
    assert _OWN_VOCABULARY.search(sources["crawler/safety.py"])  # control: the shape is seen
    elsewhere = [
        m for m, s in sources.items() if m != "crawler/safety.py" and _OWN_VOCABULARY.search(s)
    ]
    assert elsewhere == []
