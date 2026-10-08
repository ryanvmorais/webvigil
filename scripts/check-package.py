"""Check that the built sdist and wheel are what a release should ship.

``uv build`` succeeding says the package builds, not that it is the right package. This asserts
what the release plan promises (issue #111, batch 4): the sdist carries the source and not the
repository, the wheel carries the data files the engine reads at run time, and the README that
PyPI shows has no relative image or link (PyPI cannot resolve them).

Usage: ``uv build && uv run python scripts/check-package.py dist``
"""

from __future__ import annotations

import re
import sys
import tarfile
import zipfile
from email import message_from_string
from pathlib import Path

# Top-level names that live in the repository only. The dashboard, tests, specs and CI are not
# part of a published package; a local cache must never leak into one.
_REPOSITORY_ONLY = (
    "web",
    "tests",
    "specs",
    ".github",
    ".import_linter_cache",
    "docker",
    "assets",
    "Dockerfile",
    "docker-compose.yml",
    "uv.lock",
    "CLAUDE.md",
)

# Files the engine opens at run time; a wheel without them installs and then fails on first use.
_WHEEL_MUST_HAVE = (
    "webvigil/py.typed",
    "webvigil/reporting/templates/report.html.j2",
    "webvigil/checks/deps/data/retirejs.json",
)

_RELATIVE_LINK = re.compile(r"\]\((?!https?://|#|mailto:)[^)\s]+\)")


def _problems(dist: Path) -> list[str]:
    """
    Args:
        dist (Path): The directory ``uv build`` wrote to.

    Returns:
        list[str]: One line per thing wrong with the sdist, the wheel or the README; empty when
            the package is what a release should ship.
    """
    problems: list[str] = []
    sdists = sorted(dist.glob("*.tar.gz"))
    wheels = sorted(dist.glob("*.whl"))
    if len(sdists) != 1 or len(wheels) != 1:
        return [
            f"expected one sdist and one wheel in {dist}, found {len(sdists)} and {len(wheels)}"
        ]

    with tarfile.open(sdists[0]) as tar:
        top = {m.name.split("/")[1] for m in tar.getmembers() if m.name.count("/") >= 1}
    problems += [
        f"sdist ships repository-only content: {name}" for name in _REPOSITORY_ONLY if name in top
    ]

    with zipfile.ZipFile(wheels[0]) as wheel:
        names = set(wheel.namelist())
        metadata_name = next(n for n in names if n.endswith(".dist-info/METADATA"))
        metadata = message_from_string(wheel.read(metadata_name).decode("utf-8"))
    problems += [f"wheel is missing {name}" for name in _WHEEL_MUST_HAVE if name not in names]
    if not any(n.endswith("licenses/LICENSE") for n in names):
        problems.append("wheel does not carry the LICENSE")

    readme = metadata.get_payload() or ""
    problems += [
        f"README shown on PyPI has a relative link: {m}" for m in _RELATIVE_LINK.findall(readme)
    ]
    if "Development Status :: 5 - Production/Stable" not in metadata.get_all("Classifier", []):
        problems.append("the Development Status classifier is not Production/Stable")
    return problems


def main() -> int:
    """
    Returns:
        int: ``0`` when the package is right, ``1`` after printing what is wrong.
    """
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    problems = _problems(dist)
    for line in problems:
        print(f"error: {line}")
    if problems:
        return 1
    print(f"ok: {dist} holds a lean sdist, a complete wheel and a README PyPI can render")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
