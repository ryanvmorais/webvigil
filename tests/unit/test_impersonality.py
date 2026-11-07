"""What is versioned is written for whoever cloned the repository.

No tracked file names the maintainer, except the authorship and license metadata, and the
Claude Code guidance (``CLAUDE.md``, ``.claude/``) and the specs do not depend on commands
(skills) that exist only on the maintainer's machine. Steps only the maintainer runs
(accounts, tokens, announcements) live outside the repository; the role ("the maintainer")
takes the place of the name. The tests read ``git ls-files``, so they skip outside a clone
(a source tarball, for example).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]

# Authorship and license are metadata, so the name stays. This file names it in the rule below.
_MAY_NAME_THE_MAINTAINER = {
    "LICENSE",
    "NOTICE",
    "pyproject.toml",
    "tests/unit/test_impersonality.py",
}

_NAME = re.compile(r"\bRyan\b")

# Commands of personal skills: whoever clones the repository does not have them. The lookbehind
# keeps a path such as ``docs/stack.md`` or ``/specs/`` from matching.
_PERSONAL_COMMAND = re.compile(
    r"(?<![\w/.-])/(spec|idioma|estilo-arquivos|fechar-sessao|atualizar-docs"
    r"|atualizar-dependencias|revisar-dependabot|nova-interface|stack|novo-projeto"
    r"|preparar-release|atualizar-ferramentas|qualidade-python|limpar-branches"
    r"|enxugar-memoria|auditoria-[a-z]+)"
    r"(?![\w-])"
)


# ---------------------------------------------------------------------------
# Support
# ---------------------------------------------------------------------------


def _tracked_files() -> list[str]:
    """List the files git tracks.

    Returns:
        list[str]: Paths relative to the repository root. Empty when there is no git
        repository to ask.
    """
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=_ROOT,
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    return [name for name in out.decode("utf-8").split("\0") if name]


_TRACKED = _tracked_files()
pytestmark = pytest.mark.skipif(not _TRACKED, reason="not inside a git clone")


def _matches(paths: list[str], pattern: re.Pattern[str]) -> list[str]:
    """Find the lines of the given files that match a pattern.

    A file that is not UTF-8 text (an image, a font) has nothing to check and is skipped.

    Args:
        paths (list[str]): Paths relative to the repository root.
        pattern (re.Pattern[str]): What to look for on each line.

    Returns:
        list[str]: One ``path:line (match)`` entry per matching line.
    """
    found = []
    for path in paths:
        try:
            text = (_ROOT / path).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            match = pattern.search(line)
            if match:
                found.append(f"{path}:{number} ({match.group(0)})")
    return found


# ---------------------------------------------------------------------------
# The maintainer's name
# ---------------------------------------------------------------------------


def test_the_maintainers_name_only_appears_in_authorship_and_license_files() -> None:
    """Cite the role ("the maintainer") instead of the name, or keep the passage out of the repo."""
    paths = [p for p in _TRACKED if p not in _MAY_NAME_THE_MAINTAINER]

    assert _matches(paths, _NAME) == []


# ---------------------------------------------------------------------------
# Guidance for Claude Code and the specs
# ---------------------------------------------------------------------------


def test_claude_guidance_and_specs_do_not_cite_personal_skills() -> None:
    """Describe the rule in the file itself: a contributor's checkout has no such command."""
    paths = [p for p in _TRACKED if p == "CLAUDE.md" or p.startswith((".claude/", "specs/"))]
    assert "CLAUDE.md" in paths

    assert _matches(paths, _PERSONAL_COMMAND) == []


def test_the_skill_pattern_matches_a_command_and_not_a_path() -> None:
    """Guard the guard: a command is caught, a path with the same word is not."""
    assert _PERSONAL_COMMAND.search("driven by the `/spec` skill")
    assert _PERSONAL_COMMAND.search("Ready for `/spec design`")
    assert not _PERSONAL_COMMAND.search("specs/001-foundation and docs/stack.md")
    assert not _PERSONAL_COMMAND.search("see /specs/README.md")
    assert not _PERSONAL_COMMAND.search("https://example.com/spec")
