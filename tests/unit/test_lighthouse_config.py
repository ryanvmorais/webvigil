"""Consistency of the Lighthouse CI configuration with the dashboard it audits.

The audit runs only on GitHub, so a stale URL would surface as a 404 report there and
nowhere else. These tests read the JSON configs in ``.github/lighthouse/`` and the route
tree under ``web/src/app/``: nothing is booted or mocked. Every audited path must map to a
real ``page.tsx``, the mobile and desktop configs must audit the same pages with the same
checks, and each config must write where ``summary.py`` looks for it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_DIR = _ROOT / ".github" / "lighthouse"
_APP_DIR = _ROOT / "web" / "src" / "app"

_STEMS = ["mobile", "mobile-login", "desktop", "desktop-login"]


def _load(stem: str) -> dict:
    """Load one Lighthouse CI config.

    Args:
        stem (str): File name without ``.json``, e.g. ``"mobile-login"``.

    Returns:
        dict: The parsed ``ci`` section.
    """
    return json.loads((_CONFIG_DIR / f"{stem}.json").read_text(encoding="utf-8"))["ci"]


def _routes() -> list[re.Pattern[str]]:
    """Build a matcher per ``page.tsx`` of the App Router.

    Route groups (``(app)``) do not appear in the URL and dynamic segments (``[id]``) match
    any single path segment.

    Returns:
        list[re.Pattern[str]]: One compiled pattern per page, anchored on the whole path.
    """
    patterns = []
    for page in _APP_DIR.rglob("page.tsx"):
        parts = [p for p in page.parent.relative_to(_APP_DIR).parts if not p.startswith("(")]
        regex = "/" + "/".join("[^/]+" if p.startswith("[") else re.escape(p) for p in parts)
        patterns.append(re.compile(f"^{regex}$"))
    return patterns


def _paths(config: dict) -> list[str]:
    """List the URL paths a config audits.

    Args:
        config (dict): A parsed ``ci`` section.

    Returns:
        list[str]: The path of each collected URL, in order.
    """
    return [urlparse(url).path for url in config["collect"]["url"]]


@pytest.mark.parametrize("stem", _STEMS)
def test_every_audited_path_is_a_real_page(stem: str) -> None:
    routes = _routes()
    missing = [p for p in _paths(_load(stem)) if not any(r.match(p) for r in routes)]
    assert missing == []


@pytest.mark.parametrize("stem", ["login", ""])
def test_profiles_audit_the_same_pages_with_the_same_checks(stem: str) -> None:
    """Mobile and desktop differ only by preset and the performance threshold."""
    suffix = f"-{stem}" if stem else ""
    mobile, desktop = _load(f"mobile{suffix}"), _load(f"desktop{suffix}")
    assert mobile["collect"]["url"] == desktop["collect"]["url"]
    assert mobile["assert"]["assertions"].keys() == desktop["assert"]["assertions"].keys()
    assert desktop["collect"]["settings"]["preset"] == "desktop"
    assert "preset" not in mobile["collect"]["settings"]


@pytest.mark.parametrize("stem", _STEMS)
def test_reports_land_where_the_summary_script_reads_them(stem: str) -> None:
    assert _load(stem)["upload"]["outputDir"] == f".lighthouseci/{stem}"


def test_login_is_audited_without_the_session_and_the_rest_with_it() -> None:
    """The signed-in run never audits /login (it would redirect) and the login run only does."""
    assert _paths(_load("mobile-login")) == ["/login"]
    assert "/login" not in _paths(_load("mobile"))


def test_signed_in_pages_must_have_no_console_errors() -> None:
    """The missing favicon was a console error on every page; keep that class of bug out."""
    assert "errors-in-console" in _load("mobile")["assert"]["assertions"]
    # /login logs the expected 401 of GET /api/auth/me, so it cannot assert this.
    assert "errors-in-console" not in _load("mobile-login")["assert"]["assertions"]
