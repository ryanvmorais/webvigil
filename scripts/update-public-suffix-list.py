"""
Refresh the vendored Public Suffix List (the ``--scope subdomains`` boundary).

This is the ONLY place in the project that reaches publicsuffix.org. The engine reads the
vendored file from disk and never downloads anything.

Usage:

    python scripts/update-public-suffix-list.py [--source URL] [--dry-run]

It downloads the list, checks that it has both the ICANN and the PRIVATE sections, writes it
unchanged (its MPL-2.0 header included) to ``src/webvigil/core/data/public_suffix_list.dat``,
and refreshes the sibling ``PROVENANCE.json`` with the retrieval date, the source and the
SHA-256 of the file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

# The list's canonical URL: publicsuffix.org asks to be pulled from there and nowhere else.
_DEFAULT_SOURCE = "https://publicsuffix.org/list/public_suffix_list.dat"
# Where the engine reads the copy (``webvigil.core.suffixes``) and its provenance.
_DATA_DIR = Path(__file__).resolve().parent.parent / "src" / "webvigil" / "core" / "data"
_LIST_PATH = _DATA_DIR / "public_suffix_list.dat"
_PROVENANCE_PATH = _DATA_DIR / "PROVENANCE.json"

# Both sections must be there: the PRIVATE one is what keeps ``a.github.io`` and
# ``b.github.io`` apart, and a truncated download would silently widen the scope again.
_REQUIRED_MARKERS = (
    "// ===BEGIN ICANN DOMAINS===",
    "// ===END ICANN DOMAINS===",
    "// ===BEGIN PRIVATE DOMAINS===",
    "// ===END PRIVATE DOMAINS===",
    "Mozilla Public",
)


# ---------------------------------------------------------------------------
# Download and checks
# ---------------------------------------------------------------------------


def _fetch(source: str) -> tuple[bytes, str | None]:
    """
    Args:
        source (str): The URL of the list.

    Returns:
        tuple[bytes, str | None]: The body and the ``ETag`` the server sent, if any.
    """
    request = urllib.request.Request(source, headers={"User-Agent": "webvigil-psl-refresh"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(), response.headers.get("ETag")


def _rule_count(text: str) -> int:
    """
    Args:
        text (str): The list's text.

    Returns:
        int: How many rules it holds (non-empty, non-comment lines).
    """
    return sum(1 for line in text.splitlines() if line.strip() and not line.startswith("//"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """
    Returns:
        int: The exit code: ``0`` on success, ``1`` when the download is not a full list.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=_DEFAULT_SOURCE, help="upstream list URL")
    parser.add_argument("--dry-run", action="store_true", help="report changes, write nothing")
    args = parser.parse_args()

    payload, etag = _fetch(args.source)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        print(f"error: the list is not UTF-8: {exc}", file=sys.stderr)
        return 1
    missing = [marker for marker in _REQUIRED_MARKERS if marker not in text]
    if missing:
        print(f"error: the download is not a full list (missing {missing})", file=sys.stderr)
        return 1

    rules = _rule_count(text)
    old_rules = _rule_count(_LIST_PATH.read_text("utf-8")) if _LIST_PATH.is_file() else 0
    print(f"rules: {rules} ({rules - old_rules:+d})")
    if args.dry_run:
        print("--dry-run: nothing written")
        return 0

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    data = text.replace("\r\n", "\n").encode("utf-8")
    _LIST_PATH.write_bytes(data)
    provenance = {
        "source_url": args.source,
        "upstream_etag": etag,
        "retrieved": date.today().isoformat(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "license": "MPL-2.0",
        "attribution": "Public Suffix List contributors — https://publicsuffix.org/",
    }
    _PROVENANCE_PATH.write_bytes(
        (json.dumps(provenance, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    )
    root = _DATA_DIR.parents[3]
    print(f"wrote {_LIST_PATH.relative_to(root)}")
    print(f"wrote {_PROVENANCE_PATH.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
