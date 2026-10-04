"""Summarise the Lighthouse CI reports as a Markdown table.

``lighthouse.yml`` runs ``lhci`` twice per profile (the public ``/login`` page, then the
signed-in pages) and each run writes a ``manifest.json`` plus its reports under
``.lighthouseci/<profile>-login/`` and ``.lighthouseci/<profile>/``. This script reads the
representative (median) report of each page and prints one table per profile, for the
workflow to append to the job summary (``$GITHUB_STEP_SUMMARY``). Standard library only,
so it runs without installing anything.

Usage (from the repository root)::

    python3 .github/lighthouse/summary.py mobile >> "$GITHUB_STEP_SUMMARY"

With no argument both profiles are summarised (handy locally).

CI numbers are a relative comparison between PRs; Lighthouse only gives real numbers in
production.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(".lighthouseci")
PROFILES = ("mobile", "desktop")

# Category columns, in order, with their labels.
CATEGORIES = [
    ("performance", "Perf."),
    ("accessibility", "A11y"),
    ("best-practices", "Best pr."),
]


def representative_reports(profile: str) -> list[dict]:
    """Load the median report of every page of a profile.

    Lighthouse CI flags the median run of each URL in ``manifest.json``
    (``isRepresentativeRun``). The public ``/login`` run comes first, then the signed-in
    pages, in the order of their configs.

    Args:
        profile (str): ``"mobile"`` or ``"desktop"``.

    Returns:
        list[dict]: Lighthouse reports (JSON). Empty when the profile produced none, for
            example because a step failed before the audit ran.
    """
    reports: list[dict] = []
    for folder in (f"{profile}-login", profile):
        manifest = ROOT / folder / "manifest.json"
        if not manifest.is_file():
            continue
        for entry in json.loads(manifest.read_text(encoding="utf-8")):
            if entry.get("isRepresentativeRun"):
                reports.append(json.loads(Path(entry["jsonPath"]).read_text(encoding="utf-8")))
    return reports


def page(report: dict) -> str:
    """Extract the URL path of a report (``/scans``, ``/scans/1``).

    Args:
        report (dict): One Lighthouse report.

    Returns:
        str: The path of the final URL (after redirects), without the host.
    """
    url = report["finalUrl"]
    return "/" + url.split("/", 3)[3] if url.count("/") > 2 else url


def table(profile: str, reports: list[dict]) -> str:
    """Build the Markdown table of one profile.

    Args:
        profile (str): Profile name, used in the heading.
        reports (list[dict]): The profile's representative reports.

    Returns:
        str: Heading and table: scores from 0 to 100, LCP, TBT, CLS and transferred KiB.
    """
    columns = [label for _, label in CATEGORIES] + ["LCP", "TBT", "CLS", "KiB"]
    lines = [
        f"### Lighthouse — {profile}",
        "",
        "| Page | " + " | ".join(columns) + " |",
        "|---|" + "---:|" * len(columns),
    ]
    for report in reports:
        scores = [round((report["categories"][c]["score"] or 0) * 100) for c, _ in CATEGORIES]
        audits = report["audits"]
        cells = [
            *scores,
            f"{audits['largest-contentful-paint']['numericValue'] / 1000:.1f} s",
            f"{audits['total-blocking-time']['numericValue']:.0f} ms",
            f"{audits['cumulative-layout-shift']['numericValue']:.3f}",
            f"{audits['total-byte-weight']['numericValue'] / 1024:.0f}",
        ]
        lines.append(f"| `{page(report)}` | " + " | ".join(map(str, cells)) + " |")
    return "\n".join(lines)


def main(arguments: list[str]) -> int:
    """Print the table of each requested profile that produced reports.

    Args:
        arguments (list[str]): Profiles to summarise (``mobile``, ``desktop``); empty
            summarises both.

    Returns:
        int: Always ``0``: a profile without reports is only mentioned in the text, so the
            summary still appears when an earlier step failed.
    """
    for profile in arguments or PROFILES:
        reports = representative_reports(profile)
        if reports:
            print(table(profile, reports), end="\n\n")
        else:
            print(f"### Lighthouse — {profile}\n\nNo reports (a step failed before the audit).\n")
    print(
        "_CI numbers are a relative comparison between PRs; real numbers only exist in production._"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
