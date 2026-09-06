"""Refresh the vendored Retire.js advisory database (spec 004, RF-21).

This is the ONLY place in the project that reaches the Retire.js servers. The engine, the
CLI, and the Web API read the vendored file from disk and never download anything.

Usage:

    python scripts/update-retirejs-db.py [--source URL] [--dry-run]

It downloads the upstream community database, normalises it to WebVigil's native shape
(``{"components": {name: {extractors, vulnerabilities}}}``), writes
``src/webvigil/checks/deps/data/retirejs.json``, and refreshes the sibling
``PROVENANCE.json`` with the retrieval date and source.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any

_DEFAULT_SOURCE = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master"
    "/repository/jsrepository-master.json"
)
_DATA_DIR = Path(__file__).resolve().parent.parent / "src" / "webvigil" / "checks" / "deps" / "data"
_DB_PATH = _DATA_DIR / "retirejs.json"
_PROVENANCE_PATH = _DATA_DIR / "PROVENANCE.json"

# Extractor kinds WebVigil applies. ``func`` needs a live browser; ``filecontentreplace``
# is a minification-normalisation optimisation we do not implement yet.
_KEPT_EXTRACTORS = ("filename", "filecontent", "uri")
# ``identifiers`` keys that carry a reference rather than a vulnerability id.
_INFO_KEYS = ("bug", "issue", "PR", "release", "blog", "gist")
_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _url_like(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def _fetch(source: str) -> tuple[bytes, str | None]:
    request = urllib.request.Request(source, headers={"User-Agent": "webvigil-db-refresh"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(), response.headers.get("ETag")


def _normalise_identifiers(identifiers: dict[str, Any]) -> tuple[list[str], list[str]]:
    ids: list[str] = []
    info: list[str] = []
    for cve in identifiers.get("CVE", []) or []:
        ids.append(str(cve))
    github_id = identifiers.get("githubID")
    if github_id:
        ids.append(str(github_id))
    retid = identifiers.get("retid")
    if not ids and retid:
        ids.append(f"RETID-{retid}")  # last resort so every advisory has an identifier
    for key in _INFO_KEYS:
        value = identifiers.get(key)
        values = value if isinstance(value, list) else [value]
        info.extend(str(item) for item in values if isinstance(item, str) and _url_like(item))
    return ids, info


def _normalise_cwe(raw: Any) -> list[int]:
    out: list[int] = []
    for entry in raw or []:
        match = _CWE_RE.search(str(entry))
        if match:
            out.append(int(match.group(1)))
    return out


def _normalise_vulnerability(vuln: dict[str, Any]) -> dict[str, Any]:
    ids, extra_info = _normalise_identifiers(vuln.get("identifiers", {}))
    base_info = [str(i) for i in (vuln.get("info") or []) if _url_like(str(i))]
    info = list(dict.fromkeys(base_info + extra_info))
    ranges = [
        {k: v for k, v in rng.items() if k in ("atOrAbove", "below")}
        for rng in vuln.get("ranges", [])
    ]
    return {
        "ranges": ranges,
        "severity": vuln.get("severity"),
        "identifiers": ids,
        "summary": vuln.get("identifiers", {}).get("summary") or vuln.get("summary") or "",
        "cwe": _normalise_cwe(vuln.get("cwe")),
        "info": info,
    }


def _normalise_component(component: dict[str, Any]) -> dict[str, Any]:
    extractors_in = component.get("extractors", {})
    extractors: dict[str, Any] = {}
    for kind in _KEPT_EXTRACTORS:
        patterns = extractors_in.get(kind)
        if patterns:
            extractors[kind] = list(patterns)
    hashes = extractors_in.get("hashes")
    if hashes:
        extractors["hashes"] = {str(k).lower(): str(v) for k, v in hashes.items()}
    return {
        "extractors": extractors,
        "vulnerabilities": [
            _normalise_vulnerability(v) for v in component.get("vulnerabilities", [])
        ],
    }


def _normalise(raw: dict[str, Any]) -> dict[str, Any]:
    components = {
        name: _normalise_component(component)
        for name, component in sorted(raw.items())
        if name != "retire-example"
    }
    return {
        "_note": (
            "Vendored Retire.js community database, normalised for WebVigil. "
            "Do not edit by hand — run scripts/update-retirejs-db.py. See PROVENANCE.json."
        ),
        "components": components,
    }


def _counts(db: dict[str, Any]) -> tuple[int, int]:
    components = db["components"]
    vulns = sum(len(c["vulnerabilities"]) for c in components.values())
    return len(components), vulns


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=_DEFAULT_SOURCE, help="upstream JSON URL")
    parser.add_argument("--dry-run", action="store_true", help="report changes, write nothing")
    args = parser.parse_args()

    payload, etag = _fetch(args.source)
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"error: upstream response is not valid JSON: {exc}", file=sys.stderr)
        return 1

    new_db = _normalise(raw)
    components, vulnerabilities = _counts(new_db)

    old_components = old_vulnerabilities = 0
    if _DB_PATH.is_file():
        old_components, old_vulnerabilities = _counts(json.loads(_DB_PATH.read_text("utf-8")))

    print(
        f"components: {components} ({components - old_components:+d})  "
        f"vulnerabilities: {vulnerabilities} ({vulnerabilities - old_vulnerabilities:+d})"
    )

    if args.dry_run:
        print("--dry-run: nothing written")
        return 0

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _DB_PATH.write_text(
        json.dumps(new_db, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    provenance = {
        "source_url": args.source,
        "upstream_etag": etag,
        "retrieved": date.today().isoformat(),
        "license": "Apache-2.0",
        "attribution": "Retire.js contributors — https://github.com/RetireJS/retire.js",
    }
    _PROVENANCE_PATH.write_text(
        json.dumps(provenance, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {_DB_PATH.relative_to(_DATA_DIR.parents[4])}")
    print(f"wrote {_PROVENANCE_PATH.relative_to(_DATA_DIR.parents[4])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
