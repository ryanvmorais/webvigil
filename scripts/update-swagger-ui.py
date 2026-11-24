"""
Move the Swagger UI pin of the Web API's ``/docs`` page to another release.

This is the ONLY place in the project that reaches the npm registry and jsDelivr for the
Swagger UI. The API serves a page that names the pinned files; the browser fetches them and
checks each one against the hash in the page.

Usage:

    python scripts/update-swagger-ui.py [--version X.Y.Z] [--min-age-days N] [--dry-run]

Without ``--version`` it takes the newest stable ``swagger-ui-dist`` release of the pinned
major that is at least ``--min-age-days`` old (7, the project's dependency cooldown); a new
major is a deliberate ``--version``, after checking that FastAPI's page still works with it. The
script downloads the package from the npm registry, checks the tarball against the registry's
SHA-512, hashes ``swagger-ui-bundle.js`` and ``swagger-ui.css``, checks that jsDelivr serves the
same bytes and rewrites the three constants in ``src/webvigil/api/docs_ui.py``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_PACKAGE = "swagger-ui-dist"
_REGISTRY = f"https://registry.npmjs.org/{_PACKAGE}"
_CDN = f"https://cdn.jsdelivr.net/npm/{_PACKAGE}@{{version}}/{{name}}"
_MODULE = Path(__file__).resolve().parent.parent / "src" / "webvigil" / "api" / "docs_ui.py"
# Each file the page loads, and the constant that holds its hash.
_FILES = {
    "swagger-ui-bundle.js": "SWAGGER_UI_JS_INTEGRITY",
    "swagger-ui.css": "SWAGGER_UI_CSS_INTEGRITY",
}
_STABLE = re.compile(r"\d+\.\d+\.\d+")
_USER_AGENT = "webvigil-swagger-ui-refresh"


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        body: bytes = response.read()
        return body


def _sri(data: bytes) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode()


def _current(source: str, name: str) -> str:
    match = re.search(rf'^{name} = "([^"]+)"$', source, re.MULTILINE)
    if match is None:
        sys.exit(f"{name} not found in {_MODULE}")
    return match.group(1)


def _pick_version(meta: dict[str, Any], major: str, min_age: timedelta) -> str:
    """Return the newest stable release of ``major`` published at least ``min_age`` ago."""
    cutoff = datetime.now(UTC) - min_age
    candidates = [
        version
        for version in meta["versions"]
        if _STABLE.fullmatch(version)
        and version.split(".")[0] == major
        and datetime.fromisoformat(meta["time"][version]) <= cutoff
    ]
    if not candidates:
        sys.exit(f"no stable {_PACKAGE} {major}.x release older than {min_age.days} days")
    newest: str = max(candidates, key=lambda v: tuple(int(part) for part in v.split(".")))
    return newest


def _package_files(meta: dict[str, Any], version: str) -> dict[str, bytes]:
    """Download the release tarball, check its SHA-512, and read the pinned files from it."""
    dist = meta["versions"][version]["dist"]
    tarball = _get(dist["tarball"])
    expected = dist["integrity"]
    actual = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
    if actual != expected:
        sys.exit(f"the {version} tarball does not match the registry's integrity")
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        for name in _FILES:
            member = archive.extractfile(f"package/{name}")
            if member is None:
                sys.exit(f"{name} is missing from the {version} package")
            files[name] = member.read()
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--version", help="the exact release to pin (default: newest, see above)")
    parser.add_argument("--min-age-days", type=int, default=7, help="cooldown (default: 7)")
    parser.add_argument("--dry-run", action="store_true", help="print, do not write")
    args = parser.parse_args()

    source = _MODULE.read_text(encoding="utf-8")
    pinned = _current(source, "SWAGGER_UI_VERSION")
    meta = json.loads(_get(_REGISTRY))
    if args.version:
        if args.version not in meta["versions"] or not _STABLE.fullmatch(args.version):
            sys.exit(f"{args.version} is not a stable {_PACKAGE} release")
        version = args.version
    else:
        version = _pick_version(meta, pinned.split(".")[0], timedelta(days=args.min_age_days))

    # 1. The package is the reference; 2. the CDN must serve exactly its bytes.
    files = _package_files(meta, version)
    hashes: dict[str, str] = {}
    for name, constant in _FILES.items():
        digest = _sri(files[name])
        if _sri(_get(_CDN.format(version=version, name=name))) != digest:
            sys.exit(f"jsDelivr serves a different {name} for {version} than the npm package")
        hashes[constant] = digest

    updated = re.sub(
        r'^SWAGGER_UI_VERSION = "[^"]+"$',
        f'SWAGGER_UI_VERSION = "{version}"',
        source,
        flags=re.MULTILINE,
    )
    for constant, digest in hashes.items():
        updated = re.sub(
            rf'^{constant} = "[^"]+"$', f'{constant} = "{digest}"', updated, flags=re.MULTILINE
        )
    print(f"{_PACKAGE}: {pinned} -> {version}")
    for constant, digest in hashes.items():
        print(f"  {constant} = {digest}")
    if args.dry_run:
        print("dry run: nothing written")
    elif updated != source:
        _MODULE.write_text(updated, encoding="utf-8", newline="\n")
        print(f"wrote {_MODULE}")
    else:
        print("already pinned there")
    return 0


if __name__ == "__main__":
    sys.exit(main())
