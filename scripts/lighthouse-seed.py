"""Seed a running Web API for the Lighthouse CI run and write the session header.

The dashboard sits behind a login and ``/scans/[id]`` needs a finished scan, so a bare URL
list cannot audit it. This script, run once against a *fresh* database, creates the
account, signs in, runs one passive scan of the fixture app (``scripts/serve-fixture-app.py``)
and waits for it to finish. It then writes the ``Cookie`` header Lighthouse sends with the
signed-in pages (``--collect.settings.extraHeaders``). The scan is the first row, so its id
is 1: ``.github/lighthouse/{mobile,desktop}.json`` hardcode ``/scans/1``, and the script
fails when it gets another id rather than let the audit measure a 404.

The credentials are throwaway: the database lives in the runner's temp directory.

Usage::

    python scripts/lighthouse-seed.py --api http://127.0.0.1:8100 \\
        --target http://127.0.0.1:9100/ --headers-out headers.json
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SESSION_COOKIE = "webvigil_session"

_CREDENTIALS = {"username": "lighthouse", "password": "Lighthouse-Demo-2026-Throwaway!"}

# A passive scan of the fixture finishes in a few seconds; 120 s is a hang, not slowness.
_SCAN_TIMEOUT_SECONDS = 120

_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "interrupted"}


def _call(
    opener: urllib.request.OpenerDirector, method: str, url: str, body: dict[str, Any] | None = None
) -> Any:
    """Send one JSON request through the cookie-aware opener.

    Args:
        opener (urllib.request.OpenerDirector): Opener that stores the session cookie.
        method (str): HTTP method.
        url (str): Absolute URL.
        body (dict[str, Any] | None): JSON body, or ``None`` for none.

    Returns:
        Any: The decoded JSON response, or ``None`` for an empty body.

    Raises:
        SystemExit: When the API answers with an error status.
    """
    request = urllib.request.Request(url, method=method)
    if body is not None:
        request.data = json.dumps(body).encode()
        request.add_header("Content-Type", "application/json")
    try:
        with opener.open(request, timeout=30) as response:
            return json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        raise SystemExit(
            f"{method} {url} -> {error.code}: {error.read().decode()[:300]}"
        ) from error


def seed(api: str, target: str, headers_out: Path) -> None:
    """Create the account, sign in, run one scan and write the Lighthouse header file.

    Args:
        api (str): Base URL of the running Web API, with no trailing slash.
        target (str): URL the passive scan audits (the fixture app).
        headers_out (Path): Where to write ``{"Cookie": "webvigil_session=..."}``.

    Raises:
        SystemExit: When the scan does not complete, finishes late, or is not scan 1.
    """
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    _call(opener, "POST", f"{api}/api/setup", _CREDENTIALS)
    _call(opener, "POST", f"{api}/api/auth/login", _CREDENTIALS)
    cookie = next((c for c in jar if c.name == SESSION_COOKIE), None)
    if cookie is None:
        raise SystemExit(f"login did not set the {SESSION_COOKIE} cookie")

    scan = _call(opener, "POST", f"{api}/api/scans", {"target": target})
    if scan["id"] != 1:
        raise SystemExit(f"expected scan id 1 on a fresh database, got {scan['id']}")

    deadline = time.monotonic() + _SCAN_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        scan = _call(opener, "GET", f"{api}/api/scans/{scan['id']}")
        if scan["status"] in _TERMINAL_STATUSES:
            break
        time.sleep(1)
    if scan["status"] != "completed":
        raise SystemExit(f"scan 1 ended as {scan['status']!r}, expected 'completed'")

    headers_out.write_text(
        json.dumps({"Cookie": f"{cookie.name}={cookie.value}"}), encoding="utf-8"
    )
    print(f"seeded: scan 1 completed, header written to {headers_out}")


def main() -> int:
    """Parse the command line and seed the API.

    Returns:
        int: ``0`` on success; failures exit through ``SystemExit`` with a message.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api", required=True, help="Web API base URL, e.g. http://127.0.0.1:8100")
    parser.add_argument("--target", required=True, help="URL of the scan target (fixture app)")
    parser.add_argument("--headers-out", required=True, type=Path, help="Header file to write")
    args = parser.parse_args()
    seed(args.api.rstrip("/"), args.target, args.headers_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
