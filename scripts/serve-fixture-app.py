"""Serve the spec-001 Starlette fixture app as a scan target for the Web UI e2e run.

The Playwright suite (``web/e2e``) points a passive scan at this server. It is the same
in-process fixture the engine's integration tests use, exposed over HTTP.

Usage: ``uv run python scripts/serve-fixture-app.py --port 9100``
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import uvicorn  # noqa: E402
from tests.fixtures.app import make_app  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument("--profile", default="insecure", choices=["insecure", "hardened"])
    args = parser.parse_args()
    uvicorn.run(make_app(args.profile), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
