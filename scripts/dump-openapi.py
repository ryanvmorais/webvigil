"""Write the Web API's OpenAPI schema to ``web/openapi.json``.

The Web UI (spec 003) generates its TypeScript types from this file (``pnpm gen:api``);
CI regenerates it and fails on any diff. Building the FastAPI app object does not run the
lifespan, so no database, migration, or network access happens here.

Usage: ``uv run python scripts/dump-openapi.py``
"""

from __future__ import annotations

import json
from pathlib import Path

from webvigil.api.app import create_app
from webvigil.api.config import WebConfig

_OUTPUT = Path(__file__).resolve().parent.parent / "web" / "openapi.json"


def main() -> None:
    app = create_app(WebConfig(database_path=Path(":memory:")))
    schema = app.openapi()
    _OUTPUT.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {_OUTPUT.relative_to(Path.cwd())}")


if __name__ == "__main__":
    main()
