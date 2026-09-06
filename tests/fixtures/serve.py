"""ASGI entry point for the deliberately-vulnerable target app (spec 006, RF-24).

Run standalone for manual Active-Mode scans and demos:

    docker compose --profile targets up target
    uv run webvigil scan http://localhost:8080 --mode active --authorized-by me
"""

from __future__ import annotations

from tests.fixtures.app import make_app

app = make_app("insecure")
