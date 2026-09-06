"""Locate and load the vendored Retire.js data files from the installed package.

Uses :mod:`importlib.resources` so it works from a wheel, a zip, or an editable checkout —
never a path relative to this source file (RF-06, Risks).
"""

from __future__ import annotations

import json
from datetime import date
from functools import lru_cache
from importlib.resources import files
from typing import Any

from pydantic import BaseModel, ConfigDict

_PACKAGE = "webvigil.checks.deps.data"
_DB_NAME = "retirejs.json"
_PROVENANCE_NAME = "PROVENANCE.json"


class Provenance(BaseModel):
    """Where the vendored database came from and when (RF-06, RNF-06)."""

    model_config = ConfigDict(frozen=True)

    source_url: str
    retrieved: date
    license: str
    attribution: str
    upstream_etag: str | None = None


@lru_cache(maxsize=1)
def load_raw_db() -> dict[str, Any]:
    """The vendored, normalised Retire.js database as plain JSON (``{"components": {...}}``)."""
    text = files(_PACKAGE).joinpath(_DB_NAME).read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


@lru_cache(maxsize=1)
def load_provenance() -> Provenance:
    """Parsed ``PROVENANCE.json`` sitting next to the database."""
    text = files(_PACKAGE).joinpath(_PROVENANCE_NAME).read_text(encoding="utf-8")
    return Provenance.model_validate_json(text)
