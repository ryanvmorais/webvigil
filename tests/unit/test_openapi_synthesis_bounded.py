"""
The OpenAPI body synthesis is bounded in size, not only in depth and breadth.

The API description may be served by the scanned site, and the synthesizer builds a request body
for every operation. A schema that many properties reference grows with the product of them, so a
short document could produce bodies far larger than itself. Nothing is mocked: each test writes a
real document to a temp file and loads it through :func:`load_openapi` (a file source issues no
request), then reads the size of the bodies and the clock.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from webvigil.core.config import ScanConfig
from webvigil.core.target import Target
from webvigil.crawler.openapi import (
    _MAX_BODY_UNITS,
    _MAX_DOC_UNITS,
    ApiOperation,
    load_openapi,
)
from webvigil.http.client import HttpClient

_TARGET = Target.parse("https://api.example.com")
# Seconds a whole document may take to load. The bounded synthesis finishes in well under a second.
_BUDGET_S = 5.0
# Characters one body may take: its units plus the JSON punctuation around every key.
_BODY_CHARS = _MAX_BODY_UNITS * 8


def _fan_out_doc(*, operations: int, name_length: int = 8) -> dict[str, Any]:
    """
    Build a document in which each schema is referenced by 24 properties of the one above it.

    Args:
        operations (int): How many POST operations take the top schema as a JSON body.
        name_length (int): Characters in each property name. Defaults to 8.

    Returns:
        dict[str, Any]: The OpenAPI document.
    """
    names = [f"p{i:02d}".ljust(name_length, "x") for i in range(24)]
    schemas: dict[str, Any] = {}
    for depth in range(4):
        below = {"$ref": f"#/components/schemas/S{depth + 1}"}
        schemas[f"S{depth}"] = {"type": "object", "properties": dict.fromkeys(names, below)}
    schemas["S4"] = {"type": "object"}
    body = {
        "required": True,
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/S0"}}},
    }
    return {
        "openapi": "3.0.3",
        "info": {"title": "t", "version": "1"},
        "paths": {f"/op{n}": {"post": {"requestBody": body}} for n in range(operations)},
        "components": {"schemas": schemas},
    }


async def _load(doc: dict[str, Any], tmp_path: Path) -> list[ApiOperation]:
    """
    Args:
        doc (dict[str, Any]): The OpenAPI document.
        tmp_path (Path): The pytest temp directory.

    Returns:
        list[ApiOperation]: The operations loaded from ``doc``.
    """
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(doc), "utf-8")
    http = HttpClient(_TARGET, ScanConfig())  # never entered — a file source issues no request
    operations, _ = await load_openapi(str(path), http=http, target=_TARGET, max_operations=100_000)
    return operations


# ---------------------------------------------------------------------------
# Size: a short document does not produce large bodies
# ---------------------------------------------------------------------------


async def test_a_fan_out_schema_gives_a_body_of_bounded_size(tmp_path: Path) -> None:
    """One body stays under its allowance however many properties reference the same schema."""
    started = time.perf_counter()
    operations = await _load(_fan_out_doc(operations=1), tmp_path)
    assert time.perf_counter() - started < _BUDGET_S
    assert operations[0].body_json is not None
    assert len(operations[0].body_json) < _BODY_CHARS


async def test_long_property_names_do_not_grow_a_body_past_its_allowance(tmp_path: Path) -> None:
    """The characters of a key name are charged, so long names buy fewer keys."""
    operations = await _load(_fan_out_doc(operations=1, name_length=2_000), tmp_path)
    assert operations[0].body_json is not None
    assert len(operations[0].body_json) < _BODY_CHARS + _MAX_BODY_UNITS


async def test_many_operations_share_one_allowance(tmp_path: Path) -> None:
    """All the bodies of a document together stay under the document allowance."""
    started = time.perf_counter()
    operations = await _load(_fan_out_doc(operations=400), tmp_path)
    assert time.perf_counter() - started < _BUDGET_S
    total = sum(len(op.body_json or "") for op in operations)
    assert total < _MAX_DOC_UNITS * 8


# ---------------------------------------------------------------------------
# Behaviour: an ordinary schema is synthesized in full
# ---------------------------------------------------------------------------


async def test_a_small_schema_is_still_synthesized_whole(tmp_path: Path) -> None:
    """A body of a few fields, one of them nested, comes out as before."""
    doc = {
        "openapi": "3.0.3",
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "age": {"type": "integer"},
                                        "address": {
                                            "type": "object",
                                            "properties": {"city": {"type": "string"}},
                                        },
                                    },
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    operations = await _load(doc, tmp_path)
    assert json.loads(operations[0].body_json or "{}") == {
        "name": "wv",
        "age": 1,
        "address": {"city": "wv"},
    }
