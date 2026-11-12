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

import pytest

from webvigil.core.config import ScanConfig
from webvigil.core.errors import OpenApiError
from webvigil.core.target import Target
from webvigil.crawler import openapi
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


# ---------------------------------------------------------------------------
# Expansion: parameters, values, URLs and $ref chains are bounded (security audit 2026-11)
# ---------------------------------------------------------------------------


async def _load_with_warnings(
    doc: dict[str, Any], tmp_path: Path, *, max_operations: int = 150
) -> tuple[list[ApiOperation], list[str]]:
    """
    Args:
        doc (dict[str, Any]): The OpenAPI document.
        tmp_path (Path): The pytest temp directory.
        max_operations (int): The operation cap. Defaults to 150, the configured default.

    Returns:
        tuple[list[ApiOperation], list[str]]: The operations and the warnings.
    """
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(doc), "utf-8")
    http = HttpClient(_TARGET, ScanConfig())
    return await load_openapi(str(path), http=http, target=_TARGET, max_operations=max_operations)


async def test_shared_parameters_are_expanded_only_for_the_kept_operations(tmp_path: Path) -> None:
    """A path item shared by many paths, with a long parameter list, stays cheap to import."""
    shared = [{"$ref": "#/components/parameters/q"}] * 5_000
    doc = {
        "openapi": "3.0.3",
        "paths": {f"/p{n}": {"$ref": "#/components/pathItems/item"} for n in range(2_000)},
        "components": {
            "parameters": {"q": {"name": "q", "in": "query", "schema": {"type": "string"}}},
            "pathItems": {"item": {"parameters": shared, "get": {}}},
        },
    }
    started = time.perf_counter()
    operations, warnings = await _load_with_warnings(doc, tmp_path)
    assert time.perf_counter() - started < _BUDGET_S
    assert len(operations) == 150
    assert all(len(op.query) <= 100 for op in operations)
    assert any("parameters of an operation" in line for line in warnings)


async def test_the_kept_operations_are_the_same_as_before(tmp_path: Path) -> None:
    """Choosing before building keeps the sorted first N operations."""
    doc = {
        "openapi": "3.0.3",
        "paths": {f"/p{n:03d}": {"get": {}, "post": {}} for n in range(10)},
    }
    operations, _ = await _load_with_warnings(doc, tmp_path, max_operations=3)
    assert [(op.url_template.rsplit("/", 1)[1], op.method) for op in operations] == [
        ("p000", "GET"),
        ("p000", "POST"),
        ("p001", "GET"),
    ]


async def test_an_operation_whose_url_would_be_huge_is_skipped(tmp_path: Path) -> None:
    """A path that repeats a long value thousands of times is left out, with a warning."""
    param = {"name": "id", "in": "path", "example": "v" * 200}
    doc = {
        "openapi": "3.0.3",
        "paths": {
            "/x" + "/{id}" * 3_000: {"get": {"parameters": [param]}},
            "/ok/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "example": "7"}]}},
        },
    }
    operations, warnings = await _load_with_warnings(doc, tmp_path)
    assert [op.url for op in operations] == ["https://api.example.com/ok/7"]
    assert any("would exceed" in line for line in warnings)


async def test_a_long_or_structured_example_becomes_the_placeholder(tmp_path: Path) -> None:
    """Values past 256 characters, or containers, are not copied into URLs and bodies."""
    body_schema = {
        "type": "object",
        "properties": {
            "long": {"type": "string", "example": "z" * 10_000},
            "nested": {"example": {"a": list(range(1_000))}},
            "short": {"type": "string", "example": "fine"},
        },
    }
    json_body = {"content": {"application/json": {"schema": body_schema}}}
    doc = {
        "openapi": "3.0.3",
        "paths": {
            "/q": {"get": {"parameters": [{"name": "s", "in": "query", "example": "y" * 300}]}},
            "/b": {"post": {"requestBody": json_body}},
        },
    }
    operations, _ = await _load_with_warnings(doc, tmp_path)
    by_path = {op.url_template.rsplit("/", 1)[1]: op for op in operations}
    assert by_path["q"].query == (("s", "wv"),)
    body = json.loads(by_path["b"].body_json or "{}")
    assert body == {"long": "wv", "nested": "wv", "short": "fine"}


async def test_a_long_ref_chain_resolves_to_nothing_quickly(tmp_path: Path) -> None:
    """A chain of thousands of ``$ref`` hops stops at the hop limit."""
    schemas: dict[str, Any] = {
        f"s{i}": {"$ref": f"#/components/schemas/s{i + 1}"} for i in range(20_000)
    }
    schemas["s20000"] = {"type": "object", "properties": {"deep": {"type": "string"}}}
    json_body = {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/s0"}}}}
    doc = {
        "openapi": "3.0.3",
        "paths": {f"/r{n}": {"post": {"requestBody": json_body}} for n in range(100)},
        "components": {"schemas": schemas},
    }
    started = time.perf_counter()
    operations, _ = await _load_with_warnings(doc, tmp_path)
    assert time.perf_counter() - started < _BUDGET_S
    assert len(operations) == 100


async def test_a_deeply_nested_document_is_an_import_error(tmp_path: Path) -> None:
    """JSON nested past the parser recursion limit is reported, not raised as a crash."""
    path = tmp_path / "deep.json"
    path.write_text('{"openapi": "3.0.3", "x": ' + "[" * 100_000 + "]" * 100_000 + "}", "utf-8")
    http = HttpClient(_TARGET, ScanConfig())
    with pytest.raises(OpenApiError):
        await load_openapi(str(path), http=http, target=_TARGET, max_operations=150)


@pytest.mark.parametrize("levels", [257, 900])
async def test_nesting_past_the_explicit_limit_is_an_import_error(
    tmp_path: Path, levels: int
) -> None:
    """The limit holds below any parser recursion limit, so every Python and platform agrees."""
    path = tmp_path / "deep.json"
    path.write_text('{"openapi": "3.0.3", "x": ' + "[" * levels + "]" * levels + "}", "utf-8")
    http = HttpClient(_TARGET, ScanConfig())
    with pytest.raises(OpenApiError, match="nested too deeply"):
        await load_openapi(str(path), http=http, target=_TARGET, max_operations=150)


async def test_nesting_up_to_the_limit_is_read(tmp_path: Path) -> None:
    """A document whose deepest value sits exactly at the limit still imports."""
    inner = 256 - 2  # the document object and the "x" array are two of the levels
    path = tmp_path / "deep.json"
    path.write_text(
        '{"openapi": "3.0.3", "paths": {}, "x": [' + "[" * inner + "]" * inner + "]}", "utf-8"
    )
    http = HttpClient(_TARGET, ScanConfig())
    await load_openapi(str(path), http=http, target=_TARGET, max_operations=150)


async def test_a_property_schema_that_is_not_an_object_is_tolerated(tmp_path: Path) -> None:
    """A form field whose schema is a bare string gets the placeholder instead of a crash."""
    form = {"type": "object", "properties": {"a": "not a schema", "b": {"example": "ok"}}}
    form_body = {"content": {"application/x-www-form-urlencoded": {"schema": form}}}
    doc = {"openapi": "3.0.3", "paths": {"/f": {"post": {"requestBody": form_body}}}}
    operations, _ = await _load_with_warnings(doc, tmp_path)
    assert operations[0].body_fields == (("a", "wv"), ("b", "ok"))


async def test_a_local_file_over_the_size_limit_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A local document is read only up to the HAR import size (lowered here for speed)."""
    monkeypatch.setattr(openapi, "MAX_DOCUMENT_BYTES", 1_000)
    path = tmp_path / "big.json"
    path.write_text(json.dumps({"openapi": "3.0.3", "pad": "x" * 2_000}), "utf-8")
    http = HttpClient(_TARGET, ScanConfig())
    with pytest.raises(OpenApiError, match="larger than"):
        await load_openapi(str(path), http=http, target=_TARGET, max_operations=150)
