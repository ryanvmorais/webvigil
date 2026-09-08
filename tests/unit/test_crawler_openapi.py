"""
OpenAPI / Swagger import — spec 013 RF-05, RF-06, RF-07, RF-08, RF-10.

Every parsing case runs against a JSON document written under ``tmp_path`` and
loaded through :func:`load_openapi` with a never-entered :class:`HttpClient`
(a file ``source`` issues no request). The two URL cases use ``pytest-httpx``
to serve the document from the in-scope target host. ``_load`` is the shared
helper; the target is always ``https://api.example.com``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from webvigil.core.config import ScanConfig
from webvigil.core.errors import OpenApiError
from webvigil.core.target import Target
from webvigil.crawler.openapi import ApiOperation, load_openapi
from webvigil.http.client import HttpClient

_TARGET = Target.parse("https://api.example.com")


async def _load(
    doc: dict[str, Any], tmp_path: Path, *, max_operations: int = 150
) -> tuple[list[ApiOperation], list[str]]:
    """
    Write ``doc`` to a temp file and load it.

    Args:
        doc (dict[str, Any]): The OpenAPI / Swagger document.
        tmp_path (Path): The pytest temp directory.
        max_operations (int): The operation cap. Defaults to 150.

    Returns:
        tuple[list[ApiOperation], list[str]]: The operations and warnings.
    """
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(doc), "utf-8")
    http = HttpClient(_TARGET, ScanConfig())  # never entered — a file source issues no request
    return await load_openapi(str(path), http=http, target=_TARGET, max_operations=max_operations)


def _op3(**paths: Any) -> dict[str, Any]:
    """
    Args:
        **paths (Any): ``path -> path-item`` entries.

    Returns:
        dict[str, Any]: A minimal OpenAPI 3.1 document with those paths.
    """
    return {"openapi": "3.1.0", "paths": paths}


# ---------------------------------------------------------------------------
# Base-URL reconciliation (RF-06)
# ---------------------------------------------------------------------------


async def test_openapi_3_server_path_is_kept_and_host_reconciled(tmp_path: Path) -> None:
    """An absolute ``servers[0].url`` keeps its path but resolves against the target origin."""
    doc = {
        "openapi": "3.0.3",
        "servers": [{"url": "https://api.example.com/v1"}],
        "paths": {"/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}}},
    }
    ops, warnings = await _load(doc, tmp_path)
    assert [o.url for o in ops] == ["https://api.example.com/v1/search"]
    assert warnings == []


async def test_relative_server_url_joins_the_target_origin(tmp_path: Path) -> None:
    """A relative ``servers[0].url`` is joined to the target origin."""
    doc = _op3(**{"/ping": {"get": {}}})
    doc["servers"] = [{"url": "/api"}]
    ops, _ = await _load(doc, tmp_path)
    assert ops[0].url == "https://api.example.com/api/ping"


async def test_foreign_server_host_warns_and_uses_the_target_origin(tmp_path: Path) -> None:
    """A ``servers`` host other than the target's is overridden, with a warning."""
    doc = _op3(**{"/x": {"get": {}}})
    doc["servers"] = [{"url": "https://elsewhere.test/api"}]
    ops, warnings = await _load(doc, tmp_path)
    assert ops[0].url == "https://api.example.com/api/x"
    assert any("elsewhere.test" in w for w in warnings)


async def test_swagger_2_builds_the_base_from_schemes_host_basepath(tmp_path: Path) -> None:
    """Swagger 2.0 uses ``schemes`` + ``host`` + ``basePath`` for the base URL."""
    doc = {
        "swagger": "2.0",
        "schemes": ["https"],
        "host": "api.example.com",
        "basePath": "/v2",
        "paths": {"/items": {"get": {"parameters": [{"name": "page", "in": "query"}]}}},
    }
    ops, warnings = await _load(doc, tmp_path)
    assert ops[0].url == "https://api.example.com/v2/items"
    assert warnings == []


# ---------------------------------------------------------------------------
# $ref resolution (RF-07, ADR-3)
# ---------------------------------------------------------------------------


async def test_local_ref_in_a_parameter_is_resolved(tmp_path: Path) -> None:
    """A ``#/components/parameters`` ``$ref`` on a parameter is dereferenced."""
    doc = {
        "openapi": "3.1.0",
        "components": {
            "parameters": {"Page": {"name": "page", "in": "query", "schema": {"type": "integer"}}}
        },
        "paths": {"/list": {"get": {"parameters": [{"$ref": "#/components/parameters/Page"}]}}},
    }
    ops, _ = await _load(doc, tmp_path)
    assert ops[0].query == (("page", "1"),)


async def test_a_ref_cycle_does_not_hang(tmp_path: Path) -> None:
    """A schema that ``$ref``\\s itself is broken with a placeholder, not an infinite loop."""
    doc = {
        "openapi": "3.1.0",
        "components": {
            "schemas": {
                "Node": {
                    "type": "object",
                    "properties": {
                        "next": {"$ref": "#/components/schemas/Node"},
                        "label": {"type": "string"},
                    },
                }
            }
        },
        "paths": {
            "/tree": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Node"}}
                        }
                    }
                }
            }
        },
    }
    ops, _ = await _load(doc, tmp_path)
    assert ops[0].body_json is not None
    assert json.loads(ops[0].body_json)["label"] == "wv"


async def test_external_ref_is_skipped_with_one_warning(tmp_path: Path) -> None:
    """A ``$ref`` to another file is skipped and warned about exactly once."""
    doc = _op3(
        **{
            "/a": {"get": {"parameters": [{"$ref": "shared.json#/q"}]}},
            "/b": {"get": {"parameters": [{"$ref": "shared.json#/r"}]}},
        }
    )
    ops, warnings = await _load(doc, tmp_path)
    assert all(o.query == () for o in ops)
    assert sum("external $ref" in w for w in warnings) == 1


# ---------------------------------------------------------------------------
# Errors (RF-05, ADR-4)
# ---------------------------------------------------------------------------


async def test_missing_file_is_an_error() -> None:
    """A non-existent ``--openapi`` path raises ``OpenApiError``."""
    http = HttpClient(_TARGET, ScanConfig())
    with pytest.raises(OpenApiError):
        await load_openapi("nope.json", http=http, target=_TARGET, max_operations=150)


async def test_invalid_json_is_an_error(tmp_path: Path) -> None:
    """A file that is not valid JSON raises ``OpenApiError``."""
    path = tmp_path / "openapi.json"
    path.write_text("{not json", "utf-8")
    http = HttpClient(_TARGET, ScanConfig())
    with pytest.raises(OpenApiError):
        await load_openapi(str(path), http=http, target=_TARGET, max_operations=150)


async def test_json_that_is_not_an_openapi_document_is_an_error(tmp_path: Path) -> None:
    """Valid JSON with no ``openapi`` / ``swagger`` key raises ``OpenApiError``."""
    with pytest.raises(OpenApiError):
        await _load({"paths": {"/x": {"get": {}}}}, tmp_path)


# ---------------------------------------------------------------------------
# Operation filtering and the cap (RF-09, RF-10)
# ---------------------------------------------------------------------------


async def test_login_and_destructive_operations_are_not_seeded(tmp_path: Path) -> None:
    """A login path, a delete path, and a ``deleteUser`` operationId are excluded."""
    doc = _op3(
        **{
            "/login": {"get": {}},
            "/account/delete": {"post": {}},
            "/users": {"post": {"operationId": "deleteUser"}},
            "/search": {"get": {}},
        }
    )
    ops, _ = await _load(doc, tmp_path)
    assert [o.url_template for o in ops] == ["https://api.example.com/search"]


async def test_put_and_delete_methods_are_not_acted_on(tmp_path: Path) -> None:
    """Only GET and POST operations are extracted."""
    doc = _op3(**{"/thing": {"get": {}, "put": {}, "patch": {}}})
    ops, _ = await _load(doc, tmp_path)
    assert [o.method for o in ops] == ["GET"]


async def test_max_operations_cap_warns_and_truncates(tmp_path: Path) -> None:
    """More acted-on operations than the cap → the first N and a warning."""
    doc = _op3(**{f"/p{n}": {"get": {}} for n in range(5)})
    ops, warnings = await _load(doc, tmp_path, max_operations=2)
    assert len(ops) == 2
    assert any("first 2 of 5" in w for w in warnings)


async def test_empty_document_warns(tmp_path: Path) -> None:
    """A document with no GET/POST operations yields a warning and no operations."""
    ops, warnings = await _load(_op3(**{"/x": {"delete": {}}}), tmp_path)
    assert ops == []
    assert any("no usable GET or POST" in w for w in warnings)


# ---------------------------------------------------------------------------
# Value synthesis and bodies (RF-07, RF-08)
# ---------------------------------------------------------------------------


async def test_value_synthesis_precedence(tmp_path: Path) -> None:
    """``example`` beats ``enum`` beats a type placeholder."""
    doc = _op3(
        **{
            "/q": {
                "get": {
                    "parameters": [
                        {"name": "a", "in": "query", "example": "ex"},
                        {"name": "b", "in": "query", "schema": {"enum": ["first", "second"]}},
                        {"name": "c", "in": "query", "schema": {"type": "boolean"}},
                    ]
                }
            }
        }
    )
    ops, _ = await _load(doc, tmp_path)
    assert ops[0].query == (("a", "ex"), ("b", "first"), ("c", "true"))


async def test_json_body_is_synthesized_and_form_body_becomes_fields(tmp_path: Path) -> None:
    """A JSON requestBody → ``body_json``; a form requestBody → ``body_fields``."""
    doc = _op3(
        **{
            "/json": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "qty": {"type": "integer"},
                                    },
                                }
                            }
                        }
                    }
                }
            },
            "/form": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"title": {"type": "string"}},
                                }
                            }
                        }
                    }
                }
            },
        }
    )
    ops = {o.url_template: o for o in (await _load(doc, tmp_path))[0]}
    assert json.loads(ops["https://api.example.com/json"].body_json or "") == {
        "name": "wv",
        "qty": 1,
    }
    assert ops["https://api.example.com/form"].body_fields == (("title", "wv"),)
    assert ops["https://api.example.com/form"].body_json is None


async def test_path_param_fills_the_url_and_keeps_the_template(tmp_path: Path) -> None:
    """A path parameter fills ``url`` but leaves ``url_template`` with the ``{name}``."""
    doc = _op3(
        **{"/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "example": "42"}]}}}
    )
    ops, _ = await _load(doc, tmp_path)
    assert ops[0].url == "https://api.example.com/users/42"
    assert ops[0].url_template == "https://api.example.com/users/{id}"
    assert ops[0].path_params == (("id", "42"),)


# ---------------------------------------------------------------------------
# URL source (RF-05, RNF-03)
# ---------------------------------------------------------------------------


async def test_an_out_of_scope_url_source_is_an_error() -> None:
    """A ``--openapi`` URL outside the target scope is refused before any request."""
    http = HttpClient(_TARGET, ScanConfig())
    with pytest.raises(OpenApiError):
        await load_openapi(
            "https://evil.test/openapi.json", http=http, target=_TARGET, max_operations=150
        )


async def test_an_in_scope_url_source_is_fetched_and_parsed(httpx_mock: object) -> None:
    """An in-scope ``--openapi`` URL is fetched through the client and parsed."""
    doc = _op3(**{"/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}}})
    httpx_mock.add_response(  # type: ignore[attr-defined]
        url="https://api.example.com/openapi.json", json=doc
    )
    async with HttpClient(_TARGET, ScanConfig()) as http:
        ops, _ = await load_openapi(
            "https://api.example.com/openapi.json", http=http, target=_TARGET, max_operations=150
        )
    assert ops[0].query == (("q", "wv"),)
