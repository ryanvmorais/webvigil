"""
OpenAPI / Swagger import: turn an API description into seed operations (spec 013).

A JSON OpenAPI 3.0 / 3.1 or Swagger 2.0 document is parsed into
:class:`ApiOperation` records — one per acted-on ``(path, method)``. The
orchestrator uses them as a *seed source*: GET operation URLs feed the crawler
(so endpoints no HTML links to are still fetched), and every operation's query /
path parameters and form-urlencoded body fields are synthesized into injection
points by :func:`webvigil.checks.injection.points.enumerate_points`.

This module issues at most one request (fetching an in-scope ``--openapi`` URL)
and imports nothing from ``webvigil.checks`` — the ``checks -> crawler``
dependency direction is preserved. JSON only: YAML would mean a new runtime
dependency (design ADR-3). Only local ``#/`` ``$ref`` pointers are resolved
(ADR-3); an external ``$ref`` is skipped with a warning.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from webvigil.core.errors import OpenApiError, OutOfScopeError, RequestFailed
from webvigil.core.target import Target
from webvigil.http.client import HttpClient

# A JSON document is untyped; every node is walked with ``isinstance`` guards.
_Doc = dict[str, Any]

# HTTP methods WebVigil acts on. A PUT / PATCH / DELETE operation is recorded by
# neither the crawler nor the injection pass (spec 006 fuzzes GET / POST only).
_ACTED_ON_METHODS = ("get", "post")

# An operation whose path or operationId looks like authentication or a
# state-changing action is not fuzzed — mirrors ``points._EXCLUDE_FORM_RE``
# (unifying the two keyword sets is the ADR-8 follow-up).
_SKIP_OPERATION_RE = re.compile(
    r"log[\s_-]?in|log[\s_-]?out|log[\s_-]?off|sign[\s_-]?in|sign[\s_-]?out|sign[\s_-]?up|"
    r"register|delete|remove|destroy|\bdrop\b|password|passwd|\breset\b|checkout|\bpay\b|"
    r"purchase|\border\b|transfer|unsubscribe|deactivate|revoke",
    re.I,
)

# Deterministic placeholder per JSON-schema scalar type, used when a parameter
# has no ``example`` / ``default`` / ``enum`` (RNF-06 — no randomness).
_PLACEHOLDER = {"string": "wv", "integer": "1", "number": "1", "boolean": "true"}

# Bounds on request-body synthesis so a hostile or huge schema cannot blow up.
_MAX_BODY_DEPTH = 4
_MAX_BODY_KEYS = 24

_EXTERNAL_REF_WARNING = "OpenAPI import skipped one or more external $ref pointers"


@dataclass(frozen=True, slots=True)
class ApiOperation:
    """
    One acted-on API operation, ready to seed the crawl and the injection pass.

    Attributes:
        method (str): ``"GET"`` or ``"POST"``.
        url (str): Absolute URL with ``{templated}`` path segments filled with
            their synthesized values — directly fetchable.
        url_template (str): Absolute URL with ``{name}`` path segments kept
            verbatim — the identity a path-parameter injection point substitutes
            into.
        query (tuple[tuple[str, str], ...]): ``(name, synthesized value)`` for
            each ``in: query`` parameter.
        path_params (tuple[tuple[str, str], ...]): ``(name, synthesized value)``
            for each ``in: path`` parameter.
        body_fields (tuple[tuple[str, str], ...]): ``(name, synthesized value)``
            for each field of a ``application/x-www-form-urlencoded`` request
            body; empty otherwise.
        body_json (str | None): A synthesized ``application/json`` request body,
            or ``None`` when the operation has no JSON body.
        operation_id (str): The document's ``operationId``, or ``""``.
    """

    method: str
    url: str
    url_template: str
    query: tuple[tuple[str, str], ...]
    path_params: tuple[tuple[str, str], ...]
    body_fields: tuple[tuple[str, str], ...]
    body_json: str | None
    operation_id: str


async def load_openapi(
    source: str, *, http: HttpClient, target: Target, max_operations: int
) -> tuple[list[ApiOperation], list[str]]:
    """
    Load ``source`` into acted-on operations, reconciled against the target origin.

    Args:
        source (str): A local ``.json`` path or an in-scope URL returning JSON.
        http (HttpClient): The shared, scope-guarded HTTP client (used only when
            ``source`` is a URL).
        target (Target): The normalized target; supplies the origin every
            operation URL is built against and the scope rule a URL ``source``
            must satisfy.
        max_operations (int): Hard cap on the operations returned; the excess is
            a warning.

    Returns:
        tuple[list[ApiOperation], list[str]]: The operations (stably ordered,
            capped) and any non-fatal warnings (a foreign server host, skipped
            external ``$ref``\\s, the operation cap, an empty result).

    Raises:
        OpenApiError: If ``source`` cannot be read, is not JSON, or is not a
            recognizable OpenAPI / Swagger document.
    """
    warnings: list[str] = []
    doc = await _fetch_document(source, http=http, target=target)
    base = _base_url(doc, target, warnings)

    operations: list[ApiOperation] = []
    paths = doc.get("paths")
    if isinstance(paths, dict):
        for raw_path, raw_item in paths.items():
            item = _resolve(raw_item, doc, warnings)
            if not isinstance(item, dict):
                continue
            operations.extend(_operations_for(str(raw_path), item, doc, base, warnings))

    operations.sort(key=lambda operation: (operation.url_template, operation.method))
    if len(operations) > max_operations:
        warnings.append(
            f"OpenAPI import seeded the first {max_operations} of {len(operations)} operations"
        )
        operations = operations[:max_operations]
    if not operations:
        warnings.append("OpenAPI document declared no usable GET or POST operations")
    return operations, warnings


async def _fetch_document(source: str, *, http: HttpClient, target: Target) -> _Doc:
    """
    Read ``source`` and parse it into a validated OpenAPI / Swagger mapping.

    Args:
        source (str): A local path or a URL.
        http (HttpClient): The shared HTTP client, for a URL ``source``.
        target (Target): The target whose scope a URL ``source`` must satisfy.

    Returns:
        _Doc: The parsed document.

    Raises:
        OpenApiError: For an out-of-scope URL, a missing file, a non-200 or
            non-JSON response, invalid JSON, or JSON that is not an OpenAPI /
            Swagger document.
    """
    if "://" in source:
        if not target.in_scope(source):
            raise OpenApiError(f"--openapi URL is out of scope: {source}")
        try:
            response = await http.get(source)
        except (RequestFailed, OutOfScopeError) as exc:
            raise OpenApiError(f"could not fetch {source}: {exc}") from exc
        if response.status_code != 200:
            raise OpenApiError(f"{source} returned HTTP {response.status_code}")
        text = response.text
    else:
        path = Path(source)
        if not path.is_file():
            raise OpenApiError(f"OpenAPI file not found: {source}")
        text = path.read_text("utf-8")

    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise OpenApiError(f"{source} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc):
        raise OpenApiError(f"{source} is not an OpenAPI or Swagger document")
    return doc


def _base_url(doc: _Doc, target: Target, warnings: list[str]) -> str:
    """
    Resolve the base URL every operation path is joined to, against the target origin.

    Args:
        doc (_Doc): The parsed document.
        target (Target): The target whose origin wins over the document's own
            server host.
        warnings (list[str]): Scan-level warning list, appended to in place.

    Returns:
        str: ``target.origin`` optionally followed by a ``/base/path`` segment.
    """
    if "swagger" in doc:  # Swagger 2.0
        schemes = doc.get("schemes")
        scheme = schemes[0] if isinstance(schemes, list) and schemes else "https"
        host = doc.get("host")
        base_path = doc.get("basePath", "")
        raw = f"{scheme}://{host}{base_path}" if isinstance(host, str) and host else str(base_path)
    else:  # OpenAPI 3.x
        servers = doc.get("servers")
        raw = "/"
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            raw = str(servers[0].get("url") or "/")

    parts = urlsplit(raw)
    if parts.scheme and parts.hostname and parts.hostname.lower() != target.host:
        warnings.append(
            f"OpenAPI server host {parts.hostname!r} differs from the scan target; "
            f"paths are resolved against {target.origin}"
        )
    path = (parts.path if parts.scheme and parts.netloc else raw).strip("/")
    return f"{target.origin}/{path}".rstrip("/") if path else target.origin


def _operations_for(
    path: str, item: _Doc, root: _Doc, base: str, warnings: list[str]
) -> list[ApiOperation]:
    """
    Build the acted-on operations declared by one path-item object.

    Args:
        path (str): The path template, e.g. ``"/users/{id}"``.
        item (_Doc): The resolved path-item object.
        root (_Doc): The whole document, for ``$ref`` resolution.
        base (str): The base URL from :func:`_base_url`.
        warnings (list[str]): Scan-level warning list, appended to in place.

    Returns:
        list[ApiOperation]: Zero or more operations; a login / destructive
            operation is dropped.
    """
    shared = item.get("parameters", [])
    shared_list = shared if isinstance(shared, list) else []
    operations: list[ApiOperation] = []
    for method in _ACTED_ON_METHODS:
        op = item.get(method)
        if not isinstance(op, dict):
            continue
        operation_id = str(op.get("operationId") or "")
        if _SKIP_OPERATION_RE.search(f"{path} {operation_id}"):
            continue

        own = op.get("parameters", [])
        raw_params = shared_list + (own if isinstance(own, list) else [])
        params: list[_Doc] = []
        for raw_param in raw_params:
            resolved = _resolve(raw_param, root, warnings)
            if isinstance(resolved, dict):
                params.append(resolved)
        query = _param_values(params, "query")
        path_params = _param_values(params, "path")
        body_fields, body_json = _body(op, params, root, warnings)

        template = f"{base}/{path.lstrip('/')}"
        operations.append(
            ApiOperation(
                method=method.upper(),
                url=_fill_path(template, path_params),
                url_template=template,
                query=query,
                path_params=path_params,
                body_fields=body_fields,
                body_json=body_json,
                operation_id=operation_id,
            )
        )
    return operations


def _param_values(params: list[_Doc], location: str) -> tuple[tuple[str, str], ...]:
    """
    Args:
        params (list[_Doc]): The resolved parameter objects of one operation.
        location (str): ``"query"`` or ``"path"``.

    Returns:
        tuple[tuple[str, str], ...]: ``(name, synthesized value)`` for each
            named parameter whose ``in`` matches ``location``.
    """
    out: list[tuple[str, str]] = []
    for param in params:
        if param.get("in") != location:
            continue
        name = param.get("name")
        if isinstance(name, str) and name:
            out.append((name, _synth_value(param)))
    return tuple(out)


def _body(
    op: _Doc, params: list[_Doc], root: _Doc, warnings: list[str]
) -> tuple[tuple[tuple[str, str], ...], str | None]:
    """
    Synthesize a request body for one operation.

    Args:
        op (_Doc): The operation object.
        params (list[_Doc]): Its resolved parameters (Swagger 2.0 carries the
            body there).
        root (_Doc): The whole document, for ``$ref`` resolution.
        warnings (list[str]): Scan-level warning list, appended to in place.

    Returns:
        tuple[tuple[tuple[str, str], ...], str | None]: Form-urlencoded fields
            (empty when there are none) and a JSON body string (``None`` when
            there is none).
    """
    request_body = _resolve(op.get("requestBody", {}), root, warnings)
    content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
    if isinstance(content, dict):
        form_type = "application/x-www-form-urlencoded"
        if form_type in content:
            schema = _resolve(_media_schema(content, form_type), root, warnings)
            return _form_fields(schema, root, warnings), None
        if "application/json" in content:
            schema = _resolve(_media_schema(content, "application/json"), root, warnings)
            return (), json.dumps(_synth_object(schema, root, warnings))

    # Swagger 2.0: an ``in: formData`` set, or a single ``in: body`` parameter.
    form_data = tuple(
        (str(p["name"]), _synth_value(p))
        for p in params
        if p.get("in") == "formData" and isinstance(p.get("name"), str)
    )
    if form_data:
        return form_data, None
    for param in params:
        if param.get("in") == "body" and isinstance(param.get("schema"), dict):
            return (), json.dumps(_synth_object(param["schema"], root, warnings))
    return (), None


def _media_schema(content: _Doc, media_type: str) -> Any:
    """
    Args:
        content (_Doc): A ``requestBody.content`` mapping.
        media_type (str): The media type to read the schema of.

    Returns:
        Any: The media type's ``schema`` node, or ``{}`` when absent.
    """
    entry = content.get(media_type)
    return entry.get("schema", {}) if isinstance(entry, dict) else {}


def _form_fields(schema: Any, root: _Doc, warnings: list[str]) -> tuple[tuple[str, str], ...]:
    """
    Args:
        schema (Any): A resolved object schema.
        root (_Doc): The whole document, for ``$ref`` resolution.
        warnings (list[str]): Scan-level warning list, appended to in place.

    Returns:
        tuple[tuple[str, str], ...]: ``(name, synthesized value)`` for each
            top-level property.
    """
    if not isinstance(schema, dict):
        return ()
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        return ()
    return tuple(
        (name, _synth_value(_resolve(spec, root, warnings)))
        for name, spec in list(props.items())[:_MAX_BODY_KEYS]
    )


def _synth_value(node: _Doc) -> str:
    """
    Pick a deterministic string value for a parameter or a scalar schema.

    Precedence: an ``example`` / ``default`` on the node, then on its ``schema``,
    then the first ``enum`` entry, then a type-based placeholder (RF-07).

    Args:
        node (_Doc): A parameter object or a schema object.

    Returns:
        str: The synthesized value.
    """
    for key in ("example", "default"):
        if key in node:
            return _stringify(node[key])
    raw_schema = node.get("schema")
    schema = raw_schema if isinstance(raw_schema, dict) else node
    for key in ("example", "default"):
        if key in schema:
            return _stringify(schema[key])
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return _stringify(enum[0])
    return _PLACEHOLDER.get(str(schema.get("type", "")), "wv")


def _synth_object(schema: Any, root: _Doc, warnings: list[str], _depth: int = 0) -> Any:
    """
    Build a minimal JSON value from a schema, bounded in depth and breadth.

    Args:
        schema (Any): A schema node (possibly a ``$ref``).
        root (_Doc): The whole document, for ``$ref`` resolution.
        warnings (list[str]): Scan-level warning list, appended to in place.
        _depth (int): Current recursion depth. Defaults to 0.

    Returns:
        Any: A dict, a one-element list, or a typed scalar.
    """
    schema = _resolve(schema, root, warnings)
    if not isinstance(schema, dict):
        return "wv"
    if _depth >= _MAX_BODY_DEPTH:
        return {}
    if schema.get("type") == "object" or "properties" in schema:
        props = schema.get("properties", {})
        items = list(props.items())[:_MAX_BODY_KEYS] if isinstance(props, dict) else []
        return {name: _synth_object(spec, root, warnings, _depth + 1) for name, spec in items}
    if schema.get("type") == "array":
        return [_synth_object(schema.get("items", {}), root, warnings, _depth + 1)]
    return _scalar(schema)


def _scalar(schema: _Doc) -> Any:
    """
    Args:
        schema (_Doc): A scalar schema.

    Returns:
        Any: The ``example`` / ``default`` / first ``enum`` value if present,
            else a typed placeholder (``1``, ``True``, or ``"wv"``).
    """
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    kind = schema.get("type")
    if kind in ("integer", "number"):
        return 1
    if kind == "boolean":
        return True
    return "wv"


def _stringify(value: Any) -> str:
    """
    Args:
        value (Any): A JSON scalar (or a structure, defensively).

    Returns:
        str: ``"true"`` / ``"false"`` for a bool, ``"wv"`` for ``None`` or a
            container, ``str(value)`` otherwise.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None or isinstance(value, (list, dict)):
        return "wv"
    return str(value)


def _resolve(
    node: Any, root: _Doc, warnings: list[str], _seen: frozenset[str] = frozenset()
) -> Any:
    """
    Follow a local ``$ref`` chain to its target, guarding against cycles.

    Args:
        node (Any): A node that may be, or contain, a ``$ref``.
        root (_Doc): The whole document.
        warnings (list[str]): Scan-level warning list; a one-time notice is
            appended the first time an external ``$ref`` is met.
        _seen (frozenset[str]): ``$ref`` strings already on this chain.

    Returns:
        Any: The dereferenced node, or ``{}`` for an external ``$ref`` or a
            cycle.
    """
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            if _EXTERNAL_REF_WARNING not in warnings:
                warnings.append(_EXTERNAL_REF_WARNING)
            return {}
        if ref in _seen:
            return {}
        _seen = _seen | {ref}
        node = _deref(ref, root)
    return node


def _deref(ref: str, root: _Doc) -> Any:
    """
    Args:
        ref (str): A local JSON pointer, e.g. ``"#/components/schemas/User"``.
        root (_Doc): The document to walk.

    Returns:
        Any: The node the pointer addresses, or ``{}`` when a step is missing.
    """
    node: Any = root
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and token in node:
            node = node[token]
        else:
            return {}
    return node


def _fill_path(template: str, path_params: tuple[tuple[str, str], ...]) -> str:
    """
    Args:
        template (str): A URL with ``{name}`` path segments.
        path_params (tuple[tuple[str, str], ...]): ``(name, value)`` pairs.

    Returns:
        str: ``template`` with each ``{name}`` replaced by its URL-encoded value.
    """
    url = template
    for name, value in path_params:
        url = url.replace("{" + name + "}", quote(value, safe=""))
    return url


__all__ = ["ApiOperation", "load_openapi"]
