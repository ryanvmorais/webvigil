"""
The sink inventory of spec 025 (RF-09, ADR-8): every output of the package is a known site.

Every module under ``src/webvigil`` is parsed (never imported), and every output call is recorded
as ``module:qualname`` of the function around it: ``print``, ``typer.echo`` / ``secho``, a
``.print`` or ``.print_json`` on a console, ``.write`` on ``sys.stdout`` / ``sys.stderr``,
``.write_text`` / ``.write_bytes``, ``HTTPException``, a Starlette response class in the Web API,
``session.add`` and ``logging.getLogger``.

A call passes on its own when every argument is a fixed value (a literal, a constant named in
capitals, an f-string of those) or a direct call of ``safe_text``. Every other site must be in
:data:`OUTPUT_SINKS` with the reason its values are safe: an unlisted site fails, and so does a
listed site with no output call left. ``logging.getLogger`` is refused outside ``core/output.py``,
so every logger comes from ``get_logger`` and carries the log filter (ADR-4).

The positive controls run the walk over a throwaway source, so a walk that stopped seeing calls
cannot pass.
"""

from __future__ import annotations

import ast
import dataclasses
from collections.abc import Mapping
from pathlib import Path
from typing import Final

import webvigil

# The package the walk parses, the one module that may call logging.getLogger, and the package
# whose response classes are API responses.
SRC: Final = Path(webvigil.__file__).parent
OUTPUT_MODULE: Final = "webvigil.core.output"
_API_PACKAGE: Final = "webvigil.api"

# ---------------------------------------------------------------------------
# The inventory
# ---------------------------------------------------------------------------

# Every output site whose arguments are not all fixed, as ``module:qualname``, with the reason its
# values are safe. A new output is a new line here, in the pull request that adds it.
_THROUGH_RENDER: Final = "through _printable, _plain or cell, which call safe_text(Sink.TERMINAL)"
_REPORT: Final = (
    "a rendered report: every field is bounded (the STORE profile) and the reporter gives the "
    "page the DOCUMENT or JSON profile"
)
OUTPUT_SINKS: Final[Mapping[str, str]] = {
    # The terminal
    "webvigil.cli._render:banner": _THROUGH_RENDER,
    "webvigil.cli._render:error": _THROUGH_RENDER,
    "webvigil.cli._render:status": _THROUGH_RENDER,
    "webvigil.cli._render:summary": _THROUGH_RENDER,
    "webvigil.cli.app:list_checks": "a table whose cells are _render.cell, a one-line Text",
    "webvigil.cli.app:version": "the package's own version string",
    "webvigil.cli.app:_emit": _REPORT,
    "webvigil.cli.app:_write_or_print": _REPORT,
    "webvigil.cli.app:_write_stdout": _REPORT,
    # The Web API's responses
    "webvigil.api.app:_validation_failed": (
        "each string of loc and each msg through safe_text(Sink.MESSAGE); type is pydantic's code"
    ),
    "webvigil.api.docs_ui:swagger_ui_html": (
        "FastAPI's Swagger page with the pinned asset URLs and their integrity; no request value"
    ),
    "webvigil.api.routes.auth:_too_many": "a fixed word from each caller and the integer wait",
    "webvigil.api.routes.auth:login": "a fixed message; Retry-After is the constant BUSY_RETRY_S",
    "webvigil.api.routes.reports:download_report": (
        _REPORT + "; the unknown format through safe_text(Sink.MESSAGE), the file name from the "
        "scan id and a known format"
    ),
    # The database
    "webvigil.api.mapping:store_result": (
        "rows from bounded model fields, the STORE profile (ADR-1)"
    ),
    "webvigil.api.routes.scans:create_scan": (
        "the target as Target.parse normalized it, enum values, the schema-bounded authorized_by "
        "and validated options"
    ),
    "webvigil.api.routes.setup:create_first_user": (
        "the username SetupIn bounds and a password hash"
    ),
    "webvigil.api.runner:ScanRunner._claim_next_queued": "a status and a start time",
    "webvigil.api.runner:ScanRunner._terminate": (
        "a status, a time and the error message through safe_text(Sink.STORE)"
    ),
    "webvigil.api.runner:recover_interrupted_scans": "a status and a fixed error message",
    "webvigil.api.security:resolve_session_secret": "the signing secret this server generated",
}

# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------

# The names that make a call an output, by kind (ADR-8).
_CONSOLE_METHODS: Final = frozenset({"print", "print_json"})
_TYPER_FUNCTIONS: Final = frozenset({"echo", "secho"})
_FILE_WRITES: Final = frozenset({"write_text", "write_bytes"})
_STREAMS: Final = frozenset({"stdout", "stderr"})
_API_RESPONSES: Final = frozenset(
    {
        "HTTPException",
        "Response",
        "JSONResponse",
        "HTMLResponse",
        "PlainTextResponse",
        "StreamingResponse",
        "RedirectResponse",
    }
)


@dataclasses.dataclass
class _Walk:
    """
    What one module's syntax tree holds.

    Attributes:
        sites (set[str]): Every ``module:qualname`` with an output call that is not all fixed.
        seen (int): How many output calls the walk met, fixed or not.
        refused (list[str]): Every ``logging.getLogger`` outside ``core/output.py``, as
            ``module:line``.
    """

    sites: set[str] = dataclasses.field(default_factory=set)
    seen: int = 0
    refused: list[str] = dataclasses.field(default_factory=list)


def _dotted(node: ast.expr) -> str:
    """
    Args:
        node (ast.expr): A name or an attribute chain.

    Returns:
        str: Its dotted spelling (``sys.stdout.write``), or ``""`` for anything else.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _dotted(node.value)
        return f"{inner}.{node.attr}" if inner else ""
    return ""


def _is_get_logger(func: ast.expr) -> bool:
    """
    Args:
        func (ast.expr): What a call calls.

    Returns:
        bool: Whether it is ``logging.getLogger`` or a bare ``getLogger``.
    """
    return _dotted(func) in {"logging.getLogger", "getLogger"}


def _is_output(func: ast.expr, module: str) -> bool:
    """
    Args:
        func (ast.expr): What a call calls.
        module (str): The module the call is in.

    Returns:
        bool: Whether the call writes to the terminal, a file, the database or an API response.
    """
    name = _dotted(func)
    parts = name.split(".")
    last = parts[-1] if name else ""
    if name == "print" or name in {"typer.echo", "typer.secho"}:
        return True
    if isinstance(func, ast.Attribute):
        if func.attr in _CONSOLE_METHODS or func.attr in _FILE_WRITES:
            return True
        if func.attr == "write" and _STREAMS & set(parts):
            return True
        if func.attr == "add" and "session" in _dotted(func.value).lower():
            return True
    in_api = module == _API_PACKAGE or module.startswith(f"{_API_PACKAGE}.")
    return in_api and last in _API_RESPONSES and parts[0] in {last, "fastapi", "starlette"}


def _is_fixed(node: ast.expr) -> bool:
    """
    Args:
        node (ast.expr): One argument of an output call.

    Returns:
        bool: Whether its value is fixed in the source (a literal, a constant named in capitals,
            a collection or an f-string of those), or a direct call of ``safe_text``.
    """
    match node:
        case ast.Constant():
            return True
        case ast.Name(id=name):
            return name.isupper()
        case ast.Attribute(attr=attr):
            return attr.isupper()
        case ast.JoinedStr(values=values):
            return all(_is_fixed(value) for value in values)
        case ast.FormattedValue(value=value):
            return _is_fixed(value)
        case ast.Tuple(elts=items) | ast.List(elts=items) | ast.Set(elts=items):
            return all(_is_fixed(item) for item in items)
        case ast.UnaryOp(operand=operand):
            return _is_fixed(operand)
        case ast.Call(func=func):
            return _dotted(func) == "safe_text"
    return False


class _OutputVisitor(ast.NodeVisitor):
    """
    Records the output calls of a module with the qualified name of their function.

    Args:
        module (str): The module's dotted name.
        walk (_Walk): Where the findings go.
    """

    def __init__(self, module: str, walk: _Walk) -> None:
        self._module = module
        self._walk = walk
        self._scope: list[str] = []

    def _site(self) -> str:
        return f"{self._module}:{'.'.join(self._scope) or '<module>'}"

    def _scoped(self, name: str, node: ast.AST) -> None:
        """
        Visit a node with its name on the scope, so the calls inside are its site.

        Args:
            name (str): The class, function or ``<lambda>`` the node defines.
            node (ast.AST): The node.
        """
        self._scope.append(name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scoped(node.name, node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scoped(node.name, node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scoped(node.name, node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._scoped("<lambda>", node)

    def visit_Call(self, node: ast.Call) -> None:
        if _is_get_logger(node.func):
            if self._module != OUTPUT_MODULE:
                self._walk.refused.append(f"{self._module}:{node.lineno}")
        elif _is_output(node.func, self._module):
            self._walk.seen += 1
            arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
            if not all(_is_fixed(argument) for argument in arguments):
                self._walk.sites.add(self._site())
        self.generic_visit(node)


def walk_source(source: str, module: str) -> _Walk:
    """
    Args:
        source (str): A module's source.
        module (str): Its dotted name.

    Returns:
        _Walk: Its output sites and its refused loggers.
    """
    walk = _Walk()
    _OutputVisitor(module, walk).visit(ast.parse(source))
    return walk


def _module_name(path: Path, root: Path, package: str) -> str:
    """
    Args:
        path (Path): A ``.py`` file under ``root``.
        root (Path): The package's directory.
        package (str): The package's name.

    Returns:
        str: Its dotted module name (a package's ``__init__`` is the package).
    """
    parts = (package, *path.relative_to(root).with_suffix("").parts)
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def walk_package(root: Path = SRC, package: str = "webvigil") -> tuple[_Walk, int]:
    """
    Args:
        root (Path): The package's directory. Defaults to :data:`SRC`.
        package (str): The package's name. Defaults to ``webvigil``.

    Returns:
        tuple[_Walk, int]: The merged walk of every module under ``root``, and how many modules
            it parsed.
    """
    merged = _Walk()
    paths = sorted(root.rglob("*.py"))
    for path in paths:
        walk = walk_source(path.read_text(encoding="utf-8"), _module_name(path, root, package))
        merged.sites |= walk.sites
        merged.seen += walk.seen
        merged.refused += walk.refused
    return merged, len(paths)


def inventory_problems(sites: set[str], allowed: Mapping[str, str]) -> tuple[set[str], set[str]]:
    """
    Args:
        sites (set[str]): The output sites the walk found.
        allowed (Mapping[str, str]): The inventory.

    Returns:
        tuple[set[str], set[str]]: The sites missing from the inventory, and the inventoried sites
            with no output call left.
    """
    return sites - allowed.keys(), allowed.keys() - sites


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------


def test_every_output_is_in_the_inventory() -> None:
    """The output sites of the source are exactly the inventoried ones, none missing or stale."""
    walk, parsed = walk_package()
    assert parsed > 100  # the walk read the package
    assert walk.seen > len(OUTPUT_SINKS)  # and met the fixed calls as well as the listed ones
    unlisted, stale = inventory_problems(walk.sites, OUTPUT_SINKS)
    assert not unlisted, f"output outside OUTPUT_SINKS: {sorted(unlisted)}"
    assert not stale, f"OUTPUT_SINKS sites with no output call left: {sorted(stale)}"


def test_every_inventoried_site_says_why() -> None:
    """Each line of the inventory carries a reason."""
    assert all(reason.strip() for reason in OUTPUT_SINKS.values())


def test_every_logger_comes_from_get_logger() -> None:
    """No module but ``core/output.py`` calls ``logging.getLogger``."""
    walk, _ = walk_package()
    assert walk.refused == []


# A source the walk reads and never imports: one output of each kind, fixed and not, and both
# spellings of getLogger, so the controls below see every rule fire.
_THROWAWAY = """
import logging
import sys
from logging import getLogger

import typer
from fastapi import HTTPException
from fastapi.responses import JSONResponse

from webvigil.core.output import Sink, safe_text

LIMIT = 3


def fixed(console, path):
    print("done", LIMIT, -1)
    typer.echo(f"at most {LIMIT} pages", err=True)
    console.print("[dim]fixed[/]", style="dim")
    raise HTTPException(Status.HTTP_404_NOT_FOUND, "scan not found")


def treated(message):
    typer.echo(safe_text(message, Sink.TERMINAL))


def unlisted(value, console, path, session, request):
    print(value)


class Writer:
    def stream(self, report):
        sys.stdout.write(report)

    def file(self, path, report):
        path.write_text(report)

    def styled(self, name):
        return lambda: typer.secho(f"hello {name}")


def api(detail, session, row):
    session.add(row)
    return JSONResponse({"detail": detail})


LOG = logging.getLogger(__name__)
OTHER = getLogger("other")
"""


def test_the_walk_sees_every_kind_of_output() -> None:
    """Positive control: each kind of output with a value, in a function, a method, a lambda."""
    walk = walk_source(_THROWAWAY, "webvigil.api.throwaway")
    assert walk.sites == {
        "webvigil.api.throwaway:unlisted",
        "webvigil.api.throwaway:Writer.stream",
        "webvigil.api.throwaway:Writer.file",
        "webvigil.api.throwaway:Writer.styled.<lambda>",
        "webvigil.api.throwaway:api",
    }
    assert walk.seen == 11
    assert walk.sites - OUTPUT_SINKS.keys() == walk.sites  # each would fail the inventory


def test_a_fixed_or_treated_call_passes() -> None:
    """Literals, capital constants, their f-strings and a direct ``safe_text`` call pass."""
    walk = walk_source(_THROWAWAY, "webvigil.api.throwaway")
    assert not {"webvigil.api.throwaway:fixed", "webvigil.api.throwaway:treated"} & walk.sites


def test_a_response_class_counts_only_in_the_web_api() -> None:
    """An engine module that builds an ``httpx2`` response is not writing an API response."""
    source = "def build(raw):\n    return Response(raw.status_code)\n"
    assert walk_source(source, "webvigil.http.client").sites == set()
    assert walk_source(source, "webvigil.api.routes.x").sites == {"webvigil.api.routes.x:build"}


def test_the_walk_refuses_a_stray_logger() -> None:
    """Positive control: both spellings of ``getLogger`` are refused outside ``core/output.py``."""
    assert walk_source(_THROWAWAY, "webvigil.api.throwaway").refused == [
        "webvigil.api.throwaway:46",
        "webvigil.api.throwaway:47",
    ]
    assert walk_source(_THROWAWAY, OUTPUT_MODULE).refused == []


def test_the_package_walk_merges_every_module(tmp_path: Path) -> None:
    """Positive control over a throwaway package: every module's sites arrive, stale lines show."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "__init__.py").write_text("def top(value):\n    print(value)\n")
    (tmp_path / "sub" / "__init__.py").write_text("")
    (tmp_path / "sub" / "cli.py").write_text("import typer\n\ndef run(v):\n    typer.echo(v)\n")
    walk, parsed = walk_package(tmp_path, "pkg")
    assert parsed == 3
    assert walk.sites == {"pkg:top", "pkg.sub.cli:run"}
    allowed = {"pkg:top": "a reason", "pkg.sub.cli:gone": "a reason"}
    assert inventory_problems(walk.sites, allowed) == ({"pkg.sub.cli:run"}, {"pkg.sub.cli:gone"})
