"""
The walker of the sensitive-point inventory (spec 027, RF-07, ADR-5): it lists, and never judges.

A scanner warns only about what matches one of its rules. This walk does the opposite: it lists
every place where the text of an exception becomes output (the ``error`` family), every exception
raised with a dynamic value in its message (``message``) and every call of a dangerous operation
(``command``, ``code``, ``deserialization``, ``sql``, ``file``, ``xml``, ``regex``, ``html``,
``redirect``, ``network``, ``crypto``). The dashboard is read by text pattern for the same
operations, for a public build variable (``client-secret``) and for the text of a caught error.
:mod:`tests.unit.test_sensitive_point_inventory` holds the reason each point is safe.

Python is read as syntax trees, so the code read is never imported or run; the dashboard is read
as text. The files are the ones ``git ls-files`` lists under ``src/webvigil`` and ``web/src``,
without tests, vendored data and generated files. Every node of a module belongs to exactly one
scope (the module, a class body or a function; a decorator, a default value and an annotation
belong to the scope around the definition), so every call is read once, and the count of calls
read proves it.

Exception text is followed, to a fixed point, through variables (``message = f"{exc}"`` inside
the handler and used after it), wrapping exceptions (``raise Wrapped(str(exc))``) and fields of
objects across files (a field assigned from exception text in one module, or a parameter that
receives it and is stored, is followed wherever that field is read).
"""

from __future__ import annotations

import ast
import re
import subprocess
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

# The repository root, and the trees the walk reads.
ROOT: Final = Path(__file__).resolve().parent.parent
READ_UNDER: Final = ("src/webvigil", "web/src")

# Tests, vendored data and generated files are not read: the inventory is about shipped code.
_EXCLUDED: Final = re.compile(
    r"(^|/)(tests?|__tests__|e2e|fixtures?|node_modules|vendor|vendored|dist|build|\.next)/"
    r"|(^|/)test_[^/]+\.py$|\.(test|spec)\.[jt]sx?$|\.d\.ts$|\.min\.js$|(^|/)api-types\.ts$"
)
# The dashboard files, read as text.
_DASHBOARD_SUFFIXES: Final = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")

# The families, so the throwaway source can prove that every one is still seen.
PYTHON_FAMILIES: Final = frozenset(
    {
        "error",
        "message",
        "command",
        "code",
        "deserialization",
        "sql",
        "file",
        "xml",
        "regex",
        "html",
        "redirect",
        "network",
        "crypto",
    }
)
DASHBOARD_FAMILIES: Final = frozenset(
    {"error", "html", "code", "command", "redirect", "regex", "network", "crypto", "client-secret"}
)

# ---------------------------------------------------------------------------
# Python: what carries exception text
# ---------------------------------------------------------------------------

# Attributes of an exception that carry no text from outside.
_SAFE_ATTRIBUTES: Final = frozenset(
    {
        "__class__",
        "__name__",
        "__qualname__",
        "__cause__",
        "__context__",
        "__traceback__",
        "status_code",
        "code",
        "errno",
        "lineno",
        "colno",
        "pos",
        "offset",
    }
)
# Calls whose result never repeats the text of their argument.
_NO_TEXT_CALLS: Final = frozenset(
    {"type", "isinstance", "issubclass", "id", "hasattr", "bool", "len"}
)
# An assignment from one of these makes a variable that carries the text, not an output.
_TEXT_BUILDERS: Final = frozenset({"str", "repr", "format", "join"})
# How the output that receives exception text is named in a key: a logger method on a name that
# says log, a terminal writer, a collection the text joins (a list of warnings), and the calls
# that format a traceback.
_LOGGER_METHODS: Final = frozenset(
    {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}
)
_TERMINAL_CALLS: Final = frozenset({"print", "echo", "secho", "status", "error"})
_COLLECTION_METHODS: Final = frozenset({"append", "extend", "add", "insert", "appendleft"})
_TRACEBACK_CALLS: Final = ("format_exc", "format_exception", "print_exc")

# ---------------------------------------------------------------------------
# Python: the dangerous operations
# ---------------------------------------------------------------------------

# How a name matches: ``.name`` is any method of that name; ``a.b`` is that dotted name or one
# ending in it; a bare name is that name or one ending in ``.name``, except the builtins below,
# and ``text``, which match only when called bare (``session.exec`` is SQL, not the ``exec``
# builtin; ``node.text()`` is selectolax, not SQLAlchemy's ``text``).
_BUILTINS_ONLY: Final = frozenset({"eval", "exec", "compile", "open", "__import__", "text"})


def _family(family: str, dynamic: bool, *names: str) -> list[tuple[str, str, bool]]:
    """
    Args:
        family (str): The family of every name.
        dynamic (bool): Whether only a call with a non-literal first argument is a point.
        *names (str): The names of the operation.

    Returns:
        list[tuple[str, str, bool]]: ``(name, family, dynamic)`` for each name.
    """
    return [(name, family, dynamic) for name in names]


# In order: the first match wins (``shelve.open`` is deserialization before ``.open`` is a file).
OPERATIONS: Final[tuple[tuple[str, str, bool], ...]] = (
    *_family(
        "command",
        False,
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
    ),
    *_family("code", True, "eval", "exec", "compile", "__import__", "importlib.import_module"),
    *_family("code", False, "entry_points"),
    *_family(
        "deserialization",
        False,
        "pickle.load",
        "pickle.loads",
        "marshal.load",
        "marshal.loads",
        "yaml.load",
        "yaml.unsafe_load",
        "shelve.open",
        "dill.load",
        "dill.loads",
    ),
    *_family("sql", True, ".execute", ".executemany", ".exec", "text", "sqlalchemy.text"),
    *_family(
        "file",
        False,
        "open",
        ".open",
        ".write_text",
        ".write_bytes",
        ".read_text",
        ".read_bytes",
        ".unlink",
        ".rmtree",
        ".extract",
        ".extractall",
        "os.remove",
        "os.rename",
        "os.replace",
        "os.chmod",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.move",
        "zipfile.ZipFile",
    ),
    *_family(
        "xml",
        False,
        "ElementTree.fromstring",
        "ElementTree.parse",
        "ET.fromstring",
        "ET.parse",
        "minidom.parseString",
        "minidom.parse",
        "etree.fromstring",
        "etree.parse",
        "XMLParser",
    ),
    *_family(
        "regex",
        True,
        "re.compile",
        "re.search",
        "re.match",
        "re.fullmatch",
        "re.sub",
        "re.subn",
        "re.findall",
        "re.finditer",
        "re.split",
    ),
    *_family(
        "html",
        False,
        "Markup",
        "mark_safe",
        "render_template_string",
        ".from_string",
        "HTMLResponse",
        "Environment",
    ),
    *_family("redirect", True, "RedirectResponse", "redirect"),
    *_family(
        "network",
        False,
        "urlopen",
        "requests.get",
        "requests.post",
        "requests.request",
        "socket.socket",
        "socket.create_connection",
        "asyncio.open_connection",
        ".getaddrinfo",
        "httpx2.Client",
        "httpx2.AsyncClient",
        "httpx2.HTTPTransport",
        "httpx2.AsyncHTTPTransport",
    ),
    *_family(
        "crypto",
        False,
        "hashlib.md5",
        "hashlib.sha1",
        "random.random",
        "random.randint",
        "random.randrange",
        "random.uniform",
        "random.choice",
        "random.choices",
        "random.getrandbits",
        "ssl.SSLContext",
        "ssl.create_default_context",
        "ssl._create_unverified_context",
        "jwt.encode",
        "jwt.decode",
    ),
)

# A keyword or an attribute assignment that turns certificate checks off.
_TLS_OFF: Final = frozenset({"verify", "check_hostname"})

# ---------------------------------------------------------------------------
# The dashboard
# ---------------------------------------------------------------------------

DASHBOARD_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "html",
        re.compile(
            r"dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML"
            r"|document\.write"
        ),
    ),
    ("code", re.compile(r"\beval\(|new Function\(|setTimeout\(\s*[\"'`]")),
    ("command", re.compile(r"child_process|\bexecSync\(|\bspawn\(")),
    (
        "redirect",
        re.compile(
            # ``const location = ...`` declares a variable; it does not navigate.
            r"(?<!const )(?<!let )(?<!var )(?:\b(?:window|document)\.location|(?<![\w.])location)"
            r"(?:\.href)?\s*=(?!=)|\blocation\.(?:assign|replace)\(|window\.open\("
            r"|\b(?:redirect|router\.push|router\.replace)\((?![\"'`])"
        ),
    ),
    ("regex", re.compile(r"new RegExp\((?![\"'`/])")),
    ("network", re.compile(r"\bfetch\((?![\"'`])|new (?:WebSocket|EventSource)\(")),
    ("crypto", re.compile(r"Math\.random\(")),
    ("client-secret", re.compile(r"\bNEXT_PUBLIC_\w+")),
)
# Where a caught error gets a name: a ``catch (e)`` clause, or a ``.catch`` / ``onError`` callback.
_CAUGHT: Final = re.compile(
    r"\bcatch\s*\(\s*(\w+)\s*\)"
    r"|(?:\.catch\(|\bonError\s*:)\s*(?:async\s*)?\(\s*(\w+)[^)]*\)\s*=>"
)

# ---------------------------------------------------------------------------
# The result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Point:
    """
    One sensitive point.

    Attributes:
        family (str): ``error``, ``message``, ``sql``, ``file``...
        path (str): The file, relative to the repository root.
        line (int): The line of the point.
        column (int): The column, to order two points on one line.
        scope (str): ``<module>:<qualname>`` in Python (``<module>`` for module level), the path
            on the dashboard.
        callee (str): The call (``open``, ``re.compile``), the output the exception text reaches
            (``raise:RequestFailed``, ``log:logger.warning``, ``field``), or the matched text.
        snippet (str): The code on one line, cut at 120 characters.
    """

    family: str
    path: str
    line: int
    column: int
    scope: str
    callee: str
    snippet: str

    @property
    def base_key(self) -> str:
        """
        Returns:
            str: The key before the ``#n`` of a repeated one.
        """
        return f"{self.scope} {self.family} {self.callee}"


@dataclass(frozen=True)
class Inventory:
    """
    The result of a walk.

    Attributes:
        points (dict[str, Point]): Each point by its key.
        calls_read (int): Every Python call the walk read.
        lines_read (int): Every dashboard line the walk read.
        unparsed (tuple[str, ...]): The Python files that did not parse.
    """

    points: dict[str, Point]
    calls_read: int
    lines_read: int
    unparsed: tuple[str, ...]


# ---------------------------------------------------------------------------
# Python: helpers
# ---------------------------------------------------------------------------


def dotted(node: ast.expr) -> str:
    """
    Args:
        node (ast.expr): The called expression.

    Returns:
        str: The dotted name (``a.b.c``); a part that is not a name is empty (``.method``).
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return ""


def _carries(node: ast.AST | None, names: set[str], fields: frozenset[str]) -> bool:
    """
    Args:
        node (ast.AST | None): An expression.
        names (set[str]): The names that hold an exception or its text.
        fields (frozenset[str]): The object attributes that hold exception text.

    Returns:
        bool: Whether the expression's value can repeat the text of one of them.
    """
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.Attribute):
        if node.attr in fields:
            return True
        return node.attr not in _SAFE_ATTRIBUTES and _carries(node.value, names, fields)
    if isinstance(node, ast.Compare):
        return False
    if isinstance(node, ast.IfExp):
        return _carries(node.body, names, fields) or _carries(node.orelse, names, fields)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in _NO_TEXT_CALLS:
            return False
        # ``obj.error("text")`` calls a method; it does not read a field named ``error``.
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr not in _SAFE_ATTRIBUTES
            and _carries(node.func.value, names, fields)
        ):
            return True
        return any(_carries(arg, names, fields) for arg in node.args) or any(
            _carries(keyword.value, names, fields) for keyword in node.keywords
        )
    return any(_carries(child, names, fields) for child in ast.iter_child_nodes(node))


def _caught(kind: ast.expr | None) -> tuple[str, ...]:
    """
    Args:
        kind (ast.expr | None): The type of an ``except`` clause.

    Returns:
        tuple[str, ...]: The last name of each class caught; ``<any>`` for a bare ``except:``.
    """
    if kind is None:
        return ("<any>",)
    items = kind.elts if isinstance(kind, ast.Tuple) else [kind]
    return tuple(dotted(item).rsplit(".", 1)[-1] for item in items)


def _classify(call: ast.Call) -> str:
    """
    Args:
        call (ast.Call): The call that receives the text.

    Returns:
        str: ``log``, ``terminal``, ``collection`` or ``call``.
    """
    name = dotted(call.func)
    last = name.rsplit(".", 1)[-1]
    if "." in name and last in _LOGGER_METHODS and re.search(r"log", name, re.IGNORECASE):
        return "log"
    if last in _TERMINAL_CALLS:
        return "terminal"
    if last in _COLLECTION_METHODS:
        return "collection"
    return "call"


def _assignment(node: ast.AST) -> tuple[str | None, ast.expr | None]:
    """
    Args:
        node (ast.AST): Any node.

    Returns:
        tuple[str | None, ast.expr | None]: The plain name assigned and the value, or two Nones.
    """
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
        if isinstance(target, ast.Name):
            return target.id, node.value
    if isinstance(node, ast.AnnAssign | ast.AugAssign) and isinstance(node.target, ast.Name):
        return node.target.id, node.value
    if isinstance(node, ast.NamedExpr):
        return node.target.id, node.value
    return None, None


def _is_dynamic_text(node: ast.expr) -> bool:
    """
    Args:
        node (ast.expr): An argument of a raised exception.

    Returns:
        bool: Whether it builds text from a value: an f-string, ``.format`` or ``%`` / ``+`` on
            a string literal.
    """
    for part in ast.walk(node):
        if isinstance(part, ast.FormattedValue):
            return True
        if (
            isinstance(part, ast.Call)
            and isinstance(part.func, ast.Attribute)
            and part.func.attr == "format"
            and isinstance(part.func.value, ast.Constant)
        ):
            return True
        if isinstance(part, ast.BinOp) and isinstance(part.op, ast.Mod | ast.Add):
            sides = (part.left, part.right)
            if any(isinstance(s, ast.Constant) and isinstance(s.value, str) for s in sides) and any(
                not isinstance(s, ast.Constant) for s in sides
            ):
                return True
    return False


def _matches(name: str, pattern: str) -> bool:
    """
    Args:
        name (str): The dotted name of a call.
        pattern (str): A name of :data:`OPERATIONS`.

    Returns:
        bool: Whether the call is that operation.
    """
    if pattern.startswith("."):
        return name.endswith(pattern)
    if pattern in _BUILTINS_ONLY:
        return name == pattern
    return name == pattern or name.endswith(f".{pattern}")


# ---------------------------------------------------------------------------
# Python: one file
# ---------------------------------------------------------------------------


@dataclass
class _Scope:
    """
    The nodes of one scope, without the nodes of the scopes inside it.

    Attributes:
        qualname (str): ``<module>``, ``Class``, ``function`` or ``Class.method``.
        nodes (list[ast.AST]): The scope's nodes.
        handlers (list[tuple[ast.ExceptHandler, list[ast.AST]]]): Each ``except`` clause with its
            nodes in this scope.
    """

    qualname: str
    nodes: list[ast.AST]
    handlers: list[tuple[ast.ExceptHandler, list[ast.AST]]]


def _scopes(tree: ast.Module) -> list[_Scope]:
    """
    Args:
        tree (ast.Module): A module.

    Returns:
        list[_Scope]: The module, every class body and every function, each node in exactly one.
    """
    scopes: list[_Scope] = []

    def visit(owner: ast.AST, qualname: str, body: Iterable[ast.AST]) -> None:
        nodes: list[ast.AST] = []
        stack = list(body)
        while stack:
            node = stack.pop()
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                inner = {id(statement) for statement in node.body}
                # Decorators, defaults, annotations and bases run in the scope around the def.
                stack.extend(c for c in ast.iter_child_nodes(node) if id(c) not in inner)
                name = node.name if qualname == "<module>" else f"{qualname}.{node.name}"
                visit(node, name, node.body)
                continue
            nodes.append(node)
            stack.extend(ast.iter_child_nodes(node))
        ids = {id(node) for node in nodes}
        handlers = [
            (node, [n for n in ast.walk(node) if id(n) in ids])
            for node in nodes
            if isinstance(node, ast.ExceptHandler)
        ]
        nodes.sort(key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0)))
        scopes.append(_Scope(qualname, nodes, handlers))

    visit(tree, "<module>", tree.body)
    return scopes


class _PythonFile:
    """The points of one Python file."""

    def __init__(self, path: str, source: str) -> None:
        """
        Args:
            path (str): The file, relative to the repository root.
            source (str): Its code.
        """
        self.path = path
        self.module = _module_name(path)
        self.source = source
        self.tree = ast.parse(source)
        self.scopes = _scopes(self.tree)
        self.fields: frozenset[str] = frozenset()
        self.points: list[Point] = []

    @property
    def calls(self) -> int:
        """
        Returns:
            int: The calls in every scope of the file.
        """
        return sum(isinstance(n, ast.Call) for scope in self.scopes for n in scope.nodes)

    def carries(self, node: ast.AST | None, names: set[str]) -> bool:
        """
        Args:
            node (ast.AST | None): An expression.
            names (set[str]): The names with exception text.

        Returns:
            bool: Whether the expression can repeat exception text, by name or by field.
        """
        return _carries(node, names, self.fields)

    def text_names(self, scope: _Scope) -> dict[str, tuple[str, ...]]:
        """
        Args:
            scope (_Scope): A scope.

        Returns:
            dict[str, tuple[str, ...]]: Each name assigned exception text in a handler, with the
                exceptions it came from.
        """
        origin: dict[str, tuple[str, ...]] = {}
        changed = True
        while changed:  # ``last = f"{exc}"`` in one handler, ``raise X(last)`` after the loop
            changed = False
            for handler, nodes in scope.handlers:
                names = set(origin) | ({handler.name} if handler.name else set())
                for node in nodes:
                    target, value = _assignment(node)
                    if target and target not in origin and self.carries(value, names):
                        origin[target] = _caught(handler.type)
                        changed = True
        return origin

    def sends(self) -> tuple[set[str], set[tuple[str, int | str]]]:
        """
        Returns:
            tuple[set[str], set[tuple[str, int | str]]]: The fields assigned exception text, and
                each ``(function called, argument)`` that receives it.
        """
        fields: set[str] = set()
        calls: set[tuple[str, int | str]] = set()
        for scope in self.scopes:
            names = set(self.text_names(scope)) | {h.name for h, _ in scope.handlers if h.name}
            for node in scope.nodes:
                if isinstance(node, ast.Assign | ast.AnnAssign) and self.carries(node.value, names):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    fields |= {t.attr for t in targets if isinstance(t, ast.Attribute)}
                if isinstance(node, ast.Call):
                    called = dotted(node.func).rsplit(".", 1)[-1]
                    for index, argument in enumerate(node.args):
                        if self.carries(argument, names):
                            calls.add((called, index))
                    for keyword in node.keywords:
                        if keyword.arg and self.carries(keyword.value, names):
                            calls.add((called, keyword.arg))
                            fields.add(keyword.arg)
        return fields, calls

    def walk(self) -> list[Point]:
        """
        Returns:
            list[Point]: The points of every scope.
        """
        for scope in self.scopes:
            self.errors(scope)
            self.operations(scope)
            self.messages(scope)
        return self.points

    def add(self, family: str, scope: _Scope, node: ast.AST, callee: str) -> None:
        """
        Args:
            family (str): The point's family.
            scope (_Scope): Its scope.
            node (ast.AST): Its node.
            callee (str): Its call or output.
        """
        snippet = " ".join((ast.get_source_segment(self.source, node) or "").split())[:120]
        self.points.append(
            Point(
                family,
                self.path,
                getattr(node, "lineno", 0),
                getattr(node, "col_offset", 0),
                f"{self.module}:{scope.qualname}",
                callee,
                snippet,
            )
        )

    def errors(self, scope: _Scope) -> None:
        """
        Records every statement that takes exception text to an output.

        Args:
            scope (_Scope): A scope.
        """
        origin = self.text_names(scope)
        for node in scope.nodes:
            if isinstance(node, ast.Call) and dotted(node.func).endswith(_TRACEBACK_CALLS):
                self.add("error", scope, node, f"traceback:{dotted(node.func)}")
        seen: set[int] = set()
        for handler, nodes in scope.handlers:
            names = set(origin) | ({handler.name} if handler.name else set())
            for node in nodes:
                if (
                    isinstance(node, ast.Call)
                    and id(node) not in seen
                    and _classify(node) == "log"
                    and (
                        dotted(node.func).endswith(".exception")
                        or any(k.arg == "exc_info" for k in node.keywords)
                    )
                ):
                    seen.add(id(node))
                    self.add("error", scope, node, f"log-traceback:{dotted(node.func)}")
            for node in nodes:
                fresh = isinstance(node, ast.stmt) and id(node) not in seen
                if fresh and self.output(scope, node, names, seen):
                    seen.add(id(node))
        inside = {id(n) for _, nodes in scope.handlers for n in nodes}
        if origin or self.fields:
            for node in scope.nodes:
                if isinstance(node, ast.stmt) and id(node) not in inside:
                    self.output(scope, node, set(origin), seen)

    def output(self, scope: _Scope, node: ast.stmt, names: set[str], seen: set[int]) -> bool:
        """
        Args:
            scope (_Scope): The scope.
            node (ast.stmt): A statement.
            names (set[str]): The names with exception text.
            seen (set[int]): The calls already recorded as a logged traceback.

        Returns:
            bool: Whether the statement took the text to an output and was recorded.
        """
        if isinstance(node, ast.Raise) and self.carries(node.exc, names):
            target = dotted(node.exc.func) if isinstance(node.exc, ast.Call) else ""
            self.add("error", scope, node, f"raise:{target}" if target else "raise")
            return True
        if isinstance(node, ast.Return) and self.carries(node.value, names):
            self.add("error", scope, node, "return")
            return True
        if isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Attribute | ast.Subscript) for t in targets) and self.carries(
                node.value, names
            ):
                self.add("error", scope, node, "field")
                return True
            if isinstance(node.value, ast.Call) and self.carries(node.value, names):
                called = dotted(node.value.func)
                if called.rsplit(".", 1)[-1] not in _TEXT_BUILDERS:
                    self.add("error", scope, node, f"call:{called}")
                    return True
            return False
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Await | ast.Call):
            call = node.value.value if isinstance(node.value, ast.Await) else node.value
            if isinstance(call, ast.Call) and id(call) not in seen and self.carries(call, names):
                self.add("error", scope, node, f"{_classify(call)}:{dotted(call.func)}")
                return True
        return False

    def messages(self, scope: _Scope) -> None:
        """
        Records an exception raised with a message built from a dynamic value.

        The words are the project's, but the value may come from the site, a file or the
        configuration.

        Args:
            scope (_Scope): A scope.
        """
        here = f"{self.module}:{scope.qualname}"
        lines = {p.line for p in self.points if p.family == "error" and p.scope == here}
        for node in scope.nodes:
            if not (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)):
                continue
            if node.lineno in lines:
                continue
            arguments = [*node.exc.args, *(k.value for k in node.exc.keywords)]
            if any(_is_dynamic_text(argument) for argument in arguments):
                self.add("message", scope, node, dotted(node.exc.func))

    def operations(self, scope: _Scope) -> None:
        """
        Records every call of a dangerous operation and every certificate check turned off.

        Args:
            scope (_Scope): A scope.
        """
        for node in scope.nodes:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr in _TLS_OFF
                        and isinstance(node.value, ast.Constant)
                        and node.value.value is False
                    ):
                        self.add("crypto", scope, node, f"{target.attr}=False")
            if not isinstance(node, ast.Call):
                continue
            name = dotted(node.func)
            for pattern, family, dynamic in OPERATIONS:
                if not _matches(name, pattern):
                    continue
                if not (dynamic and node.args and isinstance(node.args[0], ast.Constant)):
                    self.add(family, scope, node, name)
                break
            for keyword in node.keywords:
                if (
                    keyword.arg in _TLS_OFF
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                ):
                    self.add("crypto", scope, node, f"{keyword.arg}=False")


def _module_name(path: str) -> str:
    """
    Args:
        path (str): A Python file under ``src/``.

    Returns:
        str: Its dotted module name (``src/webvigil/api/__init__.py`` is ``webvigil.api``).
    """
    parts = Path(path).with_suffix("").parts
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _carrier_fields(files: list[_PythonFile]) -> frozenset[str]:
    """
    Finds, to a fixed point and across files, the object attributes that hold exception text.

    Args:
        files (list[_PythonFile]): One walker per file.

    Returns:
        frozenset[str]: The attribute names.
    """
    functions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for file in files:
        for node in ast.walk(file.tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                functions.setdefault(node.name, []).append(node)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == "__init__":
                        functions.setdefault(node.name, []).append(item)
    fields: set[str] = set()
    while True:
        new: set[str] = set()
        for file in files:
            file.fields = frozenset(fields)
            assigned, calls = file.sends()
            new |= assigned
            for called, argument in calls:
                for function in functions.get(called, ()):
                    parameters = [a.arg for a in function.args.posonlyargs + function.args.args]
                    parameters = [p for p in parameters if p not in {"self", "cls"}]
                    if isinstance(argument, int):
                        if argument >= len(parameters):
                            continue
                        parameter = parameters[argument]
                    else:
                        parameter = argument
                    for node in ast.walk(function):
                        if (
                            isinstance(node, ast.Assign | ast.AnnAssign)
                            and isinstance(node.value, ast.Name)
                            and node.value.id == parameter
                        ):
                            targets = (
                                node.targets if isinstance(node, ast.Assign) else [node.target]
                            )
                            new |= {t.attr for t in targets if isinstance(t, ast.Attribute)}
                        if isinstance(node, ast.Call):
                            new |= {
                                k.arg
                                for k in node.keywords
                                if k.arg
                                and isinstance(k.value, ast.Name)
                                and k.value.id == parameter
                            }
        new -= _SAFE_ATTRIBUTES
        if new <= fields:
            return frozenset(fields)
        fields |= new


# ---------------------------------------------------------------------------
# The dashboard: one file
# ---------------------------------------------------------------------------


def _block_end(source: str, start: int) -> int:
    """
    Args:
        source (str): The file.
        start (int): The index of an opening ``{``.

    Returns:
        int: The index of the ``}`` that closes it, or the end of the file.
    """
    depth = 0
    for index in range(start, len(source)):
        depth += {"{": 1, "}": -1}.get(source[index], 0)
        if depth == 0:
            return index
    return len(source)


def _walk_dashboard(path: str, source: str) -> list[Point]:
    """
    Args:
        path (str): The file, relative to the repository root.
        source (str): Its code.

    Returns:
        list[Point]: The operations, and every use of a caught error's text.
    """
    points: list[Point] = []
    lines = source.splitlines()

    def add(family: str, number: int, column: int, match: str) -> None:
        snippet = " ".join(lines[number - 1].split())[:120]
        points.append(Point(family, path, number, column, path, " ".join(match.split()), snippet))

    for number, line in enumerate(lines, start=1):
        for family, pattern in DASHBOARD_PATTERNS:
            for match in pattern.finditer(line):
                add(family, number, match.start(), match.group(0))
    for caught in _CAUGHT.finditer(source):
        name = caught.group(1) or caught.group(2)
        start = caught.end()
        rest = source[start:].lstrip()
        if rest.startswith("{"):
            brace = source.index("{", start)
            region = (brace, _block_end(source, brace))
        else:  # an arrow with an expression body: the rest of the line
            end = source.find("\n", start)
            region = (start, len(source) if end < 0 else end)
        use = re.compile(
            rf"\b{name}\.(?:message|stack|cause)\b|\$\{{\s*{name}\b|String\(\s*{name}\b"
            rf"|\(\s*{name}\s*[,)]"
        )
        for match in use.finditer(source, *region):
            number = source.count("\n", 0, match.start()) + 1
            column = match.start() - (source.rfind("\n", 0, match.start()) + 1)
            add("error", number, column, match.group(0))
    return points


# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------


def walk(files: Mapping[str, str]) -> Inventory:
    """
    Args:
        files (Mapping[str, str]): Each path, relative to the repository root, with its code.

    Returns:
        Inventory: Every point by key, and what was read.
    """
    points: list[Point] = []
    python: list[_PythonFile] = []
    unparsed: list[str] = []
    lines_read = 0
    for path, source in files.items():
        if path.endswith(".py"):
            try:
                python.append(_PythonFile(path, source))
            except (SyntaxError, ValueError):
                unparsed.append(path)
        elif path.endswith(_DASHBOARD_SUFFIXES):
            points.extend(_walk_dashboard(path, source))
            lines_read += len(source.splitlines())
    fields = _carrier_fields(python)
    for file in python:
        file.fields = fields
        points.extend(file.walk())
    unique = {(p.family, p.path, p.line, p.column, p.callee): p for p in points}
    ordered = sorted(unique.values(), key=lambda p: (p.path, p.line, p.column, p.family, p.callee))
    repeats: Counter[str] = Counter()
    keyed: dict[str, Point] = {}
    for point in ordered:
        repeats[point.base_key] += 1
        count = repeats[point.base_key]
        keyed[point.base_key if count == 1 else f"{point.base_key}#{count}"] = point
    return Inventory(keyed, sum(f.calls for f in python), lines_read, tuple(sorted(unparsed)))


def tracked_files(root: Path = ROOT) -> dict[str, str]:
    """
    Args:
        root (Path): The repository root.

    Returns:
        dict[str, str]: Every file ``git ls-files`` lists under :data:`READ_UNDER`, without
            tests, vendored data and generated files, with its code.
    """
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", *READ_UNDER],
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    files: dict[str, str] = {}
    for path in listed.split("\0"):
        if path.endswith((".py", *_DASHBOARD_SUFFIXES)) and not _EXCLUDED.search(path):
            target = root / path
            if target.is_file():
                files[path] = target.read_text("utf-8")
    return files
