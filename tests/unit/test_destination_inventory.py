"""
The destination inventory of spec 026 (RF-09, ADR-7): every destination decision is a known site.

Every module under ``src/webvigil`` is parsed (never imported), and three kinds of site are
recorded as ``module:qualname`` of the function around them:

* **rule calls**, a call of an attribute named ``in_scope`` or ``carries_credentials``. They are
  allowed only in ``webvigil.core.destination``, so every pass asks the policy module;
* **destination comparisons**, a comparison with an operand that is an attribute named ``host``,
  ``hostname``, ``scheme``, ``port``, ``origin`` or ``netloc``. Outside ``core/destination.py`` and
  ``core/target.py``, each one must be in :data:`COMPARISONS` with the reason it decides no
  destination;
* **network openings**, a call of ``AsyncClient``, ``Client``, ``create_connection``, ``socket``,
  ``getaddrinfo``, ``open_connection`` or ``urlopen``. Each one must be in :data:`CONNECTIONS` with
  the reason it is safe.

An unlisted site fails, and so does a listed site with no matching call left. A comparison
through a local variable (``host = parts.hostname; host == x``) is not seen (ADR-7); the behavioural
tests of RF-03 to RF-05 cover what it would send. The positive controls run the walk over a
throwaway source, so a walk that stopped seeing sites cannot pass.
"""

from __future__ import annotations

import ast
import dataclasses
from collections.abc import Mapping
from pathlib import Path
from typing import Final

import webvigil

# The package the walk parses, the module that may call the two rules, and the modules whose
# comparisons are the rules themselves.
SRC: Final = Path(webvigil.__file__).parent
POLICY_MODULE: Final = "webvigil.core.destination"
RULE_MODULES: Final = frozenset({POLICY_MODULE, "webvigil.core.target"})

# ---------------------------------------------------------------------------
# The inventory
# ---------------------------------------------------------------------------

# Every destination comparison outside the two rule modules, as ``module:qualname``, with the
# reason it decides no destination. A new one is a new line here, in the pull request that adds it.
COMPARISONS: Final[Mapping[str, str]] = {
    "webvigil.checks.disclosure.probe:DisclosureProbe._targets": (
        "reads the host's first label to name backup files; every candidate URL is then asked "
        "of may_request"
    ),
    "webvigil.checks.tls.check:TlsHttpsCheck.run": (
        "whether the entry URL and the page it landed on are https: it chooses a finding, and "
        "sends nothing"
    ),
    "webvigil.crawler.har:load_har": (
        "a parsing rule: an entry must be http(s) and use the target's scheme, narrower than "
        "may_request, which is asked next"
    ),
    "webvigil.crawler.har:_operation": (
        "the default port of the entry's scheme, to drop it from the rebuilt URL"
    ),
    "webvigil.http.session:_jar_view": (
        "a cookie rule: a Secure cookie that arrived over plain http is not kept; the response "
        "was already allowed by may_carry_credentials"
    ),
    "webvigil.http.tls:pin_proxy_trust": (
        "whether the proxy itself is https, to give its connection the trust store"
    ),
}

# Every network opening of the package, as ``module:qualname``, with the reason it is safe.
CONNECTIONS: Final[Mapping[str, str]] = {
    "webvigil.http.client:HttpClient.__aenter__": (
        "the scan client: every request asks may_request, and credentials go only where "
        "may_carry_credentials allows"
    ),
    "webvigil.checks.deps.osv:OsvProvider._client": (
        "the OSV.dev client: its own headers (the User-Agent), package names and versions, no "
        "credential and no target data (RF-05)"
    ),
    "webvigil.http.tls_probe:_handshake": (
        "the TLS probe's socket, opened to an address the address guard returned for the target"
    ),
    "webvigil.http.addresses:system_resolver": (
        "the system resolver behind the address guard; it sends a name, no request"
    ),
    "webvigil.api.client_address:_resolve_name": (
        "the Web API resolving the names of web.trusted_proxies at start-up; no scan data"
    ),
}

# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------

# The names that make a site, by kind (ADR-7).
_RULES: Final = frozenset({"in_scope", "carries_credentials"})
_DESTINATION_ATTRIBUTES: Final = frozenset(
    {"host", "hostname", "scheme", "port", "origin", "netloc"}
)
_OPENINGS: Final = frozenset(
    {
        "AsyncClient",
        "Client",
        "create_connection",
        "socket",
        "getaddrinfo",
        "open_connection",
        "urlopen",
    }
)


@dataclasses.dataclass
class _Walk:
    """
    What one module's syntax tree holds.

    Attributes:
        rules (set[str]): Every ``module:qualname`` that calls one of the two rules.
        comparisons (set[str]): Every site with a destination comparison, outside the rule
            modules.
        connections (set[str]): Every site with a network opening.
    """

    rules: set[str] = dataclasses.field(default_factory=set)
    comparisons: set[str] = dataclasses.field(default_factory=set)
    connections: set[str] = dataclasses.field(default_factory=set)

    def merge(self, other: _Walk) -> None:
        """
        Args:
            other (_Walk): Another module's walk, added to this one.
        """
        self.rules |= other.rules
        self.comparisons |= other.comparisons
        self.connections |= other.connections


def _called_name(func: ast.expr) -> str:
    """
    Args:
        func (ast.expr): What a call calls.

    Returns:
        str: The last name of it (``getaddrinfo`` for ``loop.getaddrinfo``), whatever the
            receiver, or ``""`` for anything else.
    """
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _compares_a_destination(node: ast.Compare) -> bool:
    """
    Args:
        node (ast.Compare): A comparison.

    Returns:
        bool: Whether one of its operands is an attribute named after a part of a destination.
    """
    operands = [node.left, *node.comparators]
    return any(
        isinstance(operand, ast.Attribute) and operand.attr in _DESTINATION_ATTRIBUTES
        for operand in operands
    )


class _DestinationVisitor(ast.NodeVisitor):
    """
    Records the destination sites of a module with the qualified name of their function.

    Args:
        module (str): The module's dotted name.
        walk (_Walk): Where the findings go.
    """

    def __init__(self, module: str, walk: _Walk) -> None:
        self._module = module
        self._walk = walk
        self._scope: list[str] = []

    def _site(self) -> str:
        """
        Returns:
            str: The current site, ``module:qualname`` (``<module>`` at the top level).
        """
        return f"{self._module}:{'.'.join(self._scope) or '<module>'}"

    def _scoped(self, name: str, node: ast.AST) -> None:
        """
        Visit a node with its name on the scope, so the sites inside are its own.

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
        """Record a rule call (an attribute named after a rule) and a network opening."""
        name = _called_name(node.func)
        if name in _RULES and isinstance(node.func, ast.Attribute):
            self._walk.rules.add(self._site())
        if name in _OPENINGS:
            self._walk.connections.add(self._site())
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        """Record a destination comparison outside the two rule modules."""
        if self._module not in RULE_MODULES and _compares_a_destination(node):
            self._walk.comparisons.add(self._site())
        self.generic_visit(node)


def walk_source(source: str, module: str) -> _Walk:
    """
    Args:
        source (str): A module's source.
        module (str): Its dotted name.

    Returns:
        _Walk: Its rule calls, destination comparisons and network openings.
    """
    walk = _Walk()
    _DestinationVisitor(module, walk).visit(ast.parse(source))
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
        source = path.read_text(encoding="utf-8")
        merged.merge(walk_source(source, _module_name(path, root, package)))
    return merged, len(paths)


def stray_rule_calls(rules: set[str]) -> set[str]:
    """
    Args:
        rules (set[str]): The rule-call sites the walk found.

    Returns:
        set[str]: Those outside the policy module.
    """
    return {site for site in rules if site.split(":", 1)[0] != POLICY_MODULE}


def inventory_problems(sites: set[str], allowed: Mapping[str, str]) -> tuple[set[str], set[str]]:
    """
    Args:
        sites (set[str]): The sites of one kind the walk found.
        allowed (Mapping[str, str]): The inventory of that kind.

    Returns:
        tuple[set[str], set[str]]: The sites missing from the inventory, and the inventoried sites
            with no matching call or comparison left.
    """
    return sites - allowed.keys(), allowed.keys() - sites


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------


def test_only_the_policy_module_asks_the_two_rules() -> None:
    """Every pass asks ``core/destination.py``; the policy module itself is seen asking both."""
    walk, parsed = walk_package()
    assert parsed > 100  # the walk read the package
    assert {
        f"{POLICY_MODULE}:may_request",
        f"{POLICY_MODULE}:may_carry_credentials",
    } <= walk.rules  # the positive control: the walk sees the two calls that are allowed
    assert not stray_rule_calls(walk.rules), sorted(stray_rule_calls(walk.rules))


def test_every_destination_comparison_is_in_the_inventory() -> None:
    """The comparison sites outside the rule modules are exactly the inventoried ones."""
    walk, _ = walk_package()
    unlisted, stale = inventory_problems(walk.comparisons, COMPARISONS)
    assert not unlisted, f"destination comparison outside COMPARISONS: {sorted(unlisted)}"
    assert not stale, f"COMPARISONS sites with no comparison left: {sorted(stale)}"


def test_every_network_opening_is_in_the_inventory() -> None:
    """The network openings of the package are exactly the inventoried ones."""
    walk, _ = walk_package()
    unlisted, stale = inventory_problems(walk.connections, CONNECTIONS)
    assert not unlisted, f"network opening outside CONNECTIONS: {sorted(unlisted)}"
    assert not stale, f"CONNECTIONS sites with no opening left: {sorted(stale)}"


def test_every_inventoried_site_says_why() -> None:
    """Each line of both inventories carries a reason."""
    assert all(reason.strip() for reason in (*COMPARISONS.values(), *CONNECTIONS.values()))


# A source the walk reads and never imports: each kind of site, in a function, a method and a
# lambda, next to look-alikes the walk must leave alone.
_THROWAWAY = """
import asyncio
import socket
import urllib.request

import httpx2

from webvigil.core.destination import may_request


def asks_the_policy(target, url):
    return may_request(target, url)


def asks_the_target(target, url):
    return target.in_scope(url)


class Pass:
    def credentials(self, url):
        return self._target.carries_credentials(url)

    def compares(self, parts, target):
        return parts.hostname == target.host

    def through_a_name(self, parts, target):
        host = parts.hostname
        return host == "example.com"


def opens(url):
    client = httpx2.AsyncClient()
    sync = httpx2.Client()
    raw = socket.create_connection(("example.com", 443))
    bare = socket.socket()
    addresses = asyncio.get_running_loop().getaddrinfo("example.com", 443)
    stream = asyncio.open_connection("example.com", 443)
    return urllib.request.urlopen(url)


lazy = lambda parts: parts.scheme != "https"
"""

_MODULE: Final = "webvigil.checks.throwaway"


def test_the_walk_sees_a_rule_call_outside_the_policy() -> None:
    """Positive control: an unlisted ``in_scope`` or ``carries_credentials`` call fails."""
    walk = walk_source(_THROWAWAY, _MODULE)
    assert walk.rules == {f"{_MODULE}:asks_the_target", f"{_MODULE}:Pass.credentials"}
    assert stray_rule_calls(walk.rules) == walk.rules
    assert stray_rule_calls(walk_source(_THROWAWAY, POLICY_MODULE).rules) == set()


def test_the_walk_sees_a_destination_comparison() -> None:
    """Positive control: an unlisted ``parts.hostname == x`` fails; a local variable is not seen."""
    walk = walk_source(_THROWAWAY, _MODULE)
    assert walk.comparisons == {f"{_MODULE}:Pass.compares", f"{_MODULE}:<lambda>"}
    assert inventory_problems(walk.comparisons, COMPARISONS)[0] == walk.comparisons
    # the rule modules compare destinations by design: none of their comparisons is recorded
    for module in RULE_MODULES:
        assert walk_source(_THROWAWAY, module).comparisons == set()


def test_the_walk_sees_every_kind_of_network_opening() -> None:
    """Positive control: an unlisted ``httpx2.AsyncClient(...)`` (and each other opening) fails."""
    walk = walk_source(_THROWAWAY, _MODULE)
    assert walk.connections == {f"{_MODULE}:opens"}
    assert inventory_problems(walk.connections, CONNECTIONS)[0] == {f"{_MODULE}:opens"}
    for opening in (
        "httpx2.AsyncClient()",
        "httpx2.Client()",
        "socket.create_connection(address)",
        "socket.socket()",
        "loop.getaddrinfo(host, port)",
        "asyncio.open_connection(host, port)",
        "urlopen(url)",
    ):
        source = f"def one(address, loop, host, port, url):\n    return {opening}\n"
        assert walk_source(source, _MODULE).connections == {f"{_MODULE}:one"}, opening


def test_a_stale_entry_fails(tmp_path: Path) -> None:
    """Positive control over a throwaway package: a listed site with nothing left is reported."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "__init__.py").write_text("def top(parts):\n    return parts.port == 443\n")
    (tmp_path / "sub" / "__init__.py").write_text("")
    (tmp_path / "sub" / "net.py").write_text(
        "import httpx2\n\ndef run():\n    return httpx2.AsyncClient()\n"
    )
    walk, parsed = walk_package(tmp_path, "pkg")
    assert parsed == 3
    assert walk.comparisons == {"pkg:top"}
    assert walk.connections == {"pkg.sub.net:run"}
    allowed = {"pkg:top": "a reason", "pkg.sub.net:gone": "a reason"}
    assert inventory_problems(walk.comparisons | walk.connections, allowed) == (
        {"pkg.sub.net:run"},
        {"pkg.sub.net:gone"},
    )
