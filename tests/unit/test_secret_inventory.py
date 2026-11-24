"""
The two gates of spec 024: the reveal inventory (ADR-3) and the credential-field gate (ADR-4).

**Reveal inventory.** Every module under ``src/webvigil`` is parsed (never imported) and every call
of an attribute named ``reveal`` is recorded as ``module:qualname`` of the function around it. The
set must equal :data:`ALLOWED_REVEALS`, whose entries say why each site needs the value: an unlisted
call fails, and so does a listed site with no call left. Outside ``core/secrets.py`` the walk also
refuses the other ways to the value: a ``.reveal`` that is not called (an alias), any ``._value``,
and the strings ``"reveal"`` and ``"_value"`` (``getattr``, ``attrgetter``).

**Credential-field gate.** Every module of the engine and the Web API is imported (the suite runs
with every extra) and every pydantic model and dataclass defined there is listed. A field fails
when its name has a credential word and its annotation has ``str`` but no ``Secret``, unless its
name ends in a word that describes a credential rather than holding one. :data:`DECLARED` adds the
fields whose names do not say so, :data:`EXEMPT` lists the matches that hold no credential, with
the reason, and :data:`PENDING_CONVERSION` the credentials the later stages of the spec convert;
each stage removes its own, and an entry that already holds a ``Secret`` fails.

Each gate has positive controls over a throwaway source or model defined here, so a gate that
stopped seeing anything cannot pass.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib
import inspect
import pkgutil
import re
import typing
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Annotated, Any, Final, Literal

import pytest
from pydantic import BaseModel

import webvigil
from webvigil.core.secrets import Secret, SecretKind, secret_field

SRC: Final = Path(webvigil.__file__).parent
SECRETS_MODULE: Final = "webvigil.core.secrets"

# ---------------------------------------------------------------------------
# The inventories
# ---------------------------------------------------------------------------

# Every site that reads a secret's value, as ``module:qualname``, with the reason it needs it.
# A new sink is a new line here, in the pull request that adds it, so a reviewer sees it.
ALLOWED_REVEALS: Final[Mapping[str, str]] = {}

# A field whose name does not say it holds a credential, checked as if it did.
DECLARED: Final[frozenset[str]] = frozenset(
    {
        "core.config:AuthSection.headers",
        "auth.login:CookieTransition.pre",
        "auth.login:CookieTransition.post",
    }
)

# A field whose name matches but holds no credential, with the reason.
EXEMPT: Final[Mapping[str, str]] = {
    "core.findings:Location.cookie": "the name of the cookie a finding is about, never its value",
    "api.schemas:LocationOut.cookie": "the API's copy of Location.cookie: a cookie name",
    "checks.injection.models:StoredMarker.token": (
        "the scanner's own random marker for stored XSS, not a credential"
    ),
}

# The credentials still typed ``str``, which spec 024 converts. A converted field leaves this set in
# the same change, and the set goes when it is empty.
PENDING_CONVERSION: Final[frozenset[str]] = frozenset(
    {
        # the scan's configured credentials
        "core.config:AuthSection.cookies",
        "core.config:AuthSection.headers",
        "auth.login:Credentials.password",
        # session values
        "auth.login:CookieTransition.pre",
        "auth.login:CookieTransition.post",
        # the Web API
        "api.config:WebConfig.session_secret",
        "api.schemas:SetupIn.password",
        "api.schemas:LoginIn.password",
        "api.schemas:PasswordChangeIn.current_password",
        "api.schemas:PasswordChangeIn.new_password",
    }
)

# A word that marks a field as holding a credential, and the endings that describe one instead
# (the name of an environment variable, a form field, a hash, a cookie name, a URL, a lifetime).
CREDENTIAL_WORDS: Final = (
    "password",
    "secret",
    "token",
    "cookie",
    "credential",
    "apikey",
    "api_key",
)
EXEMPT_ENDINGS: Final = (
    "env",
    "field",
    "fields",
    "hash",
    "name",
    "names",
    "marker",
    "url",
    "secure",
    "ttl",
    "hours",
)

# ---------------------------------------------------------------------------
# Reveal inventory: the walk
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _Walk:
    """
    What one module's syntax tree holds.

    Attributes:
        sites (set[str]): Every ``module:qualname`` with a ``reveal()`` call.
        refused (list[str]): Every other way to the value, as ``module:line: what``.
    """

    sites: set[str] = dataclasses.field(default_factory=set)
    refused: list[str] = dataclasses.field(default_factory=list)


class _RevealVisitor(ast.NodeVisitor):
    """
    Records the reveal calls of a module with the qualified name of their function.

    Args:
        module (str): The module's dotted name.
        walk (_Walk): Where the findings go.
    """

    def __init__(self, module: str, walk: _Walk) -> None:
        self._module = module
        self._walk = walk
        self._scope: list[str] = []
        self._called: set[int] = set()
        self._own = module == SECRETS_MODULE

    def _site(self) -> str:
        return f"{self._module}:{'.'.join(self._scope) or '<module>'}"

    def _refuse(self, node: ast.AST, what: str) -> None:
        line = getattr(node, "lineno", 0)
        self._walk.refused.append(f"{self._module}:{line}: {what}")

    def _scoped(self, name: str, node: ast.AST) -> None:
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
        if isinstance(node.func, ast.Attribute) and node.func.attr == "reveal":
            self._walk.sites.add(self._site())
            self._called.add(id(node.func))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if not self._own:
            if node.attr == "reveal" and id(node) not in self._called:
                self._refuse(node, ".reveal without a call")
            if node.attr == "_value":
                self._refuse(node, "._value")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if not self._own and node.value in {"reveal", "_value"}:
            self._refuse(node, f"the string {node.value!r}")


def walk_source(source: str, module: str) -> _Walk:
    """
    Args:
        source (str): A module's source.
        module (str): Its dotted name.

    Returns:
        _Walk: Its reveal sites and its refused references.
    """
    walk = _Walk()
    _RevealVisitor(module, walk).visit(ast.parse(source))
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
        merged.refused += walk.refused
    return merged, len(paths)


def inventory_problems(sites: set[str], allowed: Mapping[str, str]) -> tuple[set[str], set[str]]:
    """
    Args:
        sites (set[str]): The reveal sites the walk found.
        allowed (Mapping[str, str]): The inventory.

    Returns:
        tuple[set[str], set[str]]: The sites missing from the inventory, and the inventoried sites
            with no call left.
    """
    return sites - allowed.keys(), allowed.keys() - sites


# ---------------------------------------------------------------------------
# Reveal inventory: the tests
# ---------------------------------------------------------------------------


def test_every_reveal_is_in_the_inventory() -> None:
    """The reveal calls of the source are exactly the inventoried sites, none missing or stale."""
    walk, parsed = walk_package()
    assert parsed > 100  # the walk read the package, so an empty result means something
    unlisted, stale = inventory_problems(walk.sites, ALLOWED_REVEALS)
    assert not unlisted, f"reveal() outside ALLOWED_REVEALS: {sorted(unlisted)}"
    assert not stale, f"ALLOWED_REVEALS sites with no reveal() left: {sorted(stale)}"


def test_every_inventoried_site_says_why() -> None:
    """Each line of the inventory and of the exemptions carries a reason."""
    assert all(reason.strip() for reason in ALLOWED_REVEALS.values())
    assert all(reason.strip() for reason in EXEMPT.values())


def test_there_is_no_other_way_to_the_value() -> None:
    """No alias of ``reveal``, no ``_value`` and no lookup by name outside ``core/secrets.py``."""
    walk, _ = walk_package()
    assert walk.refused == []


_THROWAWAY = """
def module_level(secret):
    return secret.reveal()


class Client:
    def send(self, secret):
        header = lambda: secret.reveal()
        return header()

    async def later(self, secret):
        return secret.reveal()


def aliased(secret):
    read = secret.reveal
    return read()


def by_name(secret):
    return getattr(secret, "reveal")(), getattr(secret, "_value")


def private(secret):
    return secret._value


TOP = Client().send.reveal()
"""


def test_the_walk_sees_every_kind_of_call_site() -> None:
    """Positive control: unlisted calls in a function, a method, a lambda and a coroutine."""
    walk = walk_source(_THROWAWAY, "webvigil.throwaway")
    assert walk.sites == {
        "webvigil.throwaway:module_level",
        "webvigil.throwaway:Client.send.<lambda>",
        "webvigil.throwaway:Client.later",
        "webvigil.throwaway:<module>",
    }
    assert walk.sites - ALLOWED_REVEALS.keys() == walk.sites  # each would fail the inventory


def test_the_walk_refuses_the_other_ways_to_the_value() -> None:
    """Positive control: an alias, a lookup by name and ``_value`` are each refused."""
    refused = walk_source(_THROWAWAY, "webvigil.throwaway").refused
    assert refused == [
        "webvigil.throwaway:16: .reveal without a call",
        "webvigil.throwaway:21: the string 'reveal'",
        "webvigil.throwaway:21: the string '_value'",
        "webvigil.throwaway:25: ._value",
    ]


def test_the_secrets_module_may_use_its_own_slot() -> None:
    """``core/secrets.py`` reads ``_value`` and names its slots; nothing there is refused."""
    assert walk_source(_THROWAWAY, SECRETS_MODULE).refused == []


def test_the_package_walk_merges_every_module(tmp_path: Path) -> None:
    """Positive control over a throwaway package: every module's sites and refusals arrive."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "__init__.py").write_text("def top(secret):\n    return secret.reveal()\n")
    (tmp_path / "sub" / "__init__.py").write_text("")
    (tmp_path / "sub" / "client.py").write_text(
        "def send(secret):\n    return secret.reveal(), secret._value\n"
    )
    walk, parsed = walk_package(tmp_path, "pkg")
    assert parsed == 3
    assert walk.sites == {"pkg:top", "pkg.sub.client:send"}
    assert walk.refused == ["pkg.sub.client:2: ._value"]
    allowed = {"pkg:top": "a reason", "pkg.sub.client:gone": "a reason"}
    assert inventory_problems(walk.sites, allowed) == (
        {"pkg.sub.client:send"},
        {"pkg.sub.client:gone"},
    )


# ---------------------------------------------------------------------------
# Credential-field gate: the walk
# ---------------------------------------------------------------------------


def _modules() -> Iterator[Any]:
    """
    Yields:
        Any: Every module of the package, imported. The Alembic migrations are not a package
            (no ``__init__``), so the walk never runs them.
    """
    yield webvigil
    for info in pkgutil.walk_packages(webvigil.__path__, "webvigil."):
        yield importlib.import_module(info.name)


def _models() -> list[type]:
    """
    Returns:
        list[type]: Every pydantic model and dataclass defined (not imported) in the package.
    """
    found: dict[str, type] = {}
    for module in _modules():
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__ != module.__name__:
                continue
            if (issubclass(cls, BaseModel) and cls is not BaseModel) or dataclasses.is_dataclass(
                cls
            ):
                found[f"{cls.__module__}.{cls.__qualname__}"] = cls
    return list(found.values())


def _fields(cls: Any) -> dict[str, object]:
    """
    Args:
        cls (Any): A pydantic model or a dataclass class.

    Returns:
        dict[str, object]: Each field's annotation: the resolved type, or the annotation's text
            when it cannot be resolved (a name imported only for type checking).
    """
    if issubclass(cls, BaseModel):
        return {name: field.annotation for name, field in cls.model_fields.items()}
    names = [field.name for field in dataclasses.fields(cls)]
    try:
        hints = typing.get_type_hints(cls, include_extras=True)
    except (NameError, TypeError):
        return {field.name: field.type for field in dataclasses.fields(cls)}
    return {name: hints[name] for name in names}


def _mentions(annotation: object, target: type) -> bool:
    """
    Args:
        annotation (object): A field's annotation, resolved or as text.
        target (type): ``str`` or ``Secret``.

    Returns:
        bool: Whether ``target`` appears anywhere in it (inside ``list[...]``, ``X | None``,
            ``Annotated[...]``, ``dict[str, ...]``), the values of a ``Literal`` aside.
    """
    if annotation is target:
        return True
    if isinstance(annotation, str):
        return re.search(rf"\b{target.__name__}\b", annotation) is not None
    if typing.get_origin(annotation) is Literal:
        return False
    return any(_mentions(arg, target) for arg in typing.get_args(annotation))


def _named_like_a_credential(field: str) -> bool:
    """
    Args:
        field (str): A field name.

    Returns:
        bool: Whether it has a credential word and does not end in a describing word.
    """
    name = field.lower()
    return any(word in name for word in CREDENTIAL_WORDS) and not name.endswith(EXEMPT_ENDINGS)


def _key(cls: type, field: str) -> str:
    """
    Args:
        cls (type): The model or dataclass.
        field (str): The field.

    Returns:
        str: ``module:Class.field``, the module without the ``webvigil.`` prefix.
    """
    return f"{cls.__module__.removeprefix('webvigil.')}:{cls.__qualname__}.{field}"


def credential_fields(
    classes: list[type], declared: frozenset[str] = DECLARED
) -> tuple[set[str], set[str]]:
    """
    Args:
        classes (list[type]): The models and dataclasses to check.
        declared (frozenset[str]): The fields checked whatever their names. Defaults to
            :data:`DECLARED`.

    Returns:
        tuple[set[str], set[str]]: Every field key seen, and the keys of the fields that hold a
            credential as a plain string (named like one, or in :data:`DECLARED`).
    """
    seen: set[str] = set()
    plain: set[str] = set()
    for cls in classes:
        for field, annotation in _fields(cls).items():
            key = _key(cls, field)
            seen.add(key)
            if not (_named_like_a_credential(field) or key in declared):
                continue
            if _mentions(annotation, str) and not _mentions(annotation, Secret):
                plain.add(key)
    return seen, plain


def field_problems(
    seen: set[str],
    plain: set[str],
    *,
    exempt: Mapping[str, str] = EXEMPT,
    pending: frozenset[str] = PENDING_CONVERSION,
    declared: frozenset[str] = DECLARED,
) -> dict[str, set[str]]:
    """
    Args:
        seen (set[str]): Every field key the gate looked at.
        plain (set[str]): The keys holding a credential as a plain string.
        exempt (Mapping[str, str]): The exemptions. Defaults to :data:`EXEMPT`.
        pending (frozenset[str]): The fields still to convert. Defaults to
            :data:`PENDING_CONVERSION`.
        declared (frozenset[str]): The declared fields. Defaults to :data:`DECLARED`.

    Returns:
        dict[str, set[str]]: What fails, by reason: ``failing`` (a plain credential with no
            entry), ``converted`` (a pending entry that holds a ``Secret`` already), ``stale``
            (an exemption that no longer matches) and ``missing`` (a declared field not found).
    """
    return {
        "failing": plain - exempt.keys() - pending,
        "converted": set(pending - plain),
        "stale": exempt.keys() - plain,
        "missing": set(declared - seen),
    }


@pytest.fixture(scope="module")
def package_fields() -> tuple[dict[str, set[str]], int]:
    """
    Returns:
        tuple[dict[str, set[str]], int]: :func:`field_problems` over the whole package, and how
            many classes it walked.
    """
    classes = _models()
    return field_problems(*credential_fields(classes)), len(classes)


# ---------------------------------------------------------------------------
# Credential-field gate: the tests
# ---------------------------------------------------------------------------


def test_no_credential_field_is_a_plain_string(
    package_fields: tuple[dict[str, set[str]], int],
) -> None:
    """Every field that holds a credential is a ``Secret``, but the exempt and the pending ones."""
    problems, walked = package_fields
    assert walked > 50  # the gate saw the package's models
    assert not problems["failing"], f"credential fields typed str: {sorted(problems['failing'])}"


def test_a_pending_entry_still_holds_a_string(
    package_fields: tuple[dict[str, set[str]], int],
) -> None:
    """A field already converted to ``Secret`` leaves ``PENDING_CONVERSION`` in the same change."""
    converted = package_fields[0]["converted"]
    assert not converted, f"already converted, drop from PENDING_CONVERSION: {sorted(converted)}"


def test_every_exemption_still_matches(package_fields: tuple[dict[str, set[str]], int]) -> None:
    """An exemption whose field is gone or no longer matches is removed."""
    stale = package_fields[0]["stale"]
    assert not stale, f"exemptions that no longer match: {sorted(stale)}"


def test_every_declared_field_exists(package_fields: tuple[dict[str, set[str]], int]) -> None:
    """A declared field that was renamed or moved is noticed, not silently dropped."""
    missing = package_fields[0]["missing"]
    assert not missing, f"declared fields not found: {sorted(missing)}"


def test_field_problems_names_each_failure() -> None:
    """Positive control: each kind of problem is reported, from synthetic sets."""
    problems = field_problems(
        {"m:A.token", "m:A.done", "m:A.cookie", "m:A.pairs"},
        {"m:A.token", "m:A.cookie"},
        exempt={"m:A.cookie": "a name", "m:A.gone": "a name"},
        pending=frozenset({"m:A.done"}),
        declared=frozenset({"m:A.pairs", "m:A.renamed"}),
    )
    assert problems == {
        "failing": {"m:A.token"},
        "converted": {"m:A.done"},
        "stale": {"m:A.gone"},
        "missing": {"m:A.renamed"},
    }


class _PlainToken(BaseModel):
    """A throwaway model holding a credential as a string."""

    api_token: str


class _SecretToken(BaseModel):
    """The same model with the credential as a secret field."""

    api_token: Annotated[Secret, secret_field(SecretKind.HEADER)]


class _SecretMap(BaseModel):
    """A credential map keyed by name, as the login record will be."""

    cookies: dict[str, Secret] = {}


class _Described(BaseModel):
    """Names that describe a credential, or hold no string, which the gate leaves alone."""

    password_env: str = "WEBVIGIL_LOGIN_PASSWORD"
    cookie_name: str = "sid"
    token_count: int = 0


@dataclasses.dataclass
class _PlainLogin:
    """A throwaway dataclass holding a password as an optional string."""

    username: str
    password: str | None = None


# An alias, which only a resolved annotation shows to be a string.
_Text = str


@dataclasses.dataclass
class _AliasedLogin:
    """A dataclass whose credentials hide behind an alias and a camel-case name."""

    password: _Text
    sessionToken: str


@dataclasses.dataclass
class _Undeclared:
    """A field whose name does not say it is a credential."""

    pairs: dict[str, str]


def test_the_gate_flags_a_plain_credential() -> None:
    """Positive control: a model and a dataclass with a credential typed ``str`` are flagged."""
    _, plain = credential_fields([_PlainToken, _PlainLogin, _AliasedLogin])
    assert plain == {
        f"{__name__}:_PlainToken.api_token",
        f"{__name__}:_PlainLogin.password",
        f"{__name__}:_AliasedLogin.password",
        f"{__name__}:_AliasedLogin.sessionToken",
    }


def test_the_gate_accepts_a_secret_and_a_describing_name() -> None:
    """A secret field, a describing ending and a field with no string are not flagged."""
    seen, plain = credential_fields([_SecretToken, _SecretMap, _Described, _Undeclared])
    assert plain == set()
    assert len(seen) == 6  # the fields were looked at


def test_a_declared_field_is_checked_whatever_its_name() -> None:
    """``DECLARED`` brings a field the names would miss into the gate."""
    key = f"{__name__}:_Undeclared.pairs"
    assert credential_fields([_Undeclared])[1] == set()
    assert credential_fields([_Undeclared], declared=frozenset({key}))[1] == {key}


def test_a_package_init_is_named_as_the_package() -> None:
    """``core/__init__.py`` is ``webvigil.core``, as a qualified site names it."""
    assert _module_name(SRC / "core" / "__init__.py", SRC, "webvigil") == "webvigil.core"
    assert _module_name(SRC / "core" / "secrets.py", SRC, "webvigil") == SECRETS_MODULE


@pytest.mark.parametrize(
    ("annotation", "has_str", "has_secret"),
    [
        (str, True, False),
        (str | None, True, False),
        (list[str], True, False),
        (Annotated[Secret, "meta"], False, True),
        (list[Secret] | None, False, True),
        (dict[str, Secret], True, True),
        (Literal["str"], False, False),
        ("dict[str, Secret]", True, True),
        ("strict", False, False),
        (int, False, False),
    ],
)
def test_mentions_reads_nested_and_textual_annotations(
    annotation: object, has_str: bool, has_secret: bool
) -> None:
    """It looks inside generics, unions, ``Annotated`` and text, never inside ``Literal``."""
    assert _mentions(annotation, str) is has_str
    assert _mentions(annotation, Secret) is has_secret
