"""
One type for every credential and session value the scanner and the Web API hold.

Spec 024. A :class:`Secret` wraps one string and turns into a fixed marker wherever text is made
from it: ``str``, ``repr``, ``format``, an f-string, ``%``, a container, a log line, a traceback,
the terminal. ``pickle`` refuses it and ``json.dumps`` cannot encode it, so an unplanned
serialization fails instead of writing the value. The only way to the value is
:meth:`Secret.reveal`, and a test lists every call of it in the source (the reveal inventory).

A pydantic model declares a secret field with ``Annotated[Secret, secret_field(kind)]``: the field
takes a plain string (with the field's length limits), keeps the object in a Python-mode dump (so a
model validated again keeps the value), writes the marker in a JSON-mode dump, and appears in a JSON
schema as a write-only password string. :func:`collect_secrets` gathers every secret under a
configuration, so the scrub list of a scan is never assembled by hand.

The module imports only the standard library and ``pydantic_core``, so the engine boundary holds and
the Web API imports it from here.
"""

from __future__ import annotations

import dataclasses
import hmac
from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Any, Final, NoReturn, final

from pydantic_core import CoreSchema, PydanticCustomError, core_schema

# ---------------------------------------------------------------------------
# Marker and kinds
# ---------------------------------------------------------------------------

# What every secret turns into as text, and what the report's scrub writes in place of a value:
# one constant, so a reader meets one marker wherever a credential was.
REDACTED: Final = "[redacted]"

# How deep collect_secrets walks. The scan configuration is about 4 levels deep; the cap only
# stops a cycle or a pathological structure.
MAX_COLLECT_DEPTH: Final = 16

# The text forms in which a value is compared: surrogatepass, so a value holding a lone surrogate
# (a cookie the target set) compares instead of raising.
_ENCODING: Final = "utf-8"
_ERRORS: Final = "surrogatepass"


class SecretKind(StrEnum):
    """
    What a secret is, which tells what the user gave from what the target issued.

    Attributes:
        COOKIE (str): An ``[auth]`` cookie value, given by the user.
        HEADER (str): An ``[auth]`` header value, given by the user.
        PASSWORD (str): The login password or a Web API password field.
        SESSION (str): A value the target issued (the session jar, the login record, the session
            checks).
        SIGNING_KEY (str): The Web API's ``session_secret``.
    """

    COOKIE = "cookie"
    HEADER = "header"
    PASSWORD = "password"
    SESSION = "session"
    SIGNING_KEY = "signing key"


# ---------------------------------------------------------------------------
# The type
# ---------------------------------------------------------------------------


@final
class Secret:
    """
    An immutable credential or session value that never becomes text by accident.

    ``len`` and ``bool`` are the value's, so "too short to scrub" or "is a cookie set" need no
    reveal. Two secrets compare by value in constant time, whatever their kinds; a secret is never
    equal to a string, so a value is never compared or looked up as text by mistake.

    Args:
        value (str): The value to hold.
        kind (SecretKind): What the value is.
        name (str | None): The cookie or header name, which is not secret. Defaults to ``None``.

    Raises:
        TypeError: When ``value`` is not a string, ``kind`` is not a :class:`SecretKind` or
            ``name`` is neither a string nor ``None``.
        AttributeError: When an existing secret is initialized again.
    """

    __slots__ = ("_kind", "_name", "_value")

    _value: str
    _kind: SecretKind
    _name: str | None

    def __init__(self, value: str, *, kind: SecretKind, name: str | None = None) -> None:
        if not isinstance(value, str):
            raise TypeError(f"a Secret holds a str, not {type(value).__name__}")
        if not isinstance(kind, SecretKind):
            raise TypeError(f"a Secret's kind is a SecretKind, not {type(kind).__name__}")
        if name is not None and not isinstance(name, str):
            raise TypeError(f"a Secret's name is a str, not {type(name).__name__}")
        try:
            object.__getattribute__(self, "_value")
        except AttributeError:
            pass
        else:
            raise AttributeError("a Secret is immutable")
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "_kind", kind)
        object.__setattr__(self, "_name", name)

    def __init_subclass__(cls, **kwargs: object) -> NoReturn:
        """
        Args:
            **kwargs (object): Ignored.

        Raises:
            TypeError: Always: a subclass could override how the value turns into text.
        """
        raise TypeError("Secret cannot be subclassed")

    # --- the one way to the value ---------------------------------------------------------

    def reveal(self) -> str:
        """
        Returns:
            str: The value. Every call site is listed in the reveal inventory
                (``tests/unit/test_secret_inventory.py``) with the reason it needs the value.
        """
        return self._value

    @property
    def kind(self) -> SecretKind:
        """
        Returns:
            SecretKind: What the value is.
        """
        return self._kind

    @property
    def name(self) -> str | None:
        """
        Returns:
            str | None: The cookie or header name, or ``None``.
        """
        return self._name

    @property
    def given(self) -> bool:
        """
        Returns:
            bool: ``True`` when the user gave the value (any kind but ``SESSION``), which the
                scrub always hides; ``False`` for a value the target issued.
        """
        return self._kind is not SecretKind.SESSION

    # --- text ------------------------------------------------------------------------------

    def __str__(self) -> str:
        return REDACTED

    def __format__(self, format_spec: str) -> str:
        return REDACTED

    def __repr__(self) -> str:
        # The name goes through repr, so a control character in a name the target chose is
        # escaped rather than written to a terminal or a log.
        name = "" if self._name is None else f", name={self._name!r}"
        return f"Secret({REDACTED!r}, kind={self._kind.value!r}{name})"

    # --- size --------------------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    # --- comparison ------------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(
            self._value.encode(_ENCODING, _ERRORS), other._value.encode(_ENCODING, _ERRORS)
        )

    def __hash__(self) -> int:
        # Tagged, so a secret never shares a hash slot with the bare string by design.
        return hash((Secret, self._value))

    # --- immutability ------------------------------------------------------------------------

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("a Secret is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("a Secret is immutable")

    def __copy__(self) -> Secret:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> Secret:
        return self

    # --- serialization -----------------------------------------------------------------------

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise TypeError("a Secret cannot be pickled")

    def __getstate__(self) -> NoReturn:
        # object.__getstate__ would hand the slots, value included, to any caller; refusing here
        # also closes copyreg's path for a pickler that skips __reduce_ex__.
        raise TypeError("a Secret cannot be pickled")

    # --- pydantic ----------------------------------------------------------------------------

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: object, handler: Callable[[Any], CoreSchema]
    ) -> CoreSchema:
        """
        A bare ``Secret`` annotation, for a value already wrapped (``list[Secret]`` filled by a
        ``mode="before"`` validator): it knows no kind, so it accepts a :class:`Secret` only.

        Args:
            source (object): The annotated type.
            handler (Callable[[Any], CoreSchema]): Pydantic's schema handler, unused.

        Returns:
            CoreSchema: An instance check with the secret serializer.
        """
        return core_schema.is_instance_schema(cls, serialization=_SERIALIZER)

    @classmethod
    def __get_pydantic_json_schema__(cls, schema: CoreSchema, handler: object) -> dict[str, Any]:
        """
        Args:
            schema (CoreSchema): The field's core schema, unused.
            handler (object): Pydantic's JSON schema handler, unused.

        Returns:
            dict[str, Any]: A write-only password string.
        """
        return _json_schema(None, None)


# ---------------------------------------------------------------------------
# Pydantic fields
# ---------------------------------------------------------------------------


def _serialize(value: Secret, info: core_schema.SerializationInfo) -> Secret | str:
    """
    Args:
        value (Secret): The field's value.
        info (core_schema.SerializationInfo): The dump's mode.

    Returns:
        Secret | str: The object itself in Python mode (a model validated again keeps it), the
            marker in JSON mode.
    """
    return REDACTED if info.mode_is_json() else value


_SERIALIZER: Final = core_schema.plain_serializer_function_ser_schema(_serialize, info_arg=True)


def _json_schema(min_length: int | None, max_length: int | None) -> dict[str, Any]:
    """
    Args:
        min_length (int | None): The field's least length, or ``None``.
        max_length (int | None): The field's greatest length, or ``None``.

    Returns:
        dict[str, Any]: ``{"type": "string", "format": "password", "writeOnly": true}`` plus the
            limits that are set.
    """
    schema: dict[str, Any] = {"type": "string", "format": "password", "writeOnly": True}
    if min_length is not None:
        schema["minLength"] = min_length
    if max_length is not None:
        schema["maxLength"] = max_length
    return schema


@dataclasses.dataclass(frozen=True, slots=True)
class SecretField:
    """
    The pydantic metadata of a secret field: ``Annotated[Secret, secret_field(kind)]``.

    Validation is a chain. The first step wraps a plain string in a secret of the field's kind and
    passes a secret through unchanged; the second checks the length. The length error is
    pydantic's own (type and message), one per field, and its ``input`` is the secret, so neither a
    ``ValidationError`` nor its ``str`` carries the value.

    Attributes:
        kind (SecretKind): The kind a plain string is wrapped with.
        min_length (int | None): The least length, or ``None``.
        max_length (int | None): The greatest length, or ``None``.
    """

    kind: SecretKind
    min_length: int | None = None
    max_length: int | None = None

    def _wrap(self, value: object) -> Secret:
        """
        Args:
            value (object): The field's input.

        Returns:
            Secret: ``value`` itself when it is a secret, otherwise a string wrapped with the
                field's kind.

        Raises:
            PydanticCustomError: ``string_type`` when ``value`` is neither.
        """
        if isinstance(value, Secret):
            return value
        if isinstance(value, str):
            return Secret(value, kind=self.kind)
        raise PydanticCustomError("string_type", "Input should be a valid string")

    def _check_length(self, value: Secret) -> Secret:
        """
        Args:
            value (Secret): The wrapped value.

        Returns:
            Secret: ``value``, unchanged.

        Raises:
            PydanticCustomError: ``string_too_short`` or ``string_too_long``, with pydantic's
                messages.
        """
        size = len(value)
        if self.min_length is not None and size < self.min_length:
            raise PydanticCustomError(
                "string_too_short",
                "String should have at least {min_length} character{expected_plural}",
                {"min_length": self.min_length, "expected_plural": _plural(self.min_length)},
            )
        if self.max_length is not None and size > self.max_length:
            raise PydanticCustomError(
                "string_too_long",
                "String should have at most {max_length} character{expected_plural}",
                {"max_length": self.max_length, "expected_plural": _plural(self.max_length)},
            )
        return value

    def __get_pydantic_core_schema__(
        self, source: object, handler: Callable[[Any], CoreSchema]
    ) -> CoreSchema:
        """
        Args:
            source (object): The annotated type (``Secret``).
            handler (Callable[[Any], CoreSchema]): Pydantic's schema handler, unused: this
                schema replaces the bare type's.

        Returns:
            CoreSchema: The wrap-then-check chain with the secret serializer.
        """
        return core_schema.chain_schema(
            [
                core_schema.no_info_plain_validator_function(self._wrap),
                core_schema.no_info_plain_validator_function(self._check_length),
            ],
            serialization=_SERIALIZER,
        )

    def __get_pydantic_json_schema__(self, schema: CoreSchema, handler: object) -> dict[str, Any]:
        """
        Args:
            schema (CoreSchema): The field's core schema, unused.
            handler (object): Pydantic's JSON schema handler, unused.

        Returns:
            dict[str, Any]: A write-only password string with the field's limits.
        """
        return _json_schema(self.min_length, self.max_length)


def _plural(count: int) -> str:
    """
    Args:
        count (int): A limit.

    Returns:
        str: ``""`` for 1, ``"s"`` otherwise, as pydantic writes its length messages.
    """
    return "" if count == 1 else "s"


def secret_field(
    kind: SecretKind, *, min_length: int | None = None, max_length: int | None = None
) -> SecretField:
    """
    Args:
        kind (SecretKind): The kind a plain string is wrapped with.
        min_length (int | None): The least length. Defaults to none.
        max_length (int | None): The greatest length. Defaults to none.

    Returns:
        SecretField: The metadata for ``Annotated[Secret, secret_field(kind, ...)]``.
    """
    return SecretField(kind, min_length, max_length)


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def collect_secrets(*roots: object) -> frozenset[Secret]:
    """
    Gather every secret under the given objects.

    It walks a pydantic model's fields, a dataclass's fields, a mapping's values and the items of
    a ``list``, ``tuple``, ``set`` or ``frozenset``, and stops at any other type, so a string, an
    HTTP object or a page is never entered. A secret field added anywhere under the configuration
    is collected with no other change.

    Args:
        *roots (object): The objects to walk (the configuration, the login credentials).

    Returns:
        frozenset[Secret]: Every secret met within :data:`MAX_COLLECT_DEPTH` levels of a root.
    """
    found: set[Secret] = set()
    for root in roots:
        _collect(root, 0, found)
    return frozenset(found)


def _collect(value: object, depth: int, found: set[Secret]) -> None:
    """
    Args:
        value (object): The object at this level.
        depth (int): How many levels below a root ``value`` is.
        found (set[Secret]): Where the secrets met are added.
    """
    if isinstance(value, Secret):
        found.add(value)
        return
    if depth >= MAX_COLLECT_DEPTH:
        return
    for child in _children(value):
        _collect(child, depth + 1, found)


def _children(value: object) -> list[object]:
    """
    Args:
        value (object): Any object.

    Returns:
        list[object]: The values a walk descends into, or nothing for a type it does not enter.
    """
    fields = getattr(type(value), "__pydantic_fields__", None)
    if isinstance(fields, Mapping):
        return [getattr(value, name, None) for name in fields]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return [getattr(value, field.name, None) for field in dataclasses.fields(value)]
    if isinstance(value, Mapping):
        return list(value.values())
    if isinstance(value, list | tuple | set | frozenset):
        return list(value)
    return []


__all__ = [
    "MAX_COLLECT_DEPTH",
    "REDACTED",
    "Secret",
    "SecretField",
    "SecretKind",
    "collect_secrets",
    "secret_field",
]
