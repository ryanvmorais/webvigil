"""
``Secret``, ``secret_field`` and ``collect_secrets`` (spec 024, RF-01 to RF-03 and RF-07).

Pure logic: no I/O, nothing mocked. The contract table runs every way a value turns into text over
a secret and asserts the value is absent; each row's positive control runs the same way out over
the revealed string and shows the value would be there, so a row that never reached the value
cannot pass. Logging goes through ``caplog`` at ``DEBUG`` and the terminal through a recording
Rich console, both in memory.
"""

from __future__ import annotations

import copy
import dataclasses
import io
import json
import logging
import pickle
import pprint
import traceback
from collections.abc import Callable
from typing import Annotated

import pytest
from pydantic import BaseModel, StringConstraints, ValidationError
from rich.console import Console

from webvigil.core.secrets import (
    MAX_COLLECT_DEPTH,
    REDACTED,
    Secret,
    SecretKind,
    collect_secrets,
    secret_field,
)

VALUE = "hunter2-canary-6f1e"


def _secret(value: str = VALUE, kind: SecretKind = SecretKind.PASSWORD) -> Secret:
    """
    Args:
        value (str): The value. Defaults to :data:`VALUE`.
        kind (SecretKind): The kind. Defaults to ``PASSWORD``.

    Returns:
        Secret: A secret holding ``value``.
    """
    return Secret(value, kind=kind)


@dataclasses.dataclass
class _Holder:
    """
    A dataclass holding a value, as ``Credentials`` does.

    Attributes:
        user (str): Plain text.
        password (object): The value under test.
    """

    user: str
    password: object


class _Model(BaseModel):
    """
    A model with a secret field, as the configuration has.

    Attributes:
        user (str): Plain text.
        password (Secret): A secret field.
    """

    user: str = "scanner"
    password: Annotated[Secret, secret_field(SecretKind.PASSWORD)]


class _Limited(BaseModel):
    """
    Secret fields with length limits, beside a plain field with the same limits.

    Attributes:
        password (Secret): Between 3 and 8 characters.
        one (Secret): At most 1 character, for pydantic's singular message.
        plain (str): A plain field with the same limits, whose messages are pydantic's own.
    """

    password: Annotated[Secret, secret_field(SecretKind.PASSWORD, min_length=3, max_length=8)] = (
        Secret("abcd", kind=SecretKind.PASSWORD)
    )
    one: Annotated[Secret, secret_field(SecretKind.HEADER, min_length=1, max_length=1)] = Secret(
        "a", kind=SecretKind.HEADER
    )
    plain: str = "abcd"


class _Bare(BaseModel):
    """
    A field typed ``Secret`` with no ``secret_field``: it takes a secret only.

    Attributes:
        value (Secret): A secret.
    """

    value: Secret


def _model(value: object) -> object:
    """
    Args:
        value (object): A secret or its revealed string.

    Returns:
        object: A model holding ``value``: a ``_Model`` for a secret, and the same fields in a
            plain model for the string, so the positive control prints the same shape.
    """
    if isinstance(value, Secret):
        return _Model(password=value)

    class _PlainModel(BaseModel):
        user: str = "scanner"
        password: str

    return _PlainModel(password=str(value))


# ---------------------------------------------------------------------------
# The contract table: every way to text (RF-01)
# ---------------------------------------------------------------------------


def _traceback(*args: object) -> str:
    """
    Args:
        *args (object): The exception's arguments.

    Returns:
        str: The formatted traceback of a raised ``ValueError`` with those arguments.
    """
    try:
        raise ValueError(*args)
    except ValueError as exc:
        return "".join(traceback.format_exception(exc))


def _rich(value: object) -> str:
    """
    Args:
        value (object): What the terminal prints.

    Returns:
        str: The text of a recording Rich console after printing it.
    """
    console = Console(file=io.StringIO(), record=True, width=200)
    console.print(value)
    return console.export_text()


WAYS_TO_TEXT: dict[str, Callable[[object], str]] = {
    "str": str,
    "repr": repr,
    "format": lambda value: format(value, ""),
    "format s": lambda value: format(value, "s"),
    "format >40": lambda value: format(value, ">40"),
    "f-string": lambda value: f"token={value}",
    "f-string !r": lambda value: f"token={value!r}",
    "percent s": lambda value: "token=%s" % (value,),  # noqa: UP031 - % is under test
    "percent r": lambda value: "token=%r" % (value,),  # noqa: UP031 - % is under test
    "pprint": pprint.pformat,
    "dict": lambda value: str({"password": value}),
    "list": lambda value: str([value]),
    "tuple": lambda value: repr((value, 1)),
    "dataclass": lambda value: repr(_Holder("scanner", value)),
    "pydantic repr": lambda value: repr(_model(value)),
    "pydantic str": lambda value: str(_model(value)),
    "exception, one argument": _traceback,
    "exception, two arguments": lambda value: _traceback(value, 1),
    "rich": _rich,
    "rich, a model": lambda value: _rich(_model(value)),
}


@pytest.mark.parametrize("way", WAYS_TO_TEXT.values(), ids=WAYS_TO_TEXT.keys())
def test_no_way_to_text_shows_the_value(way: Callable[[object], str]) -> None:
    """Every way to text writes the marker, and the same way over the string writes the value."""
    secret = _secret()
    assert VALUE not in way(secret)
    assert VALUE in way(secret.reveal())  # positive control: this way would show it


def test_text_is_the_marker() -> None:
    """``str``, ``format`` with any spec and an f-string give exactly the marker."""
    secret = _secret()
    assert str(secret) == REDACTED
    assert format(secret, ">40") == REDACTED
    assert f"{secret}" == REDACTED


def test_repr_labels_kind_and_name() -> None:
    """``repr`` carries the marker, the kind and the name, and nothing else."""
    assert repr(Secret(VALUE, kind=SecretKind.COOKIE, name="sid")) == (
        "Secret('[redacted]', kind='cookie', name='sid')"
    )
    assert repr(_secret()) == "Secret('[redacted]', kind='password')"


def test_repr_escapes_a_control_character_in_the_name() -> None:
    """A name the target chose goes through ``repr``, so an escape sequence is not written raw."""
    text = repr(Secret(VALUE, kind=SecretKind.SESSION, name="sid\x1b[2J"))
    assert "\x1b" not in text
    assert "\\x1b[2J" in text


@pytest.mark.parametrize("style", ["args", "extra"])
def test_logging_at_debug_shows_no_value(caplog: pytest.LogCaptureFixture, style: str) -> None:
    """A log line with a secret as an argument or in ``extra`` writes the marker."""
    logger = logging.getLogger("webvigil.test.secrets")
    formatter = logging.Formatter("%(message)s %(token)s")

    def emit(value: object) -> str:
        caplog.clear()
        with caplog.at_level(logging.DEBUG, logger=logger.name):
            if style == "args":
                logger.debug("token=%s repr=%r", value, value, extra={"token": "-"})
            else:
                logger.debug("login", extra={"token": value})
        assert len(caplog.records) == 1
        return formatter.format(caplog.records[0])

    secret = _secret()
    assert VALUE not in emit(secret)
    assert REDACTED in emit(secret)
    assert VALUE in emit(secret.reveal())  # positive control


# ---------------------------------------------------------------------------
# Bytes (RF-02)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "holder",
    [
        lambda value: value,
        lambda value: {"password": value},
        lambda value: [1, value],
    ],
    ids=["bare", "dict", "list"],
)
def test_json_dumps_refuses_naming_the_type(holder: Callable[[object], object]) -> None:
    """The standard encoder raises, and the error names the type; without the secret it encodes."""
    with pytest.raises(TypeError, match="Secret is not JSON serializable"):
        json.dumps(holder(_secret()))
    assert VALUE in json.dumps(holder(VALUE))  # positive control: the holder itself encodes


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_pickle_refuses_at_every_protocol(protocol: int) -> None:
    """``pickle`` refuses from ``__reduce_ex__``, bare or held; the holder alone pickles."""
    for holder in (_secret(), {"password": _secret()}):
        with pytest.raises(TypeError, match="a Secret cannot be pickled") as info:
            pickle.dumps(holder, protocol=protocol)
        assert info.traceback[-1].name == "__reduce_ex__"
    assert pickle.loads(pickle.dumps({"password": VALUE}, protocol=protocol)) == {"password": VALUE}


def test_getstate_refuses() -> None:
    """``__getstate__``, which a copier or pickler may call directly, hands out nothing."""
    with pytest.raises(TypeError, match="a Secret cannot be pickled"):
        _secret().__getstate__()


def test_vars_has_nothing_to_show() -> None:
    """A slotted secret has no ``__dict__`` for ``vars`` to hand out."""
    with pytest.raises(TypeError):
        vars(_secret())


@pytest.mark.parametrize("dump", ["model_dump_json", "json mode"])
def test_a_json_mode_dump_writes_the_marker(dump: str) -> None:
    """A JSON-mode dump of a secret field holds the marker, never the value."""
    model = _Model(password=_secret())
    text = (
        model.model_dump_json() if dump == "model_dump_json" else str(model.model_dump(mode="json"))
    )
    assert VALUE not in text
    assert REDACTED in text


def test_a_bare_secret_field_dumps_the_marker_in_json() -> None:
    """A field typed ``Secret`` serializes like a secret field."""
    model = _Bare(value=_secret())
    assert json.loads(model.model_dump_json()) == {"value": REDACTED}
    assert model.model_dump()["value"] is model.value


def test_a_python_mode_round_trip_keeps_the_value() -> None:
    """``model_dump`` returns the object, and validating it again keeps the value."""
    secret = _secret()
    dumped = _Model(password=secret).model_dump()
    assert dumped["password"] is secret
    again = _Model.model_validate(dumped)
    assert again.password.reveal() == VALUE
    assert again.password.kind is SecretKind.PASSWORD


@pytest.mark.parametrize("copier", [copy.copy, copy.deepcopy], ids=["copy", "deepcopy"])
def test_a_copy_keeps_the_value(copier: Callable[[object], object]) -> None:
    """A copy is the same immutable object, holding the same value."""
    secret = _secret()
    copied = copier(secret)
    assert copied is secret
    held = copier({"password": secret})
    assert isinstance(held, dict)
    assert held["password"].reveal() == VALUE


def test_a_model_copy_keeps_the_value() -> None:
    """A deep copy of a model holding a secret keeps it."""
    model = _Model(password=_secret())
    assert model.model_copy(deep=True).password.reveal() == VALUE


# ---------------------------------------------------------------------------
# Reading, equality, immutability (RF-03)
# ---------------------------------------------------------------------------


def test_reveal_returns_the_value() -> None:
    """``reveal`` is the way to the value."""
    assert _secret().reveal() == VALUE


@pytest.mark.parametrize("kind", list(SecretKind))
def test_kind_name_and_given(kind: SecretKind) -> None:
    """The kind and name read back; only a value the target issued is not ``given``."""
    secret = Secret(VALUE, kind=kind, name="sid")
    assert secret.kind is kind
    assert secret.name == "sid"
    assert secret.given is (kind is not SecretKind.SESSION)
    assert Secret(VALUE, kind=kind).name is None


def test_equal_values_are_equal_whatever_the_kind() -> None:
    """Two secrets with one value are equal and hash alike, across kinds."""
    cookie = Secret(VALUE, kind=SecretKind.COOKIE, name="a")
    session = Secret(VALUE, kind=SecretKind.SESSION, name="b")
    assert cookie == session
    assert not cookie != session  # noqa: SIM202 - __ne__ is what is under test
    assert hash(cookie) == hash(session)
    assert len({cookie, session}) == 1


def test_different_values_are_not_equal() -> None:
    """A different value, including a prefix, is not equal."""
    assert _secret() != _secret(VALUE + "x")
    assert _secret() != _secret(VALUE[:-1])
    assert _secret("a") != _secret("b")


def test_a_value_with_a_lone_surrogate_compares() -> None:
    """A value the target set with an unpaired surrogate compares instead of raising."""
    assert _secret("ab\udc80") == _secret("ab\udc80")
    assert _secret("ab\udc80") != _secret("ab\udc81")


def test_a_secret_is_never_equal_to_its_string() -> None:
    """A secret and a string with the same text are unequal both ways, and never hash-match."""
    secret = _secret()
    assert secret != VALUE
    assert VALUE != secret  # noqa: SIM300 - the str side is what is under test
    assert not secret == VALUE  # noqa: SIM201 - __eq__ is what is under test
    assert secret.__eq__(VALUE) is NotImplemented
    assert VALUE not in {secret}
    assert secret not in {VALUE}
    assert hash(secret) != hash(VALUE)


def test_the_value_cannot_be_reassigned_or_deleted() -> None:
    """Assignment, deletion and a second initialization are refused."""
    secret = _secret()
    with pytest.raises(AttributeError, match="immutable"):
        secret._value = "other"
    with pytest.raises(AttributeError, match="immutable"):
        secret.label = "other"
    with pytest.raises(AttributeError, match="immutable"):
        del secret._value
    with pytest.raises(AttributeError, match="immutable"):
        secret.__init__("other", kind=SecretKind.PASSWORD)
    assert secret.reveal() == VALUE


def test_a_secret_cannot_be_subclassed() -> None:
    """A subclass could print the value, so defining one fails."""
    with pytest.raises(TypeError, match="cannot be subclassed"):

        class _Leaky(Secret):  # type: ignore[misc]  # @final: the subclass is what is refused
            def __str__(self) -> str:
                return self.reveal()


@pytest.mark.parametrize(
    ("value", "kind", "name"),
    [
        (b"bytes", SecretKind.PASSWORD, None),
        (None, SecretKind.PASSWORD, None),
        (VALUE, "password", None),
        (VALUE, SecretKind.COOKIE, 1),
    ],
    ids=["bytes value", "no value", "kind as str", "name as int"],
)
def test_the_constructor_checks_its_types(value: object, kind: object, name: object) -> None:
    """A value, kind or name of the wrong type is refused, without the value in the message."""
    with pytest.raises(TypeError) as info:
        Secret(value, kind=kind, name=name)  # type: ignore[arg-type]  # wrong types on purpose
    assert VALUE not in str(info.value)


@pytest.mark.parametrize(
    ("value", "size", "truth"), [(VALUE, len(VALUE), True), ("", 0, False), ("x", 1, True)]
)
def test_len_and_bool_are_the_values(value: str, size: int, truth: bool) -> None:
    """``len`` and ``bool`` answer without a reveal."""
    assert len(_secret(value)) == size
    assert bool(_secret(value)) is truth


@pytest.mark.parametrize(
    "operation",
    [
        lambda secret: iter(secret),
        lambda secret: secret[0],
        lambda secret: "h" in secret,
        lambda secret: secret + "x",
        lambda secret: secret < secret,
    ],
    ids=["iter", "index", "in", "concatenate", "order"],
)
def test_no_operator_yields_the_value(operation: Callable[[Secret], object]) -> None:
    """Iteration, indexing, ``in``, concatenation and ordering are not defined."""
    with pytest.raises(TypeError):
        operation(_secret())


# ---------------------------------------------------------------------------
# secret_field
# ---------------------------------------------------------------------------


def test_secret_field_wraps_a_string_with_its_kind() -> None:
    """A plain string becomes a secret of the field's kind."""
    password = _Model(password=VALUE).password
    assert isinstance(password, Secret)
    assert password.kind is SecretKind.PASSWORD
    assert password.reveal() == VALUE


def test_secret_field_passes_a_secret_through() -> None:
    """A secret given to the field is kept as it is, kind and name included."""
    cookie = Secret("abcd", kind=SecretKind.COOKIE, name="sid")
    assert _Limited(password=cookie).password is cookie


def test_secret_field_validates_json_input() -> None:
    """``model_validate_json`` wraps the string too."""
    model = _Model.model_validate_json(json.dumps({"password": VALUE}))
    assert model.password.reveal() == VALUE


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("password", "ab", "string_too_short"),
        ("password", "abcdefghi", "string_too_long"),
        ("one", "", "string_too_short"),
        ("one", "ab", "string_too_long"),
    ],
)
def test_a_length_error_is_pydantics_own_and_hides_the_value(
    field: str, value: str, error: str
) -> None:
    """One error per field, with pydantic's type and message, and the secret as its input."""
    with pytest.raises(ValidationError) as secret_info:
        _Limited.model_validate({field: value})
    errors = secret_info.value.errors()
    assert len(errors) == 1
    assert errors[0]["type"] == error
    assert errors[0]["loc"] == (field,)
    assert isinstance(errors[0]["input"], Secret)
    assert f"'{value}'" not in str(secret_info.value)

    # positive control: a plain field with the same limits names the same error, input shown
    limits = {"password": (3, 8), "one": (1, 1)}[field]

    class _Plain(BaseModel):
        value: Annotated[str, StringConstraints(min_length=limits[0], max_length=limits[1])]

    with pytest.raises(ValidationError) as plain_info:
        _Plain.model_validate({"value": value})
    plain = plain_info.value.errors()[0]
    assert (plain["type"], plain["msg"]) == (errors[0]["type"], errors[0]["msg"])
    assert f"'{value}'" in str(plain_info.value)


@pytest.mark.parametrize("field", ["password", "one"])
def test_the_limits_themselves_are_accepted(field: str) -> None:
    """A value exactly at either limit validates."""
    low, high = {"password": (3, 8), "one": (1, 1)}[field]
    assert len(getattr(_Limited.model_validate({field: "x" * low}), field)) == low
    assert len(getattr(_Limited.model_validate({field: "x" * high}), field)) == high


@pytest.mark.parametrize("value", [1, None, b"bytes", ["x"]])
def test_secret_field_refuses_a_non_string(value: object) -> None:
    """Anything but a string or a secret is pydantic's ``string_type`` error."""
    with pytest.raises(ValidationError) as info:
        _Model.model_validate({"password": value})
    errors = info.value.errors()
    assert [(error["type"], error["msg"]) for error in errors] == [
        ("string_type", "Input should be a valid string")
    ]


def test_a_bare_secret_field_refuses_a_string() -> None:
    """With no kind to wrap it, a field typed ``Secret`` takes a secret only."""
    with pytest.raises(ValidationError):
        _Bare(value=VALUE)
    assert _Bare(value=_secret()).value.reveal() == VALUE


def test_the_json_schema_is_a_write_only_password() -> None:
    """In both schema modes the field is a password string with its limits, never its value."""
    for mode in ("validation", "serialization"):
        properties = _Limited.model_json_schema(mode=mode)["properties"]
        assert {
            key: value
            for key, value in properties["password"].items()
            if key not in {"title", "default"}
        } == {
            "type": "string",
            "format": "password",
            "writeOnly": True,
            "minLength": 3,
            "maxLength": 8,
        }
        # a default is written in JSON mode, so the schema shows the marker
        assert properties["password"]["default"] == REDACTED
        assert "abcd" not in json.dumps(properties["password"])
    bare = _Bare.model_json_schema()["properties"]["value"]
    assert {key: value for key, value in bare.items() if key != "title"} == {
        "type": "string",
        "format": "password",
        "writeOnly": True,
    }


# ---------------------------------------------------------------------------
# collect_secrets (RF-07)
# ---------------------------------------------------------------------------


class _Login(BaseModel):
    """
    A nested section, as ``[auth.login]`` is.

    Attributes:
        username (str): Plain text, not collected.
        extra (dict[str, Secret]): Secrets in a mapping.
    """

    username: str = "scanner"
    extra: dict[str, Secret] = {}


class _Auth(BaseModel):
    """
    A section holding secrets in sequences, as ``[auth]`` does.

    Attributes:
        cookies (list[Secret]): A list.
        headers (tuple[Secret, ...]): A tuple.
        login (_Login | None): A nested model.
    """

    cookies: list[Secret] = []
    headers: tuple[Secret, ...] = ()
    login: _Login | None = None


class _Config(BaseModel):
    """
    A configuration root.

    Attributes:
        auth (_Auth): The section with secrets.
        note (str): Plain text equal to a secret's value, which is not collected.
    """

    auth: _Auth = _Auth()
    note: str = VALUE


def test_collect_walks_models_mappings_and_sequences() -> None:
    """Every secret under nested models, a list, a tuple and a mapping is collected."""
    cookie = Secret("c-value", kind=SecretKind.COOKIE, name="sid")
    header = Secret("h-value", kind=SecretKind.HEADER, name="X-Api-Key")
    extra = Secret("e-value", kind=SecretKind.PASSWORD)
    config = _Config(
        auth=_Auth(cookies=[cookie], headers=(header,), login=_Login(extra={"k": extra}))
    )
    assert collect_secrets(config) == {cookie, header, extra}


def test_collect_walks_dataclasses_sets_and_several_roots() -> None:
    """A dataclass, a set and a frozenset are entered, and every root is walked."""
    password = _secret("p-value")
    in_set = _secret("s-value")
    in_frozenset = _secret("f-value")
    other_root = _secret("r-value")
    found = collect_secrets(
        _Holder("scanner", password), {"group": {in_set}}, [frozenset({in_frozenset})], other_root
    )
    assert found == {password, in_set, in_frozenset, other_root}


def test_collect_finds_a_new_secret_field_with_no_other_change() -> None:
    """A model with one more secret field has it collected (RF-07)."""

    class _Grown(_Config):
        api_key: Annotated[Secret, secret_field(SecretKind.HEADER)] = Secret(
            "k-value", kind=SecretKind.HEADER
        )

    grown = _Grown()
    assert collect_secrets(grown) == {grown.api_key}


class _Opaque:
    """An object of a type the walk does not enter."""

    def __init__(self) -> None:
        self.secret = _secret("o-value")


_DEFAULT = Secret("d-value", kind=SecretKind.PASSWORD)


@dataclasses.dataclass
class _WithDefault:
    """
    A dataclass whose default is a secret, so its class holds one.

    Attributes:
        password (Secret): Defaults to a secret.
    """

    password: Secret = _DEFAULT


def test_collect_does_not_enter_other_types() -> None:
    """A string, a model or dataclass class, and an arbitrary object are not entered."""
    assert collect_secrets(VALUE, _Opaque(), _Config, _WithDefault, [_Opaque()], None, 1) == (
        frozenset()
    )
    assert collect_secrets(_WithDefault()) == {_WithDefault.password}  # the instance is entered
    assert collect_secrets(_Config()) == frozenset()


def _nest(value: object, levels: int) -> object:
    """
    Args:
        value (object): The innermost value.
        levels (int): How many lists to wrap it in.

    Returns:
        object: ``value`` inside ``levels`` nested lists.
    """
    for _ in range(levels):
        value = [value]
    return value


def test_collect_stops_at_the_depth_cap() -> None:
    """A secret at the cap is collected; one level below it is not."""
    secret = _secret()
    assert collect_secrets(_nest(secret, MAX_COLLECT_DEPTH)) == {secret}
    assert collect_secrets(_nest(secret, MAX_COLLECT_DEPTH + 1)) == frozenset()


def test_collect_survives_a_cycle() -> None:
    """A list that holds itself ends at the cap instead of recursing forever."""
    secret = _secret()
    loop: list[object] = [secret]
    loop.append(loop)
    assert collect_secrets(loop) == {secret}
