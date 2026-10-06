"""
The fixture's simulated expression-language evaluator — spec 016 ADR-5, RF-12.

Pure unit of ``tests/fixtures/app.py``: the three insecure routes evaluate request text through
``_el_eval`` / ``_el_template``, a walker over ``ast`` that accepts integer and string
arithmetic and one allow-listed static call. These tests pin what it accepts, what it rejects,
and that it never reaches Python's ``eval`` / ``exec``, so a regression in the simulation cannot
quietly turn the fixture into a real code-execution sink.
"""

from __future__ import annotations

import ast
import inspect

import pytest

from tests.fixtures import app as fixture_app
from tests.fixtures.app import _el_eval, _el_template, _ElError


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("1", 1),
        ("6*7", 42),
        ("10-3", 7),
        ("9//2", 4),
        ("-5+2", -3),
        ("'wvab'+(6*7)", "wvab42"),
        ("'a'+'b'", "ab"),
        ("2+3", 5),
    ],
)
def test_arithmetic_and_string_concatenation(expression: str, expected: int | str) -> None:
    """Integer arithmetic runs and ``+`` with a string operand concatenates."""
    assert _el_eval(expression, static=False) == expected


@pytest.mark.parametrize(
    "expression",
    [
        "T(java.lang.Math).abs(-413)",  # SpEL type reference
        "@java.lang.Math@abs(-413)",  # OGNL static access
        "'wvab'+(T(java.lang.Math).abs(-413))",
    ],
)
def test_the_allow_listed_static_call_runs_only_where_static_access_is_allowed(
    expression: str,
) -> None:
    """The one pure call works with ``static=True`` and is a ``type`` error without it."""
    value = _el_eval(expression, static=True)
    assert "413" in str(value)
    with pytest.raises(_ElError) as refused:
        _el_eval(expression, static=False)
    assert refused.value.reason == "type"


@pytest.mark.parametrize(
    ("expression", "reason"),
    [
        ("1wv", "parse"),  # not valid syntax
        ("1+", "parse"),
        ("${{<%[%'\"}}%\\", "parse"),  # the SSTI polyglot
        ("__import__('os')", "unsupported"),  # a call that is not allow-listed
        ("open('/etc/passwd')", "unsupported"),
        ("(1).real", "unsupported"),  # attribute access
        ("[x for x in range(3)]", "unsupported"),  # comprehension
        ("name", "unsupported"),  # a bare name
        ("1/0", "unsupported"),  # only floor division is accepted
        ("9//0", "unsupported"),  # and never by zero
        ("abs(1, 2)", "unsupported"),  # the allow-listed call with the wrong arity
    ],
)
def test_everything_else_is_rejected(expression: str, reason: str) -> None:
    """Calls, attributes, names, comprehensions and malformed input raise ``_ElError``."""
    with pytest.raises(_ElError) as refused:
        _el_eval(expression, static=True)
    assert refused.value.reason == reason


def test_a_template_evaluates_only_its_own_delimiter() -> None:
    """``%{...}`` runs on an OGNL route and ``#{...}`` is left alone, and the reverse."""
    text = "a %{6*7} b #{6*7} c ${6*7}"
    assert _el_template(text, opener="%", static=True) == "a 42 b #{6*7} c ${6*7}"
    assert _el_template(text, opener="#", static=False) == "a %{6*7} b 42 c ${6*7}"


def test_an_unterminated_region_is_a_parse_error() -> None:
    """``%{(`` on an OGNL route draws the parser error; the other delimiter is ignored."""
    with pytest.raises(_ElError) as refused:
        _el_template("hi%{(", opener="%", static=True)
    assert refused.value.reason == "parse"
    assert _el_template("hi%{(", opener="#", static=False) == "hi%{("


def test_a_rejected_type_reference_on_a_sandboxed_route_names_the_type() -> None:
    """``#{T(...)}`` with static access off is the refusal the SpEL sandbox route returns."""
    with pytest.raises(_ElError) as refused:
        _el_template("x#{T(java.lang.Math).abs(-5)}", opener="#", static=False)
    assert refused.value.reason == "type"


def test_the_evaluator_never_calls_eval_or_exec() -> None:
    """No ``eval`` / ``exec`` / ``compile`` call exists in the evaluator's source."""
    for function in (_el_eval, _el_template, fixture_app._el_node):
        tree = ast.parse(inspect.getsource(function).lstrip())
        called = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert not called & {"eval", "exec", "compile", "__import__"}, function.__name__
