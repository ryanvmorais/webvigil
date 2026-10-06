"""
Payload tables the injection detectors share — the expression-language set (spec 016).

Pure data tests: no HTTP, no stubs. They pin the invariants the detectors lean on — the
ambiguous-delimiter hints really exist in the SSTI table (so the combined detector never
sends a form twice), every EL signature matches a hand-written error from its engine and
none of the template-engine errors, and no probe names anything with a side effect.
"""

from __future__ import annotations

import pytest

from webvigil.checks.injection import payloads

_ERRORS = {
    "SpEL": (
        "org.springframework.expression.spel.SpelParseException: EL1041E: After parsing",
        "SpelEvaluationException: Property or field 'x' cannot be found",
        "EL1008E: Property or field 'wv' cannot be found on object of type 'Map'",
    ),
    "OGNL": (
        "ognl.OgnlException: source is null for getProperty(null, 'x')",
        "ognl.ParseException: Encountered unexpected token",
        "ognl.MethodFailedException: Method 'abs' failed for object",
    ),
    "JEXL": (
        "org.apache.commons.jexl3.JexlException$Parsing: @1:4 parsing error",
        "JexlException: undefined variable x",
    ),
    "MVEL": ("org.mvel2.CompileException: unable to resolve method",),
    "Unified EL": (
        "javax.el.ELException: Error Parsing: ${(",
        "jakarta.el.PropertyNotFoundException: Property 'x' not found",
        "org.apache.el.parser.ParseException: Encountered",
    ),
}
_TEMPLATE_ERRORS = (
    "jinja2.exceptions.TemplateSyntaxError: unexpected char",
    r"Twig\Error\SyntaxError: Unexpected token",
    "freemarker.core.ParseException: Syntax error in template",
    "org.apache.velocity.exception.ParseErrorException: Encountered",
    "Smarty error: unable to read resource",
    "mako.exceptions.SyntaxException: Expected",
)
_FORBIDDEN = ("Runtime", "ProcessBuilder", "System", "Class", "File", "exec", "getProperty")


def _dialect(text: str) -> str | None:
    """
    Args:
        text (str): A response body.

    Returns:
        str | None: The first EL dialect whose signature matches, or ``None``.
    """
    for name, pattern in payloads.EL_ERROR_SIGNATURES:
        if pattern.search(text):
            return name
    return None


def test_ambiguous_hints_exist_in_the_ssti_table() -> None:
    """A rename in ``arith_payloads`` must not silently make the combined detector send twice."""
    hints = {hint for hint, _ in payloads.arith_payloads("wv", 11, 12)}
    assert hints >= payloads.EL_AMBIGUOUS_HINTS


def test_ambiguous_hints_are_the_el_delimiters_arith_payloads_already_send() -> None:
    """Each ambiguous hint's payload uses a delimiter that is in ``EL_DELIMITERS``."""
    opens = {opening for _, opening, _ in payloads.EL_DELIMITERS}
    by_hint = dict(payloads.arith_payloads("wv", 11, 12))
    for hint in payloads.EL_AMBIGUOUS_HINTS:
        body = by_hint[hint].removeprefix("wv")
        assert any(body.startswith(opening) for opening in opens), hint


@pytest.mark.parametrize(("dialect", "text"), [(d, t) for d, ts in _ERRORS.items() for t in ts])
def test_each_signature_matches_its_own_engine(dialect: str, text: str) -> None:
    """A hand-written error from each EL engine names that engine."""
    assert _dialect(text) == dialect


@pytest.mark.parametrize("text", _TEMPLATE_ERRORS)
def test_no_signature_matches_a_template_engine_error(text: str) -> None:
    """A template-engine error is never read as an EL dialect (the ``ssti`` check owns it)."""
    assert _dialect(text) is None


def test_bare_and_probe_templates_format_without_stray_braces() -> None:
    """The templates are ``str.format``-safe and carry the marker and the operands."""
    bare = payloads.EL_BARE_WHOLE.format(marker="wvAB", inner="6*7")
    assert bare == "'wvAB'+(6*7)"
    escape = payloads.EL_BARE_ESCAPE.format(marker="wvAB", inner="6*7")
    assert escape == "'+'wvAB'+(6*7)+'"
    assert payloads.EL_SPEL_PROBE.format(n=413) == "T(java.lang.Math).abs(-413)"
    assert payloads.EL_OGNL_PROBE.format(n=413) == "@java.lang.Math@abs(-413)"


def test_probes_are_pure_static_calls_only() -> None:
    """No probe names a process, a file, reflection or the environment (RNF-03)."""
    probes = (payloads.EL_SPEL_PROBE, payloads.EL_OGNL_PROBE, *payloads.EL_UNTERMINATED)
    for probe in probes:
        assert not any(token in probe for token in _FORBIDDEN), probe
