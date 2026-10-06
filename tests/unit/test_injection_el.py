"""
Expression-language injection detector — spec 016 RF-01..RF-07, RF-12.

Pure detector units: ``_ctx`` wraps a ``render`` callable as the scanner's ``send`` and records
every value sent. The stubs stand in for the sinks the detector must tell apart: ``_el_stub``
is a configurable EL evaluator (which delimiters it runs, whether the value is itself an
expression, whether ``T()`` / ``@class@method`` is allowed or refused), ``_jinja`` and
``_freemarker`` are template engines the ``ssti`` check owns, ``_reflect`` echoes the payload
unevaluated. Nothing here touches the network or the budget; the budget cut is simulated by a
``send`` that starts returning ``None``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from webvigil.checks.injection.detect import DetectCtx, el, normalize_body, ssti
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.core.findings import Confidence, Severity
from webvigil.http.client import Response

_FULL = InjectionPoint("GET", "https://example.com/report", "filter", "1", (("filter", "1"),))
_CANARY = InjectionPoint("GET", "https://example.com/banner", "caption", "hi", (("caption", "hi"),))

_SPEL_ERROR = "org.springframework.expression.spel.SpelParseException: EL1041E: After parsing"
_SPEL_SANDBOX = (
    "org.springframework.expression.spel.SpelEvaluationException: EL1005E: "
    "Type cannot be found 'java.lang.Math'"
)
_OGNL_ERROR = "ognl.ParseException: Encountered unexpected token"
_OGNL_STATIC_OFF = "ognl.MethodFailedException: Method 'abs' failed for object"
_UNIFIED_ERROR = "javax.el.ELException: Error Parsing"
_FORBIDDEN = ("Runtime", "ProcessBuilder", "System", "Class", "File", "exec", "getProperty")

_SPEL_STATIC = r"T\(java\.lang\.Math\)\.abs\(-(\d+)\)"
_OGNL_STATIC = r"@java\.lang\.Math@abs\(-(\d+)\)"


def _resp(text: str, *, status: int = 200) -> Response:
    """
    Args:
        text (str): The response body.
        status (int): The HTTP status. Defaults to 200.

    Returns:
        Response: A minimal HTML response carrying ``text``.
    """
    return Response(
        url="https://example.com/x",
        requested_url="https://example.com/x",
        status_code=status,
        headers=httpx.Headers({"content-type": "text/html"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


def _baseline(body: str = "<p>Result: 1</p>") -> Baseline:
    """
    Args:
        body (str): The baseline body. Defaults to a plain result page.

    Returns:
        Baseline: A 200 baseline carrying ``body``.
    """
    return Baseline(200, body, normalize_body(body), len(body), 1.0)


def _ctx(
    render: Callable[[str], Response | None], *, limit: int | None = None
) -> tuple[DetectCtx, list[str]]:
    """
    Args:
        render (Callable[[str], Response | None]): Maps a sent value to a response.
        limit (int | None): After this many sends, ``send`` returns ``None`` (a budget cut).
            Defaults to no limit.

    Returns:
        tuple[DetectCtx, list[str]]: The context and the list every sent value is appended to.
    """
    sent: list[str] = []

    async def send(
        point: InjectionPoint, value: str, *, time_based: bool = False, **_: Any
    ) -> Response | None:
        if limit is not None and len(sent) >= limit:
            return None
        sent.append(value)
        return render(value)

    return DetectCtx(send=send, delay_s=5, host="example.com"), sent


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


def _el_stub(
    *,
    delimiters: tuple[str, ...] = (),
    bare: bool = False,
    static: str | None = None,
    refuse: str = "",
    parse_error: str = "",
) -> Callable[[str], Response]:
    """
    A configurable stand-in for a target that evaluates its parameter as an expression.

    Args:
        delimiters (tuple[str, ...]): Opening delimiters that evaluate, e.g. ``("#{", "${")``
            (the closing one is always ``}``). Defaults to none.
        bare (bool): The whole value is itself an expression, so only the string-concatenation
            form evaluates. Defaults to ``False``.
        static (str | None): ``"spel"`` or ``"ognl"``: which static-call syntax evaluates;
            ``None`` means a static call is not evaluated. Defaults to ``None``.
        refuse (str): The body answering a static call that does not evaluate. Defaults to
            echoing the value.
        parse_error (str): The body answering the polyglot, an unterminated expression, or
            an unparseable bare value. Defaults to echoing the value.

    Returns:
        Callable[[str], Response]: The ``render`` function.
    """
    static_re = {"spel": _SPEL_STATIC, "ognl": _OGNL_STATIC}.get(static or "")
    any_static = re.compile(f"{_SPEL_STATIC}|{_OGNL_STATIC}")

    def fail(value: str) -> Response:
        return _resp(parse_error, status=500) if parse_error else _resp(f"<p>{value}</p>")

    def render(value: str) -> Response:
        if "${{<%" in value or value.endswith("("):
            return fail(value)
        if bare:
            whole = re.fullmatch(r"'(wv[0-9a-f]+)'\+\((\d+)\*(\d+)\)", value)
            if whole:
                return _resp(f"<p>{whole[1]}{int(whole[2]) * int(whole[3])}</p>")
            call = re.fullmatch(r"'(wv[0-9a-f]+)'\+\((.+)\)", value)
            if call and any_static.fullmatch(call[2]):
                hit = static_re and re.fullmatch(static_re, call[2])
                if hit:
                    return _resp(f"<p>{call[1]}{hit[1]}</p>")
                return _resp(refuse, status=500) if refuse else fail(value)
            return fail(value)
        for opening in delimiters:
            mult = re.search(r"(wv[0-9a-f]+)" + re.escape(opening) + r"(\d+)\*(\d+)\}", value)
            if mult:
                return _resp(f"<p>Hi {mult[1]}{int(mult[2]) * int(mult[3])}</p>")
            call = re.search(r"(wv[0-9a-f]+)" + re.escape(opening) + r"(.+?)\}", value)
            if call and any_static.fullmatch(call[2]):
                hit = static_re and re.fullmatch(static_re, call[2])
                if hit:
                    return _resp(f"<p>Hi {call[1]}{hit[1]}</p>")
                return _resp(refuse, status=500) if refuse else _resp(f"<p>Hi {value}</p>")
        return _resp(f"<p>Hi {value}</p>")

    return render


def _spel_bare(value: str) -> Response:
    """A Spring ``parseExpression(filter)`` sink: only the bare form evaluates."""
    return _el_stub(bare=True, static="spel", parse_error=_SPEL_ERROR)(value)


def _spel_template(value: str) -> Response:
    """A SpEL template sink: ``#{}`` and ``${}`` evaluate, ``T()`` is allowed."""
    return _el_stub(delimiters=("#{", "${"), static="spel", parse_error=_SPEL_ERROR)(value)


def _spel_sandboxed(value: str) -> Response:
    """A SpEL sink under ``SimpleEvaluationContext``: arithmetic yes, ``T()`` refused."""
    return _el_stub(delimiters=("#{",), refuse=_SPEL_SANDBOX, parse_error=_SPEL_ERROR, static=None)(
        value
    )


def _ognl(value: str) -> Response:
    """A Struts-style sink: ``%{}`` evaluates and static calls are allowed."""
    return _el_stub(delimiters=("%{",), static="ognl", parse_error=_OGNL_ERROR)(value)


def _ognl_static_off(value: str) -> Response:
    """A Struts-style sink with static method access switched off."""
    return _el_stub(delimiters=("%{",), refuse=_OGNL_STATIC_OFF, parse_error=_OGNL_ERROR)(value)


def _unified_el(value: str) -> Response:
    """A JSP / Unified EL sink: ``${}`` evaluates, a ``T()`` call raises ``ELException``."""
    return _el_stub(delimiters=("${",), refuse=_UNIFIED_ERROR, parse_error="")(value)


def _string_context(value: str) -> Response:
    """A sink that wraps the value in quotes before evaluating it as an expression."""
    escape = re.fullmatch(r"(.*)'\+'(wv[0-9a-f]+)'\+\((\d+)\*(\d+)\)\+'", value)
    if escape:
        return _resp(f"<p>{escape[1]}{escape[2]}{int(escape[3]) * int(escape[4])}</p>")
    return _resp(f"<p>{value}</p>")


def _jinja(value: str) -> Response:
    """A name concatenated into Jinja2 source: ``{{a*b}}`` and ``{{7*'7'}}`` evaluate."""
    if "${{" in value:
        return _resp("jinja2.exceptions.TemplateSyntaxError: unexpected char", status=500)
    arith = re.search(r"(wv[0-9a-f]+)\{\{(\d+)\*(\d+)\}\}", value)
    if arith:
        return _resp(f"<p>Hi {arith[1]}{int(arith[2]) * int(arith[3])}</p>")
    engine = re.search(r"(wv[0-9a-f]+)\{\{7\*'7'\}\}", value)
    if engine:
        return _resp(f"<p>Hi {engine[1]}7777777</p>")
    return _resp(f"<p>Hi {value}</p>")


def _freemarker(value: str) -> Response:
    """A Freemarker sink: ``${a*b}`` evaluates, nothing else does, and there is no EL error."""
    arith = re.search(r"(wv[0-9a-f]+)\$\{(\d+)\*(\d+)\}", value)
    if arith:
        return _resp(f"<p>Hi {arith[1]}{int(arith[2]) * int(arith[3])}</p>")
    return _resp(f"<p>Hi {value}</p>")


def _reflect(value: str) -> Response:
    """A sink that echoes the payload unevaluated."""
    return _resp(f"<p>Hi {value}</p>")


def _no_marker(value: str) -> Response:
    """A sink that computes the product but drops the marker."""
    arith = re.search(r"(\d+)\*(\d+)", value)
    return _resp(f"<p>= {int(arith[1]) * int(arith[2])}</p>" if arith else "<p>none</p>")


def _signature_only(value: str) -> Response:
    """A sink that never evaluates but prints a SpEL parse error for the polyglot."""
    if "${{<%" in value:
        return _resp(_SPEL_ERROR, status=500)
    return _resp(f"<p>Hi {value}</p>")


def _unterminated_only(value: str) -> Response:
    """A sink that prints a SpEL parse error only for an unterminated expression."""
    return _resp(_SPEL_ERROR, status=500) if value.endswith("(") else _resp(f"<p>Hi {value}</p>")


def _only(hits: list[InjectionHit]) -> InjectionHit:
    """
    Args:
        hits (list[InjectionHit]): The detector's output.

    Returns:
        InjectionHit: The single hit; fails the test when there is not exactly one.
    """
    assert len(hits) == 1, hits
    return hits[0]


def _evidence(hit: InjectionHit) -> dict[str, str]:
    """
    Args:
        hit (InjectionHit): A hit.

    Returns:
        dict[str, str]: Its evidence pairs as a mapping.
    """
    return dict(hit.evidence)


# ---------------------------------------------------------------------------
# Arithmetic proof and classification (RF-02, RF-04, RF-05)
# ---------------------------------------------------------------------------


async def test_percent_form_is_ognl_and_critical_when_the_static_call_evaluates() -> None:
    """``%{a*b}`` is OGNL on syntax; the evaluating ``@Math@abs`` probe makes it CRITICAL."""
    ctx, _ = _ctx(_ognl)
    hit = _only(await el.detect_combined(_CANARY, _baseline(), ctx))
    assert (hit.kind, hit.check_id) == ("el", "injection.el")
    assert (hit.severity, hit.confidence) == (Severity.CRITICAL, Confidence.HIGH)
    assert "(OGNL)" in hit.title and "'caption'" in hit.title
    assert "%{" in hit.payload
    evidence = _evidence(hit)
    assert "@java.lang.Math@abs" in evidence["Type access"]
    assert evidence["Dialect"] == "OGNL — type-access probe"


async def test_percent_form_stays_high_when_static_access_is_off() -> None:
    """With the static call refused the hit is OGNL by syntax and HIGH, never CRITICAL."""
    ctx, _ = _ctx(_ognl_static_off)
    hit = _only(await el.detect_combined(_CANARY, _baseline(), ctx))
    assert (hit.severity, hit.confidence) == (Severity.HIGH, Confidence.HIGH)
    evidence = _evidence(hit)
    assert "Type access" not in evidence
    assert evidence["Dialect"] == "OGNL — %{} syntax"


async def test_bare_form_names_spel_and_is_critical() -> None:
    """A parameter that is itself an expression: the concatenation form proves SpEL."""
    ctx, _ = _ctx(_spel_bare)
    hit = _only(await el.detect_combined(_FULL, _baseline(), ctx))
    assert hit.severity is Severity.CRITICAL
    assert "(SpEL)" in hit.title
    assert hit.payload.startswith("'wv")
    assert "T(java.lang.Math).abs" in _evidence(hit)["Type access"]


async def test_bare_escape_form_reaches_a_value_inside_a_string_literal() -> None:
    """The quote-closing variant evaluates where the whole-value form cannot."""
    ctx, _ = _ctx(_string_context)
    hit = _only(await el.detect_el(_FULL, _baseline(), ctx))
    assert hit.title.startswith("Expression-language injection (expression language, dialect")
    assert hit.severity is Severity.HIGH


@pytest.mark.parametrize("point", [_FULL, _CANARY], ids=["full", "canary"])
async def test_spel_template_delimiters_are_critical_on_either_point_kind(
    point: InjectionPoint,
) -> None:
    """``#{}`` / ``${}`` reach SpEL on a full point and on the canary path alike."""
    ctx, _ = _ctx(_spel_template)
    hit = _only(await el.detect_combined(point, _baseline(), ctx))
    assert hit.kind == "el" and hit.severity is Severity.CRITICAL
    assert "(SpEL)" in hit.title


async def test_sandboxed_spel_is_high_and_named_by_the_refusal() -> None:
    """A refused ``T()`` that names SpEL in its own words gives HIGH, dialect SpEL."""
    ctx, _ = _ctx(_spel_sandboxed)
    hit = _only(await el.detect_combined(_FULL, _baseline(), ctx))
    assert (hit.severity, hit.confidence) == (Severity.HIGH, Confidence.HIGH)
    assert "(SpEL)" in hit.title
    evidence = _evidence(hit)
    assert "Type access" not in evidence
    assert evidence["Dialect"] == "SpEL — error signature"
    assert "EL1005E" in evidence["Error signature"]


async def test_unified_el_is_named_by_the_refusal_and_high() -> None:
    """``${}`` evaluates, ``T()`` raises ``javax.el.ELException``: HIGH, Unified EL."""
    ctx, _ = _ctx(_unified_el)
    hit = _only(await el.detect_combined(_FULL, _baseline(), ctx))
    assert hit.severity is Severity.HIGH
    assert "(Unified EL)" in hit.title


async def test_a_dialect_with_no_static_syntax_is_never_probed() -> None:
    """When the polyglot already names Unified EL, no ``T()`` / ``@class@`` request is sent."""

    def render(value: str) -> Response:
        if "${{<%" in value:
            return _resp(_UNIFIED_ERROR, status=500)
        return _unified_el(value)

    ctx, sent = _ctx(render)
    hit = _only(await el.detect_combined(_FULL, _baseline(), ctx))
    assert "(Unified EL)" in hit.title
    assert not any("T(" in v or "@java" in v for v in sent)


async def test_the_other_dialects_probe_is_skipped_when_a_signature_names_one() -> None:
    """A SpEL signature from the polyglot means only the SpEL probe is sent."""
    ctx, sent = _ctx(_spel_template)
    await el.detect_combined(_FULL, _baseline(), ctx)
    assert any("T(java" in v for v in sent)
    assert not any("@java" in v for v in sent)


# ---------------------------------------------------------------------------
# Relationship with injection.ssti (RF-05)
# ---------------------------------------------------------------------------


async def test_a_freemarker_dollar_form_stays_ssti_in_the_combined_entry() -> None:
    """``${a*b}`` with no EL evidence is a template: the combined routine reports ``ssti``."""
    ctx, _ = _ctx(_freemarker)
    hit = _only(await el.detect_combined(_FULL, _baseline(), ctx))
    assert (hit.kind, hit.check_id) == ("ssti", "injection.ssti")
    assert hit.severity is Severity.HIGH


async def test_a_freemarker_dollar_form_is_silent_when_only_el_runs() -> None:
    """Without the ``ssti`` check, an uncorroborated ``${a*b}`` is not an EL finding."""
    ctx, _ = _ctx(_freemarker)
    assert await el.detect_el(_FULL, _baseline(), ctx) == []


async def test_jinja_is_reported_as_ssti_with_the_engine_named() -> None:
    """A template-only form is left to ``ssti`` exactly as before."""
    ctx, _ = _ctx(_jinja)
    hit = _only(await el.detect_combined(_FULL, _baseline("<p>Hi 1</p>"), ctx))
    assert hit.kind == "ssti" and "Jinja2" in hit.title


def _shape(hits: list[InjectionHit]) -> list[tuple[object, ...]]:
    """
    Args:
        hits (list[InjectionHit]): A detector's output.

    Returns:
        list[tuple[object, ...]]: Everything about each hit that is stable across runs (the
            marker and operands in the payload and evidence are random per call).
    """
    return [
        (h.kind, h.check_id, h.method, h.url, h.param, h.severity, h.confidence, h.title)
        for h in hits
    ]


@pytest.mark.parametrize("point", [_FULL, _CANARY], ids=["full", "canary"])
@pytest.mark.parametrize(
    "render",
    [_jinja, _freemarker, _reflect, _no_marker],
    ids=["jinja", "freemarker", "reflect", "no-marker"],
)
async def test_combined_reports_what_the_ssti_detector_reports(
    render: Callable[[str], Response], point: InjectionPoint
) -> None:
    """Parity: on template engines and non-hits the combined entry equals ``ssti.detect``."""
    base = _baseline("<p>Hi 1</p>")
    old_ctx, _ = _ctx(render)
    new_ctx, _ = _ctx(render)
    assert _shape(await el.detect_combined(point, base, new_ctx)) == _shape(
        await ssti.detect(point, base, old_ctx)
    )


# ---------------------------------------------------------------------------
# False-positive discipline (RF-02, RF-03, RNF-05)
# ---------------------------------------------------------------------------


async def test_a_reflected_literal_is_not_a_hit() -> None:
    """The payload echoed back unevaluated proves nothing."""
    ctx, _ = _ctx(_reflect)
    assert await el.detect_combined(_FULL, _baseline(), ctx) == []


async def test_the_product_without_the_marker_is_not_a_hit() -> None:
    """A calculator that returns the bare product is not an expression-injection finding."""
    ctx, _ = _ctx(_no_marker)
    assert await el.detect_combined(_FULL, _baseline(), ctx) == []


async def test_a_needle_already_in_the_baseline_is_suppressed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the baseline already carries ``<marker><product>`` nothing is reported."""
    monkeypatch.setattr(el.secrets, "token_hex", lambda _n: "ab12cd")
    monkeypatch.setattr(el.random, "randint", lambda low, _high: low + 1)
    ctx, _ = _ctx(_el_stub(bare=True))  # no error text, so only the arithmetic proof is in play
    assert await el.detect_combined(_FULL, _baseline("wvab12cd144"), ctx) == []


async def test_a_signature_also_in_the_baseline_is_ignored() -> None:
    """A page that always prints an EL error says nothing about this parameter."""
    ctx, _ = _ctx(_signature_only)
    assert await el.detect_combined(_FULL, _baseline(_SPEL_ERROR), ctx) == []


# ---------------------------------------------------------------------------
# Signature-only fallback (RF-03)
# ---------------------------------------------------------------------------


async def test_a_signature_without_arithmetic_is_a_medium_confidence_hit() -> None:
    """The evaluator is there and rejected the input: HIGH severity, MEDIUM confidence."""
    ctx, _ = _ctx(_signature_only)
    hit = _only(await el.detect_combined(_CANARY, _baseline(), ctx))
    assert (hit.severity, hit.confidence) == (Severity.HIGH, Confidence.MEDIUM)
    assert "(SpEL)" in hit.title
    assert "SpelParseException" in _evidence(hit)["Error signature"]


async def test_the_unterminated_probe_runs_only_on_full_points() -> None:
    """``${(`` / ``%{(`` are sent to a full point and never to a canary point."""
    full_ctx, full_sent = _ctx(_unterminated_only)
    canary_ctx, canary_sent = _ctx(_unterminated_only)
    full_hit = _only(await el.detect_combined(_FULL, _baseline(), full_ctx))
    assert full_hit.confidence is Confidence.MEDIUM
    assert await el.detect_combined(_CANARY, _baseline(), canary_ctx) == []
    assert any(v.endswith("${(") for v in full_sent)
    assert not any(v.endswith("(") for v in canary_sent)


# ---------------------------------------------------------------------------
# Budget and safety (RNF-03, RNF-04)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "point", "expected"),
    [
        (el.detect_combined, _CANARY, 8),  # ssti canary is 1 + 4 = 5: exactly +3
        (el.detect_combined, _FULL, 14),  # ssti full is 1 + 8 = 9
        (el.detect_el, _CANARY, 5),
        (el.detect_el, _FULL, 9),
    ],
    ids=["combined-canary", "combined-full", "el-canary", "el-full"],
)
async def test_request_counts_per_point_type(
    entry: Callable[..., Any], point: InjectionPoint, expected: int
) -> None:
    """With nothing evaluating, each entry sends exactly the budgeted number of requests."""
    ctx, sent = _ctx(_reflect)
    assert await entry(point, _baseline(), ctx) == []
    assert len(sent) == expected


@pytest.mark.parametrize("limit", [0, 1, 2, 5, 9])
@pytest.mark.parametrize("entry", [el.detect_combined, el.detect_el], ids=["combined", "el"])
async def test_the_detector_stops_when_send_returns_none(
    entry: Callable[..., Any], limit: int
) -> None:
    """A budget cut at any stage ends the routine quietly."""
    ctx, sent = _ctx(_reflect, limit=limit)
    assert await entry(_FULL, _baseline(), ctx) == []
    assert len(sent) <= limit


@pytest.mark.parametrize(
    "render",
    [_spel_bare, _spel_template, _spel_sandboxed, _ognl, _ognl_static_off, _unified_el],
    ids=["spel-bare", "spel-template", "spel-sandbox", "ognl", "ognl-off", "unified-el"],
)
async def test_no_probe_names_anything_with_a_side_effect(
    render: Callable[[str], Response],
) -> None:
    """Every value sent, across every classification path, avoids the forbidden tokens."""
    for point in (_FULL, _CANARY):
        ctx, sent = _ctx(render)
        await el.detect_combined(point, _baseline(), ctx)
        for value in sent:
            assert not any(token in value for token in _FORBIDDEN), value
