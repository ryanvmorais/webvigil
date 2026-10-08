"""
Expression-language injection detector — SpEL, OGNL, JEXL, MVEL, Unified EL (spec 016).

Proves evaluation the way the SSTI detector does: a per-request marker glued to the computed
product of two random operands, absent from the baseline (ADR-1 of spec 011, kept as the
contract). It differs in what it does with a hit. A delimiter form that evaluates
(``${…}``, ``#{…}``, ``*{…}``) is ambiguous — Freemarker evaluates ``${…}`` too — so the
evaluator is classified from the *evidence*, never from the delimiter alone (ADR-2): OGNL's
``%{…}`` and the bare string-concatenation form are EL by construction (ADR-4), and a pure
static call (``T(java.lang.Math).abs(-n)`` / ``@java.lang.Math@abs(-n)``) proves the type
system is reachable, which upgrades the finding to CRITICAL (ADR-3).

Two of the three entry points exist because ``ssti`` and ``el`` overlap on the ambiguous forms
and on the polyglot probe, and each draws its own marker: two independent detectors could not
share a response (ADR-1). ``detect_combined`` runs both checks in one pass and emits ``ssti``
hits exactly as :func:`~webvigil.checks.injection.detect.ssti.detect` would; ``detect_el`` runs
only the EL stages; ``ssti`` alone keeps using the untouched SSTI detector.
"""

from __future__ import annotations

import random
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx, ssti
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.checks.injection.points import is_commandlike, is_exprlike
from webvigil.core.findings import Confidence, Severity

_CHECK_ID = "injection.el"

# How much of a matched error signature rides the evidence.
_EXCERPT_MAX = 120

# Dialects whose syntax has no ``T()`` / ``@class@method`` form: named by their error
# signature, never probed for type access.
_NO_TYPE_PROBE = frozenset({"JEXL", "MVEL", "Unified EL"})

# Which delimiter form each ambiguous ``arith_payloads`` hint becomes in the combined routine.
_AMBIGUOUS_LABEL = {"Freemarker/EL": "dollar", "Slim/Pug": "hash", "Thymeleaf": "star"}

type _Category = Literal["template", "ambiguous", "ognl", "bare"]


@dataclass(frozen=True, slots=True)
class _Form:
    """
    One way to wrap an expression so the target's evaluator might run it.

    Attributes:
        label (str): ``"dollar"`` / ``"hash"`` / ``"star"`` / ``"percent"`` / ``"bare"`` /
            ``"bare-escape"``, or the ``arith_payloads`` hint for a template form.
        category (_Category): ``"template"`` (a template-only delimiter, left to ``ssti``),
            ``"ambiguous"`` (an EL delimiter a template engine also uses), ``"ognl"``
            (``%{…}``) or ``"bare"`` (the value is itself an expression).
        wrap (Callable[[InjectionPoint, str, str], str]): ``wrap(point, marker, inner)`` —
            the full value to send, where ``inner`` is the expression text. The one seam the
            arithmetic stage and the type-access probes share.
    """

    label: str
    category: _Category
    wrap: Callable[[InjectionPoint, str, str], str]


@dataclass(frozen=True, slots=True)
class _Signature:
    """
    An EL error found in a response.

    Attributes:
        dialect (str): The dialect whose signature matched.
        excerpt (str): The matched line, shortened for the evidence.
        payload (str): The value that drew the error.
    """

    dialect: str
    excerpt: str
    payload: str


@dataclass(frozen=True, slots=True)
class _Verdict:
    """
    What the evidence says about the evaluator.

    Attributes:
        dialect (str): ``"SpEL"`` / ``"OGNL"`` / ``"JEXL"`` / ``"MVEL"`` / ``"Unified EL"`` /
            ``"unknown"``.
        source (str): What named it — ``"type-access probe"``, ``"%{} syntax"`` or
            ``"error signature"``; empty when the dialect is unknown.
        type_probe (tuple[str, str] | None): ``(payload, needle)`` of the static call that
            evaluated, or ``None``.
        signature (str | None): The error excerpt that contributed, or ``None``.
    """

    dialect: str
    source: str
    type_probe: tuple[str, str] | None
    signature: str | None


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


async def detect_el(
    point: InjectionPoint, baseline: Baseline, ctx: DetectCtx
) -> list[InjectionHit]:
    """
    Run only the expression-language stages (``injection.el`` selected, ``ssti`` not).

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response; every proof must be absent from it.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: At most one ``el`` hit, or empty.
    """
    return await _run(point, baseline, ctx, templates=False)


async def detect_combined(
    point: InjectionPoint, baseline: Baseline, ctx: DetectCtx
) -> list[InjectionHit]:
    """
    Run the SSTI and EL stages in one pass (both checks selected).

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response; every proof must be absent from it.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: At most one hit — ``ssti`` (as the SSTI detector would build it)
            or ``el`` — so one proof is never reported by two checks.
    """
    return await _run(point, baseline, ctx, templates=True)


# ---------------------------------------------------------------------------
# The routine
# ---------------------------------------------------------------------------


async def _run(
    point: InjectionPoint, baseline: Baseline, ctx: DetectCtx, *, templates: bool
) -> list[InjectionHit]:
    """
    Polyglot probe, arithmetic loop, classification, then the signature-only fallback.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response.
        ctx (DetectCtx): The budget-aware send context.
        templates (bool): Also run the template-engine forms and emit ``ssti`` hits
            (``True`` for the combined entry, ``False`` for the EL-only one).

    Returns:
        list[InjectionHit]: At most one hit.
    """
    full = is_commandlike(point) or is_exprlike(point)

    # 1. Shared polyglot probe: names a template engine or an EL dialect from an error.
    polyglot = point.original + payloads.SSTI_POLYGLOT
    probe = await ctx.send(point, polyglot)
    if probe is None:
        return []
    engine = ssti.engine_from_error(probe.text, baseline.raw_body) if templates else None
    signature = _signature(probe.text, baseline.raw_body, polyglot)

    # 2. Arithmetic loop: marker + operands drawn once, as the SSTI detector does.
    marker = "wv" + secrets.token_hex(payloads.SSTI_MARKER_BYTES)
    a, b = random.randint(11, 99), random.randint(11, 99)
    needle = f"{marker}{a * b}"
    for form in _forms(marker, a, b, templates=templates, full=full, engine=engine):
        response = await ctx.send(point, form.wrap(point, marker, f"{a}*{b}"))
        if response is None:
            return []
        if needle in response.text and needle not in baseline.raw_body:
            return await _classify(
                point, baseline, ctx, form, marker, (a, b), engine, signature, templates
            )

    # 3. Nothing evaluated: an unterminated expression may still draw a parse error.
    if full and signature is None:
        signature = await _unterminated_probe(point, baseline, ctx)
    return [_signature_hit(point, signature)] if signature else []


# ---------------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------------


def _forms(
    marker: str, a: int, b: int, *, templates: bool, full: bool, engine: str | None
) -> list[_Form]:
    """
    Build the ordered forms to try, per the Form tables in the design.

    Args:
        marker (str): The per-request marker.
        a (int): First operand.
        b (int): Second operand.
        templates (bool): Include the template-engine forms.
        full (bool): ``True`` for a command- or expression-shaped point (the full set),
            ``False`` for any other (the canary set).
        engine (str | None): The template engine named by the polyglot error, which moves
            its forms to the front exactly as the SSTI detector does.

    Returns:
        list[_Form]: The forms, each label at most once.
    """
    el = {form.label: form for form in _el_forms()}
    sequence: list[_Form] = []
    extras: tuple[str, ...]
    if templates:
        pairs = payloads.arith_payloads(marker, a, b)
        if engine is not None:
            pairs = ssti.engine_first(pairs, engine)
        if not full:
            pairs = pairs[: ssti.CANARY_LIMIT]
        for hint, expr in pairs:
            label = _AMBIGUOUS_LABEL.get(hint)
            sequence.append(el[label] if label else _template_form(hint, expr))
        extras = ("percent", "bare", "bare-escape") if full else ("hash", "percent", "bare")
    elif full:
        extras = ("dollar", "hash", "star", "percent", "bare", "bare-escape")
    else:
        extras = ("dollar", "hash", "percent", "bare")
    seen = {form.label for form in sequence}
    sequence.extend(el[label] for label in extras if label not in seen)
    return sequence


def _el_forms() -> list[_Form]:
    """
    Returns:
        list[_Form]: The four EL delimiter forms and the two bare-expression forms.
    """
    forms: list[_Form] = []
    for label, opening, closing in payloads.EL_DELIMITERS:
        category: _Category = "ognl" if label == "percent" else "ambiguous"
        forms.append(_Form(label, category, _delimited(opening, closing)))
    forms.append(_Form("bare", "bare", _bare_whole))
    forms.append(_Form("bare-escape", "bare", _bare_escape))
    return forms


def _delimited(opening: str, closing: str) -> Callable[[InjectionPoint, str, str], str]:
    """
    Args:
        opening (str): The opening delimiter, e.g. ``"${"``.
        closing (str): The closing delimiter, e.g. ``"}"``.

    Returns:
        Callable[[InjectionPoint, str, str], str]: A ``wrap`` that appends
            ``<marker><opening><inner><closing>`` to the point's original value.
    """

    def wrap(point: InjectionPoint, marker: str, inner: str) -> str:
        return f"{point.original}{marker}{opening}{inner}{closing}"

    return wrap


def _bare_whole(point: InjectionPoint, marker: str, inner: str) -> str:
    """
    Args:
        point (InjectionPoint): The point under test; unused, the value is replaced.
        marker (str): The per-request marker.
        inner (str): The expression text.

    Returns:
        str: The whole value as a string-concatenation expression.
    """
    return payloads.EL_BARE_WHOLE.format(marker=marker, inner=inner)


def _bare_escape(point: InjectionPoint, marker: str, inner: str) -> str:
    """
    Args:
        point (InjectionPoint): The point under test.
        marker (str): The per-request marker.
        inner (str): The expression text.

    Returns:
        str: The original value followed by a quote-closing concatenation expression.
    """
    return point.original + payloads.EL_BARE_ESCAPE.format(marker=marker, inner=inner)


def _template_form(hint: str, expr: str) -> _Form:
    """
    Args:
        hint (str): The ``arith_payloads`` engine hint.
        expr (str): The ready-made payload suffix from ``arith_payloads``.

    Returns:
        _Form: A template-only form whose ``wrap`` ignores ``inner`` — its operands are
            already baked into ``expr``.
    """

    def wrap(point: InjectionPoint, marker: str, inner: str) -> str:
        return point.original + expr

    return _Form(hint, "template", wrap)


# ---------------------------------------------------------------------------
# Signatures and probes
# ---------------------------------------------------------------------------


def _signature(text: str, baseline_text: str, payload: str) -> _Signature | None:
    """
    Args:
        text (str): A response body.
        baseline_text (str): The baseline body; a signature also present there is ignored.
        payload (str): The value that drew ``text``.

    Returns:
        _Signature | None: The first EL signature in ``text`` and not in the baseline, or
            ``None``.
    """
    for dialect, pattern in payloads.EL_ERROR_SIGNATURES:
        found = pattern.search(payloads.head(text))
        if found and not pattern.search(payloads.head(baseline_text)):
            line = text[found.start() :].splitlines()[0]
            return _Signature(dialect, line[:_EXCERPT_MAX], payload)
    return None


async def _unterminated_probe(
    point: InjectionPoint, baseline: Baseline, ctx: DetectCtx
) -> _Signature | None:
    """
    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        _Signature | None: The first EL error an unterminated expression draws, or ``None``
            (also ``None`` once the budget is spent).
    """
    for suffix in payloads.EL_UNTERMINATED:
        payload = point.original + suffix
        response = await ctx.send(point, payload)
        if response is None:
            return None
        found = _signature(response.text, baseline.raw_body, payload)
        if found:
            return found
    return None


async def _probe_type_access(
    point: InjectionPoint,
    baseline: Baseline,
    ctx: DetectCtx,
    form: _Form,
    marker: str,
    dialects: tuple[str, ...],
) -> tuple[tuple[str, str, str] | None, _Signature | None]:
    """
    Send the pure static-call probes through the form that already evaluated arithmetic.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response.
        ctx (DetectCtx): The budget-aware send context.
        form (_Form): The form that evaluated.
        marker (str): The per-request marker.
        dialects (tuple[str, ...]): Which probes to send, in order (``"SpEL"`` / ``"OGNL"``).

    Returns:
        tuple[tuple[str, str, str] | None, _Signature | None]: ``(dialect, payload, needle)``
            of the first probe that evaluated, and the first EL error a probe response
            carried (a sandboxed evaluator rejecting the call names itself); both ``None``
            when nothing was learned.
    """
    templates = {"SpEL": payloads.EL_SPEL_PROBE, "OGNL": payloads.EL_OGNL_PROBE}
    refused: _Signature | None = None
    for dialect in dialects:
        n = random.randint(101, 999)
        value = form.wrap(point, marker, templates[dialect].format(n=n))
        response = await ctx.send(point, value)
        if response is None:
            break
        needle = f"{marker}{n}"
        if needle in response.text and needle not in baseline.raw_body:
            return (dialect, value, needle), refused
        refused = refused or _signature(response.text, baseline.raw_body, value)
    return None, refused


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


async def _classify(
    point: InjectionPoint,
    baseline: Baseline,
    ctx: DetectCtx,
    form: _Form,
    marker: str,
    operands: tuple[int, int],
    engine: str | None,
    signature: _Signature | None,
    templates: bool,
) -> list[InjectionHit]:
    """
    Decide which check owns an arithmetic hit, per the Classification table.

    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response.
        ctx (DetectCtx): The budget-aware send context.
        form (_Form): The form that evaluated.
        marker (str): The per-request marker.
        operands (tuple[int, int]): The two operands that were multiplied.
        engine (str | None): The template engine named by the polyglot error, if any.
        signature (_Signature | None): The EL error the polyglot drew, if any.
        templates (bool): Whether ``ssti`` hits may be emitted (the combined entry).

    Returns:
        list[InjectionHit]: One ``ssti`` hit (a template form, or an ambiguous form with no
            EL evidence, when ``templates``), one ``el`` hit, or empty.
    """
    a, b = operands
    needle = f"{marker}{a * b}"
    payload = form.wrap(point, marker, f"{a}*{b}")
    if form.category == "template":
        engine = engine or await ssti.identify_engine(point, ctx, marker)
        return [ssti.build_hit(point, engine, payload, needle, a, b)]

    dialects = _probe_dialects(form, signature)
    probed, refused = await _probe_type_access(point, baseline, ctx, form, marker, dialects)
    if probed is not None:
        dialect, probe_payload, probe_needle = probed
        verdict = _Verdict(dialect, "type-access probe", (probe_payload, probe_needle), None)
        return [_el_hit(point, verdict, payload, needle, a, b)]

    named = refused or signature  # the probe's own refusal is the better evidence
    if form.category == "ognl":
        verdict = _Verdict("OGNL", "%{} syntax", None, named.excerpt if named else None)
    elif named is not None:
        verdict = _Verdict(named.dialect, "error signature", None, named.excerpt)
    elif form.category == "bare":
        verdict = _Verdict("unknown", "", None, None)
    elif templates:  # an ambiguous delimiter with no EL evidence is a template (ADR-2)
        engine = engine or await ssti.identify_engine(point, ctx, marker)
        return [ssti.build_hit(point, engine, payload, needle, a, b)]
    else:
        return []
    return [_el_hit(point, verdict, payload, needle, a, b)]


def _probe_dialects(form: _Form, signature: _Signature | None) -> tuple[str, ...]:
    """
    Args:
        form (_Form): The form that evaluated.
        signature (_Signature | None): The EL error the polyglot drew, if any.

    Returns:
        tuple[str, ...]: The type-access probes worth sending: only OGNL's for ``%{…}``,
            only the named dialect's when a signature already names SpEL or OGNL, none for a
            dialect with no static-call syntax, both otherwise.
    """
    if form.category == "ognl":
        return ("OGNL",)
    if signature is not None:
        if signature.dialect in _NO_TYPE_PROBE:
            return ()
        return (signature.dialect,)
    return ("SpEL", "OGNL")


# ---------------------------------------------------------------------------
# Hits
# ---------------------------------------------------------------------------


def _label(dialect: str) -> str:
    """
    Args:
        dialect (str): A dialect name or ``"unknown"``.

    Returns:
        str: The wording used inside a finding title.
    """
    return "expression language, dialect unknown" if dialect == "unknown" else dialect


def _el_hit(
    point: InjectionPoint, verdict: _Verdict, payload: str, needle: str, a: int, b: int
) -> InjectionHit:
    """
    Args:
        point (InjectionPoint): The point under test.
        verdict (_Verdict): What the evidence says about the evaluator.
        payload (str): The arithmetic payload that evaluated.
        needle (str): The ``<marker><product>`` string found in the response.
        a (int): First operand.
        b (int): Second operand.

    Returns:
        InjectionHit: An ``el`` hit — CRITICAL when a type-access probe evaluated, HIGH
            otherwise; confidence HIGH (the arithmetic itself was proved).
    """
    evidence = [
        ("Injection point", f"{point.method} {point.base_url} — parameter '{point.param}'"),
        ("Payload", payload),
        ("Evaluated expression", f"{needle}  (= {a} * {b})"),
    ]
    if verdict.type_probe is not None:
        probe_payload, probe_needle = verdict.type_probe
        evidence.append(("Type access", f"{probe_payload}  ->  {probe_needle}"))
    if verdict.source:
        evidence.append(("Dialect", f"{verdict.dialect} — {verdict.source}"))
    if verdict.signature:
        evidence.append(("Error signature", verdict.signature))
    return InjectionHit(
        kind="el",
        check_id=_CHECK_ID,
        method=point.method,
        url=point.base_url,
        param=point.param,
        severity=Severity.CRITICAL if verdict.type_probe is not None else Severity.HIGH,
        confidence=Confidence.HIGH,
        title=(
            f"Expression-language injection ({_label(verdict.dialect)}) "
            f"via the '{point.param}' parameter"
        ),
        payload=payload,
        evidence=tuple(evidence),
    )


def _signature_hit(point: InjectionPoint, signature: _Signature) -> InjectionHit:
    """
    Args:
        point (InjectionPoint): The point under test.
        signature (_Signature): The EL error that was drawn, with nothing evaluated.

    Returns:
        InjectionHit: An ``el`` hit at HIGH severity but MEDIUM confidence: the evaluator is
            there, and it rejected the input rather than running it.
    """
    return InjectionHit(
        kind="el",
        check_id=_CHECK_ID,
        method=point.method,
        url=point.base_url,
        param=point.param,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        title=(
            f"Expression-language injection ({signature.dialect}) "
            f"via the '{point.param}' parameter"
        ),
        payload=signature.payload,
        evidence=(
            ("Injection point", f"{point.method} {point.base_url} — parameter '{point.param}'"),
            ("Payload", signature.payload),
            ("Error signature", signature.excerpt),
            ("Dialect", f"{signature.dialect} — error signature"),
        ),
    )
