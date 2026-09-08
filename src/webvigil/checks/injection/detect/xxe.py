"""
In-band XXE detector — opt-in content-type flip on POST points (spec 012, RF-04, ADR-2, ADR-4).

WebVigil has no XML injection points from crawling, so for each POST injection
point the detector re-sends the point's body as ``application/xml`` / ``text/xml``
carrying an external-entity payload set:

* a ``SYSTEM`` entity reading ``file:///etc/passwd`` / ``win.ini`` — a hit needs
  the file's content reflected (shared with the traversal signatures);
* a parameter-entity referencing an in-scope external DTD — a hit needs an
  XML-parser error naming the entity / DTD (the *error* is the proof, not a
  successful fetch);
* a bounded nested-entity payload to draw an entity-expansion-limit error.

Runs only when ``[injection] xxe`` is on (it rewrites the request body and most
endpoints reject it). Blind / OOB XXE needs a collaborator and is not on the
roadmap.
"""

from __future__ import annotations

import re
import secrets

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.core.findings import Confidence, Severity

_CHECK_ID = "injection.xxe"


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    """
    Re-send the POST body as XML with an XXE payload; look for a file read or a parser error.

    Args:
        point (InjectionPoint): The point under test — non-POST points are
            skipped (the content-type flip is POST-only).
        baseline (Baseline): Its baseline response; every proof must be absent
            from it.
        ctx (DetectCtx): The budget-aware send context; ``ctx.self_url`` fills
            the parameter-entity DTD URL.

    Returns:
        list[InjectionHit]: A single ``xxe`` hit — HIGH/HIGH for a file read,
            HIGH/MEDIUM for a parser error — or empty.
    """
    if point.method != "POST":
        return []
    token = secrets.token_hex(6)
    for content_type in payloads.XXE_CONTENT_TYPES:
        for template in payloads.XXE_PAYLOADS:
            for file_url in payloads.XXE_FILES if "{file}" in template else ("",):
                body = template.format(file=file_url, dtd=ctx.self_url, token=token)
                response = await ctx.send(point, body, content_type=content_type)
                if response is None:
                    return []
                file_sig = _first_match(
                    payloads.TRAVERSAL_SIGNATURES, response.text, baseline.raw_body
                )
                if file_sig is not None:
                    return [
                        _hit(
                            point, body, Severity.HIGH, Confidence.HIGH, "local file read", file_sig
                        )
                    ]
                err = _first_match(payloads.XXE_ERROR_SIGNATURES, response.text, baseline.raw_body)
                if err is not None:
                    return [
                        _hit(point, body, Severity.HIGH, Confidence.MEDIUM, "XML parser error", err)
                    ]
    return []


def _first_match(
    patterns: tuple[re.Pattern[str], ...], text: str, baseline_text: str
) -> str | None:
    """
    Args:
        patterns (tuple[re.Pattern[str], ...]): Patterns to try in order.
        text (str): The response body.
        baseline_text (str): The baseline body; a pattern also present here is
            skipped.

    Returns:
        str | None: A trimmed line around the first baseline-absent match, or
            ``None``.
    """
    for pattern in patterns:
        match = pattern.search(text)
        if match and not pattern.search(baseline_text):
            start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.start())
            line = text[start : end if end != -1 else len(text)].strip()
            return line[:200] + ("…" if len(line) > 200 else "")
    return None


def _hit(
    point: InjectionPoint,
    body: str,
    severity: Severity,
    confidence: Confidence,
    mechanism: str,
    proof: str,
) -> InjectionHit:
    """
    Args:
        point (InjectionPoint): The point under test.
        body (str): The XML payload sent.
        severity (Severity): HIGH.
        confidence (Confidence): HIGH for a file read, MEDIUM for a parser error.
        mechanism (str): ``"local file read"`` or ``"XML parser error"``.
        proof (str): The leaked line or the error text.

    Returns:
        InjectionHit: An ``xxe`` hit.
    """
    return InjectionHit(
        kind="xxe",
        check_id=_CHECK_ID,
        method=point.method,
        url=point.base_url,
        param=point.param,
        severity=severity,
        confidence=confidence,
        title=f"XML external entity (XXE) via the '{point.param}' parameter ({mechanism})",
        payload=body,
        evidence=(
            ("Injection point", f"{point.method} {point.base_url} — parameter '{point.param}'"),
            ("XML payload", body),
            (mechanism.capitalize(), proof),
        ),
    )
