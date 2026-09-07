"""
Path-traversal / LFI detector — read a known file, prove it by its signature (RF-10).

The payload replaces the parameter value; a hit needs a ``/etc/passwd`` or
``win.ini`` signature in the response that is absent from the baseline (RF-13).
"""

from __future__ import annotations

from webvigil.checks.injection import payloads
from webvigil.checks.injection.detect import DetectCtx
from webvigil.checks.injection.models import Baseline, InjectionHit, InjectionPoint
from webvigil.core.findings import Confidence, Severity

_CHECK_ID = "injection.traversal.path"


async def detect(point: InjectionPoint, baseline: Baseline, ctx: DetectCtx) -> list[InjectionHit]:
    """
    Args:
        point (InjectionPoint): The point under test.
        baseline (Baseline): Its baseline response; the signature must be absent
            from it.
        ctx (DetectCtx): The budget-aware send context.

    Returns:
        list[InjectionHit]: A single ``traversal`` hit when a known-file
            signature appears in a response but not the baseline, else empty.
    """
    for payload in payloads.TRAVERSAL:
        response = await ctx.send(point, payload)
        if response is None:
            break
        for pattern in payloads.TRAVERSAL_SIGNATURES:
            match = pattern.search(response.text)
            if match and not pattern.search(baseline.raw_body):
                return [
                    InjectionHit(
                        kind="traversal",
                        check_id=_CHECK_ID,
                        method=point.method,
                        url=point.base_url,
                        param=point.param,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title=f"Path traversal via the '{point.param}' parameter",
                        payload=payload,
                        evidence=(
                            (
                                "Injection point",
                                f"{point.method} {point.base_url} — parameter '{point.param}'",
                            ),
                            ("Payload", payload),
                            ("Leaked content", _line_around(response.text, match.start())),
                        ),
                    )
                ]
    return []


def _line_around(body: str, index: int, *, limit: int = 200) -> str:
    """
    Args:
        body (str): The response body.
        index (int): Offset of the match.
        limit (int): Maximum characters to keep. Defaults to 200.

    Returns:
        str: The single line containing ``index``, trimmed to ``limit``.
    """
    start = body.rfind("\n", 0, index) + 1
    end = body.find("\n", index)
    line = body[start : end if end != -1 else len(body)].strip()
    return line[:limit] + ("…" if len(line) > limit else "")
