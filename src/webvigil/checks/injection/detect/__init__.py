"""
The per-class injection detectors and the context they run in (spec 006, RF-08..RF-11).

Each detector is ``async def detect(point, baseline, ctx) -> list[InjectionHit]``.
It never touches the budget directly — :meth:`DetectCtx.send` reserves the
request and returns ``None`` when a cap is reached, at which point the detector
simply stops.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from webvigil.checks.injection.models import InjectionPoint
from webvigil.http.client import Response

_HIDDEN_INPUT = re.compile(r"<input[^>]*\btype=[\"']?hidden[\"']?[^>]*>", re.I)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-]{20,}")
_WS = re.compile(r"\s+")


def normalize_body(text: str) -> str:
    """
    Collapse whitespace and mask the tokens that vary between two identical requests.

    Args:
        text (str): A response body.

    Returns:
        str: The normalised body — hidden inputs removed, long tokens (CSRF
            tokens, nonces) masked, whitespace collapsed — suitable for a
            similarity ratio.
    """
    text = _HIDDEN_INPUT.sub("", text)
    text = _LONG_TOKEN.sub("*", text)
    return _WS.sub(" ", text).strip()


class Sender(Protocol):
    """The bound send function a detector calls; it owns the budget accounting."""

    async def __call__(
        self, point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None:
        """
        Args:
            point (InjectionPoint): The point to replay.
            value (str): The value to place in the point's slot.
            time_based (bool): Charge this against the time-based sub-budget.
                Defaults to ``False``.

        Returns:
            Response | None: The response, or ``None`` when a budget cap left no
                room — the detector should then stop.
        """
        ...


@dataclass(frozen=True, slots=True)
class DetectCtx:
    """
    What a detector needs besides the point and its baseline.

    Attributes:
        send (Sender): The budget-aware send function.
        delay_s (int): The configured ``[injection] time_based_delay_s``.
        host (str): The target host, for the ``{host}`` payload substitution.
        time_based_cmdi (bool): The configured ``[injection] time_based_cmdi`` —
            gates the command-injection detector's sleep stage (spec 011).
            Defaults to ``True``.
    """

    send: Sender
    delay_s: int
    host: str
    time_based_cmdi: bool = True
