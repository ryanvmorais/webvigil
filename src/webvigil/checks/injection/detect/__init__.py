"""The per-class injection detectors and the context they run in (spec 006, RF-08..RF-11).

Each detector is ``async def detect(point, baseline, ctx) -> list[InjectionHit]``. It never
touches the budget directly — :meth:`DetectCtx.send` reserves the request and returns
``None`` when a cap is reached, at which point the detector simply stops.
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
    """Collapse whitespace and mask the tokens that vary between two identical requests."""
    text = _HIDDEN_INPUT.sub("", text)
    text = _LONG_TOKEN.sub("*", text)
    return _WS.sub(" ", text).strip()


class Sender(Protocol):
    async def __call__(
        self, point: InjectionPoint, value: str, *, time_based: bool = False
    ) -> Response | None: ...


@dataclass(frozen=True, slots=True)
class DetectCtx:
    """What a detector needs besides the point and its baseline."""

    send: Sender
    delay_s: int  # [injection] time_based_delay_s
    host: str  # target host, for the {host} redirect payload
