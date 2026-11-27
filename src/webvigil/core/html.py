"""
Parse HTML from the scanned site within a bounded time.

The parser's tree builder looks through its stack of open elements for most start tags, so a
document costs about its length times the depth of the elements it keeps open: one that only
opens elements costs the square of its length or more, and the parser has no depth limit.
:func:`parse_html` is the one way the engine parses HTML from the target:

* it hands the parser at most :data:`MAX_PARSE_CHARS` characters of a document;
* it parses in a worker thread (the parser releases the GIL) and waits :data:`PARSE_TIMEOUT_S`
  for it: a document not parsed by then is read only in its first :data:`FALLBACK_CHARS`
  characters, which no markup makes slow, and the worker is left to finish on its own;
* while such a worker is still running, every longer document is read only in its first
  :data:`FALLBACK_CHARS` characters, so at most one parse outlives its deadline at a time.

A scan counts the documents it read in part (:func:`track_partial_parses`) and warns about them.
"""

from __future__ import annotations

import threading
from contextvars import ContextVar
from dataclasses import dataclass, field

from selectolax.lexbor import LexborHTMLParser

# Characters of a document the parser gets: a legitimate page this long parses in a fraction
# of a second, and the worst markup of this length ends in minutes, not hours.
MAX_PARSE_CHARS = 2 * 1024 * 1024
# Seconds to wait for one parse.
PARSE_TIMEOUT_S = 5.0
# Characters parsed when the full parse did not end in time: no markup this short takes long.
FALLBACK_CHARS = 16 * 1024
# Distinct documents a scan remembers for each count.
_REMEMBERED = 10_000

_lock = threading.Lock()
_running: list[threading.Thread] = []


# ---------------------------------------------------------------------------
# Documents read in part
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PartialParses:
    """
    The documents one scan read only in part, by their hash.

    Attributes:
        cut (set[int]): Documents longer than :data:`MAX_PARSE_CHARS`, parsed up to it.
        late (set[int]): Documents read only in their first :data:`FALLBACK_CHARS` characters,
            because a parse did not end in :data:`PARSE_TIMEOUT_S` seconds.
    """

    cut: set[int] = field(default_factory=set)
    late: set[int] = field(default_factory=set)

    def warnings(self) -> list[str]:
        """
        Returns:
            list[str]: The scan warnings for these documents, one per reason.
        """
        lines: list[str] = []
        if self.cut:
            lines.append(
                f"{len(self.cut)} HTML document(s) were longer than "
                f"{MAX_PARSE_CHARS // (1024 * 1024)} MiB and were parsed only up to it: links, "
                "forms and markup past it were not analysed"
            )
        if self.late:
            lines.append(
                f"{len(self.late)} HTML document(s) were read only in their first "
                f"{FALLBACK_CHARS // 1024} KiB, because parsing the target's HTML did not end "
                f"within {PARSE_TIMEOUT_S:g} s: links, forms and markup past it were not analysed"
            )
        return lines


_PARTIAL: ContextVar[PartialParses | None] = ContextVar("webvigil_partial_parses", default=None)


def track_partial_parses() -> PartialParses:
    """
    Start counting, for the calling scan, the documents read only in part.

    Returns:
        PartialParses: The counts, filled in by every :func:`parse_html` in this context.
    """
    partial = PartialParses()
    _PARTIAL.set(partial)
    return partial


def _note(kind: str, text: str) -> None:
    """
    Args:
        kind (str): ``"cut"`` or ``"late"``.
        text (str): The document it is about.
    """
    partial = _PARTIAL.get()
    if partial is None:
        return
    seen = partial.cut if kind == "cut" else partial.late
    if len(seen) < _REMEMBERED:
        seen.add(hash(text))


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _worker_running() -> bool:
    """
    Returns:
        bool: Whether a parse that outlived its deadline is still running.
    """
    with _lock:
        _running[:] = [worker for worker in _running if worker.is_alive()]
        return bool(_running)


def _parse_into(text: str, box: list[LexborHTMLParser | BaseException]) -> None:
    """
    Args:
        text (str): The document.
        box (list[LexborHTMLParser | BaseException]): Receives the parsed document, or the
            exception the parser raised.
    """
    try:
        box.append(LexborHTMLParser(text))
    except BaseException as exc:  # handed to the caller, which raises it
        box.append(exc)


def parse_html(text: str) -> LexborHTMLParser:
    """
    Parse a document from the target, in at most about :data:`PARSE_TIMEOUT_S` seconds.

    Args:
        text (str): The document.

    Returns:
        LexborHTMLParser: The parsed document, or its first :data:`FALLBACK_CHARS` characters.
    """
    if len(text) <= FALLBACK_CHARS:
        return LexborHTMLParser(text)
    if _worker_running():
        _note("late", text)
        return LexborHTMLParser(text[:FALLBACK_CHARS])
    document = text
    if len(text) > MAX_PARSE_CHARS:
        _note("cut", text)
        document = text[:MAX_PARSE_CHARS]
    box: list[LexborHTMLParser | BaseException] = []
    worker = threading.Thread(
        target=_parse_into, args=(document, box), name="webvigil-html-parse", daemon=True
    )
    worker.start()
    worker.join(PARSE_TIMEOUT_S)
    if box:
        result = box[0]
        if isinstance(result, BaseException):
            raise result
        return result
    with _lock:
        _running.append(worker)
    _note("late", text)
    return LexborHTMLParser(text[:FALLBACK_CHARS])
