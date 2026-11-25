r"""
One place for the treatment of text on its way out: redaction, a size bound, neutralization.

Text that WebVigil did not write reaches every output: what the scanned site sent, what a file
held, the message of an exception. Before it leaves it is redacted (no credential or session
value of the scan), bounded (no value grows past a known ceiling) and neutralized (control,
bidirectional and zero-width characters are shown, not acted on). Spec 025 gathers the three
here, in that order, so an output names *what kind of output it is* (a :class:`Sink`) and gets
the treatment that kind needs, the same from every caller.

- :func:`safe_text` runs the treatments for one sink. Each sink has a fixed profile (the bound
  and the neutralization); the field types of :mod:`webvigil.core.bounded` are the declared form
  of the ``STORE`` profile, with one implementation (:func:`~webvigil.core.bounded.store_text`).
- :class:`Redactor` replaces every spelling of the scan's secrets and also recognizes a cut: a
  fragment of a secret (4 characters or more) next to a cut marker, or at the edge of a piece of
  evidence, is hidden too, so a secret that straddled the point where a check or a field bound cut
  the text leaves nothing behind.
- :func:`safe_traceback`, :class:`SafeLogFilter` and :func:`get_logger` give the log the same
  rule: each exception's text stays on its line, and the record is bounded.

The bound runs before the neutralization in every profile, so a cut never splits an escape and
the bound counts what the source held.
"""

from __future__ import annotations

import html
import json
import logging
import re
import traceback
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from urllib.parse import quote, quote_plus

from webvigil.core.bounded import (
    EVIDENCE_MARKER,
    NAME_MAX_CHARS,
    TEXT_MAX_CHARS,
    TRUNCATION_MARKER,
    URL_MAX_CHARS,
    store_text,
)
from webvigil.core.secrets import REDACTED
from webvigil.core.text import escape_json_controls, replace_surrogates, show_controls

# ---------------------------------------------------------------------------
# Limits and markers
# ---------------------------------------------------------------------------

# The most characters of one terminal message or field (before the marker): the full text stays
# in the report.
TERMINAL_MAX_CHARS: Final = 4096

# A secret shorter than this is left alone: replacing a 1-3 character string would shred the
# report (every "a" in a title). The same floor holds for a fragment next to a cut.
MIN_SECRET_LENGTH: Final = 4

# What the engine and its checks write where they cut text: the field bound's marker, the
# evidence marker, and the ellipses of the snippet helpers. Longest first, so the evidence
# marker's cut point is found before the line break it starts with.
CUT_MARKERS: Final[tuple[str, ...]] = (EVIDENCE_MARKER, TRUNCATION_MARKER, "...", "\u2026")

# ``quote`` writes upper-case hex (``%2F``); some servers echo it lower case (``%2f``), so each
# encoded spelling is also scrubbed with its escapes lowered.
_PERCENT_RE = re.compile(r"%[0-9A-F]{2}")

# How much of an exception group the log shows, as ``traceback`` does.
_GROUP_WIDTH: Final = 15
_GROUP_DEPTH: Final = 10
_CAUSE_LINE: Final = "The above exception was the direct cause of the following exception:"
_CONTEXT_LINE: Final = "During handling of the above exception, another exception occurred:"


# ---------------------------------------------------------------------------
# Sinks and their profiles
# ---------------------------------------------------------------------------


class Sink(StrEnum):
    r"""
    A kind of output, each with its own profile (:func:`safe_text`).

    Attributes:
        TERMINAL: The CLI's messages and tables: 4 Ki characters, controls shown, one line or
            not per call.
        LOG: A server log record: a 16 Ki message, controls shown on one line.
        MESSAGE: A message in an API answer (the ``422`` body): 1 Ki characters, on one line.
        STORE: A stored free-text value: the field's bound (16 Ki by default) and surrogates
            replaced; controls are kept and neutralized where the value is shown.
        DOCUMENT: A rendered HTML or Markdown page: every field is already bounded, controls
            shown over the whole page.
        JSON: An encoded JSON document: DEL, the C1 controls and the invisible characters as
            ``\uNNNN`` escapes.
    """

    TERMINAL = "terminal"
    LOG = "log"
    MESSAGE = "message"
    STORE = "store"
    DOCUMENT = "document"
    JSON = "json"


@dataclass(frozen=True, slots=True)
class _Profile:
    """
    Attributes:
        limit (int | None): The most characters kept before the truncation marker, or ``None``
            when the text is not bounded here.
        neutralize (Callable[[str, bool], str]): The neutralization, given the text and the
            caller's ``one_line``.
    """

    limit: int | None
    neutralize: Callable[[str, bool], str]


def _as_stored(value: str, _one_line: bool) -> str:
    """Keep the text as bounded: a stored value is neutralized where it is shown."""
    return value


def _controls(value: str, one_line: bool) -> str:
    """Show the controls, on one line when the caller asks."""
    return show_controls(value, one_line=one_line)


def _on_one_line(value: str, _one_line: bool) -> str:
    """Show the controls, line breaks included: the record or message keeps its one line."""
    return show_controls(value, one_line=True)


def _page(value: str, _one_line: bool) -> str:
    """Show the controls of a whole page, keeping its line breaks."""
    return show_controls(value)


def _json_document(value: str, _one_line: bool) -> str:
    """Escape what a JSON encoder writes raw."""
    return escape_json_controls(value)


_PROFILES: Final[Mapping[Sink, _Profile]] = {
    Sink.TERMINAL: _Profile(TERMINAL_MAX_CHARS, _controls),
    Sink.LOG: _Profile(TEXT_MAX_CHARS, _on_one_line),
    Sink.MESSAGE: _Profile(NAME_MAX_CHARS, _on_one_line),
    Sink.STORE: _Profile(TEXT_MAX_CHARS, _as_stored),
    Sink.DOCUMENT: _Profile(None, _page),
    Sink.JSON: _Profile(None, _json_document),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def safe_text(
    value: str,
    sink: Sink,
    *,
    one_line: bool = False,
    limit: int | None = None,
    redactor: Redactor | None = None,
) -> str:
    r"""
    Make text safe for one kind of output: redact, then bound, then neutralize.

    Args:
        value (str): Text that may hold what the scanned site, a file or an exception wrote.
        sink (Sink): The kind of output it is going to.
        one_line (bool): For :attr:`Sink.TERMINAL`, whether line breaks are escaped too. The
            ``LOG`` and ``MESSAGE`` profiles are always on one line, and the others never are.
            Defaults to ``False``.
        limit (int | None): A bound in place of the profile's, for a field with a limit of its
            own. Defaults to ``None`` (the profile's).
        redactor (Redactor | None): The scan's secrets, when the caller holds them. Defaults to
            ``None``.

    Returns:
        str: The text with every secret spelling as :data:`REDACTED`, its unpaired surrogates
            replaced, cut at the bound (on the source, so an escape is never split) and its
            controls neutralized as the profile says.
    """
    profile = _PROFILES[sink]
    if redactor is not None:
        value = redactor(value)
    bound = profile.limit if limit is None else limit
    value = replace_surrogates(value) if bound is None else store_text(value, bound)
    return profile.neutralize(value, one_line)


def safe_traceback(exc: BaseException) -> str:
    """
    Format an exception for a log, each exception's own text on one line.

    The chain is walked as :mod:`traceback` walks it: the cause, the context unless it was
    suppressed, and the members of an exception group. Each stack is written as Python formats
    it, since its frames and source lines come from the installed code. Each exception's type,
    message and notes come from input as often as not, so each goes through the ``LOG`` profile
    on one line: a line break or an escape sequence in a message cannot print a line that looks
    like a record of its own.

    Args:
        exc (BaseException): The exception, with its traceback.

    Returns:
        str: The formatted chain, cut to :data:`~webvigil.core.bounded.URL_MAX_CHARS` at a line
            boundary and marked when it was cut.
    """
    lines = _chain_lines(exc, set(), 0)
    kept: list[str] = []
    size = 0
    for line in lines:
        size += len(line) + 1
        if size > URL_MAX_CHARS:
            kept.append(TRUNCATION_MARKER)
            break
        kept.append(line)
    return "\n".join(kept)


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def _spellings(secret: str) -> set[str]:
    r"""
    Args:
        secret (str): A secret value.

    Returns:
        set[str]: The ways a target is likely to echo it: raw, JSON-escaped (with and without
            ``\u`` escapes for non-ASCII), HTML-escaped (with and without the quotes),
            percent-encoded and form-encoded (UTF-8 and Latin-1, upper- and lower-case hex), and
            as a Python library quotes it in an error: the ``repr`` of its bytes, without the
            ``b''``, in the same encodings.
    """
    encoded = {quote(secret, safe=""), quote_plus(secret)}
    as_bytes = {repr(secret.encode("utf-8", "surrogatepass"))[2:-1]}
    # A page in Latin-1 escapes the same characters as other bytes (``é`` is ``%E9``).
    with suppress(UnicodeEncodeError):  # a character outside Latin-1 has no such spelling
        encoded |= {
            quote(secret, safe="", encoding="latin-1"),
            quote_plus(secret, encoding="latin-1"),
        }
        as_bytes.add(repr(secret.encode("latin-1"))[2:-1])
    return {
        secret,
        json.dumps(secret)[1:-1],
        json.dumps(secret, ensure_ascii=False)[1:-1],
        html.escape(secret),
        html.escape(secret, quote=False),
        *encoded,
        *as_bytes,
        *(_PERCENT_RE.sub(lambda m: m.group().lower(), text) for text in encoded),
    }


class Redactor:
    """
    Replaces every spelling of every secret in a string, and the fragments of one at a cut.

    A fragment is a prefix or a suffix of a spelling, at least :data:`MIN_SECRET_LENGTH`
    characters and shorter than the spelling. A prefix is looked for just before a cut (a
    :data:`CUT_MARKERS` occurrence, and the end of the text with ``cut_edges``), a suffix just
    after one (and at the start of the text with ``cut_edges``). Both are indexed by their
    :data:`MIN_SECRET_LENGTH` characters next to the cut, so memory grows with the secrets'
    length rather than with its square.

    Attributes:
        hits (int): Fields changed so far, by either rule, for the warning that makes a
            redaction visible.
    """

    def __init__(self, texts: Iterable[str]) -> None:
        """
        Args:
            texts (Iterable[str]): The values to hide; the ones under
                :data:`MIN_SECRET_LENGTH` characters are ignored.
        """
        spellings: set[str] = set()
        for text in texts:
            if len(text) >= MIN_SECRET_LENGTH:
                spellings |= _spellings(text)
        # longest first, so a secret that contains another is replaced whole
        self._ordered = sorted((s for s in spellings if s), key=len, reverse=True)
        # the last characters of each prefix -> (spelling, prefix length)
        self._prefixes: dict[str, list[tuple[str, int]]] = {}
        # the first characters of each suffix -> (spelling, where the suffix starts)
        self._suffixes: dict[str, list[tuple[str, int]]] = {}
        edge = MIN_SECRET_LENGTH
        for spelling in self._ordered:
            for length in range(edge, len(spelling)):
                self._prefixes.setdefault(spelling[length - edge : length], []).append(
                    (spelling, length)
                )
            for start in range(1, len(spelling) - edge + 1):
                self._suffixes.setdefault(spelling[start : start + edge], []).append(
                    (spelling, start)
                )
        self.hits = 0

    @property
    def empty(self) -> bool:
        """
        Returns:
            bool: ``True`` when there is nothing to redact.
        """
        return not self._ordered

    def __call__(self, text: str, *, cut_edges: bool = False) -> str:
        """
        Args:
            text (str): A free-text field.
            cut_edges (bool): Whether the start and the end of ``text`` are cuts too, as they
                are for a piece of evidence a check cut out of a body without a marker.
                Defaults to ``False``.

        Returns:
            str: ``text`` with every secret spelling, and every fragment of one at a cut,
                replaced by :data:`REDACTED`.
        """
        if not self._ordered:
            return text
        original = text
        for spelling in self._ordered:
            if spelling in text:
                text = text.replace(spelling, REDACTED)
        text = self._redact_fragments(text, cut_edges=cut_edges)
        if text != original:
            self.hits += 1
        return text

    def optional(self, text: str | None) -> str | None:
        """
        Args:
            text (str | None): A free-text field that may be absent.

        Returns:
            str | None: The redacted text, or ``None`` when it was absent.
        """
        return None if text is None else self(text)

    def _redact_fragments(self, text: str, *, cut_edges: bool) -> str:
        """
        Args:
            text (str): A field whose whole spellings are already replaced.
            cut_edges (bool): Whether the start and the end of ``text`` are cuts.

        Returns:
            str: ``text`` with the longest fragment found at each cut replaced, overlapping
                fragments joined into one :data:`REDACTED`.
        """
        before, after = _cut_points(text, cut_edges=cut_edges)
        spans = [span for point in before if (span := self._prefix_before(text, point))]
        spans += [span for point in after if (span := self._suffix_after(text, point))]
        if not spans:
            return text
        spans.sort()
        merged = [spans[0]]
        for start, end in spans[1:]:
            if start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        pieces: list[str] = []
        last = 0
        for start, end in merged:
            pieces += [text[last:start], REDACTED]
            last = end
        pieces.append(text[last:])
        return "".join(pieces)

    def _prefix_before(self, text: str, point: int) -> tuple[int, int] | None:
        """
        Args:
            text (str): The field.
            point (int): A cut: the text before it may end with a prefix of a spelling.

        Returns:
            tuple[int, int] | None: The span of the longest such prefix, or ``None``.
        """
        if point < MIN_SECRET_LENGTH:
            return None
        best = 0
        for spelling, length in self._prefixes.get(text[point - MIN_SECRET_LENGTH : point], ()):
            if best < length <= point and text.startswith(spelling[:length], point - length):
                best = length
        return (point - best, point) if best else None

    def _suffix_after(self, text: str, point: int) -> tuple[int, int] | None:
        """
        Args:
            text (str): The field.
            point (int): A cut: the text after it may start with a suffix of a spelling.

        Returns:
            tuple[int, int] | None: The span of the longest such suffix, or ``None``.
        """
        best = 0
        for spelling, start in self._suffixes.get(text[point : point + MIN_SECRET_LENGTH], ()):
            length = len(spelling) - start
            if length > best and text.startswith(spelling[start:], point):
                best = length
        return (point, point + best) if best else None


def _cut_points(text: str, *, cut_edges: bool) -> tuple[set[int], set[int]]:
    """
    Args:
        text (str): A field.
        cut_edges (bool): Whether the start and the end of ``text`` count as cuts.

    Returns:
        tuple[set[int], set[int]]: The positions just before a cut (where a prefix of a secret
            may end) and just after one (where a suffix may start).
    """
    before: set[int] = set()
    after: set[int] = set()
    for marker in CUT_MARKERS:
        found = text.find(marker)
        while found != -1:
            before.add(found)
            after.add(found + len(marker))
            found = text.find(marker, found + 1)
    if cut_edges:
        before.add(len(text))
        after.add(0)
    return before, after


# ---------------------------------------------------------------------------
# Log
# ---------------------------------------------------------------------------


class SafeLogFilter(logging.Filter):
    """
    Gives a logger's records the ``LOG`` profile, without changing its level or its handlers.

    A filter on a logger travels with the record to every handler, whoever configured them, so
    the treatment holds under uvicorn's configuration or an operator's.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Args:
            record (logging.LogRecord): A record logged on the logger this filter is attached to.

        Returns:
            bool: Always ``True``: no record is dropped. The record's message is rendered,
                treated and stored with no arguments left, and an exception's traceback is
                rebuilt by :func:`safe_traceback` into ``exc_text``, which every formatter uses
                when it is set. A record whose message cannot be rendered is left alone, so
                :mod:`logging` reports its own formatting error.
        """
        try:
            message = record.getMessage()
        except Exception:  # a bad format string or argument: logging says so itself
            return True
        record.msg = safe_text(message, Sink.LOG, one_line=True)
        record.args = ()
        if record.exc_info and record.exc_info[1] is not None:
            record.exc_text = safe_traceback(record.exc_info[1])
        return True


def get_logger(name: str) -> logging.Logger:
    """
    Args:
        name (str): The logger's name (a module's ``__name__``, or a library's logger that the
            Web API treats).

    Returns:
        logging.Logger: ``logging.getLogger(name)`` with one :class:`SafeLogFilter` attached.
            A filter sees only its own logger's records, so every module that logs takes its
            logger from here.
    """
    logger = logging.getLogger(name)
    if not any(isinstance(item, SafeLogFilter) for item in logger.filters):
        logger.addFilter(SafeLogFilter())
    return logger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chain_lines(exc: BaseException, seen: set[int], depth: int) -> list[str]:
    """
    Args:
        exc (BaseException): The last exception of a chain.
        seen (set[int]): The ids of the exceptions already written, so a cycle ends.
        depth (int): How deep in exception groups this chain is.

    Returns:
        list[str]: The chain's lines, the first cause first, as :mod:`traceback` orders them.
    """
    chain: list[tuple[BaseException, str | None]] = []
    current: BaseException | None = exc
    link: str | None = None
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append((current, link))
        if current.__cause__ is not None:
            current, link = current.__cause__, _CAUSE_LINE
        elif current.__context__ is not None and not current.__suppress_context__:
            current, link = current.__context__, _CONTEXT_LINE
        else:
            current = None
    lines: list[str] = []
    for item, link in reversed(chain):
        lines += _exception_lines(item, seen, depth)
        if link is not None:
            lines += ["", link, ""]
    return lines


def _exception_lines(exc: BaseException, seen: set[int], depth: int) -> list[str]:
    """
    Args:
        exc (BaseException): One exception of a chain.
        seen (set[int]): The ids of the exceptions already written.
        depth (int): How deep in exception groups it is.

    Returns:
        list[str]: Its stack as Python formats it, then its type and message on one line, then
            one line per note, then the members of a group, each with its own chain.
    """
    lines: list[str] = []
    if exc.__traceback__ is not None:
        lines.append("Traceback (most recent call last):")
        for entry in traceback.format_tb(exc.__traceback__):
            lines += entry.rstrip("\n").split("\n")
    lines.append(_headline(exc))
    notes = getattr(exc, "__notes__", None)
    if isinstance(notes, list | tuple):
        lines += [safe_text(_as_text(note), Sink.LOG, one_line=True) for note in notes]
    if isinstance(exc, BaseExceptionGroup):
        if depth >= _GROUP_DEPTH:
            return [*lines, f"... (exception groups nested deeper than {_GROUP_DEPTH})"]
        members = exc.exceptions
        for index, member in enumerate(members[:_GROUP_WIDTH], start=1):
            lines.append(f"--- sub-exception {index} of {len(members)} ---")
            lines += _chain_lines(member, seen, depth + 1)
        if len(members) > _GROUP_WIDTH:
            lines.append(f"--- and {len(members) - _GROUP_WIDTH} more sub-exceptions ---")
    return lines


def _headline(exc: BaseException) -> str:
    """
    Args:
        exc (BaseException): An exception.

    Returns:
        str: ``module.Type: message`` as Python writes it (the module left out for a built-in),
            through the ``LOG`` profile on one line.
    """
    kind = type(exc)
    name = kind.__qualname__
    module = kind.__module__
    if module not in ("builtins", "__main__"):
        name = f"{module}.{name}"
    message = _as_text(exc)
    line = f"{name}: {message}" if message else name
    return safe_text(line, Sink.LOG, one_line=True)


def _as_text(value: object) -> str:
    """
    Args:
        value (object): An exception or a note.

    Returns:
        str: ``str(value)``, or a placeholder when that raises, as :mod:`traceback` writes it.
    """
    try:
        return str(value)
    except Exception:
        return "<str() failed>"


__all__ = [
    "CUT_MARKERS",
    "MIN_SECRET_LENGTH",
    "REDACTED",
    "TERMINAL_MAX_CHARS",
    "Redactor",
    "SafeLogFilter",
    "Sink",
    "get_logger",
    "safe_text",
    "safe_traceback",
]
