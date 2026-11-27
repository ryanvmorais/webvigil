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
  :func:`portable_traceback` leaves the text out: the frames and types alone, for an output that
  is shared (a check's error in the result) or that must not hold the message (the Web API's log
  of an engine error).

The bound runs before the neutralization in every profile, so a cut never splits an escape and
the bound counts what the source held.
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import sys
import sysconfig
import traceback
import zlib
from bisect import bisect_right
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from itertools import accumulate
from pathlib import Path
from typing import Final
from urllib.parse import quote

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

# The characters each common percent-encoder keeps as they are, besides letters, digits and
# ``-_.``: RFC 3986 (Python, PHP ``rawurlencode``, Go), none (PHP ``urlencode``, older Python),
# JavaScript's ``encodeURIComponent``, and Java's ``URLEncoder``.
_URL_KEPT: Final[tuple[str, ...]] = ("~", "", "~!*'()", "*")

# The quote references of the common HTML escapers, ``(double, single)``: Python's
# ``html.escape``; Go, Jinja2 and the OWASP encoder; Django, Ruby and Node; PHP's
# ``htmlspecialchars``; and the HTML5 entity.
_HTML_QUOTES: Final[tuple[tuple[str, str], ...]] = (
    ("&quot;", "&#x27;"),
    ("&#34;", "&#39;"),
    ("&quot;", "&#39;"),
    ("&quot;", "&#039;"),
    ("&quot;", "&apos;"),
)

# The characters an HTML-safe JSON encoder (Go's, by default) writes as ``\u`` escapes.
_JSON_HTML_ESCAPES: Final = str.maketrans({"<": "\\u003c", ">": "\\u003e", "&": "\\u0026"})

# A ``\u`` escape of a JSON string, for its upper-case hex spelling.
_JSON_ESCAPE_RE = re.compile(r"\\u([0-9a-f]{4})")

# Up to this many spellings, the whole-spelling search of :class:`Redactor` looks for each one
# in the field (fast, one scan per spelling); past it, it walks the field once and asks an index
# of the spellings' first characters at each position, so the work follows the field and not
# the number of spellings, which the target sets with its session values.
_DIRECT_SPELLINGS: Final = 256

# The fragment search of :class:`Redactor` keeps one bit per hashed run of
# :data:`MIN_SECRET_LENGTH` characters of the spellings (1 MiB), so its memory does not grow
# with the secrets: an index of every position took about 490 bytes per character of every
# spelling, and the target is the one that sets the session values.
_FILTER_BITS: Final = 1 << 23

# The most work the whole-spelling and fragment searches may spend on one field, in characters
# scanned or compared. Only a secret that repeats one run over and over, a field with hundreds
# of cuts next to runs of a secret, or hundreds of spellings that start alike, gets near it; a
# field past it is redacted whole, which hides at least as much as the search would have.
FRAGMENT_WORK_BUDGET: Final = 4 * 1024 * 1024

# Joins the spellings into the one string the fragment search scans. A run that spans it
# belongs to no spelling, and the search drops it.
_SPELLING_SEPARATOR: Final = "\x00"

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
    How one kind of output bounds and neutralizes a value.

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
    return _cut_lines(_chain_lines(exc, set(), 0))


def _cut_lines(lines: Iterable[str]) -> str:
    """
    Args:
        lines (Iterable[str]): A traceback's lines, without their line breaks.

    Returns:
        str: The lines joined, cut to :data:`~webvigil.core.bounded.URL_MAX_CHARS` at a line
            boundary and marked when they were cut.
    """
    kept: list[str] = []
    size = -1  # the joined length: a line break goes between lines, not before the first
    for line in lines:
        size += len(line) + 1
        if size > URL_MAX_CHARS:
            kept.append(TRUNCATION_MARKER)
            break
        kept.append(line)
    return "\n".join(kept)


def _local_prefixes() -> list[tuple[str, str]]:
    """
    Returns:
        list[tuple[str, str]]: ``(directory + separator, replacement)`` for each place this
            install lives (the directory that holds the ``webvigil`` package, the interpreter's
            library paths and prefixes, then the user's home as ``~``), longest first so a
            nested directory is cut before its parent.
    """
    paths = sysconfig.get_paths()
    places = {str(Path(__file__).resolve().parents[2]), sys.prefix, sys.base_prefix}
    places |= {paths[key] for key in ("purelib", "platlib", "stdlib", "platstdlib") if key in paths}
    pairs = {(str(Path(place)) + os.sep, "") for place in places if place}
    pairs.add((str(Path.home()) + os.sep, "~" + os.sep))
    return sorted(pairs, key=lambda pair: len(pair[0]), reverse=True)


def _typed_frames(exc: BaseException, seen: set[int], depth: int = 0) -> list[str]:
    """
    Format one exception and what it chained as frames and type names, without any message.

    Args:
        exc (BaseException): The exception to format.
        seen (set[int]): The ids already formatted, since a chain can loop.
        depth (int): How many links led here. Defaults to ``0``.

    Returns:
        list[str]: The lines, oldest exception first, stopping after
            :data:`_MAX_CHAINED_EXCEPTIONS` links.
    """
    if depth >= _MAX_CHAINED_EXCEPTIONS or id(exc) in seen:
        return []
    seen.add(id(exc))
    lines: list[str] = []
    linked = exc.__cause__ or (None if exc.__suppress_context__ else exc.__context__)
    if linked is not None and (earlier := _typed_frames(linked, seen, depth + 1)):
        lines += [*earlier, "\nThe above exception led to the one below:\n\n"]
    lines.append("Traceback (most recent call last):\n")
    lines += traceback.format_tb(exc.__traceback__)
    kind = type(exc)
    prefix = "" if kind.__module__ == "builtins" else f"{kind.__module__}."
    lines.append(f"{prefix}{kind.__qualname__}\n")
    if isinstance(exc, BaseExceptionGroup):
        for inner in exc.exceptions:
            lines += _typed_frames(inner, seen, depth + 1)
    return lines


def portable_traceback(exc: BaseException) -> str:
    r"""
    Format an exception without the machine's paths or any message.

    A check's traceback is stored in ``ScanResult.errors`` and travels with the JSON report,
    which gets shared; the Web API logs an engine error with it (:data:`PORTABLE_TRACEBACK`), so
    the server log says where the error happened and not what it said. The install path names
    the OS user (``/home/<name>/...``), so each frame keeps only its path inside the install
    (``webvigil/checks/...``, ``httpx2/...``). A frame still absolute after that (a plugin in a
    directory outside the install and the home, such as ``D:\work\plugin`` on Windows) keeps
    only its file name. Exception messages are left out, chained ones included: a library's can
    quote a credential.

    Args:
        exc (BaseException): The exception, with its traceback.

    Returns:
        str: The frames and exception types, chained exceptions included, with local
            directories cut.
    """
    text = "".join(_typed_frames(exc, set()))
    for prefix, replacement in _local_prefixes():
        text = text.replace(prefix, replacement)
    return _FRAME_FILE_RE.sub(_frame_file_name, text)


# How many chained exceptions a portable traceback shows: enough for a real chain, and a long or
# self-referencing one cannot exhaust the stack of the handler that records the failure.
_MAX_CHAINED_EXCEPTIONS = 16
# A traceback frame line, ``  File "<path>", line N``; the path is the second group.
_FRAME_FILE_RE = re.compile(r'^(\s*File ")([^"\n]+)(", line )', re.MULTILINE)
# An absolute path in either OS's form: ``/x``, ``\x``, ``C:\x`` or ``C:/x``.
_ABSOLUTE_PATH_RE = re.compile(r"^(?:[A-Za-z]:)?[\\/]")


def _frame_file_name(match: re.Match[str]) -> str:
    """
    Args:
        match (re.Match[str]): A frame line matched by ``_FRAME_FILE_RE``.

    Returns:
        str: The line unchanged when its path is relative, else with the path cut to its
            file name.
    """
    head, path, tail = match.groups()
    if _ABSOLUTE_PATH_RE.match(path):
        path = re.split(r"[\\/]", path)[-1]
    return f"{head}{path}{tail}"


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def _spellings(secret: str) -> set[str]:
    r"""
    List the ways a secret can be written in a response.

    Args:
        secret (str): A secret value.

    Returns:
        set[str]: The ways a target is likely to echo it: raw, JSON-escaped
            (:func:`_json_spellings`), HTML-escaped (:func:`_html_spellings`), percent-encoded
            and form-encoded (:func:`_percent_spellings`, UTF-8 and Latin-1, upper- and
            lower-case hex), and as a Python library quotes it in an error: the ``repr`` of its
            bytes, without the ``b''``, in the same encodings.
    """
    encoded = _percent_spellings(secret, "utf-8")
    as_bytes = {repr(secret.encode("utf-8", "surrogatepass"))[2:-1]}
    # A page in Latin-1 escapes the same characters as other bytes (``é`` is ``%E9``).
    with suppress(UnicodeEncodeError):  # a character outside Latin-1 has no such spelling
        encoded |= _percent_spellings(secret, "latin-1")
        as_bytes.add(repr(secret.encode("latin-1"))[2:-1])
    return {
        secret,
        *_json_spellings(secret),
        *_html_spellings(secret),
        *encoded,
        *as_bytes,
        *(_PERCENT_RE.sub(lambda m: m.group().lower(), text) for text in encoded),
    }


def _json_spellings(secret: str) -> set[str]:
    r"""
    Args:
        secret (str): A secret value.

    Returns:
        set[str]: The secret inside a JSON string, as the common encoders write it: with and
            without ``\u`` escapes for non-ASCII, with ``/`` as ``\/`` (PHP), with ``<``, ``>``
            and ``&`` as ``\u`` escapes (Go), and with upper-case hex in the ``\u`` escapes
            (.NET, Java).
    """
    spellings: set[str] = set()
    for ensure_ascii in (True, False):
        text = json.dumps(secret, ensure_ascii=ensure_ascii)[1:-1]
        spellings |= {text, text.replace("/", "\\/"), text.translate(_JSON_HTML_ESCAPES)}
    return spellings | {_JSON_ESCAPE_RE.sub(lambda m: f"\\u{m[1].upper()}", s) for s in spellings}


def _html_spellings(secret: str) -> set[str]:
    """
    Args:
        secret (str): A secret value.

    Returns:
        set[str]: The secret HTML-escaped, without the quotes and with each pair of quote
            references of :data:`_HTML_QUOTES`.
    """
    plain = html.escape(secret, quote=False)
    if '"' not in secret and "'" not in secret:
        return {plain}
    return {plain} | {
        plain.replace('"', double).replace("'", single) for double, single in _HTML_QUOTES
    }


def _percent_spellings(secret: str, encoding: str) -> set[str]:
    """
    Args:
        secret (str): A secret value.
        encoding (str): The character encoding of the escaped bytes.

    Returns:
        set[str]: The secret percent-encoded with each set of :data:`_URL_KEPT`, a space as
            ``%20`` and as ``+``, upper-case hex.

    Raises:
        UnicodeEncodeError: When ``encoding`` cannot encode the secret.
    """
    spellings: set[str] = set()
    for kept in _URL_KEPT:
        # ``quote`` always keeps ``~``: an encoder that does not keep it writes ``%7E``
        text = quote(secret, safe=kept.replace("~", ""), encoding=encoding)
        if "~" not in kept:
            text = text.replace("~", "%7E")
        spellings |= {text, text.replace("%20", "+")}
    return spellings


class Redactor:
    """
    Replaces every spelling of every secret in a string, and the fragments of one at a cut.

    The spellings are found in one search over the field (:meth:`_whole_spans`), whose work
    follows the field's length and not the number of spellings; the spans found are joined, so
    overlapping occurrences of two secrets become one :data:`REDACTED`.

    A fragment is a prefix or a suffix of a spelling, at least :data:`MIN_SECRET_LENGTH`
    characters and shorter than the spelling. A prefix is looked for just before a cut (a
    :data:`CUT_MARKERS` occurrence, and the end of the text with ``cut_edges``), a suffix just
    after one (and at the start of the text with ``cut_edges``). The run of
    :data:`MIN_SECRET_LENGTH` characters next to the cut is first asked of a fixed-size filter,
    which answers for nearly every cut that no spelling holds it; only then are the spellings
    scanned for it. The work on one field is bounded by :data:`FRAGMENT_WORK_BUDGET`, past which
    the field is redacted whole.

    Attributes:
        hits (int): Fields changed so far, by either rule, for the warning that makes a
            redaction visible.
    """

    def __init__(self, texts: Iterable[str]) -> None:
        """
        Gather every spelling of the secrets and fill the filter of their runs.

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
        # the spellings by their first characters, longest first in each, for a long list
        heads: dict[str, list[str]] = {}
        for spelling in self._ordered:
            heads.setdefault(spelling[:MIN_SECRET_LENGTH], []).append(spelling)
        self._by_head = {head: tuple(group) for head, group in heads.items()}
        # where each spelling starts in the joined string, for the spelling of a match
        self._starts = list(
            accumulate((len(s) + len(_SPELLING_SEPARATOR) for s in self._ordered[:-1]), initial=0)
        )
        self._joined = _SPELLING_SEPARATOR.join(self._ordered)
        self._filter = bytearray(_FILTER_BITS // 8 if self._ordered else 0)
        edge = MIN_SECRET_LENGTH
        for spelling in self._ordered:
            for start in range(len(spelling) - edge + 1):
                bit = _run_bit(spelling[start : start + edge])
                self._filter[bit >> 3] |= 1 << (bit & 7)
        self.hits = 0

    @property
    def empty(self) -> bool:
        """
        Tell whether the redactor has anything to hide.

        Returns:
            bool: ``True`` when there is nothing to redact.
        """
        return not self._ordered

    def __call__(self, text: str, *, cut_edges: bool = False) -> str:
        """
        Redact every secret spelling and every fragment of one at a cut.

        Args:
            text (str): A free-text field.
            cut_edges (bool): Whether the start and the end of ``text`` are cuts too, as they
                are for a piece of evidence a check cut out of a body without a marker.
                Defaults to ``False``.

        Returns:
            str: ``text`` with every secret spelling, and every fragment of one at a cut,
                replaced by :data:`REDACTED`; :data:`REDACTED` alone when the fragment search
                would pass :data:`FRAGMENT_WORK_BUDGET`.
        """
        if not self._ordered:
            return text
        original = text
        work = _Work()
        try:
            text = _replace_spans(text, self._whole_spans(text, work))
            text = self._redact_fragments(text, cut_edges=cut_edges, work=work)
        except _OverBudget:
            text = REDACTED
        if text != original:
            self.hits += 1
        return text

    def optional(self, text: str | None) -> str | None:
        """
        Redact a field that may be absent.

        Args:
            text (str | None): A free-text field that may be absent.

        Returns:
            str | None: The redacted text, or ``None`` when it was absent.
        """
        return None if text is None else self(text)

    def _redact_fragments(self, text: str, *, cut_edges: bool, work: _Work) -> str:
        """
        Redact the fragments of a secret found at the cuts of a field.

        Args:
            text (str): A field whose whole spellings are already replaced.
            cut_edges (bool): Whether the start and the end of ``text`` are cuts.
            work (_Work): The field's work so far.

        Returns:
            str: ``text`` with the longest fragment found at each cut replaced, overlapping
                fragments joined into one :data:`REDACTED`.

        Raises:
            _OverBudget: When the search passes :data:`FRAGMENT_WORK_BUDGET`.
        """
        before, after = _cut_points(text, cut_edges=cut_edges)
        spans = [span for point in before if (span := self._prefix_before(text, point, work))]
        spans += [span for point in after if (span := self._suffix_after(text, point, work))]
        return _replace_spans(text, spans)

    def _whole_spans(self, text: str, work: _Work) -> list[tuple[int, int]]:
        """
        Find every occurrence of every spelling in a field, overlapping ones included.

        With up to :data:`_DIRECT_SPELLINGS` spellings, each one is looked for in the field;
        past that, the field is walked once and each position asks the index of first
        characters, and only the spellings that start there are compared. Both give the same
        spans once they are joined: a position's longest spelling covers its shorter ones.

        Args:
            text (str): A free-text field.
            work (_Work): The field's work so far; each comparison and each occurrence is spent.

        Returns:
            list[tuple[int, int]]: The span of each occurrence, in no order.

        Raises:
            _OverBudget: When the search passes :data:`FRAGMENT_WORK_BUDGET`.
        """
        spans: list[tuple[int, int]] = []
        if len(self._ordered) <= _DIRECT_SPELLINGS:
            for spelling in self._ordered:
                found = text.find(spelling)
                while found != -1:
                    work.spend(len(spelling))
                    spans.append((found, found + len(spelling)))
                    found = text.find(spelling, found + 1)
            return spans
        by_head = self._by_head
        for point in range(len(text) - MIN_SECRET_LENGTH + 1):
            for spelling in by_head.get(text[point : point + MIN_SECRET_LENGTH], ()):
                work.spend(len(spelling))
                if text.startswith(spelling, point):
                    spans.append((point, point + len(spelling)))
                    break
        return spans

    def _prefix_before(self, text: str, point: int, work: _Work) -> tuple[int, int] | None:
        """
        Find the longest prefix of a secret that ends at a cut.

        Args:
            text (str): The field.
            point (int): A cut: the text before it may end with a prefix of a spelling.
            work (_Work): The field's work so far.

        Returns:
            tuple[int, int] | None: The span of the longest such prefix, or ``None``.

        Raises:
            _OverBudget: When the search passes :data:`FRAGMENT_WORK_BUDGET`.
        """
        if point < MIN_SECRET_LENGTH:
            return None
        best = 0
        for spelling, start in self._runs(text[point - MIN_SECRET_LENGTH : point], work):
            # the run ends the prefix: a prefix as long as the spelling is a whole one
            length = start + MIN_SECRET_LENGTH
            if best < length < len(spelling) and length <= point:
                work.spend(length)
                if text.startswith(spelling[:length], point - length):
                    best = length
        return (point - best, point) if best else None

    def _suffix_after(self, text: str, point: int, work: _Work) -> tuple[int, int] | None:
        """
        Find the longest suffix of a secret that starts at a cut.

        Args:
            text (str): The field.
            point (int): A cut: the text after it may start with a suffix of a spelling.
            work (_Work): The field's work so far.

        Returns:
            tuple[int, int] | None: The span of the longest such suffix, or ``None``.

        Raises:
            _OverBudget: When the search passes :data:`FRAGMENT_WORK_BUDGET`.
        """
        best = 0
        for spelling, start in self._runs(text[point : point + MIN_SECRET_LENGTH], work):
            # the run starts the suffix: a suffix from the first character is a whole spelling
            length = len(spelling) - start
            if start and length > best:
                work.spend(length)
                if text.startswith(spelling[start:], point):
                    best = length
        return (point, point + best) if best else None

    def _runs(self, run: str, work: _Work) -> tuple[tuple[str, int], ...]:
        """
        Find a run of characters in the spellings, once per field.

        A field repeats its runs (every cut of a list of spreads stands next to the same four
        characters), so each run is scanned for once and its answer kept for the field's other
        cuts: the work then follows the distinct runs, not the cuts.

        Args:
            run (str): :data:`MIN_SECRET_LENGTH` characters next to a cut (fewer at the end of
                the text, which no spelling run matches).
            work (_Work): The field's work so far; every scan of the joined spellings is spent.

        Returns:
            tuple[tuple[str, int], ...]: ``(spelling, where the run starts in it)`` for each
                occurrence; empty when the filter says no spelling holds the run.

        Raises:
            _OverBudget: When the search passes :data:`FRAGMENT_WORK_BUDGET`.
        """
        if len(run) < MIN_SECRET_LENGTH:
            return ()
        known = work.runs.get(run)
        if known is not None:
            return known
        found_runs: list[tuple[str, int]] = []
        bit = _run_bit(run)
        if self._filter[bit >> 3] & (1 << (bit & 7)):
            joined = self._joined
            start = 0
            while (found := joined.find(run, start)) != -1:
                work.spend(found + len(run) - start)
                index = bisect_right(self._starts, found) - 1
                offset = found - self._starts[index]
                spelling = self._ordered[index]
                if offset + len(run) <= len(spelling):  # not across a separator
                    found_runs.append((spelling, offset))
                start = found + 1
            work.spend(len(joined) - start)
        work.runs[run] = answer = tuple(found_runs)
        return answer


class _OverBudget(Exception):
    """The fragment search of one field passed :data:`FRAGMENT_WORK_BUDGET`."""


class _Work:
    """
    The work the searches of :class:`Redactor` spent on one field.

    Attributes:
        spent (int): Characters scanned or compared so far.
        runs (dict[str, tuple[tuple[str, int], ...]]): The occurrences of each run already
            scanned for in this field.
    """

    def __init__(self) -> None:
        """Start a field with nothing spent and no run scanned for."""
        self.spent = 0
        self.runs: dict[str, tuple[tuple[str, int], ...]] = {}

    def spend(self, amount: int) -> None:
        """
        Spend ``amount`` of the field's work, or give the field up past the budget.

        Args:
            amount (int): Characters about to be scanned or compared.

        Raises:
            _OverBudget: When the field's total passes :data:`FRAGMENT_WORK_BUDGET`.
        """
        self.spent += amount
        if self.spent > FRAGMENT_WORK_BUDGET:
            raise _OverBudget


def _replace_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """
    Args:
        text (str): A field.
        spans (list[tuple[int, int]]): Spans of ``text`` to hide, in any order.

    Returns:
        str: ``text`` with each span replaced by :data:`REDACTED`, overlapping or touching
            spans joined into one.
    """
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


def _run_bit(run: str) -> int:
    """
    Args:
        run (str): A run of :data:`MIN_SECRET_LENGTH` characters.

    Returns:
        int: Its bit in the filter of :class:`Redactor`. A CRC-32 and not ``hash()``, which
            changes with every process, so the same secrets and text give the same work on
            every run.
    """
    return zlib.crc32(run.encode("utf-8", "surrogatepass")) & (_FILTER_BITS - 1)


def _cut_points(text: str, *, cut_edges: bool) -> tuple[set[int], set[int]]:
    """
    Find where the cuts of a field are.

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

# The ``extra`` key that gives a record a :func:`portable_traceback` in place of an exception: the
# filter makes it the record's ``exc_text``, which every formatter appends, so the log shows where
# an error happened without the exception, whose message a handler would print.
PORTABLE_TRACEBACK: Final = "webvigil_portable_traceback"


class SafeLogFilter(logging.Filter):
    """
    Gives a logger's records the ``LOG`` profile, without changing its level or its handlers.

    A filter on a logger travels with the record to every handler, whoever configured them, so
    the treatment holds under uvicorn's configuration or an operator's.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Treat a record's message and traceback before any handler sees them.

        Args:
            record (logging.LogRecord): A record logged on the logger this filter is attached to.

        Returns:
            bool: Always ``True``: no record is dropped. The record's message is rendered,
                treated and stored with no arguments left, and an exception's traceback is
                rebuilt by :func:`safe_traceback` into ``exc_text``, which every formatter uses
                when it is set; a :data:`PORTABLE_TRACEBACK` given in ``extra`` becomes
                ``exc_text`` as it is, bounded the same way. A record whose message cannot be
                rendered is left alone, so :mod:`logging` reports its own formatting error.
        """
        try:
            message = record.getMessage()
        except Exception:  # a bad format string or argument: logging says so itself
            return True
        record.msg = safe_text(message, Sink.LOG, one_line=True)
        record.args = ()
        portable = record.__dict__.get(PORTABLE_TRACEBACK)
        if isinstance(portable, str):
            record.exc_text = _cut_lines(portable.splitlines())
        elif record.exc_info and record.exc_info[1] is not None:
            record.exc_text = safe_traceback(record.exc_info[1])
        return True


def get_logger(name: str) -> logging.Logger:
    """
    Return a logger with the safe-output filter attached once.

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
    Write an exception's chain of causes and contexts as lines.

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
    Write one exception of a chain as lines.

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
    Write an exception's type and message on one line.

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
    Turn an exception or a note into text without raising.

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
