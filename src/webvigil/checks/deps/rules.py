"""
Compile the vendored Retire.js database into matchers (spec 004, RF-05, RF-06).

``RetireJsRules`` turns the normalised JSON (see ``_data.py``) into:

- per-component ``filename`` / ``filecontent`` / ``uri`` regexes (the ``§§version§§``
  placeholder becomes a capturing group), plus a SHA-1 → version hash table;
- the raw vulnerability entries, which :mod:`webvigil.checks.deps.advisories` evaluates.

WebVigil applies only what the file expresses — it adds no identification rules of its own
(Resolved decision 9).

The text the matchers read comes from the scanned site, and the patterns were written for
JavaScript, with unbounded repetitions that can cost time proportional to the square of a
script's size. So every open-ended repetition is bounded when the pattern is compiled
(:func:`_bound_repeats`), and a body is read up to ``_BODY_MAX`` characters (its SHA-1 still
covers all of it).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

from webvigil.checks.deps import _data
from webvigil.checks.deps._data import Provenance
from webvigil.core.context import Detection
from webvigil.core.technology import DetectionMethod

_VERSION_PLACEHOLDER = "§§version§§"
# A version string is short; the bound keeps the capture from running along a long run of
# digits or letters.
_VERSION_GROUP = r"([0-9][0-9a-zA-Z._\-]{0,64})"
# What an open-ended repetition (``*``, ``+``, ``{n,}``) in a database pattern is bounded to.
# Retire.js markers sit a few hundred characters apart at most (a header comment, a variable
# and its version), so nothing real is lost.
_REPEAT_MAX = 400
# Characters of a script the content patterns read, and of a URL path the URI patterns read.
# Past the head, a body is bundled application code, not a library header.
_BODY_MAX = 256 * 1024
_PATH_MAX = 4096
_OPEN_REPEAT = re.compile(r"\{(\d*),\}")
# Retire.js authors its regexes for JavaScript, which allows variable-width look-behind;
# Python's ``re`` does not. Such a pattern is skipped rather than failing the whole load.
_SUFFIX_RE = re.compile(r"[.\-_](?:min|slim|pack|dev|debug|latest|module|esm|cjs|umd)\b.*$", re.I)


@dataclass(frozen=True)
class VulnerabilityEntry:
    """
    One advisory, still in string form.

    :class:`~webvigil.checks.deps.advisories.RetireJsProvider` does the version
    math against these.

    Attributes:
        ranges (tuple[tuple[str | None, str | None], ...]): ``(atOrAbove,
            below)`` version bounds; either end may be ``None``.
        severity (str | None): Upstream severity label, or ``None`` when not
            supplied.
        identifiers (tuple[str, ...]): CVE / GHSA / other advisory ids.
        summary (str): One-line description.
        cwe (tuple[int, ...]): Associated CWE ids.
        info (tuple[str, ...]): Further-reading URLs.
    """

    ranges: tuple[tuple[str | None, str | None], ...]
    severity: str | None
    identifiers: tuple[str, ...]
    summary: str
    cwe: tuple[int, ...]
    info: tuple[str, ...]


@dataclass(frozen=True)
class Component:
    """
    One library from the vendored database, with its extractors compiled.

    Attributes:
        name (str): Library name.
        filename (tuple[re.Pattern[str], ...]): Regexes matched against a
            resource filename.
        filecontent (tuple[re.Pattern[str], ...]): Regexes matched against a
            body / banner.
        uri (tuple[re.Pattern[str], ...]): Regexes matched against a URL path.
        hashes (dict[str, str]): SHA-1 hex digest -> exact version.
        vulnerabilities (tuple[VulnerabilityEntry, ...]): The library's
            advisories.
    """

    name: str
    filename: tuple[re.Pattern[str], ...]
    filecontent: tuple[re.Pattern[str], ...]
    uri: tuple[re.Pattern[str], ...]
    hashes: dict[str, str]
    vulnerabilities: tuple[VulnerabilityEntry, ...]


def _bound_repeats(pattern: str) -> str:
    """
    Give every open-ended repetition in a regex an upper bound.

    Walks the pattern, skipping escapes and character classes, and rewrites ``*`` to
    ``{0,N}``, ``+`` to ``{1,N}`` and ``{n,}`` to ``{n,N}`` (a lazy ``?`` after it stays).
    A pattern that already bounds its repetitions comes back unchanged.

    Args:
        pattern (str): A regex source.

    Returns:
        str: The same regex with ``_REPEAT_MAX`` as the largest repetition.
    """
    out: list[str] = []
    i = 0
    size = len(pattern)
    while i < size:
        char = pattern[i]
        if char == "\\":
            out.append(pattern[i : i + 2])
            i += 2
        elif char == "[":
            j = i + 1
            if j < size and pattern[j] == "^":
                j += 1
            if j < size and pattern[j] == "]":
                j += 1
            while j < size and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            out.append(pattern[i : j + 1])
            i = j + 1
        elif char == "*":
            out.append(f"{{0,{_REPEAT_MAX}}}")
            i += 1
        elif char == "+":
            out.append(f"{{1,{_REPEAT_MAX}}}")
            i += 1
        elif (open_repeat := _OPEN_REPEAT.match(pattern, i)) is not None:
            low = int(open_repeat.group(1) or 0)
            out.append(f"{{{low},{max(low, _REPEAT_MAX)}}}")
            i = open_repeat.end()
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _compile_all(patterns: list[str]) -> tuple[re.Pattern[str], ...]:
    """
    Compile a list of Retire.js extractor patterns.

    The ``§§version§§`` placeholder becomes a capturing group, and every open-ended
    repetition is bounded (:func:`_bound_repeats`). A pattern that
    uses a JS-only construct Python's ``re`` rejects (e.g. variable-width
    look-behind) is skipped rather than failing the whole load.

    Args:
        patterns (list[str]): Raw extractor patterns from the database.

    Returns:
        tuple[re.Pattern[str], ...]: The compiled patterns.
    """
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        expanded = pattern.replace(_VERSION_PLACEHOLDER, _VERSION_GROUP)
        try:
            compiled.append(re.compile(_bound_repeats(expanded)))
        except re.error:
            continue  # a JS-only construct (e.g. variable look-behind) — skip this one
    return tuple(compiled)


def _clean_version(version: str | None) -> str | None:
    """
    Args:
        version (str | None): A version string captured from a marker.

    Returns:
        str | None: The version with a trailing build suffix (``.min``,
            ``-esm``, etc.) and stray separators stripped, or ``None`` when the
            result is empty.
    """
    if version is None:
        return None
    cleaned = _SUFFIX_RE.sub("", version).strip(".-_")
    return cleaned or None


def _component(name: str, raw: dict[str, Any]) -> Component:
    """
    Build a :class:`Component` from one database entry.

    Args:
        name (str): The library name (the entry's key).
        raw (dict[str, Any]): The entry's ``extractors`` and ``vulnerabilities``.

    Returns:
        Component: The compiled component.
    """
    extractors = raw.get("extractors", {})
    vulns = tuple(
        VulnerabilityEntry(
            ranges=tuple(
                (rng.get("atOrAbove"), rng.get("below")) for rng in vuln.get("ranges", [])
            ),
            severity=vuln.get("severity"),
            identifiers=tuple(vuln.get("identifiers", [])),
            summary=vuln.get("summary", ""),
            cwe=tuple(vuln.get("cwe", [])),
            info=tuple(vuln.get("info", [])),
        )
        for vuln in raw.get("vulnerabilities", [])
    )
    return Component(
        name=name,
        filename=_compile_all(extractors.get("filename", [])),
        filecontent=_compile_all(extractors.get("filecontent", [])),
        uri=_compile_all(extractors.get("uri", [])),
        hashes={str(k).lower(): str(v) for k, v in extractors.get("hashes", {}).items()},
        vulnerabilities=vulns,
    )


class RetireJsRules:
    """Compiled matchers over the vendored database."""

    def __init__(self, components: dict[str, Component], provenance: Provenance) -> None:
        """
        Args:
            components (dict[str, Component]): Compiled components, keyed by
                library name.
            provenance (Provenance): Where the database came from and when.
        """
        self._components = components
        self._provenance = provenance

    @classmethod
    def load(cls) -> RetireJsRules:
        """
        Returns:
            RetireJsRules: The process-wide rules over the vendored files
                (compiled once and cached).
        """
        return _load_cached()

    @classmethod
    def from_raw(cls, raw: dict[str, Any], provenance: Provenance) -> RetireJsRules:
        """
        Build rules from an in-memory database (the vendored shape). Used by tests.

        Args:
            raw (dict[str, Any]): A ``{"components": {...}}`` mapping.
            provenance (Provenance): Provenance to attach.

        Returns:
            RetireJsRules: The compiled rules.
        """
        components = {
            name: _component(name, component)
            for name, component in raw.get("components", {}).items()
        }
        return cls(components, provenance)

    @property
    def provenance(self) -> Provenance:
        """
        Returns:
            Provenance: Where the database came from and when.
        """
        return self._provenance

    def vulnerabilities_for(self, name: str) -> tuple[VulnerabilityEntry, ...]:
        """
        Args:
            name (str): A library name.

        Returns:
            tuple[VulnerabilityEntry, ...]: Its advisories, or ``()`` when the
                library is not in the database.
        """
        component = self._components.get(name)
        return component.vulnerabilities if component else ()

    def identify(self, *, url: str | None = None, body: str | None = None) -> list[Detection]:
        """
        Return every library a single source (a URL and/or a body) reveals.

        Applies every component's filename, URI, filecontent, and hash matchers
        to the given source.

        Args:
            url (str | None): A resource URL to match the filename and path
                against.
            body (str | None): A resource body / inline script to match the
                content patterns and SHA-1 hash against.

        Returns:
            list[Detection]: One detection per matcher that fired (before
                cross-source de-duplication).
        """
        detections: list[Detection] = []
        filename = _basename(url)[:_PATH_MAX] if url else None
        path = urlsplit(url).path[:_PATH_MAX] if url else None
        head = body[:_BODY_MAX] if body is not None else ""

        for component in self._components.values():
            if filename is not None:
                for pattern in component.filename:
                    match = pattern.search(filename)
                    if match:
                        detections.append(
                            _detection(
                                component.name,
                                _clean_version(_group(match)),
                                DetectionMethod.FILENAME,
                                url,
                                filename,
                            )
                        )
            if path is not None:
                for pattern in component.uri:
                    match = pattern.search(path)
                    if match:
                        detections.append(
                            _detection(
                                component.name,
                                _clean_version(_group(match)),
                                DetectionMethod.URI,
                                url,
                                path,
                            )
                        )
            if body is not None:
                for pattern in component.filecontent:
                    match = pattern.search(head)
                    if match:
                        marker = match.group(0)[:120]
                        detections.append(
                            _detection(
                                component.name,
                                _clean_version(_group(match)),
                                DetectionMethod.FILECONTENT,
                                url,
                                marker,
                            )
                        )
                digest = hashlib.sha1(body.encode("utf-8", "ignore")).hexdigest()
                version = component.hashes.get(digest)
                if version is not None:
                    detections.append(
                        _detection(component.name, version, DetectionMethod.HASH, url, digest)
                    )
        return detections


def _detection(
    name: str, version: str | None, method: DetectionMethod, url: str | None, marker: str
) -> Detection:
    """
    Args:
        name (str): Library name.
        version (str | None): Detected version, or ``None``.
        method (DetectionMethod): How it was detected.
        url (str | None): Source URL, normalised to ``""`` when absent.
        marker (str): The raw text that matched, for evidence.

    Returns:
        Detection: The assembled detection.
    """
    return Detection(
        name=name,
        version=version,
        method=method,
        source_url=url or "",
        marker=marker,
    )


def _group(match: re.Match[str]) -> str | None:
    """
    Args:
        match (re.Match[str]): A successful match.

    Returns:
        str | None: The first captured group (the version), or ``None`` when the
            pattern captured nothing.
    """
    return match.group(1) if match.groups() else None


def _basename(url: str) -> str:
    """
    Args:
        url (str): A resource URL.

    Returns:
        str: The last path segment.
    """
    return urlsplit(url).path.rsplit("/", 1)[-1]


@lru_cache(maxsize=1)
def _load_cached() -> RetireJsRules:
    """
    Returns:
        RetireJsRules: The rules compiled from the vendored files, cached for the
            process.
    """
    return RetireJsRules.from_raw(_data.load_raw_db(), _data.load_provenance())
