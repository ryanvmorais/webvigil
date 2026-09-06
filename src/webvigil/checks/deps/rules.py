"""Compile the vendored Retire.js database into matchers (spec 004, RF-05, RF-06).

``RetireJsRules`` turns the normalised JSON (see ``_data.py``) into:

- per-component ``filename`` / ``filecontent`` / ``uri`` regexes (the ``§§version§§``
  placeholder becomes a capturing group), plus a SHA-1 → version hash table;
- the raw vulnerability entries, which :mod:`webvigil.checks.deps.advisories` evaluates.

WebVigil applies only what the file expresses — it adds no identification rules of its own
(Resolved decision 9).
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
_VERSION_GROUP = r"([0-9][0-9a-zA-Z._\-]*)"
# Retire.js authors its regexes for JavaScript, which allows variable-width look-behind;
# Python's ``re`` does not. Such a pattern is skipped rather than failing the whole load.
_SUFFIX_RE = re.compile(r"[.\-_](?:min|slim|pack|dev|debug|latest|module|esm|cjs|umd)\b.*$", re.I)


@dataclass(frozen=True)
class VulnerabilityEntry:
    """One advisory, still in string form — :class:`RetireJsProvider` does the version math."""

    ranges: tuple[tuple[str | None, str | None], ...]  # (atOrAbove, below)
    severity: str | None
    identifiers: tuple[str, ...]
    summary: str
    cwe: tuple[int, ...]
    info: tuple[str, ...]


@dataclass(frozen=True)
class Component:
    name: str
    filename: tuple[re.Pattern[str], ...]
    filecontent: tuple[re.Pattern[str], ...]
    uri: tuple[re.Pattern[str], ...]
    hashes: dict[str, str]  # sha1 hex -> exact version
    vulnerabilities: tuple[VulnerabilityEntry, ...]


def _compile_all(patterns: list[str]) -> tuple[re.Pattern[str], ...]:
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        expanded = pattern.replace(_VERSION_PLACEHOLDER, _VERSION_GROUP)
        try:
            compiled.append(re.compile(expanded))
        except re.error:
            continue  # a JS-only construct (e.g. variable look-behind) — skip this one
    return tuple(compiled)


def _clean_version(version: str | None) -> str | None:
    if version is None:
        return None
    cleaned = _SUFFIX_RE.sub("", version).strip(".-_")
    return cleaned or None


def _component(name: str, raw: dict[str, Any]) -> Component:
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
        self._components = components
        self._provenance = provenance

    @classmethod
    def load(cls) -> RetireJsRules:
        return _load_cached()

    @classmethod
    def from_raw(cls, raw: dict[str, Any], provenance: Provenance) -> RetireJsRules:
        """Build rules from an in-memory database (the vendored shape). Used by tests."""
        components = {
            name: _component(name, component)
            for name, component in raw.get("components", {}).items()
        }
        return cls(components, provenance)

    @property
    def provenance(self) -> Provenance:
        return self._provenance

    def vulnerabilities_for(self, name: str) -> tuple[VulnerabilityEntry, ...]:
        component = self._components.get(name)
        return component.vulnerabilities if component else ()

    def identify(self, *, url: str | None = None, body: str | None = None) -> list[Detection]:
        """Return every library a single source (a URL and/or a body) reveals."""
        detections: list[Detection] = []
        filename = _basename(url) if url else None
        path = urlsplit(url).path if url else None

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
                    match = pattern.search(body)
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
    return Detection(
        name=name,
        version=version,
        method=method,
        source_url=url or "",
        marker=marker,
    )


def _group(match: re.Match[str]) -> str | None:
    return match.group(1) if match.groups() else None


def _basename(url: str) -> str:
    return urlsplit(url).path.rsplit("/", 1)[-1]


@lru_cache(maxsize=1)
def _load_cached() -> RetireJsRules:
    return RetireJsRules.from_raw(_data.load_raw_db(), _data.load_provenance())
