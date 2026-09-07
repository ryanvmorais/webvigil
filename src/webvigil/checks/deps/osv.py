"""
The OSV.dev online advisory provider (spec 010).

Opt-in via ``[deps] osv_online`` / ``--osv-online``. This is the only part of
the engine that contacts a host other than the scan target: it sends the names
and versions of the client-side libraries the fingerprint pass detected to
``api.osv.dev`` and turns the matching advisories into WebVigil's native
:class:`~webvigil.checks.deps.advisories.Advisory` shape, so the check, the
inventory, and every reporter are unchanged.

Flow (:meth:`OsvProvider.lookup`): one ``POST /v1/querybatch`` says which
packages have any advisory; then one ``POST /v1/query`` per matched package
pulls the full records. The orchestrator runs this as a pass before the checks
and hands the result to
:class:`~webvigil.checks.deps.check.VulnerableLibraryCheck` via
``ScanContext.observations`` (ADR-2). Any failure raises :class:`OsvLookupError`,
which the orchestrator turns into a scan warning — the offline Retire.js match
still stands (RF-09).
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx

from webvigil.checks.deps.advisories import (
    _DEFAULT_SEVERITY,
    Advisory,
    _lt,
    numeric_version_key,
)
from webvigil.core.context import Detection
from webvigil.core.findings import Severity

_ECOSYSTEM = "npm"
_QUERYBATCH_CAP = 1000
_OSV_URL = "https://osv.dev/vulnerability/{}"
_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

# Retire.js component name -> npm package name, for the cases where they differ (RF-05).
# Anything not listed is used verbatim.
_NPM_NAME: dict[str, str] = {
    "angularjs": "angular",
    "jquery.ui": "jquery-ui",
    "jquery-ui-dialog": "jquery-ui",
    "jquery-migrate": "jquery-migrate",
    "mustache.js": "mustache",
    "handlebars.js": "handlebars",
    "prototypejs": "prototype",
    "ember": "ember-source",
    "ckeditor": "ckeditor4",
    "yui": "yui",
    "dojo": "dojo",
}


class OsvLookupError(Exception):
    """The OSV.dev lookup could not complete (network, HTTP status, or payload shape)."""


@dataclass(frozen=True, slots=True)
class OsvResult:
    """
    The output of one OSV.dev lookup pass.

    Attributes:
        advisories (dict[tuple[str, str], tuple[Advisory, ...]]): ``(webvigil
            library name, version)`` -> the advisories OSV returned for it.
        warnings (tuple[str, ...]): Per-package failures that did not abort the
            whole lookup. Defaults to empty.
    """

    advisories: dict[tuple[str, str], tuple[Advisory, ...]]
    warnings: tuple[str, ...] = field(default=())


def _npm_name(name: str) -> str:
    """
    Args:
        name (str): A Retire.js component name.

    Returns:
        str: The matching npm package name — from ``_NPM_NAME`` when the two
            differ, else ``name`` verbatim.
    """
    return _NPM_NAME.get(name, name)


# --- CVSS v3 base score (RF-07, ADR-5) -------------------------------------------------
# Metric weights from the CVSS v3.1 specification (identical base formula to v3.0).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_PR_SCOPE_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _cvss3_base(vector: str) -> float | None:
    """
    Compute the CVSS 3.0/3.1 base score from a vector string.

    Implements the published formula directly, so no ``cvss`` dependency is
    needed (ADR-5).

    Args:
        vector (str): A CVSS vector, e.g. ``"CVSS:3.1/AV:N/AC:L/..."``.

    Returns:
        float | None: The base score rounded up to one decimal, or ``None`` when
            ``vector`` is not a v3 vector or a required metric is missing or
            unknown.
    """
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    parts: dict[str, str] = {}
    for token in vector.split("/")[1:]:
        key, _, value = token.partition(":")
        parts[key] = value
    try:
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        ui = _UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_PR_SCOPE_CHANGED if scope_changed else _PR_SCOPE_UNCHANGED)[parts["PR"]]
        conf, integ, avail = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - conf) * (1 - integ) * (1 - avail)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    total = impact + exploitability
    if scope_changed:
        total *= 1.08
    return math.ceil(round(min(total, 10.0) * 10, 4)) / 10


def _band(score: float) -> Severity | None:
    """
    Args:
        score (float): A CVSS base score.

    Returns:
        Severity | None: The qualitative band (CRITICAL / HIGH / MEDIUM / LOW),
            or ``None`` for a score below 0.1.
    """
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.1:
        return Severity.LOW
    return None


_GHSA_SEVERITY = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def _severity(record: Mapping[str, Any]) -> tuple[Severity, bool]:
    """
    Resolve the severity of an OSV record (RF-07).

    Prefers a GHSA qualitative label, then a CVSS v3 vector; falls back to the
    shared ``MEDIUM`` default.

    Args:
        record (Mapping[str, Any]): One OSV vulnerability record.

    Returns:
        tuple[Severity, bool]: The severity and whether it came from the record
            (rather than the default).
    """
    database_specific = record.get("database_specific") or {}
    label = str(database_specific.get("severity") or "").upper()
    if label in _GHSA_SEVERITY:
        return _GHSA_SEVERITY[label], True
    for entry in record.get("severity") or []:
        if not isinstance(entry, Mapping):
            continue
        if str(entry.get("type", "")).upper().startswith("CVSS_V"):
            score = _cvss3_base(str(entry.get("score", "")))
            band = _band(score) if score else None
            if band is not None:
                return band, True
    return _DEFAULT_SEVERITY, False


def _summary(record: Mapping[str, Any]) -> str:
    """
    Args:
        record (Mapping[str, Any]): One OSV vulnerability record.

    Returns:
        str: The record ``summary``, or the first sentence of ``details``
            (capped at 200 chars), or ``""``.
    """
    summary = str(record.get("summary") or "").strip()
    if summary:
        return summary
    details = str(record.get("details") or "").strip()
    if not details:
        return ""
    first_sentence = re.split(r"(?<=[.!?])\s", details, maxsplit=1)[0]
    return first_sentence[:200].strip()


def _info_urls(record: Mapping[str, Any], osv_id: str) -> tuple[str, ...]:
    """
    Args:
        record (Mapping[str, Any]): One OSV vulnerability record.
        osv_id (str): The record id, used to build the canonical OSV URL.

    Returns:
        tuple[str, ...]: The record's reference URLs plus the OSV page, de-duped.
    """
    urls: list[str] = []
    for reference in record.get("references") or []:
        if isinstance(reference, Mapping) and reference.get("url"):
            urls.append(str(reference["url"]))
    urls.append(_OSV_URL.format(osv_id))
    return tuple(dict.fromkeys(urls))


def _cwe(record: Mapping[str, Any]) -> tuple[int, ...]:
    """
    Args:
        record (Mapping[str, Any]): One OSV vulnerability record.

    Returns:
        tuple[int, ...]: The numeric CWE ids from ``database_specific.cwe_ids``,
            de-duped.
    """
    database_specific = record.get("database_specific") or {}
    found: list[int] = []
    for raw in database_specific.get("cwe_ids") or []:
        match = _CWE_RE.search(str(raw))
        if match:
            found.append(int(match.group(1)))
    return tuple(dict.fromkeys(found))


def _first_safe(record: Mapping[str, Any], npm_name: str, detected_version: str) -> str | None:
    """
    Find the lowest fixed version above the detected one.

    Args:
        record (Mapping[str, Any]): One OSV vulnerability record.
        npm_name (str): The npm package name to filter ``affected`` entries by.
        detected_version (str): The version in use.

    Returns:
        str | None: The lowest ``fixed`` version greater than
            ``detected_version``, or ``None`` when none is listed.
    """
    fixed: list[str] = []
    for affected in record.get("affected") or []:
        if not isinstance(affected, Mapping):
            continue
        package = affected.get("package") or {}
        if str(package.get("ecosystem", "")).lower() != _ECOSYSTEM:
            continue
        if package.get("name") and str(package["name"]) != npm_name:
            continue
        for version_range in affected.get("ranges") or []:
            for event in (version_range or {}).get("events") or []:
                if isinstance(event, Mapping) and event.get("fixed"):
                    fixed.append(str(event["fixed"]))
    safe = sorted({v for v in fixed if _lt(detected_version, v)}, key=numeric_version_key)
    return safe[0] if safe else None


def _to_advisory(
    record: Mapping[str, Any], *, npm_name: str, detected_version: str
) -> Advisory | None:
    """
    Convert one OSV record into a native :class:`Advisory` (RF-06).

    Args:
        record (Mapping[str, Any]): One OSV vulnerability record.
        npm_name (str): The npm package name, for the fixed-version lookup.
        detected_version (str): The version in use.

    Returns:
        Advisory | None: The native advisory, or ``None`` when the record has no
            usable id.
    """
    try:
        osv_id = str(record["id"])
    except (KeyError, TypeError):
        return None
    aliases = [str(alias) for alias in record.get("aliases") or []]
    severity, from_upstream = _severity(record)
    return Advisory(
        identifiers=tuple(dict.fromkeys([osv_id, *aliases])),
        summary=_summary(record),
        severity=severity,
        severity_from_upstream=from_upstream,
        first_safe_version=_first_safe(record, npm_name, detected_version),
        info_urls=_info_urls(record, osv_id),
        cwe=_cwe(record),
    )


class OsvProvider:
    """Queries OSV.dev for a batch of detected libraries (RF-04, ADR-3, ADR-4)."""

    def __init__(
        self,
        base_url: str,
        timeout_s: float,
        *,
        user_agent: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """
        Args:
            base_url (str): The OSV.dev API base URL; a trailing slash is
                stripped.
            timeout_s (float): Per-request timeout, in seconds.
            user_agent (str): ``User-Agent`` sent on every request.
            transport (httpx.AsyncBaseTransport | None): Test seam — a
                ``MockTransport``. ``None`` in normal operation.
        """
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self._user_agent = user_agent
        self._transport = transport

    async def lookup(self, detections: Sequence[Detection]) -> OsvResult:
        """
        Look up every versioned detection against OSV.dev.

        One ``querybatch`` filters to the packages with any advisory, then one
        ``query`` per hit pulls the full records. A per-package ``query``
        failure is recorded as a warning and skipped; a ``querybatch`` failure
        raises.

        Args:
            detections (Sequence[Detection]): The fingerprint detections;
                version-less ones are ignored.

        Returns:
            OsvResult: The advisories keyed by ``(name, version)`` and any
                per-package warnings.

        Raises:
            OsvLookupError: If the ``querybatch`` call fails or returns an
                unexpected shape.
        """
        pairs = list(
            dict.fromkeys((d.name, d.version) for d in detections if d.version is not None)
        )
        if not pairs:
            return OsvResult(advisories={})

        queries = [
            {
                "package": {"name": _npm_name(name), "ecosystem": _ECOSYSTEM},
                "version": version,
            }
            for name, version in pairs
        ]
        advisories: dict[tuple[str, str], tuple[Advisory, ...]] = {}
        warnings: list[str] = []

        async with self._client() as client:
            batch = await self._querybatch(client, queries)
            for (name, version), hit in zip(pairs, batch, strict=True):
                if not hit:
                    continue
                npm = _npm_name(name)
                try:
                    records = await self._query(client, npm, str(version))
                except OsvLookupError as exc:
                    warnings.append(f"OSV.dev lookup for {npm}@{version} failed: {exc}")
                    continue
                found = tuple(
                    advisory
                    for record in records
                    if (
                        advisory := _to_advisory(
                            record, npm_name=npm, detected_version=str(version)
                        )
                    )
                    is not None
                )
                if found:
                    advisories[(name, version)] = found

        return OsvResult(advisories=advisories, warnings=tuple(warnings))

    def _client(self) -> httpx.AsyncClient:
        """
        Returns:
            httpx.AsyncClient: A fresh client bound to the OSV base URL, with the
                configured timeout, ``User-Agent``, and test transport. This is
                a dedicated client, separate from the scan's scope-guarded one
                (engine-boundaries note).
        """
        kwargs: dict[str, Any] = {
            "base_url": self._base_url,
            "timeout": self._timeout_s,
            "headers": {"user-agent": self._user_agent},
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        return httpx.AsyncClient(**kwargs)

    async def _querybatch(
        self, client: httpx.AsyncClient, queries: list[dict[str, Any]]
    ) -> list[list[Any]]:
        """
        Run ``POST /v1/querybatch``, chunked to the API's per-request cap.

        Args:
            client (httpx.AsyncClient): The OSV client.
            queries (list[dict[str, Any]]): One package/version query per
                detection.

        Returns:
            list[list[Any]]: One list per query, aligned to ``queries``, each
                holding the vuln ids that query matched.

        Raises:
            OsvLookupError: If a chunk's response shape does not line up with the
                chunk.
        """
        results: list[list[Any]] = []
        for start in range(0, len(queries), _QUERYBATCH_CAP):
            chunk = queries[start : start + _QUERYBATCH_CAP]
            payload = await self._post(client, "/v1/querybatch", {"queries": chunk})
            chunk_results = payload.get("results")
            if not isinstance(chunk_results, list) or len(chunk_results) != len(chunk):
                raise OsvLookupError("querybatch response shape unexpected")
            for entry in chunk_results:
                vulns = entry.get("vulns") if isinstance(entry, Mapping) else None
                results.append(list(vulns) if isinstance(vulns, list) else [])
        return results

    async def _query(
        self, client: httpx.AsyncClient, npm_name: str, version: str
    ) -> list[Mapping[str, Any]]:
        """
        Run ``POST /v1/query`` for one package/version.

        Args:
            client (httpx.AsyncClient): The OSV client.
            npm_name (str): The npm package name.
            version (str): The detected version.

        Returns:
            list[Mapping[str, Any]]: The full vulnerability records, or ``[]``
                when the payload has none.

        Raises:
            OsvLookupError: On a transport error, bad status, or non-JSON body.
        """
        payload = await self._post(
            client,
            "/v1/query",
            {"package": {"name": npm_name, "ecosystem": _ECOSYSTEM}, "version": version},
        )
        vulns = payload.get("vulns")
        return [v for v in vulns if isinstance(v, Mapping)] if isinstance(vulns, list) else []

    async def _post(
        self, client: httpx.AsyncClient, path: str, json: dict[str, Any]
    ) -> Mapping[str, Any]:
        """
        POST a JSON body and return the decoded object.

        Args:
            client (httpx.AsyncClient): The OSV client.
            path (str): The API path.
            json (dict[str, Any]): The request body.

        Returns:
            Mapping[str, Any]: The decoded response object.

        Raises:
            OsvLookupError: On any transport error, a non-2xx status, a JSON
                decode failure, or a non-object payload.
        """
        try:
            response = await client.post(path, json=json)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            raise OsvLookupError(str(exc) or exc.__class__.__name__) from exc
        except ValueError as exc:  # JSON decode
            raise OsvLookupError(f"invalid JSON from {path}") from exc
        if not isinstance(data, Mapping):
            raise OsvLookupError(f"unexpected {path} payload")
        return data
