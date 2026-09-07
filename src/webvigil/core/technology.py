"""
The detected-technology inventory carried on a :class:`~webvigil.core.result.ScanResult`.

Spec 004 (RF-12). Pure data — no HTTP, crawler, or reporting imports. The
dependency fingerprint pass produces :class:`Technology` entries; the ``deps.*``
checks turn the vulnerable ones into findings.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class DetectionMethod(StrEnum):
    """
    How a client-side library was identified.

    Ordered loosely by how much the method can be trusted, most reliable first.

    Attributes:
        HASH (str): Exact SHA-1 of a fetched in-scope file.
        SRI (str): A Subresource Integrity hash in the HTML matched a known file.
        FILENAME (str): Version captured from the resource filename.
        FILECONTENT (str): Version captured from a banner or comment in a body.
        URI (str): Library — and rarely a version — inferred from the URL path.
    """

    HASH = "hash"
    SRI = "sri"
    FILENAME = "filename"
    FILECONTENT = "filecontent"
    URI = "uri"


class Technology(BaseModel):
    """
    One client-side library seen on the target.

    Attributes:
        name (str): Library name as Retire.js knows it (e.g. ``"jquery"``).
        version (str | None): Detected version, or ``None`` when only the
            library could be identified.
        detection (DetectionMethod): How the library (and version) was found.
        source_url (str): URL of the resource the detection came from.
        vulnerable (bool): ``True`` when at least one advisory matched the
            detected version. Defaults to ``False``.
        advisories (tuple[str, ...]): Advisory identifiers (CVE / GHSA / OSV)
            affecting this version. Empty unless ``vulnerable`` is ``True``.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    version: str | None
    detection: DetectionMethod
    source_url: str
    vulnerable: bool = False
    advisories: tuple[str, ...] = ()
