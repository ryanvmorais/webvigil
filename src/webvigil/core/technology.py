"""The detected-technology inventory carried on a :class:`~webvigil.core.result.ScanResult`.

Spec 004 (RF-12). Pure data — no HTTP, crawler, or reporting imports. The dependency
fingerprint pass produces ``Technology`` entries; the ``deps.*`` checks turn the vulnerable
ones into findings.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class DetectionMethod(StrEnum):
    """How a library was identified, ordered loosely by how much to trust it."""

    HASH = "hash"  # exact SHA-1 of a fetched in-scope file
    SRI = "sri"  # a Subresource Integrity hash in the HTML matched a known file
    FILENAME = "filename"  # version captured from the resource filename
    FILECONTENT = "filecontent"  # version captured from a banner/comment in a body
    URI = "uri"  # library (rarely a version) inferred from the URL path


class Technology(BaseModel):
    """One client-side library seen on the target."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str | None
    detection: DetectionMethod
    source_url: str
    vulnerable: bool = False
    advisories: tuple[str, ...] = ()
