"""
Scrub the login's secrets out of a finished scan result.

Spec 019, RF-11 / ADR-9. A target can reflect the password or the session id into a page, an
error message or a URL, and a check can quote that page as evidence. Rather than make every
check know about secrets, the orchestrator runs :func:`scrub_result` once over the result.

It works **field by field** on the free-text fields (titles, descriptions, evidence, locations,
warnings, check errors), never over the serialised JSON: a password such as ``high`` or
``passive`` must not rewrite a severity or a mode, and a naive text replace over the whole
document would.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from urllib.parse import quote, quote_plus

from webvigil.core.findings import EvidenceItem, Finding, Location
from webvigil.core.result import CheckError, ScanResult

REDACTED = "[redacted]"
# A secret shorter than this is left alone: replacing a 1-3 character string would shred the
# report (every "a" in a title), and such a value is no secret worth the damage. Documented.
MIN_SECRET_LENGTH = 4


def _spellings(secret: str) -> set[str]:
    """
    Args:
        secret (str): A secret value.

    Returns:
        set[str]: The ways a target is likely to echo it: raw, JSON-escaped (with and without
            ``\\u`` escapes for non-ASCII), percent-encoded, and form-encoded.
    """
    return {
        secret,
        json.dumps(secret)[1:-1],
        json.dumps(secret, ensure_ascii=False)[1:-1],
        quote(secret, safe=""),
        quote_plus(secret),
    }


class _Scrubber:
    """Replaces every spelling of every secret in a string."""

    def __init__(self, secrets: Iterable[str]) -> None:
        """
        Args:
            secrets (Iterable[str]): The values to hide; the ones under
                :data:`MIN_SECRET_LENGTH` characters are ignored.
        """
        spellings: set[str] = set()
        for secret in secrets:
            if len(secret) >= MIN_SECRET_LENGTH:
                spellings |= _spellings(secret)
        # longest first, so a secret that contains another is replaced whole
        self._ordered = sorted((s for s in spellings if s), key=len, reverse=True)

    @property
    def empty(self) -> bool:
        """
        Returns:
            bool: ``True`` when there is nothing to scrub.
        """
        return not self._ordered

    def __call__(self, text: str) -> str:
        """
        Args:
            text (str): A free-text field.

        Returns:
            str: ``text`` with every secret spelling replaced by :data:`REDACTED`.
        """
        for spelling in self._ordered:
            if spelling in text:
                text = text.replace(spelling, REDACTED)
        return text

    def optional(self, text: str | None) -> str | None:
        """
        Args:
            text (str | None): A free-text field that may be absent.

        Returns:
            str | None: The scrubbed text, or ``None`` when it was absent.
        """
        return None if text is None else self(text)


def _scrub_finding(finding: Finding, scrub: _Scrubber) -> Finding:
    """
    Args:
        finding (Finding): One finding.
        scrub (_Scrubber): The scrubber.

    Returns:
        Finding: A copy with the free-text fields scrubbed; the stored fingerprint, severity
            and every other structural field are untouched.
    """
    location: Location = finding.location
    return finding.model_copy(
        update={
            "title": scrub(finding.title),
            "description": scrub(finding.description),
            "remediation": scrub(finding.remediation),
            "location": location.model_copy(
                update={
                    "url": scrub(location.url),
                    "param": scrub.optional(location.param),
                    "header": scrub.optional(location.header),
                    "cookie": scrub.optional(location.cookie),
                }
            ),
            "evidence": tuple(
                EvidenceItem(label=item.label, content=scrub(item.content))
                for item in finding.evidence
            ),
        }
    )


def scrub_result(result: ScanResult, secrets: Iterable[str]) -> ScanResult:
    """
    Hide the password and every session value from a scan result.

    Args:
        result (ScanResult): The finished scan.
        secrets (Iterable[str]): The password and each session cookie value; values under
            :data:`MIN_SECRET_LENGTH` characters are not scrubbed.

    Returns:
        ScanResult: ``result`` itself when there is nothing to scrub, otherwise a copy whose
            free-text fields carry :data:`REDACTED` where a secret was. Structural fields
            (severity, mode, check ids, fingerprints) are never touched.
    """
    scrub = _Scrubber(secrets)
    if scrub.empty:
        return result
    return result.model_copy(
        update={
            "findings": tuple(_scrub_finding(f, scrub) for f in result.findings),
            "technologies": tuple(
                tech.model_copy(update={"source_url": scrub(tech.source_url)})
                for tech in result.technologies
            ),
            "errors": tuple(
                CheckError(
                    check_id=e.check_id, message=scrub(e.message), traceback=scrub(e.traceback)
                )
                for e in result.errors
            ),
            "warnings": tuple(scrub(w) for w in result.warnings),
        }
    )


__all__ = ["MIN_SECRET_LENGTH", "REDACTED", "scrub_result"]
