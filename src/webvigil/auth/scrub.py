"""
Scrub the scan's credentials out of a finished scan result.

Spec 019, RF-11 / ADR-9. A target can reflect the password, a configured cookie or header, or
the session id into a page, an error message or a URL, and a check can quote that page as
evidence. Rather than make every check know about secrets, the orchestrator runs
:func:`scrub_result` once over the result.

Two kinds of value are scrubbed. What the user gave (the password, the ``[auth]`` cookies and
headers) is always hidden. What the *target* issued (the session cookies of an automated login)
is hidden only when it looks like a session identifier (:func:`looks_like_session_value`): a
hostile target could otherwise set a cookie to a common word and blank out what the scan found.

It works **field by field** on the free-text fields (titles, descriptions, evidence, locations,
references, technologies, warnings, check errors), never over the serialised JSON: a password
such as ``high`` or ``passive`` must not rewrite a severity or a mode, and a naive text replace
over the whole document would.
"""

from __future__ import annotations

import html
import json
import re
from collections.abc import Iterable
from urllib.parse import quote, quote_plus

from webvigil.core.findings import EvidenceItem, Finding, Location
from webvigil.core.result import CheckError, ScanResult

REDACTED = "[redacted]"
# A secret shorter than this is left alone: replacing a 1-3 character string would shred the
# report (every "a" in a title). The result says so in a warning instead.
MIN_SECRET_LENGTH = 4

# A value the target issued joins the scrub list only if it is this long and mixes at least two
# of lower case, upper case and digits. PHPSESSID, JSESSIONID, ASP.NET_SessionId, a signed
# cookie and a JWT all do; a word or a fragment of a URL the target wants hidden does not.
MIN_ISSUED_LENGTH = 8
_MIN_ISSUED_CLASSES = 2

# ``quote`` writes upper-case hex (``%2F``); some servers echo it lower case (``%2f``), so each
# encoded spelling is also scrubbed with its escapes lowered.
_PERCENT_RE = re.compile(r"%[0-9A-F]{2}")


def _spellings(secret: str) -> set[str]:
    r"""
    Args:
        secret (str): A secret value.

    Returns:
        set[str]: The ways a target is likely to echo it: raw, JSON-escaped (with and without
            ``\u`` escapes for non-ASCII), HTML-escaped (with and without the quotes),
            percent-encoded and form-encoded (upper- and lower-case hex).
    """
    encoded = {quote(secret, safe=""), quote_plus(secret)}
    return {
        secret,
        json.dumps(secret)[1:-1],
        json.dumps(secret, ensure_ascii=False)[1:-1],
        html.escape(secret),
        html.escape(secret, quote=False),
        *encoded,
        *(_PERCENT_RE.sub(lambda m: m.group().lower(), text) for text in encoded),
    }


def looks_like_session_value(value: str) -> bool:
    """
    Args:
        value (str): A cookie value the target set.

    Returns:
        bool: ``True`` when it is at least :data:`MIN_ISSUED_LENGTH` characters and mixes two of
            lower case, upper case and digits, as a generated session id does.
    """
    if len(value) < MIN_ISSUED_LENGTH:
        return False
    classes = (str.islower, str.isupper, str.isdigit)
    return sum(any(test(c) for c in value) for test in classes) >= _MIN_ISSUED_CLASSES


class _Scrubber:
    """
    Replaces every spelling of every secret in a string.

    Attributes:
        hits (int): Fields changed so far, for the warning that makes a redaction visible.
    """

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
        self.hits = 0

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
        original = text
        for spelling in self._ordered:
            if spelling in text:
                text = text.replace(spelling, REDACTED)
        if text != original:
            self.hits += 1
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
            "references": tuple(scrub(ref) for ref in finding.references),
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


def scrub_result(
    result: ScanResult, secrets: Iterable[str], *, issued: Iterable[str] = ()
) -> ScanResult:
    """
    Hide the configured credentials and the session values from a scan result.

    Args:
        result (ScanResult): The finished scan.
        secrets (Iterable[str]): What the user gave: the password, each ``[auth]`` cookie value
            and each header value. Values under :data:`MIN_SECRET_LENGTH` characters are not
            scrubbed, and the result says so.
        issued (Iterable[str]): The session cookie values the target set. Only the ones that
            pass :func:`looks_like_session_value` are scrubbed. Defaults to none.

    Returns:
        ScanResult: ``result`` itself when there is nothing to scrub or to warn about, otherwise
            a copy whose free-text fields carry :data:`REDACTED` where a secret was, with a
            warning that counts the fields changed. Structural fields (severity, mode, check
            ids, fingerprints) are never touched.
    """
    given = {value for value in secrets if value}
    short = sum(1 for value in given if len(value) < MIN_SECRET_LENGTH)
    scrub = _Scrubber(given | {value for value in issued if looks_like_session_value(value)})
    if scrub.empty and not short:
        return result
    findings = tuple(_scrub_finding(f, scrub) for f in result.findings)
    technologies = tuple(
        tech.model_copy(
            update={
                "name": scrub(tech.name),
                "version": scrub.optional(tech.version),
                "source_url": scrub(tech.source_url),
                "advisories": tuple(scrub(a) for a in tech.advisories),
            }
        )
        for tech in result.technologies
    )
    errors = tuple(
        CheckError(check_id=e.check_id, message=scrub(e.message), traceback=scrub(e.traceback))
        for e in result.errors
    )
    warnings = [scrub(w) for w in result.warnings]
    if scrub.hits:
        warnings.append(
            f"the report hides a credential or session value in {scrub.hits} "
            f"field{'' if scrub.hits == 1 else 's'} as {REDACTED}"
        )
    if short:
        warnings.append(
            f"{short} configured credential value{'' if short == 1 else 's'} shorter than "
            f"{MIN_SECRET_LENGTH} characters cannot be redacted from the report"
        )
    return result.model_copy(
        update={
            "findings": findings,
            "technologies": technologies,
            "errors": errors,
            "warnings": tuple(warnings),
        }
    )


__all__ = [
    "MIN_ISSUED_LENGTH",
    "MIN_SECRET_LENGTH",
    "REDACTED",
    "looks_like_session_value",
    "scrub_result",
]
