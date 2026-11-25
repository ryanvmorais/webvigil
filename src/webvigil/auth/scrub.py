"""
Scrub the scan's credentials out of a finished scan result.

Spec 019, RF-11 / ADR-9. A target can reflect the password, a configured cookie or header, or
the session id into a page, an error message or a URL, and a check can quote that page as
evidence. Rather than make every check know about secrets, the orchestrator runs
:func:`scrub_result` once over the result.

The values come as :class:`~webvigil.core.secrets.Secret` objects, and their kind says which
of two treatments applies (spec 024, RF-07). What the user gave (the password, the ``[auth]``
cookies and headers) is always hidden. What the *target* issued (``SESSION``: the session
cookies of an automated login) is hidden only when it looks like a session identifier
(:func:`looks_like_session_value`): a hostile target could otherwise set a cookie to a common
word and blank out what the scan found. :func:`_texts` is the module's one reveal.

It works **field by field** on the free-text fields (titles, descriptions, evidence, locations,
references, technologies, warnings, check errors), never over the serialised JSON: a password
such as ``high`` or ``passive`` must not rewrite a severity or a mode, and a naive text replace
over the whole document would.
"""

from __future__ import annotations

from collections.abc import Iterable

from webvigil.core.findings import EvidenceItem, Finding, Location
from webvigil.core.output import MIN_SECRET_LENGTH, Redactor
from webvigil.core.result import CheckError, ScanResult
from webvigil.core.secrets import REDACTED, Secret, SecretKind

# A value the target issued joins the scrub list only if it is this long and mixes at least two
# of lower case, upper case and digits. PHPSESSID, JSESSIONID, ASP.NET_SessionId, a signed
# cookie and a JWT all do; a word or a fragment of a URL the target wants hidden does not.
MIN_ISSUED_LENGTH = 8
_MIN_ISSUED_CLASSES = 2


def _texts(secret: Secret) -> tuple[str, ...]:
    """
    The texts a secret stands for in a report, before their spellings.

    Args:
        secret (Secret): A value the scan held.

    Returns:
        tuple[str, ...]: For what the user gave, the value; a ``HEADER`` value also gives its
            credential without the scheme (``Bearer <token>`` gives the token on its own too),
            and a ``COOKIE`` value is stripped of the spaces around it. For a ``SESSION``
            value, the value only when :func:`looks_like_session_value` says so, else nothing.
    """
    value = secret.reveal()
    if not secret.given:
        return (value,) if looks_like_session_value(value) else ()
    if secret.kind is SecretKind.COOKIE:
        return (value.strip(),)
    if secret.kind is SecretKind.HEADER:
        # a value without a space gives an empty credential, which the caller drops
        _scheme, _sep, credential = value.partition(" ")
        return (value, credential.strip())
    return (value,)


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


def _scrub_finding(finding: Finding, scrub: Redactor) -> Finding:
    """
    Args:
        finding (Finding): One finding.
        scrub (Redactor): The scan's redactor.

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


def scrub_result(result: ScanResult, secrets: Iterable[Secret]) -> ScanResult:
    """
    Hide the configured credentials and the session values from a scan result.

    Args:
        result (ScanResult): The finished scan.
        secrets (Iterable[Secret]): Every secret the scan held. What the user gave (the
            password, each ``[auth]`` cookie value and each header value) is always scrubbed,
            except a value under :data:`MIN_SECRET_LENGTH` characters, which the result warns
            about. A ``SESSION`` value the target set is scrubbed only when it passes
            :func:`looks_like_session_value`.

    Returns:
        ScanResult: ``result`` itself when there is nothing to scrub or to warn about, otherwise
            a copy whose free-text fields carry :data:`REDACTED` where a secret was, with a
            warning that counts the fields changed. Structural fields (severity, mode, check
            ids, fingerprints) are never touched.
    """
    texts = {text for secret in secrets for text in _texts(secret) if text}
    # only what the user gave can be short: an issued value is a text only from 8 characters
    short = sum(1 for text in texts if len(text) < MIN_SECRET_LENGTH)
    scrub = Redactor(texts)
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
