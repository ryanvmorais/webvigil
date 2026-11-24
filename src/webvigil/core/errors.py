"""
Exception hierarchy for the scan engine.

Every error the engine raises on purpose derives from :class:`WebVigilError`,
so a caller — the CLI today, the Web API tomorrow — can catch one type and map
it to an exit code or an HTTP status instead of leaking a raw traceback.
"""

from __future__ import annotations

from webvigil.core.urls import display_url


class WebVigilError(Exception):
    """
    Base class for every error WebVigil raises deliberately.

    Anything deriving from this type is a controlled failure with a
    user-facing message; anything else bubbling out of the engine is a bug.
    """


class InvalidTargetError(WebVigilError):
    """The scan target could not be parsed into a usable HTTP(S) URL."""


class OutOfScopeError(WebVigilError):
    """
    A request was attempted against a host outside the target scope.

    Attributes:
        url (str): The out-of-scope URL, as :func:`~webvigil.core.urls.display_url` shows it.
    """

    def __init__(self, url: str) -> None:
        """
        Args:
            url (str): The URL whose host falls outside the target scope.
        """
        self.url = display_url(url)
        super().__init__(f"URL is out of scope: {self.url}")


class RequestFailed(WebVigilError):
    """
    An HTTP request failed after exhausting retries.

    The message reaches terminals, CI logs, reports and the Web API, so it carries neither the
    text of the library's exception, which can quote header values and response bytes, nor the
    secret parts of the URL.

    Attributes:
        url (str): The URL that could not be fetched, as
            :func:`~webvigil.core.urls.display_url` shows it.
        reason (str): The kind of failure, in words written by this project.
    """

    def __init__(self, url: str, reason: str) -> None:
        """
        Args:
            url (str): The URL that could not be fetched.
            reason (str): The kind of failure (:func:`webvigil.http.failures.failure_kind`),
                never the text of an exception.
        """
        self.url = display_url(url)
        self.reason = reason
        super().__init__(f"request to {self.url} failed: {reason}")


class ScanDeadlineExceeded(RequestFailed):
    """The scan reached ``[scan] max_duration_s``: the request was not sent."""


class TargetUnreachableError(WebVigilError):
    """
    No page of the target answered, so there is nothing to report on.

    Raised after the crawl when every request it made failed (a closed port, a name that does
    not resolve, a timeout). A target that answers with an error status has answered.
    """


class ActiveModeNotAuthorized(WebVigilError):
    """Active Mode was requested without an ``authorized_by`` attestation."""


class DuplicateCheckId(WebVigilError):
    """Two checks tried to register under the same ``id``."""


class ConfigError(WebVigilError):
    """The configuration file or CLI overrides could not be resolved into a valid config."""


class OpenApiError(WebVigilError):
    """
    The ``--openapi`` document could not be loaded into usable operations (spec 013).

    Raised for a missing file, a non-200 or non-JSON URL response, a body that
    is not valid JSON, or JSON that is not a recognizable OpenAPI / Swagger
    document. A document that parses but yields no acted-on operations is a scan
    warning, not this error.
    """


class HarError(WebVigilError):
    """
    The ``--har`` file could not be loaded into usable operations (spec 021).

    Raised for a source that is not a local file, a missing or oversized file, a file that
    is not valid JSON, or JSON without ``log.entries``. A single entry the importer does not
    understand, or a valid file with no usable entry, is a scan warning, not this error.
    """


class LoginFailedError(WebVigilError):
    """
    The automated login (spec 019) could not establish a session.

    Raised before the crawl for a missing password, a login page with no usable form, an
    out-of-scope or delegated (SSO) login, a downgrade to clear text, or a verified failure.
    The message says what was observed and never carries the password, a cookie value or a
    response body. A failed login is final: WebVigil makes one attempt and never retries with
    other credentials.
    """
