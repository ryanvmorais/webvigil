"""
Exception hierarchy for the scan engine.

Every error the engine raises on purpose derives from :class:`WebVigilError`,
so a caller — the CLI today, the Web API tomorrow — can catch one type and map
it to an exit code or an HTTP status instead of leaking a raw traceback.
"""

from __future__ import annotations


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
        url (str): The out-of-scope URL whose request was blocked.
    """

    def __init__(self, url: str) -> None:
        """
        Args:
            url (str): The URL whose host falls outside the target scope.
        """
        super().__init__(f"URL is out of scope: {url}")
        self.url = url


class RequestFailed(WebVigilError):
    """
    An HTTP request failed after exhausting retries.

    Attributes:
        url (str): The URL that could not be fetched.
        reason (str): Short description of the underlying transport failure.
    """

    def __init__(self, url: str, reason: str) -> None:
        """
        Args:
            url (str): The URL that could not be fetched.
            reason (str): Short description of the underlying transport failure.
        """
        super().__init__(f"request to {url} failed: {reason}")
        self.url = url
        self.reason = reason


class ActiveModeNotAuthorized(WebVigilError):
    """Active Mode was requested without an ``authorized_by`` attestation."""


class DuplicateCheckId(WebVigilError):
    """Two checks tried to register under the same ``id``."""


class ConfigError(WebVigilError):
    """The configuration file or CLI overrides could not be resolved into a valid config."""
