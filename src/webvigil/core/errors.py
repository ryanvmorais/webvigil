"""Exception hierarchy for the scan engine.

Every error the engine raises on purpose derives from :class:`WebVigilError`, so callers
(the CLI, the future Web API) can catch one type and map it to an exit code or HTTP status.
"""

from __future__ import annotations


class WebVigilError(Exception):
    """Base class for all deliberate WebVigil errors."""


class InvalidTargetError(WebVigilError):
    """The scan target could not be parsed into a usable HTTP(S) URL."""


class OutOfScopeError(WebVigilError):
    """A request was attempted against a host outside the target scope."""

    def __init__(self, url: str) -> None:
        super().__init__(f"URL is out of scope: {url}")
        self.url = url


class RequestFailed(WebVigilError):
    """An HTTP request failed after exhausting retries."""

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"request to {url} failed: {reason}")
        self.url = url
        self.reason = reason


class ActiveModeNotAuthorized(WebVigilError):
    """Active Mode was requested without an ``authorized_by`` attestation."""


class DuplicateCheckId(WebVigilError):
    """Two checks tried to register under the same ``id``."""


class ConfigError(WebVigilError):
    """The configuration file or CLI overrides could not be resolved into a valid config."""
