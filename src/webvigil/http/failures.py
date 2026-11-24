"""
The name of a transport failure, for the messages that reach the user.

``str()`` of an ``httpx2``, ``httpcore2`` or ``ssl`` error is written by the library and can quote
raw bytes: a header value it refused, or part of a malformed response. Such a message would reach
terminals, CI logs, reports, the database and the Web API, so a failure is named by its type. The
two failures a user can act on are told apart by the exception chain and described in this
project's own words.
"""

from __future__ import annotations

import ssl

from webvigil.http.addresses import BlockedAddressError

# ``httpx2`` wraps ``httpcore2``, which wraps the socket or TLS error: a real chain is short, and
# the limit keeps a chain that loops from holding up the failure it describes.
_MAX_CHAIN_DEPTH = 8
_BLOCKED_ADDRESS = "BlockedAddressError: the host resolves to an address the scan may not reach"
_UNTRUSTED_CERTIFICATE = "SSLCertVerificationError: the TLS certificate is not trusted"


def failure_kind(exc: BaseException) -> str:
    """
    Args:
        exc (BaseException): A transport failure.

    Returns:
        str: A fixed description when the chain holds a refusal by the address guard or an
            untrusted TLS certificate; otherwise the name of the exception's class, without a
            leading underscore. Never the text of an exception.
    """
    link: BaseException | None = exc
    for _ in range(_MAX_CHAIN_DEPTH):
        if link is None:
            break
        if isinstance(link, BlockedAddressError):
            return _BLOCKED_ADDRESS
        if isinstance(link, ssl.SSLCertVerificationError):
            return _UNTRUSTED_CERTIFICATE
        # A suppressed context still counts: the TLS layer keeps the certificate error only there
        link = link.__cause__ or link.__context__
    return type(exc).__name__.lstrip("_")


__all__ = ["failure_kind"]
