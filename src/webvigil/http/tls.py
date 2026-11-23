"""
The TLS contexts of the engine's HTTP clients.

What a client trusts decides which certificates a scan accepts, so the engine states it here
instead of inheriting the default of the HTTP library: the ``certifi`` bundle, unless
``SSL_CERT_FILE`` or ``SSL_CERT_DIR`` names another source. Every client gets its own context,
because the transport writes the ALPN protocols onto the one it receives.
"""

from __future__ import annotations

import os
import ssl

import certifi
import httpcore2
import httpx2


def client_ssl_context(*, verify: bool = True) -> ssl.SSLContext:
    """
    Build the TLS context of one engine client.

    Args:
        verify (bool): Verify the server's certificate and host name. Defaults to ``True``.

    Returns:
        ssl.SSLContext: A new context. With ``verify`` it trusts ``SSL_CERT_FILE``, else
            ``SSL_CERT_DIR``, else the ``certifi`` bundle; an empty variable counts as unset.

    Raises:
        OSError: When the file a variable names cannot be read.
    """
    if not verify:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if cafile := os.environ.get("SSL_CERT_FILE"):
        return ssl.create_default_context(cafile=cafile)
    if capath := os.environ.get("SSL_CERT_DIR"):
        return ssl.create_default_context(capath=capath)
    return ssl.create_default_context(cafile=certifi.where())


def pin_proxy_trust(client: httpx2.AsyncClient) -> None:
    """
    Fix the trust of the TLS connection to each ``https://`` proxy set in the environment.

    That connection does not use the client's context, so the HTTP library would choose its
    trust. It gets the system store plus ``certifi``, and a corporate proxy whose CA is installed
    on the machine keeps working. The connection through the proxy to the target keeps the
    client's own context. An ``http://`` or SOCKS proxy has no TLS connection to the proxy, and a
    ``NO_PROXY`` entry has no transport, so those are left alone.

    Args:
        client (httpx2.AsyncClient): A client built without a custom transport.

    Raises:
        RuntimeError: When a mount is not the ``httpx2``/``httpcore2`` layout expected.
    """
    for transport in client._mounts.values():
        if transport is None:
            continue
        pool = getattr(transport, "_pool", None)
        if isinstance(pool, httpcore2.AsyncSOCKSProxy):
            continue
        if not isinstance(pool, httpcore2.AsyncHTTPProxy) or not hasattr(
            pool, "_proxy_ssl_context"
        ):
            raise RuntimeError("unexpected httpx2 proxy layout: cannot set the proxy's TLS trust")
        if pool._proxy_url.scheme == b"https":
            context = ssl.create_default_context()
            context.load_verify_locations(certifi.where())
            pool._proxy_ssl_context = context


__all__ = ["client_ssl_context", "pin_proxy_trust"]
