"""
Size bounds for the free text of a scan result.

A result carries what the scanned site sent (a path in a title, a cookie name, a header value)
and ``webvigil report`` reloads one from a file that someone else may have written, so every
free-text field has a ceiling. A longer value is cut and marked, never refused: the engine meets
the same bound when it builds a finding, so it never writes a report it could not read back, and
a value already cut (marker included) is left as it is, so a report reloads unchanged.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BeforeValidator

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

# What a cut value ends with, so a reader knows the text goes on; the evidence marker matches it.
TRUNCATION_MARKER = "...[truncated]"
# A one-line value: a check id, a title, a parameter, header or cookie name, a library name.
NAME_MAX_CHARS = 1024
# A paragraph: a description, a remediation, an error message, a warning.
TEXT_MAX_CHARS = 16 * 1024
# A URL or a traceback. httpx refuses to build a URL longer than 64 KiB, so no request the engine
# sent is cut.
URL_MAX_CHARS = 64 * 1024


# ---------------------------------------------------------------------------
# Truncation
# ---------------------------------------------------------------------------


def truncate(value: str, limit: int, marker: str = TRUNCATION_MARKER) -> str:
    """
    Args:
        value (str): The text to bound.
        limit (int): The most characters kept before the marker.
        marker (str): What is appended to a value that was cut. Defaults to
            :data:`TRUNCATION_MARKER`.

    Returns:
        str: ``value`` unchanged when it fits in ``limit`` plus the marker's length (so a value
            cut before reads back the same), otherwise its first ``limit`` characters and the
            marker.
    """
    if len(value) > limit + len(marker):
        return value[:limit] + marker
    return value


def bounded(limit: int, marker: str = TRUNCATION_MARKER) -> BeforeValidator:
    """
    Args:
        limit (int): The most characters kept before the marker.
        marker (str): What is appended to a value that was cut. Defaults to
            :data:`TRUNCATION_MARKER`.

    Returns:
        BeforeValidator: A validator that applies :func:`truncate` to a string and passes
            anything else on, so the field's own type check still runs.
    """
    return BeforeValidator(
        lambda value: truncate(value, limit, marker) if isinstance(value, str) else value
    )


# ---------------------------------------------------------------------------
# Field types
# ---------------------------------------------------------------------------

Name = Annotated[str, bounded(NAME_MAX_CHARS)]
Text = Annotated[str, bounded(TEXT_MAX_CHARS)]
Url = Annotated[str, bounded(URL_MAX_CHARS)]
