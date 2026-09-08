"""
Unrestricted file-upload testing (spec 014, ``Category.UPLOAD``).

:class:`~webvigil.checks.upload.scanner.UploadScanner` is an orchestrator pass
(the model of ``StoredXssScanner`` / ``EnvelopeScanner``): for every discovered
file-upload ``<form>``, and for a gated ``PUT`` probe, it uploads benign marker
files and fetches them back, confirming in-band whether the target executed the
file, served it inline, or stored it out of its directory. It is opt-in
(``--file-upload`` / ``[injection] file_upload``) because it writes files the
target keeps.

:class:`~webvigil.checks.upload.checks.UnrestrictedUploadCheck` turns the pass's
``UploadHit``s into findings; it issues no request.
"""

from webvigil.checks.upload import checks  # noqa: F401
