"""
The documented metadata of every registered check: id, category, mode, default severity, CWE ids.

One table instead of a ``*_check_metadata`` test in each check's file (issue #101). The ids, the
default severities and the CWEs reach users — in the SARIF rules, in ``--fail-on`` and in the
dashboard — so a change to any of them must be deliberate: it fails here until the row is edited.
A new check fails here too until it has a row, which keeps the table the complete list.
"""

from __future__ import annotations

from webvigil.checks.registry import all_checks, load_plugins

# (check id, category, mode, default severity, CWE ids)
_CHECKS = [
    ("content.mixed", "CONTENT", "passive", "MEDIUM", (319,)),
    ("content.sri.missing", "CONTENT", "passive", "MEDIUM", (353, 1104)),
    ("csrf.form.no-token", "CSRF", "passive", "MEDIUM", (352,)),
    ("csrf.form.token-not-enforced", "CSRF", "active", "MEDIUM", (352,)),
    ("deps.js.library-detected", "DEPS", "passive", "INFO", ()),
    ("deps.js.vulnerable-library", "DEPS", "passive", "MEDIUM", ()),
    ("disclosure.backup.file-exposed", "DISCLOSURE", "passive", "MEDIUM", (538, 530)),
    ("disclosure.config.dotenv-exposed", "DISCLOSURE", "passive", "HIGH", (538, 200)),
    ("disclosure.config.manifest-exposed", "DISCLOSURE", "passive", "LOW", (538,)),
    ("disclosure.debug.endpoint-exposed", "DISCLOSURE", "passive", "MEDIUM", (215, 497)),
    ("disclosure.debug.error-page", "DISCLOSURE", "passive", "MEDIUM", (215, 200)),
    ("disclosure.listing.directory-index", "DISCLOSURE", "passive", "MEDIUM", (548, 200)),
    ("disclosure.private-ip", "DISCLOSURE", "passive", "LOW", (200,)),
    ("disclosure.session-id-in-url", "DISCLOSURE", "passive", "MEDIUM", (598,)),
    ("disclosure.sourcemap.exposed", "DISCLOSURE", "passive", "MEDIUM", (540, 200)),
    ("disclosure.vcs.exposed", "DISCLOSURE", "passive", "HIGH", (527, 538)),
    ("http.cookies.flags", "COOKIES", "passive", "MEDIUM", (614, 1004)),
    ("http.cors.misconfiguration", "CORS", "passive", "MEDIUM", (942,)),
    ("http.headers.content-type-options", "HEADERS", "passive", "LOW", (693,)),
    ("http.headers.cross-origin-isolation", "HEADERS", "passive", "INFO", ()),
    ("http.headers.csp", "HEADERS", "passive", "MEDIUM", (693,)),
    ("http.headers.frame-options", "HEADERS", "passive", "MEDIUM", (1021,)),
    ("http.headers.hsts", "HEADERS", "passive", "MEDIUM", (319,)),
    ("http.headers.permissions-policy", "HEADERS", "passive", "INFO", ()),
    ("http.headers.referrer-policy", "HEADERS", "passive", "LOW", (200,)),
    ("http.headers.revealing", "HEADERS", "passive", "LOW", (200,)),
    ("http.methods.unsafe", "HTTP", "active", "MEDIUM", (650, 693, 16)),
    ("injection.cmdi.os", "INJECTION", "active", "CRITICAL", (78, 77)),
    ("injection.crlf", "INJECTION", "active", "HIGH", (113, 93)),
    ("injection.el", "INJECTION", "active", "HIGH", (917, 94)),
    ("injection.host-header", "INJECTION", "active", "MEDIUM", (644,)),
    ("injection.ldap", "INJECTION", "active", "HIGH", (90,)),
    ("injection.redirect.open", "INJECTION", "active", "MEDIUM", (601,)),
    ("injection.sqli.boolean-based", "INJECTION", "active", "HIGH", (89,)),
    ("injection.sqli.error-based", "INJECTION", "active", "HIGH", (89, 209)),
    ("injection.sqli.time-based", "INJECTION", "active", "HIGH", (89,)),
    ("injection.ssi", "INJECTION", "active", "HIGH", (97, 94)),
    ("injection.ssrf.internal", "INJECTION", "active", "HIGH", (918,)),
    ("injection.ssrf.metadata", "INJECTION", "active", "CRITICAL", (918,)),
    ("injection.ssti", "INJECTION", "active", "HIGH", (1336, 94)),
    ("injection.traversal.path", "INJECTION", "active", "HIGH", (22, 23)),
    ("injection.xpath", "INJECTION", "active", "HIGH", (643,)),
    ("injection.xss.reflected", "INJECTION", "active", "HIGH", (79, 20)),
    ("injection.xss.stored", "INJECTION", "active", "HIGH", (79, 20)),
    ("injection.xxe", "INJECTION", "active", "HIGH", (611, 827)),
    ("session.fixation", "SESSION", "active", "MEDIUM", (384,)),
    ("session.id.weak", "SESSION", "passive", "MEDIUM", (330, 331, 340)),
    ("session.logout.not-invalidated", "SESSION", "active", "MEDIUM", (613,)),
    ("tls.https", "TLS", "passive", "HIGH", (319, 295)),
    ("upload.unrestricted", "UPLOAD", "active", "HIGH", (434, 646)),
]


def test_every_registered_check_has_a_row_with_the_documented_metadata() -> None:
    """The registry and the table list the same checks, and each check matches its row."""
    load_plugins()
    registered = {check.id: check for check in all_checks()}
    assert set(registered) == {row[0] for row in _CHECKS}
    for check_id, category, mode, severity, cwe in _CHECKS:
        check = registered[check_id]
        actual = (check.category.value, check.mode.value, check.default_severity.name, check.cwe)
        assert actual == (category, mode, severity, cwe), check_id
