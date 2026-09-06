"""The documented, static payload sets for the active-injection detectors (spec 006, RNF-07).

Small and well-known — no mutation engine, no WAF-evasion tuning. ``{token}`` /
``{d}`` / ``{host}`` are substituted by the detector. Signatures are compiled regexes
matched against a response body and required to be *absent from the baseline*.
"""

from __future__ import annotations

import re

# --- reflected XSS (RF-08) -------------------------------------------------------------

XSS_TOKEN_BYTES = 6
# Sent first: is the parameter reflected at all? (No HTML-significant characters.)
XSS_PROBE = "wv{token}"
# Sent only when the probe reflects. A hit needs the payload back *verbatim* (so `<`, `>`,
# `"` were not entity- or percent-encoded) in an HTML response.
XSS_BREAKERS: tuple[str, ...] = (
    'wv{token}"><svg onload=wv{token}>',
    "wv{token}'></script><script>wv{token}</script>",
    '"><img src=x onerror=wv{token}>',
    "javascript:wv{token}",
)

# --- SQL injection (RF-09) ------------------------------------------------------------

# Error-based: break the quoting and look for a DBMS parser error.
SQLI_ERROR: tuple[str, ...] = ("'", '"', "')", "';", "\\", "' OR '1")

SQL_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "MySQL",
        re.compile(r"SQL syntax.*MySQL|MySqlException|valid MySQL result|MariaDB server", re.I),
    ),
    (
        "PostgreSQL",
        re.compile(r"PSQLException|unterminated quoted string|syntax error at or near", re.I),
    ),
    (
        "MSSQL",
        re.compile(r"Unclosed quotation mark|Incorrect syntax near|System\.Data\.SqlClient", re.I),
    ),
    ("Oracle", re.compile(r"ORA-0\d{4}|quoted string not properly terminated", re.I)),
    (
        "SQLite",
        re.compile(
            r"SQLITE_ERROR|unrecognized token|near \".+?\": syntax error|sqlite3\.OperationalError",
            re.I,
        ),
    ),
)

# Boolean-based: (true, false) appended to the original value. The detector tries each pair
# as a candidate — a real injection makes the TRUE response match the baseline and the
# FALSE response differ. The pairs cover the common quoted and numeric contexts.
SQLI_BOOLEAN_PAIRS: tuple[tuple[str, str], ...] = (
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND '1'='1'-- -", "' AND '1'='2'-- -"),
    (" AND 1=1", " AND 1=2"),
    (") AND (1=1", ") AND (1=2"),
)

# Time-based: {d} = the configured delay in seconds. One dialect per DBMS; the detector
# stops at the first that reproduces.
SQLI_TIME: tuple[tuple[str, str], ...] = (
    ("MySQL", "' AND SLEEP({d})-- -"),
    ("PostgreSQL", "' || pg_sleep({d})-- -"),
    ("MSSQL", "'; WAITFOR DELAY '0:0:{d}'-- -"),
    ("generic", " AND SLEEP({d})"),
)

# --- path traversal / LFI (RF-10) ---------------------------------------------------

TRAVERSAL: tuple[str, ...] = (
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../windows/win.ini",
    "..\\..\\..\\..\\..\\windows\\win.ini",
)

TRAVERSAL_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(r"root:.*?:0:0:"),
    re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.I),
)

# --- open redirect (RF-11) --------------------------------------------------------

# `.invalid` is a guaranteed-unresolvable TLD; the host is never requested (it is out of
# scope, so the scope guard blocks it) — the detector only reads the Location it was sent to.
REDIRECT_SENTINEL = "webvigil.invalid"
REDIRECT_PAYLOADS: tuple[str, ...] = (
    "https://webvigil.invalid/",
    "//webvigil.invalid/",
    "https:/webvigil.invalid",
    "https:\\\\webvigil.invalid",
    "/\\webvigil.invalid",
    "\thttps://webvigil.invalid",
    "https://{host}@webvigil.invalid",
)
