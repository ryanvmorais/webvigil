"""
The sensitive-point inventory of spec 027 (RF-07, ADR-5): every sensitive point has a reason.

:mod:`tests.sensitive_points` walks the source the repository tracks under ``src/webvigil``
(syntax trees, never imported) and ``web/src`` (text patterns), and lists every place where the
text of an exception becomes output, every exception raised with a dynamic value in its message
and every call of a dangerous operation. :data:`SENSITIVE_POINTS` holds the reason each one is
safe, written after reading its code and naming the guard: a point with no line fails, a line with
no point left fails, and an empty reason fails.

A key is ``<module>:<qualname> <family> <callee>`` in Python and ``<path> <family> <match>`` on
the dashboard; the second occurrence of a key in one function is ``#2``, in source order. A new
point is a new line here, in the pull request that adds it.

The positive controls walk a throwaway source with one point of each family, Python and
dashboard, including text followed through a variable, a wrapping exception and a field read in
another file, and compare every key found with the expected set; the negative controls in the
same source must stay out. The walk also counts the calls it read, which must equal every call of
the source, so a walk that stopped reading cannot pass.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from typing import Final

import pytest

from tests.sensitive_points import (
    DASHBOARD_FAMILIES,
    PYTHON_FAMILIES,
    ROOT,
    Inventory,
    tracked_files,
    walk,
)

# ---------------------------------------------------------------------------
# The inventory
# ---------------------------------------------------------------------------

# The reasons that many points share.
_SINKS: Final = "every output of it passes safe_text with its Sink (redacted, bounded, neutralized)"
_URL: Final = "display_url drops userinfo, query, fragment and ;parameters; " + _SINKS
_REQUEST_TEXT: Final = (
    "RequestFailed / OutOfScopeError text is display_url plus failure_kind's own words; " + _SINKS
)
_FAILURE_KIND: Final = "failure_kind(): words the project wrote, never the exception's text"
_LOG_TRACEBACK: Final = (
    "get_logger's SafeLogFilter rebuilds exc_text with safe_traceback: each message on one line "
    "through the LOG profile, the whole bounded"
)
_SQLMODEL: Final = "a SQLModel statement from select/update with bound parameters; no SQL text"
_VENDORED: Final = "a data file shipped in the package, read through importlib.resources"
_CONFIG: Final = "a value of the user's own configuration file, never a secret field; " + _SINKS
_PROGRAMMER: Final = "class, attribute and type names of the code itself; no input"
_CONSTANT_PATTERN: Final = "the pattern is built from module constants and re.escape"
_OPERANDS: Final = (
    "arithmetic operands of a payload, not a secret (the marker comes from secrets.token_hex)"
)
_CHECK_WARNING: Final = (
    "a scan warning: RequestFailed / OutOfScopeError text (display_url plus failure_kind); "
    + _SINKS
)
_LOGIN_MESSAGE: Final = (
    "LoginFailedError words with display_url, status codes and field names (_name_list cuts "
    "them); never a value; " + _SINKS
)
_OPENAPI_MESSAGE: Final = (
    "the source as display_url or display_path, sizes and HTTP status; " + _SINKS
)
_HAR_MESSAGE: Final = "the file as display_path, its size, or the type name only; " + _SINKS
_OSV_MESSAGE: Final = "the OSV API path is the project's constant; status codes and sizes only"
_CLI_ERROR: Final = (
    "_render.error writes through safe_text(Sink.TERMINAL); the message is a WebVigilError's, "
    "which never quotes a credential"
)
_TLS_OFF: Final = (
    "certificate checks off only for verify_tls = false, the user's choice for the target"
)
_TLS_PROBE: Final = (
    "the TLS probe reads the certificate it is judging, valid or not; nothing is sent over it"
)

SENSITIVE_POINTS: Final[Mapping[str, str]] = {
    # --- The Web API -----------------------------------------------------------------------
    "webvigil.api.cli:_load error terminal:typer.echo": (
        "ConfigError text (describe_validation_error, no values) through "
        "safe_text(Sink.TERMINAL, one_line=True)"
    ),
    "webvigil.api.cli:reset_password sql session.exec": _SQLMODEL,
    "webvigil.api.client_address:_resolve_name network socket.getaddrinfo": (
        "a trusted_proxies host name from the server's configuration; an error gives no address"
    ),
    "webvigil.api.config:WebConfig._secret_is_long_enough message ValueError": (
        "the minimum length constant only; the secret's value is never formatted"
    ),
    "webvigil.api.config:WebConfig._plain_host_names message ValueError": _CONFIG,
    "webvigil.api.config:WebConfig._proxy_entries message ValueError": _CONFIG,
    "webvigil.api.config:WebConfig._proxy_entries message ValueError#2": _CONFIG,
    "webvigil.api.config:WebConfig.load error raise:ConfigError": (
        "describe_validation_error leaves out pydantic's input values (the session_secret)"
    ),
    "webvigil.api.db:secure_database_files file os.open": (
        "the database path of the server's configuration, created with the private file mode"
    ),
    "webvigil.api.docs_ui:_with_integrity message RuntimeError": (
        "the tag is built from the pinned Swagger UI URL constants"
    ),
    "webvigil.api.docs_ui:swagger_ui_html html HTMLResponse": (
        "FastAPI's Swagger page with the pinned asset URLs and their integrity; no request value"
    ),
    "webvigil.api.mapping:store_result message LookupError": "the scan id, an integer",
    "webvigil.api.routes.auth:login sql session.exec": _SQLMODEL,
    "webvigil.api.routes.reports:download_report sql session.exec": _SQLMODEL,
    "webvigil.api.routes.scans:create_scan sql session.exec": _SQLMODEL,
    "webvigil.api.routes.scans:create_scan message HTTPException": (
        "the MAX_QUEUED_SCANS constant"
    ),
    "webvigil.api.routes.scans:list_scans sql session.exec": _SQLMODEL,
    "webvigil.api.routes.scans:list_findings sql session.exec": (
        _SQLMODEL + "; the search text is escaped for LIKE and bound"
    ),
    "webvigil.api.routes.scans:list_findings sql session.exec#2": _SQLMODEL,
    "webvigil.api.routes.scans:list_finding_checks sql session.exec": _SQLMODEL,
    "webvigil.api.routes.setup:_user_count sql session.exec": _SQLMODEL,
    "webvigil.api.runner:ScanRunner._loop error log-traceback:logger.exception": _LOG_TRACEBACK,
    "webvigil.api.runner:ScanRunner._loop error log-traceback:logger.exception#2": _LOG_TRACEBACK,
    "webvigil.api.runner:ScanRunner._loop error log-traceback:logger.exception#3": _LOG_TRACEBACK,
    "webvigil.api.runner:ScanRunner._run_scan error call:asyncio.to_thread": (
        "a WebVigilError's message, stored by _terminate through safe_text(Sink.STORE)"
    ),
    "webvigil.api.runner:ScanRunner._run_scan error log-traceback:logger.exception": (
        _LOG_TRACEBACK
    ),
    "webvigil.api.runner:ScanRunner._run_scan error log-traceback:logger.exception#2": (
        _LOG_TRACEBACK
    ),
    "webvigil.api.runner:ScanRunner._claim_next_queued sql session.exec": _SQLMODEL,
    "webvigil.api.runner:ScanRunner._load_config message LookupError": "the scan id, an integer",
    "webvigil.api.runner:recover_interrupted_scans sql session.exec": _SQLMODEL,
    "webvigil.api.schemas:ScanCreate._check error raise:ValueError": (
        "InvalidTargetError text is display_url; the 422 handler passes msg through "
        "safe_text(Sink.MESSAGE)"
    ),
    "webvigil.api.schemas:ScanOut.from_row error return": (
        "scan.error was stored through safe_text(Sink.STORE); the dashboard shows it with display"
    ),
    "webvigil.api.security:create_token crypto jwt.encode": (
        "HS256 with the server's session secret, revealed only here (ALLOWED_REVEALS)"
    ),
    "webvigil.api.security:decode_token crypto jwt.decode": (
        "algorithms pinned to HS256, exp and iat required"
    ),
    "webvigil.api.security:store_password_hash sql session.exec": _SQLMODEL,
    "webvigil.api.security:store_password_hash sql session.exec#2": _SQLMODEL,
    # --- The automated login ---------------------------------------------------------------
    "webvigil.auth.login:Credentials.from_environment message LoginFailedError": (
        "the name of the environment variable, never its value"
    ),
    "webvigil.auth.login:Authenticator.__init__ regex re.compile": (
        "the user's logged_in_marker, validated at load and searched in MARKER_BODY_CHARS only"
    ),
    "webvigil.auth.login:Authenticator.__init__ regex re.compile#2": (
        "the user's logged_out_marker, validated at load and searched in MARKER_BODY_CHARS only"
    ),
    "webvigil.auth.login:Authenticator.login error raise:LoginFailedError": _REQUEST_TEXT,
    "webvigil.auth.login:Authenticator.relogin error call:self.session.note_failure": (
        "a LoginFailedError's message, which never carries the password, a cookie or a body"
    ),
    "webvigil.auth.login:Authenticator._check_gate message LoginFailedError": _URL,
    "webvigil.auth.login:Authenticator._check_gate message LoginFailedError#2": _URL,
    "webvigil.auth.login:Authenticator._handshake message LoginFailedError": _URL,
    "webvigil.auth.login:Authenticator._check_delegated message LoginFailedError": (
        "the redirect's host name only, parsed by urlsplit; " + _SINKS
    ),
    "webvigil.auth.login:Authenticator._pick_form message LoginFailedError": (
        "_describe lists method, action and field names of a few forms, never a value"
    ),
    "webvigil.auth.login:Authenticator._pick_form message LoginFailedError#2": _LOGIN_MESSAGE,
    "webvigil.auth.login:Authenticator._pick_form message LoginFailedError#3": _LOGIN_MESSAGE,
    "webvigil.auth.login:Authenticator._pick_fields message LoginFailedError": (
        "the configured password_field is a field name, not the password; " + _SINKS
    ),
    "webvigil.auth.login:Authenticator._pick_fields message LoginFailedError#2": _LOGIN_MESSAGE,
    "webvigil.auth.login:Authenticator._pick_fields message LoginFailedError#3": _LOGIN_MESSAGE,
    "webvigil.auth.login:Authenticator._verify message LoginFailedError": _LOGIN_MESSAGE,
    "webvigil.auth.login:Authenticator._verify message LoginFailedError#2": _LOGIN_MESSAGE,
    "webvigil.auth.login:Authenticator._verify message LoginFailedError#3": _LOGIN_MESSAGE,
    "webvigil.auth.login:Authenticator._verify message LoginFailedError#4": _LOGIN_MESSAGE,
    "webvigil.auth.login:Authenticator._verify message LoginFailedError#5": _LOGIN_MESSAGE,
    "webvigil.auth.scrub:scrub_result error call:tuple": (
        "the scrub itself: each check error's message and traceback go through scrub()"
    ),
    # --- The checks ------------------------------------------------------------------------
    "webvigil.checks.csrf.scanner:CsrfScanner.__init__ regex re.compile": (
        "the scanner's own token, hex from secrets.token_hex"
    ),
    "webvigil.checks.deps._data:load_raw_db file .read_text": _VENDORED,
    "webvigil.checks.deps._data:load_provenance file .read_text": _VENDORED,
    "webvigil.checks.deps.osv:OsvProvider.lookup error collection:warnings.append": (
        "OsvLookupError words (path, status, failure_kind); the package and version are "
        "bounded scan text; " + _SINKS
    ),
    "webvigil.checks.deps.osv:OsvProvider._client network httpx2.AsyncClient": (
        "the OSV.dev base URL, verify=client_ssl_context() and pin_proxy_trust"
    ),
    "webvigil.checks.deps.osv:OsvProvider._post message OsvLookupError": _OSV_MESSAGE,
    "webvigil.checks.deps.osv:OsvProvider._post message OsvLookupError#2": _OSV_MESSAGE,
    "webvigil.checks.deps.osv:OsvProvider._post error raise:OsvLookupError": _FAILURE_KIND,
    "webvigil.checks.deps.osv:OsvProvider._post message OsvLookupError#3": _OSV_MESSAGE,
    "webvigil.checks.deps.osv:OsvProvider._post message OsvLookupError#4": _OSV_MESSAGE,
    "webvigil.checks.deps.osv:OsvProvider._read message OsvLookupError": _OSV_MESSAGE,
    "webvigil.checks.deps.rules:<module> regex re.compile": _CONSTANT_PATTERN,
    "webvigil.checks.deps.rules:_compile_one regex re.compile": (
        "a vendored Retire.js pattern, with every repeat bounded by _bound_repeats"
    ),
    "webvigil.checks.deps.rules:_compile_one regex re.compile#2": (
        "a vendored Retire.js pattern, with every repeat bounded by _bound_repeats"
    ),
    "webvigil.checks.deps.rules:RetireJsRules.identify crypto hashlib.sha1": (
        "SHA-1 as the file fingerprint Retire.js lists, not a security use"
    ),
    "webvigil.checks.disclosure.catalogue:load_catalogue file .read_text": _VENDORED,
    "webvigil.checks.disclosure.catalogue:load_catalogue error raise:ConfigError": (
        "tomllib's message about the shipped catalogue, a file of the package"
    ),
    "webvigil.checks.disclosure.catalogue:_validator_from_toml regex re.compile": (
        "a pattern of the shipped catalogue"
    ),
    "webvigil.checks.disclosure.catalogue:_validator_from_toml error raise:ConfigError": (
        "re's message about a pattern of the shipped catalogue"
    ),
    "webvigil.checks.disclosure.catalogue:backup_spec file .read_text": _VENDORED,
    "webvigil.checks.disclosure.catalogue:_validate message ConfigError": (
        "a path and a check id of the shipped catalogue"
    ),
    "webvigil.checks.disclosure.leakage:<module> regex re.compile": _CONSTANT_PATTERN,
    "webvigil.checks.disclosure.probe:_hash crypto hashlib.sha1": (
        "SHA-1 to compare two bodies, not a security use"
    ),
    "webvigil.checks.envelope.scanner:<module> regex re.compile": _CONSTANT_PATTERN,
    "webvigil.checks.envelope.scanner:<module> regex re.compile#2": _CONSTANT_PATTERN,
    "webvigil.checks.injection.detect.cmdi:detect crypto random.randint": _OPERANDS,
    "webvigil.checks.injection.detect.cmdi:detect crypto random.randint#2": _OPERANDS,
    "webvigil.checks.injection.detect.cmdi:_whole_number regex re.compile": (
        "an integer the detector computed, between digit lookarounds"
    ),
    "webvigil.checks.injection.detect.el:_run crypto random.randint": _OPERANDS,
    "webvigil.checks.injection.detect.el:_run crypto random.randint#2": _OPERANDS,
    "webvigil.checks.injection.detect.el:_probe_type_access crypto random.randint": _OPERANDS,
    "webvigil.checks.injection.detect.redirect:<module> regex re.compile": _CONSTANT_PATTERN,
    "webvigil.checks.injection.detect.redirect:<module> regex re.compile#2": _CONSTANT_PATTERN,
    "webvigil.checks.injection.detect.ssti:detect crypto random.randint": _OPERANDS,
    "webvigil.checks.injection.detect.ssti:detect crypto random.randint#2": _OPERANDS,
    "webvigil.checks.registry:register message WebVigilError": _PROGRAMMER,
    "webvigil.checks.registry:register message DuplicateCheckId": _PROGRAMMER,
    "webvigil.checks.registry:load_plugins code entry_points": (
        "loads the checks of packages the user installed: the plugin contract"
    ),
    "webvigil.checks.session.scanner:SessionScanner._sample error "
    "collection:self.warnings.append": _CHECK_WARNING,
    "webvigil.checks.session.scanner:SessionScanner._fixation error "
    "collection:self.warnings.append": _CHECK_WARNING,
    "webvigil.checks.upload.scanner:_same_answer regex re.compile": (
        "the scanner's own token through re.escape"
    ),
    # --- The CLI ---------------------------------------------------------------------------
    "webvigil.cli.app:scan error terminal:_render.error": (
        "ConfigError text (describe_validation_error, display_path, type names); " + _CLI_ERROR
    ),
    "webvigil.cli.app:scan error terminal:_render.error#2": _CLI_ERROR,
    "webvigil.cli.app:scan error terminal:_render.error#3": _CLI_ERROR,
    "webvigil.cli.app:report error terminal:_render.error": (
        "the user's own path and load_result's words, built from the report's field names "
        "(an OSError is named by its type); safe_text(Sink.TERMINAL)"
    ),
    "webvigil.cli.app:_write_report file output.write_text": "the path is the user's --output",
    # --- The engine ------------------------------------------------------------------------
    "webvigil.core:__getattr__ message AttributeError": _PROGRAMMER,
    "webvigil.core.config:LoginSection._check_extra message ValueError": (
        "the entry's position only, never its value"
    ),
    "webvigil.core.config:LoginSection._check_marker regex re.compile": (
        "compiles the user's marker to validate it; nothing is searched"
    ),
    "webvigil.core.config:LoginSection._check_marker error raise:ValueError": _CONFIG,
    "webvigil.core.config:AuthSection._parse_cookies message ValueError": (
        "the entry's position only, never the cookie"
    ),
    "webvigil.core.config:AuthSection._parse_headers message ValueError": (
        "the entry's position only, never the header"
    ),
    "webvigil.core.config:AuthSection._parse_headers message ValueError#2": (
        "a header name (Host, Content-Length), never a value"
    ),
    "webvigil.core.config:read_toml message ConfigError": "display_path of the user's file",
    "webvigil.core.config:read_toml file file.read_text": "the user's own --config file",
    "webvigil.core.config:read_toml error raise:ConfigError": (
        "tomllib's message names a line and column of the user's own file; " + _SINKS
    ),
    "webvigil.core.config:read_toml message ConfigError#2": (
        "display_path and the type name; the OSError's text is left out"
    ),
    "webvigil.core.config:ScanConfig.model_validate_or_raise error raise:ConfigError": (
        "describe_validation_error leaves out pydantic's input values (cookies, headers, password)"
    ),
    "webvigil.core.orchestrator:Orchestrator.run error raise:TargetUnreachableError": (
        "Page.error holds RequestFailed / OutOfScopeError text (display_url plus failure_kind)"
    ),
    "webvigil.core.orchestrator:Orchestrator._osv_lookup error collection:warnings.append": (
        "OsvLookupError words (path, status, failure_kind); " + _SINKS
    ),
    "webvigil.core.orchestrator:Orchestrator._run_checks._run_one error "
    "collection:errors.append": (
        "_check_error_message keeps the exception's type name; the traceback keeps frames only"
    ),
    "webvigil.core.result:ScanResult._not_from_the_future message ValueError": (
        "two integers (the report's schema_version and SCHEMA_VERSION)"
    ),
    "webvigil.core.secrets:Secret.__init__ message TypeError": _PROGRAMMER,
    "webvigil.core.secrets:Secret.__init__ message TypeError#2": _PROGRAMMER,
    "webvigil.core.secrets:Secret.__init__ message TypeError#3": _PROGRAMMER,
    "webvigil.core.suffixes:load_rules file .read_text": _VENDORED,
    "webvigil.core.target:Target.parse message InvalidTargetError": _URL,
    "webvigil.core.text:<module> regex re.compile": _CONSTANT_PATTERN,
    "webvigil.core.text:<module> regex re.compile#2": _CONSTANT_PATTERN,
    "webvigil.core.text:<module> regex re.compile#3": _CONSTANT_PATTERN,
    "webvigil.core.urls:<module> regex re.compile": _CONSTANT_PATTERN,
    # --- The crawler -----------------------------------------------------------------------
    "webvigil.crawler.crawler:Crawler.robots_unreadable error return": (
        "the reason robots.load gives: failure_kind's words or an HTTP status"
    ),
    "webvigil.crawler.crawler:Crawler.discover error field": (
        "the reason robots.load gives: failure_kind's words or an HTTP status"
    ),
    "webvigil.crawler.crawler:Crawler._submit_form error return": _REQUEST_TEXT,
    "webvigil.crawler.crawler:Crawler._submit_operation error return": _REQUEST_TEXT,
    "webvigil.crawler.crawler:Crawler._fetch error return": _REQUEST_TEXT,
    "webvigil.crawler.har:_read_entries message HarError": _URL,
    "webvigil.crawler.har:_read_entries message HarError#2": _HAR_MESSAGE,
    "webvigil.crawler.har:_read_entries message HarError#3": _HAR_MESSAGE,
    "webvigil.crawler.har:_read_entries file source.read_bytes": (
        "the user's --har file, read only after its size is checked"
    ),
    "webvigil.crawler.har:_read_entries message HarError#4": _HAR_MESSAGE,
    "webvigil.crawler.har:_read_entries message HarError#5": _HAR_MESSAGE,
    "webvigil.crawler.har:_read_entries message HarError#6": _HAR_MESSAGE,
    "webvigil.crawler.openapi:_fetch_document message OpenApiError": _OPENAPI_MESSAGE,
    "webvigil.crawler.openapi:_fetch_document error raise:OpenApiError": _REQUEST_TEXT,
    "webvigil.crawler.openapi:_fetch_document message OpenApiError#2": _OPENAPI_MESSAGE,
    "webvigil.crawler.openapi:_fetch_document message OpenApiError#3": _OPENAPI_MESSAGE,
    "webvigil.crawler.openapi:_fetch_document message OpenApiError#4": _OPENAPI_MESSAGE,
    "webvigil.crawler.openapi:_fetch_document file path.read_text": (
        "the user's --openapi file, read only after its size is checked"
    ),
    "webvigil.crawler.openapi:_fetch_document message OpenApiError#5": _OPENAPI_MESSAGE,
    "webvigil.crawler.openapi:_fetch_document message OpenApiError#6": _OPENAPI_MESSAGE,
    "webvigil.crawler.openapi:_fetch_document message OpenApiError#7": (
        "the source as display_url or display_path and the parser's line and column, never its "
        "message; " + _SINKS
    ),
    "webvigil.crawler.openapi:_fetch_document message OpenApiError#8": _OPENAPI_MESSAGE,
    "webvigil.crawler.openapi:_fetch_document message OpenApiError#9": _OPENAPI_MESSAGE,
    "webvigil.crawler.robots:_escapes regex re.compile": (
        "kept is one of the module's fixed character sets"
    ),
    "webvigil.crawler.robots:load error return": (
        "RequestFailed.reason is failure_kind's words, never the exception's text"
    ),
    "webvigil.crawler.sitemap:parse xml ElementTree.fromstring": (
        "a body with a DOCTYPE is refused first, so no entity is defined; the body is bounded"
    ),
    # --- The HTTP layer --------------------------------------------------------------------
    "webvigil.http.addresses:system_resolver network loop.getaddrinfo": (
        "the address guard's own lookup, once per name per scan"
    ),
    "webvigil.http.addresses:system_resolver error raise:httpcore2.ConnectError": (
        "the client turns it into failure_kind's words; its text never leaves the engine"
    ),
    "webvigil.http.addresses:AddressGuard.addresses message BlockedAddressError": (
        "the host name, which every output shows through safe_text; the client keeps the kind"
    ),
    "webvigil.http.addresses:GuardedBackend.connect_tcp message httpcore2.ConnectTimeout": (
        "the host name; the client turns it into failure_kind's words"
    ),
    "webvigil.http.addresses:GuardedBackend.connect_tcp error raise": (
        "re-raises httpcore2's error; the client turns it into failure_kind's words"
    ),
    "webvigil.http.client:HttpClient.__aenter__ network httpx2.AsyncClient": (
        "verify=client_ssl_context(), no redirects followed, the address guard's transport"
    ),
    "webvigil.http.client:HttpClient._request_with_retry crypto random.uniform": (
        "the jitter of the retry backoff, not a secret"
    ),
    "webvigil.http.client:HttpClient._request_with_retry message _TotalTimeout": (
        "the total_timeout_s setting, a number"
    ),
    "webvigil.http.client:HttpClient._request_with_retry error raise:RequestFailed": (
        _FAILURE_KIND
    ),
    "webvigil.http.client:HttpClient._request_with_retry error call:failure_kind": (_FAILURE_KIND),
    "webvigil.http.client:HttpClient._request_with_retry error raise:RequestFailed#2": (
        _FAILURE_KIND
    ),
    "webvigil.http.client:HttpClient._request_with_retry error raise:RequestFailed#3": (
        "failure_kind's words and the _TotalTimeout text this function wrote"
    ),
    "webvigil.http.client:HttpClient._request_with_retry error raise:RequestFailed#4": (
        _FAILURE_KIND
    ),
    "webvigil.http.client:HttpClient._request_with_retry error raise:RequestFailed#5": (
        _FAILURE_KIND
    ),
    "webvigil.http.decoding:_Inflater._step error raise:httpx2.DecodingError": (
        "zlib's own message; the client turns the DecodingError into failure_kind's words"
    ),
    "webvigil.http.decoding:_Inflater._step error raise:httpx2.DecodingError#2": (
        "zlib's own message; the client turns the DecodingError into failure_kind's words"
    ),
    "webvigil.http.decoding:_Inflater.finish error raise:httpx2.DecodingError": (
        "zlib's own message; the client turns the DecodingError into failure_kind's words"
    ),
    "webvigil.http.session:Session.__init__ regex re.compile": (
        "the user's logged_out_marker, searched in MARKER_BODY_CHARS only"
    ),
    "webvigil.http.tls:client_ssl_context crypto ssl.SSLContext": _TLS_OFF,
    "webvigil.http.tls:client_ssl_context crypto check_hostname=False": _TLS_OFF,
    "webvigil.http.tls:client_ssl_context crypto ssl.create_default_context": (
        "verifies against SSL_CERT_FILE, the user's environment"
    ),
    "webvigil.http.tls:client_ssl_context crypto ssl.create_default_context#2": (
        "verifies against SSL_CERT_DIR, the user's environment"
    ),
    "webvigil.http.tls:client_ssl_context crypto ssl.create_default_context#3": (
        "verifies against certifi's bundle"
    ),
    "webvigil.http.tls:pin_proxy_trust crypto ssl.create_default_context": (
        "verifies an https proxy against the system store and certifi's bundle"
    ),
    "webvigil.http.tls_probe:_unverified_context crypto ssl.SSLContext": _TLS_PROBE,
    "webvigil.http.tls_probe:_unverified_context crypto check_hostname=False": _TLS_PROBE,
    "webvigil.http.tls_probe:_handshake network socket.create_connection": (
        "the address the guard allowed for the target's host"
    ),
    "webvigil.http.tls_probe:_probe_sync error return": (
        "_unreachable keeps failure_kind's words only"
    ),
    "webvigil.http.tls_probe:probe error return": "_unreachable keeps failure_kind's words only",
    # --- Reporting -------------------------------------------------------------------------
    "webvigil.reporting:get_reporter message ValueError": (
        "the format name; the CLI's Choice and the API's validation accept known names only"
    ),
    "webvigil.reporting:load_result file .open": (
        "the user's own report path, read in blocks up to MAX_REPORT_BYTES"
    ),
    "webvigil.reporting:_read_bounded message ValueError": "the MAX_REPORT_BYTES constant",
    "webvigil.reporting:_parse_report error raise:ValueError": (
        "_invalid_report counts the errors and names places, never a value from the file"
    ),
    "webvigil.reporting:_parse_report error call:_error_details": (
        "pydantic's error list without input values, for _invalid_report"
    ),
    "webvigil.reporting:_parse_report error raise:ValueError#2": (
        "_invalid_report counts the errors and names places, never a value from the file"
    ),
    "webvigil.reporting:_parse_report error raise:ValueError#3": (
        "_invalid_report counts the errors and names places, never a value from the file"
    ),
    "webvigil.reporting.html:<module> html Environment": (
        "autoescape on for report.html.j2; links only through is_http_url"
    ),
    # --- The dashboard ---------------------------------------------------------------------
    "web/src/app/(app)/scans/[id]/page.tsx error (error,": (
        "errorMessage: an API detail or Error message through display (showControls)"
    ),
    "web/src/components/providers.tsx error (error,": (
        "unauthorizedRedirect reads the status only"
    ),
    "web/src/components/providers.tsx redirect router.replace(": (
        "unauthorizedRedirect returns one of two fixed /login paths"
    ),
    "web/src/components/report-preview.tsx error (cause,": (
        "errorMessage: an API detail or Error message through display (showControls)"
    ),
    "web/src/components/scan-form.tsx error (error)": (
        "fieldErrors maps the API's 422 items, whose msg the API passed through safe_text"
    ),
    "web/src/hooks/use-auth.ts redirect router.replace(": (
        "safeNext keeps a same-origin path only"
    ),
    "web/src/hooks/use-query-param.ts redirect router.replace(": (
        "the current pathname and its own query string"
    ),
    "web/src/lib/api.ts network fetch(": "a same-origin /api path the module builds",
    "web/src/lib/api.ts network fetch(#2": "a same-origin /api path the module builds",
}


@pytest.fixture(scope="module")
def files() -> dict[str, str]:
    """
    Returns:
        dict[str, str]: The tracked source the walk reads, shared by the tests of this module.
    """
    return tracked_files()


@pytest.fixture(scope="module")
def inventory(files: dict[str, str]) -> Inventory:
    """
    Args:
        files (dict[str, str]): The tracked source.

    Returns:
        Inventory: The walk over it.
    """
    return walk(files)


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def test_every_point_is_in_the_inventory(inventory: Inventory) -> None:
    found = set(inventory.points)
    unlisted = sorted(found - set(SENSITIVE_POINTS))
    stale = sorted(set(SENSITIVE_POINTS) - found)
    detail = [
        f"  {key}  ({inventory.points[key].path}:{inventory.points[key].line}: "
        f"{inventory.points[key].snippet})"
        for key in unlisted
    ]
    assert not unlisted, "sensitive points with no reason in SENSITIVE_POINTS:\n" + "\n".join(
        detail
    )
    assert not stale, f"SENSITIVE_POINTS lines with no point left: {stale}"
    assert not inventory.unparsed, f"files the walk could not parse: {inventory.unparsed}"


def test_every_reason_is_written() -> None:
    empty = sorted(key for key, reason in SENSITIVE_POINTS.items() if not reason.strip())
    assert not empty, f"sensitive points with an empty reason: {empty}"


def test_the_walk_reads_every_call(files: dict[str, str], inventory: Inventory) -> None:
    """The count of calls read equals every call of the tracked source, and is past the table."""
    calls = sum(
        isinstance(node, ast.Call)
        for path, source in files.items()
        if path.endswith(".py")
        for node in ast.walk(ast.parse(source))
    )
    dashboard = sum(len(s.splitlines()) for p, s in files.items() if not p.endswith(".py"))
    python_points = sum(not key.startswith("web/") for key in SENSITIVE_POINTS)
    assert inventory.calls_read == calls
    assert inventory.calls_read > python_points
    assert inventory.lines_read == dashboard
    assert inventory.lines_read > len(SENSITIVE_POINTS) - python_points
    assert (ROOT / "src" / "webvigil").is_dir()


# ---------------------------------------------------------------------------
# The positive and negative controls
# ---------------------------------------------------------------------------

_SAMPLE_A = """
import hashlib
import pickle
import re
import socket
import subprocess
import traceback
from xml.etree import ElementTree

from fastapi.responses import HTMLResponse, RedirectResponse


class SampleError(Exception): ...


class Page:
    def __init__(self, url, error=None):
        self.url = url
        self.error = error


class Holder:
    PATTERN = re.compile(SOURCE)


def through_a_variable(http):
    last = ""
    for _ in range(2):
        try:
            http.get()
        except ValueError as exc:
            last = f"{exc}"
    raise SampleError(last)


def wrapping(http):
    try:
        http.get()
    except OSError as exc:
        raise SampleError(str(exc)) from exc


def into_a_field(http, url):
    try:
        http.get()
    except OSError as exc:
        return Page(url, error=str(exc))


def only_the_type(http):
    try:
        http.get()
    except OSError as exc:
        raise SampleError(f"failed ({type(exc).__name__})") from exc


def logged(logger):
    try:
        1 / 0
    except ZeroDivisionError:
        logger.exception("broke")


def formatted():
    return traceback.format_exc()


def fixed_message():
    raise SampleError("fixed")


def operations(cursor, session, statement, query, path, pattern, text, url, code, name, node):
    subprocess.run(["ls"])
    eval(code)
    pickle.loads(text)
    cursor.execute(query)
    cursor.execute("select 1")
    session.exec(statement)
    node.text()
    open(path)
    open(path)
    ElementTree.fromstring(text)
    re.compile(pattern)
    re.compile("fixed")
    HTMLResponse(text)
    RedirectResponse(url)
    socket.create_connection((name, 443))
    hashlib.md5(text)


def tls(client, context):
    client.get(verify=False)
    context.check_hostname = False


def in_a_lambda(paths):
    return sorted(paths, key=lambda path: open(path))


def by_default(compiled=re.compile(SOURCE)):
    return compiled
"""

_SAMPLE_B = """
def read_the_field(page, logger):
    logger.warning("no answer: %s", page.error)


def read_another_field(page, logger):
    logger.warning("no answer: %s", page.url)


def same_named_method(panel):
    panel.error("fixed")
"""

_SAMPLE_TSX = """
export function Sample({ html, url, code, pattern, path }: Props) {
  const location = "not a redirect";
  try {
    run();
  } catch (err) {
    toast(err.message);
  }
  query.mutate(undefined, { onError: (error) => setText(String(error)) });
  eval(code);
  require("child_process");
  window.location.href = url;
  new RegExp(pattern);
  new RegExp("fixed");
  fetch(path);
  fetch("/api/fixed");
  Math.random();
  const token = process.env.NEXT_PUBLIC_TOKEN;
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
"""

_SAMPLE: Final = {
    "src/webvigil/sample/a.py": _SAMPLE_A,
    "src/webvigil/sample/b.py": _SAMPLE_B,
    "web/src/sample.tsx": _SAMPLE_TSX,
}

_A: Final = "webvigil.sample.a"
_TSX: Final = "web/src/sample.tsx"
_EXPECTED: Final = {
    # Exception text through a variable, a wrapping exception, a field and another file's read.
    f"{_A}:through_a_variable error raise:SampleError",
    f"{_A}:wrapping error raise:SampleError",
    f"{_A}:into_a_field error return",
    "webvigil.sample.b:read_the_field error log:logger.warning",
    f"{_A}:logged error log-traceback:logger.exception",
    f"{_A}:formatted error traceback:traceback.format_exc",
    # The type's name is not the text, but the message is dynamic.
    f"{_A}:only_the_type message SampleError",
    # One of each operation; a literal SQL or pattern and selectolax's node.text() are not.
    f"{_A}:operations command subprocess.run",
    f"{_A}:operations code eval",
    f"{_A}:operations deserialization pickle.loads",
    f"{_A}:operations sql cursor.execute",
    f"{_A}:operations sql session.exec",
    f"{_A}:operations file open",
    f"{_A}:operations file open#2",
    f"{_A}:operations xml ElementTree.fromstring",
    f"{_A}:operations regex re.compile",
    f"{_A}:operations html HTMLResponse",
    f"{_A}:operations redirect RedirectResponse",
    f"{_A}:operations network socket.create_connection",
    f"{_A}:operations crypto hashlib.md5",
    f"{_A}:tls crypto verify=False",
    f"{_A}:tls crypto check_hostname=False",
    # A class body, a lambda and a default value are read too.
    f"{_A}:Holder regex re.compile",
    f"{_A}:in_a_lambda file open",
    f"{_A}:<module> regex re.compile",
    # The dashboard.
    f"{_TSX} error err.message",
    f"{_TSX} error String(error",
    f"{_TSX} code eval(",
    f"{_TSX} command child_process",
    f"{_TSX} redirect window.location.href =",
    f"{_TSX} regex new RegExp(",
    f"{_TSX} network fetch(",
    f"{_TSX} crypto Math.random(",
    f"{_TSX} client-secret NEXT_PUBLIC_TOKEN",
    f"{_TSX} html dangerouslySetInnerHTML",
}


def test_the_walk_finds_one_point_of_each_family() -> None:
    """Every family is seen, and nothing else: the negative controls stay out."""
    found = walk(_SAMPLE).points
    missing = sorted(_EXPECTED - set(found))
    unexpected = sorted(set(found) - _EXPECTED)
    assert not missing, f"points the walk no longer finds: {missing}"
    assert not unexpected, f"points the walk should not find: {unexpected}"
    python = {p.family for p in found.values() if p.path.endswith(".py")}
    dashboard = {p.family for p in found.values() if not p.path.endswith(".py")}
    assert python == PYTHON_FAMILIES
    assert dashboard == DASHBOARD_FAMILIES


def test_the_sample_walk_reads_every_call() -> None:
    sample = walk(_SAMPLE)
    calls = sum(
        isinstance(node, ast.Call)
        for path, source in _SAMPLE.items()
        if path.endswith(".py")
        for node in ast.walk(ast.parse(source))
    )
    assert sample.calls_read == calls
    assert sample.lines_read == len(_SAMPLE_TSX.splitlines())


def test_a_file_that_does_not_parse_is_reported() -> None:
    assert walk({"src/webvigil/broken.py": "def broken(:\n"}).unparsed == (
        "src/webvigil/broken.py",
    )
