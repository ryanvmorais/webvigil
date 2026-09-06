"""Error-page and directory-listing signatures — RF-01, RF-02, RNF-05."""

from __future__ import annotations

import pytest

from webvigil.checks.disclosure.signatures import (
    is_directory_listing,
    match_error,
)
from webvigil.core.findings import Severity

_WERKZEUG = (
    "<!doctype html><title>ValueError // Werkzeug Debugger</title>"
    "<body>The Werkzeug debugger. Traceback (most recent call last): "
    'File "/app/views.py", line 10, in index</body>'
)
_DJANGO = (
    '<h1>TypeError at /accounts/</h1><div id="summary"><h1>TypeError at /accounts/</h1>'
    "</div><p>You're seeing this error because you have <code>DEBUG = True</code>.</p>"
)
_RAILS = "<title>Action Controller: Exception caught</title><h1>NoMethodError</h1>"
_ASPNET = "<h2> <i>Server Error in '/' Application.</i> </h2><b>Exception Details:</b>"
_PHP_FATAL = (
    "<br /><b>Fatal error</b>:  Uncaught Error: Call to undefined function q() in "
    "<b>/var/www/html/index.php</b> on line <b>12</b><br />"
)
_PHP_NOTICE = (
    "<br /><b>Notice</b>:  Undefined variable: name in <b>/var/www/app.php</b> "
    "on line <b>3</b><br />"
)
_JAVA = (
    "<pre>java.lang.NullPointerException\n\tat com.example.web.HomeController."
    "index(HomeController.java:42)\n\tat java.base/jdk.internal.reflect</pre>"
)
_NODE = (
    "<pre>Error: connect ECONNREFUSED 127.0.0.1:5432<br>"
    "&nbsp;&nbsp;&nbsp;at TCPConnectWrap.afterConnect (node:net:1247:16)</pre>"
)
_PYTHON = (
    'Traceback (most recent call last):\n  File "/srv/app/main.py", line 7, in <module>\n'
    "    raise RuntimeError\nRuntimeError"
)
_GENERIC = "<html><body><h1>Oops</h1><p>Something went wrong. Try again later.</p></body></html>"

_APACHE_INDEX = (
    "<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1>"
    '<pre><a href="../">../</a>\n<a href="db.sql">db.sql</a>\n<a href="notes.txt">notes.txt</a>'
    "</pre></body></html>"
)
_HTTP_SERVER_INDEX = (
    "<!DOCTYPE HTML><html><head><title>Directory listing for /files/</title></head>"
    '<body><h1>Directory listing for /files/</h1><ul><li><a href="a.txt">a.txt</a></li></ul>'
)
_LINK_LIST = (
    "<html><body><h2>Our pages</h2><ul>"
    '<li><a href="/about">About</a></li><li><a href="/contact">Contact</a></li></ul></body></html>'
)


@pytest.mark.parametrize(
    ("body", "framework", "interactive", "severity"),
    [
        (_WERKZEUG, "Werkzeug", True, Severity.HIGH),
        (_DJANGO, "Django", False, Severity.MEDIUM),
        (_RAILS, "Ruby on Rails", False, Severity.MEDIUM),
        (_ASPNET, "ASP.NET", False, Severity.MEDIUM),
        (_PHP_FATAL, "PHP", False, Severity.MEDIUM),
        (_PHP_NOTICE, "PHP", False, Severity.LOW),
        (_JAVA, "Java", False, Severity.MEDIUM),
        (_NODE, "Node.js", False, Severity.MEDIUM),
        (_PYTHON, "Python", False, Severity.MEDIUM),
    ],
)
def test_error_signatures_fire(
    body: str, framework: str, interactive: bool, severity: Severity
) -> None:
    match = match_error(body)
    assert match is not None
    assert match.signature.framework == framework
    assert match.signature.interactive is interactive
    assert match.signature.severity is severity
    assert match.snippet


def test_generic_error_page_does_not_match() -> None:
    assert match_error(_GENERIC) is None
    assert match_error("") is None


def test_directory_listing_signatures() -> None:
    assert is_directory_listing(_APACHE_INDEX)
    assert is_directory_listing(_HTTP_SERVER_INDEX)


def test_normal_link_list_is_not_a_listing() -> None:
    assert not is_directory_listing(_LINK_LIST)
