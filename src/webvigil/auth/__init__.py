"""
The automated login (spec 019).

``webvigil.auth.login`` holds the ``Authenticator`` (find the form, submit credentials once,
verify) and ``Credentials``; ``webvigil.auth.scrub`` hides the password and the session values
from a finished result. The session itself lives next to the ``HttpClient``, in
``webvigil.http.session``. Import from the submodules: this package re-exports nothing so that
importing ``webvigil.http`` never pulls the crawler in.
"""
