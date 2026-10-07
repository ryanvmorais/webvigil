"""
The automated login: find the form, submit credentials once, capture and verify the session.

Spec 019. The :class:`Authenticator` performs the handshake **through the**
:class:`~webvigil.http.client.HttpClient`, so the scope guard, the rate limiter and the
in-scope redirect loop apply, and the cookies of every hop of the chain land in the session's
pending jar. It never retries a failed attempt and never varies the credentials (RF-04): one
login is one ``POST``, and an account lockout is a real harm.

The password is held only by a :class:`Credentials` and is never copied into a message, a log
line or the config.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

from webvigil.core.config import LoginSection
from webvigil.core.errors import LoginFailedError, OutOfScopeError, RequestFailed
from webvigil.core.target import Target
from webvigil.crawler.forms import Form, form_body, parse_forms_html
from webvigil.crawler.safety import is_login_url
from webvigil.http.client import HttpClient, Response
from webvigil.http.session import Session, SessionJar

# Input types a username can live in (a missing ``type`` is parsed as ``text``).
_USERNAME_TYPES = frozenset({"text", "email", "tel"})


# ---------------------------------------------------------------------------
# Credentials and result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Credentials:
    """
    The account to log in with.

    The password is hidden from ``repr`` so an accidental log line or traceback cannot print
    it, and it is never a :class:`~webvigil.core.config.ScanConfig` field (ADR-8).

    Attributes:
        username (str): The account name or e-mail.
        password (str): The password.
    """

    username: str
    password: str = field(repr=False)

    @classmethod
    def from_environment(cls, username: str, env_name: str) -> Credentials:
        """
        Read the password from an environment variable.

        Args:
            username (str): The account name or e-mail.
            env_name (str): Name of the environment variable that holds the password.

        Returns:
            Credentials: The username with the password found in the environment.

        Raises:
            LoginFailedError: If the variable is unset or empty.
        """
        password = os.environ.get(env_name, "")
        if not password:
            raise LoginFailedError(
                f"no password for the login: set the environment variable {env_name}"
            )
        return cls(username=username, password=password)


@dataclass(frozen=True, slots=True)
class LoginResult:
    """
    The outcome of a login that did not fail.

    Attributes:
        confirmed (bool): ``True`` when a marker, the ``check_url`` or the heuristic said the
            login worked; ``False`` when none could tell (the scan continues with a warning).
    """

    confirmed: bool


# ---------------------------------------------------------------------------
# The authenticator
# ---------------------------------------------------------------------------


def _safe(url: str) -> str:
    """
    Args:
        url (str): Any URL.

    Returns:
        str: ``scheme://host/path`` without the query or fragment, so a token in a URL never
            reaches a message.
    """
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


class Authenticator:
    """
    Logs in once, and again whenever the session drops (spec 019).

    Owns the :class:`~webvigil.http.session.Session` it builds: the session's re-login and
    confirmation callbacks point back at this object.
    """

    def __init__(
        self,
        http: HttpClient,
        target: Target,
        login: LoginSection,
        credentials: Credentials,
    ) -> None:
        """
        Args:
            http (HttpClient): The client the handshake goes through.
            target (Target): The scan target; its scope guards the login.
            login (LoginSection): The ``[auth.login]`` configuration.
            credentials (Credentials): The account to submit.
        """
        self._http = http
        self._target = target
        self._login = login
        self._credentials = credentials
        self._logged_in = re.compile(login.logged_in_marker) if login.logged_in_marker else None
        self._logged_out = re.compile(login.logged_out_marker) if login.logged_out_marker else None
        self._login_path = urlsplit(login.url).path
        # where the last committed login landed: an authenticated page by construction, so the
        # reference for "is the session really gone?" when no check_url is configured
        self._landing: str | None = None
        self._candidate_landing: str | None = None
        self.session = Session(
            jar=SessionJar(target.host),
            is_login_url=self.is_login_url,
            logged_out_marker=login.logged_out_marker,
            max_relogins=login.max_relogins,
            relogin=self.relogin,
            confirm_dropped=self.confirm_dropped,
            secrets=[credentials.password],
        )

    def is_login_url(self, url: str) -> bool:
        """
        Args:
            url (str): An absolute URL.

        Returns:
            bool: ``True`` for the configured login page or anything that looks like one.
        """
        return urlsplit(url).path == self._login_path or is_login_url(url)

    async def login(self) -> LoginResult:
        """
        Run the handshake and commit the session (RF-04, RF-05, RF-06).

        Returns:
            LoginResult: Whether the login was confirmed.

        Raises:
            LoginFailedError: If any step fails or the login is verified to have failed. The
                live session, if there was one, is left as it was.
        """
        self._check_gate(self._login.url, "the login page")
        try:
            async with self._http.handshake():
                try:
                    result = await self._handshake()
                except BaseException:
                    self.session.jar.rollback()
                    raise
        except (OutOfScopeError, RequestFailed) as exc:
            raise LoginFailedError(f"the login request failed: {exc}") from exc
        self._landing = self._candidate_landing
        self.session.committed()
        return result

    async def relogin(self) -> bool:
        """
        The session's re-login callback: one more attempt, failure as a plain ``False``.

        Returns:
            bool: ``True`` when a new session was committed.
        """
        try:
            await self.login()
        except LoginFailedError as exc:
            self.session.note_failure(str(exc))
            return False
        return True

    async def confirm_dropped(self) -> bool:
        """
        Fetch the reference page with the live session and say whether it looks logged out.

        The reference is ``check_url`` or, without one, the page the last login landed on.
        A ``401`` or a login redirect on some other page (an API that wants different
        credentials, a page that bounces unauthorised users) is therefore not mistaken for an
        expired session.

        Returns:
            bool: ``True`` when the session looks dropped; also when there is no reference
                page to ask.
        """
        reference = self._login.check_url or self._landing
        if reference is None:
            return True
        async with self._http.quiet():
            try:
                response = await self._http.get(reference)
            except (OutOfScopeError, RequestFailed):
                return False  # cannot tell: do not spend a login on it
        return self.session.looks_dropped(response)

    # -- the handshake ------------------------------------------------------

    def _check_gate(self, url: str, what: str) -> None:
        """
        Args:
            url (str): A URL the login is about to request.
            what (str): What it is, for the message.

        Raises:
            LoginFailedError: If ``url`` is out of scope, or the target is ``https`` and
                ``url`` is not (the password is never sent in clear).
        """
        if not self._target.in_scope(url):
            raise LoginFailedError(f"{what} {_safe(url)} is out of scope")
        if urlsplit(self._target.entry_url).scheme == "https" and urlsplit(url).scheme != "https":
            raise LoginFailedError(f"{what} {_safe(url)} is not https: the password stays home")

    async def _handshake(self) -> LoginResult:
        """
        Returns:
            LoginResult: The verified outcome; the jar is committed on success.

        Raises:
            LoginFailedError: On any failure.
        """
        page = await self._http.get(self._login.url)
        self._check_delegated(page)
        if page.status_code >= 400 or not page.is_html:
            raise LoginFailedError(
                f"the login page {_safe(page.url)} answered {page.status_code}"
                f"{'' if page.is_html else ' without HTML'}"
            )
        form = self._pick_form(page)
        self._check_gate(form.action, "the login form action")
        user_field, password_field = self._pick_fields(form)
        body = self._build_body(form, user_field, password_field)
        before = self.session.jar.pending_items()

        headers = {"Origin": self._origin(), "Referer": page.url}
        if "multipart" in form.enctype.lower():
            # text parts only: a login form never carries a file
            parts: list[tuple[str, tuple[str | None, str | bytes, str | None]]] = [
                (name, (None, value.encode(), None)) for name, value in body
            ]
            response = await self._http.request("POST", form.action, files=parts, headers=headers)
        else:
            # ``data=`` with a list of pairs makes httpx build a sync stream, which its async
            # client refuses: send the encoded body ourselves (as the CSRF pass does).
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            response = await self._http.request(
                "POST", form.action, content=urlencode(body), headers=headers
            )
        self._check_delegated(response)
        ends_on_a_page = (
            response.status_code < 400
            and not self.is_login_url(response.url)
            and self._target.in_scope(response.url)
        )
        self._candidate_landing = response.url if ends_on_a_page else None
        return await self._verify(response, before)

    def _check_delegated(self, response: Response) -> None:
        """
        Args:
            response (Response): A handshake response.

        Raises:
            LoginFailedError: If it redirected out of scope (an SSO provider) — the chain is
                not followed and the credentials have only gone to the in-scope form.
        """
        if response.redirected_out_of_scope:
            host = urlsplit(response.final_location or "").hostname or "another host"
            raise LoginFailedError(f"login redirects to {host}: delegated login is not supported")

    def _origin(self) -> str:
        """
        Returns:
            str: The ``Origin`` a browser would send: scheme and host of the target.
        """
        parts = urlsplit(self._target.entry_url)
        return f"{parts.scheme}://{parts.netloc}"

    def _pick_form(self, page: Response) -> Form:
        """
        Args:
            page (Response): The login page.

        Returns:
            Form: The ``POST`` form with a password input (``form_index`` picks among several).

        Raises:
            LoginFailedError: If there is none, there are several and no ``form_index``, or
                ``form_index`` is out of range. The message lists what was found.
        """
        forms = parse_forms_html(page.text, page.url, self._target)
        candidates = [
            f
            for f in forms
            if f.method == "POST" and any(fld.type == "password" for fld in f.fields)
        ]
        index = self._login.form_index
        if index is not None:
            if index < len(candidates):
                return candidates[index]
            raise LoginFailedError(
                f"form_index {index} does not match a login form: {self._describe(candidates)}"
            )
        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            raise LoginFailedError(
                f"no login form (a POST form with a password input) on {_safe(page.url)}; "
                f"forms seen: {self._describe(forms)}"
            )
        raise LoginFailedError(
            f"{len(candidates)} login forms on {_safe(page.url)} and no form_index: "
            f"{self._describe(candidates)}"
        )

    @staticmethod
    def _describe(forms: list[Form]) -> str:
        """
        Args:
            forms (list[Form]): Forms found on a page.

        Returns:
            str: ``method action(field, field)`` per form — names only, never values.
        """
        if not forms:
            return "none"
        return "; ".join(
            f"{f.method} {_safe(f.action)}({', '.join(fld.name for fld in f.fields)})"
            for f in forms
        )

    def _pick_fields(self, form: Form) -> tuple[str, str]:
        """
        Args:
            form (Form): The chosen login form.

        Returns:
            tuple[str, str]: The username and password input names.

        Raises:
            LoginFailedError: If an override names an input the form lacks, or no username
                input can be found.
        """
        names = [fld.name for fld in form.fields]
        password = self._login.password_field
        if password is not None and password not in names:
            raise LoginFailedError(
                f"password_field {password!r} is not in the login form ({', '.join(names)})"
            )
        if password is None:
            password = next(fld.name for fld in form.fields if fld.type == "password")
        username = self._login.username_field
        if username is not None and username not in names:
            raise LoginFailedError(
                f"username_field {username!r} is not in the login form ({', '.join(names)})"
            )
        if username is None:
            before = list(form.fields[: names.index(password)])
            usable = [fld for fld in before if fld.type in _USERNAME_TYPES]
            if not usable:
                usable = [fld for fld in form.fields if fld.type in _USERNAME_TYPES]
            if not usable:
                raise LoginFailedError(
                    f"no username input in the login form ({', '.join(names)}); "
                    "set username_field"
                )
            username = usable[-1].name  # the nearest one before the password
        return username, password

    def _build_body(
        self, form: Form, user_field: str, password_field: str
    ) -> list[tuple[str, str]]:
        """
        Args:
            form (Form): The chosen login form.
            user_field (str): The username input name.
            password_field (str): The password input name.

        Returns:
            list[tuple[str, str]]: The body a browser would send: the form's own fields
                (hidden fields, CSRF token, submit button), the account, and the extras (an
                extra the form lacks is appended).
        """
        extras = dict(self._login.extra_pairs)
        replace = {**extras, user_field: self._credentials.username}
        replace[password_field] = self._credentials.password
        pairs = form_body(form, sentinel="", replace=replace)
        present = {name for name, _value in pairs}
        pairs.extend((n, v) for n, v in extras.items() if n not in present)
        return pairs

    async def _verify(self, response: Response, before: frozenset[tuple[str, str]]) -> LoginResult:
        """
        Decide whether the login worked, first rule that applies (RF-06, ADR-5).

        Args:
            response (Response): The final response of the handshake.
            before (frozenset[tuple[str, str]]): The pending cookies before the ``POST``.

        Returns:
            LoginResult: Confirmed, or not confirmed when nothing could tell.

        Raises:
            LoginFailedError: When the login is verified to have failed.
        """
        where = _safe(response.url)
        if response.status_code >= 500:
            raise LoginFailedError(f"the login answered {response.status_code} at {where}")
        if self._logged_out is not None and self._logged_out.search(response.text):
            raise LoginFailedError(f"logged_out_marker matched after the login at {where}")
        if self._logged_in is not None:
            if self._logged_in.search(response.text):
                self.session.jar.commit()
                return LoginResult(confirmed=True)
            raise LoginFailedError(f"logged_in_marker not found after the login at {where}")
        if self._login.check_url is not None:
            check = await self._http.get(self._login.check_url)
            if self.session.looks_dropped(check):
                raise LoginFailedError(
                    f"check_url {_safe(self._login.check_url)} still looks logged out"
                )
            self.session.jar.commit()
            return LoginResult(confirmed=True)
        still_a_form = any(
            fld.type == "password"
            for form in parse_forms_html(response.text, response.url, self._target)
            for fld in form.fields
        )
        if still_a_form:
            raise LoginFailedError(f"the login form is still there after the submission at {where}")
        new_cookie = self.session.jar.pending_items() - before
        self.session.jar.commit()
        return LoginResult(confirmed=bool(new_cookie))


__all__ = ["Authenticator", "Credentials", "LoginResult"]
