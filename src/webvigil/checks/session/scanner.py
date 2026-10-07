"""
The session-security pass (spec 020): what it observed, as value-free hits.

:class:`SessionScanner` runs **last** (after the CSRF confirmation) and does up to four things:
judge the session ids the crawl already saw; sample a few fresh anonymous visits; compare the
cookies across the login (session fixation); and log out, then replay the old session (a logout
that does not invalidate it). A :class:`SessionHit` is the only thing that leaves the pass. It
names the cookie and says in numbers and words why it is weak, unchanged across a login or still
valid after a logout; it never carries a cookie value, a prefix or a hash of one (RNF-07, ADR-8).
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from selectolax.parser import HTMLParser

from webvigil.auth.login import Authenticator
from webvigil.checks.session.cookies import is_jwt, is_session_cookie, session_cookies
from webvigil.checks.session.ids import (
    Rule,
    alphabet_of,
    estimated_bits,
    judge_samples,
    judge_value,
)
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.findings import Confidence, Severity
from webvigil.core.target import Target
from webvigil.crawler.forms import Form, form_body
from webvigil.crawler.safety import is_logout
from webvigil.http.client import HttpClient, Response
from webvigil.http.session import Session

# At most this many unchanged cookies are confirmed (one request each).
_MAX_FIXATION_CANDIDATES = 3
_LOGOUT_SENTINEL = "wvlogout"


@dataclass(frozen=True, slots=True)
class SessionHit:
    """
    One session-management weakness the pass observed.

    Attributes:
        kind (Literal["weak", "fixation", "logout"]): Which check turns it into a finding.
        name (str): The cookie's **name**; never its value.
        url (str): Where the cookie was observed, or the endpoint that was tested.
        severity (Severity): How serious the weakness is.
        confidence (Confidence): How sure the pass is.
        rule (str): Which rule fired, in words (``"numeric only"``).
        facts (tuple[tuple[str, str], ...]): Evidence as ``(label, content)`` pairs built from
            numbers and words only.
    """

    kind: Literal["weak", "fixation", "logout"]
    name: str
    url: str
    severity: Severity
    confidence: Confidence
    rule: str
    facts: tuple[tuple[str, str], ...] = ()


@dataclass(slots=True)
class _Observed:
    """The ids of one cookie name: the first value the crawl saw, and the anonymous samples."""

    url: str
    first: str | None = None
    samples: list[str] | None = None


class SessionScanner:
    """
    Observes the session ids, the fixation and the logout of a target (spec 020).

    Each step is guarded: one broken step costs a warning, not the other steps. Warnings are
    collected on :attr:`warnings` for the orchestrator to surface.
    """

    def __init__(
        self,
        http: HttpClient,
        target: Target,
        config: ScanConfig,
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
        *,
        session: Session | None,
        authenticator: Authenticator | None,
        kinds: frozenset[str],
    ) -> None:
        """
        Args:
            http (HttpClient): The shared, scope-guarded client.
            target (Target): The scan target.
            config (ScanConfig): The resolved configuration (``[session]``, ``[auth.login]``).
            pages (tuple[Page, ...]): The crawled pages.
            forms (tuple[Form, ...]): The parsed ``<form>`` inventory.
            session (Session | None): The login session, or ``None`` without a login.
            authenticator (Authenticator | None): The login's authenticator, or ``None``.
            kinds (frozenset[str]): The hit kinds whose checks are selected
                (``"weak"``, ``"fixation"``, ``"logout"``).
        """
        self._http = http
        self._target = target
        self._config = config
        self._pages = pages
        self._forms = forms
        self._session = session
        self._auth = authenticator
        self._kinds = kinds
        self.warnings: list[str] = []

    async def run(self) -> list[SessionHit]:
        """
        Run the steps that are asked for and selected, in order.

        Returns:
            list[SessionHit]: The weaknesses observed, weak ids first, the logout last.
        """
        steps: list[tuple[str, bool, Callable[[], Awaitable[list[SessionHit]]]]] = [
            ("weak ids", "weak" in self._kinds, self._weak),
            ("fixation", "fixation" in self._kinds, self._fixation),
            ("logout", "logout" in self._kinds, self._logout),
        ]
        hits: list[SessionHit] = []
        for name, wanted, step in steps:
            if not wanted:
                continue
            try:
                hits.extend(await step())
            except Exception as exc:  # a step bug must cost a warning, not the whole pass
                self.warnings.append(
                    f"session checks: the {name} step failed: {exc or type(exc).__name__}"
                )
        return hits

    # -- weak ids -----------------------------------------------------------

    async def _weak(self) -> list[SessionHit]:
        """
        Returns:
            list[SessionHit]: One hit per weak session cookie name, from the ids the crawl saw
                and (with ``[session] sample_ids``) from fresh anonymous visits.
        """
        observed: dict[str, _Observed] = {}
        for page in self._pages:
            if not page.ok:
                continue
            for name, value in session_cookies(page.headers):
                observed.setdefault(name, _Observed(url=page.url, first=value))
        if self._config.session.sample_ids:
            await self._sample(observed)
        hits: list[SessionHit] = []
        for name in sorted(observed):
            hit = self._judge(name, observed[name])
            if hit is not None:
                hits.append(hit)
        return hits

    async def _sample(self, observed: dict[str, _Observed]) -> None:
        """
        Visit the entry URL anonymously ``sample_count`` times and collect the session ids.

        Args:
            observed (dict[str, _Observed]): The per-name observations, extended in place.
        """
        count = self._config.session.sample_count
        entry = self._target.entry_url
        series: dict[str, list[str]] = {}
        for _ in range(count):
            try:
                async with self._http.anonymous():
                    response = await self._http.get(entry)
            except (OutOfScopeError, RequestFailed) as exc:
                self.warnings.append(f"session sampling stopped: {exc}")
                break
            for name, value in session_cookies(response.headers):
                series.setdefault(name, []).append(value)
        if not series:
            self.warnings.append(
                "session sampling: the target issued no session cookie to an anonymous visit"
            )
            return
        for name, values in series.items():
            item = observed.setdefault(name, _Observed(url=entry, first=values[0]))
            item.samples = values

    @staticmethod
    def _judge(name: str, item: _Observed) -> SessionHit | None:
        """
        Args:
            name (str): The cookie name.
            item (_Observed): What was seen for it.

        Returns:
            SessionHit | None: A hit when any rule fires on the first value or the series.
        """
        first = item.first
        if first is None:
            return None
        rules: list[Rule] = judge_value(first)
        if item.samples:
            rules += judge_samples(item.samples)
        if not rules:
            return None
        facts: list[tuple[str, str]] = [
            ("length", str(len(first))),
            ("alphabet", alphabet_of(first)[0]),
            ("estimated bits", str(int(estimated_bits(first)))),
        ]
        if item.samples:
            facts.append(("samples", str(len(item.samples))))
        facts.append(("rules", "; ".join(rule.text for rule in rules)))
        sampled = any(rule.sampled for rule in rules)
        return SessionHit(
            kind="weak",
            name=name,
            url=item.url,
            severity=max(rule.severity for rule in rules),
            confidence=Confidence.HIGH if sampled else Confidence.MEDIUM,
            rule=rules[0].code,
            facts=tuple(facts),
        )

    # -- fixation -----------------------------------------------------------

    async def _fixation(self) -> list[SessionHit]:
        """
        Returns:
            list[SessionHit]: One hit per session cookie that is the same before and after the
                login and is what authenticates (or could not be shown not to be).
        """
        auth, session = self._auth, self._session
        if auth is None or session is None or auth.transition is None:
            return []
        pre, post = auth.transition.pre, auth.transition.post
        candidates = [
            name
            for name in sorted(pre.keys() & post.keys())
            if is_session_cookie(name) and not is_jwt(pre[name]) and pre[name] == post[name]
        ][:_MAX_FIXATION_CANDIDATES]
        login = self._config.auth.login
        url = login.url if login else self._target.entry_url
        reference = auth.reference_url
        hits: list[SessionHit] = []
        for name in candidates:
            facts = [("cookie", name), ("when", "the value is the same before and after login")]
            if reference is None or not session.confirmed:
                facts.append(("verified", "no"))
                confidence = Confidence.MEDIUM
            else:
                try:
                    dropped = await self._dropped_without(session, reference, drop=name)
                except (OutOfScopeError, RequestFailed) as exc:
                    self.warnings.append(f"session fixation check for a cookie skipped: {exc}")
                    continue
                if not dropped:
                    continue  # the unchanged cookie is not what authenticates
                facts.append(("verified", "yes: the page needs it"))
                confidence = Confidence.HIGH
            hits.append(
                SessionHit(
                    kind="fixation",
                    name=name,
                    url=url,
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    rule="session id kept across login",
                    facts=tuple(facts),
                )
            )
        return hits

    async def _dropped_without(self, session: Session, reference: str, *, drop: str) -> bool:
        """
        Whether the reference page stops being authenticated without one cookie.

        Args:
            session (Session): The live session.
            reference (str): The reference page URL.
            drop (str): The cookie name to leave out.

        Returns:
            bool: ``True`` when the page looks logged out without that cookie.
        """
        pairs = session.jar.pairs_for(reference, handshake=False)
        header = "; ".join(f"{n}={v}" for n, v in pairs if n != drop)
        async with self._http.anonymous():
            response = await self._http.get(
                reference, headers={"cookie": header} if header else None
            )
        return session.looks_dropped(response)

    # -- logout -------------------------------------------------------------

    async def _logout(self) -> list[SessionHit]:
        """
        Returns:
            list[SessionHit]: A hit when the old session still reaches the reference page after
                the logout; empty when the logout works or the test cannot run (warned).
        """
        auth, session = self._auth, self._session
        login = self._config.auth.login
        if auth is None or session is None or login is None:
            return []
        reference = auth.reference_url
        if reference is None:
            self.warnings.append("session logout test skipped: no authenticated reference page")
            return []
        endpoint = self._find_logout(login.logout_url)
        if endpoint is None:
            self.warnings.append("session logout test skipped: no logout endpoint found")
            return []
        method, url, form = endpoint

        async with self._http.anonymous():
            oracle = await self._http.get(reference)
        if not session.looks_dropped(oracle):
            self.warnings.append(
                "session logout test skipped: the reference page is public (set "
                "[auth.login] check_url to a page that needs the login)"
            )
            return []
        pairs = session.jar.pairs_for(reference, handshake=False)
        if not pairs:
            self.warnings.append("session logout test skipped: the session holds no cookie")
            return []
        snapshot = "; ".join(f"{n}={v}" for n, v in pairs)
        names = [n for n, _v in pairs]

        response = await self._request_logout(method, url, form)
        if response.status_code >= 500:
            self.warnings.append(
                f"session logout test skipped: the logout answered {response.status_code}"
            )
            return []
        session.close()  # the session ends here, on purpose: no re-login follows
        async with self._http.anonymous():
            replay = await self._http.get(reference, headers={"cookie": snapshot})
        if replay.status_code >= 400 or session.looks_dropped(replay):
            return []
        session_names = [n for n in names if is_session_cookie(n)]
        return [
            SessionHit(
                kind="logout",
                name=(session_names or names)[0],
                url=url,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                rule="old session accepted after logout",
                facts=(
                    ("logout", f"{method} {urllib.parse.urlsplit(url).path}"),
                    ("replayed cookies", ", ".join(names)),
                    ("result", "the reference page still answered as logged in"),
                ),
            )
        ]

    def _find_logout(self, configured: str | None) -> tuple[str, str, Form | None] | None:
        """
        Args:
            configured (str | None): ``[auth.login] logout_url``.

        Returns:
            tuple[str, str, Form | None] | None: ``(method, url, form)`` of the logout to
                request: the configured URL, else the first logout link of the crawl, else the
                first ``POST`` logout form; ``None`` when there is none in scope.
        """
        if configured is not None:
            return ("GET", configured, None) if self._target.in_scope(configured) else None
        for page in self._pages:
            if not (page.ok and page.is_html and page.text):
                continue
            for node in HTMLParser(page.text).css("a[href]"):
                href = (node.attributes.get("href") or "").strip()
                url = urllib.parse.urljoin(page.url, href).split("#", 1)[0]
                if href and self._target.in_scope(url) and is_logout(url):
                    return "GET", url, None
        for form in self._forms:
            if (
                form.method == "POST"
                and is_logout(form.action)
                and self._target.in_scope(form.action)
            ):
                return "POST", form.action, form
        return None

    async def _request_logout(self, method: str, url: str, form: Form | None) -> Response:
        """
        Args:
            method (str): ``"GET"`` or ``"POST"``.
            url (str): The logout endpoint.
            form (Form | None): The form to submit for a ``POST`` logout.

        Returns:
            Response: The answer to the single logout request, made with the live session.
        """
        if method == "POST" and form is not None:
            body = urllib.parse.urlencode(form_body(form, sentinel=_LOGOUT_SENTINEL))
            return await self._http.request(
                "POST",
                url,
                content=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        return await self._http.request("GET", url)


def kinds_for(check_ids: Sequence[str]) -> frozenset[str]:
    """
    Args:
        check_ids (Sequence[str]): The ids of the selected checks.

    Returns:
        frozenset[str]: The hit kinds whose checks are among them.
    """
    mapping = {
        "session.id.weak": "weak",
        "session.fixation": "fixation",
        "session.logout.not-invalidated": "logout",
    }
    return frozenset(mapping[i] for i in check_ids if i in mapping)


__all__ = ["SessionHit", "SessionScanner", "kinds_for"]
