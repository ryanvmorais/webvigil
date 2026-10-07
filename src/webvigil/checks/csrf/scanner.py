"""
The active CSRF confirmation pass: control, cross-site-shaped replays, verdict (spec 017).

Runs in the orchestrator, not as a check (like ``UploadScanner`` /
``StoredXssScanner``). For every candidate ``POST`` form it runs one short
experiment: re-fetch the form's page for a fresh token, submit the form the way a
legitimate user would (the **control**), then submit it again with the token
removed and with the token altered, carrying a foreign ``Origin`` / ``Referer`` the
way a cross-site form post would (the **replays**). A form is **confirmed** only when
the control was an acceptance and a replay produced an equivalent response; a
rejected replay **refutes** it; anything murky is **inconclusive**. Only a
confirmation becomes a :class:`CsrfHit`.

The pass writes to the target: a control and up to two replays per form, with
default field values and a benign sentinel (``wvcsrf<token>``) for fields that have
none. It never submits a payload and never changes a field other than the token.
The behaviour is documented and opt-in (``--confirm-csrf``), like ``--stored-xss``
and ``--file-upload``.
"""

from __future__ import annotations

import difflib
import re
import secrets
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlencode, urlsplit

from selectolax.parser import HTMLParser

from webvigil.checks.csrf.tokens import is_candidate, is_token_field
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.target import Target
from webvigil.crawler.forms import Form, form_body, parse_forms
from webvigil.crawler.safety import is_destructive_form, is_login_url
from webvigil.http.client import HttpClient, Response

type Verdict = Literal["confirmed", "refuted", "inconclusive"]

# Forms tested per scan, in inventory order. The rest are counted, never silently dropped.
_MAX_FORMS = 20
# Requests the pass issues for one form (fetch + control + two replays = 4, one spare).
_PER_FORM_CAP = 5
# A foreign origin carried as a header value only — never a request destination (RNF-06).
# The same sentinel host spec 012 puts in Host / X-Forwarded-*.
_FOREIGN_ORIGIN = "https://webvigil.invalid"
# Words a rejection page uses. Matched on the visible text only, so the markup of an
# ordinary page (a hidden ``csrf_token`` input) does not read as a rejection.
_REJECTION_RE = re.compile(
    r"csrf|xsrf|cross[\s-]site request|forbidden|"
    r"(?:invalid|missing|expired|bad|mismatch\w*)\W+(?:\w+\W+){0,2}(?:token|origin|referer)|"
    r"(?:token|origin|referer)\W+(?:\w+\W+){0,2}(?:invalid|missing|expired|required|mismatch\w*)|"
    r"session\W+(?:\w+\W+){0,2}expired",
    re.I,
)
# What legitimately differs between two submissions of the same form: hex ids, ISO-like
# timestamps, epoch-sized numbers.
_VOLATILE_RE = re.compile(r"\b[0-9a-f]{16,}\b|\d{4}-\d\d-\d\d[T ]\d\d:\d\d(?::\d\d)?\S*|\d{9,}")
_WORD_RE = re.compile(r"\w+|[^\w\s]")
# Two bodies are "the same page" at 95 % word-token similarity — tolerant of one more row in
# a listing, not of a form page versus a "saved" page (ADR-8) — and within 10 % in length.
_SIMILARITY = 0.95
_LENGTH_GUARD = 0.10
_TOKEN_CAP = 6000


@dataclass(frozen=True, slots=True)
class CsrfHit:
    """
    One form the server accepted without a valid anti-CSRF token.

    Attributes:
        url (str): The form action — the finding's location and fingerprint.
        source_url (str): URL of the page the form was found on.
        replay (str): The replay that was accepted: ``"token removed"``,
            ``"token altered"`` or ``"no token field"``.
        token_fields (tuple[str, ...]): Names of the form's token fields; empty
            when it has none.
        control (str): One-line summary of the control's response, e.g.
            ``"POST /newsletter -> 302 -> /panel (200)"``.
        attack (str): The same summary for the accepted replay.
    """

    url: str
    source_url: str
    replay: str
    token_fields: tuple[str, ...]
    control: str
    attack: str


@dataclass(frozen=True, slots=True)
class _Shape:
    """
    One response to a ``POST``, reduced to what the verdict compares.

    Attributes:
        first_status (int): Status of the server's answer to the ``POST`` itself
            (the first redirect hop when it redirected).
        final_status (int): Status after in-scope redirects.
        final_path (str): URL path after redirects, query dropped.
        body (str): The visible text, normalised.
        rejected (bool): ``True`` for an error status, a redirect to a login
            page, or a rejection phrase in the text.
    """

    first_status: int
    final_status: int
    final_path: str
    body: str
    rejected: bool


def _alter(value: str) -> str:
    """
    Args:
        value (str): An anti-CSRF token value.

    Returns:
        str: A same-length string that differs from ``value``: every letter and
            digit shifts to the next of its class (``a`` to ``b``, ``z`` to
            ``a``, ``9`` to ``0``). A value with no letter or digit becomes
            ``x`` repeated to its length, at least 8.
    """
    shifted: list[str] = []
    for char in value:
        if "a" <= char <= "z":
            shifted.append(chr((ord(char) - 97 + 1) % 26 + 97))
        elif "A" <= char <= "Z":
            shifted.append(chr((ord(char) - 65 + 1) % 26 + 65))
        elif "0" <= char <= "9":
            shifted.append(str((int(char) + 1) % 10))
        else:
            shifted.append(char)
    altered = "".join(shifted)
    return altered if altered != value else "x" * max(len(value), 8)


def _build_body(
    form: Form,
    *,
    sentinel: str,
    drop_tokens: bool = False,
    alter_tokens: bool = False,
) -> list[tuple[str, str]]:
    """
    Rebuild the urlencoded body a browser would send for ``form``.

    A thin wrapper over :func:`~webvigil.crawler.forms.form_body`: token fields are
    the **only** thing a replay changes — dropped, altered, or (for the control) kept
    exactly as served, even when empty.

    Args:
        form (Form): The (re-fetched) form.
        sentinel (str): The sentinel for this submission.
        drop_tokens (bool): Leave every token field out. Defaults to ``False``.
        alter_tokens (bool): Keep every token field but with an altered value.
            Defaults to ``False``.

    Returns:
        list[tuple[str, str]]: The ``(name, value)`` pairs, in parser order.
    """
    tokens = [field for field in form.fields if is_token_field(field)]
    if drop_tokens:
        return form_body(form, sentinel=sentinel, skip=frozenset(f.name for f in tokens))
    replace = {f.name: (_alter(f.value) if alter_tokens else f.value) for f in tokens}
    return form_body(form, sentinel=sentinel, replace=replace)


def _visible(response: Response) -> str:
    """
    Args:
        response (Response): A response.

    Returns:
        str: The text a person would read — scripts, styles and markup removed
            from an HTML body, the body itself otherwise.
    """
    if not response.is_html or not response.text.strip():
        return response.text
    tree = HTMLParser(response.text)
    tree.strip_tags(["script", "style"])
    return str(tree.text(separator=" "))


def _key(form: Form) -> tuple[str, str, tuple[str, ...]]:
    """
    Args:
        form (Form): A parsed form.

    Returns:
        tuple[str, str, tuple[str, ...]]: ``(method, action, field names)`` — the
            identity the pass uses to find a form again on a re-fetched page.
    """
    return (form.method, form.action, tuple(field.name for field in form.fields))


def _equivalent(control: _Shape, replay: _Shape) -> bool:
    """
    Args:
        control (_Shape): The control's response.
        replay (_Shape): A replay's response.

    Returns:
        bool: ``True`` when neither was rejected, the status class and final path
            match, and the bodies are the same page (word-token similarity at
            least ``_SIMILARITY``, lengths within ``_LENGTH_GUARD``).
    """
    if control.rejected or replay.rejected:
        return False
    if control.first_status // 100 != replay.first_status // 100:
        return False
    if control.final_path != replay.final_path:
        return False
    longest = max(len(control.body), len(replay.body))
    if longest and abs(len(control.body) - len(replay.body)) > _LENGTH_GUARD * longest:
        return False
    first = _WORD_RE.findall(control.body)[:_TOKEN_CAP]
    second = _WORD_RE.findall(replay.body)[:_TOKEN_CAP]
    return difflib.SequenceMatcher(None, first, second).ratio() >= _SIMILARITY


def _compare(control: _Shape, replay: _Shape) -> Verdict:
    """
    Args:
        control (_Shape): The control's response (an acceptance).
        replay (_Shape): One replay's response.

    Returns:
        Verdict: ``confirmed`` when equivalent to the control, ``refuted`` when
            rejected or different in status class or final path, otherwise
            ``inconclusive`` (same class and path, but the bodies differ).
    """
    if _equivalent(control, replay):
        return "confirmed"
    if (
        replay.rejected
        or control.first_status // 100 != replay.first_status // 100
        or control.final_path != replay.final_path
    ):
        return "refuted"
    return "inconclusive"


def _describe(action: str, shape: _Shape) -> str:
    """
    Args:
        action (str): The form action URL.
        shape (_Shape): A response.

    Returns:
        str: ``"POST /x -> 302 -> /y (200)"`` for a redirected answer,
            ``"POST /x -> 200"`` otherwise.
    """
    path = urlsplit(action).path or "/"
    if shape.first_status != shape.final_status:
        return f"POST {path} -> {shape.first_status} -> {shape.final_path} ({shape.final_status})"
    return f"POST {path} -> {shape.final_status}"


class CsrfScanner:
    """One bounded pass: control, replays and a verdict for each candidate ``POST`` form."""

    def __init__(
        self,
        http: HttpClient,
        target: Target,
        config: ScanConfig,
        pages: tuple[Page, ...],
        forms: tuple[Form, ...],
    ) -> None:
        """
        Args:
            http (HttpClient): The shared, scope-guarded HTTP client.
            target (Target): The normalized target.
            config (ScanConfig): The scan config (unused today; kept for symmetry
                with the other passes).
            pages (tuple[Page, ...]): The crawled pages (unused today; kept for
                symmetry with the other passes).
            forms (tuple[Form, ...]): The parsed ``<form>`` inventory.
        """
        self._http = http
        self._target = target
        self._config = config
        self._pages = pages
        self._forms = forms
        self._token = secrets.token_hex(4)
        self._sentinel_re = re.compile(rf"wvcsrf{self._token}[a-z][0-9]")
        self._calls = 0
        self.warnings: list[str] = []

    async def run(self) -> list[CsrfHit]:
        """
        Returns:
            list[CsrfHit]: One hit per confirmed form. One tally line is appended
                to ``warnings`` when the inventory had at least one ``POST`` form.
        """
        testable, skipped, over_cap, seen = self._candidates()
        hits: list[CsrfHit] = []
        tally = {"confirmed": 0, "refuted": 0, "inconclusive": 0}
        for form in testable:
            verdict, hit = await self._experiment(form)
            tally[verdict] += 1
            if hit is not None:
                hits.append(hit)
        if seen:
            noun = "form" if len(testable) == 1 else "forms"
            self.warnings.append(
                f"CSRF confirmation: {len(testable)} {noun} tested — "
                f"{tally['confirmed']} confirmed, {tally['refuted']} refuted, "
                f"{tally['inconclusive']} inconclusive, {skipped} skipped, "
                f"{over_cap} not tested (cap)"
            )
        return hits

    def _candidates(self) -> tuple[list[Form], int, int, int]:
        """
        Returns:
            tuple[list[Form], int, int, int]: The forms to test (at most
                ``_MAX_FORMS``), the count skipped for a safety or shape reason,
                the count left untested by the cap, and the number of distinct
                ``POST`` forms seen. ``GET`` forms are not counted at all.
        """
        seen_keys: set[tuple[str, str, tuple[str, ...]]] = set()
        testable: list[Form] = []
        skipped = over_cap = posts = 0
        for form in self._forms:
            if form.method != "POST" or _key(form) in seen_keys:
                continue
            seen_keys.add(_key(form))
            posts += 1
            if (
                form.enctype != "application/x-www-form-urlencoded"
                or any(field.type == "file" for field in form.fields)
                or not is_candidate(form)
                or is_destructive_form(form)
            ):
                skipped += 1
            elif len(testable) >= _MAX_FORMS:
                over_cap += 1
            else:
                testable.append(form)
        return testable, skipped, over_cap, posts

    async def _experiment(self, form: Form) -> tuple[Verdict, CsrfHit | None]:
        """
        Run fetch → control → replays for one form.

        Stops at a failed fetch, a rejected control (both inconclusive), or the
        first replay that confirms; otherwise refutes only when every replay was
        refuted.

        Args:
            form (Form): The form from the inventory.

        Returns:
            tuple[Verdict, CsrfHit | None]: The verdict, and the hit when it is
                ``confirmed``.
        """
        self._calls = 0
        fresh = await self._fetch_form(form)
        if fresh is None:
            return "inconclusive", None
        token_fields = tuple(field.name for field in fresh.fields if is_token_field(field))
        seen_tokens = tuple(
            field.value for field in fresh.fields if is_token_field(field) and field.value
        )
        scrub = seen_tokens + tuple(_alter(value) for value in seen_tokens)

        control_body = _build_body(fresh, sentinel=self._sentinel("c0"))
        control_response = await self._submit(fresh, control_body, foreign=False)
        if control_response is None:
            return "inconclusive", None
        control = self._shape(control_response, scrub)
        if control.rejected:
            return "inconclusive", None

        replays: list[tuple[str, bool, bool]] = (
            [("token removed", True, False), ("token altered", False, True)]
            if token_fields
            else [("no token field", False, False)]
        )
        verdicts: list[Verdict] = []
        for index, (label, drop, alter) in enumerate(replays, start=1):
            body = _build_body(
                fresh,
                sentinel=self._sentinel(f"r{index}"),
                drop_tokens=drop,
                alter_tokens=alter,
            )
            response = await self._submit(fresh, body, foreign=True)
            if response is None:
                verdicts.append("inconclusive")
                continue
            replay = self._shape(response, scrub)
            verdict = _compare(control, replay)
            if verdict == "confirmed":
                hit = CsrfHit(
                    url=form.action,
                    source_url=form.source_url,
                    replay=label,
                    token_fields=token_fields,
                    control=_describe(form.action, control),
                    attack=_describe(form.action, replay),
                )
                return "confirmed", hit
            verdicts.append(verdict)
        refuted = bool(verdicts) and all(verdict == "refuted" for verdict in verdicts)
        return ("refuted" if refuted else "inconclusive"), None

    def _sentinel(self, suffix: str) -> str:
        """
        Args:
            suffix (str): A letter and a digit: ``c0`` (control), ``r1`` / ``r2``
                (replays). Distinct per submission so a uniqueness constraint does
                not make a replay differ from the control for an unrelated reason.

        Returns:
            str: ``wvcsrf<pass token><suffix>``.
        """
        return f"wvcsrf{self._token}{suffix}"

    def _spend(self) -> bool:
        """
        Returns:
            bool: ``True`` while the form's request cap has room; counts one call.
        """
        if self._calls >= _PER_FORM_CAP:
            return False
        self._calls += 1
        return True

    async def _fetch_form(self, form: Form) -> Form | None:
        """
        Re-fetch the form's source page and find the form on it again.

        Args:
            form (Form): The form from the inventory.

        Returns:
            Form | None: The form as the page serves it now (fresh token), or
                ``None`` when the fetch fails or the form is no longer there.
        """
        if not self._spend():
            return None
        try:
            response = await self._http.get(form.source_url)
        except (OutOfScopeError, RequestFailed):
            return None
        page = Page.from_response(response)
        key = _key(form)
        for candidate in parse_forms(page, self._target):
            if _key(candidate) == key:
                return candidate
        return None

    async def _submit(
        self, form: Form, pairs: list[tuple[str, str]], *, foreign: bool
    ) -> Response | None:
        """
        Send one ``POST`` of ``pairs`` to the form's action.

        The control carries the target's own ``Origin`` and the form's page as
        ``Referer``; a replay carries the foreign origin. Configured ``[auth]``
        cookies are attached by the client.

        Args:
            form (Form): The (re-fetched) form.
            pairs (list[tuple[str, str]]): The urlencoded body.
            foreign (bool): ``True`` for a cross-site-shaped replay.

        Returns:
            Response | None: The response, or ``None`` when the cap is spent or
                the request failed.
        """
        if not self._spend():
            return None
        if foreign:
            headers = {"Origin": _FOREIGN_ORIGIN, "Referer": f"{_FOREIGN_ORIGIN}/"}
        else:
            headers = {"Origin": self._target.origin, "Referer": form.source_url}
        # httpx only takes a mapping as a form body; a pre-encoded body keeps the field order
        # and any repeated name exactly as the form defines them.
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            return await self._http.request(
                "POST", form.action, content=urlencode(pairs), headers=headers, crafted=True
            )
        except (OutOfScopeError, RequestFailed):
            return None

    def _shape(self, response: Response, scrub: tuple[str, ...]) -> _Shape:
        """
        Args:
            response (Response): The response to a ``POST``.
            scrub (tuple[str, ...]): Token values to remove from the body.

        Returns:
            _Shape: The status, final path, normalised visible text and the
                rejection flag.
        """
        # The sentinel carries "csrf" in its own name: strip it before looking for rejection
        # words, or an echoed field would read as a rejection page.
        text = self._sentinel_re.sub("", _visible(response))
        rejected = (
            response.status_code >= 400
            or is_login_url(response.url)
            or bool(_REJECTION_RE.search(text))
        )
        body = text
        for value in scrub:
            body = body.replace(value, "")
        body = " ".join(_VOLATILE_RE.sub("", body).split())
        first = response.history[0].status_code if response.history else response.status_code
        return _Shape(
            first_status=first,
            final_status=response.status_code,
            final_path=urlsplit(response.url).path,
            body=body,
            rejected=rejected,
        )
