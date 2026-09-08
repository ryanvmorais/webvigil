"""
The file-upload pass: upload benign markers, fetch them back, classify (spec 014, RF-01..RF-06).

Runs in the orchestrator, not as a check (like ``StoredXssScanner`` /
``EnvelopeScanner``). For every discovered file-upload ``<form>`` it uploads a
small set of benign marker files with dangerous names / types, locates the
stored file, and confirms in-band whether the target executed it, served it
inline, or stored it outside the upload directory. It also runs one gated
``PUT`` probe (the only state-changing verb 014 sends).

Every uploaded file is a few hundred inert bytes: a ``<?php echo 6*7; ?>`` that
computes a product, an HTML ``<script>`` comment, or a plain text marker. The
files are left on the target and WebVigil cannot delete them — the behaviour is
documented, exactly as for ``--stored-xss`` (ADR-7).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from webvigil.checks.injection.points import _EXCLUDE_FORM_RE
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.errors import OutOfScopeError, RequestFailed
from webvigil.core.findings import Confidence, Severity
from webvigil.core.target import Target
from webvigil.crawler.forms import Form
from webvigil.http.client import HttpClient, Response

# Conventional directories a stored upload is served from — tried in order when the upload
# response does not link the file itself.
_UPLOAD_PREFIXES = (
    "/uploads/",
    "/files/",
    "/media/",
    "/upload/",
    "/static/uploads/",
    "/img/",
    "/assets/",
)
# A served file with one of these content types (and no attachment disposition) runs in the
# site origin.
_INLINE_TYPES = ("text/html", "application/xhtml+xml", "image/svg+xml")
# Source markers: their presence means the file came back as source, not executed output.
_SOURCE_MARKERS = ("<?php", "<?=", "<% ")
_PER_FORM_CAP = 40
_SNIPPET_SPAN = 120


@dataclass(frozen=True, slots=True)
class UploadPayload:
    """
    One benign marker file to upload.

    Attributes:
        family (str): ``"server-exec"`` / ``"client-exec"`` / ``"bypass"`` /
            ``"traversal"``.
        filename (str): The multipart part filename (may carry ``../``, ``%00``,
            a double extension).
        content (bytes): The file body — inert, a few hundred bytes, carrying
            the ``wv<token>`` marker.
        part_type (str): The multipart part's declared ``Content-Type``.
        product (str): The ``a*b`` product string a server-side execution would
            print, or ``""`` for the non-executable families.
    """

    family: str
    filename: str
    content: bytes
    part_type: str
    product: str


@dataclass(frozen=True, slots=True)
class UploadHit:
    """
    One confirmed unrestricted-upload finding, ready for a check to render.

    Attributes:
        outcome (str): ``"server-exec"`` / ``"inline-html"`` / ``"traversal"`` /
            ``"put-upload"`` / ``"inert-accept"``.
        url (str): The upload endpoint (form action) or the ``PUT`` path.
        method (str): ``"POST"`` or ``"PUT"``.
        field (str | None): The file field name, or ``None`` for the ``PUT``
            probe.
        retrieved_from (str): The URL the stored file was fetched back from.
        severity (Severity): Severity for the finding.
        confidence (Confidence): Confidence for the finding.
        title (str): Finding title.
        payload_name (str): The uploaded filename that worked.
        evidence (tuple[tuple[str, str], ...]): ``(label, content)`` pairs.
    """

    outcome: str
    url: str
    method: str
    field: str | None
    retrieved_from: str
    severity: Severity
    confidence: Confidence
    title: str
    payload_name: str
    evidence: tuple[tuple[str, str], ...]


class UploadScanner:
    """One bounded pass: upload benign markers through discovered forms, fetch them back."""

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
            config (ScanConfig): The scan config; reads
                ``injection.upload_budget``.
            pages (tuple[Page, ...]): The crawled pages (unused today; kept for
                symmetry with the other passes).
            forms (tuple[Form, ...]): The parsed ``<form>`` inventory.
        """
        self._http = http
        self._target = target
        self._budget = config.injection.upload_budget
        self._pages = pages
        self._forms = forms
        self._spent = 0
        self.warnings: list[str] = []

    async def run(self) -> list[UploadHit]:
        """
        Probe every upload form, then the gated ``PUT`` endpoint.

        Returns:
            list[UploadHit]: The confirmed hits.
        """
        hits: list[UploadHit] = []
        for form in self._upload_forms():
            if self._spent >= self._budget:
                break
            hits.extend(await self._probe_form(form))
        hits.extend(await self._probe_put())
        if self._spent >= self._budget:
            self.warnings.append(f"file-upload pass stopped at the {self._budget}-request budget")
        return hits

    def _upload_forms(self) -> list[Form]:
        """
        Returns:
            list[Form]: Every discovered form with a ``type="file"`` field that
                is not auth- or destruction-shaped, de-duplicated by action.
        """
        seen: set[str] = set()
        out: list[Form] = []
        for form in self._forms:
            if not any(field.type == "file" for field in form.fields):
                continue
            blob = form.action + " " + " ".join(field.name for field in form.fields)
            if _EXCLUDE_FORM_RE.search(blob):
                continue
            if form.action in seen:
                continue
            seen.add(form.action)
            out.append(form)
        return out

    def _payloads(self, token: str) -> list[UploadPayload]:
        """
        Args:
            token (str): The per-form ``secrets.token_hex``.

        Returns:
            list[UploadPayload]: The benign marker files, in test order.
        """
        marker = f"wv{token}"
        a = secrets.randbelow(40) + 11
        b = secrets.randbelow(40) + 11
        product = str(a * b)
        php = f"{marker}:<?php echo {a}*{b}; ?>".encode()
        jsp = f"{marker}:<% out.print({a}*{b}); %>".encode()
        html = f"<!doctype html><script>/*{marker}*/</script>{marker}".encode()
        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg"><script>/*{marker}*/</script>'
            f"<text>{marker}</text></svg>"
        ).encode()
        return [
            UploadPayload("server-exec", f"{marker}.php", php, "application/octet-stream", product),
            UploadPayload(
                "server-exec", f"{marker}.phtml", php, "application/octet-stream", product
            ),
            UploadPayload("server-exec", f"{marker}.jsp", jsp, "application/octet-stream", product),
            UploadPayload("client-exec", f"{marker}.html", html, "text/html", ""),
            UploadPayload("client-exec", f"{marker}.svg", svg, "image/svg+xml", ""),
            UploadPayload("bypass", f"{marker}.php.jpg", php, "image/jpeg", product),
            UploadPayload("bypass", f"{marker}.pHtml", php, "image/jpeg", product),
            UploadPayload("bypass", f"{marker}.html%00.jpg", html, "image/jpeg", ""),
            UploadPayload("bypass", f"{marker}.html", html, "image/jpeg", ""),
            UploadPayload("traversal", f"../../{marker}-trav.html", html, "text/html", ""),
            UploadPayload("traversal", f"..%2f..%2f{marker}-trav.html", html, "text/html", ""),
        ]

    async def _probe_form(self, form: Form) -> list[UploadHit]:
        """
        Args:
            form (Form): An upload form.

        Returns:
            list[UploadHit]: The confirmed hits for this form, strongest kept
                when both a strong and the ``inert-accept`` outcome fire.
        """
        token = secrets.token_hex(6)
        field = next(f.name for f in form.fields if f.type == "file")
        data = {f.name: f.value for f in form.fields if f.type != "file" and f.name}

        baseline = await self._upload(
            form.action, field, f"wv{token}.txt", f"wv{token} marker".encode(), "text/plain", data
        )
        base_ok = baseline is not None and baseline.status_code < 400
        started = self._spent

        hits: list[UploadHit] = []
        outcomes: set[str] = set()
        for payload in self._payloads(token):
            if self._spent >= self._budget or self._spent - started >= _PER_FORM_CAP:
                break
            resp = await self._upload(
                form.action, field, payload.filename, payload.content, payload.part_type, data
            )
            if resp is None:
                continue
            if base_ok and resp.status_code >= 400:
                continue  # the endpoint rejected this type — not stored
            served, served_url = await self._retrieve(form.action, resp, token, payload)
            if served is None:
                continue
            hit = self._classify(form.action, field, token, payload, served, served_url)
            if hit is not None and hit.outcome not in outcomes:
                outcomes.add(hit.outcome)
                hits.append(hit)
        if outcomes - {"inert-accept"}:
            hits = [h for h in hits if h.outcome != "inert-accept"]
        return hits

    async def _retrieve(
        self, action: str, upload_response: Response, token: str, payload: UploadPayload
    ) -> tuple[Response | None, str]:
        """
        Args:
            action (str): The form action the file was uploaded to.
            upload_response (Response): The upload's response (its body / Location
                may link the stored file).
            token (str): The per-form token; the retrieved body must contain
                ``wv<token>``.
            payload (UploadPayload): The payload whose stored file to locate.

        Returns:
            tuple[Response | None, str]: The served response and the URL it came
                from, or ``(None, "")``.
        """
        marker = f"wv{token}"
        base_name = payload.filename.rsplit("/", 1)[-1].split("%00")[0].split("%2f")[-1]
        candidates: list[str] = []

        body = upload_response.text
        for token_pos in _iter_marker_urls(body, marker):
            candidates.append(urljoin(action, token_pos))
        location = upload_response.headers.get("location", "")
        if marker in location:
            candidates.append(urljoin(action, location))

        for prefix in _UPLOAD_PREFIXES:
            candidates.append(urljoin(action, prefix + base_name))
        candidates.append(action.rsplit("/", 1)[0] + "/" + base_name)

        if payload.family == "traversal":
            candidates.append(f"{self._target.origin}/{base_name}")
            for prefix in _UPLOAD_PREFIXES:
                candidates.append(urljoin(action, prefix + "../" + base_name))

        for url in _dedupe(candidates):
            served = await self._get(url)
            if served is not None and served.status_code < 400 and marker in served.text:
                return served, url
        return None, ""

    def _classify(
        self,
        action: str,
        field: str,
        token: str,
        payload: UploadPayload,
        served: Response,
        served_url: str,
    ) -> UploadHit | None:
        """
        Args:
            action (str): The upload endpoint.
            field (str): The file field name.
            token (str): The per-form token.
            payload (UploadPayload): The payload that was uploaded.
            served (Response): The served file's response.
            served_url (str): Where it was retrieved from.

        Returns:
            UploadHit | None: The strongest applicable outcome, or ``None``.
        """
        marker = f"wv{token}"
        body = served.text
        ctype = served.headers.get("content-type", "").lower()
        disposition = served.headers.get("content-disposition", "").lower()

        if (
            payload.product
            and payload.product in body
            and not any(s in body for s in _SOURCE_MARKERS)
        ):
            return self._hit(
                "server-exec",
                action,
                "POST",
                field,
                served_url,
                payload.filename,
                Severity.CRITICAL,
                Confidence.HIGH,
                f"Uploaded file executed server-side: {payload.filename} returned"
                f" {payload.product}",
                ("Executed output", _snippet(body, marker)),
            )
        # A traversal-named file that landed outside every upload directory is the
        # traversal finding even when it is also served inline — where it was written
        # is the stronger signal (an attacker controls the path, not just the type).
        if payload.family == "traversal" and not any(
            p in urlsplit(served_url).path for p in _UPLOAD_PREFIXES
        ):
            landed = urlsplit(served_url).path
            return self._hit(
                "traversal",
                action,
                "POST",
                field,
                served_url,
                payload.filename,
                Severity.HIGH,
                Confidence.HIGH,
                f"Upload filename traversal: {payload.filename} landed at {landed}",
                ("Retrieved from", served_url),
            )
        if any(t in ctype for t in _INLINE_TYPES) and "attachment" not in disposition:
            return self._hit(
                "inline-html",
                action,
                "POST",
                field,
                served_url,
                payload.filename,
                Severity.HIGH,
                Confidence.HIGH,
                f"Uploaded {payload.filename} is served inline as {ctype.split(';')[0]}",
                ("Served as", f"{ctype or '(no content-type)'} at {urlsplit(served_url).path}"),
            )
        if "attachment" in disposition or "octet-stream" in ctype:
            return self._hit(
                "inert-accept",
                action,
                "POST",
                field,
                served_url,
                payload.filename,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                f"Upload endpoint stores an arbitrary file type ({payload.filename})",
                ("Note", "stored and retrievable, but served as a download — no execution proved"),
            )
        return None

    async def _probe_put(self) -> list[UploadHit]:
        """
        Returns:
            list[UploadHit]: A ``put-upload`` hit per marker the target accepted
                via ``PUT`` and served back, or empty.
        """
        token = secrets.token_hex(6)
        marker = f"wv{token}"
        entry = self._target.entry_url
        directory = entry.rsplit("/", 1)[0] if urlsplit(entry).path.count("/") > 1 else entry
        base = directory.rstrip("/")

        hits: list[UploadHit] = []
        specs = (
            (f"{marker}.txt", f"{marker} put marker".encode(), False),
            (
                f"{marker}.html",
                f"<!doctype html><script>/*{marker}*/</script>{marker}".encode(),
                True,
            ),
        )
        for name, body, is_html in specs:
            put_url = f"{base}/{name}"
            put = await self._put(put_url, body)
            if put is None or put.status_code not in (200, 201, 204):
                if name.endswith(".txt"):
                    return hits  # PUT is not accepted at all
                continue
            got = await self._get(put_url)
            if got is None or marker not in got.text:
                continue
            inline = is_html and "text/html" in got.headers.get("content-type", "").lower()
            hits.append(
                self._hit(
                    "put-upload",
                    put_url,
                    "PUT",
                    None,
                    put_url,
                    name,
                    Severity.CRITICAL if inline else Severity.HIGH,
                    Confidence.HIGH,
                    f"WebDAV-style PUT upload accepted at {urlsplit(put_url).path}",
                    ("Retrieved", _snippet(got.text, marker)),
                )
            )
        return hits

    async def _upload(
        self,
        url: str,
        field: str,
        filename: str,
        content: bytes,
        part_type: str,
        data: dict[str, str],
    ) -> Response | None:
        """
        Args:
            url (str): The form action.
            field (str): The file field name.
            filename (str): The multipart part filename.
            content (bytes): The file body.
            part_type (str): The part's ``Content-Type``.
            data (dict[str, str]): The form's non-file fields at their defaults.

        Returns:
            Response | None: The upload response, or ``None`` on budget / error.
        """
        if self._spent >= self._budget:
            return None
        self._spent += 1
        try:
            return await self._http.request(
                "POST",
                url,
                data=data or None,
                files={field: (filename, content, part_type)},
                crafted=True,
            )
        except (RequestFailed, OutOfScopeError):
            return None

    async def _get(self, url: str) -> Response | None:
        """
        Args:
            url (str): A candidate retrieval URL.

        Returns:
            Response | None: The response, or ``None`` when out of scope, over
                budget, or failed.
        """
        if self._spent >= self._budget or not self._target.in_scope(url):
            return None
        self._spent += 1
        try:
            return await self._http.request("GET", url, crafted=True)
        except (RequestFailed, OutOfScopeError):
            return None

    async def _put(self, url: str, body: bytes) -> Response | None:
        """
        Args:
            url (str): The in-scope PUT target.
            body (bytes): A benign marker body.

        Returns:
            Response | None: The response, or ``None`` when out of scope, over
                budget, or failed.
        """
        if self._spent >= self._budget or not self._target.in_scope(url):
            return None
        self._spent += 1
        try:
            return await self._http.request("PUT", url, content=body, crafted=True)
        except (RequestFailed, OutOfScopeError):
            return None

    def _hit(
        self,
        outcome: str,
        url: str,
        method: str,
        field: str | None,
        retrieved_from: str,
        payload_name: str,
        severity: Severity,
        confidence: Confidence,
        title: str,
        proof: tuple[str, str],
    ) -> UploadHit:
        """Build an :class:`UploadHit` with the shared evidence shape."""
        return UploadHit(
            outcome=outcome,
            url=url,
            method=method,
            field=field,
            retrieved_from=retrieved_from,
            severity=severity,
            confidence=confidence,
            title=title,
            payload_name=payload_name,
            evidence=(
                ("Upload endpoint", f"{method} {url}"),
                ("Payload file", payload_name),
                ("Retrieved from", retrieved_from),
                proof,
            ),
        )


def _iter_marker_urls(body: str, marker: str) -> list[str]:
    """
    Args:
        body (str): A response body.
        marker (str): The ``wv<token>`` marker.

    Returns:
        list[str]: URL-shaped substrings of ``body`` that contain the marker.
    """
    out: list[str] = []
    for chunk in (
        body.replace('"', " ").replace("'", " ").replace("<", " ").replace(">", " ").split()
    ):
        if marker in chunk and ("/" in chunk or chunk.startswith("http")):
            out.append(chunk.strip("()[]"))
    return out


def _dedupe(items: list[str]) -> list[str]:
    """
    Args:
        items (list[str]): Candidate URLs, possibly with duplicates.

    Returns:
        list[str]: The list with duplicates removed, order preserved.
    """
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _snippet(body: str, marker: str) -> str:
    """
    Args:
        body (str): A response body.
        marker (str): The marker to centre on.

    Returns:
        str: A trimmed excerpt around the first marker occurrence.
    """
    idx = body.find(marker)
    if idx == -1:
        return body[:_SNIPPET_SPAN].strip()
    start = max(0, idx - _SNIPPET_SPAN // 2)
    end = min(len(body), idx + len(marker) + _SNIPPET_SPAN)
    return ("…" if start else "") + body[start:end].strip() + ("…" if end < len(body) else "")
