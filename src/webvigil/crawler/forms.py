"""Form discovery (spec 006 RF-05; spec 007 RF-05).

Parses ``<form>`` elements out of the page bodies the crawler already fetched — it issues
**no** requests of its own. :func:`parse_forms` handles one page; the crawler calls it per
page during ``discover()`` (spec 007 ADR-2) both to build the ``<form>`` inventory and to
submit safe ``GET`` forms. :func:`extract_forms` is the deduped whole-crawl wrapper, kept
for tests and any external caller.

Deciding which forms to fuzz or skip (the authentication / destruction heuristics) is
:mod:`webvigil.crawler.safety` and the injection package's job, not this module's.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from selectolax.parser import HTMLParser, Node

from webvigil.core.context import Page
from webvigil.core.target import Target, normalize_url

_DEFAULT_ENCTYPE = "application/x-www-form-urlencoded"

# <input type>s (and pseudo-types) whose current value the crawler submits with a GET form.
_SUBMIT_VALUE_TYPES = frozenset(
    {"", "text", "search", "email", "url", "tel", "number", "hidden", "date", "textarea", "select"}
)


@dataclass(frozen=True, slots=True)
class FormField:
    """One named control of a form and its current value."""

    name: str
    type: str  # lower-cased <input type>, or "textarea" / "select"
    value: str
    checked: bool = False  # <input type=checkbox|radio checked>


@dataclass(frozen=True, slots=True)
class Form:
    """A ``<form>`` found on a crawled page, with its submission target resolved."""

    method: str  # "GET" | "POST"
    action: str  # absolute, normalized; the page URL when the form has no action
    enctype: str
    fields: tuple[FormField, ...]
    source_url: str


def parse_forms(page: Page, target: Target) -> list[Form]:
    """Every in-scope ``<form>`` on **one** crawled HTML page (no cross-page de-dup)."""
    if not (page.ok and page.is_html and page.text):
        return []
    forms: list[Form] = []
    for node in HTMLParser(page.text).css("form"):
        form = _form_from_node(node, page.url)
        if form is not None and target.in_scope(form.action):
            forms.append(form)
    return forms


def extract_forms(pages: tuple[Page, ...], target: Target) -> tuple[Form, ...]:
    """Every in-scope ``<form>`` across the crawled HTML pages, de-duplicated."""
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    forms: list[Form] = []
    for page in pages:
        for form in parse_forms(page, target):
            key = (form.method, form.action, tuple(f.name for f in form.fields))
            if key not in seen:
                seen.add(key)
                forms.append(form)
    return tuple(forms)


def submission_url(form: Form) -> str | None:
    """The ``GET`` URL ``form`` submits to with its default values, or ``None`` when it is
    not a form the crawler should submit (any non-``GET`` method).

    The form's default field values replace whatever query the action already carries;
    fields are taken in a stable parser order so the URL is deterministic (RNF-04).
    """
    if form.method != "GET":
        return None
    pairs = [
        (field.name, field.value)
        for field in form.fields
        if field.type in _SUBMIT_VALUE_TYPES
        or (field.type in ("checkbox", "radio") and field.checked)
    ]
    split = urlsplit(form.action)
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs), ""))


def _form_from_node(node: Node, page_url: str) -> Form | None:
    attrs = node.attributes
    raw_action = (attrs.get("action") or "").strip()
    action = normalize_url(urljoin(page_url, raw_action or page_url))
    method = "POST" if (attrs.get("method") or "").strip().upper() == "POST" else "GET"
    enctype = (attrs.get("enctype") or "").strip().lower() or _DEFAULT_ENCTYPE

    fields: list[FormField] = []
    for child in node.css("input, textarea, select"):
        name = (child.attributes.get("name") or "").strip()
        if not name:
            continue
        fields.append(
            FormField(
                name=name,
                type=_field_type(child),
                value=_field_value(child),
                checked="checked" in child.attributes,
            )
        )
    if not fields:
        return None
    return Form(
        method=method,
        action=action,
        enctype=enctype,
        fields=tuple(fields),
        source_url=page_url,
    )


def _field_type(node: Node) -> str:
    tag = node.tag or ""
    if tag in ("textarea", "select"):
        return tag
    return (node.attributes.get("type") or "text").strip().lower()


def _field_value(node: Node) -> str:
    tag = node.tag or ""
    if tag == "textarea":
        return node.text(deep=True) or ""
    if tag == "select":
        options = node.css("option")
        selected = [o for o in options if "selected" in o.attributes]
        chosen = selected[0] if selected else (options[0] if options else None)
        if chosen is None:
            return ""
        return (chosen.attributes.get("value") or chosen.text(deep=True) or "").strip()
    return (node.attributes.get("value") or "").strip()
