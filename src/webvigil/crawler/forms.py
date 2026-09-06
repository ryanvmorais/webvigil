"""Form discovery for the active-injection pass (spec 006, RF-05, ADR-3).

Parses ``<form>`` elements out of the page bodies the crawler already fetched — it issues
**no** requests of its own. The crawler stays focused on ``<a href>`` discovery; the
orchestrator calls :func:`extract_forms` right after the crawl and hands the result to the
injection engine. Deciding which forms to fuzz (the authentication / destruction heuristic)
is the injection package's job, not this module's.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

from selectolax.parser import HTMLParser, Node

from webvigil.core.context import Page
from webvigil.core.target import Target, normalize_url

_DEFAULT_ENCTYPE = "application/x-www-form-urlencoded"


@dataclass(frozen=True, slots=True)
class FormField:
    """One named control of a form and its current value."""

    name: str
    type: str  # lower-cased <input type>, or "textarea" / "select"
    value: str


@dataclass(frozen=True, slots=True)
class Form:
    """A ``<form>`` found on a crawled page, with its submission target resolved."""

    method: str  # "GET" | "POST"
    action: str  # absolute, normalized; the page URL when the form has no action
    enctype: str
    fields: tuple[FormField, ...]
    source_url: str


def extract_forms(pages: tuple[Page, ...], target: Target) -> tuple[Form, ...]:
    """Every in-scope ``<form>`` on the crawled HTML pages, de-duplicated."""
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    forms: list[Form] = []
    for page in pages:
        if not (page.ok and page.is_html and page.text):
            continue
        for node in HTMLParser(page.text).css("form"):
            form = _form_from_node(node, page.url)
            if form is None or not target.in_scope(form.action):
                continue
            key = (form.method, form.action, tuple(f.name for f in form.fields))
            if key in seen:
                continue
            seen.add(key)
            forms.append(form)
    return tuple(forms)


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
        fields.append(FormField(name=name, type=_field_type(child), value=_field_value(child)))
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
