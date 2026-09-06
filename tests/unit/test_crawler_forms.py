"""Form discovery from crawled page bodies — spec 006 RF-05, ADR-3."""

from __future__ import annotations

from tests.support import make_page
from webvigil.core.target import Target
from webvigil.crawler.forms import extract_forms

_TARGET = Target.parse("https://example.com/")


def _forms(html: str, *, url: str = "https://example.com/page"):
    return extract_forms((make_page(url=url, text=html),), _TARGET)


def test_relative_action_is_resolved_against_the_page() -> None:
    (form,) = _forms('<form action="search" method="get"><input name="q"></form>')
    assert form.action == "https://example.com/search"
    assert form.method == "GET"


def test_empty_action_falls_back_to_the_page_url() -> None:
    (form,) = _forms('<form method="post"><input name="q"></form>')
    assert form.action == "https://example.com/page"
    assert form.method == "POST"


def test_method_is_normalised_and_defaults_to_get() -> None:
    (form,) = _forms('<form method="DELETE"><input name="q"></form>')
    assert form.method == "GET"


def test_out_of_scope_action_is_dropped() -> None:
    assert _forms('<form action="https://evil.test/x"><input name="q"></form>') == ()


def test_fields_from_input_textarea_and_select() -> None:
    (form,) = _forms(
        "<form>"
        '<input name="q" value="hi">'
        '<input type="hidden" name="csrf" value="tok">'
        '<textarea name="body">draft</textarea>'
        '<select name="cat">'
        '<option value="a">A</option><option value="b" selected>B</option>'
        "</select>"
        '<input type="submit" value="go">'
        "</form>"
    )
    by_name = {f.name: f for f in form.fields}
    assert by_name["q"].type == "text" and by_name["q"].value == "hi"
    assert by_name["csrf"].type == "hidden" and by_name["csrf"].value == "tok"
    assert by_name["body"].type == "textarea" and by_name["body"].value == "draft"
    assert by_name["cat"].type == "select" and by_name["cat"].value == "b"
    assert "" not in by_name  # the unnamed submit button is skipped


def test_identical_forms_across_pages_are_deduplicated() -> None:
    html = '<form action="/s" method="get"><input name="q"></form>'
    forms = extract_forms(
        (
            make_page(url="https://example.com/a", text=html),
            make_page(url="https://example.com/b", text=html),
        ),
        _TARGET,
    )
    assert len(forms) == 1


def test_a_form_with_no_named_field_is_ignored() -> None:
    assert _forms("<form><input type=submit value=go></form>") == ()


def test_a_page_with_no_form_yields_nothing() -> None:
    assert _forms("<html><body><p>hello</p></body></html>") == ()
