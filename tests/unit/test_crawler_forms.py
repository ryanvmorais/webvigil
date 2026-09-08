"""
Form discovery from crawled page bodies — spec 006 RF-05, ADR-3; spec 007 RF-05.
"""

from __future__ import annotations

from tests.support import make_page
from webvigil.core.target import Target
from webvigil.crawler.forms import extract_forms, parse_forms, submission_url

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


# --- spec 007: parse_forms, checkbox/radio state, submission_url ---


def test_parse_forms_handles_one_page_without_dedup() -> None:
    html = '<form action="/s" method="get"><input name="q"></form>' * 2
    assert len(parse_forms(make_page(url="https://example.com/p", text=html), _TARGET)) == 2


def test_checkbox_checked_state_is_captured() -> None:
    (form,) = _forms(
        "<form>"
        '<input type="checkbox" name="on" value="1" checked>'
        '<input type="checkbox" name="off" value="1">'
        "</form>"
    )
    by_name = {f.name: f for f in form.fields}
    assert by_name["on"].checked is True
    assert by_name["off"].checked is False


def test_submission_url_builds_a_get_query_from_default_values() -> None:
    (form,) = _forms(
        '<form action="/search" method="get">'
        '<input name="q" value="shoes">'
        '<input type="hidden" name="page" value="1">'
        '<select name="sort"><option value="new" selected>New</option></select>'
        '<input type="checkbox" name="sale" value="yes" checked>'
        '<input type="checkbox" name="used" value="yes">'
        '<input type="submit" value="Go">'
        '<input type="password" name="pw">'
        "</form>"
    )
    url = submission_url(form)
    assert url is not None and url.startswith("https://example.com/search?")
    # deterministic (selectolax groups by tag), value-carrying fields only: no submit, no
    # password, no unchecked checkbox.
    assert sorted(url.split("?", 1)[1].split("&")) == ["page=1", "q=shoes", "sale=yes", "sort=new"]


def test_submission_url_replaces_an_existing_query_on_the_action() -> None:
    (form,) = _forms('<form action="/s?old=1" method="get"><input name="q" value="x"></form>')
    assert submission_url(form) == "https://example.com/s?q=x"


def test_submission_url_is_none_for_a_post_form() -> None:
    (form,) = _forms('<form action="/s" method="post"><input name="q"></form>')
    assert submission_url(form) is None
