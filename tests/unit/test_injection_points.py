"""Injection-point enumeration and the fuzz / skip heuristics — spec 006 RF-04, RF-06."""

from __future__ import annotations

from tests.support import make_page
from webvigil.checks.injection.points import enumerate_points, is_pathlike, is_redirect_name
from webvigil.crawler.forms import Form, FormField


def _form(*fields: FormField, method: str = "GET", action: str = "https://example.com/s") -> Form:
    return Form(method=method, action=action, enctype="", fields=tuple(fields), source_url=action)


def test_query_parameters_become_points() -> None:
    page = make_page(url="https://example.com/search?q=hi&lang=en")
    points, warnings = enumerate_points((page,), (), max_points=100)
    assert warnings == []
    assert {p.param for p in points} == {"q", "lang"}
    q = next(p for p in points if p.param == "q")
    assert q.method == "GET"
    assert q.base_url == "https://example.com/search"
    assert q.original == "hi"


def test_form_fields_become_points_respecting_the_type_filter() -> None:
    form = _form(
        FormField("q", "text", ""),
        FormField("csrf", "hidden", "tok"),
        FormField("agree", "checkbox", "yes"),
        FormField("body", "textarea", ""),
        method="POST",
    )
    points, _ = enumerate_points((), (form,), max_points=100)
    assert {p.param for p in points} == {"q", "body"}
    assert all(p.method == "POST" and p.source == "form" for p in points)
    # the hidden and checkbox fields still travel in every request
    assert dict(points[0].params)["csrf"] == "tok"


def test_authentication_and_destructive_forms_are_skipped() -> None:
    for action in ("https://example.com/login", "https://example.com/account/delete"):
        form = _form(FormField("x", "text", ""), action=action)
        assert enumerate_points((), (form,), max_points=100)[0] == []
    login_by_field = _form(FormField("password", "password", ""), FormField("user", "text", ""))
    assert enumerate_points((), (login_by_field,), max_points=100)[0] == []


def test_an_innocuous_form_is_not_skipped() -> None:
    form = _form(FormField("q", "text", ""), action="https://example.com/search")
    assert len(enumerate_points((), (form,), max_points=100)[0]) == 1


def test_the_same_parameter_on_many_urls_is_one_point() -> None:
    pages = (
        make_page(url="https://example.com/p?id=1"),
        make_page(url="https://example.com/p?id=2&x=9"),
    )
    points, _ = enumerate_points(pages, (), max_points=100)
    assert sorted(p.param for p in points) == ["id", "x"]


def test_max_points_truncates_and_warns() -> None:
    page = make_page(url="https://example.com/p?" + "&".join(f"a{i}=1" for i in range(10)))
    points, warnings = enumerate_points((page,), (), max_points=4)
    assert len(points) == 4
    assert warnings and "first 4 of 10" in warnings[0]


def test_priority_helpers() -> None:
    pages = (make_page(url="https://example.com/x?next=/a&file=b&q=c&p=/etc/x"),)
    points = {p.param: p for p in enumerate_points(pages, (), max_points=100)[0]}
    assert is_redirect_name(points["next"]) and not is_redirect_name(points["q"])
    assert is_pathlike(points["file"])  # by name
    assert is_pathlike(points["p"])  # by value shape
    assert not is_pathlike(points["q"])
