"""Tests for the scope guard (allowlist / denylist)."""

import pytest

from reconkit.scope import Scope, ScopeError


def test_exact_host_allowed() -> None:
    scope = Scope.from_entries(["scanme.lab"])
    assert scope.is_allowed("scanme.lab")
    assert scope.is_allowed("SCANME.LAB")  # case-insensitive
    assert not scope.is_allowed("evil.example.com")


def test_ip_in_cidr_allowed() -> None:
    scope = Scope.from_entries(["10.0.0.0/24"])
    assert scope.is_allowed("10.0.0.5")
    assert scope.is_allowed("10.0.0.0/28")  # sub-range of the allowed net
    assert not scope.is_allowed("10.0.1.5")


def test_deny_takes_precedence() -> None:
    scope = Scope.from_entries(["10.0.0.0/24", "!10.0.0.1"])
    assert scope.is_allowed("10.0.0.2")
    assert not scope.is_allowed("10.0.0.1")


def test_comments_and_blank_lines_ignored() -> None:
    scope = Scope.from_entries(["# a comment", "", "   ", "host.lab"])
    assert scope.allow_hosts == {"host.lab"}


def test_empty_scope_denies_everything() -> None:
    scope = Scope()
    assert not scope.is_allowed("anything.lab")
    assert not scope.is_allowed("10.0.0.1")


def test_ensure_allowed_raises_for_out_of_scope() -> None:
    scope = Scope.from_entries(["scanme.lab"])
    scope.ensure_allowed("scanme.lab")  # no raise
    with pytest.raises(ScopeError):
        scope.ensure_allowed("out.example.com")


def test_from_file(tmp_path: object) -> None:
    import pathlib

    p = pathlib.Path(str(tmp_path)) / "scope.txt"
    p.write_text("scanme.lab\n10.0.0.0/24\n!10.0.0.1\n", encoding="utf-8")
    scope = Scope.from_file(p)
    assert scope.is_allowed("scanme.lab")
    assert scope.is_allowed("10.0.0.9")
    assert not scope.is_allowed("10.0.0.1")
