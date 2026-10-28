"""Tests for the scope guard (allowlist / denylist)."""

from pathlib import Path

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


def test_range_containing_denied_host_is_refused() -> None:
    """Regression (G4): scanning a range must not sneak past a denied host inside it."""
    scope = Scope.from_entries(["10.0.0.0/24", "!10.0.0.1"])
    assert not scope.is_allowed("10.0.0.0/24")  # whole range contains 10.0.0.1
    assert not scope.is_allowed("10.0.0.0/30")  # small range containing it
    assert scope.is_allowed("10.0.0.128/25")  # range clear of the denied host


def test_denied_range_blocks_any_overlapping_target() -> None:
    scope = Scope.from_entries(["10.0.0.0/16", "!10.0.5.0/28"])
    assert not scope.is_allowed("10.0.0.0/16")  # target contains the denied range
    assert not scope.is_allowed("10.0.5.0/24")  # target contains the denied range
    assert not scope.is_allowed("10.0.5.3")  # target inside the denied range
    assert scope.is_allowed("10.0.6.0/24")  # no overlap


def test_deny_of_other_ip_version_does_not_interfere() -> None:
    scope = Scope.from_entries(["10.0.0.0/24", "!fd00::/8"])
    assert scope.is_allowed("10.0.0.0/24")


def test_comments_and_blank_lines_ignored() -> None:
    scope = Scope.from_entries(["# a comment", "", "   ", "host.lab"])
    assert scope.allow_hosts == {"host.lab"}


def test_inline_comment_does_not_disable_entry() -> None:
    """Regression (G4): '!10.0.0.1  # router' used to become a bogus hostname."""
    scope = Scope.from_entries(["10.0.0.0/24", "!10.0.0.1          # router", "host.lab # lab"])
    assert not scope.is_allowed("10.0.0.1")
    assert scope.is_allowed("host.lab")


@pytest.mark.parametrize(
    "entry",
    [
        "has space.lab",  # whitespace inside an entry
        "10.0.0.300",  # looks like an IP but is not one
        "10.0.0.0/33",  # invalid prefix length
        "bad!host.lab",  # illegal character
        "*.example.com",  # wildcards are not supported (yet) — must not silently never match
        "!",  # deny marker with nothing after it
    ],
)
def test_invalid_entry_is_rejected(entry: str) -> None:
    with pytest.raises(ScopeError):
        Scope.from_entries([entry])


def test_from_file_reports_line_number(tmp_path: Path) -> None:
    p = tmp_path / "scope.txt"
    p.write_text("scanme.lab\n# ok\n10.0.0.300\n", encoding="utf-8")
    with pytest.raises(ScopeError, match=r"scope\.txt:3"):
        Scope.from_file(p)


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
