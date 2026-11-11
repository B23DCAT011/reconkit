"""Tests for the scope guard (allowlist / denylist)."""

import socket
from pathlib import Path

import pytest

from reconkit.schema import ScanTarget
from reconkit.scope import ResolutionError, Resolver, Scope, ScopeError, resolve_ipv4


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


# --- plan(): from a requested target to the exact addresses to scan (G4) ---------


def _dns(records: dict[str, list[str]]) -> Resolver:
    return lambda hostname: list(records[hostname])


def test_plan_for_an_address_in_scope() -> None:
    plan = Scope.from_entries(["10.0.0.0/24"]).plan("10.0.0.5")
    assert plan == ScanTarget(requested="10.0.0.5", addresses=("10.0.0.5",))


def test_plan_refuses_an_address_outside_the_allowlist() -> None:
    with pytest.raises(ScopeError, match="outside the authorised scope"):
        Scope.from_entries(["10.0.0.0/24"]).plan("10.0.1.5")


def test_plan_resolves_a_name_and_returns_its_addresses() -> None:
    scope = Scope.from_entries(["scanme.lab", "10.0.0.0/24"])
    plan = scope.plan("ScanMe.Lab", _dns({"scanme.lab": ["10.0.0.5", "10.0.0.6", "10.0.0.5"]}))
    assert plan.addresses == ("10.0.0.5", "10.0.0.6")  # every address, de-duplicated
    assert plan.hostname == "scanme.lab"
    assert plan.requested == "ScanMe.Lab"


def test_plan_refuses_a_name_that_is_not_allowlisted_without_resolving_it() -> None:
    def must_not_be_called(hostname: str) -> list[str]:
        raise AssertionError(f"resolved {hostname}, which is out of scope")

    scope = Scope.from_entries(["scanme.lab", "10.0.0.0/24"])
    with pytest.raises(ScopeError):
        scope.plan("evil.example.com", must_not_be_called)


def test_plan_refuses_a_name_whose_address_is_not_allowlisted() -> None:
    # The classic gap: the name is ours on paper, the machine is someone else's.
    scope = Scope.from_entries(["scanme.lab", "10.0.0.0/24"])
    with pytest.raises(ScopeError, match=r"resolves to 203\.0\.113\.9"):
        scope.plan("scanme.lab", _dns({"scanme.lab": ["203.0.113.9"]}))


def test_plan_refuses_a_name_when_only_one_of_its_addresses_is_outside() -> None:
    scope = Scope.from_entries(["scanme.lab", "10.0.0.0/24"])
    with pytest.raises(ScopeError, match=r"resolves to 203\.0\.113\.9"):
        scope.plan("scanme.lab", _dns({"scanme.lab": ["10.0.0.5", "203.0.113.9"]}))


def test_plan_refuses_a_name_that_resolves_to_a_denied_address() -> None:
    scope = Scope.from_entries(["scanme.lab", "10.0.0.0/24", "!10.0.0.1"])
    with pytest.raises(ScopeError, match=r"resolves to 10\.0\.0\.1"):
        scope.plan("scanme.lab", _dns({"scanme.lab": ["10.0.0.1"]}))


def test_plan_refuses_a_name_with_only_the_name_in_the_scope() -> None:
    # A name entry alone authorises nothing: its address must be listed too.
    with pytest.raises(ScopeError, match=r"resolves to 10\.0\.0\.5"):
        Scope.from_entries(["scanme.lab"]).plan("scanme.lab", _dns({"scanme.lab": ["10.0.0.5"]}))


def test_plan_reports_a_name_with_no_address() -> None:
    scope = Scope.from_entries(["scanme.lab", "10.0.0.0/24"])
    with pytest.raises(ResolutionError):
        scope.plan("scanme.lab", _dns({"scanme.lab": []}))


def test_plan_excludes_denied_addresses_inside_a_range() -> None:
    scope = Scope.from_entries(["10.0.0.0/16", "!10.0.0.1", "!10.0.0.64/26", "!10.0.9.9"])
    plan = scope.plan("10.0.0.0/24")
    assert plan.addresses == ("10.0.0.0/24",)
    assert plan.exclude == ("10.0.0.1", "10.0.0.64/26")  # 10.0.9.9 is not in the target


def test_plan_normalises_a_range_given_with_host_bits() -> None:
    plan = Scope.from_entries(["10.0.0.0/24"]).plan("10.0.0.77/24")
    assert plan.addresses == ("10.0.0.0/24",)


def test_plan_refuses_a_target_that_is_entirely_denied() -> None:
    scope = Scope.from_entries(["10.0.0.0/16", "!10.0.5.0/24"])
    for target in ("10.0.5.3", "10.0.5.0/28", "10.0.5.0/24"):
        with pytest.raises(ScopeError, match="entirely covered by the denylist"):
            scope.plan(target)


def test_plan_refuses_a_range_denied_piece_by_piece() -> None:
    scope = Scope.from_entries(["10.0.0.0/24", "!10.0.0.0/25", "!10.0.0.128/25"])
    with pytest.raises(ScopeError, match="entirely covered by the denylist"):
        scope.plan("10.0.0.0/24")


def test_resolve_ipv4_turns_a_lookup_failure_into_resolution_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise socket.gaierror(11001, "getaddrinfo failed")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(ResolutionError, match="cannot resolve 'nope.invalid'"):
        resolve_ipv4("nope.invalid")


def test_resolve_ipv4_returns_the_addresses_of_the_system_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def lookup(host: str, port: object, family: int = 0) -> list[tuple[object, ...]]:
        assert family == socket.AF_INET  # IPv4 only
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("10.0.0.5", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.6", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    assert resolve_ipv4("scanme.lab") == ["10.0.0.5", "10.0.0.5", "10.0.0.6"]


def test_from_file(tmp_path: object) -> None:
    import pathlib

    p = pathlib.Path(str(tmp_path)) / "scope.txt"
    p.write_text("scanme.lab\n10.0.0.0/24\n!10.0.0.1\n", encoding="utf-8")
    scope = Scope.from_file(p)
    assert scope.is_allowed("scanme.lab")
    assert scope.is_allowed("10.0.0.9")
    assert not scope.is_allowed("10.0.0.1")
