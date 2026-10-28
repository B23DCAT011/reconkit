"""Scope guard — the safety/legal gate every scan must pass through first.

ReconKit must only ever touch assets we own or are authorised to test. The scope is
an explicit **allowlist** of targets: exact hostnames, exact IPs, or CIDR ranges.
A target is permitted only if it matches an allow entry (and no deny entry). The
orchestrator refuses to scan anything that does not pass this gate.

The allowlist is loaded from a plain-text file, one entry per line:

    # lab targets
    scanme.lab
    10.0.0.0/24
    203.0.113.10
    !10.0.0.1          # deny takes precedence (leading '!')

`#` starts a comment anywhere on a line. Any entry that is not a valid IP, CIDR or
hostname is an error (with its line number) — never silently reinterpreted.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeError(Exception):
    """Raised when a target is outside the authorised scope."""


def _parse_net(entry: str) -> Network | None:
    """Parse an entry as an IP/CIDR network, or return None if it is a hostname."""
    try:
        # strict=False lets "10.0.0.0/24" and bare "203.0.113.10" both parse.
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


# One DNS label: letters, digits, '-' and '_' (no leading/trailing '-'), max 63 chars.
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")


def _is_hostname(entry: str) -> bool:
    """True if `entry` is a syntactically valid hostname (wildcards not supported).

    An all-numeric last label is rejected: no real TLD is numeric, so "10.0.0.300"
    is a mistyped IP, not a hostname.
    """
    labels = entry.lower().split(".")
    if len(entry) > 253 or labels[-1].isdigit():
        return False
    return all(_LABEL.fullmatch(label) for label in labels)


def _contained(inner: Network, outer: Network) -> bool:
    """True if `inner` is a subnet of `outer` (same IP version only)."""
    if inner.version != outer.version:
        return False
    return inner.subnet_of(outer)  # type: ignore[arg-type]


def _overlaps(a: Network, b: Network) -> bool:
    """True if `a` and `b` share at least one address (same IP version only)."""
    if a.version != b.version:
        return False
    return a.overlaps(b)


@dataclass
class Scope:
    """An allowlist (with optional denylist) of hostnames and IP/CIDR targets."""

    allow_hosts: set[str] = field(default_factory=set)
    allow_nets: list[Network] = field(default_factory=list)
    deny_hosts: set[str] = field(default_factory=set)
    deny_nets: list[Network] = field(default_factory=list)

    def add(self, entry: str) -> None:
        """Add one allow (or deny, if prefixed with '!') entry.

        Raises :class:`ScopeError` for anything that is neither a valid IP/CIDR nor a
        valid hostname. A safety config we cannot read must stop the scan, not be
        guessed at (fail closed).
        """
        raw = entry
        entry = entry.split("#", 1)[0].strip()  # drop comments, incl. trailing ones
        if not entry:
            return
        deny = entry.startswith("!")
        if deny:
            entry = entry[1:].strip()
        net = _parse_net(entry)
        if net is not None:
            (self.deny_nets if deny else self.allow_nets).append(net)
        elif _is_hostname(entry):
            (self.deny_hosts if deny else self.allow_hosts).add(entry.lower())
        else:
            raise ScopeError(f"invalid scope entry {raw.strip()!r}")

    @classmethod
    def from_file(cls, path: str | Path) -> Scope:
        """Load a scope from an allowlist file (one entry per line)."""
        scope = cls()
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        for lineno, line in enumerate(lines, start=1):
            try:
                scope.add(line)
            except ScopeError as exc:
                raise ScopeError(f"{path}:{lineno}: {exc}") from None
        return scope

    @classmethod
    def from_entries(cls, entries: list[str]) -> Scope:
        """Build a scope from an in-memory list of entries (handy for tests)."""
        scope = cls()
        for entry in entries:
            scope.add(entry)
        return scope

    def is_allowed(self, target: str) -> bool:
        """True iff `target` is inside the allowlist and touches nothing in the denylist.

        A range target is refused if *any* of its addresses is denied (fail closed):
        `10.0.0.0/24` with `!10.0.0.1` is refused as a whole. Excluding the denied
        hosts and scanning the rest is a later, deliberate step (TASKS.md F6).
        """
        target = target.strip().lower()
        net = _parse_net(target)
        if net is not None:
            if any(_overlaps(net, d) for d in self.deny_nets):
                return False
            return any(_contained(net, a) for a in self.allow_nets)
        # Hostname target.
        if target in self.deny_hosts:
            return False
        return target in self.allow_hosts

    def ensure_allowed(self, target: str) -> None:
        """Raise :class:`ScopeError` if `target` is not authorised."""
        if not self.is_allowed(target):
            raise ScopeError(
                f"Target {target!r} is outside the authorised scope. "
                f"Add it to the allowlist only if you are permitted to scan it."
            )
