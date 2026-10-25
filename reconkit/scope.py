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
"""

from __future__ import annotations

import ipaddress
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


def _contained(inner: Network, outer: Network) -> bool:
    """True if `inner` is a subnet of `outer` (same IP version only)."""
    if inner.version != outer.version:
        return False
    return inner.subnet_of(outer)  # type: ignore[arg-type]


@dataclass
class Scope:
    """An allowlist (with optional denylist) of hostnames and IP/CIDR targets."""

    allow_hosts: set[str] = field(default_factory=set)
    allow_nets: list[Network] = field(default_factory=list)
    deny_hosts: set[str] = field(default_factory=set)
    deny_nets: list[Network] = field(default_factory=list)

    def add(self, entry: str) -> None:
        """Add one allow (or deny, if prefixed with '!') entry."""
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            return
        deny = entry.startswith("!")
        if deny:
            entry = entry[1:].strip()
        net = _parse_net(entry)
        if net is not None:
            (self.deny_nets if deny else self.allow_nets).append(net)
        else:
            (self.deny_hosts if deny else self.allow_hosts).add(entry.lower())

    @classmethod
    def from_file(cls, path: str | Path) -> Scope:
        """Load a scope from an allowlist file (one entry per line)."""
        scope = cls()
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            scope.add(line)
        return scope

    @classmethod
    def from_entries(cls, entries: list[str]) -> Scope:
        """Build a scope from an in-memory list of entries (handy for tests)."""
        scope = cls()
        for entry in entries:
            scope.add(entry)
        return scope

    def is_allowed(self, target: str) -> bool:
        """True iff `target` is inside the allowlist and not in the denylist."""
        target = target.strip().lower()
        net = _parse_net(target)
        if net is not None:
            if any(_contained(net, d) for d in self.deny_nets):
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
