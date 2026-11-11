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

A hostname entry authorises the *name* only. Before a scan the name is resolved and
every address it points at must itself be in the allowlist (see `Scope.plan`), so a
scope that lists `scanme.lab` must also list the address or range it lives in.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from reconkit.schema import ScanTarget

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeError(Exception):
    """Raised when a target is outside the authorised scope."""


class ResolutionError(Exception):
    """Raised when a hostname cannot be resolved, so there is nothing to check or scan."""


# A resolver maps a hostname to its IPv4 addresses. Injectable so tests need no DNS.
Resolver = Callable[[str], list[str]]


def resolve_ipv4(hostname: str) -> list[str]:
    """Resolve `hostname` to all of its IPv4 addresses using the system resolver.

    IPv6 (AAAA) records are not looked up: scans run against the IPv4 addresses
    returned here only, so an IPv6 address is never touched (KNOWN-GAPS G22).
    """
    try:
        infos = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
    except socket.gaierror as exc:
        raise ResolutionError(f"cannot resolve {hostname!r}: {exc.strerror or exc}") from exc
    return [str(info[4][0]) for info in infos]


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

    def plan(self, target: str, resolver: Resolver | None = None) -> ScanTarget:
        """Turn a requested target into the exact addresses that may be scanned.

        This is the gate every scan goes through. It raises :class:`ScopeError` if
        the target is not authorised, or :class:`ResolutionError` if a name cannot
        be resolved.

        * IP / CIDR: must lie inside the allowlist. Denied addresses inside it are
          returned in `exclude`; a target that is denied entirely is refused.
        * Hostname: the name must be allowlisted, and so must **every** IPv4 address
          it resolves to. An allowlisted name is not proof that the machine behind
          it is ours (it may point at a CDN, or have been repointed). The name is
          resolved here, once, and the scan uses these addresses, so it cannot
          change between the check and the scan.
        """
        target = target.strip()
        net = _parse_net(target)
        if net is not None:
            return self._plan_network(target, net)
        return self._plan_hostname(target, resolver or resolve_ipv4)

    def _plan_network(self, target: str, net: Network) -> ScanTarget:
        if not any(_contained(net, a) for a in self.allow_nets):
            raise ScopeError(_outside(target))
        # Two CIDR blocks overlap only if one contains the other, so each denied
        # block is either all of the target or a part of it.
        denied = [d for d in self.deny_nets if _overlaps(net, d)]
        parts: list[Network] = [d for d in denied if _contained(d, net)]
        # Merge adjacent/nested parts, so their sizes can be added up.
        exclude: list[Network] = list(ipaddress.collapse_addresses(parts))  # type: ignore[type-var]
        covered_by_one = any(_contained(net, d) for d in denied)
        covered_in_parts = sum(d.num_addresses for d in exclude) >= net.num_addresses
        if covered_by_one or covered_in_parts:
            raise ScopeError(f"Target {target!r} is entirely covered by the denylist.")
        return ScanTarget(
            requested=target,
            addresses=(_net_str(net),),
            exclude=tuple(_net_str(d) for d in exclude),
        )

    def _plan_hostname(self, target: str, resolver: Resolver) -> ScanTarget:
        name = target.lower()
        if name in self.deny_hosts or name not in self.allow_hosts:
            raise ScopeError(_outside(target))
        addresses = tuple(dict.fromkeys(resolver(name)))  # de-duplicated, order kept
        if not addresses:
            raise ResolutionError(f"{target!r} did not resolve to any IPv4 address")
        for address in addresses:
            if not self.is_allowed(address):
                raise ScopeError(
                    f"Target {target!r} resolves to {address}, which is outside the "
                    f"authorised scope. A name in the allowlist does not authorise the "
                    f"address behind it: add the address only if you may scan it."
                )
        return ScanTarget(requested=target, addresses=addresses, hostname=name)

    def is_allowed(self, target: str) -> bool:
        """True iff `target` is wholly inside the allowlist and touches no deny entry.

        A pure check on the text of `target`: no DNS. For an address it is the full
        answer (the orchestrator uses it to re-check every host a scan returns). For
        a hostname it only says the *name* is allowlisted; :meth:`plan` is what
        decides whether a name may be scanned.

        A range is "allowed" here only if none of its addresses is denied:
        `10.0.0.0/24` with `!10.0.0.1` is False, although :meth:`plan` can still
        scan it with the denied address excluded.
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


def _outside(target: str) -> str:
    return (
        f"Target {target!r} is outside the authorised scope. "
        f"Add it to the allowlist only if you are permitted to scan it."
    )


def _net_str(net: Network) -> str:
    """A network the way nmap expects it: a bare IP for one address, else CIDR."""
    return str(net.network_address) if net.num_addresses == 1 else str(net)
