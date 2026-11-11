"""Shared test fixtures/helpers."""

from __future__ import annotations

from reconkit.schema import Asset, ScanTarget, Service
from reconkit.scope import ResolutionError, Resolver, Scope

# The lab every test scans: one name, living at 10.0.0.5 inside an allowed /24.
LAB_DNS = {"scanme.lab": ["10.0.0.5"]}


def lab_scope(*extra: str) -> Scope:
    """A scope that authorises the lab name *and* the range it lives in."""
    return Scope.from_entries(["scanme.lab", "10.0.0.0/24", *extra])


def fake_resolver(records: dict[str, list[str]]) -> Resolver:
    """A resolver answering from a dict instead of real DNS."""

    def resolve(hostname: str) -> list[str]:
        if hostname not in records:
            raise ResolutionError(f"cannot resolve {hostname!r}: no such host (test)")
        return list(records[hostname])

    return resolve


lab_resolver = fake_resolver(LAB_DNS)


def lab_asset(*services: Service, host: str = "scanme.lab", ip: str = "10.0.0.5") -> Asset:
    """One scanned host, as a plugin would report it."""
    return Asset(host=host, ip=ip, services=list(services))


class FakePlugin:
    """A ScannerPlugin stub returning canned assets (no binary needed)."""

    name = "fake"

    def __init__(
        self,
        assets: list[Asset],
        available: bool = True,
        error: Exception | None = None,
    ) -> None:
        self._assets = assets
        self._available = available
        self._error = error  # raised by scan() to simulate a failing tool
        self.seen: list[ScanTarget] = []  # every target this plugin was asked to scan

    def is_available(self) -> bool:
        return self._available

    def scan(self, target: ScanTarget) -> list[Asset]:
        self.seen.append(target)
        if self._error is not None:
            raise self._error
        # Hand out copies: the orchestrator merges into and adds findings to them.
        return [
            Asset(host=a.host, ip=a.ip, services=list(a.services), findings=list(a.findings))
            for a in self._assets
        ]
