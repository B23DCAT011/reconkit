"""Shared test fixtures/helpers."""

from __future__ import annotations

from reconkit.schema import Asset, Service


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

    def is_available(self) -> bool:
        return self._available

    def scan(self, target: str) -> list[Asset]:
        if self._error is not None:
            raise self._error
        # Hand out copies: the orchestrator merges into and adds findings to them.
        return [
            Asset(host=a.host, ip=a.ip, services=list(a.services), findings=list(a.findings))
            for a in self._assets
        ]
