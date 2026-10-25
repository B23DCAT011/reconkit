"""Shared test fixtures/helpers."""

from __future__ import annotations

from reconkit.schema import Service


class FakePlugin:
    """A ScannerPlugin stub returning canned services (no binary needed)."""

    name = "fake"

    def __init__(self, services: list[Service], available: bool = True) -> None:
        self._services = services
        self._available = available

    def is_available(self) -> bool:
        return self._available

    def scan(self, target: str) -> list[Service]:
        return list(self._services)
