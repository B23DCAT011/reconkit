"""The plugin contract every scanner adapter implements.

Adding a new tool (subfinder, nuclei, ...) means writing one class that satisfies
this interface — the orchestrator never changes. A plugin takes a single target and
returns a list of :class:`~reconkit.schema.Service` objects; the orchestrator wraps
those into an :class:`~reconkit.schema.Asset`.

Splitting `parse` from `run` keeps the tool-specific parsing unit-testable without
actually invoking the external binary.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from reconkit.schema import Service


@runtime_checkable
class ScannerPlugin(Protocol):
    """A recon tool adapter."""

    name: str

    def is_available(self) -> bool:
        """True if the underlying binary is installed and runnable."""
        ...

    def scan(self, target: str) -> list[Service]:
        """Run the tool against `target` and return the services discovered."""
        ...
