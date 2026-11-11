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


class ScanError(Exception):
    """A scanner plugin could not produce a trustworthy result.

    Plugins translate every tool-specific failure (binary missing, non-zero exit,
    timeout, unreadable output) into this one type at their boundary, so callers
    handle a single exception instead of knowing how each tool is invoked.

    `stderr` keeps what the tool itself printed, for the user to diagnose with.
    """

    def __init__(self, message: str, *, plugin: str, stderr: str | None = None) -> None:
        super().__init__(message)
        self.plugin = plugin
        self.stderr = stderr


@runtime_checkable
class ScannerPlugin(Protocol):
    """A recon tool adapter."""

    name: str

    def is_available(self) -> bool:
        """True if the underlying binary is installed and runnable."""
        ...

    def scan(self, target: str) -> list[Service]:
        """Run the tool against `target` and return the services discovered.

        Raises :class:`ScanError` if the tool fails; never returns a partial or
        empty list to signal failure.
        """
        ...
