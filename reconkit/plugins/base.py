"""The plugin contract every scanner adapter implements.

Adding a new tool (subfinder, nuclei, ...) means writing one class that satisfies
this interface — the orchestrator never changes. A plugin takes a single target and
returns a list of :class:`~reconkit.schema.Asset` objects, one per host; the
orchestrator merges the assets that several plugins report for the same host.

Splitting `parse` from `run` keeps the tool-specific parsing unit-testable without
actually invoking the external binary.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from reconkit.schema import Asset


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

    def scan(self, target: str) -> list[Asset]:
        """Run the tool against `target` and return one `Asset` per host found.

        A target may be a single host or a whole range, so the unit of a result is
        the host, never the target. Each asset carries what this tool learnt about
        that host: its address, its services, its findings.

        Raises :class:`ScanError` if the tool fails; never returns a partial or
        empty list to signal failure.
        """
        ...
