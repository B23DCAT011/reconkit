"""Orchestrator — drives a scan through the pipeline, tool-agnostic.

It knows the *order of stages*, not the details of any tool:

    scope gate  ->  run each available plugin  ->  collect services  ->  CVE stage

A scan that could not run is an error, never an empty result: a run with zero
services must mean "we looked and found nothing", not "we did not look".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from reconkit.cve import CveSource
from reconkit.plugins.base import ScannerPlugin
from reconkit.schema import Asset
from reconkit.scope import Scope


class NoPluginAvailableError(Exception):
    """None of the configured scanner plugins can run on this machine."""

    def __init__(self, plugins: list[str]) -> None:
        self.plugins = plugins
        if plugins:
            names = ", ".join(plugins)
            message = f"no scanner available: {names} not installed or not on PATH"
        else:
            message = "no scanner configured"
        super().__init__(message)


@dataclass
class ScanRun:
    """The result of one scan of one target."""

    target: str
    started_at: str
    finished_at: str
    assets: list[Asset] = field(default_factory=list)
    # Plugins that were configured but could not run; the result is partial.
    skipped_plugins: list[str] = field(default_factory=list)


class Orchestrator:
    """Runs the recon pipeline for a single target."""

    def __init__(
        self,
        plugins: list[ScannerPlugin],
        scope: Scope,
        cve_source: CveSource | None = None,
    ) -> None:
        self.plugins = plugins
        self.scope = scope
        self.cve_source = cve_source

    def run(self, target: str) -> ScanRun:
        # 1. Safety gate: refuse anything outside the authorised scope.
        self.scope.ensure_allowed(target)

        # 2. Fail loudly if nothing can scan: saving an empty run would look "clean".
        runnable = [p for p in self.plugins if p.is_available()]
        skipped = [p.name for p in self.plugins if p not in runnable]
        if not runnable:
            raise NoPluginAvailableError(skipped)

        started = datetime.now(UTC).isoformat()

        # 3. Run every available plugin and merge the services onto one asset.
        asset = Asset(host=target)
        for plugin in runnable:
            asset.services.extend(plugin.scan(target))

        # 4. CVE stage: match each service against known vulnerabilities.
        if self.cve_source is not None:
            for service in asset.services:
                asset.findings.extend(self.cve_source.find(service, asset.host))

        finished = datetime.now(UTC).isoformat()
        return ScanRun(
            target=target,
            started_at=started,
            finished_at=finished,
            assets=[asset],
            skipped_plugins=skipped,
        )
