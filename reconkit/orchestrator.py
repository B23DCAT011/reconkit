"""Orchestrator — drives a scan through the pipeline, tool-agnostic.

It knows the *order of stages*, not the details of any tool:

    scope gate  ->  run each available plugin  ->  collect services into an Asset

Findings (CVE matches etc.) are produced by a later stage and are left empty here;
the `Asset.findings` list is the extension point for that work (see TASKS.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from reconkit.cve import CveSource
from reconkit.plugins.base import ScannerPlugin
from reconkit.schema import Asset
from reconkit.scope import Scope


@dataclass
class ScanRun:
    """The result of one scan of one target."""

    target: str
    started_at: str
    finished_at: str
    assets: list[Asset] = field(default_factory=list)


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

        started = datetime.now(UTC).isoformat()

        # 2. Run every available plugin and merge the services onto one asset.
        asset = Asset(host=target)
        for plugin in self.plugins:
            if not plugin.is_available():
                continue
            asset.services.extend(plugin.scan(target))

        # 3. CVE stage: match each service against known vulnerabilities.
        if self.cve_source is not None:
            for service in asset.services:
                asset.findings.extend(self.cve_source.find(service, asset.host))

        finished = datetime.now(UTC).isoformat()
        return ScanRun(target=target, started_at=started, finished_at=finished, assets=[asset])
