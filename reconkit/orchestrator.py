"""Orchestrator — drives a scan through the pipeline, tool-agnostic.

It knows the *order of stages*, not the details of any tool:

    scope gate  ->  run each available plugin  ->  merge assets per host  ->  CVE stage

One target can be many hosts (a CIDR range), so a run holds one `Asset` per host.

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
    """The result of one scan of one target: one asset per host found."""

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

        # 3. Run every available plugin; each reports one asset per host it found.
        #    What several plugins say about the same host is merged into one asset.
        assets: list[Asset] = []
        for plugin in runnable:
            for found in plugin.scan(target):
                known = next((a for a in assets if _same_host(a, found)), None)
                if known is None:
                    assets.append(found)
                else:
                    _merge_into(known, found)

        # 4. CVE stage: match each service against known vulnerabilities.
        if self.cve_source is not None:
            for asset in assets:
                for service in asset.services:
                    asset.findings.extend(self.cve_source.find(service, asset.host))

        finished = datetime.now(UTC).isoformat()
        return ScanRun(
            target=target,
            started_at=started,
            finished_at=finished,
            assets=assets,
            skipped_plugins=skipped,
        )


def _same_host(a: Asset, b: Asset) -> bool:
    """Do two plugin reports describe the same machine?

    The IP decides whenever both reports have one: one name can point at several
    machines. A report without an IP (a tool that only lists names) is matched by name.
    """
    if a.ip and b.ip:
        return a.ip == b.ip
    return a.host.lower() == b.host.lower()


def _merge_into(known: Asset, found: Asset) -> None:
    """Add what another plugin learnt about the same host to `known`."""
    if known.ip is None:
        known.ip = found.ip
    seen = {(s.port, s.protocol) for s in known.services}
    for service in found.services:
        if (service.port, service.protocol) not in seen:
            seen.add((service.port, service.protocol))
            known.services.append(service)
    known.findings.extend(found.findings)
