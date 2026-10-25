"""CVE stage — turn a fingerprinted Service into Findings.

A `CveSource` takes a service (product + version) and returns the known
vulnerabilities for it, as :class:`~reconkit.schema.Finding` objects. Mirroring the
scanner-plugin design, the source is an interface: today there is one offline
implementation (:class:`LocalCveSource`, backed by a JSON seed file); an online NVD
source can be added later as another class without touching the orchestrator.

Matching here is deliberately simple — exact product name (case-insensitive) + exact
version. Real CVE data expresses affected *version ranges* (e.g. "< 7.7"); supporting
ranges is noted as future work in TASKS.md.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from reconkit.schema import Finding, Service, Severity

# Bundled seed data ships next to this module.
DEFAULT_SEED = Path(__file__).parent / "data" / "cve_seed.json"


class CveSource(Protocol):
    """A source of known vulnerabilities for a given service."""

    name: str

    def find(self, service: Service, asset_host: str) -> list[Finding]:
        """Return findings for `service` (empty list if none known)."""
        ...


class LocalCveSource:
    """Offline CVE source backed by a JSON seed file.

    The seed is indexed by (product_lower, version) so lookups are O(1).
    """

    name = "local-seed"

    def __init__(self, path: str | Path = DEFAULT_SEED) -> None:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        self._index: dict[tuple[str, str], list[dict[str, str]]] = {}
        for entry in raw.get("entries", []):
            key = (entry["product"].lower(), entry["version"])
            self._index.setdefault(key, []).append(entry)

    def find(self, service: Service, asset_host: str) -> list[Finding]:
        if not service.product or not service.version:
            return []  # cannot match without a product + version
        key = (service.product.lower(), service.version)
        findings: list[Finding] = []
        for entry in self._index.get(key, []):
            finding = Finding(
                asset=asset_host,
                title=entry["title"],
                severity=Severity(entry.get("severity", "info")),
                service=service,
                cve=entry.get("cve"),
                description=entry.get("description", ""),
            )
            finding.compute_fingerprint()
            findings.append(finding)
        return findings
