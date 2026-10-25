"""Shared data model — the common language every module speaks.

Three nested entities describe what a scan discovers:

    Asset   a host reachable on the network (resolved from a domain, IP or CIDR)
      └─ Service   an open port + the software fingerprinted behind it
           └─ Finding   something worth reporting about that service (e.g. a CVE)

Each `Finding` carries a stable `fingerprint`: a hash of its *identifying* fields
only, so the same issue hashes identically across scans. That is what later lets us
diff runs — detect a reappearing issue (a fake fix) or a brand-new one — without
re-reading the whole database. See GHI-CHU.md section 5.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """Severity of a finding, ordered from least to most serious."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Service:
    """An open port on an asset and the software fingerprinted behind it."""

    port: int
    protocol: str = "tcp"  # "tcp" | "udp"
    state: str = "open"
    name: str | None = None  # e.g. "ssh", "http"
    product: str | None = None  # e.g. "OpenSSH"
    version: str | None = None  # e.g. "7.4"
    cpe: str | None = None  # e.g. "cpe:/a:openbsd:openssh:7.4"
    banner: str | None = None


@dataclass(slots=True)
class Finding:
    """Something worth reporting about a service (a CVE match, a weak config, ...).

    `fingerprint` is filled by :meth:`compute_fingerprint` from the identifying
    fields; `evidence` and anything volatile (timestamps, session ids) are
    deliberately excluded so the hash stays stable across scans.
    """

    asset: str  # host the finding belongs to, e.g. "api.example.com"
    title: str  # short human label, e.g. "OpenSSH 7.4 - user enumeration"
    severity: Severity = Severity.INFO
    service: Service | None = None
    cve: str | None = None  # e.g. "CVE-2018-15473"
    description: str = ""
    evidence: str = ""  # raw proof; NOT part of the fingerprint
    fingerprint: str = ""

    def identity(self) -> dict[str, str | int | None]:
        """The identifying fields a fingerprint is derived from.

        Chosen so that the *same vulnerability on the same service* produces the
        same dict on every run. Noisy fields (evidence, severity score drift,
        timestamps) are excluded on purpose.
        """
        svc = self.service
        return {
            "asset": self.asset,
            "title": self.title,
            "cve": self.cve,
            "port": svc.port if svc else None,
            "protocol": svc.protocol if svc else None,
            "product": svc.product if svc else None,
            "version": svc.version if svc else None,
        }

    def compute_fingerprint(self) -> str:
        """Return a stable SHA-256 over this finding's identity (and set it)."""
        canonical = json.dumps(self.identity(), sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.fingerprint = digest
        return digest


@dataclass(slots=True)
class Asset:
    """A host discovered during recon, with the services found on it."""

    host: str  # domain or IP, e.g. "api.example.com" or "203.0.113.10"
    ip: str | None = None
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
