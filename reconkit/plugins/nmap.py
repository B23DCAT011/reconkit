"""nmap adapter — port/service scan via `nmap -oX`.

`scan()` runs nmap and feeds its XML straight into `parse_xml()`; `parse_xml()` is a
pure function over the XML string, so the parsing logic is tested without nmap
installed (see tests/data/nmap_sample.xml).

Safety: the target is validated by the scope guard *before* a plugin is called, and
nmap is invoked with an argument list (never a shell string), so the target cannot be
used to inject extra commands.
"""

from __future__ import annotations

import shutil
import subprocess
from xml.etree import ElementTree as ET

from reconkit.schema import Service


class NmapPlugin:
    """Scanner plugin backed by the `nmap` binary."""

    name = "nmap"

    def __init__(self, extra_args: list[str] | None = None, timeout: int = 300) -> None:
        # -sV = service/version detection; -T4 = reasonable speed for a lab.
        self.extra_args = extra_args if extra_args is not None else ["-sV", "-T4"]
        self.timeout = timeout

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def _command(self, target: str) -> list[str]:
        return ["nmap", *self.extra_args, "-oX", "-", target]

    def scan(self, target: str) -> list[Service]:
        if not self.is_available():
            raise RuntimeError("nmap is not installed or not on PATH")
        proc = subprocess.run(
            self._command(target),
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=True,
        )
        return self.parse_xml(proc.stdout)

    @staticmethod
    def parse_xml(xml: str) -> list[Service]:
        """Parse nmap `-oX` output into a list of open services."""
        services: list[Service] = []
        root = ET.fromstring(xml)
        for host in root.findall("host"):
            ports = host.find("ports")
            if ports is None:
                continue
            for port in ports.findall("port"):
                state_el = port.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if state != "open":
                    continue
                svc_el = port.find("service")
                cpe = None
                name = product = version = banner = None
                if svc_el is not None:
                    name = svc_el.get("name")
                    product = svc_el.get("product")
                    version = svc_el.get("version")
                    cpe_el = svc_el.find("cpe")
                    cpe = cpe_el.text if cpe_el is not None else None
                    banner = (
                        " ".join(p for p in (product, version, svc_el.get("extrainfo")) if p)
                        or None
                    )
                services.append(
                    Service(
                        port=int(port.get("portid", "0")),
                        protocol=port.get("protocol", "tcp"),
                        state=state,
                        name=name,
                        product=product,
                        version=version,
                        cpe=cpe,
                        banner=banner,
                    )
                )
        return services
