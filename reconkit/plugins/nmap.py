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

from reconkit.plugins.base import ScanError
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
        """Run nmap against `target`; every failure surfaces as `ScanError`."""
        if not self.is_available():
            raise ScanError("nmap is not installed or not on PATH", plugin=self.name)
        try:
            proc = subprocess.run(
                self._command(target),
                capture_output=True,
                # nmap writes UTF-8 XML; decode it as such instead of the Windows
                # locale codepage, and never crash on a stray byte in a banner.
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError(
                f"nmap timed out after {self.timeout}s scanning {target}",
                plugin=self.name,
            ) from exc
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip() or None
            raise ScanError(
                f"nmap exited with code {exc.returncode} scanning {target}",
                plugin=self.name,
                stderr=stderr,
            ) from exc
        except OSError as exc:
            # The binary vanished or is not executable between the check and the call.
            raise ScanError(f"could not start nmap: {exc}", plugin=self.name) from exc

        stderr = proc.stderr.strip() or None
        try:
            root = ET.fromstring(proc.stdout)
        except ET.ParseError as exc:
            # Truncated or non-XML output: report it rather than guess at a result.
            raise ScanError(
                f"nmap produced unreadable XML scanning {target}: {exc}",
                plugin=self.name,
                stderr=stderr,
            ) from exc

        # nmap exits 0 even when it examined nothing, so the exit code alone cannot
        # be trusted: check its own host counts before reporting "no open ports".
        counts = self._host_counts(root)
        if counts is not None:
            up, total = counts
            if total == 0:
                raise ScanError(
                    f"nmap scanned 0 hosts for {target} (could the name not be resolved?)",
                    plugin=self.name,
                    stderr=stderr,
                )
            if up == 0:
                raise ScanError(
                    f"no host responded for {target} ({total} probed): "
                    "down, or blocking nmap's host discovery",
                    plugin=self.name,
                    stderr=stderr,
                )
        return self._services(root)

    @staticmethod
    def _host_counts(root: ET.Element) -> tuple[int, int] | None:
        """Return nmap's own `(hosts up, hosts total)`, or None if it did not say."""
        hosts = root.find("runstats/hosts")
        if hosts is None:
            return None
        try:
            return int(hosts.get("up", "")), int(hosts.get("total", ""))
        except ValueError:
            return None

    @staticmethod
    def parse_xml(xml: str) -> list[Service]:
        """Parse nmap `-oX` output into a list of open services."""
        return NmapPlugin._services(ET.fromstring(xml))

    @staticmethod
    def _services(root: ET.Element) -> list[Service]:
        services: list[Service] = []
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
