"""Tests for the nmap plugin — parsing only, no binary required."""

from pathlib import Path

from reconkit.plugins.base import ScannerPlugin
from reconkit.plugins.nmap import NmapPlugin

SAMPLE = (Path(__file__).parent / "data" / "nmap_sample.xml").read_text(encoding="utf-8")


def test_satisfies_plugin_protocol() -> None:
    assert isinstance(NmapPlugin(), ScannerPlugin)


def test_parses_only_open_ports() -> None:
    services = NmapPlugin.parse_xml(SAMPLE)
    ports = {s.port for s in services}
    assert ports == {22, 80}  # 443 is closed and excluded


def test_extracts_service_fields() -> None:
    services = {s.port: s for s in NmapPlugin.parse_xml(SAMPLE)}
    ssh = services[22]
    assert ssh.name == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "7.4"
    assert ssh.cpe == "cpe:/a:openbsd:openssh:7.4"
    assert ssh.protocol == "tcp"


def test_builds_argument_list_without_shell() -> None:
    cmd = NmapPlugin()._command("scanme.lab")
    assert cmd[0] == "nmap"
    assert cmd[-1] == "scanme.lab"
    assert "-oX" in cmd and "-" in cmd


def test_empty_output_yields_no_services() -> None:
    xml = '<?xml version="1.0"?><nmaprun></nmaprun>'
    assert NmapPlugin.parse_xml(xml) == []
