"""Tests for the nmap plugin — no binary required.

Parsing is tested on a saved XML sample; `scan()` is tested by replacing
`subprocess.run`, so each failure mode can be triggered on demand.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from reconkit.plugins.base import ScanError, ScannerPlugin
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


# --- scan(): every way nmap can fail must surface as ScanError (G3) ---------------


def _fake_run(monkeypatch: pytest.MonkeyPatch, outcome: object) -> None:
    """Make scan() see nmap as installed, and `subprocess.run` raise/return `outcome`."""

    def run(*args: object, **kwargs: object) -> object:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(subprocess, "run", run)


def test_scan_returns_services_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    done = subprocess.CompletedProcess(args=["nmap"], returncode=0, stdout=SAMPLE, stderr="")
    _fake_run(monkeypatch, done)
    assert {s.port for s in NmapPlugin().scan("scanme.lab")} == {22, 80}


def test_scan_wraps_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(ScanError, match="not installed"):
        NmapPlugin().scan("scanme.lab")


def test_scan_wraps_nonzero_exit_and_keeps_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = subprocess.CalledProcessError(
        returncode=1, cmd=["nmap"], stderr="You requested a scan type which requires root\n"
    )
    _fake_run(monkeypatch, failure)
    with pytest.raises(ScanError, match="exited with code 1") as excinfo:
        NmapPlugin().scan("scanme.lab")
    assert excinfo.value.plugin == "nmap"
    assert excinfo.value.stderr == "You requested a scan type which requires root"


def test_scan_wraps_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_run(monkeypatch, subprocess.TimeoutExpired(cmd=["nmap"], timeout=5))
    with pytest.raises(ScanError, match="timed out after 5s"):
        NmapPlugin(timeout=5).scan("scanme.lab")


def test_scan_wraps_failure_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_run(monkeypatch, PermissionError("access denied"))
    with pytest.raises(ScanError, match="could not start nmap"):
        NmapPlugin().scan("scanme.lab")


def test_scan_wraps_truncated_xml(monkeypatch: pytest.MonkeyPatch) -> None:
    done = subprocess.CompletedProcess(
        args=["nmap"], returncode=0, stdout=SAMPLE[: len(SAMPLE) // 2], stderr=""
    )
    _fake_run(monkeypatch, done)
    with pytest.raises(ScanError, match="unreadable XML"):
        NmapPlugin().scan("scanme.lab")
