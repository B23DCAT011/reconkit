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
from reconkit.schema import ScanTarget

DATA = Path(__file__).parent / "data"
SAMPLE = (DATA / "nmap_sample.xml").read_text(encoding="utf-8")
TWO_HOSTS = (DATA / "nmap_two_hosts.xml").read_text(encoding="utf-8")

# What the scope guard hands a plugin when the user asks for "scanme.lab".
LAB = ScanTarget(requested="scanme.lab", addresses=("10.0.0.5",), hostname="scanme.lab")


def _ip_target(address: str) -> ScanTarget:
    return ScanTarget(requested=address, addresses=(address,))


def test_satisfies_plugin_protocol() -> None:
    assert isinstance(NmapPlugin(), ScannerPlugin)


# --- command line: nmap is given addresses, never a name (G4) --------------------


def test_builds_argument_list_without_shell() -> None:
    cmd = NmapPlugin()._command(LAB)
    assert cmd[0] == "nmap"
    assert "-oX" in cmd and "-" in cmd


def test_command_scans_the_resolved_address_not_the_name() -> None:
    cmd = NmapPlugin()._command(LAB)
    assert cmd[-1] == "10.0.0.5"
    assert "scanme.lab" not in cmd  # nmap must not resolve the name a second time


def test_command_scans_every_address_of_a_name() -> None:
    target = ScanTarget(
        requested="scanme.lab", addresses=("10.0.0.5", "10.0.0.6"), hostname="scanme.lab"
    )
    assert NmapPlugin()._command(target)[-2:] == ["10.0.0.5", "10.0.0.6"]


def test_command_excludes_denied_addresses() -> None:
    target = ScanTarget(
        requested="10.0.0.0/24", addresses=("10.0.0.0/24",), exclude=("10.0.0.1", "10.0.0.64/26")
    )
    cmd = NmapPlugin()._command(target)
    at = cmd.index("--exclude")
    assert cmd[at + 1] == "10.0.0.1,10.0.0.64/26"
    assert cmd[-1] == "10.0.0.0/24"


def test_command_has_no_exclude_flag_when_nothing_is_denied() -> None:
    assert "--exclude" not in NmapPlugin()._command(LAB)


# --- parsing: one asset per host (G1, G16) ---------------------------------------


def test_host_scanned_by_name_is_named_after_the_request() -> None:
    (asset,) = NmapPlugin.parse_xml(SAMPLE, hostname="scanme.lab")
    assert asset.host == "scanme.lab"  # the name the user asked for, not the PTR name
    assert asset.ip == "10.0.0.5"


def test_host_scanned_by_address_is_named_after_its_ip() -> None:
    (asset,) = NmapPlugin.parse_xml(SAMPLE)
    assert (asset.host, asset.ip) == ("10.0.0.5", "10.0.0.5")  # not the PTR name


def test_parses_only_open_ports() -> None:
    (asset,) = NmapPlugin.parse_xml(SAMPLE)
    ports = {s.port for s in asset.services}
    assert ports == {22, 80}  # 443 is closed and excluded


def test_range_scan_yields_one_asset_per_live_host() -> None:
    # Every service stays attached to the machine it was found on.
    web, quiet = NmapPlugin.parse_xml(TWO_HOSTS)  # 10.0.0.9 is down: not an asset
    assert (web.host, web.ip) == ("10.0.0.5", "10.0.0.5")  # IP, not MAC or PTR name
    assert [s.port for s in web.services] == [22]
    assert (quiet.host, quiet.ip) == ("10.0.0.7", "10.0.0.7")
    assert quiet.services == []  # up, nothing open: still reported


def test_ipv6_address_is_used_as_the_ip() -> None:
    xml = (
        '<nmaprun><host><status state="up"/>'
        '<address addr="2001:db8::5" addrtype="ipv6"/></host></nmaprun>'
    )
    (asset,) = NmapPlugin.parse_xml(xml)
    assert (asset.host, asset.ip) == ("2001:db8::5", "2001:db8::5")


def test_extracts_service_fields() -> None:
    services = {s.port: s for s in NmapPlugin.parse_xml(SAMPLE)[0].services}
    ssh = services[22]
    assert ssh.name == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "7.4"
    assert ssh.cpe == "cpe:/a:openbsd:openssh:7.4"
    assert ssh.protocol == "tcp"


def test_empty_output_yields_no_assets() -> None:
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


def test_scan_returns_assets_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    done = subprocess.CompletedProcess(args=["nmap"], returncode=0, stdout=SAMPLE, stderr="")
    _fake_run(monkeypatch, done)
    (asset,) = NmapPlugin().scan(LAB)
    assert (asset.host, asset.ip) == ("scanme.lab", "10.0.0.5")
    assert {s.port for s in asset.services} == {22, 80}


def test_scan_wraps_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(ScanError, match="not installed"):
        NmapPlugin().scan(LAB)


def test_scan_wraps_nonzero_exit_and_keeps_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = subprocess.CalledProcessError(
        returncode=1, cmd=["nmap"], stderr="You requested a scan type which requires root\n"
    )
    _fake_run(monkeypatch, failure)
    with pytest.raises(ScanError, match="exited with code 1 scanning scanme.lab") as excinfo:
        NmapPlugin().scan(LAB)
    assert excinfo.value.plugin == "nmap"
    assert excinfo.value.stderr == "You requested a scan type which requires root"


def test_scan_wraps_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_run(monkeypatch, subprocess.TimeoutExpired(cmd=["nmap"], timeout=5))
    with pytest.raises(ScanError, match="timed out after 5s"):
        NmapPlugin(timeout=5).scan(LAB)


def test_scan_wraps_failure_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_run(monkeypatch, PermissionError("access denied"))
    with pytest.raises(ScanError, match="could not start nmap"):
        NmapPlugin().scan(LAB)


def test_scan_wraps_truncated_xml(monkeypatch: pytest.MonkeyPatch) -> None:
    done = subprocess.CompletedProcess(
        args=["nmap"], returncode=0, stdout=SAMPLE[: len(SAMPLE) // 2], stderr=""
    )
    _fake_run(monkeypatch, done)
    with pytest.raises(ScanError, match="unreadable XML"):
        NmapPlugin().scan(LAB)


# --- scan(): nmap exits 0 but examined nothing (G2) --------------------------------


def _run_xml(up: int, down: int, total: int) -> str:
    """Minimal nmap output carrying only its own host counts."""
    return (
        '<?xml version="1.0"?><nmaprun><runstats>'
        f'<hosts up="{up}" down="{down}" total="{total}"/>'
        "</runstats></nmaprun>"
    )


def test_scan_rejects_zero_hosts_scanned(monkeypatch: pytest.MonkeyPatch) -> None:
    # nmap exits 0 with total="0" when it ends up with nothing to scan.
    done = subprocess.CompletedProcess(
        args=["nmap"],
        returncode=0,
        stdout=_run_xml(up=0, down=0, total=0),
        stderr="WARNING: No targets were specified, so 0 hosts scanned.\n",
    )
    _fake_run(monkeypatch, done)
    with pytest.raises(ScanError, match="scanned 0 hosts") as excinfo:
        NmapPlugin().scan(_ip_target("10.0.0.5"))
    assert excinfo.value.stderr == "WARNING: No targets were specified, so 0 hosts scanned."


def test_scan_rejects_no_host_up(monkeypatch: pytest.MonkeyPatch) -> None:
    done = subprocess.CompletedProcess(
        args=["nmap"], returncode=0, stdout=_run_xml(up=0, down=1, total=1), stderr=""
    )
    _fake_run(monkeypatch, done)
    with pytest.raises(ScanError, match="no host responded"):
        NmapPlugin().scan(_ip_target("192.0.2.1"))


def test_scan_accepts_live_host_with_no_open_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    # A host that answered and has nothing open is a real, clean result.
    xml = (
        '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/></host>'
        '<runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    )
    done = subprocess.CompletedProcess(args=["nmap"], returncode=0, stdout=xml, stderr="")
    _fake_run(monkeypatch, done)
    (asset,) = NmapPlugin().scan(_ip_target("10.0.0.5"))
    assert asset.ip == "10.0.0.5"
    assert asset.services == []
