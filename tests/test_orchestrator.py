"""Tests for the orchestrator pipeline."""

import pytest
from conftest import FakePlugin, lab_asset

from reconkit.cve import LocalCveSource
from reconkit.orchestrator import NoPluginAvailableError, Orchestrator
from reconkit.schema import Asset, Finding, Service
from reconkit.scope import Scope, ScopeError

OPENSSH_74 = Service(port=22, name="ssh", product="OpenSSH", version="7.4")


def test_refuses_out_of_scope_target() -> None:
    orch = Orchestrator(plugins=[FakePlugin([])], scope=Scope.from_entries(["scanme.lab"]))
    with pytest.raises(ScopeError):
        orch.run("evil.example.com")


def test_collects_services_from_plugins() -> None:
    plugin = FakePlugin([lab_asset(Service(port=22, name="ssh"), Service(port=80, name="http"))])
    orch = Orchestrator(plugins=[plugin], scope=Scope.from_entries(["scanme.lab"]))
    run = orch.run("scanme.lab")
    assert run.target == "scanme.lab"
    assert len(run.assets) == 1
    assert run.assets[0].host == "scanme.lab"
    assert run.assets[0].ip == "10.0.0.5"
    assert {s.port for s in run.assets[0].services} == {22, 80}


def test_range_target_yields_one_asset_per_host() -> None:
    # G1: a range must not collapse into a single asset named after the range.
    plugin = FakePlugin(
        [
            lab_asset(Service(port=22), host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(Service(port=80), host="10.0.0.7", ip="10.0.0.7"),
        ]
    )
    orch = Orchestrator(plugins=[plugin], scope=Scope.from_entries(["10.0.0.0/24"]))
    run = orch.run("10.0.0.0/24")
    assert run.target == "10.0.0.0/24"
    ports_by_ip = {a.ip: [s.port for s in a.services] for a in run.assets}
    assert ports_by_ip == {"10.0.0.5": [22], "10.0.0.7": [80]}


def test_same_issue_on_two_hosts_gives_two_distinct_findings() -> None:
    # G1: two machines with the same vulnerable software are two findings.
    plugin = FakePlugin(
        [
            lab_asset(OPENSSH_74, host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(OPENSSH_74, host="10.0.0.7", ip="10.0.0.7"),
        ]
    )
    orch = Orchestrator(
        plugins=[plugin],
        scope=Scope.from_entries(["10.0.0.0/24"]),
        cve_source=LocalCveSource(),
    )
    run = orch.run("10.0.0.0/24")
    findings = [f for a in run.assets for f in a.findings]
    assert [f.asset for f in findings] == ["10.0.0.5", "10.0.0.7"]
    assert len({f.fingerprint for f in findings}) == 2


def test_merges_what_two_plugins_report_for_the_same_host() -> None:
    ports = FakePlugin([lab_asset(Service(port=22, name="ssh"), Service(port=80, name="http"))])
    issue = Finding(asset="scanme.lab", title="exposed admin panel")
    checks = FakePlugin(
        [
            Asset(
                host="10.0.0.5",  # same machine, named differently by this tool
                ip="10.0.0.5",
                services=[Service(port=80, name="http-alt"), Service(port=443, name="https")],
                findings=[issue],
            )
        ]
    )
    orch = Orchestrator(plugins=[ports, checks], scope=Scope.from_entries(["scanme.lab"]))
    run = orch.run("scanme.lab")

    assert len(run.assets) == 1
    asset = run.assets[0]
    assert asset.host == "scanme.lab"  # the first plugin's name for the host is kept
    assert [(s.port, s.name) for s in asset.services] == [
        (22, "ssh"),
        (80, "http"),  # already known: the second report of port 80 is not duplicated
        (443, "https"),
    ]
    assert asset.findings == [issue]


def test_assets_without_ip_are_matched_by_name() -> None:
    first = FakePlugin([Asset(host="api.scanme.lab")])
    second = FakePlugin([Asset(host="api.scanme.lab", ip="10.0.0.9")])
    orch = Orchestrator(plugins=[first, second], scope=Scope.from_entries(["scanme.lab"]))
    run = orch.run("scanme.lab")
    assert [(a.host, a.ip) for a in run.assets] == [("api.scanme.lab", "10.0.0.9")]


def test_cve_stage_produces_findings() -> None:
    orch = Orchestrator(
        plugins=[FakePlugin([lab_asset(OPENSSH_74)])],
        scope=Scope.from_entries(["scanme.lab"]),
        cve_source=LocalCveSource(),
    )
    run = orch.run("scanme.lab")
    findings = run.assets[0].findings
    assert len(findings) == 1
    assert findings[0].cve == "CVE-2018-15473"
    assert findings[0].asset == "scanme.lab"


def test_no_cve_source_means_no_findings() -> None:
    plugin = FakePlugin([lab_asset(OPENSSH_74)])
    orch = Orchestrator(plugins=[plugin], scope=Scope.from_entries(["scanme.lab"]))
    run = orch.run("scanme.lab")
    assert run.assets[0].findings == []


def test_skips_unavailable_plugins() -> None:
    present = FakePlugin([lab_asset(Service(port=22))], available=True)
    missing = FakePlugin([lab_asset(Service(port=443))], available=False)
    orch = Orchestrator(plugins=[present, missing], scope=Scope.from_entries(["scanme.lab"]))
    run = orch.run("scanme.lab")
    assert {s.port for s in run.assets[0].services} == {22}
    assert run.skipped_plugins == ["fake"]  # the result is flagged as partial


def test_no_available_plugin_is_an_error() -> None:
    missing = FakePlugin([lab_asset(Service(port=22))], available=False)
    orch = Orchestrator(plugins=[missing], scope=Scope.from_entries(["scanme.lab"]))
    with pytest.raises(NoPluginAvailableError, match="fake not installed"):
        orch.run("scanme.lab")


def test_no_configured_plugin_is_an_error() -> None:
    orch = Orchestrator(plugins=[], scope=Scope.from_entries(["scanme.lab"]))
    with pytest.raises(NoPluginAvailableError, match="no scanner configured"):
        orch.run("scanme.lab")


def test_scope_is_checked_before_plugin_availability() -> None:
    missing = FakePlugin([], available=False)
    orch = Orchestrator(plugins=[missing], scope=Scope.from_entries(["scanme.lab"]))
    with pytest.raises(ScopeError):
        orch.run("evil.example.com")
