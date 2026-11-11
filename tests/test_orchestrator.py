"""Tests for the orchestrator pipeline."""

import pytest
from conftest import FakePlugin, fake_resolver, lab_asset, lab_resolver, lab_scope

from reconkit.cve import CveSource, LocalCveSource
from reconkit.orchestrator import NoPluginAvailableError, Orchestrator
from reconkit.plugins.base import ScannerPlugin
from reconkit.schema import Asset, Finding, Service
from reconkit.scope import ResolutionError, Resolver, Scope, ScopeError

OPENSSH_74 = Service(port=22, name="ssh", product="OpenSSH", version="7.4")


def _orch(
    plugins: list[ScannerPlugin],
    scope: Scope | None = None,
    cve_source: CveSource | None = None,
    resolver: Resolver = lab_resolver,
) -> Orchestrator:
    """An orchestrator over the lab scope, with DNS answered from a dict."""
    return Orchestrator(
        plugins=plugins, scope=scope or lab_scope(), cve_source=cve_source, resolver=resolver
    )


def test_refuses_out_of_scope_target() -> None:
    plugin = FakePlugin([])
    with pytest.raises(ScopeError):
        _orch([plugin]).run("evil.example.com")
    assert plugin.seen == []  # refused before any plugin was called


def test_collects_services_from_plugins() -> None:
    plugin = FakePlugin([lab_asset(Service(port=22, name="ssh"), Service(port=80, name="http"))])
    run = _orch([plugin]).run("scanme.lab")
    assert run.target == "scanme.lab"
    assert len(run.assets) == 1
    assert run.assets[0].host == "scanme.lab"
    assert run.assets[0].ip == "10.0.0.5"
    assert {s.port for s in run.assets[0].services} == {22, 80}


# --- scope gate: names are resolved once and plugins get addresses (G4) ----------


def test_plugin_is_given_the_resolved_addresses_not_the_name() -> None:
    plugin = FakePlugin([lab_asset()])
    run = _orch([plugin]).run("scanme.lab")
    (seen,) = plugin.seen
    assert seen.addresses == ("10.0.0.5",)
    assert seen.hostname == "scanme.lab"
    assert run.plan == seen  # the run records what was authorised


def test_refuses_name_that_resolves_outside_the_scope() -> None:
    # The name is allowlisted, but it points at a machine that is not ours.
    plugin = FakePlugin([])
    orch = _orch([plugin], resolver=fake_resolver({"scanme.lab": ["203.0.113.9"]}))
    with pytest.raises(ScopeError, match=r"resolves to 203\.0\.113\.9"):
        orch.run("scanme.lab")
    assert plugin.seen == []


def test_unresolvable_name_is_an_error_before_any_scan() -> None:
    plugin = FakePlugin([])
    orch = _orch([plugin], resolver=fake_resolver({}))
    with pytest.raises(ResolutionError):
        orch.run("scanme.lab")
    assert plugin.seen == []


def test_range_overlapping_denylist_is_scanned_with_exclusions() -> None:
    plugin = FakePlugin([lab_asset(host="10.0.0.5", ip="10.0.0.5")])
    _orch([plugin], scope=lab_scope("!10.0.0.1")).run("10.0.0.0/24")
    (seen,) = plugin.seen
    assert seen.addresses == ("10.0.0.0/24",)
    assert seen.exclude == ("10.0.0.1",)


def test_host_reported_outside_the_scope_is_dropped_and_recorded() -> None:
    # A tool that strays (or a discovery tool listing third-party hosts) must not
    # get out-of-scope machines into the results.
    plugin = FakePlugin(
        [
            lab_asset(Service(port=22), host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(Service(port=22), host="10.0.0.1", ip="10.0.0.1"),  # denied
            lab_asset(Service(port=80), host="192.0.2.50", ip="192.0.2.50"),  # not allowed
        ]
    )
    run = _orch([plugin], scope=lab_scope("!10.0.0.1")).run("10.0.0.0/24")
    assert [a.ip for a in run.assets] == ["10.0.0.5"]
    assert run.out_of_scope == ["10.0.0.1", "192.0.2.50"]


# --- one asset per host (G1) -----------------------------------------------------


def test_range_target_yields_one_asset_per_host() -> None:
    # A range must not collapse into a single asset named after the range.
    plugin = FakePlugin(
        [
            lab_asset(Service(port=22), host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(Service(port=80), host="10.0.0.7", ip="10.0.0.7"),
        ]
    )
    run = _orch([plugin]).run("10.0.0.0/24")
    assert run.target == "10.0.0.0/24"
    ports_by_ip = {a.ip: [s.port for s in a.services] for a in run.assets}
    assert ports_by_ip == {"10.0.0.5": [22], "10.0.0.7": [80]}


def test_same_issue_on_two_hosts_gives_two_distinct_findings() -> None:
    # Two machines with the same vulnerable software are two findings.
    plugin = FakePlugin(
        [
            lab_asset(OPENSSH_74, host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(OPENSSH_74, host="10.0.0.7", ip="10.0.0.7"),
        ]
    )
    run = _orch([plugin], cve_source=LocalCveSource()).run("10.0.0.0/24")
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
    run = _orch([ports, checks]).run("scanme.lab")

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
    first = FakePlugin([Asset(host="scanme.lab")])
    second = FakePlugin([Asset(host="scanme.lab", ip="10.0.0.5")])
    run = _orch([first, second]).run("scanme.lab")
    assert [(a.host, a.ip) for a in run.assets] == [("scanme.lab", "10.0.0.5")]


# --- CVE stage -------------------------------------------------------------------


def test_cve_stage_produces_findings() -> None:
    run = _orch([FakePlugin([lab_asset(OPENSSH_74)])], cve_source=LocalCveSource()).run(
        "scanme.lab"
    )
    findings = run.assets[0].findings
    assert len(findings) == 1
    assert findings[0].cve == "CVE-2018-15473"
    assert findings[0].asset == "scanme.lab"


def test_no_cve_source_means_no_findings() -> None:
    run = _orch([FakePlugin([lab_asset(OPENSSH_74)])]).run("scanme.lab")
    assert run.assets[0].findings == []


# --- plugin availability (G2) ----------------------------------------------------


def test_skips_unavailable_plugins() -> None:
    present = FakePlugin([lab_asset(Service(port=22))], available=True)
    missing = FakePlugin([lab_asset(Service(port=443))], available=False)
    run = _orch([present, missing]).run("scanme.lab")
    assert {s.port for s in run.assets[0].services} == {22}
    assert run.skipped_plugins == ["fake"]  # the result is flagged as partial


def test_no_available_plugin_is_an_error() -> None:
    missing = FakePlugin([lab_asset(Service(port=22))], available=False)
    with pytest.raises(NoPluginAvailableError, match="fake not installed"):
        _orch([missing]).run("scanme.lab")


def test_no_configured_plugin_is_an_error() -> None:
    with pytest.raises(NoPluginAvailableError, match="no scanner configured"):
        _orch([]).run("scanme.lab")


def test_scope_is_checked_before_plugin_availability() -> None:
    missing = FakePlugin([], available=False)
    with pytest.raises(ScopeError):
        _orch([missing]).run("evil.example.com")
