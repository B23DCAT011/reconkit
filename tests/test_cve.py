"""Tests for the CVE matching stage (offline local source)."""

from reconkit.cve import LocalCveSource
from reconkit.schema import Service, Severity


def test_matches_known_product_version() -> None:
    src = LocalCveSource()
    svc = Service(port=22, name="ssh", product="OpenSSH", version="7.4")
    findings = src.find(svc, asset_host="host.lab")
    assert len(findings) == 1
    assert findings[0].cve == "CVE-2018-15473"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].fingerprint  # fingerprint was computed


def test_match_is_case_insensitive_on_product() -> None:
    src = LocalCveSource()
    lower = src.find(Service(port=80, product="nginx", version="1.18.0"), "h")
    upper = src.find(Service(port=80, product="NGINX", version="1.18.0"), "h")
    assert len(lower) == 1 and len(upper) == 1
    assert lower[0].cve == upper[0].cve == "CVE-2021-23017"


def test_no_match_for_patched_version() -> None:
    src = LocalCveSource()
    # 7.4 is vulnerable in the seed; 9.6 is not listed -> no finding.
    assert src.find(Service(port=22, product="OpenSSH", version="9.6"), "h") == []


def test_no_match_without_version() -> None:
    src = LocalCveSource()
    assert src.find(Service(port=22, product="OpenSSH", version=None), "h") == []


def test_finding_carries_service_for_fingerprint() -> None:
    src = LocalCveSource()
    svc = Service(port=21, product="vsftpd", version="2.3.4")
    finding = src.find(svc, "h")[0]
    assert finding.service == svc
    assert finding.severity == Severity.CRITICAL
