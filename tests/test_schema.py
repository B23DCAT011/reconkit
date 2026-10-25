"""Tests for the shared data model, focused on fingerprint stability."""

from reconkit.schema import Asset, Finding, Service, Severity


def _ssh_finding() -> Finding:
    svc = Service(port=22, name="ssh", product="OpenSSH", version="7.4")
    return Finding(
        asset="host.lab",
        title="OpenSSH 7.4 - user enumeration",
        severity=Severity.MEDIUM,
        service=svc,
        cve="CVE-2018-15473",
    )


def test_fingerprint_is_deterministic() -> None:
    assert _ssh_finding().compute_fingerprint() == _ssh_finding().compute_fingerprint()


def test_fingerprint_ignores_volatile_fields() -> None:
    a = _ssh_finding()
    b = _ssh_finding()
    a.evidence = "banner captured at 12:00:01, session 9f3c"
    b.evidence = "banner captured at 15:42:59, session a1b2"
    b.severity = Severity.HIGH  # severity is not part of identity
    assert a.compute_fingerprint() == b.compute_fingerprint()


def test_fingerprint_changes_with_version() -> None:
    a = _ssh_finding()
    b = _ssh_finding()
    assert b.service is not None
    patched = Service(port=22, name="ssh", product="OpenSSH", version="9.6")
    b.service = patched
    assert a.compute_fingerprint() != b.compute_fingerprint()


def test_fingerprint_is_hex_sha256() -> None:
    fp = _ssh_finding().compute_fingerprint()
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_asset_defaults_are_independent() -> None:
    a = Asset(host="a.lab")
    b = Asset(host="b.lab")
    a.services.append(Service(port=80))
    assert b.services == []  # no shared mutable default
