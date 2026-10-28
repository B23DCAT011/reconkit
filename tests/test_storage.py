"""Tests for the SQLite storage repository."""

from pathlib import Path

from reconkit.orchestrator import ScanRun
from reconkit.schema import Asset, Finding, Service, Severity
from reconkit.storage import Storage


def _make_run() -> ScanRun:
    svc = Service(port=22, name="ssh", product="OpenSSH", version="7.4")
    finding = Finding(
        asset="scanme.lab",
        title="OpenSSH 7.4",
        severity=Severity.MEDIUM,
        service=svc,
        cve="CVE-2018-15473",
    )
    finding.compute_fingerprint()
    asset = Asset(host="scanme.lab", ip="10.0.0.5", services=[svc], findings=[finding])
    return ScanRun(
        "scanme.lab", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:05+00:00", assets=[asset]
    )


def _store(tmp_path: Path) -> Storage:
    return Storage(tmp_path / "test.db")


def test_save_and_read_back_services(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run_id = store.save_run(_make_run())
        services = store.services_for_run(run_id)
    assert [s.port for s in services] == [22]
    assert services[0].product == "OpenSSH"


def test_save_and_read_back_findings(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run_id = store.save_run(_make_run())
        findings = store.findings_for_run(run_id)
    assert len(findings) == 1
    assert findings[0].cve == "CVE-2018-15473"
    assert len(findings[0].fingerprint) == 64


def test_run_ids_increment(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        first = store.save_run(_make_run())
        second = store.save_run(_make_run())
    assert second == first + 1


def test_rollback_on_failure_leaves_no_partial_run(tmp_path: Path) -> None:
    """If writing a run fails midway, the whole transaction must roll back."""
    with _store(tmp_path) as store:
        # Make the findings insert blow up *after* the scan_run + asset rows were
        # inserted within the same transaction.
        def boom(*_: object, **__: object) -> None:
            raise RuntimeError("simulated failure mid-write")

        store._insert_findings = boom  # type: ignore[method-assign]
        try:
            store.save_run(_make_run())
        except RuntimeError:
            pass
        # Nothing should have been committed.
        n_runs = store._conn.execute("SELECT COUNT(*) AS n FROM scan_run").fetchone()["n"]
        n_assets = store._conn.execute("SELECT COUNT(*) AS n FROM asset").fetchone()["n"]
        assert n_runs == 0
        assert n_assets == 0
