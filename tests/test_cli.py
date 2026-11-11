"""End-to-end CLI test using a fake plugin injected via monkeypatch."""

from pathlib import Path

from conftest import FakePlugin, lab_asset

from reconkit import cli
from reconkit.plugins.base import ScanError
from reconkit.schema import Service
from reconkit.storage import Storage


def test_scan_end_to_end(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("scanme.lab\n", encoding="utf-8")
    db = tmp_path / "out.db"

    # Replace the real nmap plugin with a deterministic fake.
    fake = FakePlugin([lab_asset(Service(port=22, name="ssh", product="OpenSSH", version="7.4"))])
    monkeypatch.setattr(cli, "NmapPlugin", lambda: fake)

    code = cli.main(["scan", "scanme.lab", "--scope", str(scope_file), "--db", str(db)])
    out = capsys.readouterr().out

    assert code == 0
    assert db.exists()
    assert "Scan run #1" in out
    assert "hosts: 1 " in out
    assert "scanme.lab (10.0.0.5)" in out
    assert "22/tcp" in out
    assert "OpenSSH 7.4" in out
    assert "CVE-2018-15473" in out


def test_range_scan_is_reported_and_stored_per_host(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("10.0.0.0/24\n", encoding="utf-8")
    db = tmp_path / "out.db"

    fake = FakePlugin(
        [
            lab_asset(Service(port=22, name="ssh"), host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(host="10.0.0.7", ip="10.0.0.7"),  # up, nothing open
        ]
    )
    monkeypatch.setattr(cli, "NmapPlugin", lambda: fake)

    code = cli.main(["scan", "10.0.0.0/24", "--scope", str(scope_file), "--db", str(db)])
    out = capsys.readouterr().out

    assert code == 0
    assert "hosts: 2 responded of 256 addresses" in out
    # Each host has its own block; the port is listed under the host it belongs to.
    first, second = out.index("\n  10.0.0.5\n"), out.index("\n  10.0.0.7\n")
    assert first < out.index("22/tcp") < second
    assert "no open ports found" in out[second:]

    with Storage(db) as store:
        rows = store._conn.execute("SELECT host, ip FROM asset ORDER BY id").fetchall()
    assert [(r["host"], r["ip"]) for r in rows] == [
        ("10.0.0.5", "10.0.0.5"),
        ("10.0.0.7", "10.0.0.7"),
    ]


def test_scan_refuses_out_of_scope(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("scanme.lab\n", encoding="utf-8")

    monkeypatch.setattr(cli, "NmapPlugin", lambda: FakePlugin([]))
    code = cli.main(
        ["scan", "evil.example.com", "--scope", str(scope_file), "--db", str(tmp_path / "x.db")]
    )
    assert code == 3  # refused
    assert "refused" in capsys.readouterr().err


def test_scan_rejects_invalid_scope_file(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("scanme.lab\nnot a host\n", encoding="utf-8")

    monkeypatch.setattr(cli, "NmapPlugin", lambda: FakePlugin([]))
    code = cli.main(
        ["scan", "scanme.lab", "--scope", str(scope_file), "--db", str(tmp_path / "x.db")]
    )
    assert code == 2  # bad input, same as a missing scope file
    err = capsys.readouterr().err
    assert "invalid scope file" in err
    assert "scope.txt:2" in err


def test_scan_failure_is_reported_not_saved(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("scanme.lab\n", encoding="utf-8")
    db = tmp_path / "out.db"

    error = ScanError("nmap exited with code 1", plugin="nmap", stderr="requires root\nQUITTING!")
    monkeypatch.setattr(cli, "NmapPlugin", lambda: FakePlugin([], error=error))

    code = cli.main(["scan", "scanme.lab", "--scope", str(scope_file), "--db", str(db)])
    captured = capsys.readouterr()

    assert code == 4  # scan failed
    assert "scan failed [nmap]: nmap exited with code 1" in captured.err
    assert "  | requires root" in captured.err  # the tool's own stderr is shown
    assert "Traceback" not in captured.err
    assert "Scan run" not in captured.out
    assert not db.exists()  # a failed scan must not be stored as a clean run


def test_scan_without_any_scanner_fails_and_saves_nothing(  # type: ignore[no-untyped-def]
    tmp_path: Path, monkeypatch, capsys
) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("scanme.lab\n", encoding="utf-8")
    db = tmp_path / "out.db"

    monkeypatch.setattr(cli, "NmapPlugin", lambda: FakePlugin([], available=False))
    code = cli.main(["scan", "scanme.lab", "--scope", str(scope_file), "--db", str(db)])
    captured = capsys.readouterr()

    assert code == 4
    assert "scan failed: no scanner available: fake" in captured.err
    assert "Scan run" not in captured.out
    assert not db.exists()  # "could not scan" must never be stored as "clean"
