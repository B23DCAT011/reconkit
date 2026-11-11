"""End-to-end CLI tests using a fake plugin and fake DNS injected via monkeypatch."""

from pathlib import Path

import pytest
from conftest import FakePlugin, fake_resolver, lab_asset, lab_resolver

from reconkit import cli
from reconkit.plugins.base import ScanError
from reconkit.schema import Service
from reconkit.storage import Storage

LAB_SCOPE = "scanme.lab\n10.0.0.0/24\n"


@pytest.fixture(autouse=True)
def _lab_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer DNS from the lab records: no test may depend on the real resolver."""
    monkeypatch.setattr("reconkit.scope.resolve_ipv4", lab_resolver)


def _scope_file(tmp_path: Path, text: str = LAB_SCOPE) -> str:
    path = tmp_path / "scope.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_scan_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"

    # Replace the real nmap plugin with a deterministic fake.
    fake = FakePlugin([lab_asset(Service(port=22, name="ssh", product="OpenSSH", version="7.4"))])
    monkeypatch.setattr(cli, "NmapPlugin", lambda: fake)

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])
    out = capsys.readouterr().out

    assert code == 0
    assert db.exists()
    assert "Scan run #1" in out
    assert "resolved: scanme.lab -> 10.0.0.5" in out
    assert "hosts: 1 " in out
    assert "scanme.lab (10.0.0.5)" in out
    assert "22/tcp" in out
    assert "OpenSSH 7.4" in out
    assert "CVE-2018-15473" in out
    assert fake.seen[0].addresses == ("10.0.0.5",)  # the plugin scanned the address


def test_range_scan_is_reported_and_stored_per_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"
    fake = FakePlugin(
        [
            lab_asset(Service(port=22, name="ssh"), host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(host="10.0.0.7", ip="10.0.0.7"),  # up, nothing open
        ]
    )
    monkeypatch.setattr(cli, "NmapPlugin", lambda: fake)

    code = cli.main(["scan", "10.0.0.0/24", "--scope", _scope_file(tmp_path), "--db", str(db)])
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


def test_range_scan_excludes_denied_addresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakePlugin([lab_asset(host="10.0.0.5", ip="10.0.0.5")])
    monkeypatch.setattr(cli, "NmapPlugin", lambda: fake)
    scope = _scope_file(tmp_path, "10.0.0.0/24\n!10.0.0.1  # router\n")

    code = cli.main(["scan", "10.0.0.0/24", "--scope", scope, "--db", str(tmp_path / "x.db")])
    out = capsys.readouterr().out

    assert code == 0
    assert fake.seen[0].exclude == ("10.0.0.1",)
    assert "excluded (denylist): 10.0.0.1" in out
    assert "responded of 255 addresses" in out  # the denied address is not counted


def test_scan_refuses_out_of_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "NmapPlugin", lambda: FakePlugin([]))
    code = cli.main(
        [
            "scan",
            "evil.example.com",
            "--scope",
            _scope_file(tmp_path),
            "--db",
            str(tmp_path / "x.db"),
        ]
    )
    assert code == 3  # refused
    assert "refused" in capsys.readouterr().err


def test_scan_refuses_name_pointing_outside_the_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # G4: the name is in the allowlist, the machine behind it is not.
    fake = FakePlugin([])
    monkeypatch.setattr(cli, "NmapPlugin", lambda: fake)
    monkeypatch.setattr(
        "reconkit.scope.resolve_ipv4", fake_resolver({"scanme.lab": ["203.0.113.9"]})
    )
    db = tmp_path / "x.db"

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])
    err = capsys.readouterr().err

    assert code == 3
    assert "refused" in err
    assert "resolves to 203.0.113.9" in err
    assert fake.seen == []  # nothing was scanned
    assert not db.exists()


def test_scan_of_unresolvable_name_fails_and_saves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "NmapPlugin", lambda: FakePlugin([]))
    monkeypatch.setattr("reconkit.scope.resolve_ipv4", fake_resolver({}))
    db = tmp_path / "x.db"

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])
    err = capsys.readouterr().err

    assert code == 4
    assert "scan failed: cannot resolve 'scanme.lab'" in err
    assert not db.exists()


def test_out_of_scope_host_in_results_is_warned_about_and_not_saved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakePlugin(
        [
            lab_asset(host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(host="192.0.2.50", ip="192.0.2.50"),  # the tool strayed
        ]
    )
    monkeypatch.setattr(cli, "NmapPlugin", lambda: fake)
    db = tmp_path / "out.db"

    code = cli.main(["scan", "10.0.0.0/24", "--scope", _scope_file(tmp_path), "--db", str(db)])
    captured = capsys.readouterr()

    assert code == 0
    assert "outside the scope; not saved: 192.0.2.50" in captured.err
    assert "192.0.2.50" not in captured.out
    with Storage(db) as store:
        rows = store._conn.execute("SELECT ip FROM asset").fetchall()
    assert [r["ip"] for r in rows] == ["10.0.0.5"]


def test_scan_rejects_invalid_scope_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "NmapPlugin", lambda: FakePlugin([]))
    scope = _scope_file(tmp_path, "scanme.lab\nnot a host\n")
    code = cli.main(["scan", "scanme.lab", "--scope", scope, "--db", str(tmp_path / "x.db")])
    assert code == 2  # bad input, same as a missing scope file
    err = capsys.readouterr().err
    assert "invalid scope file" in err
    assert "scope.txt:2" in err


def test_scan_failure_is_reported_not_saved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"
    error = ScanError("nmap exited with code 1", plugin="nmap", stderr="requires root\nQUITTING!")
    monkeypatch.setattr(cli, "NmapPlugin", lambda: FakePlugin([], error=error))

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])
    captured = capsys.readouterr()

    assert code == 4  # scan failed
    assert "scan failed [nmap]: nmap exited with code 1" in captured.err
    assert "  | requires root" in captured.err  # the tool's own stderr is shown
    assert "Traceback" not in captured.err
    assert "Scan run" not in captured.out
    assert not db.exists()  # a failed scan must not be stored as a clean run


def test_scan_without_any_scanner_fails_and_saves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"
    monkeypatch.setattr(cli, "NmapPlugin", lambda: FakePlugin([], available=False))

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])
    captured = capsys.readouterr()

    assert code == 4
    assert "scan failed: no scanner available: fake" in captured.err
    assert "Scan run" not in captured.out
    assert not db.exists()  # "could not scan" must never be stored as "clean"
