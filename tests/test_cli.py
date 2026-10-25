"""End-to-end CLI test using a fake plugin injected via monkeypatch."""

from pathlib import Path

from conftest import FakePlugin

from reconkit import cli
from reconkit.schema import Service


def test_scan_end_to_end(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("scanme.lab\n", encoding="utf-8")
    db = tmp_path / "out.db"

    # Replace the real nmap plugin with a deterministic fake.
    fake = FakePlugin([Service(port=22, name="ssh", product="OpenSSH", version="7.4")])
    monkeypatch.setattr(cli, "NmapPlugin", lambda: fake)

    code = cli.main(["scan", "scanme.lab", "--scope", str(scope_file), "--db", str(db)])
    out = capsys.readouterr().out

    assert code == 0
    assert db.exists()
    assert "Scan run #1" in out
    assert "22/tcp" in out
    assert "OpenSSH 7.4" in out


def test_scan_refuses_out_of_scope(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("scanme.lab\n", encoding="utf-8")

    monkeypatch.setattr(cli, "NmapPlugin", lambda: FakePlugin([]))
    code = cli.main(
        ["scan", "evil.example.com", "--scope", str(scope_file), "--db", str(tmp_path / "x.db")]
    )
    assert code == 3  # refused
    assert "refused" in capsys.readouterr().err
