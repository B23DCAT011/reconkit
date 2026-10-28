"""SQLite persistence via a thin repository.

One `scan_run` (with all its assets, services and findings) is written inside a single
transaction, so a crash mid-write rolls back cleanly rather than leaving half a scan
in the database (GHI-CHU.md section 6). The repository hides SQL behind methods, so
swapping SQLite for PostgreSQL later is a storage-layer change only.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

from reconkit.schema import Finding, Service, Severity

if TYPE_CHECKING:
    from reconkit.orchestrator import ScanRun

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_run (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS asset (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  INTEGER NOT NULL REFERENCES scan_run(id),
    host    TEXT NOT NULL,
    ip      TEXT
);
CREATE TABLE IF NOT EXISTS service (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id  INTEGER NOT NULL REFERENCES asset(id),
    port      INTEGER NOT NULL,
    protocol  TEXT NOT NULL,
    state     TEXT NOT NULL,
    name      TEXT,
    product   TEXT,
    version   TEXT,
    cpe       TEXT,
    banner    TEXT
);
CREATE TABLE IF NOT EXISTS finding (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL REFERENCES asset(id),
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    cve         TEXT,
    description TEXT,
    evidence    TEXT,
    fingerprint TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_fingerprint ON finding(fingerprint);
"""


class Storage:
    """A SQLite-backed repository for scan results."""

    def __init__(self, path: str | Path = "reconkit.db") -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Storage:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def save_run(self, run: ScanRun) -> int:
        """Persist a whole scan run atomically; return the new run id."""
        with self._conn:  # BEGIN ... COMMIT, or ROLLBACK on exception
            cur = self._conn.execute(
                "INSERT INTO scan_run (target, started_at, finished_at) VALUES (?, ?, ?)",
                (run.target, run.started_at, run.finished_at),
            )
            run_id = int(cur.lastrowid or 0)
            for asset in run.assets:
                cur = self._conn.execute(
                    "INSERT INTO asset (run_id, host, ip) VALUES (?, ?, ?)",
                    (run_id, asset.host, asset.ip),
                )
                asset_id = int(cur.lastrowid or 0)
                self._insert_services(asset_id, asset.services)
                self._insert_findings(asset_id, asset.findings)
        return run_id

    def _insert_services(self, asset_id: int, services: list[Service]) -> None:
        self._conn.executemany(
            "INSERT INTO service "
            "(asset_id, port, protocol, state, name, product, version, cpe, banner) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    asset_id,
                    s.port,
                    s.protocol,
                    s.state,
                    s.name,
                    s.product,
                    s.version,
                    s.cpe,
                    s.banner,
                )
                for s in services
            ],
        )

    def _insert_findings(self, asset_id: int, findings: list[Finding]) -> None:
        rows = []
        for f in findings:
            fp = f.fingerprint or f.compute_fingerprint()
            rows.append((asset_id, f.title, str(f.severity), f.cve, f.description, f.evidence, fp))
        self._conn.executemany(
            "INSERT INTO finding "
            "(asset_id, title, severity, cve, description, evidence, fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    def services_for_run(self, run_id: int) -> list[Service]:
        """Read back the services recorded for a run (used by tests/reporting)."""
        rows = self._conn.execute(
            "SELECT s.* FROM service s "
            "JOIN asset a ON a.id = s.asset_id WHERE a.run_id = ? ORDER BY s.port",
            (run_id,),
        ).fetchall()
        return [
            Service(
                port=r["port"],
                protocol=r["protocol"],
                state=r["state"],
                name=r["name"],
                product=r["product"],
                version=r["version"],
                cpe=r["cpe"],
                banner=r["banner"],
            )
            for r in rows
        ]

    def findings_for_run(self, run_id: int) -> list[Finding]:
        """Read back the findings recorded for a run."""
        rows = self._conn.execute(
            "SELECT f.*, a.host FROM finding f "
            "JOIN asset a ON a.id = f.asset_id WHERE a.run_id = ?",
            (run_id,),
        ).fetchall()
        return [
            Finding(
                asset=r["host"],
                title=r["title"],
                severity=Severity(r["severity"]),
                cve=r["cve"],
                description=r["description"] or "",
                evidence=r["evidence"] or "",
                fingerprint=r["fingerprint"],
            )
            for r in rows
        ]
