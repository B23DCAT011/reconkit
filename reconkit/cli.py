"""Command-line entry point: `reconkit scan <target> --scope <file>`.

Wires the pieces of the vertical slice together: load scope -> build orchestrator
with the nmap plugin -> run -> persist to SQLite -> print a summary.
"""

from __future__ import annotations

import argparse
import sys

from reconkit.cve import LocalCveSource
from reconkit.orchestrator import Orchestrator, ScanRun
from reconkit.plugins.nmap import NmapPlugin
from reconkit.scope import Scope, ScopeError
from reconkit.storage import Storage


def _print_summary(run: ScanRun, run_id: int, db_path: str) -> None:
    services = [s for a in run.assets for s in a.services]
    findings = [f for a in run.assets for f in a.findings]
    print(f"\nScan run #{run_id}  target={run.target}  (saved to {db_path})")
    print(f"  services: {len(services)}   findings: {len(findings)}\n")
    if services:
        print(f"  {'PORT':<9}{'SERVICE':<12}{'PRODUCT / VERSION'}")
        print(f"  {'-' * 9}{'-' * 12}{'-' * 20}")
        for s in services:
            pv = " ".join(p for p in (s.product, s.version) if p) or "-"
            print(f"  {f'{s.port}/{s.protocol}':<9}{(s.name or '-'):<12}{pv}")
    for f in findings:
        print(f"  [{f.severity.upper()}] {f.title}" + (f" ({f.cve})" if f.cve else ""))


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        scope = Scope.from_file(args.scope)
    except FileNotFoundError:
        print(f"error: scope file not found: {args.scope}", file=sys.stderr)
        return 2

    if args.no_cve:
        cve_source = None
    elif args.cve_db:
        cve_source = LocalCveSource(args.cve_db)
    else:
        cve_source = LocalCveSource()  # bundled seed
    orch = Orchestrator(plugins=[NmapPlugin()], scope=scope, cve_source=cve_source)
    try:
        run = orch.run(args.target)
    except ScopeError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    with Storage(args.db) as store:
        run_id = store.save_run(run)
    _print_summary(run, run_id, args.db)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconkit",
        description="Recon orchestrator & vulnerability management (academic project).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a single target in scope")
    scan.add_argument("target", help="domain, IP, or CIDR to scan")
    scan.add_argument(
        "--scope", required=True, help="path to the allowlist file (one entry per line)"
    )
    scan.add_argument("--db", default="reconkit.db", help="SQLite database path")
    scan.add_argument("--no-cve", action="store_true", help="skip the CVE matching stage")
    scan.add_argument("--cve-db", help="path to a CVE seed JSON (default: bundled seed)")
    scan.set_defaults(func=_cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = args.func  # set by the chosen subcommand
    return int(func(args))


if __name__ == "__main__":
    raise SystemExit(main())
