"""Command-line entry point: `reconkit scan <target> --scope <file>`.

Wires the pieces of the vertical slice together: load scope -> build orchestrator
with the nmap plugin -> run -> persist to SQLite -> print a summary.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys

from reconkit.cve import LocalCveSource
from reconkit.orchestrator import NoPluginAvailableError, Orchestrator, ScanRun
from reconkit.plugins.base import ScanError
from reconkit.plugins.nmap import NmapPlugin
from reconkit.scope import ResolutionError, Scope, ScopeError
from reconkit.storage import Storage


def _print_summary(run: ScanRun, run_id: int, db_path: str) -> None:
    services = [s for a in run.assets for s in a.services]
    findings = [f for a in run.assets for f in a.findings]
    print(f"\nScan run #{run_id}  target={run.target}  (saved to {db_path})")
    plan = run.plan
    if plan is not None and plan.hostname:
        print(f"  resolved: {plan.hostname} -> {', '.join(plan.addresses)}")
    if plan is not None and plan.exclude:
        print(f"  excluded (denylist): {', '.join(plan.exclude)}")
    print(f"  hosts: {_hosts_summary(run)}   services: {len(services)}   findings: {len(findings)}")
    for asset in run.assets:
        label = asset.host if asset.ip in (None, asset.host) else f"{asset.host} ({asset.ip})"
        print(f"\n  {label}")
        if not asset.services:
            print("    no open ports found")
            continue
        print(f"    {'PORT':<11}{'SERVICE':<16}{'PRODUCT / VERSION'}")
        print(f"    {'-' * 10} {'-' * 15} {'-' * 20}")
        for s in asset.services:
            pv = " ".join(p for p in (s.product, s.version) if p) or "-"
            print(f"    {f'{s.port}/{s.protocol}':<11}{(s.name or '-'):<16}{pv}")
        for f in asset.findings:
            print(f"    [{f.severity.upper()}] {f.title}" + (f" ({f.cve})" if f.cve else ""))


def _hosts_summary(run: ScanRun) -> str:
    """Hosts that responded; for a range target, out of how many addresses scanned."""
    found = len(run.assets)
    plan = run.plan
    if plan is None or plan.hostname:
        return str(found)  # a name: no range to compare against
    size = sum(_size(a) for a in plan.addresses) - sum(_size(e) for e in plan.exclude)
    # The silent addresses are not listed: they may be unused, down, or filtered.
    return f"{found} responded of {size} addresses" if size > 1 else str(found)


def _size(network: str) -> int:
    return ipaddress.ip_network(network, strict=False).num_addresses


def _indent(text: str, prefix: str = "  | ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        scope = Scope.from_file(args.scope)
    except FileNotFoundError:
        print(f"error: scope file not found: {args.scope}", file=sys.stderr)
        return 2
    except ScopeError as exc:
        print(f"error: invalid scope file: {exc}", file=sys.stderr)
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
    except (NoPluginAvailableError, ResolutionError) as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        return 4
    except ScanError as exc:
        # A failed scan is never saved: an empty run would read as "nothing found".
        print(f"scan failed [{exc.plugin}]: {exc}", file=sys.stderr)
        if exc.stderr:
            print(_indent(exc.stderr), file=sys.stderr)
        return 4
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if run.skipped_plugins:
        skipped = ", ".join(run.skipped_plugins)
        print(f"warning: skipped unavailable scanners: {skipped}", file=sys.stderr)
    if run.out_of_scope:
        dropped = ", ".join(run.out_of_scope)
        print(
            f"warning: a scanner reported hosts outside the scope; not saved: {dropped}",
            file=sys.stderr,
        )

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
