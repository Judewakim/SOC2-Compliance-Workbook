"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .registry import all_checks, required_permissions


def _policy_document() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "Soc2KitReadOnly",
            "Effect": "Allow",
            "Action": required_permissions(),
            "Resource": "*",
        }],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soc2kit", description="Collect SOC 2 technical evidence from an AWS account.")
    p.add_argument("--version", action="version", version=f"soc2kit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Run checks and write an evidence pack")
    s.add_argument("--profile", help="AWS CLI profile to use (default: standard credential chain)")
    s.add_argument("--role-arn", help="Read-only role to assume in the target account")
    s.add_argument("--external-id", help="External ID required by the role's trust policy")
    s.add_argument("--regions", help="Comma-separated regions (default: all enabled regions)")
    s.add_argument("--checks", help="Comma-separated check IDs (default: all)")
    s.add_argument("--out", default="soc2-evidence", help="Output directory (default: ./soc2-evidence)")
    s.add_argument("--no-zip", action="store_true", help="Skip creating the zip archive")
    s.add_argument("--fail-on-findings", action="store_true",
                   help="Exit with code 2 if any check fails (for CI pipelines)")

    sub.add_parser("list-checks", help="List every check and its SOC 2 mapping")
    sub.add_parser("policy", help="Print the least-privilege IAM policy the scan needs")

    args = p.parse_args(argv)

    if args.cmd == "list-checks":
        for c in all_checks():
            print(f"{c.id:8} {c.severity.value:9} {','.join(c.criteria):14} {c.scope:8} {c.title}")
        return 0

    if args.cmd == "policy":
        print(json.dumps(_policy_document(), indent=2))
        return 0

    from .report import write_pack
    from .runner import build_session, scan

    session = build_session(args.profile, args.role_arn, args.external_id)
    regions = [r.strip() for r in args.regions.split(",")] if args.regions else None
    check_ids = [c.strip().upper() for c in args.checks.split(",")] if args.checks else None

    def progress(i, total, res):
        print(f"\r[{i}/{total}] {res.check.id} {res.region}: {res.status.value}".ljust(60), end="", file=sys.stderr)

    result = scan(session, regions=regions, check_ids=check_ids, progress=progress)
    print(file=sys.stderr)
    summary = write_pack(result, args.out, make_zip=not args.no_zip)
    c = summary["counts"]
    print(f"Account {summary['account_id']}: score {summary['score']}% of controls passing "
          f"({c['PASS']} pass, {c['FAIL']} fail, {c['ERROR']} could not be evaluated, {c['N/A']} not applicable "
          f"across {len(summary['regions'])} regions)")
    print(f"Evidence pack written to {args.out}/ (open report.html)")
    if c["ERROR"]:
        print("Some checks could not run - see the ERROR rows. Usually a missing permission.", file=sys.stderr)
    return 2 if args.fail_on_findings and c["FAIL"] else 0
