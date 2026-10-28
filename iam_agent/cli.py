"""Command-line entry point for the real system.

On-board, move, off-board, and review, against either the mock
provider (default, nothing persists) or the SQLite provider (state
lives in a database file that survives restarts).

Examples (from the project folder):

    python -m iam_agent.cli --dry-run
    python -m iam_agent.cli --provider sqlite --db iam.db --audit-file audit.jsonl
    python -m iam_agent.cli --provider sqlite --db iam.db --review
    python -m iam_agent.cli --provider sqlite --db iam.db --offboard bob.builder
    python -m iam_agent.cli --provider sqlite --db iam.db --move bob.builder --new-role manager
    python -m iam_agent.cli --hires hires.csv --requester alice.admin

hires.csv columns: first_name,last_name,username,department,role,
manager,start_date,email (email optional; without it the welcome
email step is skipped and noted in the audit log). Without --hires,
two demo hires are used.

Welcome emails use the sender from iam_agent.emailing: SMTP when
IAM_SMTP_* is set, console output when IAM_EMAIL_CONSOLE=1, and
skipped otherwise.

--auto-approve skips the human prompt. It exists for scripted tests
only and prints a loud warning: a real deployment must never run
unattended against a real provider. Off-board and move operations
always ask a human directly (bypassing the auto-approval router),
because removing or changing access is the operation most worth a
second pair of eyes -- unless --auto-approve is explicitly given.
"""

import argparse
import csv
import json
import logging
import sys

from .approval import make_approver, terminal_human_approver
from .audit_store import SqliteAuditStore
from .emailing import email_sender_from_env
from .engine import OnboardingAgent
from .entra_provider import EntraProvider
from .models import NewHire
from .notifiers import ConsoleNotifier
from .providers import MockProvider
from .sqlite_provider import SqliteProvider

_DEMO_HIRES = [
    NewHire("Ada", "Lovelace", "ada.lovelace", "Engineering",
            "engineer", manager="carol.manager", start_date="2026-11-02"),
    NewHire("Bob", "Builder", "bob.builder", "Sales",
            "sales", manager="carol.manager", start_date="2026-11-02"),
]


def load_hires_csv(path: str) -> list:
    hires = []
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            hires.append(NewHire(
                first_name=row["first_name"],
                last_name=row["last_name"],
                username=row["username"],
                department=row["department"],
                role=row["role"],
                manager=row.get("manager", ""),
                start_date=row.get("start_date", ""),
                email=row.get("email", ""),
            ))
    if not hires:
        raise ValueError(f"no hires found in {path}")
    return hires


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="IAM system: on-board, move, off-board, review")
    parser.add_argument("--provider", choices=["mock", "sqlite", "entra"],
                        default="mock",
                        help="identity store: mock (nothing persists), "
                             "sqlite (local database), or entra (real "
                             "Microsoft Entra ID via Graph; needs the "
                             "IAM_ENTRA_* environment variables)")
    parser.add_argument("--db", default="iam.db",
                        help="SQLite file for --provider sqlite and the audit store")
    parser.add_argument("--dry-run", action="store_true",
                        help="print plans, change nothing")
    parser.add_argument("--auto-approve", action="store_true",
                        help="skip the human prompt for on-boarding (tests only)")
    parser.add_argument("--audit-file", default=None,
                        help="append audit entries as JSON lines to this file")
    parser.add_argument("--audit-db", action="store_true",
                        help="write audit entries to a hash-chained SQLite "
                             "store (on by default with --provider sqlite)")
    parser.add_argument("--hires", default=None,
                        help="CSV file of hires (see module docstring)")
    parser.add_argument("--requester", default=None,
                        help="who requested this change (can never approve it)")
    parser.add_argument("--notify", action="store_true",
                        help="print a notification line per completed run")
    parser.add_argument("--review", action="store_true",
                        help="print every user and their access, then exit")
    parser.add_argument("--offboard", default=None, metavar="USERNAME",
                        help="off-board one user (always asks a human)")
    parser.add_argument("--move", default=None, metavar="USERNAME",
                        help="move one user to --new-role")
    parser.add_argument("--new-role", default=None,
                        help="target role for --move")
    parser.add_argument("--report", default=None,
                        choices=["access", "activity", "approvals",
                                 "summary"],
                        help="print a report and exit")
    parser.add_argument("--verify-audit", action="store_true",
                        help="verify the hash-chained audit log and exit "
                             "(use after a restore to prove the log is "
                             "intact)")
    parser.add_argument("--format", default="json", choices=["json", "csv"],
                        help="report output format (default: json)")
    return parser


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)

    try:
        if args.provider == "sqlite":
            provider = SqliteProvider(args.db)
        elif args.provider == "entra":
            provider = EntraProvider.from_env()
        else:
            provider = MockProvider()
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    # A real system audits by default: with a persistent provider,
    # the hash-chained audit store is on unless explicitly disabled.
    # The mock provider stays side-effect free.
    audit_store = (SqliteAuditStore(args.db)
                   if (args.audit_db or args.provider in ("sqlite", "entra"))
                   else None)
    notifier = ConsoleNotifier() if args.notify else None

    if args.verify_audit:
        if audit_store is None:
            print("no audit store configured for this provider")
            return 2
        valid = audit_store.verify()
        print(f"audit chain valid: {valid}")
        audit_store.close()
        if args.provider == "sqlite":
            provider.close()
        return 0 if valid else 1

    if args.review:
        if args.provider == "mock":
            print("review needs --provider sqlite or entra (the mock "
                  "holds nothing between runs)")
            return 2
        print(json.dumps(provider.list_users(), indent=2))
        return 0

    if args.report:
        from .db import Database
        from .migrations import migrate
        from .reporting import (access_report, activity_report,
                                approval_report, summary_report, to_csv,
                                to_json)
        from .requests import RequestStore
        db = Database(args.db)
        migrate(db)
        reports = {
            "access": access_report(provider),
            "activity": activity_report(
                audit_store.list_entries(10000) if audit_store else []),
            "approvals": approval_report(RequestStore(db).list()),
            "summary": summary_report(
                provider,
                audit_store.list_entries(10000) if audit_store else [],
                RequestStore(db).list()),
        }
        report = reports[args.report]
        if args.format == "csv":
            print(to_csv(report, args.report), end="")
        else:
            print(to_json(report))
        return 0

    # On-boarding may auto-approve in tests. Move/offboard always ask a
    # human directly, bypassing the router's auto-approval path.
    if args.auto_approve:
        print("WARNING: --auto-approve: running without human approval. "
              "Tests only; never use this against a real provider.")
        approver = make_approver(lambda p, h: True, human_name="auto")
    elif args.offboard or args.move:
        approver = terminal_human_approver
    else:
        approver = make_approver(terminal_human_approver,
                                 human_name="terminal-user")
    agent = OnboardingAgent(provider, approver=approver,
                            audit_file=args.audit_file,
                            audit_store=audit_store, notifier=notifier,
                            email_sender=email_sender_from_env())

    try:
        if args.offboard:
            result = agent.offboard(args.offboard, dry_run=args.dry_run,
                                    requester=args.requester)
            print(f"  [{args.offboard}] offboard status: {result['status']}")
            return 0 if result["status"] in ("done", "dry-run") else 1
        if args.move:
            if not args.new_role:
                print("--move needs --new-role")
                return 2
            result = agent.move(args.move, args.new_role,
                                dry_run=args.dry_run,
                                requester=args.requester)
            print(f"  [{args.move}] move status: {result['status']}")
            return 0 if result["status"] in ("done", "dry-run") else 1

        hires = load_hires_csv(args.hires) if args.hires else _DEMO_HIRES
        overall_ok = True
        for hire in hires:
            try:
                result = agent.run(hire, dry_run=args.dry_run,
                                   requester=args.requester)
            except ValueError as exc:
                # Plan-time refusal (e.g. segregation-of-duties
                # conflict): nothing was created, and the reason is
                # the whole point.
                print(f"  [{hire.username}] REFUSED: {exc}")
                overall_ok = False
                continue
            print(f"  [{hire.username}] status: {result['status']}")
            overall_ok = overall_ok and result["status"] in ("done", "dry-run")
        return 0 if overall_ok else 1
    finally:
        if audit_store is not None:
            audit_store.close()
        if args.provider == "sqlite":
            provider.close()


if __name__ == "__main__":
    sys.exit(main())
