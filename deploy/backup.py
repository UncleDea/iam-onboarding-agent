"""Back up the IAM database safely.

Usage:
    python3 deploy/backup.py --db iam.db --dir backups --keep-days 7

Uses SQLite's online backup API, so the app does not need to stop
(the backup is a consistent snapshot even while the app runs).
Files are named iam-YYYYMMDD-HHMMSS.db; files older than
--keep-days are deleted. Run it from cron, e.g. nightly:

    0 2 * * * /usr/bin/python3 /opt/iam-app/deploy/backup.py \
        --db /opt/iam-app/iam.db --dir /var/backups/iam-app

Restore: stop the app, copy the backup over iam.db, start the app,
then prove the audit log survived intact:

    python -m iam_agent.cli --provider sqlite --db iam.db --verify-audit
"""

import argparse
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Back up the IAM database")
    parser.add_argument("--db", required=True, help="database file to back up")
    parser.add_argument("--dir", required=True, help="backup directory")
    parser.add_argument("--keep-days", type=int, default=7)
    args = parser.parse_args(argv)

    source = Path(args.db)
    if not source.exists():
        print(f"error: database {source} does not exist", file=sys.stderr)
        return 2
    backup_dir = Path(args.dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = backup_dir / f"iam-{stamp}.db"
    source_conn = sqlite3.connect(str(source))
    try:
        target_conn = sqlite3.connect(str(target))
        try:
            source_conn.backup(target_conn)
        finally:
            target_conn.close()
    finally:
        source_conn.close()
    print(f"backup written: {target}")

    cutoff = datetime.now() - timedelta(days=args.keep_days)
    for old in backup_dir.glob("iam-*.db"):
        try:
            stamp = datetime.strptime(old.stem[4:], "%Y%m%d-%H%M%S")
        except ValueError:
            continue
        if stamp < cutoff:
            old.unlink()
            print(f"pruned old backup: {old}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
