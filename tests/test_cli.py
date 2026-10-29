import os
import tempfile
import unittest

from iam_agent.auth import AuthStore
from iam_agent.cli import main
from iam_agent.db import Database
from iam_agent.migrations import migrate


class TestCliApproval(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.path)
        db = Database(self.path)
        migrate(db)
        auth = AuthStore(db)
        auth.create_user("alice", "alice-password", "requester")
        auth.create_user("boss", "boss-password1", "approver")
        db.close()

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)
        for suffix in ("-wal", "-shm"):
            extra = self.path + suffix
            if os.path.exists(extra):
                os.unlink(extra)

    def test_dry_run_needs_no_approver(self):
        self.assertEqual(main(["--provider", "mock", "--dry-run"]), 0)

    def test_a_real_run_needs_both_people(self):
        self.assertEqual(
            main(["--provider", "mock", "--db", self.path,
                  "--requester", "alice"]), 2)

    def test_approver_is_looked_up_and_the_hire_is_created(self):
        csv_path = _one_hire()
        try:
            code = main([
                "--provider", "mock", "--db", self.path,
                "--requester", "alice", "--approver", "boss",
                "--hires", csv_path,
            ])
            self.assertEqual(code, 0)
        finally:
            os.unlink(csv_path)


def _one_hire() -> str:
    fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "first_name,last_name,username,department,role,manager,"
            "start_date,email\n"
            "Ada,Lovelace,ada.lovelace,Engineering,engineer,,,\n")
    return path


if __name__ == "__main__":
    unittest.main()
