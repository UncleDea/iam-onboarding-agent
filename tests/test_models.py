import unittest

from iam_agent.models import NewHire


def hire(**overrides):
    base = dict(first_name="Ada", last_name="Lovelace",
                username="ada.lovelace", department="Engineering",
                role="engineer")
    base.update(overrides)
    return NewHire(**base)


class TestNewHireValidation(unittest.TestCase):
    def test_valid_hire(self):
        self.assertEqual(hire().display_name, "Ada Lovelace")

    def test_blank_name_rejected(self):
        with self.assertRaises(ValueError):
            hire(first_name="  ")

    def test_blank_role_rejected(self):
        with self.assertRaises(ValueError):
            hire(role="")

    def test_uppercase_username_rejected(self):
        with self.assertRaises(ValueError):
            hire(username="Ada.Lovelace")

    def test_username_with_space_rejected(self):
        with self.assertRaises(ValueError):
            hire(username="ada lovelace")

    def test_short_username_rejected(self):
        with self.assertRaises(ValueError):
            hire(username="ab")


if __name__ == "__main__":
    unittest.main()
