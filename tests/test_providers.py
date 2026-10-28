import unittest

from iam_agent import MockProvider, NewHire


class TestMockProvider(unittest.TestCase):
    def setUp(self):
        self.provider = MockProvider()
        self.hire = NewHire("Ada", "Lovelace", "ada.lovelace",
                            "Engineering", "engineer")

    def test_create_then_disable(self):
        self.provider.create_user(self.hire)
        self.provider.disable_user("ada.lovelace")
        self.assertFalse(self.provider.users["ada.lovelace"]["active"])

    def test_duplicate_create_raises(self):
        self.provider.create_user(self.hire)
        with self.assertRaises(ValueError):
            self.provider.create_user(self.hire)

    def test_group_and_license_do_not_duplicate(self):
        self.provider.create_user(self.hire)
        self.provider.add_to_group("ada.lovelace", "engineering")
        self.provider.add_to_group("ada.lovelace", "engineering")
        self.assertEqual(
            self.provider.users["ada.lovelace"]["groups"], ["engineering"])

    def test_unknown_user_raises(self):
        with self.assertRaises(ValueError):
            self.provider.add_to_group("ghost", "engineering")


if __name__ == "__main__":
    unittest.main()
