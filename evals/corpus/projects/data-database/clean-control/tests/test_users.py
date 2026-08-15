from pathlib import Path
import sqlite3
import unittest

from src.users import find_users_by_email


ROOT = Path(__file__).resolve().parents[1]


class UserRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.addCleanup(self.connection.close)
        self.connection.executescript(
            (ROOT / "schema.sql").read_text(encoding="utf-8")
        )
        self.connection.executemany(
            "INSERT INTO users (id, email, display_name) VALUES (?, ?, ?)",
            [
                (1, "ada@example.test", "Ada"),
                (2, "grace@example.test", "Grace"),
            ],
        )

    def test_finds_only_the_exact_email(self) -> None:
        users = find_users_by_email(self.connection, "ada@example.test")
        self.assertEqual([user.display_name for user in users], ["Ada"])

    def test_treats_query_syntax_as_literal_data(self) -> None:
        users = find_users_by_email(self.connection, "' OR 1=1 --")
        self.assertEqual(users, [])

    def test_unknown_email_returns_an_empty_result(self) -> None:
        self.assertEqual(
            find_users_by_email(self.connection, "missing@example.test"), []
        )


if __name__ == "__main__":
    unittest.main()
