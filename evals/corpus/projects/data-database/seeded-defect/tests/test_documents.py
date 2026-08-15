from pathlib import Path
import sqlite3
import unittest

from src.documents import list_documents


ROOT = Path(__file__).resolve().parents[1]


def database(rows):
    connection = sqlite3.connect(":memory:")
    connection.executescript((ROOT / "schema.sql").read_text(encoding="utf-8"))
    connection.executemany(
        "INSERT INTO documents (id, tenant_id, title, archived) VALUES (?, ?, ?, ?)",
        rows,
    )
    return connection


class DocumentRepositoryTests(unittest.TestCase):
    def test_default_listing_is_tenant_scoped_and_omits_archived(self) -> None:
        connection = database(
            [
                (1, "tenant-a", "Active A", 0),
                (2, "tenant-a", "Archived A", 1),
                (3, "tenant-b", "Active B", 0),
            ]
        )
        self.addCleanup(connection.close)

        documents = list_documents(connection, "tenant-a")
        self.assertEqual([document.title for document in documents], ["Active A"])

    def test_include_archived_preserves_stable_id_order(self) -> None:
        connection = database(
            [
                (8, "tenant-a", "Later", 0),
                (2, "tenant-a", "Earlier", 1),
            ]
        )
        self.addCleanup(connection.close)

        documents = list_documents(connection, "tenant-a", include_archived=True)
        self.assertEqual([document.document_id for document in documents], [2, 8])
        self.assertEqual([document.archived for document in documents], [True, False])


if __name__ == "__main__":
    unittest.main()
