"""Tenant-scoped document queries."""

import sqlite3
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Document:
    document_id: int
    tenant_id: str
    title: str
    archived: bool


def list_documents(
    connection: sqlite3.Connection, tenant_id: str, include_archived: bool = False
) -> List[Document]:
    if include_archived:
        rows = connection.execute(
            "SELECT id, tenant_id, title, archived FROM documents ORDER BY id"
        ).fetchall()
    else:
        rows = connection.execute(
            """
            SELECT id, tenant_id, title, archived
            FROM documents
            WHERE tenant_id = ? AND archived = 0
            ORDER BY id
            """,
            (tenant_id,),
        ).fetchall()

    return [
        Document(
            document_id=int(row[0]),
            tenant_id=str(row[1]),
            title=str(row[2]),
            archived=bool(row[3]),
        )
        for row in rows
    ]
