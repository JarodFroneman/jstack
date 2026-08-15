"""Exact user-directory lookup."""

import sqlite3
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class User:
    user_id: int
    email: str
    display_name: str


def find_users_by_email(connection: sqlite3.Connection, email: str) -> List[User]:
    rows = connection.execute(
        "SELECT id, email, display_name FROM users WHERE email = ? ORDER BY id",
        (email,),
    ).fetchall()
    return [
        User(user_id=int(row[0]), email=str(row[1]), display_name=str(row[2]))
        for row in rows
    ]
