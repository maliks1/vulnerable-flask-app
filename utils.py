import os
import sqlite3
import logging

logger = logging.getLogger("utils")

DB_PATH = "users.db"

def sql_connect(db_path: str = DB_PATH) -> sqlite3.Connection | None:
    """
    Establish a connection to the SQLite database.
    """
    try:
        return sqlite3.connect(db_path)
    except sqlite3.Error as err:
        logger.error("DB connection error: %s", err)
        print(f"[DB ERROR] {err}")
        return None

def parse_statements(raw_sql: str) -> list[str]:
    """
    Split a raw SQL string into individual statements on ';',
    while correctly handling single-quoted string literals
    (including SQL-escaped '' quotes inside strings).

    Example:
        "SELECT * FROM users; DROP TABLE users"
        -> ["SELECT * FROM users", "DROP TABLE users"]

        "SELECT * FROM users WHERE name='O''Brien'; SELECT 1"
        -> ["SELECT * FROM users WHERE name='O''Brien'", "SELECT 1"]
    """
    statements: list[str] = []
    buf: list[str] = []
    in_str = False
    i = 0

    while i < len(raw_sql):
        ch = raw_sql[i]

        if in_str:
            buf.append(ch)
            if ch == "'":
                # Escaped quote '' stays inside the string
                if i + 1 < len(raw_sql) and raw_sql[i + 1] == "'":
                    buf.append("'")
                    i += 1
                else:
                    in_str = False
        elif ch == "'":
            in_str = True
            buf.append(ch)
        elif ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
        else:
            buf.append(ch)

        i += 1

    # Trailing statement without a semicolon
    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)

    return statements
