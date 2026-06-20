import logging
from contextlib import contextmanager

import pymysql
import pymysql.constants
from pymysql.constants import CLIENT

from config import IS_DEBUG
from mysql_config import MYSQL_CONFIG

logger = logging.getLogger("utils")

# MySQL database configuration


def sql_connect() -> pymysql.connections.Connection | None:
    """
    Establish a connection to the MySQL database.
    """
    try:
        return pymysql.connect(
            host=MYSQL_CONFIG["host"],
            port=MYSQL_CONFIG["port"],
            user=MYSQL_CONFIG["user"],
            password=MYSQL_CONFIG["password"],
            database=MYSQL_CONFIG["database"],
            # TAMBAHAN: Izinkan eksekusi multi-statement untuk simulasi Stacked Queries
            client_flag=CLIENT.MULTI_STATEMENTS,
        )
    except pymysql.Error as err:
        if IS_DEBUG == "1":
            logger.error("DB connection error: %s", err)
            print(f"[DB ERROR] {err}")
        return None


@contextmanager
def db_session():
    """
    Context manager untuk koneksi database MySQL.
    Menjamin koneksi ditutup secara otomatis saat keluar dari block 'with'.
    """
    conn = sql_connect()
    try:
        yield conn
    finally:
        if conn:
            conn.close()


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
