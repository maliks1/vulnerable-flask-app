import sqlite3

DB_PATH = 'users.db'

DUMMY_USERS = [
    ('admin', 'admin123'),
    ('alice', 'alice123'),
    ('bob', 'bob123'),
    ('charlie', 'charlie123'),
    ('diana', 'diana123'),
    ('evan', 'evan123'),
    ('farah', 'farah123'),
    ('guest', 'guest123'),
    ('test', 'test123'),
    ('demo', 'demo123')
]

def initialize_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
        """
    )

    cursor.executemany(
        "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
        DUMMY_USERS
    )

    conn.commit()
    cursor.close()
    conn.close()
    print(f'SQLite database initialized successfully at {DB_PATH}')
    print(f'Dummy users seeded: {len(DUMMY_USERS)} entries (INSERT OR IGNORE).')


if __name__ == '__main__':
    initialize_database()
