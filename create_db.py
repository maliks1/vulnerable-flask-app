from config import IS_DEBUG
from utils import db_session
import pymysql
from mysql_config import MYSQL_CONFIG

if IS_DEBUG != "1":
    def print(*args, **kwargs):
        pass

# DB_PATH = 'users.db'  # SQLite path (kept for reference)

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
    """
    Initialize MySQL database.
    Creates database if it doesn't exist, then creates tables and seeds data.
    """
    # First, create database if it doesn't exist
    try:
        # Connect without specifying database to create it
        conn = pymysql.connect(
            host=MYSQL_CONFIG['host'],
            port=MYSQL_CONFIG['port'],
            user=MYSQL_CONFIG['user'],
            password=MYSQL_CONFIG['password']
        )
        cursor = conn.cursor()

        # Create database if not exists
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {MYSQL_CONFIG['database']}")
        cursor.execute(f"USE {MYSQL_CONFIG['database']}")
        conn.commit()
        cursor.close()
        conn.close()
        print(f"Database '{MYSQL_CONFIG['database']}' created or already exists")
    except pymysql.Error as err:
        print(f"Error creating database: {err}")
        return

    # Now connect to the database and create tables
    with db_session() as conn:
        if conn is None:
            print("Failed to connect to database after creation")
            return

        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL
            )
            """
        )

        # Use INSERT IGNORE for MySQL compatibility
        cursor.executemany(
            "INSERT IGNORE INTO users (username, password) VALUES (%s, %s)",
            DUMMY_USERS
        )

        # Create stored procedure for SQL injection testing
        try:
            cursor.execute("""
            DROP PROCEDURE IF EXISTS test_procedure
            """)
            cursor.execute("""
            CREATE PROCEDURE test_procedure()
            BEGIN
                SELECT 'Stored procedure executed successfully! This can be exploited via SQL injection.';
            END
            """)
            print('Stored procedure "test_procedure" created successfully.')
        except pymysql.Error as err:
            print(f'Error creating stored procedure: {err}')

        conn.commit()
        cursor.close()
        print(f'MySQL database initialized successfully')
        print(f'Dummy users seeded: {len(DUMMY_USERS)} entries (INSERT IGNORE).')

if __name__ == '__main__':
    initialize_database()