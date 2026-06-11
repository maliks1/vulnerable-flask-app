#!/usr/bin/env python3
"""
MySQL Migration Script

This script handles:
1. Backup of existing SQLite database
2. Migration of data from SQLite to MySQL
3. Verification of migration success

Usage:
    python mysql_migration.py [--backup-only] [--migrate] [--verify]
"""

import os
import sqlite3
import pymysql
import argparse
import subprocess
from datetime import datetime
from mysql_config import MYSQL_CONFIG

# SQLite configuration
SQLITE_DB = "users.db"
BACKUP_DIR = "backups"

def ensure_backup_dir():
    """Ensure backup directory exists"""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

def backup_sqlite_db():
    """
    Backup SQLite database to SQL file using Python's sqlite3 module
    Returns: path to backup file
    """
    ensure_backup_dir()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"sqlite_backup_{timestamp}.sql")

    try:
        # Use Python's sqlite3 module to dump database
        conn = sqlite3.connect(SQLITE_DB)
        cursor = conn.cursor()

        with open(backup_file, 'w') as f:
            # Write schema
            f.write("-- SQLite database backup\n")
            f.write(f"-- Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Get table schema
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
            schema = cursor.fetchone()
            if schema:
                f.write(f"{schema[0]};\n\n")

            # Get data
            cursor.execute("SELECT * FROM users")
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]

            if rows:
                placeholders = ', '.join(['?'] * len(columns))
                insert_stmt = f"INSERT INTO users ({', '.join(columns)}) VALUES ({placeholders});"
                for row in rows:
                    # Escape values properly
                    escaped_row = []
                    for value in row:
                        if value is None:
                            escaped_row.append('NULL')
                        elif isinstance(value, (int, float)):
                            escaped_row.append(str(value))
                        else:
                            escaped_value = str(value).replace("'", "''")
                            escaped_row.append(f"'{escaped_value}'")
                    f.write(f"{insert_stmt.replace(placeholders, ', '.join(escaped_row))}\n")

        conn.close()
        print(f"SQLite backup created: {backup_file}")
        return backup_file
    except sqlite3.Error as e:
        print(f"Error creating SQLite backup: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error creating backup: {e}")
        return None

def get_sqlite_data():
    """
    Extract data from SQLite database
    Returns: dictionary with table data
    """
    try:
        conn = sqlite3.connect(SQLITE_DB)
        cursor = conn.cursor()

        # Get table schema
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
        schema = cursor.fetchone()[0]

        # Get all data from users table
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]

        conn.close()

        return {
            'schema': schema,
            'columns': columns,
            'rows': rows
        }
    except sqlite3.Error as e:
        print(f"Error reading SQLite data: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

def migrate_to_mysql():
    """
    Migrate data from SQLite to MySQL
    Returns: True if migration successful, False otherwise
    """
    # Get data from SQLite
    sqlite_data = get_sqlite_data()
    if not sqlite_data:
        print("Failed to get SQLite data")
        return False

    try:
        # Connect to MySQL
        conn = pymysql.connect(
            host=MYSQL_CONFIG['host'],
            port=MYSQL_CONFIG['port'],
            user=MYSQL_CONFIG['user'],
            password=MYSQL_CONFIG['password'],
            database=MYSQL_CONFIG['database']
        )
        cursor = conn.cursor()

        # Create table (drop if exists)
        cursor.execute("DROP TABLE IF EXISTS users")

        # Create table with MySQL-compatible schema
        # Convert SQLite schema to MySQL
        mysql_schema = sqlite_data['schema'].replace("AUTOINCREMENT", "AUTO_INCREMENT")
        mysql_schema = mysql_schema.replace("INTEGER PRIMARY KEY", "INT PRIMARY KEY")
        mysql_schema = mysql_schema.replace("TEXT", "VARCHAR(255)")

        cursor.execute(mysql_schema)

        # Insert data
        if sqlite_data['rows']:
            placeholders = ', '.join(['%s'] * len(sqlite_data['columns']))
            columns = ', '.join(sqlite_data['columns'])
            insert_query = f"INSERT INTO users ({columns}) VALUES ({placeholders})"

            cursor.executemany(insert_query, sqlite_data['rows'])

        conn.commit()
        cursor.close()
        conn.close()

        print("Data migration to MySQL completed successfully")
        return True

    except pymysql.Error as e:
        print(f"MySQL error during migration: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error during migration: {e}")
        return False

def verify_migration():
    """
    Verify that data was migrated correctly
    Returns: True if verification successful, False otherwise
    """
    try:
        # Get SQLite data
        sqlite_data = get_sqlite_data()
        if not sqlite_data:
            print("Failed to get SQLite data for verification")
            return False

        # Connect to MySQL
        conn = pymysql.connect(
            host=MYSQL_CONFIG['host'],
            port=MYSQL_CONFIG['port'],
            user=MYSQL_CONFIG['user'],
            password=MYSQL_CONFIG['password'],
            database=MYSQL_CONFIG['database']
        )
        cursor = conn.cursor()

        # Get MySQL data
        cursor.execute("SELECT * FROM users")
        mysql_rows = cursor.fetchall()
        mysql_columns = [desc[0] for desc in cursor.description]

        cursor.close()
        conn.close()

        # Compare column names
        if sqlite_data['columns'] != mysql_columns:
            print(f"Column mismatch: SQLite {sqlite_data['columns']} vs MySQL {mysql_columns}")
            return False

        # Compare row counts
        if len(sqlite_data['rows']) != len(mysql_rows):
            print(f"Row count mismatch: SQLite {len(sqlite_data['rows'])} vs MySQL {len(mysql_rows)}")
            return False

        # Compare data (excluding auto-increment IDs which may differ)
        # Create sets of tuples without the ID column (first column)
        sqlite_data_set = {tuple(row[1:]) for row in sqlite_data['rows']}
        mysql_data_set = {tuple(row[1:]) for row in mysql_rows}

        if sqlite_data_set != mysql_data_set:
            print("Data content mismatch")
            return False

        print("Migration verification successful")
        return True

    except pymysql.Error as e:
        print(f"MySQL error during verification: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error during verification: {e}")
        return False

def test_mysql_connection():
    """
    Test MySQL connection
    Returns: True if connection successful, False otherwise
    """
    try:
        conn = pymysql.connect(
            host=MYSQL_CONFIG['host'],
            port=MYSQL_CONFIG['port'],
            user=MYSQL_CONFIG['user'],
            password=MYSQL_CONFIG['password'],
            database=MYSQL_CONFIG['database']
        )
        conn.close()
        print("MySQL connection test successful")
        return True
    except pymysql.Error as e:
        print(f"MySQL connection test failed: {e}")
        return False

def main():
    """Main function to handle command line arguments"""
    parser = argparse.ArgumentParser(description="SQLite to MySQL Migration Tool")
    parser.add_argument('--backup-only', action='store_true', help="Only create SQLite backup")
    parser.add_argument('--migrate', action='store_true', help="Migrate data from SQLite to MySQL")
    parser.add_argument('--verify', action='store_true', help="Verify migration was successful")
    parser.add_argument('--test-connection', action='store_true', help="Test MySQL connection")

    args = parser.parse_args()

    if args.test_connection:
        test_mysql_connection()
        return

    if args.backup_only:
        backup_sqlite_db()
        return

    if args.verify:
        verify_migration()
        return

    if args.migrate:
        # First create backup
        backup_file = backup_sqlite_db()
        if not backup_file:
            print("Backup failed, aborting migration")
            return

        # Then migrate
        success = migrate_to_mysql()
        if success:
            print("Migration completed successfully")
        else:
            print("Migration failed")
        return

    # Default: backup + migrate + verify
    print("Starting complete migration process...")

    # Step 1: Backup
    backup_file = backup_sqlite_db()
    if not backup_file:
        print("Backup failed, aborting")
        return

    # Step 2: Test connection
    if not test_mysql_connection():
        print("MySQL connection test failed, aborting")
        return

    # Step 3: Migrate
    success = migrate_to_mysql()
    if not success:
        print("Migration failed, aborting")
        return

    # Step 4: Verify
    if verify_migration():
        print("Migration process completed successfully!")
    else:
        print("Migration completed but verification failed")

if __name__ == "__main__":
    main()