"""Build the shared SQLite database from schema.sql, the seed users and seed.sql.

Usage: python -m database.init_db --reset
"""

import sqlite3
import sys
from pathlib import Path

from common.auth import hash_password
from common.config import DB_PATH

DATABASE_DIR = Path(__file__).resolve().parent

SEED_USERS = [
    (1, "Rana Khoury", "admin", "admin@sidrms.com", "Admin@1234", "IT Security", "Security Administrator", "Active"),
    (2, "Omar Saleh", "analyst1", "analyst1@sidrms.com", "Analyst@1234", "SOC", "Security Analyst", "Active"),
    (3, "Maya Nasser", "analyst2", "analyst2@sidrms.com", "Analyst@1234", "SOC", "Security Analyst", "Active"),
    (4, "Ali Hamdan", "employee1", "employee1@sidrms.com", "Employee@1234", "Human Resources", "Regular User", "Active"),
    (5, "Lara Fares", "employee2", "employee2@sidrms.com", "Employee@1234", "Finance", "Regular User", "Active"),
    (6, "Sami Daher", "auditor1", "auditor1@sidrms.com", "Auditor@1234", "Compliance", "Auditor", "Active"),
    (7, "Hadi Mansour", "suspended1", "suspended1@sidrms.com", "Employee@1234", "Marketing", "Regular User", "Suspended"),
    (8, "Nour Zein", "inactive1", "inactive1@sidrms.com", "Employee@1234", "Sales", "Regular User", "Inactive"),
]


def remove_database():
    """Delete the database file and its WAL side files."""
    for suffix in ("", "-wal", "-shm"):
        path = Path(DB_PATH + suffix)
        if path.exists():
            path.unlink()


def insert_seed_users(connection):
    """Insert the fixed test accounts with bcrypt-hashed passwords."""
    connection.executemany(
        "INSERT INTO users (user_id, full_name, username, email, password_hash, department, role, account_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [(uid, name, user, mail, hash_password(pw), dept, role, status)
         for uid, name, user, mail, pw, dept, role, status in SEED_USERS],
    )


def print_summary(connection):
    """Print the number of rows in every table."""
    tables = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    print(f"Database ready: {DB_PATH}")
    for (table,) in tables:
        count = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"  {table:<22}{count:>5} rows")


def main():
    """Create the database, optionally deleting the existing one first."""
    if Path(DB_PATH).exists():
        if "--reset" not in sys.argv:
            sys.exit("Database already exists. Run with --reset to rebuild it.")
        remove_database()

    connection = sqlite3.connect(DB_PATH)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript((DATABASE_DIR / "schema.sql").read_text())
        insert_seed_users(connection)
        connection.executescript((DATABASE_DIR / "seed.sql").read_text())
        connection.commit()
        print_summary(connection)
    finally:
        connection.close()


if __name__ == "__main__":
    main()
