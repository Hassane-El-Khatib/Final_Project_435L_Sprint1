"""SQLite connection handling for the shared SIDRMS database."""

import sqlite3
from contextlib import contextmanager

from common.config import DB_PATH


class Database:
    """Opens connections to the shared database with foreign keys enforced."""

    path = DB_PATH

    @classmethod
    def connect(cls):
        """Return a new connection whose rows behave like dictionaries."""
        connection = sqlite3.connect(cls.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @classmethod
    @contextmanager
    def session(cls):
        """Yield a connection, commit on success, roll back on error and always close it."""
        connection = cls.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
