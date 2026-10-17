"""Parent class for every repository: parameterised CRUD and search on one table."""

import sqlite3

from common.db import Database
from common.errors import ConflictError, ValidationError


class BaseRepository:
    """Generic data access for a single table.

    Subclasses set ``table``, ``id_column``, ``columns`` (the only column names
    allowed in generated SQL) and ``model`` (a class with ``from_row``).
    Values are always passed as ``?`` parameters; table and column names never
    come from the request, which protects every query against SQL injection.
    """

    table = None
    id_column = None
    columns = ()
    model = None
    duplicate_message = "A record with the same unique values already exists"
    delete_conflict_message = "This record is still referenced by other records"

    def _to_model(self, row):
        """Convert a database row into the repository's model, or None."""
        if row is None:
            return None
        return self.model.from_row(row) if self.model else dict(row)

    def _check_columns(self, names):
        """Reject any column name that is not declared in ``columns``."""
        unknown = [name for name in names if name not in self.columns]
        if unknown:
            raise ValidationError(f"Unknown field(s): {', '.join(unknown)}")

    def _integrity_error(self, exc, default):
        """Translate a SQLite integrity error into a client-facing error."""
        text = str(exc)
        if "FOREIGN KEY" in text:
            return ValidationError("A referenced record does not exist")
        if "CHECK" in text or "NOT NULL" in text:
            return ValidationError("One or more values are not allowed")
        return ConflictError(default)

    def fetch_one(self, sql, params=()):
        """Run a SELECT and return the first row as a model."""
        with Database.session() as connection:
            row = connection.execute(sql, params).fetchone()
        return self._to_model(row)

    def fetch_all(self, sql, params=()):
        """Run a SELECT and return all rows as models."""
        with Database.session() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [self._to_model(row) for row in rows]

    def fetch_value(self, sql, params=()):
        """Run a SELECT that returns a single value."""
        with Database.session() as connection:
            row = connection.execute(sql, params).fetchone()
        return row[0] if row else None

    def get_by_id(self, record_id):
        """Return one record by primary key, or None."""
        return self.fetch_one(f"SELECT * FROM {self.table} WHERE {self.id_column} = ?", (record_id,))

    def get_all(self, order_by=None):
        """Return every record, ordered by ``order_by`` or the primary key."""
        order = order_by or self.id_column
        return self.fetch_all(f"SELECT * FROM {self.table} ORDER BY {order}")

    def exists(self, record_id):
        """Return True if a record with this primary key exists."""
        sql = f"SELECT 1 FROM {self.table} WHERE {self.id_column} = ?"
        return self.fetch_value(sql, (record_id,)) is not None

    def insert(self, values):
        """Insert a record and return its new primary key."""
        self._check_columns(values)
        names = ", ".join(values)
        placeholders = ", ".join("?" for _ in values)
        sql = f"INSERT INTO {self.table} ({names}) VALUES ({placeholders})"
        try:
            with Database.session() as connection:
                cursor = connection.execute(sql, tuple(values.values()))
                return cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise self._integrity_error(exc, self.duplicate_message) from None

    def update(self, record_id, values):
        """Update the given columns of one record."""
        if not values:
            return
        self._check_columns(values)
        assignments = ", ".join(f"{name} = ?" for name in values)
        sql = f"UPDATE {self.table} SET {assignments} WHERE {self.id_column} = ?"
        try:
            with Database.session() as connection:
                connection.execute(sql, (*values.values(), record_id))
        except sqlite3.IntegrityError as exc:
            raise self._integrity_error(exc, self.duplicate_message) from None

    def delete(self, record_id):
        """Delete one record; references that block the delete become a 409."""
        sql = f"DELETE FROM {self.table} WHERE {self.id_column} = ?"
        try:
            with Database.session() as connection:
                connection.execute(sql, (record_id,))
        except sqlite3.IntegrityError:
            raise ConflictError(self.delete_conflict_message) from None

    def search(self, exact=None, partial=None, order_by=None):
        """Filter with AND: ``exact`` uses ``=``, ``partial`` uses case-insensitive LIKE."""
        exact = exact or {}
        partial = partial or {}
        self._check_columns(list(exact) + list(partial))
        conditions = [f"{name} = ?" for name in exact]
        conditions += [f"LOWER({name}) LIKE LOWER(?)" for name in partial]
        params = list(exact.values()) + [f"%{value}%" for value in partial.values()]
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        order = order_by or self.id_column
        return self.fetch_all(f"SELECT * FROM {self.table}{where} ORDER BY {order}", tuple(params))
