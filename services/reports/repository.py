"""Read-only aggregate queries on the tables of the other services."""

from common.db import Database
from common.errors import ValidationError

ALLOWED = {
    "users": ("role", "account_status"),
    "assets": ("asset_type", "status", "criticality"),
    "incidents": ("severity", "status", "category"),
    "threats": ("severity", "threat_type"),
    "vulnerabilities": ("severity", "status"),
    "logs": ("action", "related_service", "severity"),
}


class ReportRepository:
    """Counts and groupings used by the reports; table and column names come only from ``ALLOWED``."""

    @staticmethod
    def _check(table, column=None):
        """Reject any table or column that is not in the whitelist."""
        if table not in ALLOWED or (column is not None and column not in ALLOWED[table]):
            raise ValidationError("Unknown report table or column")

    @staticmethod
    def _rows(sql, params=()):
        """Run a read-only query and return plain rows."""
        with Database.session() as connection:
            return connection.execute(sql, params).fetchall()

    def count(self, table, where=None, params=()):
        """Return the number of rows in ``table`` matching the optional condition."""
        self._check(table)
        sql = f"SELECT COUNT(*) FROM {table}" + (f" WHERE {where}" if where else "")
        return self._rows(sql, params)[0][0]

    def group_count(self, table, column, allowed_values=None):
        """Return {value: count} for ``column``; every allowed value appears, with 0 if absent."""
        self._check(table, column)
        result = {value: 0 for value in allowed_values or []}
        for row in self._rows(f"SELECT {column}, COUNT(*) FROM {table} GROUP BY {column} ORDER BY {column}"):
            result[row[0]] = row[1]
        return result

    def top_actions(self, limit=5):
        """Return the most frequent audit-log actions."""
        rows = self._rows("SELECT action, COUNT(*) AS n FROM logs GROUP BY action ORDER BY n DESC, action LIMIT ?",
                          (limit,))
        return [{"action": row[0], "count": row[1]} for row in rows]

    def recent_logs(self, limit=5):
        """Return the latest audit-log records."""
        rows = self._rows("SELECT logs.log_id, logs.action, logs.description, logs.timestamp, users.username "
                          "FROM logs LEFT JOIN users ON users.user_id = logs.user_id "
                          "ORDER BY logs.timestamp DESC, logs.log_id DESC LIMIT ?", (limit,))
        return [dict(row) for row in rows]

    def recent_threats(self, limit=5):
        """Return the newest threat indicators."""
        rows = self._rows("SELECT threat_id, threat_type, threat_value, severity, date_added FROM threats "
                          "ORDER BY date_added DESC, threat_id DESC LIMIT ?", (limit,))
        return [dict(row) for row in rows]

    def critical_assets(self):
        """Return the id and name of every Critical asset."""
        rows = self._rows("SELECT asset_id, asset_name FROM assets WHERE criticality = 'Critical' ORDER BY asset_id")
        return [dict(row) for row in rows]

    def critical_vulnerabilities(self):
        """Return every Critical vulnerability with its asset name."""
        rows = self._rows("SELECT v.vulnerability_id, v.cve_id, v.title, v.status, a.asset_name "
                          "FROM vulnerabilities v LEFT JOIN assets a ON a.asset_id = v.asset_id "
                          "WHERE v.severity = 'Critical' ORDER BY v.vulnerability_id")
        return [dict(row) for row in rows]

    def average_cvss(self):
        """Return the average CVSS score of all vulnerabilities, rounded to one decimal."""
        value = self._rows("SELECT AVG(cvss_score) FROM vulnerabilities")[0][0]
        return round(value, 1) if value is not None else None

    def now(self):
        """Return the current local time as stored by the database."""
        return self._rows("SELECT datetime('now', 'localtime')")[0][0]
