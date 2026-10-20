"""Data access for the threats table."""

from common.base_repository import BaseRepository
from services.threats.models import Threat

SELECT_WITH_USER = (
    "SELECT threats.*, users.full_name AS added_by_name "
    "FROM threats LEFT JOIN users ON users.user_id = threats.added_by"
)


class ThreatRepository(BaseRepository):
    """Queries on the threats table."""

    table = "threats"
    id_column = "threat_id"
    columns = ("threat_type", "threat_value", "description", "severity", "source", "added_by")
    model = Threat
    duplicate_message = "This threat indicator already exists"

    def get_with_user(self, threat_id):
        """Return one threat including the name of the user who added it."""
        return self.fetch_one(f"{SELECT_WITH_USER} WHERE threats.threat_id = ?", (threat_id,))

    def list_threats(self):
        """Return every threat, newest first."""
        return self.fetch_all(f"{SELECT_WITH_USER} ORDER BY threats.date_added DESC, threats.threat_id DESC")

    def find_duplicate(self, threat_type, threat_value):
        """Return the id of an existing threat with the same type and value, or None."""
        sql = "SELECT threat_id FROM threats WHERE threat_type = ? AND threat_value = ?"
        return self.fetch_value(sql, (threat_type, threat_value))

    def search_threats(self, threat_type=None, threat_value=None, severity=None, source=None):
        """Return threats matching every given filter (AND); value and source are partial matches."""
        conditions = []
        params = []
        if threat_type is not None:
            conditions.append("threats.threat_type = ?")
            params.append(threat_type)
        if threat_value is not None:
            conditions.append("LOWER(threats.threat_value) LIKE LOWER(?)")
            params.append(f"%{threat_value}%")
        if severity is not None:
            conditions.append("threats.severity = ?")
            params.append(severity)
        if source is not None:
            conditions.append("LOWER(threats.source) LIKE LOWER(?)")
            params.append(f"%{source}%")
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"{SELECT_WITH_USER}{where} ORDER BY threats.date_added DESC, threats.threat_id DESC"
        return self.fetch_all(sql, tuple(params))
