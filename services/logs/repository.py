"""Data access for the logs table. There is deliberately no update method: logs are immutable."""

from common.base_repository import BaseRepository
from services.logs.models import Log

SELECT_WITH_USERNAME = (
    "SELECT logs.*, users.username AS username "
    "FROM logs LEFT JOIN users ON users.user_id = logs.user_id"
)
NEWEST_FIRST = " ORDER BY logs.timestamp DESC, logs.log_id DESC"


class LogRepository(BaseRepository):
    """Queries on the logs table."""

    table = "logs"
    id_column = "log_id"
    columns = ("user_id", "action", "description", "severity", "related_service")
    model = Log

    def update(self, record_id, values):
        """Audit logs cannot be modified."""
        raise NotImplementedError("Audit logs are immutable")

    def get_with_username(self, log_id):
        """Return one log including the username of the user who performed it."""
        return self.fetch_one(f"{SELECT_WITH_USERNAME} WHERE logs.log_id = ?", (log_id,))

    def list_logs(self, limit=None):
        """Return logs newest first, optionally limited."""
        sql = SELECT_WITH_USERNAME + NEWEST_FIRST
        if limit:
            return self.fetch_all(sql + " LIMIT ?", (limit,))
        return self.fetch_all(sql)

    def filter_logs(self, user_id=None, action=None, severity=None, related_service=None,
                    date=None, date_from=None, date_to=None):
        """Return logs matching every given filter (AND), newest first."""
        conditions = []
        params = []
        if user_id is not None:
            conditions.append("logs.user_id = ?")
            params.append(user_id)
        if action is not None:
            conditions.append("logs.action = ?")
            params.append(action)
        if severity is not None:
            conditions.append("logs.severity = ?")
            params.append(severity)
        if related_service is not None:
            conditions.append("logs.related_service = ?")
            params.append(related_service)
        if date is not None:
            conditions.append("date(logs.timestamp) = ?")
            params.append(date)
        if date_from is not None:
            conditions.append("date(logs.timestamp) >= ?")
            params.append(date_from)
        if date_to is not None:
            conditions.append("date(logs.timestamp) <= ?")
            params.append(date_to)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        return self.fetch_all(SELECT_WITH_USERNAME + where + NEWEST_FIRST, tuple(params))

    def user_exists(self, user_id):
        """Return True if the user exists in the shared users table."""
        return self.fetch_value("SELECT 1 FROM users WHERE user_id = ?", (user_id,)) is not None
