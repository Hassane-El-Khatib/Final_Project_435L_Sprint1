"""Audit log entity."""


class Log:
    """One immutable security audit record."""

    def __init__(self, log_id, user_id, action, description, timestamp, severity, related_service,
                 username=None):
        self.log_id = log_id
        self.user_id = user_id
        self.action = action
        self.description = description
        self.timestamp = timestamp
        self.severity = severity
        self.related_service = related_service
        self.username = username

    @classmethod
    def from_row(cls, row):
        """Build a Log from a database row (``username`` is present when joined with users)."""
        return cls(**{key: row[key] for key in row.keys()})

    def to_dict(self):
        """Return the log as a dictionary."""
        return {
            "log_id": self.log_id,
            "user_id": self.user_id,
            "username": self.username,
            "action": self.action,
            "description": self.description,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "related_service": self.related_service,
        }
