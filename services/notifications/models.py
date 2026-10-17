"""Notification entity."""


class Notification:
    """A security alert or system message delivered to one user."""

    def __init__(self, notification_id, user_id, title, message, notification_type, severity,
                 status, created_at=None, read_at=None):
        self.notification_id = notification_id
        self.user_id = user_id
        self.title = title
        self.message = message
        self.notification_type = notification_type
        self.severity = severity
        self.status = status
        self.created_at = created_at
        self.read_at = read_at

    @classmethod
    def from_row(cls, row):
        """Build a Notification from a database row."""
        return cls(**{key: row[key] for key in row.keys()})

    def is_read(self):
        """Return True if the notification was already read."""
        return self.status == "Read"

    def to_dict(self):
        """Return the notification as a dictionary."""
        return {
            "notification_id": self.notification_id,
            "user_id": self.user_id,
            "title": self.title,
            "message": self.message,
            "notification_type": self.notification_type,
            "severity": self.severity,
            "status": self.status,
            "created_at": self.created_at,
            "read_at": self.read_at,
        }
