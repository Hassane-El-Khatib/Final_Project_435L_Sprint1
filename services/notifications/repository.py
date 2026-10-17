"""Data access for the notifications table."""

from common.base_repository import BaseRepository
from services.notifications.models import Notification

NEWEST_FIRST = "created_at DESC, notification_id DESC"


class NotificationRepository(BaseRepository):
    """Queries on the notifications table."""

    table = "notifications"
    id_column = "notification_id"
    columns = ("user_id", "title", "message", "notification_type", "severity", "status", "read_at")
    model = Notification

    def get_for_user(self, user_id, status=None):
        """Return a user's notifications newest first, optionally only one status."""
        exact = {"user_id": user_id}
        if status:
            exact["status"] = status
        return self.search(exact=exact, order_by=NEWEST_FIRST)

    def unread_count(self, user_id):
        """Return how many unread notifications the user has."""
        sql = "SELECT COUNT(*) FROM notifications WHERE user_id = ? AND status = 'Unread'"
        return self.fetch_value(sql, (user_id,))

    def mark_read(self, notification_id):
        """Set the status to Read and store the current local time as read_at."""
        now = self.fetch_value("SELECT datetime('now', 'localtime')")
        self.update(notification_id, {"status": "Read", "read_at": now})

    def user_exists(self, user_id):
        """Return True if the user exists in the shared users table."""
        return self.fetch_value("SELECT 1 FROM users WHERE user_id = ?", (user_id,)) is not None
