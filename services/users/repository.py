"""Data access for the users table."""

from common.base_repository import BaseRepository
from services.users.models import User


class UserRepository(BaseRepository):
    """Queries on the users table."""

    table = "users"
    id_column = "user_id"
    columns = (
        "full_name",
        "username",
        "email",
        "password_hash",
        "department",
        "role",
        "account_status",
        "last_login",
    )
    model = User
    duplicate_message = "Username or email is already registered"
    delete_conflict_message = (
        "User is still referenced by assets, incidents, notes or playbooks; reassign or remove them first"
    )

    def get_by_username(self, username):
        """Return the user with this exact username, or None."""
        return self.fetch_one("SELECT * FROM users WHERE username = ?", (username,))

    def get_by_login(self, identifier):
        """Return the user whose username or email matches the identifier, or None."""
        return self.fetch_one(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier.lower()),
        )

    def username_taken(self, username):
        """Return True if the username is already used."""
        return self.fetch_value("SELECT 1 FROM users WHERE username = ?", (username,)) is not None

    def email_taken(self, email, exclude_id=None):
        """Return True if another user already has this email."""
        if exclude_id is None:
            return self.fetch_value("SELECT 1 FROM users WHERE email = ?", (email,)) is not None
        sql = "SELECT 1 FROM users WHERE email = ? AND user_id != ?"
        return self.fetch_value(sql, (email, exclude_id)) is not None

    def touch_last_login(self, user_id):
        """Store the current local time as the user's last login."""
        self.update(user_id, {"last_login": self.fetch_value("SELECT datetime('now', 'localtime')")})
