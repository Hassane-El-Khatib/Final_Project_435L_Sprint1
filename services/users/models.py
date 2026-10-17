"""User entity."""


class User:
    """A platform account. ``to_dict`` never exposes the password hash."""

    def __init__(self, user_id, full_name, username, email, password_hash, department,
                 role, account_status, created_at=None, last_login=None):
        self.user_id = user_id
        self.full_name = full_name
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.department = department
        self.role = role
        self.account_status = account_status
        self.created_at = created_at
        self.last_login = last_login

    @classmethod
    def from_row(cls, row):
        """Build a User from a database row."""
        return cls(**{key: row[key] for key in row.keys()})

    def is_active(self):
        """Return True if the account may log in."""
        return self.account_status == "Active"

    def to_dict(self):
        """Return the public representation of the user."""
        return {
            "user_id": self.user_id,
            "full_name": self.full_name,
            "username": self.username,
            "email": self.email,
            "department": self.department,
            "role": self.role,
            "account_status": self.account_status,
            "created_at": self.created_at,
            "last_login": self.last_login,
        }

    def to_public_dict(self):
        """Return the minimal details other services need."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "full_name": self.full_name,
            "role": self.role,
            "account_status": self.account_status,
        }
