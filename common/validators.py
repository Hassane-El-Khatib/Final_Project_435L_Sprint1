"""Reusable input validation for request bodies and query strings."""

import ipaddress
import re
from datetime import datetime

from flask import request

from common.constants import next_status
from common.errors import ValidationError

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,30}$")
DATE_FORMATS = ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S")


class Validator:
    """Static validation helpers. Each one raises ValidationError on bad input."""

    @staticmethod
    def body():
        """Return the JSON body as a dict, rejecting missing, empty or malformed bodies."""
        data = request.get_json(silent=True)
        if data is None and request.get_data(as_text=True).strip():
            raise ValidationError("Malformed JSON body")
        if not isinstance(data, dict) or not data:
            raise ValidationError("Request body must be a non-empty JSON object")
        return data

    @staticmethod
    def require(data, fields):
        """Ensure every field is present and not blank."""
        missing = []
        for field in fields:
            value = data.get(field)
            if value is None or (isinstance(value, str) and not value.strip()):
                missing.append(field)
        if missing:
            raise ValidationError(
                f"Missing required fields: {', '.join(missing)}",
                [f"{field} is required" for field in missing],
            )

    @staticmethod
    def only_fields(data, allowed):
        """Reject keys that are not in ``allowed``."""
        extra = [key for key in data if key not in allowed]
        if extra:
            raise ValidationError(f"Field(s) not updatable: {', '.join(extra)}")

    @staticmethod
    def only_query(allowed):
        """Reject query-string parameters that are not in ``allowed``."""
        extra = [key for key in request.args if key not in allowed]
        if extra:
            raise ValidationError(
                f"Unknown query parameter(s): {', '.join(extra)}. Allowed: {', '.join(allowed)}"
            )

    @staticmethod
    def text(value, field, min_len=1, max_len=255):
        """Return the trimmed string, enforcing type and length."""
        if not isinstance(value, str):
            raise ValidationError(f"{field} must be a string")
        cleaned = value.strip()
        if not min_len <= len(cleaned) <= max_len:
            raise ValidationError(f"{field} must be between {min_len} and {max_len} characters")
        return cleaned

    @staticmethod
    def email(value, field="email"):
        """Return the lowercase email if it has a valid format."""
        cleaned = Validator.text(value, field, 6, 120).lower()
        if not EMAIL_PATTERN.match(cleaned):
            raise ValidationError("Invalid email format")
        return cleaned

    @staticmethod
    def username(value):
        """Return the username if it is 3-30 letters, digits or underscores."""
        cleaned = Validator.text(value, "username", 3, 30)
        if not USERNAME_PATTERN.match(cleaned):
            raise ValidationError("Username must be 3-30 letters, digits or underscores")
        return cleaned

    @staticmethod
    def password(value):
        """Enforce the password policy and return the password unchanged."""
        if not isinstance(value, str):
            raise ValidationError("password must be a string")
        problems = []
        if len(value) < 8:
            problems.append("at least 8 characters")
        if not re.search(r"[A-Z]", value):
            problems.append("an uppercase letter")
        if not re.search(r"[a-z]", value):
            problems.append("a lowercase letter")
        if not re.search(r"\d", value):
            problems.append("a digit")
        if not re.search(r"[^A-Za-z0-9]", value):
            problems.append("a special character")
        if problems:
            raise ValidationError(
                "Password does not meet requirements: needs " + ", ".join(problems),
                problems,
            )
        return value

    @staticmethod
    def ip(value, field="ip_address"):
        """Return the normalised IPv4 or IPv6 address."""
        if not isinstance(value, str):
            raise ValidationError(f"{field} must be a string")
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            raise ValidationError(f"Invalid IP address format for {field}") from None

    @staticmethod
    def enum(value, allowed, field):
        """Ensure the value is exactly one of ``allowed``."""
        if value not in allowed:
            raise ValidationError(f"{field} must be one of: {', '.join(allowed)}")
        return value

    @staticmethod
    def integer(value, field, min_value=None):
        """Ensure a real integer (not a bool or a string) above ``min_value``."""
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"{field} must be an integer")
        if min_value is not None and value < min_value:
            raise ValidationError(f"{field} must be at least {min_value}")
        return value

    @staticmethod
    def query_integer(value, field, min_value=None, max_value=None):
        """Convert a query-string value to an integer within the given range."""
        if value is None or not value.strip().lstrip("-").isdigit():
            raise ValidationError(f"{field} must be an integer")
        number = int(value)
        if min_value is not None and number < min_value:
            raise ValidationError(f"{field} must be at least {min_value}")
        if max_value is not None and number > max_value:
            raise ValidationError(f"{field} must be at most {max_value}")
        return number

    @staticmethod
    def number(value, field, low, high):
        """Ensure an int or float between ``low`` and ``high``."""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValidationError(f"{field} must be a number")
        if not low <= value <= high:
            raise ValidationError(f"{field} must be between {low} and {high}")
        return float(value)

    @staticmethod
    def date(value, field):
        """Accept YYYY-MM-DD or YYYY-MM-DD HH:MM:SS and return it unchanged."""
        if isinstance(value, str):
            for fmt in DATE_FORMATS:
                try:
                    datetime.strptime(value.strip(), fmt)
                    return value.strip()
                except ValueError:
                    continue
        raise ValidationError(f"{field} must be in the format YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")

    @staticmethod
    def transition(current, new, flow, field="status"):
        """Allow only a move to the next status in ``flow``."""
        allowed = next_status(current, flow)
        if allowed is None:
            raise ValidationError(f"{field} is already {current} and cannot change anymore")
        if new != allowed:
            raise ValidationError(
                f"Invalid {field} transition from {current} to {new}. Next allowed {field}: {allowed}"
            )
        return new
