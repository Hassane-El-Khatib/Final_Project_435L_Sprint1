"""Password hashing, JWT tokens and role-based access control."""

import hmac
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import current_app, g, request

from common.clients import log_event
from common.config import JWT_EXPIRY_MINUTES, JWT_SECRET, SERVICE_KEY
from common.errors import AuthError, ForbiddenError

ALGORITHM = "HS256"
SERVICE_ROLE = "SERVICE"


def hash_password(plain):
    """Return a salted bcrypt hash of the password."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(plain, hashed):
    """Return True if the password matches the stored bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_token(user_id, username, role):
    """Return a signed JWT that expires after JWT_EXPIRY_MINUTES."""
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def decode_token(token):
    """Return the token payload or raise AuthError if it is expired or invalid."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired, please log in again") from None
    except jwt.InvalidTokenError:
        raise AuthError("Invalid authentication token") from None


def _bearer_token():
    """Return the token from the Authorization header, or None."""
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer ") and header[7:].strip():
        return header[7:].strip()
    return None


def _log_violation(user_id, description):
    """Record an unauthorized access attempt in the audit log."""
    log_event(user_id, "UNAUTHORIZED_ACCESS", description, "Warning", current_app.name)


def authenticate():
    """Return the payload of a valid token or raise AuthError (logging the attempt)."""
    token = _bearer_token()
    if token is None:
        _log_violation(None, f"Request without authentication token to {request.method} {request.path}")
        raise AuthError("Authentication required")
    try:
        return decode_token(token)
    except AuthError:
        _log_violation(None, f"Invalid or expired token used on {request.method} {request.path}")
        raise


def require_roles(*roles):
    """Allow the route only for authenticated users whose role is in ``roles``."""

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            payload = authenticate()
            if payload.get("role") not in roles:
                _log_violation(
                    payload.get("user_id"),
                    f"User {payload.get('username')} ({payload.get('role')}) attempted "
                    f"{request.method} {request.path}",
                )
                raise ForbiddenError("User does not have permission to perform this operation")
            g.user = payload
            return view(*args, **kwargs)

        return wrapper

    return decorator


def is_service_call():
    """Return True if the request carries the internal service key."""
    key = request.headers.get("X-Service-Key", "")
    return bool(key) and hmac.compare_digest(key, SERVICE_KEY)


def require_service_or_roles(*roles):
    """Allow internal service calls (X-Service-Key) or users whose role is in ``roles``."""

    def decorator(view):
        protected = require_roles(*roles)(view)

        @wraps(view)
        def wrapper(*args, **kwargs):
            if is_service_call():
                g.user = {"user_id": None, "username": "service", "role": SERVICE_ROLE}
                return view(*args, **kwargs)
            return protected(*args, **kwargs)

        return wrapper

    return decorator


def optional_user():
    """Return the token payload if a valid token is sent, None if no token is sent."""
    if _bearer_token() is None:
        return None
    return authenticate()


def deny(message):
    """Log an ownership violation by the current user and raise ForbiddenError."""
    user = getattr(g, "user", {}) or {}
    _log_violation(
        user.get("user_id"),
        f"User {user.get('username')} ({user.get('role')}) was denied {request.method} {request.path}: {message}",
    )
    raise ForbiddenError(message)
