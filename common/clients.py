"""HTTP calls from one service to another (audit logging, notifications, user lookup)."""

import requests

from common.config import SERVICE_KEY, URLS
from common.errors import ServiceUnavailableError

TIMEOUT_SECONDS = 3
SERVICE_HEADERS = {"X-Service-Key": SERVICE_KEY}


def log_event(user_id, action, description, severity="Information", service=None):
    """Record an audit log through the Logs service. Never raises."""
    payload = {
        "user_id": user_id,
        "action": action,
        "description": description,
        "severity": severity,
        "related_service": service,
    }
    try:
        requests.post(f"{URLS['logs']}/logs", json=payload, headers=SERVICE_HEADERS, timeout=TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        print(f"[log_event] Logs service unreachable, event not recorded: {action} ({exc})")


def notify(user_id, title, message, notification_type, severity):
    """Create a notification for one user through the Notifications service. Never raises."""
    payload = {
        "user_id": user_id,
        "title": title,
        "message": message,
        "notification_type": notification_type,
        "severity": severity,
    }
    try:
        requests.post(
            f"{URLS['notifications']}/notifications",
            json=payload,
            headers=SERVICE_HEADERS,
            timeout=TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        print(f"[notify] Notifications service unreachable, notification not sent: {title} ({exc})")


def get_user(user_id):
    """Return a user's public details from the Users service, or None if the user does not exist."""
    try:
        response = requests.get(
            f"{URLS['users']}/internal/users/{user_id}", headers=SERVICE_HEADERS, timeout=TIMEOUT_SECONDS
        )
    except requests.RequestException:
        raise ServiceUnavailableError("Users service is unavailable") from None
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise ServiceUnavailableError("Users service returned an unexpected response")
    return response.json()["data"]


def get_users_by_role(role):
    """Return every user with the given role from the Users service."""
    try:
        response = requests.get(
            f"{URLS['users']}/internal/users",
            params={"role": role},
            headers=SERVICE_HEADERS,
            timeout=TIMEOUT_SECONDS,
        )
    except requests.RequestException:
        print(f"[get_users_by_role] Users service unreachable, no users returned for {role}")
        return []
    if response.status_code != 200:
        return []
    return response.json()["data"]


def notify_role(role, title, message, notification_type, severity):
    """Notify every Active user that has the given role."""
    for user in get_users_by_role(role):
        if user["account_status"] == "Active":
            notify(user["user_id"], title, message, notification_type, severity)
