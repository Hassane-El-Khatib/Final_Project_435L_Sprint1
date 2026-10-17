"""Notification and Alert Management Service (port 5008).

Developed by: Hassane El Khatib
"""

from flask import g, request

from common.app_factory import create_app, run_service
from common.auth import SERVICE_ROLE, deny, require_roles, require_service_or_roles
from common.clients import log_event
from common.constants import (
    ADMIN,
    ANALYST,
    AUDITOR,
    NOTIFICATION_STATUSES,
    NOTIFICATION_TYPES,
    REGULAR,
    SEVERITIES,
)
from common.errors import NotFoundError, ValidationError
from common.responses import success
from common.validators import Validator
from services.notifications.repository import NotificationRepository

app = create_app("notifications")
notifications = NotificationRepository()

OWN_ONLY_ROLES = (ANALYST, REGULAR)
SEARCH_PARAMS = ["user_id", "notification_type", "severity", "status"]


def find_notification_or_404(notification_id):
    """Return the notification or raise NotFoundError."""
    notification = notifications.get_by_id(notification_id)
    if notification is None:
        raise NotFoundError(f"Notification {notification_id} not found")
    return notification


def check_owner(user_id):
    """Analysts and regular users may only access their own notifications."""
    if g.user["role"] in OWN_ONLY_ROLES and g.user["user_id"] != user_id:
        deny("You can only access your own notifications")


@app.route("/notifications", methods=["POST"])
@require_service_or_roles(ADMIN)
def create_notification():
    """Create Notification.

    Called automatically by other services (X-Service-Key) when an incident is assigned
    or a security, threat or vulnerability alert is raised, and manually by administrators.
    Developed by: Hassane El Khatib
    """
    data = Validator.body()
    Validator.require(data, ["user_id", "title", "message", "notification_type", "severity"])
    user_id = Validator.integer(data["user_id"], "user_id", 1)
    if not notifications.user_exists(user_id):
        raise ValidationError(f"user_id {user_id} does not exist")

    notification_id = notifications.insert({
        "user_id": user_id,
        "title": Validator.text(data["title"], "title", 3, 100),
        "message": Validator.text(data["message"], "message", 3, 1000),
        "notification_type": Validator.enum(data["notification_type"], NOTIFICATION_TYPES, "notification_type"),
        "severity": Validator.enum(data["severity"], SEVERITIES, "severity"),
        "status": "Unread",
    })
    if g.user["role"] != SERVICE_ROLE:
        log_event(g.user["user_id"], "NOTIFICATION_CREATED",
                  f"Notification {notification_id} ({data['notification_type']}) created for user {user_id}",
                  "Information", "notifications")
    return success(notifications.get_by_id(notification_id).to_dict(), "Notification created successfully", 201)


@app.route("/notifications/user/<int:user_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, REGULAR, AUDITOR)
def get_user_notifications(user_id):
    """Retrieve User Notifications.

    Administrators and auditors may read anyone's notifications; analysts and regular
    users only their own. Optional query parameter: status (Unread or Read).
    Developed by: Hassane El Khatib
    """
    check_owner(user_id)
    Validator.only_query(["status"])
    if not notifications.user_exists(user_id):
        raise NotFoundError(f"User {user_id} not found")
    status = None
    if "status" in request.args:
        status = Validator.enum(request.args["status"], NOTIFICATION_STATUSES, "status")
    result = [n.to_dict() for n in notifications.get_for_user(user_id, status)]
    message = "Notifications retrieved successfully" if result else f"No notifications for user {user_id}"
    return success(result, message, unread_count=notifications.unread_count(user_id))


@app.route("/notifications/<int:notification_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, REGULAR, AUDITOR)
def get_notification(notification_id):
    """Retrieve Specific Notification.

    Developed by: Hassane El Khatib
    """
    notification = find_notification_or_404(notification_id)
    check_owner(notification.user_id)
    return success(notification.to_dict(), "Notification retrieved successfully")


@app.route("/notifications/<int:notification_id>/read", methods=["PUT"])
@require_roles(ADMIN, ANALYST, REGULAR)
def mark_notification_read(notification_id):
    """Mark Notification as Read.

    Sets the status to Read and records the read date. Marking an already read
    notification again keeps the original read date.
    Developed by: Hassane El Khatib
    """
    notification = find_notification_or_404(notification_id)
    check_owner(notification.user_id)
    if notification.is_read():
        return success(notification.to_dict(), "Notification was already read")
    notifications.mark_read(notification_id)
    return success(notifications.get_by_id(notification_id).to_dict(), "Notification marked as read")


@app.route("/notifications/search", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def search_notifications():
    """Search Notifications.

    Filters (combined with AND): user_id, notification_type, severity, status.
    Analysts can only search their own notifications.
    Developed by: Hassane El Khatib
    """
    Validator.only_query(SEARCH_PARAMS)
    args = request.args
    filters = {}
    if "user_id" in args:
        filters["user_id"] = Validator.query_integer(args["user_id"], "user_id", 1)
    if g.user["role"] == ANALYST:
        if filters.get("user_id", g.user["user_id"]) != g.user["user_id"]:
            deny("You can only search your own notifications")
        filters["user_id"] = g.user["user_id"]
    if "notification_type" in args:
        filters["notification_type"] = Validator.enum(args["notification_type"], NOTIFICATION_TYPES,
                                                      "notification_type")
    if "severity" in args:
        filters["severity"] = Validator.enum(args["severity"], SEVERITIES, "severity")
    if "status" in args:
        filters["status"] = Validator.enum(args["status"], NOTIFICATION_STATUSES, "status")
    if not filters:
        raise ValidationError(f"Provide at least one filter: {', '.join(SEARCH_PARAMS)}")

    result = [n.to_dict() for n in notifications.search(exact=filters, order_by="created_at DESC, notification_id DESC")]
    message = "Notifications retrieved successfully" if result else "No notifications match the given filters"
    return success(result, message, filters=filters)


@app.route("/notifications/<int:notification_id>", methods=["DELETE"])
@require_roles(ADMIN)
def delete_notification(notification_id):
    """Delete Notification.

    Only Security Administrators may delete notifications.
    Developed by: Hassane El Khatib
    """
    notification = find_notification_or_404(notification_id)
    notifications.delete(notification_id)
    log_event(g.user["user_id"], "NOTIFICATION_DELETED",
              f"Notification {notification_id} ('{notification.title}') of user {notification.user_id} deleted",
              "Warning", "notifications")
    return success(message=f"Notification {notification_id} deleted successfully")


if __name__ == "__main__":
    run_service(app)
