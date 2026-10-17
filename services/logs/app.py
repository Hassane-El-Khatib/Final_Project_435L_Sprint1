"""Security Audit Logging Service (port 5005).

Developed by: Hassane El Khatib
"""

import re

from flask import g, request

from common.app_factory import create_app, run_service
from common.auth import SERVICE_ROLE, require_roles, require_service_or_roles
from common.clients import log_event
from common.constants import ADMIN, ANALYST, AUDITOR, LOG_SEVERITIES, SERVICES
from common.errors import NotFoundError, ValidationError
from common.responses import success
from common.validators import Validator
from services.logs.repository import LogRepository

app = create_app("logs")
logs = LogRepository()

SEARCH_PARAMS = ["user_id", "action", "severity", "related_service", "date", "from", "to"]


def normalise_action(value):
    """Return the action in UPPER_SNAKE_CASE."""
    action = Validator.text(value, "action", 3, 50).upper()
    return re.sub(r"[\s\-]+", "_", action)


def find_log_or_404(log_id):
    """Return the log or raise NotFoundError."""
    log = logs.get_with_username(log_id)
    if log is None:
        raise NotFoundError(f"Log {log_id} not found")
    return log


@app.route("/logs", methods=["POST"])
@require_service_or_roles(ADMIN)
def create_log():
    """Create Log Record.

    Records a security activity. Called automatically by every service (X-Service-Key)
    and manually by Security Administrators. The timestamp is always set by the database.
    Developed by: Hassane El Khatib
    """
    data = Validator.body()
    is_service = g.user["role"] == SERVICE_ROLE
    required = ["action", "description", "severity", "related_service"]
    if not is_service:
        required = ["user_id"] + required
    Validator.require(data, required)

    user_id = data.get("user_id")
    if user_id is not None:
        Validator.integer(user_id, "user_id", 1)
        if not logs.user_exists(user_id):
            raise ValidationError(f"user_id {user_id} does not exist")

    log_id = logs.insert({
        "user_id": user_id,
        "action": normalise_action(data["action"]),
        "description": Validator.text(data["description"], "description", 3, 500),
        "severity": Validator.enum(data["severity"], LOG_SEVERITIES, "severity"),
        "related_service": Validator.enum(data["related_service"], SERVICES, "related_service"),
    })
    return success(logs.get_with_username(log_id).to_dict(), "Log record created successfully", 201)


@app.route("/logs", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def get_all_logs():
    """Retrieve All Logs.

    Returns audit records newest first. Optional query parameter: limit (1-500).
    Developed by: Hassane El Khatib
    """
    Validator.only_query(["limit"])
    limit = None
    if "limit" in request.args:
        limit = Validator.query_integer(request.args["limit"], "limit", 1, 500)
    result = [log.to_dict() for log in logs.list_logs(limit)]
    return success(result, "Logs retrieved successfully")


@app.route("/logs/<int:log_id>", methods=["GET"])
@require_roles(ADMIN, AUDITOR, ANALYST)
def get_log(log_id):
    """Retrieve Specific Log.

    Developed by: Hassane El Khatib
    """
    return success(find_log_or_404(log_id).to_dict(), "Log retrieved successfully")


@app.route("/logs/search", methods=["GET"])
@require_roles(ADMIN, AUDITOR, ANALYST)
def search_logs():
    """Search Logs.

    Filters (combined with AND): user_id, action, severity, related_service,
    date (YYYY-MM-DD), from and to (YYYY-MM-DD).
    Developed by: Hassane El Khatib
    """
    Validator.only_query(SEARCH_PARAMS)
    args = request.args
    if not any(args.get(name, "").strip() for name in SEARCH_PARAMS):
        raise ValidationError(f"Provide at least one filter: {', '.join(SEARCH_PARAMS)}")

    filters = {}
    if "user_id" in args:
        filters["user_id"] = Validator.query_integer(args["user_id"], "user_id", 1)
    if "action" in args:
        filters["action"] = normalise_action(args["action"])
    if "severity" in args:
        filters["severity"] = Validator.enum(args["severity"], LOG_SEVERITIES, "severity")
    if "related_service" in args:
        filters["related_service"] = Validator.enum(args["related_service"], SERVICES, "related_service")
    for param, key in (("date", "date"), ("from", "date_from"), ("to", "date_to")):
        if param in args:
            value = Validator.date(args[param], param)
            if len(value) != 10:
                raise ValidationError(f"{param} must be in the format YYYY-MM-DD")
            filters[key] = value
    if "date_from" in filters and "date_to" in filters and filters["date_from"] > filters["date_to"]:
        raise ValidationError("from must be earlier than or equal to to")

    result = [log.to_dict() for log in logs.filter_logs(**filters)]
    message = "Logs retrieved successfully" if result else "No logs match the given filters"
    return success(result, message, filters=dict(args))


@app.route("/logs/<int:log_id>", methods=["DELETE"])
@require_roles(ADMIN)
def delete_log(log_id):
    """Delete Logs.

    Only Security Administrators may delete audit records. The deletion itself is logged.
    Developed by: Hassane El Khatib
    """
    log = find_log_or_404(log_id)
    logs.delete(log_id)
    log_event(g.user["user_id"], "LOG_DELETED", f"Audit log {log_id} ({log.action}) deleted", "Warning", "logs")
    return success(message=f"Log {log_id} deleted successfully")


@app.route("/logs/user/<int:user_id>", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def get_logs_by_user(user_id):
    """Retrieve Logs By User.

    Returns every activity performed by one user, newest first.
    Developed by: Hassane El Khatib
    """
    if not logs.user_exists(user_id):
        raise NotFoundError(f"User {user_id} not found")
    result = [log.to_dict() for log in logs.filter_logs(user_id=user_id)]
    message = "Logs retrieved successfully" if result else f"No logs found for user {user_id}"
    return success(result, message)


if __name__ == "__main__":
    run_service(app)
