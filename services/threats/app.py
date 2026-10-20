"""Threat Intelligence Service (port 5004).

Developed by: Abdul Rahman Habbal
"""

from flask import g, request

from common.app_factory import create_app, run_service
from common.auth import require_roles
from common.clients import log_event, notify_role
from common.constants import ADMIN, ANALYST, AUDITOR, SEVERITIES, THREAT_TYPES
from common.errors import ConflictError, NotFoundError, ValidationError
from common.responses import success
from common.validators import Validator
from services.threats.models import ThreatValueValidator
from services.threats.repository import ThreatRepository

app = create_app("threats")
threats = ThreatRepository()
value_validator = ThreatValueValidator()

CREATE_FIELDS = ["threat_type", "threat_value", "description", "severity", "source"]
UPDATABLE_FIELDS = ["description", "severity", "source"]
SEARCH_PARAMS = ["threat_type", "threat_value", "severity", "source"]


def find_threat_or_404(threat_id):
    """Return the threat or raise NotFoundError."""
    threat = threats.get_with_user(threat_id)
    if threat is None:
        raise NotFoundError(f"Threat {threat_id} not found")
    return threat


@app.route("/threats", methods=["POST"])
@require_roles(ADMIN)
def add_threat():
    """Add Threat Indicator.

    Required: threat_type, threat_value, description, severity, source. The value is
    validated according to its type, and the same type and value cannot be added twice.
    Developed by: Abdul Rahman Habbal
    """
    data = Validator.body()
    Validator.require(data, CREATE_FIELDS)
    Validator.only_fields(data, CREATE_FIELDS)
    threat_type = Validator.enum(data["threat_type"], THREAT_TYPES, "threat_type")
    threat_value = value_validator.validate(threat_type, data["threat_value"])
    description = Validator.text(data["description"], "description", 5, 1000)
    severity = Validator.enum(data["severity"], SEVERITIES, "severity")
    source = Validator.text(data["source"], "source", 2, 100)
    existing = threats.find_duplicate(threat_type, threat_value)
    if existing:
        raise ConflictError(f"Threat indicator ({threat_type}, {threat_value}) already exists as threat {existing}")

    threat_id = threats.insert({
        "threat_type": threat_type,
        "threat_value": threat_value,
        "description": description,
        "severity": severity,
        "source": source,
        "added_by": g.user["user_id"],
    })
    log_event(g.user["user_id"], "THREAT_CREATED",
              f"Threat {threat_id} {threat_type} {threat_value} ({severity}) added from {source}",
              "Warning" if severity in ("High", "Critical") else "Information", "threats")
    if severity in ("High", "Critical"):
        message = f"{threat_type} {threat_value} from {source}"
        notify_role(ADMIN, f"New {severity} threat indicator", message, "Threat Alert", severity)
        notify_role(ANALYST, f"New {severity} threat indicator", message, "Threat Alert", severity)
    return success(find_threat_or_404(threat_id).to_dict(), "Threat indicator created successfully", 201)


@app.route("/threats", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def get_all_threats():
    """Retrieve All Threat Indicators.

    Returns every threat with its type, value, severity, source and date added, newest first.
    Developed by: Abdul Rahman Habbal
    """
    Validator.only_query([])
    result = [threat.to_dict() for threat in threats.list_threats()]
    return success(result, "Threat indicators retrieved successfully")


@app.route("/threats/search", methods=["GET"])
@require_roles(ADMIN, ANALYST)
def search_threats():
    """Search Threat Indicators.

    Filters (combined with AND): threat_type, threat_value (partial), severity, source (partial).
    Auditors may list and view threats but not search them, as in the specification.
    Developed by: Abdul Rahman Habbal
    """
    Validator.only_query(SEARCH_PARAMS)
    args = request.args
    if not any(args.get(name, "").strip() for name in SEARCH_PARAMS):
        raise ValidationError(f"Provide at least one filter: {', '.join(SEARCH_PARAMS)}")
    filters = {}
    if "threat_type" in args:
        filters["threat_type"] = Validator.enum(args["threat_type"], THREAT_TYPES, "threat_type")
    if "threat_value" in args:
        filters["threat_value"] = Validator.text(args["threat_value"], "threat_value", 1, 500)
    if "severity" in args:
        filters["severity"] = Validator.enum(args["severity"], SEVERITIES, "severity")
    if "source" in args:
        filters["source"] = Validator.text(args["source"], "source", 1, 100)

    result = [threat.to_dict() for threat in threats.search_threats(**filters)]
    message = "Threat indicators retrieved successfully" if result else "No threat indicators match the given filters"
    return success(result, message, filters=dict(args))


@app.route("/threats/<int:threat_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def get_threat(threat_id):
    """Retrieve Specific Threat Indicator.

    Developed by: Abdul Rahman Habbal
    """
    return success(find_threat_or_404(threat_id).to_dict(), "Threat indicator retrieved successfully")


@app.route("/threats/<int:threat_id>", methods=["PUT"])
@require_roles(ADMIN)
def update_threat(threat_id):
    """Update Threat Information.

    Updatable: description, severity, source. The type and value cannot change because
    that would bypass the uniqueness rule; delete the indicator and add a new one instead.
    Developed by: Abdul Rahman Habbal
    """
    data = Validator.body()
    threat = find_threat_or_404(threat_id)
    if "threat_type" in data or "threat_value" in data:
        raise ValidationError("threat_type and threat_value cannot be changed; delete the indicator and add a new one")
    Validator.only_fields(data, UPDATABLE_FIELDS)
    if not data:
        raise ValidationError(f"Provide at least one field to update: {', '.join(UPDATABLE_FIELDS)}")
    changes = {}
    if "description" in data:
        changes["description"] = Validator.text(data["description"], "description", 5, 1000)
    if "severity" in data:
        changes["severity"] = Validator.enum(data["severity"], SEVERITIES, "severity")
    if "source" in data:
        changes["source"] = Validator.text(data["source"], "source", 2, 100)

    changed = {key: value for key, value in changes.items() if getattr(threat, key) != value}
    if not changed:
        return success(threat.to_dict(), "No changes were made")
    threats.update(threat_id, changed)
    summary = "; ".join(f"{key} {getattr(threat, key)} -> {value}" for key, value in changed.items())
    log_event(g.user["user_id"], "THREAT_UPDATED", f"Threat {threat_id} {threat.threat_value} updated: {summary}",
              "Information", "threats")
    return success(find_threat_or_404(threat_id).to_dict(), "Threat indicator updated successfully")


@app.route("/threats/<int:threat_id>", methods=["DELETE"])
@require_roles(ADMIN)
def delete_threat(threat_id):
    """Delete Threat Indicator.

    Only Security Administrators may delete threat indicators.
    Developed by: Abdul Rahman Habbal
    """
    threat = find_threat_or_404(threat_id)
    threats.delete(threat_id)
    log_event(g.user["user_id"], "THREAT_DELETED",
              f"Threat {threat_id} {threat.threat_type} {threat.threat_value} deleted", "Warning", "threats")
    return success(message=f"Threat {threat_id} ({threat.threat_value}) deleted successfully")


if __name__ == "__main__":
    run_service(app)
