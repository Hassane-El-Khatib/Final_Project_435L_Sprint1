"""Incident Management Service (port 5003).

Developed by: Yehia Afesh
"""

from flask import g, request

from common.app_factory import create_app, run_service
from common.auth import deny, require_roles
from common.clients import get_user, log_event, notify, notify_role
from common.constants import (
    ADMIN,
    ANALYST,
    AUDITOR,
    INCIDENT_CATEGORIES,
    INCIDENT_FLOW,
    REGULAR,
    SEVERITIES,
)
from common.errors import NotFoundError, ValidationError
from common.responses import success
from common.validators import Validator
from services.incidents.repository import IncidentRepository, NoteRepository

app = create_app("incidents")
incidents = IncidentRepository()
notes = NoteRepository()

CREATE_FIELDS = ["title", "description", "category", "severity", "asset_id"]


def find_incident_or_404(incident_id):
    """Return the incident with joined names or raise NotFoundError."""
    incident = incidents.get_details(incident_id)
    if incident is None:
        raise NotFoundError(f"Incident {incident_id} not found")
    return incident


def check_access(incident):
    """Analysts may only touch incidents assigned to them; regular users only incidents they reported."""
    role = g.user["role"]
    user_id = g.user["user_id"]
    if role == ANALYST and incident.assigned_analyst_id != user_id:
        deny(f"Incident {incident.incident_id} is not assigned to you")
    if role == REGULAR and incident.reporter_id != user_id:
        deny(f"You can only view incidents you reported; incident {incident.incident_id} is not yours")


def with_notes(incident):
    """Return the incident as a dictionary including its investigation notes."""
    data = incident.to_dict()
    data["notes"] = [note.to_dict() for note in notes.for_incident(incident.incident_id)]
    return data


@app.route("/incidents", methods=["POST"])
@require_roles(ADMIN, REGULAR)
def create_incident():
    """Create Incident.

    Reports a cybersecurity incident. Required: title, description, category, severity,
    asset_id. The reporter is the logged-in user (taken from the token).
    Developed by: Yehia Afesh
    """
    data = Validator.body()
    Validator.require(data, CREATE_FIELDS)
    Validator.only_fields(data, CREATE_FIELDS)
    title = Validator.text(data["title"], "title", 5, 150)
    description = Validator.text(data["description"], "description", 10, 2000)
    category = Validator.enum(data["category"], INCIDENT_CATEGORIES, "category")
    severity = Validator.enum(data["severity"], SEVERITIES, "severity")
    asset_id = Validator.integer(data["asset_id"], "asset_id", 1)
    if not incidents.asset_exists(asset_id):
        raise ValidationError(f"Asset {asset_id} does not exist")

    incident_id = incidents.insert({
        "title": title,
        "description": description,
        "category": category,
        "severity": severity,
        "reporter_id": g.user["user_id"],
        "asset_id": asset_id,
        "status": "Open",
    })
    log_event(g.user["user_id"], "INCIDENT_CREATED",
              f"Incident {incident_id} '{title}' ({severity}, {category}) reported on asset {asset_id}",
              "Critical" if severity == "Critical" else "Information", "incidents")
    if severity == "Critical":
        notify_role(ADMIN, "Critical incident reported",
                    f"Incident {incident_id}: {title} (asset {asset_id}) requires immediate response.",
                    "Security Alert", "Critical")
    return success(with_notes(find_incident_or_404(incident_id)), "Incident created successfully", 201)


@app.route("/incidents", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def get_all_incidents():
    """Retrieve All Incidents.

    Returns every incident with its status and assigned analyst, newest first.
    Optional query parameters: status, severity.
    Developed by: Yehia Afesh
    """
    Validator.only_query(["status", "severity"])
    status = severity = None
    if "status" in request.args:
        status = Validator.enum(request.args["status"], INCIDENT_FLOW, "status")
    if "severity" in request.args:
        severity = Validator.enum(request.args["severity"], SEVERITIES, "severity")
    result = [incident.to_dict() for incident in incidents.list_incidents(status, severity)]
    return success(result, "Incidents retrieved successfully")


@app.route("/incidents/<int:incident_id>", methods=["GET"])
@require_roles(ADMIN, AUDITOR, ANALYST, REGULAR)
def get_incident(incident_id):
    """Retrieve Specific Incident.

    Administrators and auditors see every incident, analysts only those assigned to them,
    regular users only those they reported. Includes the investigation notes.
    Developed by: Yehia Afesh
    """
    incident = find_incident_or_404(incident_id)
    check_access(incident)
    return success(with_notes(incident), "Incident retrieved successfully")


@app.route("/incidents/<int:incident_id>/assign", methods=["PUT"])
@require_roles(ADMIN)
def assign_incident(incident_id):
    """Assign Incident to Analyst.

    Body: analyst_id. The incident must exist and not be closed, and the user must be
    an active Security Analyst. The analyst is notified and the assignment is logged.
    Developed by: Yehia Afesh
    """
    data = Validator.body()
    Validator.require(data, ["analyst_id"])
    Validator.only_fields(data, ["analyst_id"])
    analyst_id = Validator.integer(data["analyst_id"], "analyst_id", 1)
    incident = find_incident_or_404(incident_id)
    if incident.is_closed():
        raise ValidationError(f"Incident {incident_id} is Closed and cannot be reassigned")

    analyst = get_user(analyst_id)
    if analyst is None:
        raise NotFoundError(f"User {analyst_id} not found")
    if analyst["role"] != ANALYST:
        raise ValidationError(f"User {analyst_id} ({analyst['username']}) is not a Security Analyst")
    if analyst["account_status"] != "Active":
        raise ValidationError(f"User {analyst_id} ({analyst['username']}) is not active")

    incidents.update(incident_id, {"assigned_analyst_id": analyst_id, "updated_at": incidents.now()})
    log_event(g.user["user_id"], "INCIDENT_ASSIGNED",
              f"Incident {incident_id} assigned to {analyst['username']} (user {analyst_id})",
              "Information", "incidents")
    notify(analyst_id, "New incident assigned",
           f"Incident {incident_id} '{incident.title}' ({incident.severity}) is assigned to you.",
           "Incident Assignment", incident.severity)
    return success(with_notes(find_incident_or_404(incident_id)), "Incident assigned successfully")


@app.route("/incidents/<int:incident_id>/status", methods=["PUT"])
@require_roles(ADMIN, ANALYST)
def update_incident_status(incident_id):
    """Update Incident Status.

    Enforces Open -> Under Investigation -> Mitigated -> Resolved -> Closed, one step at a time.
    Analysts may only update incidents assigned to them. The reporter is notified.
    Developed by: Yehia Afesh
    """
    data = Validator.body()
    Validator.require(data, ["status"])
    Validator.only_fields(data, ["status"])
    new_status = Validator.enum(data["status"], INCIDENT_FLOW, "status")
    incident = find_incident_or_404(incident_id)
    check_access(incident)
    if incident.is_closed():
        raise ValidationError(f"Incident {incident_id} is already Closed")
    Validator.transition(incident.status, new_status, INCIDENT_FLOW)
    if new_status == "Under Investigation" and incident.assigned_analyst_id is None:
        raise ValidationError("Assign an analyst before starting the investigation")

    now = incidents.now()
    changes = {"status": new_status, "updated_at": now}
    if new_status == "Resolved":
        changes["resolved_at"] = now
    incidents.update(incident_id, changes)
    log_event(g.user["user_id"], "INCIDENT_STATUS_CHANGED",
              f"Incident {incident_id}: {incident.status} -> {new_status}", "Information", "incidents")
    notify(incident.reporter_id, "Your incident status changed",
           f"Incident {incident_id} '{incident.title}' is now {new_status}.", "System Notification", "Low")
    return success(with_notes(find_incident_or_404(incident_id)),
                   f"Incident status updated from {incident.status} to {new_status}")


@app.route("/incidents/<int:incident_id>/notes", methods=["POST"])
@require_roles(ADMIN, ANALYST)
def add_investigation_note(incident_id):
    """Add Investigation Notes.

    Body: content. Analysts may only add notes to incidents assigned to them;
    closed incidents accept no new notes.
    Developed by: Yehia Afesh
    """
    data = Validator.body()
    Validator.require(data, ["content"])
    Validator.only_fields(data, ["content"])
    incident = find_incident_or_404(incident_id)
    check_access(incident)
    if incident.is_closed():
        raise ValidationError(f"Cannot add notes to incident {incident_id} because it is Closed")
    content = Validator.text(data["content"], "content", 5, 2000)

    note_id = notes.insert({"incident_id": incident_id, "analyst_id": g.user["user_id"], "content": content})
    incidents.update(incident_id, {"updated_at": incidents.now()})
    log_event(g.user["user_id"], "INCIDENT_NOTE_ADDED", f"Note {note_id} added to incident {incident_id}",
              "Information", "incidents")
    return success(notes.get_with_analyst(note_id).to_dict(), "Investigation note added successfully", 201)


if __name__ == "__main__":
    run_service(app)