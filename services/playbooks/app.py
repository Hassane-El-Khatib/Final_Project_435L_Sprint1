"""Security Playbook and Response Automation Service (port 5009).

Developed by: Abdul Rahman Habbal
"""

from datetime import datetime

from flask import g, request

from common.app_factory import create_app, run_service
from common.auth import require_roles
from common.clients import get_user, log_event, notify
from common.constants import ACTION_FLOW, ADMIN, ANALYST, AUDITOR, INCIDENT_CATEGORIES, SEVERITIES
from common.errors import ConflictError, NotFoundError, ValidationError
from common.responses import success
from common.validators import Validator
from services.playbooks.repository import ActionHistoryRepository, ActionRepository, PlaybookRepository

app = create_app("playbooks")
playbooks = PlaybookRepository()
actions = ActionRepository()
history = ActionHistoryRepository()

PLAYBOOK_FIELDS = ["name", "description", "incident_category", "severity"]
ACTION_FIELDS = ["description", "step_number", "assigned_user_id"]
STATUS_FIELDS = ["status", "assigned_user_id", "completed_at"]


def find_playbook_or_404(playbook_id):
    """Return the playbook with its counts or raise NotFoundError."""
    playbook = playbooks.get_details(playbook_id)
    if playbook is None:
        raise NotFoundError(f"Playbook {playbook_id} not found")
    return playbook


def find_action_or_404(action_id):
    """Return the response action or raise NotFoundError."""
    action = actions.get_details(action_id)
    if action is None:
        raise NotFoundError(f"Action {action_id} not found")
    return action


def action_with_history(action):
    """Return the action as a dictionary including its history, oldest first."""
    data = action.to_dict()
    data["history"] = [entry.to_dict() for entry in history.for_action(action.action_id)]
    return data


def playbook_with_actions(playbook):
    """Return the playbook as a dictionary including its actions in step order."""
    data = playbook.to_dict()
    data["actions"] = [action_with_history(action) for action in actions.for_playbook(playbook.playbook_id)]
    return data


def validate_assignee(user_id):
    """Ensure the assignee is an active Security Administrator or Security Analyst."""
    Validator.integer(user_id, "assigned_user_id", 1)
    user = get_user(user_id)
    if user is None:
        raise ValidationError(f"User {user_id} does not exist")
    if user["role"] not in (ADMIN, ANALYST):
        raise ValidationError(f"User {user_id} ({user['username']}) is not security staff; only administrators "
                              "and analysts execute response actions")
    if user["account_status"] != "Active":
        raise ValidationError(f"User {user_id} ({user['username']}) is not active")
    return user


@app.route("/playbooks", methods=["POST"])
@require_roles(ADMIN)
def create_playbook():
    """Create Response Playbook.

    Required: name, description, incident_category, severity. Playbook names are unique.
    Developed by: Abdul Rahman Habbal
    """
    data = Validator.body()
    Validator.require(data, PLAYBOOK_FIELDS)
    Validator.only_fields(data, PLAYBOOK_FIELDS)
    name = Validator.text(data["name"], "name", 3, 100)
    description = Validator.text(data["description"], "description", 10, 1000)
    incident_category = Validator.enum(data["incident_category"], INCIDENT_CATEGORIES, "incident_category")
    severity = Validator.enum(data["severity"], SEVERITIES, "severity")
    existing = playbooks.name_taken(name)
    if existing:
        raise ConflictError(f"A playbook named '{name}' already exists (playbook {existing})")

    playbook_id = playbooks.insert({
        "name": name,
        "description": description,
        "incident_category": incident_category,
        "severity": severity,
        "created_by": g.user["user_id"],
    })
    log_event(g.user["user_id"], "PLAYBOOK_CREATED",
              f"Playbook {playbook_id} '{name}' ({incident_category}, {severity}) created", "Information", "playbooks")
    return success(playbook_with_actions(find_playbook_or_404(playbook_id)), "Playbook created successfully", 201)


@app.route("/playbooks", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def get_all_playbooks():
    """Retrieve All Playbooks.

    Returns every playbook with its creator, number of actions and completed actions.
    Optional query parameters: incident_category, severity.
    Developed by: Abdul Rahman Habbal
    """
    Validator.only_query(["incident_category", "severity"])
    category = severity = None
    if "incident_category" in request.args:
        category = Validator.enum(request.args["incident_category"], INCIDENT_CATEGORIES, "incident_category")
    if "severity" in request.args:
        severity = Validator.enum(request.args["severity"], SEVERITIES, "severity")
    result = [playbook.to_dict() for playbook in playbooks.summary_list(category, severity)]
    return success(result, "Playbooks retrieved successfully")


@app.route("/playbooks/<int:playbook_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def get_playbook(playbook_id):
    """Retrieve Specific Playbook.

    Returns the playbook with its response actions in step order, each with its history.
    Developed by: Abdul Rahman Habbal
    """
    return success(playbook_with_actions(find_playbook_or_404(playbook_id)), "Playbook retrieved successfully")


@app.route("/playbooks/<int:playbook_id>/actions", methods=["POST"])
@require_roles(ADMIN, ANALYST)
def add_response_action(playbook_id):
    """Add Response Action.

    Required: description, step_number (a positive integer, unique within the playbook).
    Optional: assigned_user_id (an active Security Administrator or Security Analyst).
    Developed by: Abdul Rahman Habbal
    """
    data = Validator.body()
    playbook = find_playbook_or_404(playbook_id)
    Validator.require(data, ["description", "step_number"])
    Validator.only_fields(data, ACTION_FIELDS)
    description = Validator.text(data["description"], "description", 5, 500)
    step_number = Validator.integer(data["step_number"], "step_number", 1)
    if actions.step_taken(playbook_id, step_number):
        raise ConflictError(f"Step {step_number} already exists in playbook {playbook_id}")
    assignee = None
    if data.get("assigned_user_id") is not None:
        assignee = validate_assignee(data["assigned_user_id"])["user_id"]

    action_id = actions.insert({
        "playbook_id": playbook_id,
        "description": description,
        "step_number": step_number,
        "status": "Pending",
        "assigned_user_id": assignee,
    })
    history.insert({"action_id": action_id, "old_status": None, "new_status": "Pending", "old_assignee": None,
                    "new_assignee": assignee, "changed_by": g.user["user_id"]})
    log_event(g.user["user_id"], "ACTION_ADDED",
              f"Step {step_number} (action {action_id}) added to playbook {playbook_id} '{playbook.name}'",
              "Information", "playbooks")
    if assignee is not None:
        notify(assignee, "Response action assigned",
               f"Step {step_number} of playbook '{playbook.name}': {description}", "System Notification",
               playbook.severity)
    return success(action_with_history(find_action_or_404(action_id)), "Response action added successfully", 201)


@app.route("/actions/<int:action_id>/status", methods=["PUT"])
@require_roles(ADMIN, ANALYST)
def update_action_status(action_id):
    """Update Response Action Status.

    Body (at least one): status, assigned_user_id, completed_at. Status follows
    Pending -> In Progress -> Completed; a step can only start when every earlier step is
    Completed and someone is assigned. Every change is stored in the action history.
    Developed by: Abdul Rahman Habbal
    """
    data = Validator.body()
    action = find_action_or_404(action_id)
    Validator.only_fields(data, STATUS_FIELDS)
    if not data:
        raise ValidationError(f"Provide at least one field: {', '.join(STATUS_FIELDS)}")
    if action.status == "Completed":
        raise ValidationError(f"Action {action_id} is already Completed and cannot change anymore")

    changes = {}
    new_status = action.status
    if "status" in data:
        new_status = Validator.enum(data["status"], ACTION_FLOW, "status")
        if new_status != action.status:
            Validator.transition(action.status, new_status, ACTION_FLOW)
            changes["status"] = new_status
    new_assignee = action.assigned_user_id
    if data.get("assigned_user_id") is not None:
        new_assignee = validate_assignee(data["assigned_user_id"])["user_id"]
        if new_assignee != action.assigned_user_id:
            changes["assigned_user_id"] = new_assignee
    if new_status == "In Progress" and "status" in changes:
        blocking = actions.first_unfinished_earlier_step(action.playbook_id, action.step_number)
        if blocking is not None:
            raise ValidationError(f"Step {blocking} must be completed before starting step {action.step_number}")
        if new_assignee is None:
            raise ValidationError("Assign a user before starting this action")
    if "completed_at" in data:
        if new_status != "Completed" or "status" not in changes:
            raise ValidationError("completed_at can only be set together with status Completed")
        completed_at = Validator.date(data["completed_at"], "completed_at")
        if completed_at > datetime.now().strftime("%Y-%m-%d %H:%M:%S"):
            raise ValidationError("completed_at cannot be in the future")
        changes["completed_at"] = completed_at
    elif changes.get("status") == "Completed":
        changes["completed_at"] = actions.now()
    if not changes:
        return success(action_with_history(action), "No changes were made")

    actions.update(action_id, changes)
    history.insert({"action_id": action_id, "old_status": action.status, "new_status": new_status,
                    "old_assignee": action.assigned_user_id, "new_assignee": new_assignee,
                    "changed_by": g.user["user_id"]})
    log_event(g.user["user_id"], "ACTION_UPDATED",
              f"Action {action_id} (step {action.step_number} of playbook {action.playbook_id}): "
              f"{action.status} -> {new_status}, assignee {action.assigned_user_id} -> {new_assignee}",
              "Information", "playbooks")
    if "assigned_user_id" in changes:
        playbook = find_playbook_or_404(action.playbook_id)
        notify(new_assignee, "Response action assigned",
               f"Step {action.step_number} of playbook '{playbook.name}': {action.description}",
               "System Notification", playbook.severity)
    return success(action_with_history(find_action_or_404(action_id)), "Action updated successfully")


@app.route("/playbooks/<int:playbook_id>", methods=["DELETE"])
@require_roles(ADMIN)
def delete_playbook(playbook_id):
    """Delete Playbook.

    Only Security Administrators may delete playbooks; the playbook's actions and their
    history are deleted with it.
    Developed by: Abdul Rahman Habbal
    """
    playbook = find_playbook_or_404(playbook_id)
    playbooks.delete(playbook_id)
    log_event(g.user["user_id"], "PLAYBOOK_DELETED",
              f"Playbook {playbook_id} '{playbook.name}' deleted with {playbook.action_count} actions",
              "Warning", "playbooks")
    return success(message=f"Playbook {playbook_id} ({playbook.name}) deleted with {playbook.action_count} actions")


if __name__ == "__main__":
    run_service(app)
