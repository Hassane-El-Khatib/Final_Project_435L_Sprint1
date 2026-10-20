"""Playbook, response action and action history entities."""


class Playbook:
    """A predefined incident response procedure for one incident category and severity."""

    def __init__(self, playbook_id, name, description, incident_category, severity, created_by, created_at=None,
                 created_by_name=None, action_count=None, completed_count=None):
        self.playbook_id = playbook_id
        self.name = name
        self.description = description
        self.incident_category = incident_category
        self.severity = severity
        self.created_by = created_by
        self.created_at = created_at
        self.created_by_name = created_by_name
        self.action_count = action_count
        self.completed_count = completed_count

    @classmethod
    def from_row(cls, row):
        """Build a Playbook from a database row (joined names and counts are optional)."""
        return cls(**{key: row[key] for key in row.keys()})

    def to_dict(self):
        """Return the playbook as a dictionary."""
        data = {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "incident_category": self.incident_category,
            "severity": self.severity,
            "created_by": self.created_by,
            "created_by_name": self.created_by_name,
            "created_at": self.created_at,
        }
        if self.action_count is not None:
            data["action_count"] = self.action_count
            data["completed_count"] = self.completed_count or 0
        return data


class ResponseAction:
    """One ordered step of a playbook, tracked from Pending to Completed."""

    def __init__(self, action_id, playbook_id, description, step_number, status, assigned_user_id=None,
                 completed_at=None, assigned_user_name=None):
        self.action_id = action_id
        self.playbook_id = playbook_id
        self.description = description
        self.step_number = step_number
        self.status = status
        self.assigned_user_id = assigned_user_id
        self.completed_at = completed_at
        self.assigned_user_name = assigned_user_name

    @classmethod
    def from_row(cls, row):
        """Build a ResponseAction from a database row."""
        return cls(**{key: row[key] for key in row.keys()})

    def to_dict(self):
        """Return the action as a dictionary."""
        assigned = None
        if self.assigned_user_id is not None:
            assigned = {"user_id": self.assigned_user_id, "full_name": self.assigned_user_name}
        return {
            "action_id": self.action_id,
            "playbook_id": self.playbook_id,
            "step_number": self.step_number,
            "description": self.description,
            "status": self.status,
            "assigned_user": assigned,
            "completed_at": self.completed_at,
        }


class ActionHistory:
    """A recorded change of an action's status or assignee."""

    def __init__(self, history_id, action_id, old_status, new_status, old_assignee, new_assignee, changed_by,
                 changed_at=None, changed_by_name=None):
        self.history_id = history_id
        self.action_id = action_id
        self.old_status = old_status
        self.new_status = new_status
        self.old_assignee = old_assignee
        self.new_assignee = new_assignee
        self.changed_by = changed_by
        self.changed_at = changed_at
        self.changed_by_name = changed_by_name

    @classmethod
    def from_row(cls, row):
        """Build an ActionHistory entry from a database row."""
        return cls(**{key: row[key] for key in row.keys()})

    def to_dict(self):
        """Return the history entry as a dictionary."""
        return {
            "history_id": self.history_id,
            "old_status": self.old_status,
            "new_status": self.new_status,
            "old_assignee": self.old_assignee,
            "new_assignee": self.new_assignee,
            "changed_by": self.changed_by,
            "changed_by_name": self.changed_by_name,
            "changed_at": self.changed_at,
        }
