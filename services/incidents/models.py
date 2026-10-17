"""Incident and investigation note entities."""


class Incident:
    """A cybersecurity incident tracked from report to closure."""

    def __init__(self, incident_id, title, description, category, severity, reporter_id, asset_id,
                 assigned_analyst_id, status, created_at=None, updated_at=None, resolved_at=None,
                 reporter_name=None, asset_name=None, analyst_name=None, notes_count=None):
        self.incident_id = incident_id
        self.title = title
        self.description = description
        self.category = category
        self.severity = severity
        self.reporter_id = reporter_id
        self.asset_id = asset_id
        self.assigned_analyst_id = assigned_analyst_id
        self.status = status
        self.created_at = created_at
        self.updated_at = updated_at
        self.resolved_at = resolved_at
        self.reporter_name = reporter_name
        self.asset_name = asset_name
        self.analyst_name = analyst_name
        self.notes_count = notes_count

    @classmethod
    def from_row(cls, row):
        """Build an Incident from a database row (joined names are optional)."""
        return cls(**{key: row[key] for key in row.keys()})

    def is_closed(self):
        """Return True once the incident reached the end of its lifecycle."""
        return self.status == "Closed"

    def to_dict(self):
        """Return the incident as a dictionary."""
        analyst = None
        if self.assigned_analyst_id is not None:
            analyst = {"user_id": self.assigned_analyst_id, "full_name": self.analyst_name}
        data = {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "reporter_id": self.reporter_id,
            "reporter_name": self.reporter_name,
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "assigned_analyst": analyst,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "resolved_at": self.resolved_at,
        }
        if self.notes_count is not None:
            data["notes_count"] = self.notes_count
        return data


class InvestigationNote:
    """An analyst's note attached to exactly one incident."""

    def __init__(self, note_id, incident_id, analyst_id, content, created_at=None, analyst_name=None):
        self.note_id = note_id
        self.incident_id = incident_id
        self.analyst_id = analyst_id
        self.content = content
        self.created_at = created_at
        self.analyst_name = analyst_name

    @classmethod
    def from_row(cls, row):
        """Build an InvestigationNote from a database row."""
        return cls(**{key: row[key] for key in row.keys()})

    def to_dict(self):
        """Return the note as a dictionary."""
        return {
            "note_id": self.note_id,
            "incident_id": self.incident_id,
            "analyst_id": self.analyst_id,
            "analyst_name": self.analyst_name,
            "content": self.content,
            "created_at": self.created_at,
        }