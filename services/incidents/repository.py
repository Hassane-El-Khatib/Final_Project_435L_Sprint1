"""Data access for incidents and investigation notes."""

from common.base_repository import BaseRepository
from services.incidents.models import Incident, InvestigationNote

SELECT_DETAILS = (
    "SELECT incidents.*, reporter.full_name AS reporter_name, assets.asset_name AS asset_name, "
    "analyst.full_name AS analyst_name, "
    "(SELECT COUNT(*) FROM investigation_notes n WHERE n.incident_id = incidents.incident_id) AS notes_count "
    "FROM incidents "
    "LEFT JOIN users reporter ON reporter.user_id = incidents.reporter_id "
    "LEFT JOIN users analyst ON analyst.user_id = incidents.assigned_analyst_id "
    "LEFT JOIN assets ON assets.asset_id = incidents.asset_id"
)


class IncidentRepository(BaseRepository):
    """Queries on the incidents table."""

    table = "incidents"
    id_column = "incident_id"
    columns = (
        "title",
        "description",
        "category",
        "severity",
        "reporter_id",
        "asset_id",
        "assigned_analyst_id",
        "status",
        "updated_at",
        "resolved_at",
    )
    model = Incident

    def get_details(self, incident_id):
        """Return one incident with reporter, analyst and asset names."""
        return self.fetch_one(f"{SELECT_DETAILS} WHERE incidents.incident_id = ?", (incident_id,))

    def list_incidents(self, status=None, severity=None):
        """Return incidents newest first, optionally filtered by status and severity."""
        conditions = []
        params = []
        if status is not None:
            conditions.append("incidents.status = ?")
            params.append(status)
        if severity is not None:
            conditions.append("incidents.severity = ?")
            params.append(severity)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"{SELECT_DETAILS}{where} ORDER BY incidents.created_at DESC, incidents.incident_id DESC"
        return self.fetch_all(sql, tuple(params))

    def asset_exists(self, asset_id):
        """Return True if the asset exists."""
        return self.fetch_value("SELECT 1 FROM assets WHERE asset_id = ?", (asset_id,)) is not None

    def now(self):
        """Return the current local time as stored by the database."""
        return self.fetch_value("SELECT datetime('now', 'localtime')")


class NoteRepository(BaseRepository):
    """Queries on the investigation_notes table."""

    table = "investigation_notes"
    id_column = "note_id"
    columns = ("incident_id", "analyst_id", "content")
    model = InvestigationNote

    def get_with_analyst(self, note_id):
        """Return one note with the analyst's name."""
        sql = ("SELECT investigation_notes.*, users.full_name AS analyst_name FROM investigation_notes "
               "LEFT JOIN users ON users.user_id = investigation_notes.analyst_id WHERE note_id = ?")
        return self.fetch_one(sql, (note_id,))

    def for_incident(self, incident_id):
        """Return all notes of an incident, oldest first."""
        sql = ("SELECT investigation_notes.*, users.full_name AS analyst_name FROM investigation_notes "
               "LEFT JOIN users ON users.user_id = investigation_notes.analyst_id "
               "WHERE incident_id = ? ORDER BY created_at, note_id")
        return self.fetch_all(sql, (incident_id,))