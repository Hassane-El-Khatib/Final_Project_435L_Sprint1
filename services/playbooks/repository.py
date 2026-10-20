"""Data access for playbooks, response actions and their history."""

from common.base_repository import BaseRepository
from services.playbooks.models import ActionHistory, Playbook, ResponseAction

SELECT_PLAYBOOK = (
    "SELECT playbooks.*, users.full_name AS created_by_name, "
    "(SELECT COUNT(*) FROM response_actions a WHERE a.playbook_id = playbooks.playbook_id) AS action_count, "
    "(SELECT COUNT(*) FROM response_actions a WHERE a.playbook_id = playbooks.playbook_id "
    "AND a.status = 'Completed') AS completed_count "
    "FROM playbooks LEFT JOIN users ON users.user_id = playbooks.created_by"
)
SELECT_ACTION = (
    "SELECT response_actions.*, users.full_name AS assigned_user_name FROM response_actions "
    "LEFT JOIN users ON users.user_id = response_actions.assigned_user_id"
)


class PlaybookRepository(BaseRepository):
    """Queries on the playbooks table."""

    table = "playbooks"
    id_column = "playbook_id"
    columns = ("name", "description", "incident_category", "severity", "created_by")
    model = Playbook
    duplicate_message = "A playbook with this name already exists"

    def get_details(self, playbook_id):
        """Return one playbook with its creator's name and action counts."""
        return self.fetch_one(f"{SELECT_PLAYBOOK} WHERE playbooks.playbook_id = ?", (playbook_id,))

    def summary_list(self, incident_category=None, severity=None):
        """Return all playbooks with action counts, optionally filtered."""
        conditions = []
        params = []
        if incident_category is not None:
            conditions.append("playbooks.incident_category = ?")
            params.append(incident_category)
        if severity is not None:
            conditions.append("playbooks.severity = ?")
            params.append(severity)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        return self.fetch_all(f"{SELECT_PLAYBOOK}{where} ORDER BY playbooks.playbook_id", tuple(params))

    def name_taken(self, name):
        """Return the id of a playbook with the same name (case-insensitive), or None."""
        return self.fetch_value("SELECT playbook_id FROM playbooks WHERE LOWER(name) = LOWER(?)", (name,))


class ActionRepository(BaseRepository):
    """Queries on the response_actions table."""

    table = "response_actions"
    id_column = "action_id"
    columns = ("playbook_id", "description", "step_number", "status", "assigned_user_id", "completed_at")
    model = ResponseAction
    duplicate_message = "This step number already exists in the playbook"

    def get_details(self, action_id):
        """Return one action with the assigned user's name."""
        return self.fetch_one(f"{SELECT_ACTION} WHERE response_actions.action_id = ?", (action_id,))

    def for_playbook(self, playbook_id):
        """Return the actions of a playbook in step order."""
        sql = f"{SELECT_ACTION} WHERE response_actions.playbook_id = ? ORDER BY response_actions.step_number"
        return self.fetch_all(sql, (playbook_id,))

    def step_taken(self, playbook_id, step_number):
        """Return True if the playbook already has this step number."""
        sql = "SELECT 1 FROM response_actions WHERE playbook_id = ? AND step_number = ?"
        return self.fetch_value(sql, (playbook_id, step_number)) is not None

    def first_unfinished_earlier_step(self, playbook_id, step_number):
        """Return the lowest earlier step that is not Completed, or None if all are done."""
        sql = ("SELECT MIN(step_number) FROM response_actions "
               "WHERE playbook_id = ? AND step_number < ? AND status != 'Completed'")
        return self.fetch_value(sql, (playbook_id, step_number))

    def now(self):
        """Return the current local time as stored by the database."""
        return self.fetch_value("SELECT datetime('now', 'localtime')")


class ActionHistoryRepository(BaseRepository):
    """Queries on the action_history table."""

    table = "action_history"
    id_column = "history_id"
    columns = ("action_id", "old_status", "new_status", "old_assignee", "new_assignee", "changed_by")
    model = ActionHistory

    def for_action(self, action_id):
        """Return the history of one action, oldest first."""
        sql = ("SELECT action_history.*, users.full_name AS changed_by_name FROM action_history "
               "LEFT JOIN users ON users.user_id = action_history.changed_by "
               "WHERE action_id = ? ORDER BY changed_at, history_id")
        return self.fetch_all(sql, (action_id,))
