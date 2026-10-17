from flask import request, jsonify
import sqlite3
import os
from common.app_factory import create_app, run_service
from common.auth import require_roles
from common.clients import log_event
from common.validators import Validator

app = create_app("playbooks")

def get_db():
    db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../database/sidrms.db'))
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    return db

@app.route('/playbooks', methods=['POST'])
@require_roles(['Security Administrator'])
def create_playbook():
    data = request.json or {}
    Validator.require_fields(data, ['name', 'incident_category', 'severity'])
    db = get_db()
    cursor = db.execute(
        "INSERT INTO playbooks (playbook_name, description, incident_category, severity_level, created_by) VALUES (?, ?, ?, ?, ?)",
        (data['name'], data.get('description'), data['incident_category'], data['severity'], request.user['user_id'])
    )
    db.commit()
    log_event(request.user['user_id'], 'PLAYBOOK_CREATED', f"Created playbook {data['name']}", 'Information', 'Playbooks')
    return jsonify({"status": "success", "data": {"playbook_id": cursor.lastrowid}}), 201

@app.route('/playbooks', methods=['GET'])
@require_roles(['Security Administrator', 'Security Analyst', 'Auditor'])
def get_playbooks():
    db = get_db()
    query = """
        SELECT p.*, COUNT(a.action_id) as action_count 
        FROM playbooks p 
        LEFT JOIN response_actions a ON p.playbook_id = a.playbook_id 
        GROUP BY p.playbook_id
    """
    rows = db.execute(query).fetchall()
    return jsonify({"status": "success", "data": [dict(r) for r in rows]}), 200

@app.route('/playbooks/<int:id>', methods=['GET'])
@require_roles(['Security Administrator', 'Security Analyst', 'Auditor'])
def get_playbook(id):
    db = get_db()
    playbook = db.execute("SELECT * FROM playbooks WHERE playbook_id = ?", (id,)).fetchone()
    if not playbook:
        return jsonify({"status": "error", "message": "Playbook not found"}), 404
    actions = db.execute("SELECT * FROM response_actions WHERE playbook_id = ? ORDER BY step_number ASC", (id,)).fetchall()
    data = dict(playbook)
    data['actions'] = [dict(a) for a in actions]
    return jsonify({"status": "success", "data": data}), 200

@app.route('/playbooks/<int:id>/actions', methods=['POST'])
@require_roles(['Security Administrator', 'Security Analyst'])
def add_action(id):
    data = request.json or {}
    step = data.get('step_number')
    if not isinstance(step, int) or step <= 0:
        return jsonify({"status": "error", "message": "Step number must be a positive integer"}), 400
    db = get_db()
    try:
        db.execute(
            "INSERT INTO response_actions (playbook_id, action_description, step_number, assigned_user_id) VALUES (?, ?, ?, ?)",
            (id, data.get('description'), step, data.get('assigned_user'))
        )
        db.commit()
        return jsonify({"status": "success", "message": "Action added successfully"}), 201
    except Exception:
        return jsonify({"status": "error", "message": "Step number already exists in playbook"}), 409

@app.route('/actions/<int:id>/status', methods=['PUT'])
@require_roles(['Security Administrator', 'Security Analyst'])
def update_action_status(id):
    data = request.json or {}
    new_status = data.get('status')
    valid_transitions = {'Pending': ['In Progress'], 'In Progress': ['Completed']}
    db = get_db()
    action = db.execute("SELECT status FROM response_actions WHERE action_id = ?", (id,)).fetchone()
    if not action:
        return jsonify({"status": "error", "message": "Action not found"}), 404
    if new_status not in valid_transitions.get(action['status'], []):
        return jsonify({"status": "error", "message": f"Invalid transition from {action['status']} to {new_status}"}), 400

    query, params = "UPDATE response_actions SET status = ?", [new_status]
    if new_status == 'Completed':
        query += ", completion_date = CURRENT_TIMESTAMP"
    query, params = query + " WHERE action_id = ?", params + [id]
    db.execute(query, params)
    db.execute(
        "INSERT INTO action_history (action_id, previous_status, new_status, changed_by) VALUES (?, ?, ?, ?)",
        (id, action['status'], new_status, request.user['user_id'])
    )
    db.commit()
    return jsonify({"status": "success", "message": "Action status updated"}), 200

@app.route('/playbooks/<int:id>', methods=['DELETE'])
@require_roles(['Security Administrator'])
def delete_playbook(id):
    db = get_db()
    db.execute("DELETE FROM playbooks WHERE playbook_id = ?", (id,))
    db.commit()
    log_event(request.user['user_id'], 'PLAYBOOK_DELETED', f'Deleted playbook ID {id}', 'Warning', 'Playbooks')
    return jsonify({"status": "success", "message": "Playbook deleted successfully"}), 200

if __name__ == "__main__":
    run_service(app)