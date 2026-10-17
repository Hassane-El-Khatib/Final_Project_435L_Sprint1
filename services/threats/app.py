from flask import request, jsonify
import sqlite3
import os
import ipaddress
import re
from common.app_factory import create_app, run_service
from common.auth import require_roles
from common.clients import log_event, notify_role
from common.validators import Validator

app = create_app("threats")

def get_db():
    db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../database/sidrms.db'))
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    return db

@app.route('/threats', methods=['POST'])
@require_roles(['Security Administrator'])
def add_threat():
    data = request.json or {}
    Validator.require_fields(data, ['type', 'value', 'severity'])
    t_type, t_val, sev = data.get('type'), data.get('value'), data.get('severity')
    try:
        if t_type == 'IP Address':
            ipaddress.ip_address(t_val)
        elif t_type == 'Domain':
            if not re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", t_val):
                return jsonify({"status": "error", "message": "Invalid Domain format"}), 400
        elif t_type == 'File Hash':
            if not re.match(r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$", t_val):
                return jsonify({"status": "error", "message": "Invalid Hash format"}), 400
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid IP format"}), 400

    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO threats (threat_type, threat_value, description, severity_level, source) VALUES (?, ?, ?, ?, ?)",
            (t_type, t_val, data.get('description'), sev, data.get('source'))
        )
        db.commit()
        log_event(request.user['user_id'], 'THREAT_ADDED', f'Added threat {t_val}', 'Warning', 'Threat Intelligence')
        if sev in ['High', 'Critical']:
            notify_role(['Security Administrator', 'Security Analyst'], 'Threat Alert', f'New {sev} threat added: {t_val}', 'Threat Alert', sev)
        return jsonify({"status": "success", "data": {"threat_id": cursor.lastrowid}}), 201
    except Exception:
        return jsonify({"status": "error", "message": "Duplicate threat indicator"}), 409

@app.route('/threats', methods=['GET'])
@require_roles(['Security Administrator', 'Security Analyst', 'Auditor'])
def get_threats():
    db = get_db()
    rows = db.execute("SELECT * FROM threats").fetchall()
    return jsonify({"status": "success", "data": [dict(r) for r in rows]}), 200

@app.route('/threats/<int:id>', methods=['GET'])
@require_roles(['Security Administrator', 'Security Analyst', 'Auditor'])
def get_threat(id):
    db = get_db()
    threat = db.execute("SELECT * FROM threats WHERE threat_id = ?", (id,)).fetchone()
    if not threat:
        return jsonify({"status": "error", "message": "Threat not found"}), 404
    return jsonify({"status": "success", "data": dict(threat)}), 200

@app.route('/threats/search', methods=['GET'])
@require_roles(['Security Administrator', 'Security Analyst', 'Auditor'])
def search_threats():
    query, params = "SELECT * FROM threats WHERE 1=1", []
    if 'type' in request.args:
        query, params = query + " AND threat_type = ?", params + [request.args['type']]
    if 'value' in request.args:
        query, params = query + " AND threat_value LIKE ?", params + [f"%{request.args['value']}%"]
    if 'severity' in request.args:
        query, params = query + " AND severity_level = ?", params + [request.args['severity']]
    db = get_db()
    rows = db.execute(query, params).fetchall()
    return jsonify({"status": "success", "data": [dict(r) for r in rows]}), 200

@app.route('/threats/<int:id>', methods=['PUT'])
@require_roles(['Security Administrator'])
def update_threat(id):
    data = request.json or {}
    if 'type' in data or 'value' in data:
        return jsonify({"status": "error", "message": "Cannot modify threat type or value"}), 400
    db = get_db()
    db.execute("UPDATE threats SET description = ?, severity_level = ?, source = ? WHERE threat_id = ?",
               (data.get('description'), data.get('severity'), data.get('source'), id))
    db.commit()
    log_event(request.user['user_id'], 'THREAT_UPDATED', f'Updated threat ID {id}', 'Information', 'Threat Intelligence')
    return jsonify({"status": "success", "message": "Threat updated successfully"}), 200

@app.route('/threats/<int:id>', methods=['DELETE'])
@require_roles(['Security Administrator'])
def delete_threat(id):
    db = get_db()
    db.execute("DELETE FROM threats WHERE threat_id = ?", (id,))
    db.commit()
    log_event(request.user['user_id'], 'THREAT_DELETED', f'Deleted threat ID {id}', 'Warning', 'Threat Intelligence')
    return jsonify({"status": "success", "message": "Threat deleted successfully"}), 200

if __name__ == "__main__":
    run_service(app)