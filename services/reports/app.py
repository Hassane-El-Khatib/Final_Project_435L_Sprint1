from flask import jsonify
import sqlite3
import os
from common.app_factory import create_app, run_service
from common.auth import require_roles

app = create_app("reports")

def get_db():
    db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../database/sidrms.db'))
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    return db

@app.route('/reports/summary', methods=['GET'])
@require_roles(['Security Administrator', 'Auditor'])
def summary_report():
    db = get_db()
    users = db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
    assets = db.execute("SELECT COUNT(*) as c FROM assets").fetchone()['c']
    open_incidents = db.execute("SELECT COUNT(*) as c FROM incidents WHERE status != 'Closed'").fetchone()['c']
    critical_threats = db.execute("SELECT COUNT(*) as c FROM threats WHERE severity_level = 'Critical'").fetchone()['c']
    vulns = db.execute("SELECT COUNT(*) as c FROM vulnerabilities").fetchone()['c']
    return jsonify({
        "status": "success",
        "data": {
            "users": users,
            "assets": assets,
            "open_incidents": open_incidents,
            "critical_threats": critical_threats,
            "vulnerabilities": vulns
        }
    }), 200

@app.route('/reports/incidents', methods=['GET'])
@require_roles(['Security Administrator', 'Auditor'])
def incident_report():
    db = get_db()
    total = db.execute("SELECT COUNT(*) as c FROM incidents").fetchone()['c']
    by_sev = db.execute("SELECT severity, COUNT(*) as count FROM incidents GROUP BY severity").fetchall()
    by_status = db.execute("SELECT status, COUNT(*) as count FROM incidents GROUP BY status").fetchall()
    return jsonify({"status": "success", "data": {"total_incidents": total, "by_severity": [dict(r) for r in by_sev], "by_status": [dict(r) for r in by_status]}}), 200

@app.route('/reports/assets', methods=['GET'])
@require_roles(['Security Administrator', 'Auditor'])
def asset_report():
    db = get_db()
    total = db.execute("SELECT COUNT(*) as c FROM assets").fetchone()['c']
    critical = db.execute("SELECT COUNT(*) as c FROM assets WHERE criticality_level = 'Critical'").fetchone()['c']
    by_type = db.execute("SELECT asset_type, COUNT(*) as count FROM assets GROUP BY asset_type").fetchall()
    return jsonify({"status": "success", "data": {"total_assets": total, "critical_assets": critical, "by_type": [dict(r) for r in by_type]}}), 200

@app.route('/reports/threats', methods=['GET'])
@require_roles(['Security Administrator', 'Auditor'])
def threat_report():
    db = get_db()
    total = db.execute("SELECT COUNT(*) as c FROM threats").fetchone()['c']
    by_sev = db.execute("SELECT severity_level, COUNT(*) as count FROM threats GROUP BY severity_level").fetchall()
    by_type = db.execute("SELECT threat_type, COUNT(*) as count FROM threats GROUP BY threat_type").fetchall()
    recent = db.execute("SELECT * FROM threats ORDER BY date_added DESC LIMIT 5").fetchall()
    return jsonify({"status": "success", "data": {"total_threats": total, "by_severity": [dict(r) for r in by_sev], "by_type": [dict(r) for r in by_type], "recent_threats": [dict(r) for r in recent]}}), 200

@app.route('/reports/vulnerabilities', methods=['GET'])
@require_roles(['Security Administrator', 'Auditor'])
def vuln_report():
    db = get_db()
    total = db.execute("SELECT COUNT(*) as c FROM vulnerabilities").fetchone()['c']
    by_sev = db.execute("SELECT severity_level, COUNT(*) as count FROM vulnerabilities GROUP BY severity_level").fetchall()
    by_status = db.execute("SELECT status, COUNT(*) as count FROM vulnerabilities GROUP BY status").fetchall()
    critical_list = db.execute("SELECT * FROM vulnerabilities WHERE severity_level = 'Critical'").fetchall()
    return jsonify({"status": "success", "data": {"total_vulnerabilities": total, "by_severity": [dict(r) for r in by_sev], "by_status": [dict(r) for r in by_status], "critical_vulnerabilities": [dict(r) for r in critical_list]}}), 200

@app.route('/reports/activity', methods=['GET'])
@require_roles(['Security Administrator', 'Auditor'])
def activity_report():
    db = get_db()
    total = db.execute("SELECT COUNT(*) as c FROM logs").fetchone()['c']
    login_attempts = db.execute("SELECT COUNT(*) as c FROM logs WHERE action_performed IN ('LOGIN_SUCCESS', 'LOGIN_FAILED')").fetchone()['c']
    failed_logins = db.execute("SELECT COUNT(*) as c FROM logs WHERE action_performed = 'LOGIN_FAILED'").fetchone()['c']
    top_actions = db.execute("SELECT action_performed, COUNT(*) as count FROM logs GROUP BY action_performed ORDER BY count DESC LIMIT 5").fetchall()
    return jsonify({"status": "success", "data": {"total_activities": total, "login_attempts": login_attempts, "failed_logins": failed_logins, "top_actions": [dict(r) for r in top_actions]}}), 200

if __name__ == "__main__":
    run_service(app)