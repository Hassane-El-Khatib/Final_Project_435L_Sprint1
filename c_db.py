"""Print database tables and report proofs for evidence screenshots.

Usage:
    python c_db.py columns
    python c_db.py fks
    python c_db.py <table> [WHERE condition]
    python c_db.py check <activity|summary|incidents|assets|threats|vulnerabilities>
"""

import sqlite3
import sys

DB_PATH = "database/sidrms.db"
MY_TABLES = ["threats", "playbooks", "response_actions", "action_history"]
CHECKS = {
    "activity": [
        "SELECT COUNT(*) AS total_activities FROM logs",
        "SELECT action, COUNT(*) AS count FROM logs WHERE action IN ('LOGIN_SUCCESS', 'LOGIN_FAILED', 'UNAUTHORIZED_ACCESS') GROUP BY action",
        "SELECT action, COUNT(*) AS count FROM logs GROUP BY action ORDER BY count DESC, action LIMIT 5",
    ],
    "summary": [
        "SELECT (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM assets) AS assets, "
        "(SELECT COUNT(*) FROM incidents WHERE status IN ('Open', 'Under Investigation', 'Mitigated')) AS open_incidents, "
        "(SELECT COUNT(*) FROM threats WHERE severity = 'Critical') AS critical_threats",
        "SELECT (SELECT COUNT(*) FROM incidents) AS total_incidents, (SELECT COUNT(*) FROM threats) AS threats, "
        "(SELECT COUNT(*) FROM vulnerabilities WHERE status NOT IN ('Resolved', 'Closed')) AS open_vulnerabilities, "
        "(SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'Critical') AS critical_vulnerabilities",
    ],
    "incidents": [
        "SELECT COUNT(*) AS total_incidents, SUM(assigned_analyst_id IS NULL) AS unassigned FROM incidents",
        "SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity",
        "SELECT status, COUNT(*) AS count FROM incidents GROUP BY status",
        "SELECT category, COUNT(*) AS count FROM incidents GROUP BY category",
    ],
    "assets": [
        "SELECT COUNT(*) AS total_assets FROM assets",
        "SELECT asset_id, asset_name FROM assets WHERE criticality = 'Critical'",
        "SELECT asset_type, COUNT(*) AS count FROM assets GROUP BY asset_type",
        "SELECT status, COUNT(*) AS count FROM assets GROUP BY status",
    ],
    "threats": [
        "SELECT COUNT(*) AS total_threats FROM threats",
        "SELECT severity, COUNT(*) AS count FROM threats GROUP BY severity",
        "SELECT threat_type, COUNT(*) AS count FROM threats GROUP BY threat_type",
        "SELECT threat_id, threat_type, threat_value, severity, date_added FROM threats ORDER BY date_added DESC, threat_id DESC LIMIT 5",
    ],
    "vulnerabilities": [
        "SELECT COUNT(*) AS total, ROUND(AVG(cvss_score), 1) AS average_cvss FROM vulnerabilities",
        "SELECT severity, COUNT(*) AS count FROM vulnerabilities GROUP BY severity",
        "SELECT status, COUNT(*) AS count FROM vulnerabilities GROUP BY status",
        "SELECT vulnerability_id, cve_id, status FROM vulnerabilities WHERE severity = 'Critical'",
    ],
}


def show(cursor, title):
    """Print the rows of a cursor as an aligned table."""
    headers = [column[0] for column in cursor.description]
    rows = [["" if value is None else str(value) for value in row] for row in cursor.fetchall()]
    widths = [min(max([len(h)] + [len(r[i]) for r in rows]), 40) for i, h in enumerate(headers)]
    print(f"\n== {title} ({len(rows)} rows) ==")
    print(" | ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("+".join("-" * (w + 2) for w in widths))
    for row in rows:
        print(" | ".join(value[:w].ljust(w) for value, w in zip(row, widths)))


def main():
    """Run the requested view."""
    connection = sqlite3.connect(DB_PATH)
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    if args[0] == "columns":
        for table in MY_TABLES:
            show(connection.execute(f"SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info('{table}')"),
                 f"Columns of {table}")
    elif args[0] == "fks":
        for table in MY_TABLES:
            show(connection.execute(f"SELECT \"from\" AS column_name, \"table\" AS references_table, \"to\" AS references_column, "
                                    f"on_delete FROM pragma_foreign_key_list('{table}')"), f"Foreign keys of {table}")
    elif args[0] == "check":
        for sql in CHECKS[args[1]]:
            print(f"\nSQL> {sql};")
            show(connection.execute(sql), "result")
    else:
        where = " ".join(args[1:])
        sql = f"SELECT * FROM {args[0]}" + (f" WHERE {where}" if where else "")
        print(f"SQL> {sql};")
        show(connection.execute(sql), args[0])
    connection.close()


if __name__ == "__main__":
    main()
