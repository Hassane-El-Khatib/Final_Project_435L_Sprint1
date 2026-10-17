PRAGMA foreign_keys = ON;

CREATE TABLE users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name       TEXT NOT NULL,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    department      TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('Security Administrator', 'Security Analyst', 'Regular User', 'Auditor')),
    account_status  TEXT NOT NULL DEFAULT 'Active' CHECK (account_status IN ('Active', 'Inactive', 'Suspended')),
    created_at      TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    last_login      TEXT
);

CREATE TABLE logs (
    log_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    action           TEXT NOT NULL,
    description      TEXT NOT NULL,
    timestamp        TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    severity         TEXT NOT NULL CHECK (severity IN ('Information', 'Warning', 'Error', 'Critical')),
    related_service  TEXT NOT NULL CHECK (related_service IN ('users', 'assets', 'incidents', 'threats', 'logs', 'reports', 'vulnerabilities', 'notifications', 'playbooks'))
);

CREATE INDEX idx_logs_user ON logs(user_id);

CREATE TRIGGER logs_are_immutable
BEFORE UPDATE OF log_id, action, description, timestamp, severity, related_service ON logs
BEGIN
    SELECT RAISE(ABORT, 'Audit logs cannot be modified');
END;

CREATE TRIGGER logs_user_cannot_be_reassigned
BEFORE UPDATE OF user_id ON logs
WHEN NEW.user_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'Audit logs cannot be modified');
END;

CREATE TABLE notifications (
    notification_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    title              TEXT NOT NULL,
    message            TEXT NOT NULL,
    notification_type  TEXT NOT NULL CHECK (notification_type IN ('Incident Assignment', 'Security Alert', 'System Notification', 'Threat Alert', 'Vulnerability Alert')),
    severity           TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    status             TEXT NOT NULL DEFAULT 'Unread' CHECK (status IN ('Unread', 'Read')),
    created_at         TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    read_at            TEXT
);

CREATE INDEX idx_notifications_user ON notifications(user_id);


CREATE TABLE IF NOT EXISTS threats (
    threat_id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type TEXT NOT NULL CHECK(threat_type IN ('IP Address', 'Domain', 'File Hash', 'Malware Signature', 'Other')),
    threat_value TEXT NOT NULL,
    description TEXT,
    severity_level TEXT NOT NULL CHECK(severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    source TEXT,
    date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(threat_type, threat_value)
);

CREATE TABLE IF NOT EXISTS playbooks (
    playbook_id INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_name TEXT NOT NULL,
    description TEXT,
    incident_category TEXT NOT NULL,
    severity_level TEXT NOT NULL CHECK(severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    created_by INTEGER,
    creation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS response_actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id INTEGER NOT NULL,
    action_description TEXT NOT NULL,
    step_number INTEGER NOT NULL,
    status TEXT DEFAULT 'Pending' CHECK(status IN ('Pending', 'In Progress', 'Completed')),
    assigned_user_id INTEGER,
    completion_date DATETIME,
    FOREIGN KEY(playbook_id) REFERENCES playbooks(playbook_id) ON DELETE CASCADE,
    FOREIGN KEY(assigned_user_id) REFERENCES users(user_id),
    UNIQUE(playbook_id, step_number)
);

CREATE TABLE IF NOT EXISTS action_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id INTEGER NOT NULL,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    changed_by INTEGER,
    change_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(action_id) REFERENCES response_actions(action_id) ON DELETE CASCADE
);

CREATE TABLE assets (
    asset_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name        TEXT NOT NULL,
    asset_type        TEXT NOT NULL CHECK (asset_type IN ('Server', 'Workstation', 'Database', 'Application', 'Network Device', 'Cloud Resource')),
    ip_address        TEXT NOT NULL,
    operating_system  TEXT,
    owner_id          INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    department        TEXT NOT NULL,
    location          TEXT,
    criticality       TEXT NOT NULL CHECK (criticality IN ('Low', 'Medium', 'High', 'Critical')),
    status            TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive', 'Under Maintenance')),
    created_at        TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX idx_assets_owner ON assets(owner_id);

CREATE TABLE incidents (
    incident_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title                TEXT NOT NULL,
    description          TEXT NOT NULL,
    category             TEXT NOT NULL CHECK (category IN ('Malware', 'Unauthorized Access', 'Phishing', 'Data Leakage', 'Account Compromise', 'Denial of Service', 'Other')),
    severity             TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    reporter_id          INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    asset_id             INTEGER REFERENCES assets(asset_id) ON DELETE SET NULL,
    assigned_analyst_id  INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    status               TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed')),
    created_at           TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at           TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    resolved_at          TEXT
);

CREATE INDEX idx_incidents_reporter ON incidents(reporter_id);
CREATE INDEX idx_incidents_analyst ON incidents(assigned_analyst_id);

CREATE TABLE investigation_notes (
    note_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    analyst_id   INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    content      TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX idx_notes_incident ON investigation_notes(incident_id);

CREATE TABLE vulnerabilities (
    vulnerability_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    title             TEXT NOT NULL,
    description       TEXT NOT NULL,
    cve_id            TEXT NOT NULL,
    cvss_score        REAL NOT NULL CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    severity          TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    asset_id          INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE RESTRICT,
    discovery_source  TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Under Investigation', 'In Progress', 'Resolved', 'Closed')),
    created_at        TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    resolved_at       TEXT,
    UNIQUE (cve_id, asset_id)
);

CREATE INDEX idx_vulnerabilities_asset ON vulnerabilities(asset_id);

