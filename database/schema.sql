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