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
