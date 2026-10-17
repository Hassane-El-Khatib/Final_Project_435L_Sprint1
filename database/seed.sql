INSERT INTO notifications (notification_id, user_id, title, message, notification_type, severity, status, read_at) VALUES
    (1, 4, 'Welcome to SIDRMS', 'Your account is active. You can now report security incidents.', 'System Notification', 'Low', 'Unread', NULL),
    (2, 2, 'Suspicious outbound traffic', 'Unusual outbound traffic volume detected from the finance subnet.', 'Security Alert', 'High', 'Unread', NULL),
    (3, 3, 'New command-and-control indicator', 'A new critical C2 server IP was added to threat intelligence.', 'Threat Alert', 'Critical', 'Read', datetime('now', 'localtime'));
