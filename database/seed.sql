INSERT INTO notifications (notification_id, user_id, title, message, notification_type, severity, status, read_at) VALUES
    (1, 4, 'Welcome to SIDRMS', 'Your account is active. You can now report security incidents.', 'System Notification', 'Low', 'Unread', NULL),
    (2, 2, 'Suspicious outbound traffic', 'Unusual outbound traffic volume detected from the finance subnet.', 'Security Alert', 'High', 'Unread', NULL),
    (3, 3, 'New command-and-control indicator', 'A new critical C2 server IP was added to threat intelligence.', 'Threat Alert', 'Critical', 'Read', datetime('now', 'localtime'));

INSERT INTO threats (threat_id, threat_type, threat_value, description, severity_level, source) VALUES 
(1, 'IP Address', '192.168.1.50', 'Suspicious outbound traffic', 'High', 'Firewall Log'),
(2, 'Domain', 'malicious-test.com', 'Known phishing domain', 'Critical', 'ThreatIntel API'),
(3, 'File Hash', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'Ransomware payload', 'Critical', 'Endpoint Protection'),
(4, 'Malware Signature', 'Trojan.Win32.Generic', 'Heuristic match', 'Medium', 'Antivirus'),
(5, 'Other', 'Suspicious User Agent', 'Automated scanning script', 'Low', 'WAF'),
(6, 'IP Address', '10.0.0.99', 'Internal brute force', 'Medium', 'Active Directory'),
(7, 'Domain', 'c2-server.net', 'Command and control server', 'High', 'Network Monitor'),
(8, 'File Hash', 'd41d8cd98f00b204e9800998ecf8427e', 'Empty file bypass', 'Low', 'Manual Analysis');