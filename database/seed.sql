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

INSERT INTO assets (asset_id, asset_name, asset_type, ip_address, operating_system, owner_id, department, location, criticality, status) VALUES
    (1, 'WEB-SRV-01', 'Server', '10.0.1.10', 'Ubuntu 22.04', 1, 'IT', 'Beirut DC Rack 3', 'Critical', 'Active'),
    (2, 'HR-WS-07', 'Workstation', '10.0.2.37', 'Windows 11', 4, 'Human Resources', 'Floor 2', 'Low', 'Active'),
    (3, 'FIN-DB-01', 'Database', '10.0.1.20', 'PostgreSQL 15 on Debian 12', 5, 'Finance', 'Beirut DC Rack 1', 'Critical', 'Active'),
    (4, 'PAYROLL-APP', 'Application', '10.0.1.30', NULL, 5, 'Finance', 'Beirut DC', 'High', 'Active'),
    (5, 'CORE-SW-01', 'Network Device', '10.0.0.1', 'Cisco IOS', 1, 'IT', 'Server room', 'Medium', 'Under Maintenance'),
    (6, 'BACKUP-BUCKET', 'Cloud Resource', '203.0.113.50', NULL, 1, 'IT', 'Cloud (eu-central)', 'High', 'Active'),
    (7, 'MKT-WS-12', 'Workstation', '10.0.3.12', 'macOS 14', 2, 'Marketing', 'Floor 3', 'Low', 'Inactive'),
    (8, 'MAIL-SRV-01', 'Server', '10.0.1.25', 'Windows Server 2022', 1, 'IT', 'Beirut DC Rack 2', 'High', 'Active');

INSERT INTO incidents (incident_id, title, description, category, severity, reporter_id, asset_id, assigned_analyst_id, status, resolved_at) VALUES
    (1, 'Suspicious invoice email received', 'An email with an unexpected invoice attachment was reported by HR staff.', 'Phishing', 'Low', 4, 2, NULL, 'Open', NULL),
    (2, 'Unknown login to finance database', 'A database login from an unrecognised internal IP address was detected at night.', 'Unauthorized Access', 'High', 5, 3, 2, 'Under Investigation', NULL),
    (3, 'Malware alert on marketing laptop', 'Antivirus quarantined a trojan downloader on the marketing workstation.', 'Malware', 'Medium', 4, 7, 3, 'Resolved', datetime('now', 'localtime', '-1 day')),
    (4, 'Web server flooded with requests', 'The public web server became unreachable because of a flood of HTTP requests.', 'Denial of Service', 'Critical', 5, 1, 2, 'Closed', datetime('now', 'localtime', '-2 days'));

INSERT INTO investigation_notes (note_id, incident_id, analyst_id, content) VALUES
    (1, 2, 2, 'Source IP belongs to a contractor laptop; requested access logs from the database team.');

INSERT INTO vulnerabilities (vulnerability_id, title, description, cve_id, cvss_score, severity, asset_id, discovery_source, status, resolved_at) VALUES
    (1, 'Zerologon privilege escalation', 'Netlogon protocol flaw allows an attacker to take over the domain controller.', 'CVE-2020-1472', 10.0, 'Critical', 8, 'Vendor advisory', 'Open', NULL),
    (2, 'HTTP/2 Rapid Reset denial of service', 'HTTP/2 stream cancellation can be abused to exhaust server resources.', 'CVE-2023-44487', 7.5, 'High', 1, 'Nessus scan', 'In Progress', NULL),
    (3, 'OpenSSL NULL pointer dereference', 'A crafted renegotiation message can crash the TLS server.', 'CVE-2021-3449', 5.9, 'Medium', 1, 'Nessus scan', 'Resolved', datetime('now', 'localtime', '-3 days')),
    (4, 'Log4Shell remote code execution', 'Apache Log4j2 JNDI lookup allows remote code execution.', 'CVE-2021-44228', 10.0, 'Critical', 3, 'Penetration test', 'Under Investigation', NULL),
    (5, 'Terrapin SSH prefix truncation', 'SSH handshake sequence numbers can be manipulated to downgrade connection security.', 'CVE-2023-48795', 5.9, 'Medium', 8, 'Penetration test', 'Closed', datetime('now', 'localtime', '-5 days'));

