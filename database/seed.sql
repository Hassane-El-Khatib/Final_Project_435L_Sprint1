INSERT INTO notifications (notification_id, user_id, title, message, notification_type, severity, status, read_at) VALUES
    (1, 4, 'Welcome to SIDRMS', 'Your account is active. You can now report security incidents.', 'System Notification', 'Low', 'Unread', NULL),
    (2, 2, 'Suspicious outbound traffic', 'Unusual outbound traffic volume detected from the finance subnet.', 'Security Alert', 'High', 'Unread', NULL),
    (3, 3, 'New command-and-control indicator', 'A new critical C2 server IP was added to threat intelligence.', 'Threat Alert', 'Critical', 'Read', datetime('now', 'localtime'));


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

INSERT INTO threats (threat_id, threat_type, threat_value, description, severity, source, added_by) VALUES
    (1, 'IP Address', '198.51.100.23', 'Repeated SSH brute-force attempts against the web server.', 'High', 'Internal SOC', 1),
    (2, 'IP Address', '203.0.113.77', 'Known command-and-control server used by a banking trojan.', 'Critical', 'AlienVault OTX', 1),
    (3, 'Domain', 'secure-login-example.net', 'Credential phishing page imitating the company login portal.', 'High', 'PhishTank', 1),
    (4, 'Domain', 'update-check-example.org', 'Domain serving fake software updates that install malware.', 'Medium', 'URLhaus', 1),
    (5, 'File Hash', '44d88612fea8a8f36de82e1278abb02f', 'MD5 of the EICAR antivirus test file.', 'Low', 'VirusTotal', 1),
    (6, 'File Hash', '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'SHA-256 of the EICAR antivirus test file.', 'Medium', 'VirusTotal', 1),
    (7, 'Malware Signature', 'Trojan.GenericKD.Downloader', 'Downloader trojan detected on endpoints by the antivirus vendor.', 'High', 'Vendor advisory', 1),
    (8, 'Other', 'User-Agent: sqlmap/1.7', 'Automated SQL injection scanner seen in web server logs.', 'Low', 'WAF logs', 1);

INSERT INTO playbooks (playbook_id, name, description, incident_category, severity, created_by) VALUES
    (1, 'Ransomware Response', 'Steps to contain and recover from a ransomware infection.', 'Malware', 'Critical', 1),
    (2, 'Phishing Response', 'Steps to handle a reported phishing email.', 'Phishing', 'Medium', 1);

INSERT INTO response_actions (action_id, playbook_id, description, step_number, status, assigned_user_id, completed_at) VALUES
    (1, 1, 'Isolate affected hosts from the network', 1, 'Completed', 2, datetime('now', 'localtime', '-1 day')),
    (2, 1, 'Identify the ransomware strain', 2, 'In Progress', 2, NULL),
    (3, 1, 'Restore systems from clean backups', 3, 'Pending', NULL, NULL),
    (4, 1, 'Reset credentials of affected accounts', 4, 'Pending', NULL, NULL),
    (5, 1, 'Run a post-incident review', 5, 'Pending', NULL, NULL),
    (6, 2, 'Block the sender domain on the mail gateway', 1, 'Pending', NULL, NULL),
    (7, 2, 'Remove the email from all mailboxes', 2, 'Pending', NULL, NULL),
    (8, 2, 'Reset passwords of users who clicked the link', 3, 'Pending', NULL, NULL),
    (9, 2, 'Send a phishing awareness reminder', 4, 'Pending', NULL, NULL);

INSERT INTO action_history (action_id, old_status, new_status, old_assignee, new_assignee, changed_by) VALUES
    (1, NULL, 'Pending', NULL, NULL, 1),
    (1, 'Pending', 'In Progress', NULL, 2, 2),
    (1, 'In Progress', 'Completed', 2, 2, 2),
    (2, NULL, 'Pending', NULL, NULL, 1),
    (2, 'Pending', 'In Progress', NULL, 2, 2);
