"""Role names and the allowed values used across all services."""

ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
REGULAR = "Regular User"
AUDITOR = "Auditor"
ROLES = [ADMIN, ANALYST, REGULAR, AUDITOR]

SEVERITIES = ["Low", "Medium", "High", "Critical"]
LOG_SEVERITIES = ["Information", "Warning", "Error", "Critical"]

ACCOUNT_STATUSES = ["Active", "Inactive", "Suspended"]

ASSET_TYPES = ["Server", "Workstation", "Database", "Application", "Network Device", "Cloud Resource"]
ASSET_STATUSES = ["Active", "Inactive", "Under Maintenance"]

INCIDENT_CATEGORIES = [
    "Malware",
    "Unauthorized Access",
    "Phishing",
    "Data Leakage",
    "Account Compromise",
    "Denial of Service",
    "Other",
]
INCIDENT_FLOW = ["Open", "Under Investigation", "Mitigated", "Resolved", "Closed"]

VULN_FLOW = ["Open", "Under Investigation", "In Progress", "Resolved", "Closed"]

ACTION_FLOW = ["Pending", "In Progress", "Completed"]

THREAT_TYPES = ["IP Address", "Domain", "File Hash", "Malware Signature", "Other"]

NOTIFICATION_TYPES = [
    "Incident Assignment",
    "Security Alert",
    "System Notification",
    "Threat Alert",
    "Vulnerability Alert",
]
NOTIFICATION_STATUSES = ["Unread", "Read"]

SERVICES = [
    "users",
    "assets",
    "incidents",
    "threats",
    "logs",
    "reports",
    "vulnerabilities",
    "notifications",
    "playbooks",
]


def next_status(current, flow):
    """Return the status that follows ``current`` in ``flow``, or None if it is the last one."""
    position = flow.index(current)
    if position + 1 < len(flow):
        return flow[position + 1]
    return None
