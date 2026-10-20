"""Builds each report from the aggregate queries."""

from common.constants import (
    ASSET_STATUSES,
    ASSET_TYPES,
    INCIDENT_CATEGORIES,
    INCIDENT_FLOW,
    LOG_SEVERITIES,
    ROLES,
    SERVICES,
    SEVERITIES,
    THREAT_TYPES,
    VULN_FLOW,
)
from services.reports.repository import ReportRepository

OPEN_INCIDENT = "status IN ('Open', 'Under Investigation', 'Mitigated')"
OPEN_VULNERABILITY = "status NOT IN ('Resolved', 'Closed')"


class ReportBuilder:
    """One method per report; each returns a dictionary ready to be sent as JSON."""

    def __init__(self, repository=None):
        self.repo = repository or ReportRepository()

    def summary(self):
        """Overall security status."""
        return {
            "users": self.repo.count("users"),
            "assets": self.repo.count("assets"),
            "open_incidents": self.repo.count("incidents", OPEN_INCIDENT),
            "critical_threats": self.repo.count("threats", "severity = 'Critical'"),
            "total_incidents": self.repo.count("incidents"),
            "incidents_by_severity": self.repo.group_count("incidents", "severity", SEVERITIES),
            "threats": self.repo.count("threats"),
            "open_vulnerabilities": self.repo.count("vulnerabilities", OPEN_VULNERABILITY),
            "critical_vulnerabilities": self.repo.count("vulnerabilities", "severity = 'Critical'"),
            "users_by_role": self.repo.group_count("users", "role", ROLES),
            "recent_activities": self.repo.recent_logs(5),
        }

    def incidents(self):
        """Incident statistics."""
        return {
            "total_incidents": self.repo.count("incidents"),
            "open_incidents": self.repo.count("incidents", OPEN_INCIDENT),
            "unassigned_incidents": self.repo.count("incidents", "assigned_analyst_id IS NULL"),
            "by_severity": self.repo.group_count("incidents", "severity", SEVERITIES),
            "by_status": self.repo.group_count("incidents", "status", INCIDENT_FLOW),
            "by_category": self.repo.group_count("incidents", "category", INCIDENT_CATEGORIES),
        }

    def assets(self):
        """Asset statistics."""
        critical = self.repo.critical_assets()
        return {
            "total_assets": self.repo.count("assets"),
            "critical_assets": {"count": len(critical), "assets": critical},
            "by_type": self.repo.group_count("assets", "asset_type", ASSET_TYPES),
            "by_status": self.repo.group_count("assets", "status", ASSET_STATUSES),
            "by_criticality": self.repo.group_count("assets", "criticality", SEVERITIES),
        }

    def threats(self):
        """Threat intelligence statistics."""
        return {
            "total_threats": self.repo.count("threats"),
            "by_severity": self.repo.group_count("threats", "severity", SEVERITIES),
            "by_type": self.repo.group_count("threats", "threat_type", THREAT_TYPES),
            "recent_threats": self.repo.recent_threats(5),
        }

    def vulnerabilities(self):
        """Vulnerability statistics."""
        critical = self.repo.critical_vulnerabilities()
        return {
            "total_vulnerabilities": self.repo.count("vulnerabilities"),
            "open_vulnerabilities": self.repo.count("vulnerabilities", OPEN_VULNERABILITY),
            "average_cvss": self.repo.average_cvss(),
            "by_severity": self.repo.group_count("vulnerabilities", "severity", SEVERITIES),
            "by_status": self.repo.group_count("vulnerabilities", "status", VULN_FLOW),
            "critical_vulnerabilities": {"count": len(critical), "vulnerabilities": critical},
        }

    def activity(self):
        """Security activity statistics from the audit log."""
        successful = self.repo.count("logs", "action = 'LOGIN_SUCCESS'")
        failed = self.repo.count("logs", "action = 'LOGIN_FAILED'")
        return {
            "total_activities": self.repo.count("logs"),
            "login_attempts": successful + failed,
            "successful_logins": successful,
            "failed_logins": failed,
            "unauthorized_attempts": self.repo.count("logs", "action = 'UNAUTHORIZED_ACCESS'"),
            "most_performed_actions": self.repo.top_actions(5),
            "by_service": self.repo.group_count("logs", "related_service", SERVICES),
            "by_severity": self.repo.group_count("logs", "severity", LOG_SEVERITIES),
        }
