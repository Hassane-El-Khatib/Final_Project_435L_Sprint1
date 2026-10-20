"""Security Reports Service (port 5006).

Developed by: Abdul Rahman Habbal
"""

from flask import g

from common.app_factory import create_app, run_service
from common.auth import require_roles
from common.constants import ADMIN, AUDITOR
from common.responses import success
from common.validators import Validator
from services.reports.builder import ReportBuilder

app = create_app("reports")
builder = ReportBuilder()


def report(name, data):
    """Wrap a report with who generated it and when."""
    Validator.only_query([])
    return success(data, f"{name} report generated successfully", generated_at=builder.repo.now(),
                   generated_by=g.user["username"])


@app.route("/reports/summary", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def summary_report():
    """Generate Security Summary Report.

    Totals of users, assets, open incidents and critical threats, plus incidents by
    severity, open and critical vulnerabilities, users by role and recent activities.
    Developed by: Abdul Rahman Habbal
    """
    return report("Security summary", builder.summary())


@app.route("/reports/incidents", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def incident_report():
    """Generate Incident Report.

    Total incidents and incidents by severity, status and category.
    Developed by: Abdul Rahman Habbal
    """
    return report("Incident", builder.incidents())


@app.route("/reports/assets", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def asset_report():
    """Generate Asset Report.

    Total assets, critical assets and assets by type, status and criticality.
    Developed by: Abdul Rahman Habbal
    """
    return report("Asset", builder.assets())


@app.route("/reports/threats", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def threat_report():
    """Generate Threat Report.

    Total threats, threats by severity and type, and the five most recent threats.
    Developed by: Abdul Rahman Habbal
    """
    return report("Threat", builder.threats())


@app.route("/reports/vulnerabilities", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def vulnerability_report():
    """Generate Vulnerability Report.

    Total vulnerabilities, vulnerabilities by severity and status, and the critical ones.
    Developed by: Abdul Rahman Habbal
    """
    return report("Vulnerability", builder.vulnerabilities())


@app.route("/reports/activity", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def activity_report():
    """Generate Activity Report.

    Total activities, login attempts, failed logins and the most performed actions.
    Developed by: Abdul Rahman Habbal
    """
    return report("Activity", builder.activity())


if __name__ == "__main__":
    run_service(app)
