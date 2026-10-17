"""Vulnerability Management Service (port 5007).

Developed by: Yehia Afesh
"""

import re

from flask import g, request

from common.app_factory import create_app, run_service
from common.auth import require_roles
from common.clients import log_event, notify_role
from common.constants import ADMIN, ANALYST, AUDITOR, SEVERITIES, VULN_FLOW
from common.errors import ConflictError, NotFoundError, ValidationError
from common.responses import success
from common.validators import Validator
from services.vulnerabilities.models import Vulnerability
from services.vulnerabilities.repository import VulnerabilityRepository

app = create_app("vulnerabilities")
vulnerabilities = VulnerabilityRepository()

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CREATE_FIELDS = ["title", "description", "cve_id", "cvss_score", "severity", "asset_id", "discovery_source"]
UPDATABLE_FIELDS = ["description", "severity", "status", "cvss_score", "resolved_at"]
SEARCH_PARAMS = ["cve_id", "severity", "asset_id", "status"]


def find_vulnerability_or_404(vulnerability_id):
    """Return the vulnerability with its asset name or raise NotFoundError."""
    vulnerability = vulnerabilities.get_with_asset(vulnerability_id)
    if vulnerability is None:
        raise NotFoundError(f"Vulnerability {vulnerability_id} not found")
    return vulnerability


def validate_cve(value):
    """Return the CVE identifier in upper case if it looks like CVE-YYYY-NNNN."""
    cve_id = Validator.text(value, "cve_id", 3, 20).upper()
    if not CVE_PATTERN.match(cve_id):
        raise ValidationError("cve_id must look like CVE-2021-44228")
    return cve_id


def check_severity_matches(cvss_score, severity):
    """Reject a severity that contradicts the CVSS v3 rating band of the score."""
    expected = Vulnerability.expected_severity(cvss_score)
    if severity != expected:
        raise ValidationError(f"Severity {severity} does not match CVSS score {cvss_score} (expected {expected})")


@app.route("/vulnerabilities", methods=["POST"])
@require_roles(ADMIN)
def add_vulnerability():
    """Add New Vulnerability.

    Required: title, description, cve_id, cvss_score, severity, asset_id, discovery_source.
    The severity must match the CVSS score band; the same CVE cannot be recorded twice on one asset.
    Developed by: Yehia Afesh
    """
    data = Validator.body()
    Validator.require(data, CREATE_FIELDS)
    Validator.only_fields(data, CREATE_FIELDS)
    title = Validator.text(data["title"], "title", 5, 150)
    description = Validator.text(data["description"], "description", 10, 2000)
    cve_id = validate_cve(data["cve_id"])
    cvss_score = Validator.number(data["cvss_score"], "cvss_score", 0.0, 10.0)
    severity = Validator.enum(data["severity"], SEVERITIES, "severity")
    check_severity_matches(cvss_score, severity)
    asset_id = Validator.integer(data["asset_id"], "asset_id", 1)
    asset_name = vulnerabilities.asset_name(asset_id)
    if asset_name is None:
        raise ValidationError(f"Asset {asset_id} does not exist")
    discovery_source = Validator.text(data["discovery_source"], "discovery_source", 2, 100)
    existing = vulnerabilities.duplicate_exists(cve_id, asset_id)
    if existing:
        raise ConflictError(f"{cve_id} is already recorded for asset {asset_id} as vulnerability {existing}")

    vulnerability_id = vulnerabilities.insert({
        "title": title,
        "description": description,
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "severity": severity,
        "asset_id": asset_id,
        "discovery_source": discovery_source,
        "status": "Open",
    })
    log_event(g.user["user_id"], "VULN_CREATED",
              f"Vulnerability {vulnerability_id} {cve_id} (CVSS {cvss_score}, {severity}) recorded on {asset_name}",
              "Warning" if severity in ("High", "Critical") else "Information", "vulnerabilities")
    if severity in ("High", "Critical"):
        notify_role(ADMIN, f"New {severity} vulnerability",
                    f"{cve_id} ({title}) was found on {asset_name}.", "Vulnerability Alert", severity)
    return success(find_vulnerability_or_404(vulnerability_id).to_dict(), "Vulnerability created successfully", 201)


@app.route("/vulnerabilities", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def get_all_vulnerabilities():
    """Retrieve All Vulnerabilities.

    Returns every vulnerability with its severity, affected asset and status.
    Optional query parameter: status.
    Developed by: Yehia Afesh
    """
    Validator.only_query(["status"])
    status = None
    if "status" in request.args:
        status = Validator.enum(request.args["status"], VULN_FLOW, "status")
    result = [v.to_dict() for v in vulnerabilities.list_vulnerabilities(status)]
    return success(result, "Vulnerabilities retrieved successfully")


@app.route("/vulnerabilities/search", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def search_vulnerabilities():
    """Search Vulnerabilities.

    Filters (combined with AND): cve_id (partial), severity, asset_id, status.
    Developed by: Yehia Afesh
    """
    Validator.only_query(SEARCH_PARAMS)
    args = request.args
    if not any(args.get(name, "").strip() for name in SEARCH_PARAMS):
        raise ValidationError(f"Provide at least one filter: {', '.join(SEARCH_PARAMS)}")
    filters = {}
    if "cve_id" in args:
        filters["cve_id"] = Validator.text(args["cve_id"], "cve_id", 1, 20)
    if "severity" in args:
        filters["severity"] = Validator.enum(args["severity"], SEVERITIES, "severity")
    if "asset_id" in args:
        filters["asset_id"] = Validator.query_integer(args["asset_id"], "asset_id", 1)
    if "status" in args:
        filters["status"] = Validator.enum(args["status"], VULN_FLOW, "status")

    result = [v.to_dict() for v in vulnerabilities.search_vulnerabilities(**filters)]
    message = "Vulnerabilities retrieved successfully" if result else "No vulnerabilities match the given filters"
    return success(result, message, filters=dict(args))


@app.route("/vulnerabilities/<int:vulnerability_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def get_vulnerability(vulnerability_id):
    """Retrieve Specific Vulnerability.

    Developed by: Yehia Afesh
    """
    return success(find_vulnerability_or_404(vulnerability_id).to_dict(), "Vulnerability retrieved successfully")


@app.route("/vulnerabilities/<int:vulnerability_id>", methods=["PUT"])
@require_roles(ADMIN, ANALYST)
def update_vulnerability(vulnerability_id):
    """Update Vulnerability Information.

    Updatable: description, severity, status, cvss_score, resolved_at. Status follows
    Open -> Under Investigation -> In Progress -> Resolved -> Closed, and the severity must
    still match the CVSS score after the update.
    Developed by: Yehia Afesh
    """
    data = Validator.body()
    vulnerability = find_vulnerability_or_404(vulnerability_id)
    Validator.only_fields(data, UPDATABLE_FIELDS)

    changes = {}
    if "description" in data:
        changes["description"] = Validator.text(data["description"], "description", 10, 2000)
    if "cvss_score" in data:
        changes["cvss_score"] = Validator.number(data["cvss_score"], "cvss_score", 0.0, 10.0)
    if "severity" in data:
        changes["severity"] = Validator.enum(data["severity"], SEVERITIES, "severity")
    if "status" in data:
        new_status = Validator.enum(data["status"], VULN_FLOW, "status")
        if new_status != vulnerability.status:
            Validator.transition(vulnerability.status, new_status, VULN_FLOW)
            changes["status"] = new_status
    if "resolved_at" in data:
        changes["resolved_at"] = Validator.date(data["resolved_at"], "resolved_at")

    final_score = changes.get("cvss_score", vulnerability.cvss_score)
    final_severity = changes.get("severity", vulnerability.severity)
    check_severity_matches(final_score, final_severity)
    final_status = changes.get("status", vulnerability.status)
    if "resolved_at" in changes and final_status not in ("Resolved", "Closed"):
        raise ValidationError("resolved_at can only be set when the status is Resolved or Closed")
    if final_status == "Resolved" and not changes.get("resolved_at") and not vulnerability.resolved_at:
        changes["resolved_at"] = vulnerabilities.now()

    changed = {key: value for key, value in changes.items() if getattr(vulnerability, key) != value}
    if not changed:
        return success(vulnerability.to_dict(), "No changes were made")

    vulnerabilities.update(vulnerability_id, changed)
    summary = "; ".join(f"{key} {getattr(vulnerability, key)} -> {value}" for key, value in changed.items())
    log_event(g.user["user_id"], "VULN_UPDATED",
              f"Vulnerability {vulnerability_id} {vulnerability.cve_id} updated: {summary}",
              "Information", "vulnerabilities")
    return success(find_vulnerability_or_404(vulnerability_id).to_dict(), "Vulnerability updated successfully")


@app.route("/vulnerabilities/<int:vulnerability_id>", methods=["DELETE"])
@require_roles(ADMIN)
def delete_vulnerability(vulnerability_id):
    """Delete Vulnerability.

    Only Security Administrators may delete vulnerability records.
    Developed by: Yehia Afesh
    """
    vulnerability = find_vulnerability_or_404(vulnerability_id)
    vulnerabilities.delete(vulnerability_id)
    log_event(g.user["user_id"], "VULN_DELETED",
              f"Vulnerability {vulnerability_id} {vulnerability.cve_id} on asset {vulnerability.asset_id} deleted",
              "Warning", "vulnerabilities")
    return success(message=f"Vulnerability {vulnerability_id} ({vulnerability.cve_id}) deleted successfully")


if __name__ == "__main__":
    run_service(app)