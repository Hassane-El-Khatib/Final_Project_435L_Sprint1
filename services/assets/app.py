"""Asset Management Service (port 5002).

Developed by: Yehia Afesh
"""

from flask import g, request

from common.app_factory import create_app, run_service
from common.auth import require_roles
from common.clients import get_user, log_event
from common.constants import ADMIN, ANALYST, ASSET_STATUSES, ASSET_TYPES, AUDITOR, SEVERITIES
from common.errors import ConflictError, NotFoundError, ValidationError
from common.responses import success
from common.validators import Validator
from services.assets.repository import AssetRepository

app = create_app("assets")
assets = AssetRepository()

REQUIRED_FIELDS = ["asset_name", "asset_type", "ip_address", "department", "owner_id", "criticality"]
OPTIONAL_FIELDS = ["operating_system", "location", "status"]
UPDATABLE_FIELDS = ["asset_name", "owner_id", "department", "criticality", "status", "operating_system", "location"]
SEARCH_PARAMS = ["name", "type", "ip", "department", "criticality", "status"]


def find_asset_or_404(asset_id):
    """Return the asset with its owner name or raise NotFoundError."""
    asset = assets.get_with_owner(asset_id)
    if asset is None:
        raise NotFoundError(f"Asset {asset_id} not found")
    return asset


def validate_owner(owner_id):
    """Ensure the owner is an integer id of an existing user."""
    Validator.integer(owner_id, "owner_id", 1)
    if get_user(owner_id) is None:
        raise ValidationError(f"Owner {owner_id} does not exist")
    return owner_id


def clean_field(field, value):
    """Validate one asset field and return its cleaned value."""
    if field == "asset_name":
        return Validator.text(value, "asset_name", 2, 100)
    if field == "asset_type":
        return Validator.enum(value, ASSET_TYPES, "asset_type")
    if field == "ip_address":
        return Validator.ip(value)
    if field == "department":
        return Validator.text(value, "department", 2, 100)
    if field == "owner_id":
        return validate_owner(value)
    if field == "criticality":
        return Validator.enum(value, SEVERITIES, "criticality")
    if field == "status":
        return Validator.enum(value, ASSET_STATUSES, "status")
    if field == "operating_system":
        return Validator.text(value, "operating_system", 1, 100)
    if field == "location":
        return Validator.text(value, "location", 1, 100)
    raise ValidationError(f"Unknown field: {field}")


@app.route("/assets", methods=["POST"])
@require_roles(ADMIN)
def add_asset():
    """Add New Asset.

    Registers an organisational asset. Required: asset_name, asset_type, ip_address,
    department, owner_id, criticality. Optional: operating_system, location, status.
    Developed by: Yehia Afesh
    """
    data = Validator.body()
    Validator.require(data, REQUIRED_FIELDS)
    Validator.only_fields(data, REQUIRED_FIELDS + OPTIONAL_FIELDS)
    values = {field: clean_field(field, data[field]) for field in REQUIRED_FIELDS}
    for field in OPTIONAL_FIELDS:
        if data.get(field) is not None:
            values[field] = clean_field(field, data[field])
    values.setdefault("status", "Active")

    asset_id = assets.insert(values)
    log_event(g.user["user_id"], "ASSET_CREATED",
              f"Asset {asset_id} {values['asset_name']} ({values['asset_type']}, {values['criticality']}) created",
              "Information", "assets")
    return success(assets.get_with_owner(asset_id).to_dict(), "Asset created successfully", 201)


@app.route("/assets/<int:asset_id>", methods=["PUT"])
@require_roles(ADMIN)
def update_asset(asset_id):
    """Update Asset Information.

    Updatable: asset_name, owner_id, department, criticality, status, operating_system, location.
    Developed by: Yehia Afesh
    """
    data = Validator.body()
    asset = find_asset_or_404(asset_id)
    Validator.only_fields(data, UPDATABLE_FIELDS)
    changes = {field: clean_field(field, value) for field, value in data.items()}
    changed = {key: value for key, value in changes.items() if getattr(asset, key) != value}
    if not changed:
        return success(asset.to_dict(), "No changes were made")

    assets.update(asset_id, {**changed, "updated_at": assets.now()})
    summary = "; ".join(f"{key} {getattr(asset, key)} -> {value}" for key, value in changed.items())
    log_event(g.user["user_id"], "ASSET_UPDATED", f"Asset {asset_id} {asset.asset_name} updated: {summary}",
              "Information", "assets")
    return success(assets.get_with_owner(asset_id).to_dict(), "Asset updated successfully")


@app.route("/assets/<int:asset_id>", methods=["DELETE"])
@require_roles(ADMIN)
def delete_asset(asset_id):
    """Delete Asset.

    Only Security Administrators may delete assets. Assets that still have
    vulnerabilities cannot be deleted; incidents keep existing without the asset link.
    Developed by: Yehia Afesh
    """
    asset = find_asset_or_404(asset_id)
    vulnerability_count = assets.count_vulnerabilities(asset_id)
    if vulnerability_count:
        raise ConflictError(
            f"Asset {asset_id} has {vulnerability_count} vulnerabilities; delete or resolve them first"
        )
    assets.delete(asset_id)
    log_event(g.user["user_id"], "ASSET_DELETED", f"Asset {asset_id} {asset.asset_name} deleted", "Warning",
              "assets")
    return success(message=f"Asset {asset_id} ({asset.asset_name}) deleted successfully")


@app.route("/assets", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def get_all_assets():
    """Retrieve All Assets.

    Returns every asset with its criticality, status and owner. Optional query parameter: status.
    Developed by: Yehia Afesh
    """
    Validator.only_query(["status"])
    status = None
    if "status" in request.args:
        status = Validator.enum(request.args["status"], ASSET_STATUSES, "status")
    result = [asset.to_dict() for asset in assets.list_assets(status)]
    return success(result, "Assets retrieved successfully")


@app.route("/assets/search", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def search_assets():
    """Search Assets.

    Filters (combined with AND): name (partial), type, ip, department, criticality, status.
    Developed by: Yehia Afesh
    """
    Validator.only_query(SEARCH_PARAMS)
    args = request.args
    if not any(args.get(name, "").strip() for name in SEARCH_PARAMS):
        raise ValidationError(f"Provide at least one filter: {', '.join(SEARCH_PARAMS)}")
    filters = {}
    if "name" in args:
        filters["name"] = Validator.text(args["name"], "name", 1, 100)
    if "type" in args:
        filters["asset_type"] = Validator.enum(args["type"], ASSET_TYPES, "type")
    if "ip" in args:
        filters["ip"] = Validator.ip(args["ip"], "ip")
    if "department" in args:
        filters["department"] = Validator.text(args["department"], "department", 1, 100)
    if "criticality" in args:
        filters["criticality"] = Validator.enum(args["criticality"], SEVERITIES, "criticality")
    if "status" in args:
        filters["status"] = Validator.enum(args["status"], ASSET_STATUSES, "status")

    result = [asset.to_dict() for asset in assets.search_assets(**filters)]
    message = "Assets retrieved successfully" if result else "No assets match the given filters"
    return success(result, message, filters=dict(args))


@app.route("/assets/<int:asset_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def get_asset(asset_id):
    """Retrieve Specific Asset.

    Returns the asset with its owner, related incidents and related vulnerabilities.
    Developed by: Yehia Afesh
    """
    asset = find_asset_or_404(asset_id)
    data = asset.to_dict()
    data["related_incidents"] = assets.related_incidents(asset_id)
    data["related_vulnerabilities"] = assets.related_vulnerabilities(asset_id)
    return success(data, "Asset retrieved successfully")


if __name__ == "__main__":
    run_service(app)