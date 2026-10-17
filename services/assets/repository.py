"""Data access for the assets table and its relationships."""

from common.base_repository import BaseRepository
from common.db import Database
from services.assets.models import Asset

SELECT_WITH_OWNER = (
    "SELECT assets.*, users.full_name AS owner_name "
    "FROM assets LEFT JOIN users ON users.user_id = assets.owner_id"
)


class AssetRepository(BaseRepository):
    """Queries on the assets table."""

    table = "assets"
    id_column = "asset_id"
    columns = (
        "asset_name",
        "asset_type",
        "ip_address",
        "operating_system",
        "owner_id",
        "department",
        "location",
        "criticality",
        "status",
        "updated_at",
    )
    model = Asset
    delete_conflict_message = "Asset is still referenced by vulnerabilities"

    def get_with_owner(self, asset_id):
        """Return one asset including its owner's name."""
        return self.fetch_one(f"{SELECT_WITH_OWNER} WHERE assets.asset_id = ?", (asset_id,))

    def list_assets(self, status=None):
        """Return every asset, optionally only one status, ordered by id."""
        if status:
            return self.fetch_all(f"{SELECT_WITH_OWNER} WHERE assets.status = ? ORDER BY assets.asset_id", (status,))
        return self.fetch_all(f"{SELECT_WITH_OWNER} ORDER BY assets.asset_id")

    def search_assets(self, name=None, asset_type=None, ip=None, department=None, criticality=None,
                      status=None):
        """Return assets matching every given filter (AND); name is a partial match."""
        conditions = []
        params = []
        if name is not None:
            conditions.append("LOWER(assets.asset_name) LIKE LOWER(?)")
            params.append(f"%{name}%")
        if asset_type is not None:
            conditions.append("assets.asset_type = ?")
            params.append(asset_type)
        if ip is not None:
            conditions.append("assets.ip_address = ?")
            params.append(ip)
        if department is not None:
            conditions.append("LOWER(assets.department) = LOWER(?)")
            params.append(department)
        if criticality is not None:
            conditions.append("assets.criticality = ?")
            params.append(criticality)
        if status is not None:
            conditions.append("assets.status = ?")
            params.append(status)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        return self.fetch_all(f"{SELECT_WITH_OWNER}{where} ORDER BY assets.asset_id", tuple(params))

    def related_incidents(self, asset_id):
        """Return a short summary of every incident affecting the asset."""
        sql = ("SELECT incident_id, title, severity, status FROM incidents "
               "WHERE asset_id = ? ORDER BY incident_id")
        return [dict(row) for row in self._raw(sql, (asset_id,))]

    def related_vulnerabilities(self, asset_id):
        """Return a short summary of every vulnerability found on the asset."""
        sql = ("SELECT vulnerability_id, cve_id, title, severity, status FROM vulnerabilities "
               "WHERE asset_id = ? ORDER BY vulnerability_id")
        return [dict(row) for row in self._raw(sql, (asset_id,))]

    def count_vulnerabilities(self, asset_id):
        """Return how many vulnerabilities reference the asset."""
        return self.fetch_value("SELECT COUNT(*) FROM vulnerabilities WHERE asset_id = ?", (asset_id,))

    def now(self):
        """Return the current local time as stored by the database."""
        return self.fetch_value("SELECT datetime('now', 'localtime')")

    def _raw(self, sql, params=()):
        """Run a SELECT and return plain rows (not models)."""
        with Database.session() as connection:
            return connection.execute(sql, params).fetchall()