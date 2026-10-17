"""Data access for the vulnerabilities table."""

from common.base_repository import BaseRepository
from services.vulnerabilities.models import Vulnerability

SELECT_WITH_ASSET = (
    "SELECT vulnerabilities.*, assets.asset_name AS asset_name "
    "FROM vulnerabilities LEFT JOIN assets ON assets.asset_id = vulnerabilities.asset_id"
)


class VulnerabilityRepository(BaseRepository):
    """Queries on the vulnerabilities table."""

    table = "vulnerabilities"
    id_column = "vulnerability_id"
    columns = (
        "title",
        "description",
        "cve_id",
        "cvss_score",
        "severity",
        "asset_id",
        "discovery_source",
        "status",
        "resolved_at",
    )
    model = Vulnerability
    duplicate_message = "This CVE is already recorded for this asset"

    def get_with_asset(self, vulnerability_id):
        """Return one vulnerability including the asset name."""
        sql = f"{SELECT_WITH_ASSET} WHERE vulnerabilities.vulnerability_id = ?"
        return self.fetch_one(sql, (vulnerability_id,))

    def list_vulnerabilities(self, status=None):
        """Return all vulnerabilities ordered by id, optionally only one status."""
        if status:
            sql = f"{SELECT_WITH_ASSET} WHERE vulnerabilities.status = ? ORDER BY vulnerabilities.vulnerability_id"
            return self.fetch_all(sql, (status,))
        return self.fetch_all(f"{SELECT_WITH_ASSET} ORDER BY vulnerabilities.vulnerability_id")

    def search_vulnerabilities(self, cve_id=None, severity=None, asset_id=None, status=None):
        """Return vulnerabilities matching every given filter (AND); cve_id is a partial match."""
        conditions = []
        params = []
        if cve_id is not None:
            conditions.append("UPPER(vulnerabilities.cve_id) LIKE UPPER(?)")
            params.append(f"%{cve_id}%")
        if severity is not None:
            conditions.append("vulnerabilities.severity = ?")
            params.append(severity)
        if asset_id is not None:
            conditions.append("vulnerabilities.asset_id = ?")
            params.append(asset_id)
        if status is not None:
            conditions.append("vulnerabilities.status = ?")
            params.append(status)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        return self.fetch_all(f"{SELECT_WITH_ASSET}{where} ORDER BY vulnerabilities.vulnerability_id",
                              tuple(params))

    def duplicate_exists(self, cve_id, asset_id):
        """Return the id of an existing record with the same CVE on the same asset, or None."""
        sql = "SELECT vulnerability_id FROM vulnerabilities WHERE cve_id = ? AND asset_id = ?"
        return self.fetch_value(sql, (cve_id, asset_id))

    def asset_name(self, asset_id):
        """Return the asset's name, or None if it does not exist."""
        return self.fetch_value("SELECT asset_name FROM assets WHERE asset_id = ?", (asset_id,))

    def now(self):
        """Return the current local time as stored by the database."""
        return self.fetch_value("SELECT datetime('now', 'localtime')")