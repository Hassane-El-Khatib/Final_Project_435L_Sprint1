"""Asset entity."""


class Asset:
    """An organisational asset that incidents and vulnerabilities can affect."""

    def __init__(self, asset_id, asset_name, asset_type, ip_address, operating_system, owner_id,
                 department, location, criticality, status, created_at=None, updated_at=None,
                 owner_name=None):
        self.asset_id = asset_id
        self.asset_name = asset_name
        self.asset_type = asset_type
        self.ip_address = ip_address
        self.operating_system = operating_system
        self.owner_id = owner_id
        self.department = department
        self.location = location
        self.criticality = criticality
        self.status = status
        self.created_at = created_at
        self.updated_at = updated_at
        self.owner_name = owner_name

    @classmethod
    def from_row(cls, row):
        """Build an Asset from a database row (``owner_name`` is present when joined with users)."""
        return cls(**{key: row[key] for key in row.keys()})

    def to_dict(self):
        """Return the asset as a dictionary."""
        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "asset_type": self.asset_type,
            "ip_address": self.ip_address,
            "operating_system": self.operating_system,
            "owner_id": self.owner_id,
            "owner_name": self.owner_name,
            "department": self.department,
            "location": self.location,
            "criticality": self.criticality,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }