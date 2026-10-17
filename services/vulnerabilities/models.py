"""Vulnerability entity."""

SEVERITY_BANDS = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.0, "Low"),
)


class Vulnerability:
    """A security weakness (CVE) found on one asset, tracked until it is closed."""

    def __init__(self, vulnerability_id, title, description, cve_id, cvss_score, severity, asset_id,
                 discovery_source, status, created_at=None, resolved_at=None, asset_name=None):
        self.vulnerability_id = vulnerability_id
        self.title = title
        self.description = description
        self.cve_id = cve_id
        self.cvss_score = cvss_score
        self.severity = severity
        self.asset_id = asset_id
        self.discovery_source = discovery_source
        self.status = status
        self.created_at = created_at
        self.resolved_at = resolved_at
        self.asset_name = asset_name

    @classmethod
    def from_row(cls, row):
        """Build a Vulnerability from a database row (``asset_name`` is present when joined)."""
        return cls(**{key: row[key] for key in row.keys()})

    @staticmethod
    def expected_severity(cvss_score):
        """Return the CVSS v3 qualitative severity for a score between 0.0 and 10.0."""
        for minimum, severity in SEVERITY_BANDS:
            if cvss_score >= minimum:
                return severity
        return "Low"

    def to_dict(self):
        """Return the vulnerability as a dictionary."""
        return {
            "vulnerability_id": self.vulnerability_id,
            "title": self.title,
            "description": self.description,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "asset": {"asset_id": self.asset_id, "asset_name": self.asset_name},
            "discovery_source": self.discovery_source,
            "status": self.status,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
        }