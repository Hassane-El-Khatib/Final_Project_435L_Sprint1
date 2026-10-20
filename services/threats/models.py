"""Threat indicator entity and the per-type value rules."""

import ipaddress
import re

from common.errors import ValidationError

DOMAIN_PATTERN = re.compile(r"^(?=.{4,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
HEX_PATTERN = re.compile(r"^[A-Fa-f0-9]+$")
HASH_LENGTHS = (32, 40, 64)


class Threat:
    """A threat intelligence indicator such as a malicious IP address, domain or file hash."""

    def __init__(self, threat_id, threat_type, threat_value, description, severity, source, added_by=None,
                 date_added=None, added_by_name=None):
        self.threat_id = threat_id
        self.threat_type = threat_type
        self.threat_value = threat_value
        self.description = description
        self.severity = severity
        self.source = source
        self.added_by = added_by
        self.date_added = date_added
        self.added_by_name = added_by_name

    @classmethod
    def from_row(cls, row):
        """Build a Threat from a database row (``added_by_name`` is present when joined with users)."""
        return cls(**{key: row[key] for key in row.keys()})

    def to_dict(self):
        """Return the threat as a dictionary."""
        return {
            "threat_id": self.threat_id,
            "threat_type": self.threat_type,
            "threat_value": self.threat_value,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "added_by": self.added_by,
            "added_by_name": self.added_by_name,
            "date_added": self.date_added,
        }


class ThreatValueValidator:
    """Validates and normalises a threat value according to its threat type."""

    def __init__(self):
        self.rules = {
            "IP Address": self.ip_address,
            "Domain": self.domain,
            "File Hash": self.file_hash,
            "Malware Signature": self.signature,
            "Other": self.other,
        }

    def validate(self, threat_type, value):
        """Return the normalised value or raise ValidationError naming the failed rule."""
        if not isinstance(value, str) or not value.strip():
            raise ValidationError("threat_value must be a non-empty string")
        return self.rules[threat_type](value.strip())

    @staticmethod
    def ip_address(value):
        """Accept any valid IPv4 or IPv6 address."""
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise ValidationError("threat_value is not a valid IP Address") from None

    @staticmethod
    def domain(value):
        """Accept a bare domain name such as example.com (no scheme or path)."""
        value = value.rstrip(".").lower()
        if not DOMAIN_PATTERN.match(value):
            raise ValidationError("threat_value is not a valid Domain (expected a name like example.com, without http:// or a path)")
        return value

    @staticmethod
    def file_hash(value):
        """Accept an MD5, SHA-1 or SHA-256 hash in hexadecimal."""
        if not HEX_PATTERN.match(value) or len(value) not in HASH_LENGTHS:
            raise ValidationError("threat_value is not a valid File Hash (expected 32, 40 or 64 hexadecimal characters)")
        return value.lower()

    @staticmethod
    def signature(value):
        """Accept a malware signature name of 3 to 200 characters."""
        if not 3 <= len(value) <= 200:
            raise ValidationError("threat_value must be between 3 and 200 characters for a Malware Signature")
        return value

    @staticmethod
    def other(value):
        """Accept any other indicator of 3 to 500 characters."""
        if not 3 <= len(value) <= 500:
            raise ValidationError("threat_value must be between 3 and 500 characters")
        return value
