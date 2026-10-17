"""Central configuration shared by every service."""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

JWT_SECRET = os.getenv("JWT_SECRET", "sidrms-435l-jwt-secret-change-this-to-a-long-random-value")
SERVICE_KEY = os.getenv("SERVICE_KEY", "sidrms-435l-internal-service-key-change-this-too")
DB_PATH = str(BASE_DIR / os.getenv("DB_PATH", "database/sidrms.db"))
JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))

HOST = "127.0.0.1"

PORTS = {
    "users": 5001,
    "assets": 5002,
    "incidents": 5003,
    "threats": 5004,
    "logs": 5005,
    "reports": 5006,
    "vulnerabilities": 5007,
    "notifications": 5008,
    "playbooks": 5009,
}

URLS = {name: f"http://{HOST}:{port}" for name, port in PORTS.items()}
