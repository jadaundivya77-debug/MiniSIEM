import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend"
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_DIR = BASE_DIR / "data"
DATABASE_DIR = DATA_DIR / "database"
SAMPLE_LOGS_DIR = DATA_DIR / "sample_logs"

DATABASE_DIR.mkdir(parents=True, exist_ok=True)
SAMPLE_LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Environment and Security Config
SECRET_KEY = os.getenv("SECRET_KEY", "minisiemx-super-secret-key-soc-platform-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

# Database Configuration (SQLite by default, modular for PostgreSQL)
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    f"sqlite:///{DATABASE_DIR / 'minisiemx.db'}"
)

# Ingestion & Detection Thresholds
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "25"))
BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW_SECONDS = int(os.getenv("BRUTE_FORCE_WINDOW_SECONDS", "120"))
PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "10"))
PORT_SCAN_WINDOW_SECONDS = int(os.getenv("PORT_SCAN_WINDOW_SECONDS", "60"))
CORRELATION_WINDOW_SECONDS = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "180"))

# Default Trusted IPs
DEFAULT_TRUSTED_IPS = [
    "127.0.0.1",
    "10.0.0.1",
    "10.0.0.2",
    "192.168.1.1",
    "192.168.1.10",
    "::1"
]

