"""
NetSentinel AI — Configuration Management
"""

import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = BASE_DIR / "backend"
DATA_DIR = Path(os.getenv("DATA_DIR", str(BACKEND_DIR / "data")))
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", str(BASE_DIR / "reports")))

# Ensure necessary directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Application metadata
APP_NAME = os.getenv("APP_NAME", "NetSentinel AI")
APP_VERSION = os.getenv("APP_VERSION", "2.3.0")
APP_DESCRIPTION = os.getenv(
    "APP_DESCRIPTION",
    "AI-powered Vendor-Agnostic Network Security Compliance Engine"
)

# Server configuration
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))
DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")
RELOAD = os.getenv("RELOAD", "true").lower() in ("true", "1", "yes")

# CORS configuration
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "*").split(",")
    if origin.strip()
]
