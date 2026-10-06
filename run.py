"""
NetSentinel AI — Root Application Runner

Usage:
    python run.py
"""

import sys
import uvicorn
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.app.config import HOST, PORT, RELOAD, APP_NAME, APP_VERSION

if __name__ == "__main__":
    print(f"============================================================")
    print(f"  {APP_NAME} v{APP_VERSION} — Security Compliance Engine")
    print(f"  Starting server at: http://{HOST}:{PORT}")
    print(f"  API Documentation:  http://{HOST}:{PORT}/docs")
    print(f"============================================================")
    uvicorn.run("backend.app.main:app", host=HOST, port=PORT, reload=RELOAD)
