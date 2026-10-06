"""
NetSentinel AI — API Routers Package
"""

from backend.app.api.routes_system import router as system_router
from backend.app.api.routes_learning import router as learning_router
from backend.app.api.routes_analyze import router as analyze_router

__all__ = ["system_router", "learning_router", "analyze_router"]
