"""
NetSentinel AI — Main Application Entry Point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import (
    APP_NAME,
    APP_VERSION,
    APP_DESCRIPTION,
    CORS_ORIGINS,
)
from backend.app.api.routes_system import router as system_router
from backend.app.api.routes_learning import router as learning_router
from backend.app.api.routes_analyze import router as analyze_router


def create_app() -> FastAPI:
    """Create and configure the NetSentinel AI FastAPI application."""
    app = FastAPI(
        title=APP_NAME,
        description=APP_DESCRIPTION,
        version=APP_VERSION,
    )

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS if CORS_ORIGINS != ["*"] else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API Routers
    app.include_router(system_router)
    app.include_router(learning_router)
    app.include_router(analyze_router)

    return app


app = create_app()
