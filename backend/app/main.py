from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.api import api_router
from app.api.routes.health import router as health_router
from app.core.config import settings
from app.core.errors import register_error_handlers

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
)

# Standardized error envelope for every error response (plan §2.14).
register_error_handlers(app)

if settings.all_cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.all_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# /health at the root (probed by Caddy / docker healthchecks).
app.include_router(health_router)
# Versioned API.
app.include_router(api_router, prefix=settings.API_V1_STR)
