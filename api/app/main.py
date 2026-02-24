# api/app/main.py

import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis

from app.core.config import settings
from app.core import dependencies
from app.routers import auth, sites, ips, patterns, system, logs, certificates, policies, audits, forward_proxy

_logger = logging.getLogger("app.requests")


# ── Phase 9A.1-E: Structured request/error logging middleware ────────
class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every request with status code and latency; log 5xx with full context."""

    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            elapsed_ms = (time.monotonic() - start) * 1000
            _logger.exception(
                "UNHANDLED_EXCEPTION method=%s path=%s client=%s elapsed_ms=%.1f",
                request.method,
                request.url.path,
                request.client.host if request.client else "unknown",
                elapsed_ms,
            )
            raise

        elapsed_ms = (time.monotonic() - start) * 1000
        if response.status_code >= 500:
            _logger.error(
                "SERVER_ERROR status=%d method=%s path=%s client=%s elapsed_ms=%.1f",
                response.status_code,
                request.method,
                request.url.path,
                request.client.host if request.client else "unknown",
                elapsed_ms,
            )
        elif response.status_code >= 400:
            _logger.warning(
                "CLIENT_ERROR status=%d method=%s path=%s client=%s elapsed_ms=%.1f",
                response.status_code,
                request.method,
                request.url.path,
                request.client.host if request.client else "unknown",
                elapsed_ms,
            )
        else:
            _logger.debug(
                "OK status=%d method=%s path=%s elapsed_ms=%.1f",
                response.status_code,
                request.method,
                request.url.path,
                elapsed_ms,
            )
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages application startup and shutdown events.
    """
    # On startup: Initialize the Redis connection pool
    dependencies.redis_pool = redis.ConnectionPool.from_url(
        settings.REDIS_URL, max_connections=10, decode_responses=True
    )

    # The application is now ready to run
    yield

    # On shutdown: Disconnect the Redis connection pool
    if dependencies.redis_pool:
        await dependencies.redis_pool.disconnect()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    description="Admin dashboard API for the Web Application Firewall (WAF)",
    lifespan=lifespan,  # Use the modern lifespan event handler
    openapi_tags=[
        {"name": "Authentication", "description": "User login and token management."},
        {"name": "Sites", "description": "Manage protected websites."},
        {"name": "IP Management", "description": "Manage banned and whitelisted IP addresses."},
        {"name": "Patterns", "description": "Manage malicious security patterns."},
        {"name": "Certificates", "description": "Manage TLS certificates for HTTPS sites."},
        {"name": "Forward Proxy", "description": "Manage explicit outbound proxy profiles and destination rules."},
        {"name": "Policies", "description": "Manage upstream security policy configuration."},
        {"name": "Audit", "description": "Audit trail for control-plane actions."},
        {"name": "System", "description": "System health, status, and cache operations."},
        {"name": "logs", "description": "Request and response logging management."},
    ],
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin) for origin in settings.CORS_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Phase 9A.1-E: Request logging / failure visibility middleware
app.add_middleware(RequestLoggingMiddleware)

# Include all the routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(sites.router, prefix=settings.API_V1_STR)
app.include_router(ips.router, prefix=settings.API_V1_STR)
app.include_router(patterns.router, prefix=settings.API_V1_STR)
app.include_router(certificates.router, prefix=settings.API_V1_STR)
app.include_router(forward_proxy.router, prefix=settings.API_V1_STR)
app.include_router(policies.router, prefix=settings.API_V1_STR)
app.include_router(audits.router, prefix=settings.API_V1_STR)
app.include_router(system.router, prefix=settings.API_V1_STR)
app.include_router(logs.router, prefix=settings.API_V1_STR)
