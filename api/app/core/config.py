# api/app/core/config.py

from __future__ import annotations

import logging
import sys
import warnings

from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── Secrets that MUST NOT remain at their default/example values in production ──
_WEAK_JWT_SECRETS = frozenset({
    "change-me",
    "your-super-secret-jwt-key-change-this-in-production",
    "secret",
    "jwt-secret",
    "",
})
_WEAK_CONTROL_TOKENS = frozenset({
    "change-me-nginx-control-token",
    "change-me-forward-proxy-control-token",
    "change-me",
    "",
})
_WEAK_POSTGRES_PASSWORDS = frozenset({"waf", "postgres", "password", "changeme", ""})

_DEV_CORS_MARKERS = frozenset({"localhost", "127.0.0.1", "0.0.0.0"})


class Settings(BaseSettings):
    PROJECT_NAME: str = "WAF Admin API"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # ── Core ──
    DATABASE_URL: str
    REDIS_URL: str
    JWT_SECRET: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    CORS_ORIGINS: List[AnyHttpUrl]
    port: int = 8001

    # ── Environment mode  (development | production) ──
    APP_ENV: str = "development"

    # ── Control plane tokens (validated at startup) ──
    NGINX_CONTROL_TOKEN: Optional[str] = None
    FORWARD_PROXY_CONTROL_TOKEN: Optional[str] = None

    # ── Admin seed control ──
    ADMIN_INITIAL_PASSWORD: Optional[str] = None

    # ── MONGODB_URL (informational, used by logs router) ──
    MONGODB_URL: str = "mongodb://mongodb:27017/waf_logs"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    # ── helpers ──
    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower().strip() == "production"

    def _postgres_password(self) -> str:
        """Extract password from DATABASE_URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.DATABASE_URL.replace("+asyncpg", ""))
            return parsed.password or ""
        except Exception:
            return ""

    # ── Startup validation ──
    def validate_security(self) -> None:
        """
        Enforce secure-by-default rules.
        In production → hard fail (SystemExit) for P0 violations.
        In development → warning only.
        """
        errors: list[str] = []
        warns: list[str] = []

        # 1) JWT_SECRET
        if self.JWT_SECRET.strip().lower() in _WEAK_JWT_SECRETS or len(self.JWT_SECRET) < 16:
            msg = "JWT_SECRET is weak/default. Generate one: openssl rand -hex 32"
            (errors if self.is_production else warns).append(msg)

        # 2) Control tokens
        nginx_tok = self.NGINX_CONTROL_TOKEN or ""
        if nginx_tok.strip().lower() in _WEAK_CONTROL_TOKENS or len(nginx_tok) < 16:
            msg = "NGINX_CONTROL_TOKEN is weak/default. Generate one: openssl rand -hex 32"
            (errors if self.is_production else warns).append(msg)

        fp_tok = self.FORWARD_PROXY_CONTROL_TOKEN or ""
        if fp_tok.strip().lower() in _WEAK_CONTROL_TOKENS or len(fp_tok) < 16:
            msg = "FORWARD_PROXY_CONTROL_TOKEN is weak/default. Generate one: openssl rand -hex 32"
            (errors if self.is_production else warns).append(msg)

        # 3) Postgres password
        pg_pass = self._postgres_password()
        if pg_pass.lower() in _WEAK_POSTGRES_PASSWORDS or len(pg_pass) < 8:
            msg = "POSTGRES_PASSWORD is weak/default. Use a strong password for production."
            (errors if self.is_production else warns).append(msg)

        # 4) CORS origins – all-localhost in production is suspicious
        origins_str = " ".join(str(o) for o in self.CORS_ORIGINS).lower()
        if self.is_production:
            if not self.CORS_ORIGINS:
                errors.append("CORS_ORIGINS is empty in production mode.")
            elif all(any(marker in str(o).lower() for marker in _DEV_CORS_MARKERS) for o in self.CORS_ORIGINS):
                errors.append(
                    "CORS_ORIGINS contains only dev/localhost origins in production. "
                    "Set real domain origins for production."
                )

        # Emit warnings
        for w in warns:
            logger.warning("[SECURITY] %s", w)
            warnings.warn(f"[SECURITY] {w}", stacklevel=2)

        # Emit errors – fatal in production
        if errors:
            for e in errors:
                logger.error("[SECURITY-FATAL] %s", e)
            if self.is_production:
                print("\n".join(f"FATAL: {e}" for e in errors), file=sys.stderr)
                raise SystemExit(
                    f"Startup blocked: {len(errors)} security violation(s) in production mode. "
                    "Fix the issues above or set APP_ENV=development."
                )


settings = Settings()
settings.validate_security()