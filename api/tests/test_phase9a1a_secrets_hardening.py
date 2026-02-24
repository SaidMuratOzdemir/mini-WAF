# tests/test_phase9a1a_secrets_hardening.py
"""
Phase 9A.1-A — Secrets & Env Hardening tests.

Validates:
  - Production mode + weak JWT → startup fail
  - Production mode + weak control token → startup fail
  - Development  mode + weak values → warning only (no fail)
  - Admin seed behaviour per APP_ENV
"""

from __future__ import annotations

import os
import warnings
from unittest.mock import patch

import pytest

# We need to import the module but avoid triggering the module-level
# validate_security() call on the singleton.  The singleton reads from
# the *real* environment, so dev defaults satisfy it.  Then we build
# isolated instances for each test via explicit env overrides.
# Ensure we have safe defaults so the module can be imported.
_SAFE_ENV = {
    "DATABASE_URL": "postgresql+asyncpg://waf:strongpassword1234@localhost:5432/waf",
    "REDIS_URL": "redis://localhost:6379",
    "JWT_SECRET": "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5a6b7c8d9e0f1a2b3c4d5a6b7c8d9e0f1",
    "CORS_ORIGINS": '["https://waf.example.com"]',
    "APP_ENV": "development",
    "NGINX_CONTROL_TOKEN": "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666",
    "FORWARD_PROXY_CONTROL_TOKEN": "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666",
    "MONGODB_URL": "mongodb://mongodb:27017/waf_logs",
}

# patch env BEFORE first import of config module
with patch.dict(os.environ, _SAFE_ENV, clear=False):
    from app.core.config import Settings


# ---------------------------------------------------------------------------
# Helper: build a Settings object with overrides
# ---------------------------------------------------------------------------
def _make_settings(**overrides):
    defaults = dict(_SAFE_ENV)
    defaults.update(overrides)
    with patch.dict(os.environ, defaults, clear=False):
        return Settings()


# ---------------------------------------------------------------------------
# Tests: production strict enforcement
# ---------------------------------------------------------------------------
class TestProductionSecretEnforcement:
    def test_weak_jwt_secret_fails_in_production(self):
        s = _make_settings(APP_ENV="production", JWT_SECRET="change-me")
        with pytest.raises(SystemExit):
            s.validate_security()

    def test_short_jwt_secret_fails_in_production(self):
        s = _make_settings(APP_ENV="production", JWT_SECRET="short")
        with pytest.raises(SystemExit):
            s.validate_security()

    def test_weak_nginx_token_fails_in_production(self):
        s = _make_settings(APP_ENV="production", NGINX_CONTROL_TOKEN="change-me-nginx-control-token")
        with pytest.raises(SystemExit):
            s.validate_security()

    def test_weak_forward_proxy_token_fails_in_production(self):
        s = _make_settings(APP_ENV="production", FORWARD_PROXY_CONTROL_TOKEN="change-me-forward-proxy-control-token")
        with pytest.raises(SystemExit):
            s.validate_security()

    def test_weak_postgres_password_fails_in_production(self):
        s = _make_settings(APP_ENV="production", DATABASE_URL="postgresql+asyncpg://waf:waf@postgres:5432/waf")
        with pytest.raises(SystemExit):
            s.validate_security()

    def test_localhost_only_cors_fails_in_production(self):
        s = _make_settings(APP_ENV="production", CORS_ORIGINS='["http://localhost:5173"]')
        with pytest.raises(SystemExit):
            s.validate_security()

    def test_strong_secrets_pass_in_production(self):
        s = _make_settings(
            APP_ENV="production",
            JWT_SECRET="a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5a6b7c8d9e0f1a2b3c4d5a6b7c8d9e0f1",
            NGINX_CONTROL_TOKEN="a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
            FORWARD_PROXY_CONTROL_TOKEN="a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
            DATABASE_URL="postgresql+asyncpg://waf:Sup3rS3cur3Pa55w0rd@postgres:5432/waf",
            CORS_ORIGINS='["https://waf.example.com"]',
        )
        s.validate_security()


# ---------------------------------------------------------------------------
# Tests: development lenient mode
# ---------------------------------------------------------------------------
class TestDevelopmentWarningsOnly:
    def test_weak_jwt_warns_but_does_not_fail(self):
        s = _make_settings(APP_ENV="development", JWT_SECRET="change-me")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            s.validate_security()  # must NOT raise
        security_warnings = [x for x in w if "JWT_SECRET" in str(x.message)]
        assert len(security_warnings) >= 1

    def test_weak_tokens_warning_only(self):
        s = _make_settings(
            APP_ENV="development",
            NGINX_CONTROL_TOKEN="change-me-nginx-control-token",
            FORWARD_PROXY_CONTROL_TOKEN="change-me-forward-proxy-control-token",
        )
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            s.validate_security()  # must NOT raise
        msgs = " ".join(str(x.message) for x in w)
        assert "NGINX_CONTROL_TOKEN" in msgs
        assert "FORWARD_PROXY_CONTROL_TOKEN" in msgs


# ---------------------------------------------------------------------------
# Tests: admin seed behaviour
# ---------------------------------------------------------------------------
_SEED_MODULE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "alembic", "versions",
    "20250728_initial_migration_with_user_seed.py",
)


def _load_seed_module():
    """Load migration module by file path (avoids conflict with alembic package)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("seed_migration", _SEED_MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestAdminSeedBehaviour:
    def test_resolve_admin_password_dev_default(self):
        """Development without ADMIN_INITIAL_PASSWORD uses legacy default."""
        env = {"APP_ENV": "development"}
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("ADMIN_INITIAL_PASSWORD", None)
            mod = _load_seed_module()
            pw = mod._resolve_admin_password()
            assert pw == "waf"

    def test_resolve_admin_password_prod_no_env(self):
        """Production without ADMIN_INITIAL_PASSWORD → None (skip seed)."""
        env = {"APP_ENV": "production", "ADMIN_INITIAL_PASSWORD": ""}
        with patch.dict(os.environ, env, clear=False):
            mod = _load_seed_module()
            pw = mod._resolve_admin_password()
            assert pw is None

    def test_resolve_admin_password_prod_with_env(self):
        """Production with ADMIN_INITIAL_PASSWORD → uses that value."""
        env = {"APP_ENV": "production", "ADMIN_INITIAL_PASSWORD": "S3cureP@ss!"}
        with patch.dict(os.environ, env, clear=False):
            mod = _load_seed_module()
            pw = mod._resolve_admin_password()
            assert pw == "S3cureP@ss!"
