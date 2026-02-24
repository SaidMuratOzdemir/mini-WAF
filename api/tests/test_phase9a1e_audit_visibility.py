"""Phase 9A.1-E — Audit Logging Hardening & Failure Visibility Tests.

Validates:
  1. Structured error logging on audit persistence failure.
  2. Audit failure counter increments and is exposed via health endpoint.
  3. Request context is captured in error messages.
  4. Control clients expose retry parameters.
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import os
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── helpers ──────────────────────────────────────────────────────────

# Load audit_logger by file path to avoid interfering with the real module system
_AUDIT_LOGGER_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "audit_logger.py"


def _load_audit_module():
    """
    Load audit_logger directly by file path, with mocked dependencies.
    This avoids SQLAlchemy re-registration errors when running the full suite.
    """
    # Create mock modules for the heavy dependencies
    mock_db = types.ModuleType("app.database")
    mock_db.AsyncSessionLocal = MagicMock()

    mock_models = types.ModuleType("app.models")
    mock_models.AuditLog = MagicMock

    mock_schemas = types.ModuleType("app.schemas")
    mock_schemas.UserInDB = MagicMock

    module_mocks = {
        "app": types.ModuleType("app"),
        "app.database": mock_db,
        "app.models": mock_models,
        "app.schemas": mock_schemas,
    }

    # Load via importlib with a unique name to avoid collisions
    spec = importlib.util.spec_from_file_location(
        "test_audit_logger_isolated",
        str(_AUDIT_LOGGER_PATH),
        submodule_search_locations=[],
    )
    with patch.dict(sys.modules, module_mocks):
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

    return mod


def _make_fake_request(path: str = "/api/test", method: str = "POST", client_ip: str = "10.0.0.1"):
    """Build a minimal Request-like mock."""
    request = MagicMock()
    request.method = method
    request.url.path = path
    request.client.host = client_ip
    request.headers = {"x-forwarded-for": client_ip, "x-request-id": "req-abc-123"}
    return request


# ── Tests ────────────────────────────────────────────────────────────

class TestAuditStructuredError:
    """Verify structured error output on DB failure."""

    def test_failure_counter_increments(self):
        mod = _load_audit_module()
        assert mod.get_audit_failure_count() == 0

        mod.AsyncSessionLocal = MagicMock(side_effect=RuntimeError("DB down"))
        asyncio.get_event_loop().run_until_complete(
            mod.write_audit_log(
                action="test.action",
                target_type="site",
                target_id="42",
                actor=None,
                request=None,
                success=True,
            )
        )
        assert mod.get_audit_failure_count() == 1

    def test_failure_counter_increments_multiple(self):
        mod = _load_audit_module()

        mod.AsyncSessionLocal = MagicMock(side_effect=RuntimeError("DB down"))
        for _ in range(3):
            asyncio.get_event_loop().run_until_complete(
                mod.write_audit_log(
                    action="test.action",
                    target_type="site",
                    target_id="1",
                    actor=None,
                    request=None,
                    success=True,
                )
            )
        assert mod.get_audit_failure_count() == 3

    def test_structured_log_contains_context(self, caplog):
        mod = _load_audit_module()
        fake_request = _make_fake_request(path="/api/v1/sites", method="DELETE", client_ip="192.168.1.100")
        fake_actor = MagicMock()
        fake_actor.id = 7
        fake_actor.username = "admin_user"

        mod.AsyncSessionLocal = MagicMock(side_effect=RuntimeError("connection refused"))
        with caplog.at_level(logging.ERROR):
            asyncio.get_event_loop().run_until_complete(
                mod.write_audit_log(
                    action="site.delete",
                    target_type="site",
                    target_id="99",
                    actor=fake_actor,
                    request=fake_request,
                    success=True,
                )
            )

        error_records = [r for r in caplog.records if "AUDIT_PERSIST_FAILURE" in r.message]
        assert len(error_records) >= 1
        msg = error_records[0].message
        assert "site.delete" in msg
        assert "admin_user" in msg
        assert "192.168.1.100" in msg
        assert "failures=" in msg

    def test_log_includes_request_id(self, caplog):
        mod = _load_audit_module()
        fake_request = _make_fake_request()

        mod.AsyncSessionLocal = MagicMock(side_effect=RuntimeError("timeout"))
        with caplog.at_level(logging.ERROR):
            asyncio.get_event_loop().run_until_complete(
                mod.write_audit_log(
                    action="ip.ban",
                    target_type="ip",
                    target_id="1.2.3.4",
                    actor=None,
                    request=fake_request,
                    success=True,
                )
            )

        error_records = [r for r in caplog.records if "AUDIT_PERSIST_FAILURE" in r.message]
        assert len(error_records) >= 1
        assert "req-abc-123" in error_records[0].message

    def test_no_exception_raised_on_failure(self):
        """Audit failure must not propagate — it's fire-and-forget."""
        mod = _load_audit_module()

        mod.AsyncSessionLocal = MagicMock(side_effect=RuntimeError("DB exploded"))
        # Should NOT raise
        asyncio.get_event_loop().run_until_complete(
            mod.write_audit_log(
                action="pattern.update",
                target_type="pattern",
                target_id="5",
                actor=None,
                request=None,
                success=True,
            )
        )
        # If we got here, the test passes — no exception propagated


class TestRequestContext:
    """Verify _request_context helper."""

    def test_none_request(self):
        mod = _load_audit_module()
        ctx = mod._request_context(None)
        assert ctx["client_ip"] is None
        assert ctx["method"] is None

    def test_with_request(self):
        mod = _load_audit_module()
        req = _make_fake_request(path="/api/v1/auth/login", method="POST", client_ip="172.16.0.5")
        ctx = mod._request_context(req)
        assert ctx["client_ip"] == "172.16.0.5"
        assert ctx["method"] == "POST"
        assert ctx["path"] == "/api/v1/auth/login"
        assert ctx["request_id"] == "req-abc-123"


class TestControlClientRetryConfig:
    """Verify that control clients expose retry/backoff configuration."""

    def test_nginx_control_client_has_retry_constants(self):
        import app.services.nginx_control_client as ncc
        assert hasattr(ncc, "MAX_RETRIES")
        assert hasattr(ncc, "BACKOFF_BASE")
        assert ncc.MAX_RETRIES >= 1
        assert ncc.BACKOFF_BASE > 0

    def test_forward_proxy_control_client_has_retry_constants(self):
        import app.services.forward_proxy_control_client as fpc
        assert hasattr(fpc, "MAX_RETRIES")
        assert hasattr(fpc, "BACKOFF_BASE")
        assert fpc.MAX_RETRIES >= 1
        assert fpc.BACKOFF_BASE > 0
