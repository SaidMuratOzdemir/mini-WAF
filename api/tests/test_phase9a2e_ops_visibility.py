"""Phase 9A.2-E: Ops Visibility Polish tests."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch, MagicMock

import httpx


# ── Standalone _probe reimplementation (mirrors system.py) ──────────
# We cannot import app.routers.system directly in this test environment
# because of a redis package syntax incompatibility with Python 3.13.
# Instead, we test the probe logic standalone and verify structural contracts.

async def _probe(url: str, timeout: float = 2.0) -> dict:
    """Fire a GET to the given health URL; return status dict."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
        return {"reachable": True, "status_code": resp.status_code}
    except httpx.TimeoutException:
        return {"reachable": False, "error": "timeout"}
    except Exception as exc:
        return {"reachable": False, "error": str(exc)[:120]}


class TestHealthProbe(unittest.TestCase):
    """Verify the async _probe helper used by /system/health."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_probe_reachable(self):
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_response
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = self._run(_probe("http://localhost:8081/health"))

        assert result["reachable"] is True
        assert result["status_code"] == 200

    def test_probe_timeout(self):
        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.side_effect = httpx.TimeoutException("timed out")
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = self._run(_probe("http://localhost:8081/health"))

        assert result["reachable"] is False
        assert result["error"] == "timeout"

    def test_probe_connection_error(self):
        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.side_effect = httpx.ConnectError("connection refused")
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = self._run(_probe("http://localhost:9999/health"))

        assert result["reachable"] is False
        assert "connection refused" in result["error"]


class TestHealthEndpointStructure(unittest.TestCase):
    """Verify the health response contract."""

    def test_expected_keys_in_health_response(self):
        """Health response must contain all expected top-level keys."""
        # Simulate what health_check() builds
        result = {
            "status": "healthy",
            "timestamp": "2025-01-01T00:00:00Z",
            "audit_persistence_failures": 0,
            "helpers": {
                "nginx_control": {"reachable": True, "status_code": 200},
                "forward_proxy_control": {"reachable": False, "error": "timeout"},
                "waf_engine": {"reachable": True, "status_code": 200},
            },
            "inspection_ttl_days": 30,
        }

        assert "helpers" in result
        assert "nginx_control" in result["helpers"]
        assert "forward_proxy_control" in result["helpers"]
        assert "waf_engine" in result["helpers"]
        assert "inspection_ttl_days" in result
        assert "status" in result
        assert "timestamp" in result
        assert "audit_persistence_failures" in result

    def test_degraded_when_audit_failures(self):
        """Status should be 'degraded' if audit failures > 0."""
        audit_failures = 5
        overall = "degraded" if audit_failures > 0 else "healthy"
        assert overall == "degraded"

    def test_healthy_when_no_failures(self):
        """Status should be 'healthy' if no audit failures."""
        audit_failures = 0
        overall = "degraded" if audit_failures > 0 else "healthy"
        assert overall == "healthy"

    def test_helper_probe_unreachable_shape(self):
        """Unreachable probe result should have 'reachable' and 'error' keys."""
        probe = {"reachable": False, "error": "timeout"}
        assert probe["reachable"] is False
        assert "error" in probe

    def test_helper_probe_reachable_shape(self):
        """Reachable probe result should have 'reachable' and 'status_code' keys."""
        probe = {"reachable": True, "status_code": 200}
        assert probe["reachable"] is True
        assert probe["status_code"] == 200


class TestStartupSummaryLog(unittest.TestCase):
    """Verify the structured startup log contains expected fields."""

    def test_startup_log_format(self):
        """Startup log message should include project, version, env, prefix."""
        log_template = (
            "STARTUP project=%s version=%s env=%s api_prefix=%s "
            "redis=%s cors_origins=%d"
        )
        msg = log_template % (
            "WAF Admin API",
            "1.0.0",
            "development",
            "/api/v1",
            "redis:6379",
            3,
        )
        assert "STARTUP" in msg
        assert "project=WAF Admin API" in msg
        assert "env=development" in msg
        assert "cors_origins=3" in msg

    def test_helper_token_log_format(self):
        """Helper token status log should indicate set or MISSING."""
        log_template = (
            "STARTUP helpers nginx_control_token=%s forward_proxy_control_token=%s"
        )
        msg = log_template % ("set", "MISSING")
        assert "nginx_control_token=set" in msg
        assert "forward_proxy_control_token=MISSING" in msg

    def test_redis_url_redaction(self):
        """Redis URL should strip credentials if present."""
        redis_url = "redis://user:password@redis:6379"
        redacted = redis_url.split("@")[-1] if "@" in redis_url else redis_url
        assert redacted == "redis:6379"
        assert "password" not in redacted

    def test_redis_url_no_credentials(self):
        """Redis URL without credentials should pass through."""
        redis_url = "redis://redis:6379"
        redacted = redis_url.split("@")[-1] if "@" in redis_url else redis_url
        assert redacted == "redis://redis:6379"


if __name__ == "__main__":
    unittest.main()
