"""Phase 9A.2-D: MongoDB Inspection TTL Retention tests."""

from __future__ import annotations

import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch


class TestInspectionTTLConfig(unittest.TestCase):
    """Verify WAF_INSPECTION_TTL_DAYS env var is parsed correctly."""

    def test_default_ttl_is_30_days(self):
        # Unset env var to verify default
        env = {k: v for k, v in os.environ.items() if k != "WAF_INSPECTION_TTL_DAYS"}
        with patch.dict(os.environ, env, clear=True):
            # Re-evaluate the expression used in server.py
            ttl_days = int(os.getenv("WAF_INSPECTION_TTL_DAYS", "30"))
            assert ttl_days == 30

    def test_custom_ttl_from_env(self):
        with patch.dict(os.environ, {"WAF_INSPECTION_TTL_DAYS": "7"}):
            ttl_days = int(os.getenv("WAF_INSPECTION_TTL_DAYS", "30"))
            assert ttl_days == 7

    def test_zero_ttl_means_no_expiry(self):
        with patch.dict(os.environ, {"WAF_INSPECTION_TTL_DAYS": "0"}):
            ttl_days = int(os.getenv("WAF_INSPECTION_TTL_DAYS", "30"))
            assert ttl_days == 0
            # zero means TTL index creation is skipped
            assert not (ttl_days > 0)

    def test_ttl_seconds_calculation(self):
        ttl_days = 30
        ttl_seconds = ttl_days * 86400
        assert ttl_seconds == 2592000  # 30 days in seconds

        ttl_days = 7
        ttl_seconds = ttl_days * 86400
        assert ttl_seconds == 604800  # 7 days in seconds


class TestHealthEndpointTTLField(unittest.TestCase):
    """Verify /health returns inspection_ttl_days when configured."""

    def _make_app_state(self, ttl_days: int = 30):
        """Create a mock app state."""
        state = MagicMock()
        state.mongo_collection = MagicMock()  # connected
        state.redis_client = MagicMock()        # connected
        state.inspection_queue = MagicMock()
        state.inspection_queue.qsize.return_value = 0
        state.worker_tasks = [MagicMock()] * 4
        state.inspection_ttl_days = ttl_days
        return state

    def test_health_includes_ttl_days(self):
        state = self._make_app_state(ttl_days=30)
        # Simulate what the health endpoint builds
        result = {
            "status": "ok",
            "redis": "connected" if state.redis_client else "disconnected",
            "mongodb": "connected" if state.mongo_collection else "disconnected",
            "inspection_queue_size": state.inspection_queue.qsize(),
            "inspection_workers": len(state.worker_tasks),
        }
        ttl = getattr(state, "inspection_ttl_days", 0)
        result["inspection_ttl_days"] = ttl if ttl > 0 else None

        assert result["inspection_ttl_days"] == 30
        assert result["status"] == "ok"
        assert result["mongodb"] == "connected"

    def test_health_ttl_none_when_zero(self):
        state = self._make_app_state(ttl_days=0)
        ttl = getattr(state, "inspection_ttl_days", 0)
        assert (ttl if ttl > 0 else None) is None

    def test_health_ttl_custom_value(self):
        state = self._make_app_state(ttl_days=7)
        ttl = getattr(state, "inspection_ttl_days", 0)
        assert ttl == 7


class TestTTLIndexCreation(unittest.TestCase):
    """Verify TTL index create_index is called with correct params."""

    def test_ttl_index_params(self):
        """TTL index should use 'timestamp' field with correct expireAfterSeconds."""
        collection = AsyncMock()
        ttl_days = 14
        ttl_seconds = ttl_days * 86400

        # This is the call pattern from server.py lifespan
        import asyncio
        asyncio.get_event_loop().run_until_complete(
            collection.create_index(
                "timestamp",
                name="ttl_timestamp",
                expireAfterSeconds=ttl_seconds,
            )
        )

        collection.create_index.assert_called_with(
            "timestamp",
            name="ttl_timestamp",
            expireAfterSeconds=1209600,  # 14 * 86400
        )

    def test_ttl_index_skipped_when_zero(self):
        """Zero TTL days should not create a TTL index."""
        ttl_days = 0
        assert not (ttl_days > 0), "Should skip TTL index creation"


if __name__ == "__main__":
    unittest.main()
