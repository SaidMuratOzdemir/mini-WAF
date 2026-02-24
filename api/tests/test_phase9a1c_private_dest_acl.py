# tests/test_phase9a1c_private_dest_acl.py
"""
Phase 9A.1-C — Forward Proxy Private Destination ACL tests.

Validates:
  - block_private_destinations=True → private ACL lines in rendered config
  - block_private_destinations=False → no private ACL lines
  - Schema accepts the new field
  - Default profile (None) still renders block ACL
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from typing import Optional
from unittest.mock import patch

import pytest

# Ensure safe env for module import
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

with patch.dict(os.environ, _SAFE_ENV, clear=False):
    from app.services.forward_proxy_config_manager import ForwardProxyConfigManager
    from app.schemas import OutboundProxyProfileCreate


# Lightweight stand-in for ORM model
@dataclass
class FakeProfile:
    id: int = 1
    name: str = "test"
    listen_port: int = 3128
    is_enabled: bool = True
    require_auth: bool = False
    allow_connect_ports: str = "443,563"
    allowed_client_cidrs: Optional[str] = None
    default_action: str = "deny"
    block_private_destinations: bool = True


class TestPrivateDestinationACLRendering:
    """Verify that squid.conf.j2 renders private ACL blocks correctly."""

    def setup_method(self):
        self.mgr = ForwardProxyConfigManager()

    def test_private_acl_present_when_block_enabled(self):
        profile = FakeProfile(block_private_destinations=True)
        config = self.mgr.render_proxy_config(profile, rules=[])
        assert "private_dst" in config
        assert "10.0.0.0/8" in config
        assert "172.16.0.0/12" in config
        assert "192.168.0.0/16" in config
        assert "169.254.0.0/16" in config
        assert "100.64.0.0/10" in config
        assert "http_access deny private_dst" in config
        assert "http_access deny CONNECT private_dst" in config

    def test_private_acl_absent_when_block_disabled(self):
        profile = FakeProfile(block_private_destinations=False)
        config = self.mgr.render_proxy_config(profile, rules=[])
        assert "private_dst" not in config

    def test_null_profile_renders_with_private_block(self):
        """Default (no profile) still blocks private destinations."""
        config = self.mgr.render_proxy_config(None, rules=None)
        assert "private_dst" in config
        assert "http_access deny private_dst" in config

    def test_ipv6_private_ranges_present(self):
        profile = FakeProfile(block_private_destinations=True)
        config = self.mgr.render_proxy_config(profile, rules=[])
        assert "fc00::/7" in config
        assert "::1/128" in config
        assert "fe80::/10" in config


class TestPrivateDestinationSchema:
    """Verify schema accepts new field."""

    def test_default_block_private_is_true(self):
        payload = OutboundProxyProfileCreate(
            name="test",
            listen_port=3128,
        )
        assert payload.block_private_destinations is True

    def test_explicit_false(self):
        payload = OutboundProxyProfileCreate(
            name="test",
            listen_port=3128,
            block_private_destinations=False,
        )
        assert payload.block_private_destinations is False


class TestOpenProxyWarning:
    """Verify that the config manager context handles open-proxy edge cases."""

    def test_default_action_allow_no_clients_logged(self):
        """Verify config renders (does not crash) for wide-open profile."""
        mgr = ForwardProxyConfigManager()
        profile = FakeProfile(
            default_action="allow",
            allowed_client_cidrs=None,
            block_private_destinations=True,
        )
        config = mgr.render_proxy_config(profile, rules=[])
        # Even if wide-open, private destinations are still blocked
        assert "http_access deny private_dst" in config
        assert "http_access allow all" in config
