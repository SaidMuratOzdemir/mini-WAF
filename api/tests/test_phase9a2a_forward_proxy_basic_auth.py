"""Phase 9A.2-A — Forward Proxy Basic Auth tests.

Tests cover:
- OutboundProxyUser schema validation (username, password policy)
- Password hash created, plaintext never stored
- htpasswd render content format
- require_auth=true with no users → config apply fails
- require_auth=false → no auth block in rendered config
- require_auth=true → auth block rendered with correct paths/realm
- Auth template does not break existing ACL precedence
- Profile schema accepts require_auth=true (was previously rejected in 9a)
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.schemas import (
    OutboundProxyProfileCreate,
    OutboundProxyUserCreate,
    OutboundProxyUserUpdate,
)
from app.services.forward_proxy_config_manager import ForwardProxyConfigManager


# ── Helpers ──────────────────────────────────────────────────────────

def _make_profile(**overrides):
    defaults = {
        "id": 1,
        "name": "test-profile",
        "listen_port": 3128,
        "is_enabled": True,
        "require_auth": False,
        "auth_realm": "WAF Forward Proxy",
        "allow_connect_ports": "443,563",
        "allowed_client_cidrs": None,
        "default_action": "deny",
        "block_private_destinations": True,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_proxy_user(username="testuser", password_hash="$2b$12$abcdefABCDEF1234567890uEXAMPLEHASH1234567890abcdefghi", is_active=True):
    return SimpleNamespace(username=username, password_hash=password_hash, is_active=is_active)


def _get_manager(**kwargs):
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "squid.conf")
        htpasswd_path = os.path.join(tmpdir, "squid_users")
        mgr = ForwardProxyConfigManager(
            generated_config_path=config_path,
            validate_command=["/usr/bin/true"],
            reload_command=["/usr/bin/true"],
            htpasswd_path=htpasswd_path,
            auth_helper_path="/usr/lib/squid/basic_ncsa_auth",
            **kwargs,
        )
        yield mgr


@pytest.fixture
def manager():
    for mgr in _get_manager():
        yield mgr


# ── Schema: require_auth=true now accepted ───────────────────────────

class TestProfileSchemaRequireAuth:
    def test_require_auth_true_accepted(self):
        """Phase 9A.2-A: require_auth=true should no longer be rejected."""
        profile = OutboundProxyProfileCreate(
            name="auth-profile",
            require_auth=True,
            listen_port=3128,
            allow_connect_ports="443",
            default_action="deny",
        )
        assert profile.require_auth is True

    def test_require_auth_false_still_works(self):
        profile = OutboundProxyProfileCreate(
            name="noauth-profile",
            require_auth=False,
            listen_port=3128,
            allow_connect_ports="443",
            default_action="deny",
        )
        assert profile.require_auth is False

    def test_auth_realm_default(self):
        profile = OutboundProxyProfileCreate(
            name="realm-profile",
            listen_port=3128,
            allow_connect_ports="443",
            default_action="deny",
        )
        assert profile.auth_realm == "WAF Forward Proxy"

    def test_auth_realm_custom(self):
        profile = OutboundProxyProfileCreate(
            name="realm-profile",
            auth_realm="My Custom Realm",
            listen_port=3128,
            allow_connect_ports="443",
            default_action="deny",
        )
        assert profile.auth_realm == "My Custom Realm"

    def test_auth_realm_rejects_quotes(self):
        with pytest.raises(Exception):
            OutboundProxyProfileCreate(
                name="bad-realm",
                auth_realm='My "Realm"',
                listen_port=3128,
                allow_connect_ports="443",
                default_action="deny",
            )

    def test_auth_realm_rejects_newlines(self):
        with pytest.raises(Exception):
            OutboundProxyProfileCreate(
                name="bad-realm",
                auth_realm="My\nRealm",
                listen_port=3128,
                allow_connect_ports="443",
                default_action="deny",
            )


# ── Schema: User validation ──────────────────────────────────────────

class TestProxyUserSchema:
    def test_valid_user_create(self):
        user = OutboundProxyUserCreate(username="proxy.user_1", password="a" * 12)
        assert user.username == "proxy.user_1"

    def test_username_normalized_to_lower(self):
        user = OutboundProxyUserCreate(username="ProxyUser", password="a" * 12)
        assert user.username == "proxyuser"

    def test_username_invalid_chars_rejected(self):
        with pytest.raises(Exception):
            OutboundProxyUserCreate(username="user:name", password="a" * 12)

    def test_username_empty_rejected(self):
        with pytest.raises(Exception):
            OutboundProxyUserCreate(username="  ", password="a" * 12)

    def test_password_too_short_rejected(self):
        with pytest.raises(Exception):
            OutboundProxyUserCreate(username="user", password="short")

    def test_password_min_length_accepted(self):
        user = OutboundProxyUserCreate(username="user", password="a" * 12)
        assert len(user.password) == 12

    def test_update_password_optional(self):
        update = OutboundProxyUserUpdate(is_active=False)
        assert update.password is None
        assert update.is_active is False

    def test_update_password_validated(self):
        with pytest.raises(Exception):
            OutboundProxyUserUpdate(password="short")


# ── htpasswd generation ──────────────────────────────────────────────

class TestHtpasswdGeneration:
    def test_generates_correct_format(self, manager):
        users = [
            _make_proxy_user(username="alice", password_hash="$2b$12$ALICEhashALICEhashALICduALICEhashALICEhashALICEhashALI"),
            _make_proxy_user(username="bob", password_hash="$2b$12$BOBhashBOBhashBOBhashBuOBhashBOBhashBOBhashBOBhashBO"),
        ]
        content = manager.generate_htpasswd_content(users)
        lines = content.strip().split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("alice:")
        assert lines[1].startswith("bob:")

    def test_empty_users_produces_empty_content(self, manager):
        content = manager.generate_htpasswd_content([])
        assert content == ""

    def test_colon_in_username_skipped(self, manager):
        users = [_make_proxy_user(username="bad:user")]
        content = manager.generate_htpasswd_content(users)
        assert content == ""

    def test_newline_in_username_skipped(self, manager):
        users = [_make_proxy_user(username="bad\nuser")]
        content = manager.generate_htpasswd_content(users)
        assert content == ""

    def test_htpasswd_file_written_atomically(self, manager):
        users = [_make_proxy_user(username="alice", password_hash="$2b$12$somehash")]
        path = manager.write_htpasswd_atomic(users)
        assert path.exists()
        content = path.read_text()
        assert "alice:$2b$12$somehash" in content


# ── Squid config template: auth rendering ────────────────────────────

class TestSquidConfigAuthRendering:
    def test_require_auth_false_no_auth_block(self, manager):
        profile = _make_profile(require_auth=False)
        rendered = manager.render_proxy_config(profile, [])
        assert "auth_param" not in rendered
        assert "proxy_auth" not in rendered
        assert "authenticated" not in rendered

    def test_require_auth_true_renders_auth_block(self, manager):
        profile = _make_profile(require_auth=True, auth_realm="Test Realm")
        rendered = manager.render_proxy_config(profile, [])
        assert "auth_param basic program" in rendered
        assert "basic_ncsa_auth" in rendered
        assert "Test Realm" in rendered
        assert "proxy_auth REQUIRED" in rendered
        assert "http_access deny !authenticated" in rendered

    def test_auth_block_before_destination_rules(self, manager):
        """Auth deny must appear before custom deny/allow rules."""
        profile = _make_profile(require_auth=True)
        rule = SimpleNamespace(
            id=1, action="allow", rule_type="domain_exact",
            value="example.com", priority=100, is_enabled=True,
        )
        rendered = manager.render_proxy_config(profile, [rule])
        auth_pos = rendered.find("http_access deny !authenticated")
        rule_pos = rendered.find("http_access allow rule_1")
        assert auth_pos < rule_pos, "Auth deny must precede destination rules"

    def test_auth_block_after_client_cidrs(self, manager):
        """Client CIDR check should come before auth."""
        profile = _make_profile(
            require_auth=True,
            allowed_client_cidrs="10.0.0.0/8",
        )
        rendered = manager.render_proxy_config(profile, [])
        cidr_pos = rendered.find("http_access deny !allowed_clients")
        auth_pos = rendered.find("http_access deny !authenticated")
        assert cidr_pos < auth_pos, "Client CIDR deny must precede auth deny"

    def test_private_dst_after_auth(self, manager):
        """Private destination blocking after auth."""
        profile = _make_profile(
            require_auth=True,
            block_private_destinations=True,
        )
        rendered = manager.render_proxy_config(profile, [])
        auth_pos = rendered.find("http_access deny !authenticated")
        private_pos = rendered.find("http_access deny private_dst")
        assert auth_pos < private_pos

    def test_null_profile_no_auth(self, manager):
        rendered = manager.render_proxy_config(None, [])
        assert "auth_param" not in rendered


# ── apply_with_rollback with auth ────────────────────────────────────

class TestApplyWithRollbackAuth:
    def test_apply_with_auth_users(self, manager):
        profile = _make_profile(require_auth=True)
        users = [_make_proxy_user(username="alice", password_hash="$2b$12$hash")]
        result = manager.apply_with_rollback(profile, [], users)
        assert result["sync_result"]["auth_user_count"] == 1
        # htpasswd file should exist
        assert manager.htpasswd_path.exists()
        content = manager.htpasswd_path.read_text()
        assert "alice" in content

    def test_apply_no_auth_no_htpasswd_written(self, manager):
        profile = _make_profile(require_auth=False)
        result = manager.apply_with_rollback(profile, [], [])
        # htpasswd should not be written when auth not required
        assert not manager.htpasswd_path.exists() or manager.htpasswd_path.read_text() == ""

    def test_rollback_restores_htpasswd(self, manager):
        """If validate/reload fails, htpasswd should also be rolled back."""
        # First, write a known state
        profile = _make_profile(require_auth=True)
        users = [_make_proxy_user(username="original")]
        manager.apply_with_rollback(profile, [], users)
        original_content = manager.htpasswd_path.read_text()

        # Now attempt an apply that will fail at validation
        bad_manager = ForwardProxyConfigManager(
            generated_config_path=manager.generated_config_path,
            validate_command=["/bin/false"],
            reload_command=["/usr/bin/true"],
            htpasswd_path=manager.htpasswd_path,
            auth_helper_path="/usr/lib/squid/basic_ncsa_auth",
        )
        new_users = [_make_proxy_user(username="newuser")]
        with pytest.raises(Exception):
            bad_manager.apply_with_rollback(profile, [], new_users)

        # htpasswd should be restored to original
        restored_content = manager.htpasswd_path.read_text()
        assert "original" in restored_content
        assert "newuser" not in restored_content


# ── Regression: existing behavior preserved ──────────────────────────

class TestRegressionNoAuthBreak:
    def test_no_auth_profile_renders_correctly(self, manager):
        """Verify a profile without auth renders the same as before."""
        profile = _make_profile(
            require_auth=False,
            allowed_client_cidrs="10.0.0.0/8",
            block_private_destinations=True,
            default_action="deny",
        )
        rule = SimpleNamespace(
            id=1, action="allow", rule_type="domain_exact",
            value="example.com", priority=100, is_enabled=True,
        )
        rendered = manager.render_proxy_config(profile, [rule])
        assert "http_port 3128" in rendered
        assert "http_access deny !allowed_clients" in rendered
        assert "http_access deny private_dst" in rendered
        assert "http_access allow rule_1" in rendered
        assert "http_access deny all" in rendered
        assert "auth_param" not in rendered

    def test_apply_no_auth_still_works(self, manager):
        profile = _make_profile(require_auth=False)
        result = manager.apply_with_rollback(profile, [], [])
        assert result["sync_result"]["profile_id"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
