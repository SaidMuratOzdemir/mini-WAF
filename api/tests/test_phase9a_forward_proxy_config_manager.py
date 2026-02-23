from types import SimpleNamespace

from app.services.forward_proxy_config_manager import ForwardProxyConfigManager


def _profile(**overrides):
    base = {
        "id": 1,
        "name": "default",
        "listen_port": 3128,
        "is_enabled": True,
        "require_auth": False,
        "allow_connect_ports": "443,563",
        "allowed_client_cidrs": "10.0.0.0/24",
        "default_action": "deny",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _rule(rule_id: int, action: str, rule_type: str, value: str, priority: int = 100):
    return SimpleNamespace(
        id=rule_id,
        profile_id=1,
        action=action,
        rule_type=rule_type,
        value=value,
        priority=priority,
        is_enabled=True,
    )


def test_phase9a_render_includes_connect_ports_client_acl_and_default_action(tmp_path):
    manager = ForwardProxyConfigManager(generated_config_path=tmp_path / "squid.conf")

    rendered = manager.render_proxy_config(
        _profile(allow_connect_ports="443,8443", allowed_client_cidrs="10.0.0.0/24,192.168.1.0/24"),
        [],
    )

    assert "http_port 3128" in rendered
    assert "acl SSL_ports port 443 8443" in rendered
    assert "acl allowed_clients src 10.0.0.0/24 192.168.1.0/24" in rendered
    assert "http_access deny !allowed_clients" in rendered
    assert "http_access deny all" in rendered


def test_phase9a_deny_rules_rendered_before_allow_rules(tmp_path):
    manager = ForwardProxyConfigManager(generated_config_path=tmp_path / "squid.conf")

    rendered = manager.render_proxy_config(
        _profile(),
        [
            _rule(1, "allow", "domain_suffix", ".example.com", 100),
            _rule(2, "deny", "domain_exact", "blocked.example.com", 200),
        ],
    )

    deny_pos = rendered.find("http_access deny rule_2")
    allow_pos = rendered.find("http_access allow rule_1")
    assert deny_pos != -1 and allow_pos != -1
    assert deny_pos < allow_pos


def test_phase9a_write_and_apply_with_true_commands(tmp_path):
    manager = ForwardProxyConfigManager(
        generated_config_path=tmp_path / "generated" / "squid.conf",
        validate_command=["/usr/bin/true"],
        reload_command=["/usr/bin/true"],
    )

    result = manager.apply_with_rollback(
        _profile(),
        [_rule(1, "allow", "domain_suffix", ".github.com", 10)],
    )

    written_path = tmp_path / "generated" / "squid.conf"
    assert written_path.exists()
    assert result["validate"]["ok"] is True
    assert result["reload"]["ok"] is True
